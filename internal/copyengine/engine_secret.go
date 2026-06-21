/*
Copyright 2024-2026 Graham Dumpleton.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package copyengine

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Request describes a single copy of an already-fetched source secret into one
// target namespace.
type Request struct {
	// Source is the already-fetched source secret whose type and data are
	// copied to the target.
	Source *corev1.Secret

	// SourceNamespace and SourceName identify the logical source of the copy.
	// They are recorded in the tracking annotation and used for the
	// same-namespace guard. For SecretCopier these match the source secret's
	// own namespace/name; they are kept separate from Source so other callers
	// (e.g. SecretExporter) can supply their own identity.
	SourceNamespace string
	SourceName      string

	// TargetNamespace is the namespace the copy is created in.
	TargetNamespace string

	// TargetName is the name to give the copy.
	TargetName string

	// TargetLabels are extra labels overlaid on top of the source secret's
	// labels on the copy.
	TargetLabels map[string]string

	// TargetAnnotations are annotations applied to the copy, reconciled under
	// managed-subset semantics like labels (annotations outside this set are
	// never compared or touched). Source annotations are never copied. Keys
	// under the operator-owned annotation prefix are rejected at admission by
	// the CRD schema.
	TargetAnnotations map[string]string

	// ManagedByValue is stamped under SecretAnnotationManagedBy and used for conflict
	// detection: an existing target is only updated when its annotation matches
	// this value (and the source annotation matches the source identity).
	ManagedByValue string

	// OwnerReferences are set on a newly created copy (typically to drive
	// garbage collection). They are applied only on creation, never on update.
	// Leave empty to set no owner reference (e.g. a Retain reclaim policy).
	OwnerReferences []metav1.OwnerReference

	// Authorize, if non-nil, gates the copy. When it returns false the engine
	// makes no change and reports AwaitingAuthorization. A nil hook means the
	// copy is always authorized.
	Authorize func(ctx context.Context) bool
}

// CopySecret copies the source secret described by req into its target
// namespace, creating the target secret if it does not exist or updating it if
// it exists and has drifted from the source. It returns an Outcome describing
// what happened so the caller can summarise it in status.
func (e *Engine) CopySecret(ctx context.Context, req Request) Outcome {
	log := logf.FromContext(ctx)

	// Never copy a secret into the namespace it originated from.

	if req.SourceNamespace == req.TargetNamespace {
		log.V(1).Info("Skipping copy of secret to same namespace", "sourceNamespace", req.SourceNamespace, "targetNamespace", req.TargetNamespace)
		return Skipped
	}

	// If an authorization gate is supplied and it does not authorize the copy,
	// make no change and report that we are awaiting authorization.

	if req.Authorize != nil && !req.Authorize(ctx) {
		log.V(1).Info("Copy not authorized", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)
		return AwaitingAuthorization
	}

	sourceRef := req.SourceNamespace + "/" + req.SourceName
	expectedLabels := overlayLabels(req.Source.Labels, req.TargetLabels)

	// Fetch the target secret.

	var targetSecret corev1.Secret

	err := e.Client.Get(ctx, client.ObjectKey{Namespace: req.TargetNamespace, Name: req.TargetName}, &targetSecret)

	if err != nil && client.IgnoreNotFound(err) != nil {
		log.Error(err, "Unable to fetch target secret", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)
		return Failed
	}

	// If the target secret does not exist, create it. Labels are a copy of those
	// from the source secret, overlaid with any extra labels for the target;
	// annotations are the rule's target annotations only (source annotations are
	// never copied). Tracking annotations record the owning rule, the source
	// secret, and the label and annotation keys the operator manages. Owner
	// references, if any, drive garbage collection.

	if err != nil {
		log.V(1).Info("Creating target secret", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)

		annotations := overlayLabels(req.TargetAnnotations, map[string]string{
			SecretAnnotationManagedBy:          req.ManagedByValue,
			SecretAnnotationSourceResource:     sourceRef,
			SecretAnnotationManagedLabels:      encodeManagedKeys(expectedLabels),
			SecretAnnotationManagedAnnotations: encodeManagedKeys(req.TargetAnnotations),
		})

		targetSecret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            req.TargetName,
				Namespace:       req.TargetNamespace,
				Labels:          expectedLabels,
				Annotations:     annotations,
				OwnerReferences: req.OwnerReferences,
			},
			Type: req.Source.Type,
			Data: req.Source.Data,
		}

		if err := e.Client.Create(ctx, &targetSecret); err != nil {
			log.Error(err, "Unable to create target secret", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)
			return Failed
		}

		log.V(1).Info("Created target secret", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)

		return InSync
	}

	// The target secret exists. Only touch it if it was created by this rule
	// from this source; otherwise a foreign secret owns the target name and we
	// leave it untouched, reporting a conflict.

	if !TargetManagedBy(secretAnnotationKeys, &targetSecret, req.ManagedByValue, sourceRef) {
		log.V(1).Info("Skipping update of target secret as not managed by this rule", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)
		return Conflict
	}

	// Update the target secret only if it has drifted from the source. Labels
	// and annotations follow managed-subset semantics (the apply helpers must
	// run before the managed-keys tracking annotations are rewritten). Owner
	// references are intentionally left as they were set on creation.

	if SourceChanged(req.Source, &targetSecret, req.TargetLabels, req.TargetAnnotations) {
		log.V(1).Info("Updating target secret", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)

		targetSecret.Labels = applyManagedLabels(secretAnnotationKeys, &targetSecret, expectedLabels)
		targetSecret.Annotations = applyManagedAnnotations(secretAnnotationKeys, &targetSecret, req.TargetAnnotations)
		targetSecret.Annotations[SecretAnnotationManagedLabels] = encodeManagedKeys(expectedLabels)
		targetSecret.Annotations[SecretAnnotationManagedAnnotations] = encodeManagedKeys(req.TargetAnnotations)
		targetSecret.Data = req.Source.Data
		targetSecret.Type = req.Source.Type

		if err := e.Client.Update(ctx, &targetSecret); err != nil {
			log.Error(err, "Unable to update target secret", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)
			return Failed
		}

		log.V(1).Info("Updated target secret", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)
	}

	return InSync
}

// SourceChanged reports whether the target secret has drifted from the source
// and therefore needs re-syncing. It compares the secret type, the data, the
// managed labels (the source's labels overlaid with the extra target labels)
// and the managed annotations (the rule's target annotations), both under
// managed-subset semantics - keys outside the managed sets are ignored.
func SourceChanged(source, target *corev1.Secret, extraLabels, extraAnnotations map[string]string) bool {
	if source.Type != target.Type {
		return true
	}

	if !mapStringBytesEqual(source.Data, target.Data) {
		return true
	}

	if labelsDrift(secretAnnotationKeys, target, overlayLabels(source.Labels, extraLabels)) {
		return true
	}

	return annotationsDrift(secretAnnotationKeys, target, extraAnnotations)
}
