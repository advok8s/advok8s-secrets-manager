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

// Package copyengine holds the logic for copying a single source secret into a
// single target namespace, shared by the resources that copy secrets
// (SecretCopier, and in future SecretExporter). The engine is deliberately
// agnostic about which custom resource drives it: the caller fetches the source
// secret, decides the target name, labels, owner references and (optionally) an
// authorization gate, and the engine performs the create/update/skip decision
// and reports an outcome for the caller to summarise in status.
package copyengine

import (
	"bytes"
	"context"
	"maps"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Outcome is the result of attempting to copy a source secret into a single
// target namespace.
type Outcome int

const (
	// InSync means the target secret was created, updated, or already up to
	// date.
	InSync Outcome = iota
	// Conflict means a secret with the target name already exists but is owned
	// by something else (a different owner, a different source, or not created
	// by this operator) and so was left untouched.
	Conflict
	// Failed means an API error occurred creating or updating the target.
	Failed
	// Skipped means there was nothing to do (e.g. the target namespace is the
	// source namespace).
	Skipped
	// AwaitingAuthorization means the copy was gated by an authorization hook
	// that did not (yet) authorize it — for example an export awaiting a
	// matching importer. No copy is made. SecretCopier does not currently use an
	// authorization hook, so it never produces this outcome.
	AwaitingAuthorization
)

// Annotation keys stamped on copied secrets so the operator can recognise the
// secrets it manages and which source secret they were copied from.
const (
	// AnnotationManagedBy records which copy rule owns the target secret. Its
	// value is supplied by the caller (Request.ManagedByValue) so the same key
	// can identify copies made by different custom resources.
	AnnotationManagedBy = "secrets.advok8s.io/secret-copier"
	// AnnotationSourceSecret records the "namespace/name" of the source secret
	// the target was copied from.
	AnnotationSourceSecret = "secrets.advok8s.io/secret-name"
)

// Engine performs secret copies against a Kubernetes client.
type Engine struct {
	Client client.Client
}

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

	// ManagedByValue is stamped under AnnotationManagedBy and used for conflict
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

// FilterActiveNamespaces returns the namespaces that are not terminating. The
// operator skips terminating namespaces when copying so it does not generate
// noise trying to create secrets that the API server will reject.
func FilterActiveNamespaces(namespaces []corev1.Namespace) []corev1.Namespace {
	active := make([]corev1.Namespace, 0, len(namespaces))

	for _, namespace := range namespaces {
		if namespace.Status.Phase != corev1.NamespaceTerminating {
			active = append(active, namespace)
		}
	}

	return active
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

	// Fetch the target secret.

	var targetSecret corev1.Secret

	err := e.Client.Get(ctx, client.ObjectKey{Namespace: req.TargetNamespace, Name: req.TargetName}, &targetSecret)

	if err != nil && client.IgnoreNotFound(err) != nil {
		log.Error(err, "Unable to fetch target secret", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)
		return Failed
	}

	// If the target secret does not exist, create it. Labels are a copy of those
	// from the source secret, overlaid with any extra labels for the target.
	// Tracking annotations record the owning rule and the source secret. Owner
	// references, if any, drive garbage collection.

	if err != nil {
		log.V(1).Info("Creating target secret", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)

		targetSecret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      req.TargetName,
				Namespace: req.TargetNamespace,
				Labels:    overlayLabels(req.Source.Labels, req.TargetLabels),
				Annotations: map[string]string{
					AnnotationManagedBy:    req.ManagedByValue,
					AnnotationSourceSecret: sourceRef,
				},
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

	if !TargetManagedBy(&targetSecret, req.ManagedByValue, sourceRef) {
		log.V(1).Info("Skipping update of target secret as not managed by this rule", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)
		return Conflict
	}

	// Update the target secret only if it has drifted from the source. Owner
	// references are intentionally left as they were set on creation.

	if SourceChanged(req.Source, &targetSecret, req.TargetLabels) {
		log.V(1).Info("Updating target secret", "targetSecret", req.TargetName, "targetNamespace", req.TargetNamespace)

		targetSecret.Labels = overlayLabels(req.Source.Labels, req.TargetLabels)
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

// TargetManagedBy reports whether an existing target secret was created by the
// given rule (managedByValue) from the given source ("namespace/name"). It is
// determined from the tracking annotations on the target.
func TargetManagedBy(target *corev1.Secret, managedByValue, sourceRef string) bool {
	if target.Annotations[AnnotationManagedBy] != managedByValue {
		return false
	}

	if target.Annotations[AnnotationSourceSecret] != sourceRef {
		return false
	}

	return true
}

// SourceChanged reports whether the target secret has drifted from the source
// and therefore needs re-syncing. It compares the secret type, the data, and
// the labels the target should carry (the source's labels overlaid with the
// extra target labels).
func SourceChanged(source, target *corev1.Secret, extraLabels map[string]string) bool {
	if source.Type != target.Type {
		return true
	}

	if !mapStringBytesEqual(source.Data, target.Data) {
		return true
	}

	return !mapStringStringEqual(target.Labels, overlayLabels(source.Labels, extraLabels))
}

// overlayLabels returns a new map of the base labels overlaid with the extra
// labels (extra wins on conflict). The result is always non-nil.
func overlayLabels(base, extra map[string]string) map[string]string {
	labels := make(map[string]string, len(base)+len(extra))
	maps.Copy(labels, base)
	maps.Copy(labels, extra)
	return labels
}

func mapStringBytesEqual(a, b map[string][]byte) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for key, valueA := range a {
		if valueB, ok := b[key]; !ok || !bytes.Equal(valueA, valueB) {
			return false
		}
	}
	return true
}

func mapStringStringEqual(a, b map[string]string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for key, valueA := range a {
		if valueB, ok := b[key]; !ok || valueA != valueB {
			return false
		}
	}
	return true
}
