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

// ConfigMapRequest describes a single copy of an already-fetched source
// ConfigMap into one target namespace. Unlike the Secret copy path there is no
// authorization hook: ConfigMap copying is an admin-operated distribution
// mechanism (ConfigMapCopier is cluster-scoped) with no importer handshake.
type ConfigMapRequest struct {
	// Source is the already-fetched source ConfigMap whose data and binaryData
	// are copied to the target.
	Source *corev1.ConfigMap

	// SourceNamespace and SourceName identify the logical source of the copy.
	// They are recorded in the tracking annotation and used for the
	// same-namespace guard.
	SourceNamespace string
	SourceName      string

	// TargetNamespace is the namespace the copy is created in.
	TargetNamespace string

	// TargetName is the name to give the copy.
	TargetName string

	// TargetLabels are extra labels overlaid on top of the source ConfigMap's
	// labels on the copy.
	TargetLabels map[string]string

	// TargetAnnotations are annotations applied to the copy, reconciled under
	// managed-subset semantics like labels (annotations outside this set are
	// never compared or touched). Source annotations are never copied. Keys
	// under the operator-owned annotation prefix are rejected at admission by
	// the CRD schema.
	TargetAnnotations map[string]string

	// ManagedByValue is stamped under AnnotationManagedBy and used for conflict
	// detection: an existing target is only updated when its annotation matches
	// this value (and the source annotation matches the source identity).
	ManagedByValue string

	// OwnerReferences are set on a newly created copy (typically to drive
	// garbage collection). They are applied only on creation, never on update.
	// Leave empty to set no owner reference (e.g. a Retain reclaim policy).
	OwnerReferences []metav1.OwnerReference
}

// CopyConfigMap copies the source ConfigMap described by req into its target
// namespace, creating the target if it does not exist or updating it if it
// exists and has drifted from the source. Data and binaryData are replaced
// together as a pair, so a key migrating between the two maps in the source
// converges cleanly on the target. It returns an Outcome describing what
// happened so the caller can summarise it in status.
func (e *Engine) CopyConfigMap(ctx context.Context, req ConfigMapRequest) Outcome {
	log := logf.FromContext(ctx)

	// Never copy a configmap into the namespace it originated from.

	if req.SourceNamespace == req.TargetNamespace {
		log.V(1).Info("Skipping copy of configmap to same namespace", "sourceNamespace", req.SourceNamespace, "targetNamespace", req.TargetNamespace)
		return Skipped
	}

	sourceRef := req.SourceNamespace + "/" + req.SourceName
	expectedLabels := overlayLabels(req.Source.Labels, req.TargetLabels)

	// Fetch the target configmap.

	var targetConfigMap corev1.ConfigMap

	err := e.Client.Get(ctx, client.ObjectKey{Namespace: req.TargetNamespace, Name: req.TargetName}, &targetConfigMap)

	if err != nil && client.IgnoreNotFound(err) != nil {
		log.Error(err, "Unable to fetch target configmap", "targetConfigMap", req.TargetName, "targetNamespace", req.TargetNamespace)
		return Failed
	}

	// If the target configmap does not exist, create it. Labels are a copy of
	// those from the source, overlaid with any extra labels for the target;
	// annotations are the rule's target annotations only (source annotations
	// are never copied). Tracking annotations record the owning rule, the
	// source configmap, and the label and annotation keys the operator manages.
	// Owner references, if any, drive garbage collection.

	if err != nil {
		log.V(1).Info("Creating target configmap", "targetConfigMap", req.TargetName, "targetNamespace", req.TargetNamespace)

		annotations := overlayLabels(req.TargetAnnotations, map[string]string{
			AnnotationManagedBy:          req.ManagedByValue,
			AnnotationSourceResource:     sourceRef,
			AnnotationManagedLabels:      encodeManagedKeys(expectedLabels),
			AnnotationManagedAnnotations: encodeManagedKeys(req.TargetAnnotations),
		})

		targetConfigMap = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:            req.TargetName,
				Namespace:       req.TargetNamespace,
				Labels:          expectedLabels,
				Annotations:     annotations,
				OwnerReferences: req.OwnerReferences,
			},
			Data:       req.Source.Data,
			BinaryData: req.Source.BinaryData,
		}

		if err := e.Client.Create(ctx, &targetConfigMap); err != nil {
			log.Error(err, "Unable to create target configmap", "targetConfigMap", req.TargetName, "targetNamespace", req.TargetNamespace)
			return Failed
		}

		log.V(1).Info("Created target configmap", "targetConfigMap", req.TargetName, "targetNamespace", req.TargetNamespace)

		return InSync
	}

	// The target configmap exists. Only touch it if it was created by this rule
	// from this source; otherwise a foreign configmap owns the target name and
	// we leave it untouched, reporting a conflict.

	if !TargetManagedBy(&targetConfigMap, req.ManagedByValue, sourceRef) {
		log.V(1).Info("Skipping update of target configmap as not managed by this rule", "targetConfigMap", req.TargetName, "targetNamespace", req.TargetNamespace)
		return Conflict
	}

	// Update the target configmap only if it has drifted from the source.
	// Labels and annotations follow managed-subset semantics (the apply helpers
	// must run before the managed-keys tracking annotations are rewritten).
	// Owner references are intentionally left as they were set on creation.

	if ConfigMapSourceChanged(req.Source, &targetConfigMap, req.TargetLabels, req.TargetAnnotations) {
		log.V(1).Info("Updating target configmap", "targetConfigMap", req.TargetName, "targetNamespace", req.TargetNamespace)

		targetConfigMap.Labels = applyManagedLabels(&targetConfigMap, expectedLabels)
		targetConfigMap.Annotations = applyManagedAnnotations(&targetConfigMap, req.TargetAnnotations)
		targetConfigMap.Annotations[AnnotationManagedLabels] = encodeManagedKeys(expectedLabels)
		targetConfigMap.Annotations[AnnotationManagedAnnotations] = encodeManagedKeys(req.TargetAnnotations)
		targetConfigMap.Data = req.Source.Data
		targetConfigMap.BinaryData = req.Source.BinaryData

		if err := e.Client.Update(ctx, &targetConfigMap); err != nil {
			log.Error(err, "Unable to update target configmap", "targetConfigMap", req.TargetName, "targetNamespace", req.TargetNamespace)
			return Failed
		}

		log.V(1).Info("Updated target configmap", "targetConfigMap", req.TargetName, "targetNamespace", req.TargetNamespace)
	}

	return InSync
}

// ConfigMapSourceChanged reports whether the target ConfigMap has drifted from
// the source and therefore needs re-syncing. It compares both data maps (data
// and binaryData), the managed labels (the source's labels overlaid with the
// extra target labels) and the managed annotations (the rule's target
// annotations), both under managed-subset semantics - keys outside the managed
// sets are ignored.
func ConfigMapSourceChanged(source, target *corev1.ConfigMap, extraLabels, extraAnnotations map[string]string) bool {
	if !mapStringStringEqual(source.Data, target.Data) {
		return true
	}

	if !mapStringBytesEqual(source.BinaryData, target.BinaryData) {
		return true
	}

	if labelsDrift(target, overlayLabels(source.Labels, extraLabels)) {
		return true
	}

	return annotationsDrift(target, extraAnnotations)
}
