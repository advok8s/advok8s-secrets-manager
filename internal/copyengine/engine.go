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

// Package copyengine holds the logic for copying a single source resource (a
// Secret or a ConfigMap) into a single target namespace, shared by the
// resources that copy (SecretCopier, SecretExporter, ConfigMapCopier). The
// engine is deliberately agnostic about which custom resource drives it: the
// caller fetches the source, decides the target name, labels, owner references
// and (for secrets, optionally) an authorization gate, and the engine performs
// the create/update/skip decision and reports an outcome for the caller to
// summarise in status.
//
// The per-kind copy functions (CopySecret, CopyConfigMap) are deliberately
// separate, straight-line implementations rather than one generic state
// machine: the control flow is short and stable, and the kinds legitimately
// differ (secrets carry a type and an authorization hook; configmaps carry two
// data maps and no authorization). All the subtle, shared logic - conflict
// detection, label semantics, map equality - lives in this file so a fix in
// one place applies to both kinds.
package copyengine

import (
	"bytes"
	"maps"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Outcome is the result of attempting to copy a source resource into a single
// target namespace.
type Outcome int

const (
	// InSync means the target was created, updated, or already up to date.
	InSync Outcome = iota
	// Conflict means a resource with the target name already exists but is
	// owned by something else (a different owner, a different source, or not
	// created by this operator) and so was left untouched.
	Conflict
	// Failed means an API error occurred creating or updating the target.
	Failed
	// Skipped means there was nothing to do (e.g. the target namespace is the
	// source namespace).
	Skipped
	// AwaitingAuthorization means the copy was gated by an authorization hook
	// that did not (yet) authorize it — for example an export awaiting a
	// matching importer. No copy is made. Only the Secret copy path uses an
	// authorization hook; ConfigMap copies never produce this outcome.
	AwaitingAuthorization
)

// Annotation keys stamped on copied resources so the operator can recognise
// the copies it manages, which source they were copied from, and which labels
// it owns on them.
const (
	// AnnotationManagedBy records which copy rule owns the target. Its value
	// is supplied by the caller (ManagedByValue) as "kind/name" (e.g.
	// "secretcopier/x", "secretexporter/y" or "configmapcopier/z") so the same
	// key identifies copies made by different custom resources without them
	// fighting over a shared target name.
	AnnotationManagedBy = "secrets.advok8s.io/copier-rule"
	// AnnotationSourceResource records the "namespace/name" of the source
	// resource the target was copied from. A copied Secret can only have a
	// Secret source (and a ConfigMap a ConfigMap source), so the kind is not
	// encoded in the value.
	AnnotationSourceResource = "secrets.advok8s.io/resource"
	// AnnotationManagedLabels records, as a sorted comma-joined list, the
	// label keys the operator manages on the target. Label reconciliation is
	// managed-subset: labels outside this set (for example injected by a
	// mutating admission webhook such as a Kyverno policy) are neither
	// compared nor touched, so the operator never fights admission-time label
	// injection in a reconcile loop. The recorded set is how a label removed
	// from the source is also removed from the target.
	AnnotationManagedLabels = "secrets.advok8s.io/managed-labels"
)

// Engine performs resource copies against a Kubernetes client.
type Engine struct {
	Client client.Client
}

// FilterActiveNamespaces returns the namespaces that are not terminating. The
// operator skips terminating namespaces when copying so it does not generate
// noise trying to create resources that the API server will reject.
func FilterActiveNamespaces(namespaces []corev1.Namespace) []corev1.Namespace {
	active := make([]corev1.Namespace, 0, len(namespaces))

	for _, namespace := range namespaces {
		if namespace.Status.Phase != corev1.NamespaceTerminating {
			active = append(active, namespace)
		}
	}

	return active
}

// TargetManagedBy reports whether an existing target resource was created by
// the given rule (managedByValue) from the given source ("namespace/name"). It
// is determined from the tracking annotations on the target.
func TargetManagedBy(target metav1.Object, managedByValue, sourceRef string) bool {
	annotations := target.GetAnnotations()

	if annotations[AnnotationManagedBy] != managedByValue {
		return false
	}

	if annotations[AnnotationSourceResource] != sourceRef {
		return false
	}

	return true
}

// ---- label semantics (managed-subset) -------------------------------------

// overlayLabels returns a new map of the base labels overlaid with the extra
// labels (extra wins on conflict). The result is always non-nil.
func overlayLabels(base, extra map[string]string) map[string]string {
	labels := make(map[string]string, len(base)+len(extra))
	maps.Copy(labels, base)
	maps.Copy(labels, extra)
	return labels
}

// managedLabelKeys returns the label keys recorded as managed on the target
// (from AnnotationManagedLabels). A missing or empty annotation yields nil.
func managedLabelKeys(target metav1.Object) []string {
	raw := target.GetAnnotations()[AnnotationManagedLabels]
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// encodeManagedLabelKeys serialises the managed key set for
// AnnotationManagedLabels: sorted, comma-joined. Label keys cannot contain
// commas, so the encoding is unambiguous.
func encodeManagedLabelKeys(expected map[string]string) string {
	keys := make([]string, 0, len(expected))
	for k := range expected {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// labelsDrift reports whether the target's labels need re-syncing under
// managed-subset semantics: an expected key is missing or has the wrong value,
// or a previously managed key is no longer expected but still present. Labels
// outside the managed set are invisible to the comparison, so admission-time
// label injection never triggers an update.
func labelsDrift(target metav1.Object, expected map[string]string) bool {
	current := target.GetLabels()

	for key, value := range expected {
		if got, ok := current[key]; !ok || got != value {
			return true
		}
	}

	for _, key := range managedLabelKeys(target) {
		if _, isExpected := expected[key]; isExpected {
			continue
		}
		if _, present := current[key]; present {
			return true
		}
	}

	return false
}

// applyManagedLabels returns the target's labels with the expected set applied
// and stale previously-managed keys removed. Labels outside both sets (owned
// by someone else, e.g. an admission webhook) are preserved untouched. It must
// be called before the AnnotationManagedLabels annotation is rewritten, since
// it reads the previously managed set from the target.
func applyManagedLabels(target metav1.Object, expected map[string]string) map[string]string {
	out := make(map[string]string, len(target.GetLabels())+len(expected))
	maps.Copy(out, target.GetLabels())

	for _, key := range managedLabelKeys(target) {
		if _, isExpected := expected[key]; !isExpected {
			delete(out, key)
		}
	}

	maps.Copy(out, expected)
	return out
}

// ---- map equality ----------------------------------------------------------

func mapStringBytesEqual(a, b map[string][]byte) bool {
	// A nil map and an empty map are treated as equal: a resource stored with
	// no data reads back as nil, whereas a freshly computed map may be empty
	// but non-nil, and the two must not be seen as different.
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
	// As above: nil and empty must compare equal, else a copy with an absent
	// map would be updated on every reconcile.
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
