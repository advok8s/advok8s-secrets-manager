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

package v1beta1

import (
	"github.com/advok8s/advok8s-secrets-manager/pkg/selectors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SourceSecret is a reference to a secret to copy from.
type SourceSecret struct {
	// Name of the secret to copy from.
	Name string `json:"name"`

	// Namespace of the secret to copy from.
	Namespace string `json:"namespace"`
}

// TargetSecret is a reference to a secret to copy to.
type TargetSecret struct {
	// Name of the secret to copy to.
	Name string `json:"name"`

	// Labels to apply to the secret.
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to apply to the secret. Reconciled as a managed subset, like
	// labels: annotations outside this set are never compared or touched. Keys
	// under the operator-owned secrets.advok8s.io/ prefix are rejected (the
	// tracking annotations live there).
	// +kubebuilder:validation:MaxProperties=32
	// +kubebuilder:validation:XValidation:rule="self.all(k, !k.startsWith('secrets.advok8s.io/'))",message="annotation keys under the operator-owned secrets.advok8s.io/ prefix are not allowed"
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// CopyAuthorization gates copying a secret into a target namespace on a
// SecretImporter in that namespace carrying a matching shared secret. It is the
// handshake that lets the owner of a target namespace consent to receiving a
// copy: without a matching SecretImporter the copy is not made. The same shape
// is used by SecretExporter.
type CopyAuthorization struct {
	// SharedSecret must match the sharedSecret of the SecretImporter (named the
	// same as the target secret) in the target namespace before a copy is made.
	SharedSecret string `json:"sharedSecret,omitempty"`
}

// Reclaim policy for copied secret.
// +kubebuilder:validation:Enum=Delete;Retain
type ReclaimPolicy string

const (
	ReclaimDelete ReclaimPolicy = "Delete"
	ReclaimRetain ReclaimPolicy = "Retain"
)

// SecretCopierRule is a rule for copying a secret.
type SecretCopierRule struct {
	// Reference to the secret to copy to.
	SourceSecret SourceSecret `json:"sourceSecret"`

	// Target namespaces to copy to.
	TargetNamespaces selectors.TargetNamespaces `json:"targetNamespaces,omitempty"`

	// Target secret to copy to.
	TargetSecret TargetSecret `json:"targetSecret,omitempty"`

	// CopyAuthorization, when set, requires a matching SecretImporter in the
	// target namespace before the secret is copied there.
	// +optional
	CopyAuthorization CopyAuthorization `json:"copyAuthorization,omitempty"`

	// Reclaim policy for copied secret.
	// +kubebuilder:default=Delete
	ReclaimPolicy ReclaimPolicy `json:"reclaimPolicy,omitempty"`
}

// SecretCopierSpec defines the desired state of SecretCopier
type SecretCopierSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// A list of rules for copying secrets.
	// +kubebuilder:validation:MaxItems=100
	Rules []SecretCopierRule `json:"rules,omitempty"`
}

// Condition types reported on a SecretCopier.
const (
	// ConditionReady is True when the last reconcile copied all matched
	// secrets without error.
	ConditionReady = "Ready"
	// ConditionDegraded is True when one or more copies failed during the
	// last reconcile.
	ConditionDegraded = "Degraded"
)

// SecretCopierStatus defines the observed state of SecretCopier.
type SecretCopierStatus struct {
	// observedGeneration is the .metadata.generation last processed by the
	// controller. When it is less than .metadata.generation the status does
	// not yet reflect the current spec.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the SecretCopier resource.
	// Each condition has a unique type and reflects the status of a specific
	// aspect of the resource. The status of each condition is one of True,
	// False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// summary holds aggregate counts across all rules from the last reconcile.
	// +optional
	Summary SecretCopierSummary `json:"summary,omitempty"`

	// rules summarises the outcome of each rule, one entry per rule in spec
	// order. It records counts only - never the individual target namespaces -
	// so its size is bounded by the number of rules, not the size of the
	// cluster.
	// +optional
	Rules []RuleStatus `json:"rules,omitempty"`
}

// SecretCopierSummary holds aggregate counts across all rules.
type SecretCopierSummary struct {
	// targetNamespaces is the total number of (rule, namespace) matches across
	// all rules. A namespace matched by two rules counts twice.
	// +optional
	TargetNamespaces int `json:"targetNamespaces"`

	// secretsInSync is the number of target secrets confirmed present and up to
	// date after the last reconcile.
	// +optional
	SecretsInSync int `json:"secretsInSync"`

	// conflicts is the number of target secret names that already existed and
	// are owned by something else (a different SecretCopier, a different source,
	// or not created by this operator at all) and so were left untouched.
	// +optional
	Conflicts int `json:"conflicts"`

	// awaitingAuthorization is the number of (rule, namespace) matches whose
	// copyAuthorization was not satisfied (no matching SecretImporter, or a
	// mismatched shared secret) and so were not copied.
	// +optional
	AwaitingAuthorization int `json:"awaitingAuthorization"`

	// failures is the number of target secrets that could not be created or
	// updated during the last reconcile.
	// +optional
	Failures int `json:"failures"`
}

// RuleStatus summarises the outcome of a single rule.
type RuleStatus struct {
	// sourceSecret identifies the rule's source secret as "namespace/name".
	SourceSecret string `json:"sourceSecret"`

	// sourceExists is whether the source secret was found this reconcile.
	SourceExists bool `json:"sourceExists"`

	// targetNamespaces is the number of namespaces this rule matched.
	// +optional
	TargetNamespaces int `json:"targetNamespaces"`

	// secretsInSync is the number of target secrets in sync for this rule.
	// +optional
	SecretsInSync int `json:"secretsInSync"`

	// conflicts is the number of target secret names matched by this rule that
	// are owned by something else and so were left untouched.
	// +optional
	Conflicts int `json:"conflicts"`

	// awaitingAuthorization is the number of namespaces matched by this rule
	// whose copyAuthorization was not satisfied and so were not copied.
	// +optional
	AwaitingAuthorization int `json:"awaitingAuthorization"`

	// failures is the number of target secrets that could not be copied for
	// this rule.
	// +optional
	Failures int `json:"failures"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Namespaces",type=integer,JSONPath=".status.summary.targetNamespaces"
// +kubebuilder:printcolumn:name="In Sync",type=integer,JSONPath=".status.summary.secretsInSync"
// +kubebuilder:printcolumn:name="Failures",type=integer,JSONPath=".status.summary.failures"
// +kubebuilder:printcolumn:name="Conflicts",type=integer,JSONPath=".status.summary.conflicts",priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].reason",priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// SecretCopier is the Schema for the secretcopiers API
type SecretCopier struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecretCopier
	// +required
	Spec SecretCopierSpec `json:"spec"`

	// status defines the observed state of SecretCopier
	// +optional
	Status SecretCopierStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecretCopierList contains a list of SecretCopier
type SecretCopierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecretCopier `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecretCopier{}, &SecretCopierList{})
}
