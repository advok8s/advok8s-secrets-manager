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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/advok8s/advok8s-secrets-manager/pkg/selectors"
)

// SecretExporterRule is a rule for copying this exporter's secret into a set of
// target namespaces. The source secret is the secret in the exporter's own
// namespace whose name matches the exporter, so a rule names only the
// destination, not the source.
type SecretExporterRule struct {
	// Target namespaces to copy to.
	TargetNamespaces selectors.TargetNamespaces `json:"targetNamespaces,omitempty"`

	// Target secret to copy to.
	TargetSecret TargetSecret `json:"targetSecret,omitempty"`

	// CopyAuthorization gates the copy on a matching SecretImporter in the
	// target namespace. When the shared secret is left unset, the importer must
	// instead carry this exporter's UID as its shared secret.
	// +optional
	CopyAuthorization CopyAuthorization `json:"copyAuthorization,omitempty"`
}

// SecretExporterSpec defines the desired state of SecretExporter.
type SecretExporterSpec struct {
	// A list of rules for exporting this exporter's secret to other namespaces.
	Rules []SecretExporterRule `json:"rules,omitempty"`

	// The interval at which to re-synchronise copied secrets. Leave unset to
	// use the default; set to "0s" to disable the periodic re-sync (copies are
	// still updated in response to source secret and namespace changes).
	// +kubebuilder:default="1m"
	SyncPeriod *metav1.Duration `json:"syncPeriod,omitempty"`
}

// SecretExporterCounts holds copy outcome counts, used for both the aggregate
// summary and the per-rule breakdown.
type SecretExporterCounts struct {
	// targetNamespaces is the number of (rule, namespace) matches.
	// +optional
	TargetNamespaces int `json:"targetNamespaces"`

	// secretsInSync is the number of target secrets confirmed present and up to
	// date.
	// +optional
	SecretsInSync int `json:"secretsInSync"`

	// conflicts is the number of target secret names owned by something else and
	// so left untouched.
	// +optional
	Conflicts int `json:"conflicts"`

	// awaitingAuthorization is the number of matches whose copyAuthorization was
	// not satisfied (no matching SecretImporter, or a mismatched shared secret)
	// and so were not copied.
	// +optional
	AwaitingAuthorization int `json:"awaitingAuthorization"`

	// failures is the number of target secrets that could not be created or
	// updated.
	// +optional
	Failures int `json:"failures"`
}

// SecretExporterStatus defines the observed state of SecretExporter.
type SecretExporterStatus struct {
	// observedGeneration is the .metadata.generation last processed by the
	// controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the SecretExporter resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// sourceExists is whether the secret this exporter exports (a secret named
	// the same as the exporter, in the exporter's namespace) was found this
	// reconcile.
	// +optional
	SourceExists bool `json:"sourceExists,omitempty"`

	// summary holds aggregate counts across all rules from the last reconcile.
	// +optional
	Summary SecretExporterCounts `json:"summary,omitempty"`

	// rules summarises the outcome of each rule, one entry per rule in spec
	// order.
	// +optional
	Rules []SecretExporterCounts `json:"rules,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Source",type=boolean,JSONPath=".status.sourceExists"
// +kubebuilder:printcolumn:name="In Sync",type=integer,JSONPath=".status.summary.secretsInSync"
// +kubebuilder:printcolumn:name="Failures",type=integer,JSONPath=".status.summary.failures"
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].reason",priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// SecretExporter is the Schema for the secretexporters API.
type SecretExporter struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecretExporter
	// +required
	Spec SecretExporterSpec `json:"spec"`

	// status defines the observed state of SecretExporter
	// +optional
	Status SecretExporterStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecretExporterList contains a list of SecretExporter.
type SecretExporterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecretExporter `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecretExporter{}, &SecretExporterList{})
}
