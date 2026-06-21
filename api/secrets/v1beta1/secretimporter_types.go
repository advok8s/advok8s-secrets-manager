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

// ImporterSourceNamespaces qualifies which source namespaces a SecretImporter
// will accept a copy from.
type ImporterSourceNamespaces struct {
	// NameSelector matches source namespaces by name (glob patterns, with a "!"
	// prefix to exclude). When empty, any source namespace is accepted.
	// +optional
	NameSelector selectors.NameSelector `json:"nameSelector,omitempty"`
}

// SecretImporterSpec defines the desired state of SecretImporter. A
// SecretImporter authorizes copying a secret into its namespace: a paired
// SecretExporter or SecretCopier copies the secret only when this importer
// exists (named the same as the target secret) and its shared secret matches.
type SecretImporterSpec struct {
	// SourceNamespaces optionally restricts which source namespaces a copy may
	// originate from. When omitted, any source namespace is accepted.
	// +optional
	SourceNamespaces *ImporterSourceNamespaces `json:"sourceNamespaces,omitempty"`

	// CopyAuthorization carries the shared secret that must match the exporter
	// or copier rule before a copy is made into this namespace.
	CopyAuthorization CopyAuthorization `json:"copyAuthorization"`
}

// SecretImporterStatus defines the observed state of SecretImporter.
type SecretImporterStatus struct {
	// observedGeneration is the .metadata.generation last processed by the
	// controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the SecretImporter resource.
	// The Ready condition is True once the requested secret has been imported
	// into this namespace.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// imported is whether the secret named the same as this importer currently
	// exists in this namespace and is owned by this importer.
	// +optional
	Imported bool `json:"imported,omitempty"`

	// boundTo identifies the exporter or copier rule satisfying this importer,
	// as "kind namespace/name" (e.g. "secretexporter registry/registry-creds").
	// Empty when nothing is currently exporting to this importer.
	// +optional
	BoundTo string `json:"boundTo,omitempty"`

	// targetSecretName is the name of the secret this importer manages (the same
	// as the importer's own name).
	// +optional
	TargetSecretName string `json:"targetSecretName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Imported",type=boolean,JSONPath=".status.imported"
// +kubebuilder:printcolumn:name="Bound To",type=string,JSONPath=".status.boundTo"
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=".status.targetSecretName",priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// SecretImporter is the Schema for the secretimporters API.
type SecretImporter struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecretImporter
	// +required
	Spec SecretImporterSpec `json:"spec"`

	// status defines the observed state of SecretImporter
	// +optional
	Status SecretImporterStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecretImporterList contains a list of SecretImporter.
type SecretImporterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecretImporter `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecretImporter{}, &SecretImporterList{})
}
