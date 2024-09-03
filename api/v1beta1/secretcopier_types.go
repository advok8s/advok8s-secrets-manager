/*
Copyright 2024 Graham Dumpleton.

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
	"github.com/advok8s/advok8s-secrets-manager/internal/selectors"
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

	// Reclaim policy for copied secret.
	// +kubebuilder:default=Delete
	ReclaimPolicy ReclaimPolicy `json:"reclaimPolicy,omitempty"`
}

// SecretCopierSpec defines the desired state of SecretCopier
type SecretCopierSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// A list of rules for copying secrets.
	Rules []SecretCopierRule `json:"rules,omitempty"`

	// The interval at which to run the controller.
	// +kubebuilder:default="1m"
	SyncPeriod metav1.Duration `json:"syncPeriod,omitempty"`
}

// SecretCopierStatus defines the observed state of SecretCopier
type SecretCopierStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// SecretCopier is the Schema for the secretcopiers API
type SecretCopier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecretCopierSpec   `json:"spec,omitempty"`
	Status SecretCopierStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecretCopierList contains a list of SecretCopier
type SecretCopierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecretCopier `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecretCopier{}, &SecretCopierList{})
}
