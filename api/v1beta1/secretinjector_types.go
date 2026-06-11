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

// SecretInjectorRule is a rule for injecting references to matching secrets into
// matching service accounts within matching namespaces. Image pull secrets
// (type kubernetes.io/dockerconfigjson) are injected into a service account's
// imagePullSecrets; all other secret types are injected into its secrets.
type SecretInjectorRule struct {
	// SourceSecrets selects the secrets whose references are injected. At least
	// a name or label selector should be given. It uses the richer SecretSelector
	// (name/label/owner/uid); name matching supports globs and "!" exclusions.
	SourceSecrets selectors.SecretSelector `json:"sourceSecrets"`

	// TargetNamespaces selects the namespaces the rule applies to. When omitted,
	// all namespaces except the Kubernetes-reserved kube-* namespaces match.
	// +optional
	TargetNamespaces selectors.TargetNamespaces `json:"targetNamespaces,omitempty"`

	// ServiceAccounts selects the service accounts to inject into. When omitted,
	// all service accounts in a matching namespace are injected into.
	// +optional
	ServiceAccounts selectors.NameLabelSelector `json:"serviceAccounts,omitempty"`
}

// SecretInjectorSpec defines the desired state of SecretInjector.
type SecretInjectorSpec struct {
	// A list of rules for injecting secret references into service accounts.
	Rules []SecretInjectorRule `json:"rules,omitempty"`
}

// SecretInjectorCounts holds injection outcome counts, used for both the
// aggregate summary and the per-rule breakdown.
type SecretInjectorCounts struct {
	// targetNamespaces is the number of (rule, namespace) matches.
	// +optional
	TargetNamespaces int `json:"targetNamespaces"`

	// serviceAccountsMatched is the number of service accounts matched by the
	// rule across matched namespaces.
	// +optional
	ServiceAccountsMatched int `json:"serviceAccountsMatched"`

	// injectionsInSync is the number of (secret, service account) pairs whose
	// reference is present on the service account after the last reconcile.
	// Because injections are only added, never removed, this counts references
	// that are present rather than a reconciled-to-exact-desired-state total.
	// +optional
	InjectionsInSync int `json:"injectionsInSync"`

	// failures is the number of service accounts that could not be updated.
	// +optional
	Failures int `json:"failures"`
}

// SecretInjectorStatus defines the observed state of SecretInjector.
type SecretInjectorStatus struct {
	// observedGeneration is the .metadata.generation last processed by the
	// controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the SecretInjector resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// summary holds aggregate counts across all rules from the last reconcile.
	// +optional
	Summary SecretInjectorCounts `json:"summary,omitempty"`

	// rules summarises the outcome of each rule, one entry per rule in spec
	// order.
	// +optional
	Rules []SecretInjectorCounts `json:"rules,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Namespaces",type=integer,JSONPath=".status.summary.targetNamespaces"
// +kubebuilder:printcolumn:name="Svc Accounts",type=integer,JSONPath=".status.summary.serviceAccountsMatched"
// +kubebuilder:printcolumn:name="In Sync",type=integer,JSONPath=".status.summary.injectionsInSync"
// +kubebuilder:printcolumn:name="Failures",type=integer,JSONPath=".status.summary.failures"
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].reason",priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// SecretInjector is the Schema for the secretinjectors API.
type SecretInjector struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecretInjector
	// +required
	Spec SecretInjectorSpec `json:"spec"`

	// status defines the observed state of SecretInjector
	// +optional
	Status SecretInjectorStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecretInjectorList contains a list of SecretInjector.
type SecretInjectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecretInjector `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecretInjector{}, &SecretInjectorList{})
}
