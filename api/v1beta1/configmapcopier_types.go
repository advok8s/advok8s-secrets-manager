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

// SourceConfigMap is a reference to a configmap to copy from.
type SourceConfigMap struct {
	// Name of the configmap to copy from.
	Name string `json:"name"`

	// Namespace of the configmap to copy from.
	Namespace string `json:"namespace"`
}

// TargetConfigMap is a reference to a configmap to copy to.
type TargetConfigMap struct {
	// Name of the configmap to copy to. Defaults to the source configmap's
	// name when empty.
	Name string `json:"name,omitempty"`

	// Labels to apply to the configmap.
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to apply to the configmap. Reconciled as a managed subset,
	// like labels: annotations outside this set are never compared or touched.
	// Keys under the operator-owned secrets.advok8s.io/ prefix are rejected
	// (the tracking annotations live there).
	// +kubebuilder:validation:MaxProperties=32
	// +kubebuilder:validation:XValidation:rule="self.all(k, !k.startsWith('secrets.advok8s.io/'))",message="annotation keys under the operator-owned secrets.advok8s.io/ prefix are not allowed"
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ConfigMapCopierRule is a rule for copying a configmap. Unlike SecretCopier
// there is no copyAuthorization: ConfigMaps carry no secret material, so
// distribution is an admin-operated mechanism with no importer handshake.
type ConfigMapCopierRule struct {
	// Reference to the configmap to copy from.
	SourceConfigMap SourceConfigMap `json:"sourceConfigMap"`

	// Target namespaces to copy to.
	TargetNamespaces selectors.TargetNamespaces `json:"targetNamespaces,omitempty"`

	// Target configmap to copy to.
	TargetConfigMap TargetConfigMap `json:"targetConfigMap,omitempty"`

	// Reclaim policy for copied configmap.
	// +kubebuilder:default=Delete
	ReclaimPolicy ReclaimPolicy `json:"reclaimPolicy,omitempty"`
}

// ConfigMapCopierSpec defines the desired state of ConfigMapCopier.
type ConfigMapCopierSpec struct {
	// A list of rules for copying configmaps.
	// +kubebuilder:validation:MaxItems=100
	Rules []ConfigMapCopierRule `json:"rules,omitempty"`
}

// ConfigMapCopierStatus defines the observed state of ConfigMapCopier.
type ConfigMapCopierStatus struct {
	// observedGeneration is the .metadata.generation last processed by the
	// controller. When it is less than .metadata.generation the status does
	// not yet reflect the current spec.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the ConfigMapCopier resource.
	// Each condition has a unique type and reflects the status of a specific
	// aspect of the resource. The status of each condition is one of True,
	// False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// summary holds aggregate counts across all rules from the last reconcile.
	// +optional
	Summary ConfigMapCopierSummary `json:"summary,omitempty"`

	// rules summarises the outcome of each rule, one entry per rule in spec
	// order. It records counts only - never the individual target namespaces -
	// so its size is bounded by the number of rules, not the size of the
	// cluster.
	// +optional
	Rules []ConfigMapRuleStatus `json:"rules,omitempty"`
}

// ConfigMapCopierSummary holds aggregate counts across all rules.
type ConfigMapCopierSummary struct {
	// targetNamespaces is the total number of (rule, namespace) matches across
	// all rules. A namespace matched by two rules counts twice.
	// +optional
	TargetNamespaces int `json:"targetNamespaces"`

	// configMapsInSync is the number of target configmaps confirmed present
	// and up to date after the last reconcile.
	// +optional
	ConfigMapsInSync int `json:"configMapsInSync"`

	// conflicts is the number of target configmap names that already existed
	// and are owned by something else (a different ConfigMapCopier, a
	// different source, or not created by this operator at all) and so were
	// left untouched.
	// +optional
	Conflicts int `json:"conflicts"`

	// failures is the number of target configmaps that could not be created or
	// updated during the last reconcile.
	// +optional
	Failures int `json:"failures"`
}

// ConfigMapRuleStatus summarises the outcome of a single rule.
type ConfigMapRuleStatus struct {
	// sourceConfigMap identifies the rule's source configmap as "namespace/name".
	SourceConfigMap string `json:"sourceConfigMap"`

	// sourceExists is whether the source configmap was found this reconcile.
	SourceExists bool `json:"sourceExists"`

	// targetNamespaces is the number of namespaces this rule matched.
	// +optional
	TargetNamespaces int `json:"targetNamespaces"`

	// configMapsInSync is the number of target configmaps in sync for this rule.
	// +optional
	ConfigMapsInSync int `json:"configMapsInSync"`

	// conflicts is the number of target configmap names matched by this rule
	// that are owned by something else and so were left untouched.
	// +optional
	Conflicts int `json:"conflicts"`

	// failures is the number of target configmaps that could not be copied for
	// this rule.
	// +optional
	Failures int `json:"failures"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Namespaces",type=integer,JSONPath=".status.summary.targetNamespaces"
// +kubebuilder:printcolumn:name="In Sync",type=integer,JSONPath=".status.summary.configMapsInSync"
// +kubebuilder:printcolumn:name="Failures",type=integer,JSONPath=".status.summary.failures"
// +kubebuilder:printcolumn:name="Conflicts",type=integer,JSONPath=".status.summary.conflicts",priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].reason",priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// ConfigMapCopier is the Schema for the configmapcopiers API
type ConfigMapCopier struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ConfigMapCopier
	// +required
	Spec ConfigMapCopierSpec `json:"spec"`

	// status defines the observed state of ConfigMapCopier
	// +optional
	Status ConfigMapCopierStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ConfigMapCopierList contains a list of ConfigMapCopier
type ConfigMapCopierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ConfigMapCopier `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConfigMapCopier{}, &ConfigMapCopierList{})
}
