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
	"k8s.io/apimachinery/pkg/runtime"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
)

// ConfigMapBuilderSpec defines how a ConfigMap named the same as the
// ConfigMapBuilder is generated from declared inputs by a script or template.
type ConfigMapBuilderSpec struct {
	// inputs are what the generator can read: plaintext constants, referenced
	// Secrets and ConfigMaps, operator-generated non-secret random material
	// (uuid, randomInt), and (Starlark-only) loadable libraries. Unlike
	// SecretBuilder there is no serviceAccount input (a minted token must not
	// land in a ConfigMap) and the generated kinds are curated to the
	// non-secret ones - generate secret material with a SecretBuilder and pull
	// the non-secret parts in via a secrets input.
	// +optional
	Inputs ConfigMapBuilderInputs `json:"inputs,omitzero"`

	// output shapes the produced ConfigMap. Its name is always the
	// ConfigMapBuilder's name; only labels and annotations are configurable
	// here (a ConfigMap has no type).
	// +optional
	Output ConfigMapBuilderOutput `json:"output,omitzero"`

	// generator selects exactly one engine - a Starlark script or a gotemplate
	// template - that produces the ConfigMap's data.
	// +required
	Generator ConfigMapBuilderGenerator `json:"generator"`

	// regeneration controls if and when the ConfigMap is rebuilt after it is
	// first generated. The default is to generate once and never touch it again.
	// +optional
	Regeneration secretsv1beta1.Regeneration `json:"regeneration,omitzero"`
}

// ConfigMapBuilderInputs declares everything the generator may reference.
type ConfigMapBuilderInputs struct {
	// constants is a free-form map of non-secret, typed configuration the
	// generator can reference. Values arrive with their natural type. It is not
	// OpenAPI-validated or pruned per key (author-controlled literals), and must
	// not hold secret material.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	Constants *runtime.RawExtension `json:"constants,omitempty"`

	// secrets references existing Secrets in this namespace, decoded for the
	// generator. Each entry binds a handle to either one Secret (secretRef) or a
	// set (selector). Take care that only non-secret fields (a username, a CA
	// certificate) flow into the produced ConfigMap - it is world-readable.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	Secrets []secretsv1beta1.SecretInput `json:"secrets,omitempty"`

	// configMaps references existing ConfigMaps in this namespace. Same shape
	// as secrets.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	ConfigMaps []secretsv1beta1.ConfigMapInput `json:"configMaps,omitempty"`

	// generated declares operator-produced random material. Only the
	// non-secret kinds are available (uuid, randomInt); secret material
	// (passwords, tokens, keys, certificates) belongs in a SecretBuilder.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	Generated []ConfigMapGeneratedValue `json:"generated,omitempty"`

	// libraries (Starlark only) declares load()-able modules sourced from a key
	// of a referenced ConfigMap.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	Libraries []secretsv1beta1.LibraryReference `json:"libraries,omitempty"`
}

// ConfigMapGeneratedValue declares one piece of operator-generated, non-secret
// material. Exactly one kind must be set. It is the curated subset of
// SecretBuilder's GeneratedValue: every excluded kind either is secret
// material or is only useful when its secret half lives somewhere usable.
// +kubebuilder:validation:XValidation:rule="has(self.uuid) != has(self.randomInt)",message="set exactly one of 'uuid' or 'randomInt'"
type ConfigMapGeneratedValue struct {
	// name is the generator binding handle. It must be a valid identifier
	// (dash-free) and is unique within the generated list.
	// +required
	// +kubebuilder:validation:Pattern=`^[A-Za-z_][A-Za-z0-9_]*$`
	Name string `json:"name"`

	// +optional
	UUID *secretsv1beta1.UUIDSpec `json:"uuid,omitempty"`
	// +optional
	RandomInt *secretsv1beta1.RandomIntSpec `json:"randomInt,omitempty"`
}

// ConfigMapBuilderOutput configures the produced ConfigMap. Its name is always
// the ConfigMapBuilder's name. There is no type (ConfigMaps have none) and no
// immutable flag (immutability conflicts with the regeneration model).
type ConfigMapBuilderOutput struct {
	// labels are merged with any the generator returns.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// annotations are merged with any the generator returns (the generator's win
	// on a shared key).
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ConfigMapBuilderGenerator selects exactly one engine. script is Starlark;
// template is gotemplate (a per-key template map).
// +kubebuilder:validation:XValidation:rule="has(self.script) != has(self.template)",message="set exactly one of 'script' or 'template'"
type ConfigMapBuilderGenerator struct {
	// script is a Starlark program returning the
	// configMap = {data, binaryData, labels, annotations} global. Placement decides the
	// destination map; values are raw str or bytes (never base64-encode -
	// the machinery handles encoding); data values must be valid UTF-8; a key
	// may not appear in both dicts.
	// +optional
	Script *string `json:"script,omitempty"`
	// template is a gotemplate engine: a per-key map of templates producing
	// data values. Templates render UTF-8 text only - there is deliberately no
	// binaryData support; binary output requires the script generator.
	// +optional
	Template *ConfigMapTemplateGenerator `json:"template,omitempty"`
}

// ConfigMapTemplateGenerator holds a per-key map of gotemplate templates, with
// optional labels and annotations (the gotemplate analogue of the Starlark
// configMap = {data, labels, annotations} global). Each label and annotation
// value is itself a gotemplate, so a plain literal works and a computed value
// is possible.
type ConfigMapTemplateGenerator struct {
	// data maps each output ConfigMap data key to a gotemplate producing its
	// value. Rendered values must be valid UTF-8.
	// +required
	Data map[string]string `json:"data"`

	// labels are merged onto the output ConfigMap (over spec.output.labels).
	// Each value is rendered as a gotemplate.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// annotations are merged onto the output ConfigMap (over
	// spec.output.annotations). Each value is rendered as a gotemplate. Keys
	// under the operator-owned configmaps.advok8s.io/ prefix are rejected.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ConfigMapBuilderStatus is the observed state of a ConfigMapBuilder.
type ConfigMapBuilderStatus struct {
	// observedGeneration is the .metadata.generation last processed.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the ConfigMapBuilder resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// configMapName is the name of the produced ConfigMap (always the
	// ConfigMapBuilder's name).
	// +optional
	ConfigMapName string `json:"configMapName,omitempty"`

	// generated is whether the output ConfigMap has been produced.
	// +optional
	Generated bool `json:"generated,omitempty"`

	// lastGeneratedTime is when the material was last (re)generated.
	// +optional
	LastGeneratedTime *metav1.Time `json:"lastGeneratedTime,omitempty"`

	// nextRotationTime is when the next rotateEvery rotation is due, when set.
	// +optional
	NextRotationTime *metav1.Time `json:"nextRotationTime,omitempty"`

	// observedRegenerateToken is the last-handled value of the regenerate annotation.
	// +optional
	ObservedRegenerateToken string `json:"observedRegenerateToken,omitempty"`

	// inputFingerprint folds input revisions/hashes; it drives onInputChange.
	// +optional
	InputFingerprint string `json:"inputFingerprint,omitempty"`

	// revision is a content-derived hash, also stamped on the output ConfigMap.
	// +optional
	Revision string `json:"revision,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:validation:XValidation:rule="self.metadata.name.size() <= 230",message="name must be at most 230 characters so the companion state Secret name fits the 253-character object name limit"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Generated",type=boolean,JSONPath=".status.generated"
// +kubebuilder:printcolumn:name="Last Generated",type=date,JSONPath=".status.lastGeneratedTime"
// +kubebuilder:printcolumn:name="Next Rotation",type=date,JSONPath=".status.nextRotationTime",priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].reason",priority=1
// +kubebuilder:printcolumn:name="Revision",type=string,JSONPath=".status.revision",priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// ConfigMapBuilder is the Schema for the configmapbuilders API
type ConfigMapBuilder struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ConfigMapBuilder
	// +required
	Spec ConfigMapBuilderSpec `json:"spec"`

	// status defines the observed state of ConfigMapBuilder
	// +optional
	Status ConfigMapBuilderStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ConfigMapBuilderList contains a list of ConfigMapBuilder
type ConfigMapBuilderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ConfigMapBuilder `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConfigMapBuilder{}, &ConfigMapBuilderList{})
}
