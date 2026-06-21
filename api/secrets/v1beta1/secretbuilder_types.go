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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/advok8s/advok8s-secrets-manager/pkg/selectors"
)

// SecretBuilderSpec defines how a Secret named the same as the SecretBuilder is
// generated from declared inputs by a script or template.
type SecretBuilderSpec struct {
	// inputs are what the generator can read: plaintext constants, referenced
	// Secrets and ConfigMaps, a service account token, operator-generated random
	// material, and (Starlark-only) loadable libraries.
	// +optional
	Inputs SecretBuilderInputs `json:"inputs,omitzero"`

	// output shapes the produced Secret. Its name is always the SecretBuilder's
	// name; only the type, labels and annotations are configurable here.
	// +optional
	Output SecretBuilderOutput `json:"output,omitzero"`

	// generator selects exactly one engine - a Starlark script or a gotemplate
	// template - that produces the Secret's data.
	// +required
	Generator SecretBuilderGenerator `json:"generator"`

	// regeneration controls if and when the Secret is rebuilt after it is first
	// generated. The default is to generate once and never touch it again.
	// +optional
	Regeneration Regeneration `json:"regeneration,omitzero"`
}

// SecretBuilderInputs declares everything the generator may reference.
type SecretBuilderInputs struct {
	// constants is a free-form map of non-secret, typed configuration the
	// generator can reference. Values arrive with their natural type. It is not
	// OpenAPI-validated or pruned per key (author-controlled literals), and must
	// not hold secret material - those come from secrets or generated.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	Constants *runtime.RawExtension `json:"constants,omitempty"`

	// secrets references existing Secrets in this namespace, decoded for the
	// generator. Each entry binds a handle to either one Secret (secretRef) or a
	// set (selector).
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	Secrets []SecretInput `json:"secrets,omitempty"`

	// configMaps references existing ConfigMaps in this namespace for non-secret
	// data. Same shape as secrets.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	ConfigMaps []ConfigMapInput `json:"configMaps,omitempty"`

	// serviceAccount, when set, mints a bound token for the named ServiceAccount
	// (via the TokenRequest API) for kubeconfig-style outputs.
	// +optional
	ServiceAccount *ServiceAccountInput `json:"serviceAccount,omitempty"`

	// generated declares operator-produced random material (passwords, tokens,
	// keys, certificates, ...). All entropy lives here so the script stays
	// deterministic.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	Generated []GeneratedValue `json:"generated,omitempty"`

	// libraries (Starlark only) declares load()-able modules sourced from a key of
	// a referenced ConfigMap.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	Libraries []LibraryReference `json:"libraries,omitempty"`
}

// SecretInput binds a handle to one Secret (secretRef) or a matched set
// (selector). Exactly one of the two must be set.
// +kubebuilder:validation:XValidation:rule="has(self.secretRef) != has(self.selector)",message="set exactly one of 'secretRef' or 'selector'"
// +kubebuilder:validation:XValidation:rule="!has(self.selector) || has(self.selector.nameSelector) || has(self.selector.labelSelector) || has(self.selector.ownerSelector) || has(self.selector.uidSelector)",message="'selector' must set at least one sub-selector"
type SecretInput struct {
	// name is the generator binding handle. It must be a valid identifier
	// (dash-free) and is unique within the secrets list.
	// +required
	// +kubebuilder:validation:Pattern=`^[A-Za-z_][A-Za-z0-9_]*$`
	Name string `json:"name"`

	// secretRef references exactly one Secret in this namespace by name.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// selector matches a set of Secrets in this namespace; the handle binds a list.
	// +optional
	Selector *selectors.ResourceSelector `json:"selector,omitempty"`

	// allowEmpty permits a selector to match zero Secrets (binding an empty list)
	// instead of holding generation in AwaitingInput.
	// +optional
	AllowEmpty bool `json:"allowEmpty,omitempty"`
}

// ConfigMapInput binds a handle to one ConfigMap (configMapRef) or a matched set
// (selector). Exactly one of the two must be set.
// +kubebuilder:validation:XValidation:rule="has(self.configMapRef) != has(self.selector)",message="set exactly one of 'configMapRef' or 'selector'"
// +kubebuilder:validation:XValidation:rule="!has(self.selector) || has(self.selector.nameSelector) || has(self.selector.labelSelector) || has(self.selector.ownerSelector) || has(self.selector.uidSelector)",message="'selector' must set at least one sub-selector"
type ConfigMapInput struct {
	// name is the generator binding handle. It must be a valid identifier
	// (dash-free) and is unique within the configMaps list.
	// +required
	// +kubebuilder:validation:Pattern=`^[A-Za-z_][A-Za-z0-9_]*$`
	Name string `json:"name"`

	// configMapRef references exactly one ConfigMap in this namespace by name.
	// +optional
	ConfigMapRef *corev1.LocalObjectReference `json:"configMapRef,omitempty"`

	// selector matches a set of ConfigMaps in this namespace; the handle binds a list.
	// +optional
	Selector *selectors.ResourceSelector `json:"selector,omitempty"`

	// allowEmpty permits a selector to match zero ConfigMaps (binding an empty list).
	// +optional
	AllowEmpty bool `json:"allowEmpty,omitempty"`
}

// ServiceAccountInput names a ServiceAccount for which the operator mints a bound
// token, passed through to the TokenRequest API.
type ServiceAccountInput struct {
	// serviceAccountRef references the ServiceAccount in this namespace.
	// +required
	ServiceAccountRef corev1.LocalObjectReference `json:"serviceAccountRef"`

	// audiences sets the token's audiences. Omit for the API server's default
	// audience (the kubeconfig/cluster case).
	// +optional
	Audiences []string `json:"audiences,omitempty"`

	// expirationSeconds is the requested token TTL. The API server clamps it to
	// [600, its configured maximum].
	// +optional
	// +kubebuilder:validation:Minimum=600
	ExpirationSeconds *int64 `json:"expirationSeconds,omitempty"`
}

// GeneratedValue declares one piece of operator-generated material. Exactly one
// kind must be set.
// +kubebuilder:validation:XValidation:rule="[has(self.password),has(self.token),has(self.randomInt),has(self.bytes),has(self.uuid),has(self.rsaPrivateKey),has(self.ecdsaPrivateKey),has(self.sshKeyPair),has(self.caCertificate),has(self.tlsCertificate)].filter(x, x).size() == 1",message="set exactly one generated kind"
type GeneratedValue struct {
	// name is the generator binding handle. It must be a valid identifier
	// (dash-free) and is unique within the generated list.
	// +required
	// +kubebuilder:validation:Pattern=`^[A-Za-z_][A-Za-z0-9_]*$`
	Name string `json:"name"`

	// +optional
	Password *PasswordSpec `json:"password,omitempty"`
	// +optional
	Token *TokenSpec `json:"token,omitempty"`
	// +optional
	RandomInt *RandomIntSpec `json:"randomInt,omitempty"`
	// +optional
	Bytes *BytesSpec `json:"bytes,omitempty"`
	// +optional
	UUID *UUIDSpec `json:"uuid,omitempty"`
	// +optional
	RSAPrivateKey *RSAPrivateKeySpec `json:"rsaPrivateKey,omitempty"`
	// +optional
	ECDSAPrivateKey *ECDSAPrivateKeySpec `json:"ecdsaPrivateKey,omitempty"`
	// +optional
	SSHKeyPair *SSHKeyPairSpec `json:"sshKeyPair,omitempty"`
	// +optional
	CACertificate *CACertificateSpec `json:"caCertificate,omitempty"`
	// +optional
	TLSCertificate *TLSCertificateSpec `json:"tlsCertificate,omitempty"`
}

// PasswordSpec generates a human-facing password with composition rules.
type PasswordSpec struct {
	// +required
	// +kubebuilder:validation:Minimum=1
	Length int `json:"length"`
	// +optional
	// +kubebuilder:default=true
	Upper *bool `json:"upper,omitempty"`
	// +optional
	// +kubebuilder:default=true
	Lower *bool `json:"lower,omitempty"`
	// +optional
	// +kubebuilder:default=true
	Digits *bool `json:"digits,omitempty"`
	// +optional
	// +kubebuilder:default=true
	Symbols *bool `json:"symbols,omitempty"`
	// +optional
	MinUpper int `json:"minUpper,omitempty"`
	// +optional
	MinLower int `json:"minLower,omitempty"`
	// +optional
	MinDigits int `json:"minDigits,omitempty"`
	// +optional
	MinSymbols int `json:"minSymbols,omitempty"`
	// +optional
	SymbolSet string `json:"symbolSet,omitempty"`
	// +optional
	ExcludeAmbiguous bool `json:"excludeAmbiguous,omitempty"`
	// +optional
	ExcludeCharacters string `json:"excludeCharacters,omitempty"`
	// +optional
	// +kubebuilder:default=true
	AllowRepeat *bool `json:"allowRepeat,omitempty"`
	// charset, if set, is a literal alphabet that overrides the class toggles.
	// +optional
	Charset string `json:"charset,omitempty"`
}

// TokenSpec generates a machine-facing token from a uniform alphabet.
type TokenSpec struct {
	// length is the number of random characters, excluding any prefix.
	// +required
	// +kubebuilder:validation:Minimum=1
	Length int `json:"length"`
	// +optional
	// +kubebuilder:validation:Enum=alphanumeric;lowerAlphanumeric;hex;base32;base64url;custom
	// +kubebuilder:default=alphanumeric
	Alphabet string `json:"alphabet,omitempty"`
	// charset is the alphabet when alphabet is "custom".
	// +optional
	Charset string `json:"charset,omitempty"`
	// prefix is prepended verbatim (e.g. "mytool_").
	// +optional
	Prefix string `json:"prefix,omitempty"`
}

// RandomIntSpec generates a bounded random integer in the inclusive range
// [min, max].
// +kubebuilder:validation:XValidation:rule="self.max >= self.min",message="max must be >= min"
type RandomIntSpec struct {
	// +required
	Max int64 `json:"max"`
	// +optional
	// +kubebuilder:default=0
	Min int64 `json:"min,omitempty"`
}

// BytesSpec generates raw random bytes, surfaced encoded as a string.
type BytesSpec struct {
	// +required
	// +kubebuilder:validation:Minimum=1
	Length int `json:"length"`
	// +optional
	// +kubebuilder:validation:Enum=base64;base64url;hex;base32
	// +kubebuilder:default=base64
	Encoding string `json:"encoding,omitempty"`
}

// UUIDSpec generates a random UUID.
type UUIDSpec struct {
	// version is 4 (fully random) or 7 (time-ordered from the generation time).
	// +optional
	// +kubebuilder:validation:Enum=4;7
	// +kubebuilder:default=4
	Version int `json:"version,omitempty"`
}

// RSAPrivateKeySpec generates a bare RSA private key (PEM), no certificate.
type RSAPrivateKeySpec struct {
	// +optional
	// +kubebuilder:default=2048
	RSABits int `json:"rsaBits,omitempty"`
}

// ECDSAPrivateKeySpec generates a bare ECDSA private key (PEM), no certificate.
type ECDSAPrivateKeySpec struct {
	// +optional
	// +kubebuilder:validation:Enum=P256;P384;P521
	// +kubebuilder:default=P256
	ECDSACurve string `json:"ecdsaCurve,omitempty"`
}

// SSHKeyPairSpec generates an OpenSSH keypair.
type SSHKeyPairSpec struct {
	// +optional
	// +kubebuilder:validation:Enum=Ed25519;RSA;ECDSA
	// +kubebuilder:default=Ed25519
	Algorithm string `json:"algorithm,omitempty"`
	// +optional
	// +kubebuilder:default=2048
	RSABits int `json:"rsaBits,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=P256;P384;P521
	// +kubebuilder:default=P256
	ECDSACurve string `json:"ecdsaCurve,omitempty"`
	// comment is the trailing comment on the public key.
	// +optional
	Comment string `json:"comment,omitempty"`
}

// CertificateSubject holds optional distinguished-name parts for a certificate.
type CertificateSubject struct {
	// +optional
	Organizations []string `json:"organizations,omitempty"`
	// +optional
	OrganizationalUnits []string `json:"organizationalUnits,omitempty"`
	// +optional
	Countries []string `json:"countries,omitempty"`
	// +optional
	Localities []string `json:"localities,omitempty"`
	// +optional
	Provinces []string `json:"provinces,omitempty"`
	// +optional
	PostalCodes []string `json:"postalCodes,omitempty"`
}

// IssuerReference points at the CA that signs a certificate: a caCertificate
// declared earlier in this builder (generated) or a CA in an input Secret
// (secret). Exactly one must be set. Omitting the whole issuerRef means
// self-signed.
// +kubebuilder:validation:XValidation:rule="has(self.generated) != has(self.secret)",message="set exactly one of 'generated' or 'secret'"
type IssuerReference struct {
	// generated names a caCertificate generated entry in this builder.
	// +optional
	Generated string `json:"generated,omitempty"`
	// secret names an input Secret holding a CA (tls.crt + tls.key).
	// +optional
	Secret string `json:"secret,omitempty"`
}

// CACertificateSpec generates a CA certificate and key.
type CACertificateSpec struct {
	// +optional
	CommonName string `json:"commonName,omitempty"`
	// +optional
	Subject *CertificateSubject `json:"subject,omitempty"`
	// +optional
	Duration *metav1.Duration `json:"duration,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=RSA;ECDSA;Ed25519
	// +kubebuilder:default=RSA
	Algorithm string `json:"algorithm,omitempty"`
	// +optional
	// +kubebuilder:default=2048
	RSABits int `json:"rsaBits,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=P256;P384;P521
	// +kubebuilder:default=P256
	ECDSACurve string `json:"ecdsaCurve,omitempty"`
	// issuerRef, when set, makes this an intermediate CA signed by the parent;
	// omitted means a self-signed root.
	// +optional
	IssuerRef *IssuerReference `json:"issuerRef,omitempty"`
	// maxPathLen bounds the number of intermediate CAs below this one.
	// +optional
	MaxPathLen *int `json:"maxPathLen,omitempty"`
}

// TLSCertificateSpec generates a leaf certificate and key.
type TLSCertificateSpec struct {
	// +optional
	CommonName string `json:"commonName,omitempty"`
	// +optional
	Subject *CertificateSubject `json:"subject,omitempty"`
	// +optional
	Duration *metav1.Duration `json:"duration,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=RSA;ECDSA;Ed25519
	// +kubebuilder:default=RSA
	Algorithm string `json:"algorithm,omitempty"`
	// +optional
	// +kubebuilder:default=2048
	RSABits int `json:"rsaBits,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=P256;P384;P521
	// +kubebuilder:default=P256
	ECDSACurve string `json:"ecdsaCurve,omitempty"`
	// issuerRef, when set, makes this CA-signed; omitted means self-signed.
	// +optional
	IssuerRef *IssuerReference `json:"issuerRef,omitempty"`
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`
	// +optional
	IPAddresses []string `json:"ipAddresses,omitempty"`
	// +optional
	URIs []string `json:"uris,omitempty"`
	// +optional
	EmailAddresses []string `json:"emailAddresses,omitempty"`
	// usages are the key usages / extended key usages.
	// +optional
	Usages []string `json:"usages,omitempty"`
}

// LibraryReference (Starlark only) declares a load()-able module sourced from a
// key of a referenced ConfigMap.
type LibraryReference struct {
	// name is the load() module name. It must be a valid identifier (dash-free)
	// and is unique within the libraries list.
	// +required
	// +kubebuilder:validation:Pattern=`^[A-Za-z_][A-Za-z0-9_]*$`
	Name string `json:"name"`

	// from is the handle of an inputs.configMaps entry to source the module from.
	// +required
	From string `json:"from"`

	// key is the data key within that ConfigMap holding the module source.
	// +required
	Key string `json:"key"`
}

// SecretBuilderOutput configures the produced Secret. Its name is always the
// SecretBuilder's name.
type SecretBuilderOutput struct {
	// type is the Secret type (defaults to Opaque).
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`
	// labels are merged with any the generator returns.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// annotations are merged with any the generator returns (the generator's win
	// on a shared key).
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// SecretBuilderGenerator selects exactly one engine. script is Starlark; template
// is gotemplate (a per-key template map).
// +kubebuilder:validation:XValidation:rule="has(self.script) != has(self.template)",message="set exactly one of 'script' or 'template'"
type SecretBuilderGenerator struct {
	// script is a Starlark program returning the secret = {data, labels, annotations, type} global.
	// +optional
	Script *string `json:"script,omitempty"`
	// template is a gotemplate engine: a per-key map of templates producing data values.
	// +optional
	Template *TemplateGenerator `json:"template,omitempty"`
}

// TemplateGenerator holds a per-key map of gotemplate templates, with optional
// type, labels and annotations (the gotemplate analogue of the Starlark
// secret = {data, type, labels, annotations} global). type and each label and
// annotation value are themselves gotemplates, so a plain literal works and a
// computed value is possible.
type TemplateGenerator struct {
	// data maps each output Secret data key to a gotemplate producing its value.
	// +required
	Data map[string]string `json:"data"`

	// type optionally overrides spec.output.type. It is rendered as a gotemplate.
	// +optional
	Type string `json:"type,omitempty"`

	// labels are merged onto the output Secret (over spec.output.labels). Each
	// value is rendered as a gotemplate.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// annotations are merged onto the output Secret (over
	// spec.output.annotations). Each value is rendered as a gotemplate. Keys
	// under the operator-owned secrets.advok8s.io/ prefix are rejected.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Regeneration controls if and when the Secret is rebuilt. The zero value means
// generate once and never again.
type Regeneration struct {
	// onInputChange re-runs the generator when inputs or spec change, keeping
	// generated material stable (a refresh).
	// +optional
	OnInputChange bool `json:"onInputChange,omitempty"`
	// rotateEvery rotates the material this long after it was generated.
	// +optional
	RotateEvery *metav1.Duration `json:"rotateEvery,omitempty"`
	// rotateGenerated, on a rotate, also re-rolls the random material (otherwise
	// only the generation timestamp advances).
	// +optional
	RotateGenerated bool `json:"rotateGenerated,omitempty"`
}

// SecretBuilderStatus is the observed state of a SecretBuilder.
type SecretBuilderStatus struct {
	// observedGeneration is the .metadata.generation last processed.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the SecretBuilder resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// secretName is the name of the produced Secret (always the SecretBuilder's name).
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// generated is whether the output Secret has been produced.
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

	// revision is a content-derived hash, also stamped on the output Secret.
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

// SecretBuilder is the Schema for the secretbuilders API
type SecretBuilder struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecretBuilder
	// +required
	Spec SecretBuilderSpec `json:"spec"`

	// status defines the observed state of SecretBuilder
	// +optional
	Status SecretBuilderStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecretBuilderList contains a list of SecretBuilder
type SecretBuilderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecretBuilder `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecretBuilder{}, &SecretBuilderList{})
}
