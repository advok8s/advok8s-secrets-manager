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

// Package builder holds the output-kind-agnostic pieces of the SecretBuilder
// pipeline - inputs resolver, generator engines, recipes and the output writer -
// so they can be reused by a future ConfigMapBuilder. This file is the inputs
// resolver: it turns a SecretBuilder's declared inputs into a typed bundle the
// generator engines consume, alongside an input fingerprint and a list of inputs
// that are not yet available.
package builder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// RevisionAnnotation is stamped on a produced Secret with a content-derived hash
// so downstream builders observe upstream changes. The resolver folds it into the
// input fingerprint when present on a referenced Secret.
const RevisionAnnotation = "secrets.advok8s.io/revision"

// rootCAConfigMap is the well-known ConfigMap kube-* publishes into every
// namespace; its ca.crt key is the cluster CA used for serviceAccount.cluster.caCert.
const (
	rootCAConfigMap = "kube-root-ca.crt"
	rootCAKey       = "ca.crt"
)

// Pending reasons, mirrored by the controller onto status conditions.
const (
	ReasonAwaitingInput     = "AwaitingInput"
	ReasonMissingServiceAcc = "MissingServiceAccount"
)

// TokenMinter mints a bound ServiceAccount token. It is an interface so the
// resolver can be unit-tested without a real API server (the fake client cannot
// service the TokenRequest subresource); production wires a clientset-backed
// implementation.
type TokenMinter interface {
	MintToken(ctx context.Context, namespace, serviceAccount string, audiences []string, expirationSeconds *int64) (string, error)
}

// Pending records one input that is not yet available, so the controller can hold
// generation in AwaitingInput (or MissingServiceAccount) rather than producing a
// degenerate Secret.
type Pending struct {
	Reason  string
	Message string
}

// Context is the ambient metadata exposed to the generator as input.context.
type Context struct {
	Namespace   string
	Name        string
	Labels      map[string]string
	Annotations map[string]string
	UID         string
	GeneratedAt time.Time
}

// ResolvedSecret is one decoded Secret exposed to the generator.
type ResolvedSecret struct {
	Name        string
	Type        string
	UID         string
	Labels      map[string]string
	Annotations map[string]string
	Data        map[string]string // decoded (the generator never sees base64)
}

// ResolvedConfigMap is one ConfigMap exposed to the generator.
type ResolvedConfigMap struct {
	Name        string
	UID         string
	Labels      map[string]string
	Annotations map[string]string
	Data        map[string]string // plaintext
	BinaryData  map[string][]byte // decoded bytes
}

// SecretBinding is what a secrets handle binds to: a single Secret for a
// secretRef, or a (name-sorted) list for a selector.
type SecretBinding struct {
	Single *ResolvedSecret
	List   []*ResolvedSecret
	IsList bool
}

// ConfigMapBinding is the ConfigMap equivalent of SecretBinding.
type ConfigMapBinding struct {
	Single *ResolvedConfigMap
	List   []*ResolvedConfigMap
	IsList bool
}

// ResolvedServiceAccount is the serviceAccount input with a freshly minted token.
type ResolvedServiceAccount struct {
	Name          string
	Namespace     string
	Token         string
	ClusterServer string
	ClusterCACert string
}

// ResolvedInputs is the typed bundle the generator engines consume. Generated
// holds operator-produced material and is populated by the generation phase, not
// the resolver.
type ResolvedInputs struct {
	Constants      map[string]any
	Context        Context
	Secrets        map[string]*SecretBinding
	ConfigMaps     map[string]*ConfigMapBinding
	ServiceAccount *ResolvedServiceAccount
	Libraries      map[string]string // module name -> source
	Generated      map[string]any
}

// Resolver resolves a SecretBuilder's declared inputs against the cluster.
type Resolver struct {
	Client client.Client
	// TokenMinter mints ServiceAccount tokens. Required only when a SecretBuilder
	// declares a serviceAccount input.
	TokenMinter TokenMinter
	// ClusterServer is the API server URL exposed as serviceAccount.cluster.server.
	// Populated from ClusterAPIServerURL() at operator startup (the in-cluster
	// address); only the internal endpoint is exposed, not any external one.
	ClusterServer string
}

// ClusterAPIServerURL returns the in-cluster Kubernetes API server URL, derived
// from the standard KUBERNETES_SERVICE_HOST / KUBERNETES_SERVICE_PORT environment
// variables (present in every pod), falling back to the in-cluster DNS name
// https://kubernetes.default.svc when they are unset. This is deliberately the
// internal endpoint - suitable for in-cluster consumers of a generated kubeconfig;
// no attempt is made to discover an external API server address.
func ClusterAPIServerURL() string {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host != "" && port != "" {
		return "https://" + net.JoinHostPort(host, port)
	}
	return "https://kubernetes.default.svc"
}

// Resolve turns the SecretBuilder's inputs into a bundle. It returns the resolved
// inputs (always non-nil), any pending inputs (the caller holds generation when
// non-empty), and an error for hard failures (API errors, invalid spec). The
// generatedAt timestamp is supplied by the caller (the persisted "now"), never
// read from a clock here, to keep generation deterministic.
func (r *Resolver) Resolve(ctx context.Context, sb *secretsv1beta1.SecretBuilder, generatedAt time.Time) (*ResolvedInputs, []Pending, error) {
	resolved := &ResolvedInputs{
		Context: Context{
			Namespace:   sb.Namespace,
			Name:        sb.Name,
			Labels:      sb.Labels,
			Annotations: sb.Annotations,
			UID:         string(sb.UID),
			GeneratedAt: generatedAt,
		},
		Secrets:    map[string]*SecretBinding{},
		ConfigMaps: map[string]*ConfigMapBinding{},
		Libraries:  map[string]string{},
		Generated:  map[string]any{},
	}

	var pending []Pending

	constants, err := decodeConstants(sb.Spec.Inputs.Constants)
	if err != nil {
		return resolved, nil, fmt.Errorf("inputs.constants: %w", err)
	}
	resolved.Constants = constants

	secretsPending, err := r.resolveSecrets(ctx, sb, resolved)
	if err != nil {
		return resolved, nil, err
	}
	pending = append(pending, secretsPending...)

	configMapsPending, err := r.resolveConfigMaps(ctx, sb, resolved)
	if err != nil {
		return resolved, nil, err
	}
	pending = append(pending, configMapsPending...)

	if err := r.resolveLibraries(sb, resolved); err != nil {
		return resolved, nil, err
	}

	saPending, err := r.resolveServiceAccount(ctx, sb, resolved)
	if err != nil {
		return resolved, nil, err
	}
	pending = append(pending, saPending...)

	return resolved, pending, nil
}

// Fingerprint is a stable hash of the external inputs that should trigger a
// refresh when they change (onInputChange). It deliberately excludes the minted
// token and generatedAt (non-deterministic) and generated material (stable, and
// owned by the generation phase).
func (in *ResolvedInputs) Fingerprint() string {
	h := sha256.New()
	enc := json.NewEncoder(h)

	// Constants, in canonical (json.Marshal sorts map keys) form.
	_ = enc.Encode(in.Constants)
	// The SecretBuilder's own labels/annotations fold in (they are referenceable
	// context and changing them is an input change).
	_ = enc.Encode(in.Context.Labels)
	_ = enc.Encode(in.Context.Annotations)

	for _, handle := range sortedKeys(in.Secrets) {
		_, _ = fmt.Fprintf(h, "secret/%s\n", handle)
		for _, s := range bindingSecrets(in.Secrets[handle]) {
			_, _ = fmt.Fprintf(h, "%s=%s\n", s.Name, secretRevision(s))
		}
	}

	for _, handle := range sortedKeys(in.ConfigMaps) {
		_, _ = fmt.Fprintf(h, "configmap/%s\n", handle)
		for _, c := range bindingConfigMaps(in.ConfigMaps[handle]) {
			_, _ = fmt.Fprintf(h, "%s=%s\n", c.Name, configMapRevision(c))
		}
	}

	for _, name := range sortedKeys(in.Libraries) {
		_, _ = fmt.Fprintf(h, "library/%s=%s\n", name, hashString(in.Libraries[name]))
	}

	if in.ServiceAccount != nil {
		_, _ = fmt.Fprintf(h, "serviceaccount/%s\n", in.ServiceAccount.Name)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func (r *Resolver) resolveSecrets(ctx context.Context, sb *secretsv1beta1.SecretBuilder, resolved *ResolvedInputs) ([]Pending, error) {
	var pending []Pending

	for i := range sb.Spec.Inputs.Secrets {
		input := sb.Spec.Inputs.Secrets[i]

		switch {
		case input.SecretRef != nil:
			var secret corev1.Secret
			err := r.Client.Get(ctx, client.ObjectKey{Namespace: sb.Namespace, Name: input.SecretRef.Name}, &secret)
			if apierrors.IsNotFound(err) {
				pending = append(pending, Pending{ReasonAwaitingInput, fmt.Sprintf("secret %q for input %q not found", input.SecretRef.Name, input.Name)})
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("fetching secret %q for input %q: %w", input.SecretRef.Name, input.Name, err)
			}
			resolved.Secrets[input.Name] = &SecretBinding{Single: resolveSecret(&secret)}

		case input.Selector != nil:
			var list corev1.SecretList
			if err := r.Client.List(ctx, &list, client.InNamespace(sb.Namespace)); err != nil {
				return nil, fmt.Errorf("listing secrets for input %q: %w", input.Name, err)
			}
			var matched []*ResolvedSecret
			for j := range list.Items {
				if input.Selector.Matches(&list.Items[j].ObjectMeta) {
					matched = append(matched, resolveSecret(&list.Items[j]))
				}
			}
			sort.Slice(matched, func(a, b int) bool { return matched[a].Name < matched[b].Name })
			if len(matched) == 0 && !input.AllowEmpty {
				pending = append(pending, Pending{ReasonAwaitingInput, fmt.Sprintf("selector for input %q matched no secrets", input.Name)})
				continue
			}
			resolved.Secrets[input.Name] = &SecretBinding{List: matched, IsList: true}

		default:
			return nil, fmt.Errorf("inputs.secrets %q: set exactly one of secretRef or selector", input.Name)
		}
	}

	return pending, nil
}

func (r *Resolver) resolveConfigMaps(ctx context.Context, sb *secretsv1beta1.SecretBuilder, resolved *ResolvedInputs) ([]Pending, error) {
	var pending []Pending

	for i := range sb.Spec.Inputs.ConfigMaps {
		input := sb.Spec.Inputs.ConfigMaps[i]

		switch {
		case input.ConfigMapRef != nil:
			var cm corev1.ConfigMap
			err := r.Client.Get(ctx, client.ObjectKey{Namespace: sb.Namespace, Name: input.ConfigMapRef.Name}, &cm)
			if apierrors.IsNotFound(err) {
				pending = append(pending, Pending{ReasonAwaitingInput, fmt.Sprintf("configMap %q for input %q not found", input.ConfigMapRef.Name, input.Name)})
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("fetching configMap %q for input %q: %w", input.ConfigMapRef.Name, input.Name, err)
			}
			resolved.ConfigMaps[input.Name] = &ConfigMapBinding{Single: resolveConfigMap(&cm)}

		case input.Selector != nil:
			var list corev1.ConfigMapList
			if err := r.Client.List(ctx, &list, client.InNamespace(sb.Namespace)); err != nil {
				return nil, fmt.Errorf("listing configMaps for input %q: %w", input.Name, err)
			}
			var matched []*ResolvedConfigMap
			for j := range list.Items {
				if input.Selector.Matches(&list.Items[j].ObjectMeta) {
					matched = append(matched, resolveConfigMap(&list.Items[j]))
				}
			}
			sort.Slice(matched, func(a, b int) bool { return matched[a].Name < matched[b].Name })
			if len(matched) == 0 && !input.AllowEmpty {
				pending = append(pending, Pending{ReasonAwaitingInput, fmt.Sprintf("selector for input %q matched no configMaps", input.Name)})
				continue
			}
			resolved.ConfigMaps[input.Name] = &ConfigMapBinding{List: matched, IsList: true}

		default:
			return nil, fmt.Errorf("inputs.configMaps %q: set exactly one of configMapRef or selector", input.Name)
		}
	}

	return pending, nil
}

// resolveLibraries sources each load() module from a key of a referenced
// ConfigMap (a single configMapRef handle). It runs after configMaps are resolved.
func (r *Resolver) resolveLibraries(sb *secretsv1beta1.SecretBuilder, resolved *ResolvedInputs) error {
	for i := range sb.Spec.Inputs.Libraries {
		lib := sb.Spec.Inputs.Libraries[i]

		binding, ok := resolved.ConfigMaps[lib.From]
		if !ok {
			// The referenced configMap may be pending (absent) this round; skip
			// quietly so the library resolves once its source ConfigMap appears.
			continue
		}
		if binding.IsList || binding.Single == nil {
			return fmt.Errorf("library %q: 'from' handle %q must reference a single configMap (configMapRef), not a selector", lib.Name, lib.From)
		}
		source, ok := binding.Single.Data[lib.Key]
		if !ok {
			return fmt.Errorf("library %q: key %q not found in configMap %q", lib.Name, lib.Key, binding.Single.Name)
		}
		resolved.Libraries[lib.Name] = source
	}

	return nil
}

func (r *Resolver) resolveServiceAccount(ctx context.Context, sb *secretsv1beta1.SecretBuilder, resolved *ResolvedInputs) ([]Pending, error) {
	spec := sb.Spec.Inputs.ServiceAccount
	if spec == nil {
		return nil, nil
	}

	var sa corev1.ServiceAccount
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: sb.Namespace, Name: spec.ServiceAccountRef.Name}, &sa)
	if apierrors.IsNotFound(err) {
		return []Pending{{ReasonMissingServiceAcc, fmt.Sprintf("serviceAccount %q not found", spec.ServiceAccountRef.Name)}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fetching serviceAccount %q: %w", spec.ServiceAccountRef.Name, err)
	}

	if r.TokenMinter == nil {
		return nil, fmt.Errorf("serviceAccount input declared but no token minter configured")
	}

	token, err := r.TokenMinter.MintToken(ctx, sb.Namespace, spec.ServiceAccountRef.Name, spec.Audiences, spec.ExpirationSeconds)
	if err != nil {
		return nil, fmt.Errorf("minting token for serviceAccount %q: %w", spec.ServiceAccountRef.Name, err)
	}

	resolved.ServiceAccount = &ResolvedServiceAccount{
		Name:          spec.ServiceAccountRef.Name,
		Namespace:     sb.Namespace,
		Token:         token,
		ClusterServer: r.ClusterServer,
		ClusterCACert: r.clusterCACert(ctx, sb.Namespace),
	}

	return nil, nil
}

// clusterCACert reads the cluster CA from the kube-root-ca.crt ConfigMap, best
// effort - an absent CA is not fatal (the server URL may suffice for the use).
func (r *Resolver) clusterCACert(ctx context.Context, namespace string) string {
	var cm corev1.ConfigMap
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: rootCAConfigMap}, &cm); err != nil {
		return ""
	}
	return cm.Data[rootCAKey]
}

func resolveSecret(secret *corev1.Secret) *ResolvedSecret {
	data := make(map[string]string, len(secret.Data))
	for k, v := range secret.Data {
		data[k] = string(v)
	}
	return &ResolvedSecret{
		Name:        secret.Name,
		Type:        string(secret.Type),
		UID:         string(secret.UID),
		Labels:      secret.Labels,
		Annotations: secret.Annotations,
		Data:        data,
	}
}

func resolveConfigMap(cm *corev1.ConfigMap) *ResolvedConfigMap {
	return &ResolvedConfigMap{
		Name:        cm.Name,
		UID:         string(cm.UID),
		Labels:      cm.Labels,
		Annotations: cm.Annotations,
		Data:        cm.Data,
		BinaryData:  cm.BinaryData,
	}
}

// decodeConstants unmarshals the free-form constants object into a typed map.
func decodeConstants(raw *runtime.RawExtension) (map[string]any, error) {
	if raw == nil || len(raw.Raw) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw.Raw, &out); err != nil {
		return nil, fmt.Errorf("decoding constants: %w", err)
	}
	return out, nil
}

func secretRevision(s *ResolvedSecret) string {
	if rev := s.Annotations[RevisionAnnotation]; rev != "" {
		return rev
	}
	h := sha256.New()
	for _, k := range sortedKeys(s.Data) {
		_, _ = fmt.Fprintf(h, "%s=%s\n", k, s.Data[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func configMapRevision(c *ResolvedConfigMap) string {
	if rev := c.Annotations[RevisionAnnotation]; rev != "" {
		return rev
	}
	h := sha256.New()
	for _, k := range sortedKeys(c.Data) {
		_, _ = fmt.Fprintf(h, "%s=%s\n", k, c.Data[k])
	}
	for _, k := range sortedKeysBytes(c.BinaryData) {
		_, _ = fmt.Fprintf(h, "%s=%x\n", k, c.BinaryData[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func bindingSecrets(b *SecretBinding) []*ResolvedSecret {
	if b.IsList {
		return b.List
	}
	if b.Single != nil {
		return []*ResolvedSecret{b.Single}
	}
	return nil
}

func bindingConfigMaps(b *ConfigMapBinding) []*ResolvedConfigMap {
	if b.IsList {
		return b.List
	}
	if b.Single != nil {
		return []*ResolvedConfigMap{b.Single}
	}
	return nil
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysBytes(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
