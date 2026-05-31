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

package builder

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
	"github.com/advok8s/advok8s-secrets-manager/pkg/selectors"
)

var fixedTime = time.Unix(1700000000, 0).UTC()

type stubMinter struct {
	token string
	err   error
	calls int
}

func (m *stubMinter) MintToken(_ context.Context, _, _ string, _ []string, _ *int64) (string, error) {
	m.calls++
	return m.token, m.err
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	if err := secretsv1beta1.AddToScheme(scheme); err != nil {
		t.Fatalf("add secretsv1beta1: %v", err)
	}
	return scheme
}

func newResolver(t *testing.T, minter TokenMinter, objs ...client.Object) *Resolver {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(objs...).Build()
	return &Resolver{Client: c, TokenMinter: minter, ClusterServer: "https://api.example"}
}

func builderFor(spec secretsv1beta1.SecretBuilderSpec) *secretsv1beta1.SecretBuilder {
	return &secretsv1beta1.SecretBuilder{
		ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "app", UID: "sb-uid"},
		Spec:       spec,
	}
}

func secret(name string, labels map[string]string, data map[string]string) *corev1.Secret {
	bin := map[string][]byte{}
	for k, v := range data {
		bin[k] = []byte(v)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app", Labels: labels},
		Type:       corev1.SecretTypeOpaque,
		Data:       bin,
	}
}

func resolve(t *testing.T, r *Resolver, sb *secretsv1beta1.SecretBuilder) (*ResolvedInputs, []Pending) {
	t.Helper()
	in, pending, err := r.Resolve(context.Background(), sb, fixedTime)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	return in, pending
}

func TestResolveConstantsAndContext(t *testing.T) {
	r := newResolver(t, nil)
	sb := builderFor(secretsv1beta1.SecretBuilderSpec{
		Inputs: secretsv1beta1.SecretBuilderInputs{
			Constants: &runtime.RawExtension{Raw: []byte(`{"realm":"Demo","replicas":3,"tls":true}`)},
		},
	})
	sb.Labels = map[string]string{"team": "platform"}

	in, pending := resolve(t, r, sb)
	if len(pending) != 0 {
		t.Fatalf("unexpected pending: %v", pending)
	}
	if in.Constants["realm"] != "Demo" {
		t.Errorf("realm = %v", in.Constants["realm"])
	}
	if in.Constants["replicas"] != float64(3) { // JSON numbers decode to float64
		t.Errorf("replicas = %v (%T)", in.Constants["replicas"], in.Constants["replicas"])
	}
	if in.Constants["tls"] != true {
		t.Errorf("tls = %v", in.Constants["tls"])
	}
	if in.Context.Namespace != "app" || in.Context.Name != "my-secret" {
		t.Errorf("context = %+v", in.Context)
	}
	if !in.Context.GeneratedAt.Equal(fixedTime) {
		t.Errorf("generatedAt = %v", in.Context.GeneratedAt)
	}
	if in.Context.Labels["team"] != "platform" {
		t.Errorf("labels = %v", in.Context.Labels)
	}
}

func TestResolveSecretRef(t *testing.T) {
	r := newResolver(t, nil, secret("db-credentials", nil, map[string]string{"password": "s3cr3t"}))
	sb := builderFor(secretsv1beta1.SecretBuilderSpec{
		Inputs: secretsv1beta1.SecretBuilderInputs{
			Secrets: []secretsv1beta1.SecretInput{{Name: "db", SecretRef: &corev1.LocalObjectReference{Name: "db-credentials"}}},
		},
	})

	in, pending := resolve(t, r, sb)
	if len(pending) != 0 {
		t.Fatalf("unexpected pending: %v", pending)
	}
	binding := in.Secrets["db"]
	if binding == nil || binding.IsList || binding.Single == nil {
		t.Fatalf("expected single binding, got %+v", binding)
	}
	if got := binding.Single.Data["password"]; got != "s3cr3t" {
		t.Errorf("decoded password = %q", got)
	}
}

func TestResolveSecretRefAbsentIsPending(t *testing.T) {
	r := newResolver(t, nil)
	sb := builderFor(secretsv1beta1.SecretBuilderSpec{
		Inputs: secretsv1beta1.SecretBuilderInputs{
			Secrets: []secretsv1beta1.SecretInput{{Name: "db", SecretRef: &corev1.LocalObjectReference{Name: "missing"}}},
		},
	})

	in, pending := resolve(t, r, sb)
	if len(pending) != 1 || pending[0].Reason != ReasonAwaitingInput {
		t.Fatalf("expected one AwaitingInput pending, got %v", pending)
	}
	if _, ok := in.Secrets["db"]; ok {
		t.Errorf("absent secret should not bind")
	}
}

func TestResolveSecretSelectorSortedAndFiltered(t *testing.T) {
	r := newResolver(t, nil,
		secret("user-2", map[string]string{"app": "dashboard"}, map[string]string{"pw": "b"}),
		secret("user-1", map[string]string{"app": "dashboard"}, map[string]string{"pw": "a"}),
		secret("user-test", map[string]string{"app": "dashboard"}, map[string]string{"pw": "x"}),
		secret("other", map[string]string{"app": "dashboard"}, map[string]string{"pw": "z"}),
	)
	sb := builderFor(secretsv1beta1.SecretBuilderSpec{
		Inputs: secretsv1beta1.SecretBuilderInputs{
			Secrets: []secretsv1beta1.SecretInput{{
				Name:     "users",
				Selector: &selectors.SecretSelector{NameSelector: &selectors.NameSelector{MatchNames: []string{"user-*", "!user-test"}}},
			}},
		},
	})

	in, pending := resolve(t, r, sb)
	if len(pending) != 0 {
		t.Fatalf("unexpected pending: %v", pending)
	}
	binding := in.Secrets["users"]
	if binding == nil || !binding.IsList {
		t.Fatalf("expected list binding, got %+v", binding)
	}
	if len(binding.List) != 2 || binding.List[0].Name != "user-1" || binding.List[1].Name != "user-2" {
		t.Fatalf("expected [user-1 user-2], got %v", names(binding.List))
	}
}

func TestResolveSelectorEmpty(t *testing.T) {
	mkBuilder := func(allowEmpty bool) *secretsv1beta1.SecretBuilder {
		return builderFor(secretsv1beta1.SecretBuilderSpec{
			Inputs: secretsv1beta1.SecretBuilderInputs{
				Secrets: []secretsv1beta1.SecretInput{{
					Name:       "users",
					AllowEmpty: allowEmpty,
					Selector:   &selectors.SecretSelector{NameSelector: &selectors.NameSelector{MatchNames: []string{"none-*"}}},
				}},
			},
		})
	}

	// Without allowEmpty: zero matches is pending.
	r := newResolver(t, nil)
	_, pending := resolve(t, r, mkBuilder(false))
	if len(pending) != 1 || pending[0].Reason != ReasonAwaitingInput {
		t.Fatalf("expected AwaitingInput, got %v", pending)
	}

	// With allowEmpty: zero matches binds an empty list, no pending.
	in, pending := resolve(t, r, mkBuilder(true))
	if len(pending) != 0 {
		t.Fatalf("unexpected pending with allowEmpty: %v", pending)
	}
	binding := in.Secrets["users"]
	if binding == nil || !binding.IsList || len(binding.List) != 0 {
		t.Fatalf("expected empty list binding, got %+v", binding)
	}
}

func TestResolveConfigMapAndBinaryData(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "gen-lib", Namespace: "app"},
		Data:       map[string]string{"domain": "example.com", "util.star": "def f():\n  pass"},
		BinaryData: map[string][]byte{"blob": {0x01, 0x02, 0x03}},
	}
	r := newResolver(t, nil, cm)
	sb := builderFor(secretsv1beta1.SecretBuilderSpec{
		Inputs: secretsv1beta1.SecretBuilderInputs{
			ConfigMaps: []secretsv1beta1.ConfigMapInput{{Name: "lib", ConfigMapRef: &corev1.LocalObjectReference{Name: "gen-lib"}}},
			Libraries:  []secretsv1beta1.LibraryReference{{Name: "util", From: "lib", Key: "util.star"}},
		},
	})

	in, pending := resolve(t, r, sb)
	if len(pending) != 0 {
		t.Fatalf("unexpected pending: %v", pending)
	}
	binding := in.ConfigMaps["lib"]
	if binding == nil || binding.Single == nil {
		t.Fatalf("expected single configMap binding, got %+v", binding)
	}
	if binding.Single.Data["domain"] != "example.com" {
		t.Errorf("data domain = %q", binding.Single.Data["domain"])
	}
	if string(binding.Single.BinaryData["blob"]) != "\x01\x02\x03" {
		t.Errorf("binaryData blob = %v", binding.Single.BinaryData["blob"])
	}
	if in.Libraries["util"] != "def f():\n  pass" {
		t.Errorf("library util = %q", in.Libraries["util"])
	}
}

func TestResolveServiceAccount(t *testing.T) {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "deployer", Namespace: "app"}}
	rootCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: rootCAConfigMap, Namespace: "app"},
		Data:       map[string]string{rootCAKey: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"},
	}
	minter := &stubMinter{token: "minted-token"}
	r := newResolver(t, minter, sa, rootCA)
	sb := builderFor(secretsv1beta1.SecretBuilderSpec{
		Inputs: secretsv1beta1.SecretBuilderInputs{
			ServiceAccount: &secretsv1beta1.ServiceAccountInput{ServiceAccountRef: corev1.LocalObjectReference{Name: "deployer"}},
		},
	})

	in, pending := resolve(t, r, sb)
	if len(pending) != 0 {
		t.Fatalf("unexpected pending: %v", pending)
	}
	if minter.calls != 1 {
		t.Errorf("minter calls = %d", minter.calls)
	}
	got := in.ServiceAccount
	if got == nil || got.Token != "minted-token" || got.ClusterServer != "https://api.example" {
		t.Fatalf("serviceAccount = %+v", got)
	}
	if got.ClusterCACert == "" {
		t.Errorf("expected cluster CA cert to be resolved")
	}
}

func TestResolveServiceAccountAbsentIsPending(t *testing.T) {
	r := newResolver(t, &stubMinter{token: "x"})
	sb := builderFor(secretsv1beta1.SecretBuilderSpec{
		Inputs: secretsv1beta1.SecretBuilderInputs{
			ServiceAccount: &secretsv1beta1.ServiceAccountInput{ServiceAccountRef: corev1.LocalObjectReference{Name: "missing"}},
		},
	})

	_, pending := resolve(t, r, sb)
	if len(pending) != 1 || pending[0].Reason != ReasonMissingServiceAcc {
		t.Fatalf("expected MissingServiceAccount, got %v", pending)
	}
}

func TestFingerprint(t *testing.T) {
	mk := func(data map[string]string) *ResolvedInputs {
		r := newResolver(t, nil, secret("db-credentials", nil, data))
		sb := builderFor(secretsv1beta1.SecretBuilderSpec{
			Inputs: secretsv1beta1.SecretBuilderInputs{
				Secrets: []secretsv1beta1.SecretInput{{Name: "db", SecretRef: &corev1.LocalObjectReference{Name: "db-credentials"}}},
			},
		})
		in, _ := resolve(t, r, sb)
		return in
	}

	a := mk(map[string]string{"password": "one"})
	b := mk(map[string]string{"password": "one"})
	c := mk(map[string]string{"password": "two"})

	if a.Fingerprint() != b.Fingerprint() {
		t.Errorf("identical inputs should fingerprint identically")
	}
	if a.Fingerprint() == c.Fingerprint() {
		t.Errorf("changed secret data should change the fingerprint")
	}
}

func TestFingerprintUsesRevisionAnnotation(t *testing.T) {
	mk := func(data map[string]string) *ResolvedInputs {
		s := secret("db-credentials", nil, data)
		s.Annotations = map[string]string{RevisionAnnotation: "rev-1"}
		r := newResolver(t, nil, s)
		sb := builderFor(secretsv1beta1.SecretBuilderSpec{
			Inputs: secretsv1beta1.SecretBuilderInputs{
				Secrets: []secretsv1beta1.SecretInput{{Name: "db", SecretRef: &corev1.LocalObjectReference{Name: "db-credentials"}}},
			},
		})
		in, _ := resolve(t, r, sb)
		return in
	}

	// Same revision annotation, different data -> same fingerprint (the annotation
	// is authoritative; the upstream builder only re-stamps it when content changes).
	if mk(map[string]string{"password": "one"}).Fingerprint() != mk(map[string]string{"password": "two"}).Fingerprint() {
		t.Errorf("fingerprint should track the revision annotation, not raw data, when present")
	}
}

func names(secrets []*ResolvedSecret) []string {
	out := make([]string, len(secrets))
	for i, s := range secrets {
		out[i] = s.Name
	}
	return out
}
