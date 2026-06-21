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
	"crypto/sha1" //nolint:gosec // verifying the {SHA} htpasswd scheme
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"k8s.io/client-go/tools/clientcmd"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
)

func TestTLSBundle(t *testing.T) {
	out, err := GenerateAll([]secretsv1beta1.GeneratedValue{
		{Name: "ca", CACertificate: &secretsv1beta1.CACertificateSpec{CommonName: "CA", Algorithm: "Ed25519"}},
		{Name: "leaf", TLSCertificate: &secretsv1beta1.TLSCertificateSpec{CommonName: "x", Algorithm: "Ed25519", IssuerRef: &secretsv1beta1.IssuerReference{Generated: "ca"}}},
	}, seeded(), fixedTime, &ResolvedInputs{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	bundle, err := TLSBundle([]string{out["leaf"]["certPEM"].(string), out["leaf"]["caPEM"].(string)})
	if err != nil {
		t.Fatalf("TLSBundle: %v", err)
	}
	if n := strings.Count(bundle, "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("bundle has %d certificates, want 2", n)
	}

	if _, err := TLSBundle([]string{"not a pem block"}); err == nil {
		t.Errorf("expected error for non-PEM input")
	}
}

func TestBasicAuth(t *testing.T) {
	const userPassB64 = "dXNlcjpwYXNz" // base64("user:pass")
	if got := BasicAuthCredentials("user", "pass"); got != userPassB64 {
		t.Errorf("credentials = %q, want %q", got, userPassB64)
	}
	if got := BasicAuthHeader("user", "pass"); got != "Basic "+userPassB64 {
		t.Errorf("header = %q", got)
	}
}

func TestDockerConfigJSON(t *testing.T) {
	out, err := DockerConfigJSON([]DockerRegistry{{Registry: "registry.example.com", Username: "u", Password: "p", Email: "e@x"}})
	if err != nil {
		t.Fatalf("DockerConfigJSON: %v", err)
	}
	var parsed struct {
		Auths map[string]struct {
			Username, Password, Auth, Email string
		}
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	entry, ok := parsed.Auths["registry.example.com"]
	if !ok {
		t.Fatalf("missing registry entry: %s", out)
	}
	if entry.Auth != base64.StdEncoding.EncodeToString([]byte("u:p")) {
		t.Errorf("auth = %q", entry.Auth)
	}
	if entry.Username != "u" || entry.Password != "p" || entry.Email != "e@x" {
		t.Errorf("entry = %+v", entry)
	}
}

func TestHtpasswdBcrypt(t *testing.T) {
	out, err := HtpasswdBcrypt([]HtpasswdEntry{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatalf("HtpasswdBcrypt: %v", err)
	}
	user, hash, ok := strings.Cut(strings.TrimSpace(out), ":")
	if !ok || user != "alice" {
		t.Fatalf("unexpected line %q", out)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("secret")); err != nil {
		t.Errorf("bcrypt does not verify: %v", err)
	}
}

func TestHtpasswdSHA(t *testing.T) {
	out := HtpasswdSHA([]HtpasswdEntry{{Username: "bob", Password: "hunter2"}})
	sum := sha1.Sum([]byte("hunter2")) //nolint:gosec
	want := "bob:{SHA}" + base64.StdEncoding.EncodeToString(sum[:]) + "\n"
	if out != want {
		t.Errorf("HtpasswdSHA = %q, want %q", out, want)
	}
}

func TestHtpasswdAPR1(t *testing.T) {
	out, err := HtpasswdAPR1([]HtpasswdEntry{{Username: "carol", Password: "pw"}}, []string{"abcd1234"})
	if err != nil {
		t.Fatalf("HtpasswdAPR1: %v", err)
	}
	line := strings.TrimSpace(out)
	if !strings.HasPrefix(line, "carol:$apr1$abcd1234$") {
		t.Fatalf("unexpected apr1 line %q", line)
	}
	// Deterministic: same password + salt reproduces the same hash.
	again, _ := HtpasswdAPR1([]HtpasswdEntry{{Username: "carol", Password: "pw"}}, []string{"abcd1234"})
	if out != again {
		t.Errorf("apr1 is not deterministic for a fixed salt")
	}
	// Salt is required.
	if _, err := HtpasswdAPR1([]HtpasswdEntry{{Username: "x", Password: "y"}}, nil); err == nil {
		t.Errorf("expected error when salt missing")
	}
}

func TestKubeconfigFromServiceAccount(t *testing.T) {
	out, err := KubeconfigFromServiceAccount("the-token", "https://api.example:6443", "CA-PEM", "prod", "deployer", "prod-ctx")
	if err != nil {
		t.Fatalf("KubeconfigFromServiceAccount: %v", err)
	}
	cfg, err := clientcmd.Load([]byte(out))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.CurrentContext != "prod-ctx" {
		t.Errorf("currentContext = %q", cfg.CurrentContext)
	}
	if cfg.Clusters["prod"].Server != "https://api.example:6443" {
		t.Errorf("server = %q", cfg.Clusters["prod"].Server)
	}
	if cfg.AuthInfos["deployer"].Token != "the-token" {
		t.Errorf("token = %q", cfg.AuthInfos["deployer"].Token)
	}
	if string(cfg.Clusters["prod"].CertificateAuthorityData) != "CA-PEM" {
		t.Errorf("ca = %q", cfg.Clusters["prod"].CertificateAuthorityData)
	}
}

func TestKubeconfigBuild(t *testing.T) {
	// Client-cert/key credential and an explicit context namespace; defaulted names.
	out, err := KubeconfigBuild(KubeconfigParams{
		Server:     "https://api.example:6443",
		CACert:     "CA-PEM",
		ClientCert: "CERT-PEM",
		ClientKey:  "KEY-PEM",
		Namespace:  "team-a",
	})
	if err != nil {
		t.Fatalf("KubeconfigBuild: %v", err)
	}
	cfg, err := clientcmd.Load([]byte(out))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Names default to cluster/user, context to the cluster name.
	if cfg.CurrentContext != "cluster" {
		t.Errorf("currentContext = %q, want %q", cfg.CurrentContext, "cluster")
	}
	auth := cfg.AuthInfos["user"]
	if auth == nil || string(auth.ClientCertificateData) != "CERT-PEM" || string(auth.ClientKeyData) != "KEY-PEM" {
		t.Errorf("client cert/key not set: %+v", auth)
	}
	if auth.Token != "" {
		t.Errorf("token should be empty, got %q", auth.Token)
	}
	if cfg.Contexts["cluster"].Namespace != "team-a" {
		t.Errorf("namespace = %q", cfg.Contexts["cluster"].Namespace)
	}
}

func TestKubeconfigMerge(t *testing.T) {
	a, _ := KubeconfigFromServiceAccount("ta", "https://a", "", "ca", "ua", "ctx-a")
	b, _ := KubeconfigFromServiceAccount("tb", "https://b", "", "cb", "ub", "ctx-b")

	merged, err := KubeconfigMerge([]string{a, b}, "ctx-b", false)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	cfg, err := clientcmd.Load([]byte(merged))
	if err != nil {
		t.Fatalf("load merged: %v", err)
	}
	if len(cfg.Contexts) != 2 || cfg.Contexts["ctx-a"] == nil || cfg.Contexts["ctx-b"] == nil {
		t.Errorf("expected both contexts, got %v", cfg.Contexts)
	}
	if cfg.CurrentContext != "ctx-b" {
		t.Errorf("currentContext override = %q", cfg.CurrentContext)
	}

	// Strict mode errors on a clashing name (merging a with itself).
	if _, err := KubeconfigMerge([]string{a, a}, "", true); err == nil {
		t.Errorf("expected strict conflict error")
	}
}

func TestJWTSignHS256(t *testing.T) {
	const secret = "topsecret"
	token, err := JWTSign(map[string]any{"sub": "alice"}, secret, "HS256", JWTOptions{IssuedAt: fixedTime, ExpiresIn: time.Hour, Kid: "k1"})
	if err != nil {
		t.Fatalf("JWTSign: %v", err)
	}

	parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return []byte(secret), nil },
		jwt.WithTimeFunc(func() time.Time { return fixedTime.Add(time.Minute) }))
	if err != nil || !parsed.Valid {
		t.Fatalf("verify: %v valid=%v", err, parsed.Valid)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != "alice" {
		t.Errorf("sub = %v", claims["sub"])
	}
	if parsed.Header["kid"] != "k1" {
		t.Errorf("kid = %v", parsed.Header["kid"])
	}
	if _, ok := claims["exp"]; !ok {
		t.Errorf("exp claim missing")
	}
}

func TestJWTSignAsymmetric(t *testing.T) {
	cases := []struct {
		alg      string
		genAttrs func() (map[string]any, error)
	}{
		{"RS256", func() (map[string]any, error) { return generatePrivateKey("RSA", 2048, "", seeded()) }},
		{"ES256", func() (map[string]any, error) { return generatePrivateKey("ECDSA", 0, "P256", seeded()) }},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			attrs, err := tc.genAttrs()
			if err != nil {
				t.Fatalf("gen key: %v", err)
			}
			token, err := JWTSign(map[string]any{"sub": "svc"}, attrs["privatePEM"].(string), tc.alg, JWTOptions{IssuedAt: fixedTime})
			if err != nil {
				t.Fatalf("JWTSign: %v", err)
			}
			pub := parsePublicPEM(t, attrs["publicPEM"].(string))
			parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return pub, nil })
			if err != nil || !parsed.Valid {
				t.Fatalf("verify: %v valid=%v", err, parsed.Valid)
			}
		})
	}
}

func TestJWTDecodeNoVerify(t *testing.T) {
	token, _ := JWTSign(map[string]any{"sub": "x", "role": "admin"}, "secret", "HS256", JWTOptions{IssuedAt: fixedTime})
	header, claims, err := JWTDecode(token)
	if err != nil {
		t.Fatalf("JWTDecode: %v", err)
	}
	if claims["role"] != "admin" || header["alg"] != "HS256" {
		t.Errorf("decoded header=%v claims=%v", header, claims)
	}
}

func TestJWTEdDSARejected(t *testing.T) {
	if _, err := JWTSign(map[string]any{"sub": "x"}, "key", "EdDSA", JWTOptions{IssuedAt: fixedTime}); err == nil {
		t.Errorf("expected EdDSA to be rejected in v1")
	}
}

func parsePublicPEM(t *testing.T, pemStr string) any {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("no PEM block in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	return pub
}
