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
	"crypto/x509"
	"io"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// seeded returns a deterministic byte stream, so generation is reproducible in
// tests (production uses crypto/rand.Reader).
func seeded() io.Reader { return mathrand.New(mathrand.NewSource(42)) }

func ptrBool(b bool) *bool { return &b }

func TestPasswordComposition(t *testing.T) {
	spec := secretsv1beta1.PasswordSpec{
		Length:           24,
		MinUpper:         2,
		MinLower:         2,
		MinDigits:        3,
		MinSymbols:       1,
		ExcludeAmbiguous: true,
	}
	value, err := buildPassword(spec, seeded())
	if err != nil {
		t.Fatalf("buildPassword: %v", err)
	}
	if len([]rune(value)) != 24 {
		t.Fatalf("length = %d, want 24", len([]rune(value)))
	}

	var upper, lower, digit, symbol int
	for _, c := range value {
		switch {
		case unicode.IsUpper(c):
			upper++
		case unicode.IsLower(c):
			lower++
		case unicode.IsDigit(c):
			digit++
		default:
			symbol++
		}
		if strings.ContainsRune(ambiguousChars, c) {
			t.Errorf("ambiguous character %q present", c)
		}
	}
	if upper < 2 || lower < 2 || digit < 3 || symbol < 1 {
		t.Errorf("composition not satisfied: upper=%d lower=%d digit=%d symbol=%d", upper, lower, digit, symbol)
	}
}

func TestPasswordCharsetOnlyDigits(t *testing.T) {
	value, err := buildPassword(secretsv1beta1.PasswordSpec{Length: 6, Charset: "0123456789"}, seeded())
	if err != nil {
		t.Fatalf("buildPassword: %v", err)
	}
	for _, c := range value {
		if !unicode.IsDigit(c) {
			t.Fatalf("non-digit %q in digit-only password %q", c, value)
		}
	}
}

func TestPasswordBcryptVerifies(t *testing.T) {
	attrs, err := generatePassword(secretsv1beta1.PasswordSpec{Length: 16, Symbols: ptrBool(false)}, seeded())
	if err != nil {
		t.Fatalf("generatePassword: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(attrs["bcrypt"].(string)), []byte(attrs["value"].(string))); err != nil {
		t.Errorf("bcrypt does not verify the password: %v", err)
	}
}

func TestTokenPrefixAndAlphabet(t *testing.T) {
	attrs, err := generateToken(secretsv1beta1.TokenSpec{Prefix: "wsk_", Alphabet: "lowerAlphanumeric", Length: 32}, seeded())
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	value := attrs["value"].(string)
	if !strings.HasPrefix(value, "wsk_") {
		t.Fatalf("missing prefix: %q", value)
	}
	body := strings.TrimPrefix(value, "wsk_")
	if len(body) != 32 {
		t.Fatalf("body length = %d, want 32", len(body))
	}
	for _, c := range body {
		if !unicode.IsLower(c) && !unicode.IsDigit(c) {
			t.Errorf("unexpected character %q for lowerAlphanumeric", c)
		}
	}
}

func TestRandomIntRange(t *testing.T) {
	for i := 0; i < 200; i++ {
		attrs, err := generateRandomInt(secretsv1beta1.RandomIntSpec{Min: -5, Max: 5}, seeded())
		if err != nil {
			t.Fatalf("generateRandomInt: %v", err)
		}
		v := attrs["value"].(int64)
		if v < -5 || v > 5 {
			t.Fatalf("value %d out of range", v)
		}
	}
	// min == max returns min.
	attrs, err := generateRandomInt(secretsv1beta1.RandomIntSpec{Min: 7, Max: 7}, seeded())
	if err != nil {
		t.Fatalf("generateRandomInt: %v", err)
	}
	if attrs["value"].(int64) != 7 {
		t.Errorf("min==max value = %v, want 7", attrs["value"])
	}
}

func TestBytesEncoding(t *testing.T) {
	attrs, err := generateBytes(secretsv1beta1.BytesSpec{Length: 16, Encoding: "hex"}, seeded())
	if err != nil {
		t.Fatalf("generateBytes: %v", err)
	}
	if raw, ok := attrs["bytes"].([]byte); !ok || len(raw) != 16 {
		t.Fatalf("raw bytes = %v", attrs["bytes"])
	}
	if hexVal := attrs["value"].(string); len(hexVal) != 32 {
		t.Errorf("hex value length = %d, want 32", len(hexVal))
	}
}

func TestUUIDVersions(t *testing.T) {
	v4, err := generateUUID(secretsv1beta1.UUIDSpec{Version: 4}, seeded(), fixedTime)
	if err != nil {
		t.Fatalf("uuid v4: %v", err)
	}
	if got := v4["value"].(string); got[14] != '4' {
		t.Errorf("v4 version nibble = %q in %q", got[14], got)
	}
	v7, err := generateUUID(secretsv1beta1.UUIDSpec{Version: 7}, seeded(), fixedTime)
	if err != nil {
		t.Fatalf("uuid v7: %v", err)
	}
	if got := v7["value"].(string); got[14] != '7' {
		t.Errorf("v7 version nibble = %q in %q", got[14], got)
	}
}

func TestPrivateKeysParse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs func() (map[string]any, error)
	}{
		{"rsa", func() (map[string]any, error) { return generatePrivateKey("RSA", 2048, "", seeded()) }},
		{"ecdsa", func() (map[string]any, error) { return generatePrivateKey("ECDSA", 0, "P256", seeded()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := tc.attrs()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if _, err := parsePrivateKey(attrs["privatePEM"].(string)); err != nil {
				t.Errorf("privatePEM does not parse: %v", err)
			}
			if !strings.Contains(attrs["publicPEM"].(string), "PUBLIC KEY") {
				t.Errorf("publicPEM missing")
			}
		})
	}
}

func TestSSHKeyPair(t *testing.T) {
	attrs, err := generateSSHKeyPair(secretsv1beta1.SSHKeyPairSpec{Algorithm: "Ed25519", Comment: "deploy@host"}, seeded())
	if err != nil {
		t.Fatalf("generateSSHKeyPair: %v", err)
	}
	if !strings.Contains(attrs["privatePEM"].(string), "OPENSSH PRIVATE KEY") {
		t.Errorf("privatePEM is not OpenSSH format")
	}
	pub := attrs["publicOpenSSH"].(string)
	if !strings.HasPrefix(pub, "ssh-ed25519 ") || !strings.HasSuffix(pub, " deploy@host") {
		t.Errorf("publicOpenSSH = %q", pub)
	}
	if !strings.HasPrefix(attrs["fingerprintSHA256"].(string), "SHA256:") {
		t.Errorf("fingerprint = %q", attrs["fingerprintSHA256"])
	}
}

// TestCertificateChainVerifies is the key property test: a generated leaf signed
// by a generated CA must verify against that CA.
func TestCertificateChainVerifies(t *testing.T) {
	values := []secretsv1beta1.GeneratedValue{
		{Name: "ca", CACertificate: &secretsv1beta1.CACertificateSpec{CommonName: "Test CA", Algorithm: "Ed25519"}},
		{Name: "leaf", TLSCertificate: &secretsv1beta1.TLSCertificateSpec{
			CommonName: "app.example.com",
			Algorithm:  "Ed25519",
			DNSNames:   []string{"app.example.com"},
			IssuerRef:  &secretsv1beta1.IssuerReference{Generated: "ca"},
		}},
	}

	out, err := GenerateAll(values, seeded(), fixedTime, &ResolvedInputs{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	leafPEM := out["leaf"]["certPEM"].(string)
	caPEM, ok := out["leaf"]["caPEM"].(string)
	if !ok || caPEM == "" {
		t.Fatalf("leaf is missing caPEM (issuing CA)")
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatalf("could not load CA into pool")
	}
	leaf, err := parseCertificate(leafPEM)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: fixedTime.Add(time.Hour),
		DNSName:     "app.example.com",
	}); err != nil {
		t.Errorf("leaf does not verify against its CA: %v", err)
	}
}

func TestSelfSignedTLSHasNoCAPEM(t *testing.T) {
	values := []secretsv1beta1.GeneratedValue{
		{Name: "leaf", TLSCertificate: &secretsv1beta1.TLSCertificateSpec{CommonName: "dev.local", Algorithm: "Ed25519"}},
	}
	out, err := GenerateAll(values, seeded(), fixedTime, &ResolvedInputs{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	if _, ok := out["leaf"]["caPEM"]; ok {
		t.Errorf("self-signed leaf should not expose caPEM")
	}
}

// TestDeterministicRegen confirms that, given the same seed and generatedAt, the
// reader-driven primitives reproduce identical material.
//
// Note: RSA/ECDSA key generation (and therefore certificates) is intentionally
// NOT byte-reproducible - Go's crypto calls randutil.MaybeReadByte to discourage
// relying on deterministic key generation, which also consumes a variable amount
// of the stream and desyncs anything generated afterwards. Ed25519 keygen and
// signing are deterministic, so an SSH Ed25519 public key is. This is why the
// real model persists generated material and replays it on refresh rather than
// regenerating it (the bcrypt hash and the OpenSSH private-key checkint are
// likewise non-deterministic and persisted).
func TestDeterministicRegen(t *testing.T) {
	gen := func() map[string]map[string]any {
		values := []secretsv1beta1.GeneratedValue{
			{Name: "tok", Token: &secretsv1beta1.TokenSpec{Length: 20}},
			{Name: "b", Bytes: &secretsv1beta1.BytesSpec{Length: 16}},
			{Name: "id", UUID: &secretsv1beta1.UUIDSpec{Version: 4}},
			{Name: "ssh", SSHKeyPair: &secretsv1beta1.SSHKeyPairSpec{Algorithm: "Ed25519"}},
		}
		out, err := GenerateAll(values, seeded(), fixedTime, &ResolvedInputs{})
		if err != nil {
			t.Fatalf("GenerateAll: %v", err)
		}
		return out
	}

	a, b := gen(), gen()
	cases := []struct{ handle, attr string }{
		{"tok", "value"},
		{"b", "value"},
		{"id", "value"},
		{"ssh", "publicOpenSSH"},
		{"ssh", "fingerprintSHA256"},
	}
	for _, c := range cases {
		if toComparable(a[c.handle][c.attr]) != toComparable(b[c.handle][c.attr]) {
			t.Errorf("non-deterministic %s.%s", c.handle, c.attr)
		}
	}
}

func toComparable(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return ""
	}
}
