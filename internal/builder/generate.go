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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// Character classes for password generation.
const (
	upperChars     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars     = "abcdefghijklmnopqrstuvwxyz"
	digitChars     = "0123456789"
	defaultSymbols = "!@#$%^&*()-_=+[]{}"
	ambiguousChars = "0O1lI|"
)

// GenerateAll produces every declared generated value, in declaration order so a
// caCertificate can be referenced as the issuer of a later certificate. It draws
// all entropy from r (crypto/rand.Reader in production; a deterministic reader in
// tests) and anchors time-bound material at generatedAt, so output is reproducible
// given the same seed. It returns a map of handle -> attribute map, which the
// generator engines expose (e.g. input.generated.<handle>.<attr>).
func GenerateAll(values []secretsv1beta1.GeneratedValue, r io.Reader, generatedAt time.Time, resolved *ResolvedInputs) (map[string]map[string]any, error) {
	out := make(map[string]map[string]any, len(values))
	cas := map[string]*caMaterial{} // generated caCertificate handle -> signing material

	for i := range values {
		v := values[i]

		var attrs map[string]any
		var err error

		switch {
		case v.Password != nil:
			attrs, err = generatePassword(*v.Password, r)
		case v.Token != nil:
			attrs, err = generateToken(*v.Token, r)
		case v.RandomInt != nil:
			attrs, err = generateRandomInt(*v.RandomInt, r)
		case v.Bytes != nil:
			attrs, err = generateBytes(*v.Bytes, r)
		case v.UUID != nil:
			attrs, err = generateUUID(*v.UUID, r, generatedAt)
		case v.RSAPrivateKey != nil:
			attrs, err = generatePrivateKey("RSA", v.RSAPrivateKey.RSABits, "", r)
		case v.ECDSAPrivateKey != nil:
			attrs, err = generatePrivateKey("ECDSA", 0, v.ECDSAPrivateKey.ECDSACurve, r)
		case v.SSHKeyPair != nil:
			attrs, err = generateSSHKeyPair(*v.SSHKeyPair, r)
		case v.CACertificate != nil:
			var ca *caMaterial
			ca, attrs, err = generateCACertificate(*v.CACertificate, r, generatedAt, cas, resolved)
			if err == nil {
				cas[v.Name] = ca
			}
		case v.TLSCertificate != nil:
			attrs, err = generateTLSCertificate(*v.TLSCertificate, r, generatedAt, cas, resolved)
		default:
			err = fmt.Errorf("no kind set")
		}

		if err != nil {
			return nil, fmt.Errorf("generated %q: %w", v.Name, err)
		}
		out[v.Name] = attrs
	}

	return out, nil
}

// ---- passwords and tokens ------------------------------------------------

func generatePassword(spec secretsv1beta1.PasswordSpec, r io.Reader) (map[string]any, error) {
	value, err := buildPassword(spec, r)
	if err != nil {
		return nil, err
	}

	// bcrypt draws its own salt from crypto/rand (the x/crypto API does not accept
	// an injected reader); the resulting hash is persisted with the rest of the
	// generated material, so it stays stable across refreshes.
	hashed, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt: %w", err)
	}
	sum := sha256.Sum256([]byte(value))

	return map[string]any{
		"value":  value,
		"bcrypt": string(hashed),
		"sha256": hex.EncodeToString(sum[:]),
	}, nil
}

func buildPassword(spec secretsv1beta1.PasswordSpec, r io.Reader) (string, error) {
	if spec.Length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}

	// An explicit charset overrides the class toggles and per-class minimums.
	if spec.Charset != "" {
		alphabet := removeRunes(spec.Charset, spec.ExcludeCharacters, spec.ExcludeAmbiguous)
		if alphabet == "" {
			return "", fmt.Errorf("charset is empty after exclusions")
		}
		return drawString(alphabet, spec.Length, boolOrTrue(spec.AllowRepeat), r)
	}

	type class struct {
		enabled bool
		min     int
		chars   string
	}
	classes := []class{
		{boolOrTrue(spec.Upper), spec.MinUpper, removeRunes(upperChars, spec.ExcludeCharacters, spec.ExcludeAmbiguous)},
		{boolOrTrue(spec.Lower), spec.MinLower, removeRunes(lowerChars, spec.ExcludeCharacters, spec.ExcludeAmbiguous)},
		{boolOrTrue(spec.Digits), spec.MinDigits, removeRunes(digitChars, spec.ExcludeCharacters, spec.ExcludeAmbiguous)},
		{boolOrTrue(spec.Symbols), spec.MinSymbols, removeRunes(symbolSet(spec), spec.ExcludeCharacters, spec.ExcludeAmbiguous)},
	}

	var alphabet strings.Builder
	totalMin := 0
	for _, c := range classes {
		if c.enabled {
			alphabet.WriteString(c.chars)
		}
		if c.min > 0 {
			totalMin += c.min
		}
	}
	full := alphabet.String()
	if full == "" {
		return "", fmt.Errorf("no character classes enabled")
	}
	if totalMin > spec.Length {
		return "", fmt.Errorf("sum of minimums (%d) exceeds length (%d)", totalMin, spec.Length)
	}

	allowRepeat := boolOrTrue(spec.AllowRepeat)

	// Place the required per-class minimums first, then fill the remainder from the
	// full alphabet, then shuffle so the required characters are not positional.
	var chars []rune
	used := map[rune]bool{}
	draw := func(pool string) (rune, error) {
		for {
			if pool == "" {
				return 0, fmt.Errorf("ran out of characters (allowRepeat=false with too small an alphabet)")
			}
			runes := []rune(pool)
			idx, err := drawIndex(len(runes), r)
			if err != nil {
				return 0, err
			}
			ch := runes[idx]
			if !allowRepeat {
				if used[ch] {
					// remove and retry
					pool = strings.Map(func(x rune) rune {
						if x == ch {
							return -1
						}
						return x
					}, pool)
					continue
				}
				used[ch] = true
			}
			return ch, nil
		}
	}

	for _, c := range classes {
		for i := 0; i < c.min; i++ {
			ch, err := draw(c.chars)
			if err != nil {
				return "", err
			}
			chars = append(chars, ch)
		}
	}
	for len(chars) < spec.Length {
		ch, err := draw(full)
		if err != nil {
			return "", err
		}
		chars = append(chars, ch)
	}

	if err := shuffle(chars, r); err != nil {
		return "", err
	}
	return string(chars), nil
}

func symbolSet(spec secretsv1beta1.PasswordSpec) string {
	if spec.SymbolSet != "" {
		return spec.SymbolSet
	}
	return defaultSymbols
}

func generateToken(spec secretsv1beta1.TokenSpec, r io.Reader) (map[string]any, error) {
	if spec.Length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}

	var alphabet string
	switch spec.Alphabet {
	case "", "alphanumeric":
		alphabet = upperChars + lowerChars + digitChars
	case "lowerAlphanumeric":
		alphabet = lowerChars + digitChars
	case "hex":
		alphabet = "0123456789abcdef"
	case "base32":
		alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	case "base64url":
		alphabet = upperChars + lowerChars + digitChars + "-_"
	case "custom":
		if spec.Charset == "" {
			return nil, fmt.Errorf("charset required when alphabet is custom")
		}
		alphabet = spec.Charset
	default:
		return nil, fmt.Errorf("unknown alphabet %q", spec.Alphabet)
	}

	body, err := drawString(alphabet, spec.Length, true, r)
	if err != nil {
		return nil, err
	}
	return map[string]any{"value": spec.Prefix + body}, nil
}

// ---- numbers, bytes, uuids ----------------------------------------------

func generateRandomInt(spec secretsv1beta1.RandomIntSpec, r io.Reader) (map[string]any, error) {
	if spec.Max < spec.Min {
		return nil, fmt.Errorf("max (%d) must be >= min (%d)", spec.Max, spec.Min)
	}
	span := uint64(spec.Max-spec.Min) + 1
	offset, err := drawUint64(span, r)
	if err != nil {
		return nil, err
	}
	return map[string]any{"value": spec.Min + int64(offset)}, nil
}

func generateBytes(spec secretsv1beta1.BytesSpec, r io.Reader) (map[string]any, error) {
	if spec.Length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}
	raw := make([]byte, spec.Length)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, err
	}

	var encoded string
	switch spec.Encoding {
	case "", "base64":
		encoded = base64.StdEncoding.EncodeToString(raw)
	case "base64url":
		encoded = base64.RawURLEncoding.EncodeToString(raw)
	case "hex":
		encoded = hex.EncodeToString(raw)
	case "base32":
		encoded = base32.StdEncoding.EncodeToString(raw)
	default:
		return nil, fmt.Errorf("unknown encoding %q", spec.Encoding)
	}
	return map[string]any{"value": encoded, "bytes": raw}, nil
}

func generateUUID(spec secretsv1beta1.UUIDSpec, r io.Reader, generatedAt time.Time) (map[string]any, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}

	switch spec.Version {
	case 0, 4:
		b[6] = (b[6] & 0x0f) | 0x40 // version 4
		b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	case 7:
		ms := uint64(generatedAt.UnixMilli())
		b[0] = byte(ms >> 40)
		b[1] = byte(ms >> 32)
		b[2] = byte(ms >> 24)
		b[3] = byte(ms >> 16)
		b[4] = byte(ms >> 8)
		b[5] = byte(ms)
		b[6] = (b[6] & 0x0f) | 0x70 // version 7
		b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	default:
		return nil, fmt.Errorf("unsupported uuid version %d", spec.Version)
	}

	return map[string]any{"value": formatUUID(b)}, nil
}

func formatUUID(b [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ---- keys ---------------------------------------------------------------

func generateSigner(algorithm string, rsaBits int, ecdsaCurve string, r io.Reader) (crypto.Signer, error) {
	switch algorithm {
	case "", "RSA":
		bits := rsaBits
		if bits == 0 {
			bits = 2048
		}
		return rsa.GenerateKey(r, bits)
	case "ECDSA":
		curve, err := curveFor(ecdsaCurve)
		if err != nil {
			return nil, err
		}
		return ecdsa.GenerateKey(curve, r)
	case "Ed25519":
		_, key, err := ed25519.GenerateKey(r)
		return key, err
	default:
		return nil, fmt.Errorf("unknown algorithm %q", algorithm)
	}
}

func curveFor(name string) (elliptic.Curve, error) {
	switch name {
	case "", "P256":
		return elliptic.P256(), nil
	case "P384":
		return elliptic.P384(), nil
	case "P521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unknown curve %q", name)
	}
}

func generatePrivateKey(algorithm string, rsaBits int, ecdsaCurve string, r io.Reader) (map[string]any, error) {
	key, err := generateSigner(algorithm, rsaBits, ecdsaCurve, r)
	if err != nil {
		return nil, err
	}
	privatePEM, publicPEM, err := keyPEMs(key)
	if err != nil {
		return nil, err
	}
	return map[string]any{"privatePEM": privatePEM, "publicPEM": publicPEM}, nil
}

func keyPEMs(key crypto.Signer) (privatePEM, publicPEM string, err error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	privatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return "", "", err
	}
	publicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return privatePEM, publicPEM, nil
}

func generateSSHKeyPair(spec secretsv1beta1.SSHKeyPairSpec, r io.Reader) (map[string]any, error) {
	key, err := generateSigner(spec.Algorithm, spec.RSABits, spec.ECDSACurve, r)
	if err != nil {
		return nil, err
	}

	block, err := ssh.MarshalPrivateKey(key, spec.Comment)
	if err != nil {
		return nil, fmt.Errorf("marshal openssh private key: %w", err)
	}
	privatePEM := string(pem.EncodeToMemory(block))

	sshPub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if spec.Comment != "" {
		authorized += " " + spec.Comment
	}

	return map[string]any{
		"privatePEM":        privatePEM,
		"publicOpenSSH":     authorized,
		"fingerprintSHA256": ssh.FingerprintSHA256(sshPub),
	}, nil
}

// ---- certificates -------------------------------------------------------

// caMaterial is a generated CA retained so later certificates can be signed by it.
type caMaterial struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM string
}

func generateCACertificate(spec secretsv1beta1.CACertificateSpec, r io.Reader, generatedAt time.Time, cas map[string]*caMaterial, resolved *ResolvedInputs) (*caMaterial, map[string]any, error) {
	key, err := generateSigner(spec.Algorithm, spec.RSABits, spec.ECDSACurve, r)
	if err != nil {
		return nil, nil, err
	}

	serial, err := randomSerial(r)
	if err != nil {
		return nil, nil, err
	}

	notBefore := generatedAt
	notAfter := notBefore.Add(durationOr(spec.Duration, 87600*time.Hour)) // 10y default

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subjectFor(spec.CommonName, spec.Subject),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if spec.MaxPathLen != nil {
		template.MaxPathLen = *spec.MaxPathLen
		template.MaxPathLenZero = *spec.MaxPathLen == 0
	}

	parentCert := template
	signerKey := key
	if spec.IssuerRef != nil {
		issuer, err := resolveIssuer(spec.IssuerRef, cas, resolved)
		if err != nil {
			return nil, nil, err
		}
		parentCert = issuer.cert
		signerKey = issuer.key
	}

	certPEM, cert, err := createCertificate(template, parentCert, key.Public(), signerKey, r)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return nil, nil, err
	}

	return &caMaterial{cert: cert, key: key, certPEM: certPEM},
		map[string]any{"certPEM": certPEM, "keyPEM": keyPEM}, nil
}

func generateTLSCertificate(spec secretsv1beta1.TLSCertificateSpec, r io.Reader, generatedAt time.Time, cas map[string]*caMaterial, resolved *ResolvedInputs) (map[string]any, error) {
	key, err := generateSigner(spec.Algorithm, spec.RSABits, spec.ECDSACurve, r)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial(r)
	if err != nil {
		return nil, err
	}

	notBefore := generatedAt
	notAfter := notBefore.Add(durationOr(spec.Duration, 8760*time.Hour)) // 1y default

	keyUsage, extKeyUsage := certUsages(spec.Usages)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subjectFor(spec.CommonName, spec.Subject),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		DNSNames:              spec.DNSNames,
		EmailAddresses:        spec.EmailAddresses,
	}
	for _, ip := range spec.IPAddresses {
		if parsed := net.ParseIP(ip); parsed != nil {
			template.IPAddresses = append(template.IPAddresses, parsed)
		} else {
			return nil, fmt.Errorf("invalid ipAddress %q", ip)
		}
	}
	for _, raw := range spec.URIs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid uri %q: %w", raw, err)
		}
		template.URIs = append(template.URIs, u)
	}

	parentCert := template
	signerKey := key
	caPEM := ""
	if spec.IssuerRef != nil {
		issuer, err := resolveIssuer(spec.IssuerRef, cas, resolved)
		if err != nil {
			return nil, err
		}
		parentCert = issuer.cert
		signerKey = issuer.key
		caPEM = issuer.certPEM
	}

	certPEM, _, err := createCertificate(template, parentCert, key.Public(), signerKey, r)
	if err != nil {
		return nil, err
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return nil, err
	}

	attrs := map[string]any{"certPEM": certPEM, "keyPEM": keyPEM}
	if caPEM != "" {
		attrs["caPEM"] = caPEM
	}
	return attrs, nil
}

func resolveIssuer(ref *secretsv1beta1.IssuerReference, cas map[string]*caMaterial, resolved *ResolvedInputs) (*caMaterial, error) {
	switch {
	case ref.Generated != "":
		ca, ok := cas[ref.Generated]
		if !ok {
			return nil, fmt.Errorf("issuerRef.generated %q is not a caCertificate declared earlier", ref.Generated)
		}
		return ca, nil
	case ref.Secret != "":
		if resolved == nil {
			return nil, fmt.Errorf("issuerRef.secret %q cannot be resolved without inputs", ref.Secret)
		}
		binding, ok := resolved.Secrets[ref.Secret]
		if !ok || binding.Single == nil {
			return nil, fmt.Errorf("issuerRef.secret %q must reference a single secret input", ref.Secret)
		}
		return caFromSecret(binding.Single)
	default:
		return nil, fmt.Errorf("issuerRef sets neither generated nor secret")
	}
}

func caFromSecret(s *ResolvedSecret) (*caMaterial, error) {
	certPEM := s.Data["tls.crt"]
	keyPEM := s.Data["tls.key"]
	if certPEM == "" || keyPEM == "" {
		return nil, fmt.Errorf("issuer secret %q must hold tls.crt and tls.key", s.Name)
	}
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	return &caMaterial{cert: cert, key: key, certPEM: certPEM}, nil
}

func createCertificate(template, parent *x509.Certificate, pub crypto.PublicKey, signerKey crypto.Signer, r io.Reader) (string, *x509.Certificate, error) {
	der, err := x509.CreateCertificate(r, template, parent, pub, signerKey)
	if err != nil {
		return "", nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", nil, err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return certPEM, cert, nil
}

func privateKeyPEM(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKey(keyPEM string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a signer")
	}
	return signer, nil
}

func subjectFor(commonName string, subject *secretsv1beta1.CertificateSubject) pkix.Name {
	name := pkix.Name{CommonName: commonName}
	if subject != nil {
		name.Organization = subject.Organizations
		name.OrganizationalUnit = subject.OrganizationalUnits
		name.Country = subject.Countries
		name.Locality = subject.Localities
		name.Province = subject.Provinces
		name.PostalCode = subject.PostalCodes
	}
	return name
}

func certUsages(usages []string) (x509.KeyUsage, []x509.ExtKeyUsage) {
	if len(usages) == 0 {
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	var ku x509.KeyUsage
	var eku []x509.ExtKeyUsage
	for _, u := range usages {
		switch u {
		case "digitalSignature":
			ku |= x509.KeyUsageDigitalSignature
		case "keyEncipherment":
			ku |= x509.KeyUsageKeyEncipherment
		case "dataEncipherment":
			ku |= x509.KeyUsageDataEncipherment
		case "keyAgreement":
			ku |= x509.KeyUsageKeyAgreement
		case "serverAuth":
			eku = append(eku, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			eku = append(eku, x509.ExtKeyUsageClientAuth)
		}
	}
	return ku, eku
}

func durationOr(d *metav1.Duration, fallback time.Duration) time.Duration {
	if d != nil && d.Duration > 0 {
		return d.Duration
	}
	return fallback
}

// ---- low-level random helpers (all drawing from the injected reader) ----

// drawIndex returns a uniformly random index in [0, n) using rejection sampling
// over bytes read from r, so there is no modulo bias.
func drawIndex(n int, r io.Reader) (int, error) {
	v, err := drawUint64(uint64(n), r)
	return int(v), err
}

// drawUint64 returns a uniformly random value in [0, n) for n > 0.
func drawUint64(n uint64, r io.Reader) (uint64, error) {
	if n == 0 {
		return 0, fmt.Errorf("range must be positive")
	}
	if n == 1 {
		return 0, nil
	}
	// Largest multiple of n that fits in uint64; reject values at or above it.
	limit := (^uint64(0)/n)*n - 1
	var buf [8]byte
	for {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint64(buf[:])
		if v <= limit {
			return v % n, nil
		}
	}
}

func drawString(alphabet string, length int, allowRepeat bool, r io.Reader) (string, error) {
	runes := []rune(alphabet)
	if !allowRepeat && length > len(runes) {
		return "", fmt.Errorf("length %d exceeds alphabet size %d with allowRepeat=false", length, len(runes))
	}
	used := map[rune]bool{}
	out := make([]rune, 0, length)
	for len(out) < length {
		idx, err := drawIndex(len(runes), r)
		if err != nil {
			return "", err
		}
		ch := runes[idx]
		if !allowRepeat {
			if used[ch] {
				continue
			}
			used[ch] = true
		}
		out = append(out, ch)
	}
	return string(out), nil
}

func shuffle(runes []rune, r io.Reader) error {
	for i := len(runes) - 1; i > 0; i-- {
		j, err := drawIndex(i+1, r)
		if err != nil {
			return err
		}
		runes[i], runes[j] = runes[j], runes[i]
	}
	return nil
}

func randomSerial(r io.Reader) (*big.Int, error) {
	var buf [16]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}
	serial := new(big.Int).SetBytes(buf[:])
	serial.Abs(serial)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func removeRunes(s, exclude string, excludeAmbiguous bool) string {
	drop := map[rune]bool{}
	for _, c := range exclude {
		drop[c] = true
	}
	if excludeAmbiguous {
		for _, c := range ambiguousChars {
			drop[c] = true
		}
	}
	return strings.Map(func(c rune) rune {
		if drop[c] {
			return -1
		}
		return c
	}, s)
}

// boolOrTrue dereferences an optional bool, defaulting to true when unset (the
// default for every PasswordSpec class toggle).
func boolOrTrue(p *bool) bool {
	if p == nil {
		return true
	}
	return *p
}
