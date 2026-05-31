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
	"crypto/md5"  //nolint:gosec // apr1 (htpasswd) is defined in terms of MD5; not used for security here
	"crypto/sha1" //nolint:gosec // the htpasswd {SHA} scheme is defined in terms of SHA-1
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// This file holds the engine-agnostic recipe functions: pure Go that the Starlark
// and gotemplate engines wrap as callable helpers. Each takes plain values and
// returns strings (or data maps), so it can be unit-tested directly.

// ---- tls ----------------------------------------------------------------

// TLSBundle concatenates PEM certificates in order into a single PEM blob, used
// for a leaf+issuer fullchain (leaf first) or a multi-CA trust bundle. Each input
// may itself contain multiple CERTIFICATE blocks; all are normalised and kept in
// order. A non-certificate or empty input is an error.
func TLSBundle(certs []string) (string, error) {
	var out strings.Builder
	for i, cert := range certs {
		rest := []byte(cert)
		found := false
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = remaining
			if block.Type != "CERTIFICATE" {
				return "", fmt.Errorf("bundle entry %d: unexpected PEM block %q (want CERTIFICATE)", i, block.Type)
			}
			out.Write(pem.EncodeToMemory(block))
			found = true
		}
		if !found {
			return "", fmt.Errorf("bundle entry %d: no CERTIFICATE PEM block found", i)
		}
	}
	return out.String(), nil
}

// ---- basicauth ----------------------------------------------------------

// BasicAuthCredentials returns base64(user:password) with no scheme prefix - the
// form embedded as the "auth" field of a docker config and the body of an
// Authorization header.
func BasicAuthCredentials(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}

// BasicAuthHeader returns a full HTTP Basic Authorization header value.
func BasicAuthHeader(user, password string) string {
	return "Basic " + BasicAuthCredentials(user, password)
}

// ---- dockerconfig -------------------------------------------------------

// DockerRegistry is one registry credential for a docker config JSON.
type DockerRegistry struct {
	Registry string
	Username string
	Password string
	Email    string
}

// DockerConfigJSON builds the .dockerconfigjson content for a set of registry
// credentials, computing each auth as base64(user:password) so callers never deal
// with the encoding themselves.
func DockerConfigJSON(registries []DockerRegistry) (string, error) {
	auths := map[string]map[string]string{}
	for _, r := range registries {
		if r.Registry == "" {
			return "", fmt.Errorf("docker registry entry is missing a registry host")
		}
		entry := map[string]string{
			"username": r.Username,
			"password": r.Password,
			"auth":     BasicAuthCredentials(r.Username, r.Password),
		}
		if r.Email != "" {
			entry["email"] = r.Email
		}
		auths[r.Registry] = entry
	}
	encoded, err := json.Marshal(map[string]any{"auths": auths})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// ---- htpasswd -----------------------------------------------------------

// HtpasswdEntry is one username/password pair for an htpasswd file.
type HtpasswdEntry struct {
	Username string
	Password string
}

// HtpasswdBcrypt produces htpasswd file content with bcrypt-hashed passwords (the
// recommended scheme). bcrypt draws its own salt; the result is persisted with the
// generated material so it is stable across refreshes.
func HtpasswdBcrypt(entries []HtpasswdEntry) (string, error) {
	var lines []string
	for _, e := range entries {
		hash, err := bcrypt.GenerateFromPassword([]byte(e.Password), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		lines = append(lines, e.Username+":"+string(hash))
	}
	return joinLines(lines), nil
}

// HtpasswdSHA produces htpasswd content using the {SHA} scheme
// (base64(sha1(password))). Provided for compatibility; it is unsalted, so prefer
// bcrypt.
func HtpasswdSHA(entries []HtpasswdEntry) string {
	var lines []string
	for _, e := range entries {
		sum := sha1.Sum([]byte(e.Password)) //nolint:gosec // {SHA} scheme is defined as SHA-1
		lines = append(lines, e.Username+":{SHA}"+base64.StdEncoding.EncodeToString(sum[:]))
	}
	return joinLines(lines)
}

// HtpasswdAPR1 produces htpasswd content using Apache's apr1 (MD5-based) scheme.
// Each entry's salt (up to 8 chars from the apr1 alphabet) is supplied by the
// caller so the hash is reproducible/persisted.
func HtpasswdAPR1(entries []HtpasswdEntry, salts []string) (string, error) {
	var lines []string
	for i, e := range entries {
		salt := ""
		if i < len(salts) {
			salt = salts[i]
		}
		if salt == "" {
			return "", fmt.Errorf("apr1 entry %d (%q) needs a salt", i, e.Username)
		}
		lines = append(lines, e.Username+":"+apr1(e.Password, salt))
	}
	return joinLines(lines), nil
}

func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// apr1Alphabet is the non-standard base64 ordering used by crypt(3)/apr1.
const apr1Alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// apr1 implements Apache's apr1 password hashing (md5crypt with the "$apr1$"
// magic). The salt is truncated to 8 characters, as in the reference.
func apr1(password, salt string) string {
	if len(salt) > 8 {
		salt = salt[:8]
	}
	const magic = "$apr1$"

	// Primary digest: password + magic + salt.
	primary := md5.New() //nolint:gosec // apr1 is defined in terms of MD5
	primary.Write([]byte(password))
	primary.Write([]byte(magic))
	primary.Write([]byte(salt))

	// Alternate digest: password + salt + password, folded into the primary.
	alt := md5.New() //nolint:gosec // apr1 is defined in terms of MD5
	alt.Write([]byte(password))
	alt.Write([]byte(salt))
	alt.Write([]byte(password))
	altSum := alt.Sum(nil)

	for i := len(password); i > 0; i -= 16 {
		n := 16
		if i < 16 {
			n = i
		}
		primary.Write(altSum[:n])
	}

	// Weird length-dependent mixing from the reference.
	for i := len(password); i > 0; i >>= 1 {
		if i&1 == 1 {
			primary.Write([]byte{0})
		} else {
			primary.Write([]byte{password[0]})
		}
	}

	digest := primary.Sum(nil)

	// 1000 strengthening iterations.
	for i := 0; i < 1000; i++ {
		ctx := md5.New() //nolint:gosec // apr1 is defined in terms of MD5
		if i&1 == 1 {
			ctx.Write([]byte(password))
		} else {
			ctx.Write(digest)
		}
		if i%3 != 0 {
			ctx.Write([]byte(salt))
		}
		if i%7 != 0 {
			ctx.Write([]byte(password))
		}
		if i&1 == 1 {
			ctx.Write(digest)
		} else {
			ctx.Write([]byte(password))
		}
		digest = ctx.Sum(nil)
	}

	return magic + salt + "$" + apr1Encode(digest)
}

// apr1Encode applies the crypt-style base64 over the digest in apr1's byte order.
func apr1Encode(digest []byte) string {
	var out strings.Builder
	encode := func(b2, b1, b0 byte, n int) {
		v := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
		for i := 0; i < n; i++ {
			out.WriteByte(apr1Alphabet[v&0x3f])
			v >>= 6
		}
	}
	encode(digest[0], digest[6], digest[12], 4)
	encode(digest[1], digest[7], digest[13], 4)
	encode(digest[2], digest[8], digest[14], 4)
	encode(digest[3], digest[9], digest[15], 4)
	encode(digest[4], digest[10], digest[5], 4)
	encode(0, 0, digest[11], 2)
	return out.String()
}
