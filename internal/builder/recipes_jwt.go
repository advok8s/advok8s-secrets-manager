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
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTOptions carries the time-bound and header parameters for JWTSign. Times are
// anchored at IssuedAt (the persisted generatedAt) so a signed token is
// reproducible across refreshes.
type JWTOptions struct {
	Kid       string
	IssuedAt  time.Time     // iat; also the anchor for exp/nbf
	ExpiresIn time.Duration // exp = IssuedAt + ExpiresIn, when > 0
	NotBefore time.Duration // nbf = IssuedAt + NotBefore, when != 0
}

// JWTSign produces a compact signed JWT. The key is interpreted per the algorithm
// family: HS* take the raw shared secret; RS*/PS* and ES* take a PEM-encoded
// private key. EdDSA is intentionally not offered in v1 (no bare Ed25519 key kind
// backs it - see the design notes).
func JWTSign(claims map[string]any, key, alg string, opts JWTOptions) (string, error) {
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", fmt.Errorf("unknown JWT algorithm %q", alg)
	}

	mc := jwt.MapClaims{}
	for k, v := range claims {
		mc[k] = v
	}
	if !opts.IssuedAt.IsZero() {
		mc["iat"] = opts.IssuedAt.Unix()
	}
	if opts.ExpiresIn > 0 {
		mc["exp"] = opts.IssuedAt.Add(opts.ExpiresIn).Unix()
	}
	if opts.NotBefore != 0 {
		mc["nbf"] = opts.IssuedAt.Add(opts.NotBefore).Unix()
	}

	token := jwt.NewWithClaims(method, mc)
	if opts.Kid != "" {
		token.Header["kid"] = opts.Kid
	}

	keyObj, err := jwtSigningKey(alg, key)
	if err != nil {
		return "", err
	}
	return token.SignedString(keyObj)
}

// jwtSigningKey turns the key material into the type golang-jwt expects for the
// algorithm family.
func jwtSigningKey(alg, key string) (any, error) {
	switch {
	case strings.HasPrefix(alg, "HS"):
		return []byte(key), nil
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"), strings.HasPrefix(alg, "ES"):
		signer, err := parsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parsing PEM signing key: %w", err)
		}
		return signer, nil
	case alg == "EdDSA":
		return nil, fmt.Errorf("EdDSA is not offered in v1 (no bare Ed25519 key kind)")
	default:
		return nil, fmt.Errorf("unsupported JWT algorithm %q", alg)
	}
}

// JWTDecode parses a token's header and claims WITHOUT verifying its signature -
// a pure transform for reshaping a token already held. It does not establish
// trust; verification is deliberately out of scope.
func JWTDecode(token string) (header map[string]any, claims map[string]any, err error) {
	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, nil, err
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected claims type")
	}
	return parsed.Header, map[string]any(mc), nil
}
