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
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // sha1 offered for non-security digests (parity with Sprig sha1sum)
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"sigs.k8s.io/yaml"
)

// This file binds the Go recipe functions and base64 primitive as Starlark
// modules (tls.bundle, basicauth.credentials, jwt.sign, ...). Each builtin parses
// Starlark arguments into Go values, calls the engine-agnostic recipe, and returns
// a Starlark value.

func module(name string, members starlark.StringDict) *starlarkstruct.Module {
	return &starlarkstruct.Module{Name: name, Members: members}
}

// hashModule exposes deterministic digests over a string or bytes value, each
// returning a lowercase hex string. hmac_sha256 takes a key and the value.
func hashModule() *starlarkstruct.Module {
	digest := func(name string, sum func([]byte) []byte) *starlark.Builtin {
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var v starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "value", &v); err != nil {
				return nil, err
			}
			b, err := starlarkToBytes(v)
			if err != nil {
				return nil, err
			}
			return starlark.String(hex.EncodeToString(sum(b))), nil
		})
	}
	return module("hash", starlark.StringDict{
		"sha256": digest("hash.sha256", func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }),
		"sha512": digest("hash.sha512", func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }),
		"sha1":   digest("hash.sha1", func(b []byte) []byte { s := sha1.Sum(b); return s[:] }), //nolint:gosec // non-security digest
		"hmac_sha256": starlark.NewBuiltin("hash.hmac_sha256", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var keyVal, v starlark.Value
			if err := starlark.UnpackArgs("hash.hmac_sha256", args, kwargs, "key", &keyVal, "value", &v); err != nil {
				return nil, err
			}
			key, err := starlarkToBytes(keyVal)
			if err != nil {
				return nil, err
			}
			data, err := starlarkToBytes(v)
			if err != nil {
				return nil, err
			}
			mac := hmac.New(sha256.New, key)
			mac.Write(data)
			return starlark.String(hex.EncodeToString(mac.Sum(nil))), nil
		}),
	})
}

// hexModule encodes a string/bytes value to a hex string and decodes a hex string
// to bytes (mirroring base64).
func hexModule() *starlarkstruct.Module {
	return module("hex", starlark.StringDict{
		"encode": starlark.NewBuiltin("hex.encode", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var v starlark.Value
			if err := starlark.UnpackArgs("hex.encode", args, kwargs, "value", &v); err != nil {
				return nil, err
			}
			b, err := starlarkToBytes(v)
			if err != nil {
				return nil, err
			}
			return starlark.String(hex.EncodeToString(b)), nil
		}),
		"decode": starlark.NewBuiltin("hex.decode", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var s string
			if err := starlark.UnpackArgs("hex.decode", args, kwargs, "value", &s); err != nil {
				return nil, err
			}
			decoded, err := hex.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("hex.decode: %w", err)
			}
			return starlark.Bytes(decoded), nil
		}),
	})
}

// regexpModule offers match/replace/find_all over RE2 patterns (Go regexp).
func regexpModule() *starlarkstruct.Module {
	return module("regexp", starlark.StringDict{
		"match": starlark.NewBuiltin("regexp.match", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var pattern, s string
			if err := starlark.UnpackArgs("regexp.match", args, kwargs, "pattern", &pattern, "str", &s); err != nil {
				return nil, err
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("regexp.match: %w", err)
			}
			return starlark.Bool(re.MatchString(s)), nil
		}),
		"replace": starlark.NewBuiltin("regexp.replace", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var pattern, s, repl string
			if err := starlark.UnpackArgs("regexp.replace", args, kwargs, "pattern", &pattern, "str", &s, "repl", &repl); err != nil {
				return nil, err
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("regexp.replace: %w", err)
			}
			return starlark.String(re.ReplaceAllString(s, repl)), nil
		}),
		"find_all": starlark.NewBuiltin("regexp.find_all", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var pattern, s string
			if err := starlark.UnpackArgs("regexp.find_all", args, kwargs, "pattern", &pattern, "str", &s); err != nil {
				return nil, err
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("regexp.find_all: %w", err)
			}
			matches := re.FindAllString(s, -1)
			items := make([]starlark.Value, len(matches))
			for i, m := range matches {
				items[i] = starlark.String(m)
			}
			return starlark.NewList(items), nil
		}),
	})
}

// urlModule wraps net/url query/path escaping for building URLs from input values.
func urlModule() *starlarkstruct.Module {
	escaper := func(name string, fn func(string) string) *starlark.Builtin {
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var s string
			if err := starlark.UnpackArgs(name, args, kwargs, "value", &s); err != nil {
				return nil, err
			}
			return starlark.String(fn(s)), nil
		})
	}
	unescaper := func(name string, fn func(string) (string, error)) *starlark.Builtin {
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var s string
			if err := starlark.UnpackArgs(name, args, kwargs, "value", &s); err != nil {
				return nil, err
			}
			out, err := fn(s)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			return starlark.String(out), nil
		})
	}
	return module("url", starlark.StringDict{
		"query_escape":   escaper("url.query_escape", url.QueryEscape),
		"query_unescape": unescaper("url.query_unescape", url.QueryUnescape),
		"path_escape":    escaper("url.path_escape", url.PathEscape),
		"path_unescape":  unescaper("url.path_unescape", url.PathUnescape),
	})
}

// yamlModule encodes a value to YAML and decodes YAML to a value, via
// sigs.k8s.io/yaml (YAML<->JSON) so decoded maps carry string keys.
func yamlModule() *starlarkstruct.Module {
	return module("yaml", starlark.StringDict{
		"encode": starlark.NewBuiltin("yaml.encode", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var v starlark.Value
			if err := starlark.UnpackArgs("yaml.encode", args, kwargs, "value", &v); err != nil {
				return nil, err
			}
			decoded, err := fromStarlark(v)
			if err != nil {
				return nil, err
			}
			out, err := yaml.Marshal(decoded)
			if err != nil {
				return nil, fmt.Errorf("yaml.encode: %w", err)
			}
			return starlark.String(out), nil
		}),
		"decode": starlark.NewBuiltin("yaml.decode", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var s string
			if err := starlark.UnpackArgs("yaml.decode", args, kwargs, "value", &s); err != nil {
				return nil, err
			}
			var decoded any
			if err := yaml.Unmarshal([]byte(s), &decoded); err != nil {
				return nil, fmt.Errorf("yaml.decode: %w", err)
			}
			return toStarlark(decoded)
		}),
	})
}

func base64Module() *starlarkstruct.Module {
	return module("base64", starlark.StringDict{
		"encode": starlark.NewBuiltin("base64.encode", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var v starlark.Value
			if err := starlark.UnpackArgs("base64.encode", args, kwargs, "value", &v); err != nil {
				return nil, err
			}
			b, err := starlarkToBytes(v)
			if err != nil {
				return nil, err
			}
			return starlark.String(base64.StdEncoding.EncodeToString(b)), nil
		}),
		"decode": starlark.NewBuiltin("base64.decode", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var s string
			if err := starlark.UnpackArgs("base64.decode", args, kwargs, "value", &s); err != nil {
				return nil, err
			}
			decoded, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("base64.decode: %w", err)
			}
			return starlark.Bytes(decoded), nil
		}),
	})
}

func tlsModule() *starlarkstruct.Module {
	return module("tls", starlark.StringDict{
		"bundle": starlark.NewBuiltin("tls.bundle", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var certsVal starlark.Value
			if err := starlark.UnpackArgs("tls.bundle", args, kwargs, "certs", &certsVal); err != nil {
				return nil, err
			}
			certs, err := starlarkStringSlice(certsVal)
			if err != nil {
				return nil, err
			}
			out, err := TLSBundle(certs)
			if err != nil {
				return nil, err
			}
			return starlark.String(out), nil
		}),
	})
}

func basicAuthModule() *starlarkstruct.Module {
	cred := func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var user, pw string
		if err := starlark.UnpackArgs("basicauth.credentials", args, kwargs, "user", &user, "password", &pw); err != nil {
			return nil, err
		}
		return starlark.String(BasicAuthCredentials(user, pw)), nil
	}
	header := func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var user, pw string
		if err := starlark.UnpackArgs("basicauth.header", args, kwargs, "user", &user, "password", &pw); err != nil {
			return nil, err
		}
		return starlark.String(BasicAuthHeader(user, pw)), nil
	}
	return module("basicauth", starlark.StringDict{
		"credentials": starlark.NewBuiltin("basicauth.credentials", cred),
		"header":      starlark.NewBuiltin("basicauth.header", header),
	})
}

func dockerConfigModule() *starlarkstruct.Module {
	build := func(registriesVal starlark.Value) (string, error) {
		rows, err := starlarkMapSlice(registriesVal)
		if err != nil {
			return "", err
		}
		registries := make([]DockerRegistry, 0, len(rows))
		for _, row := range rows {
			registries = append(registries, DockerRegistry{
				Registry: asString(row["registry"]),
				Username: asString(row["username"]),
				Password: asString(row["password"]),
				Email:    asString(row["email"]),
			})
		}
		return DockerConfigJSON(registries)
	}
	return module("dockerconfig", starlark.StringDict{
		"json": starlark.NewBuiltin("dockerconfig.json", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var v starlark.Value
			if err := starlark.UnpackArgs("dockerconfig.json", args, kwargs, "registries", &v); err != nil {
				return nil, err
			}
			out, err := build(v)
			if err != nil {
				return nil, err
			}
			return starlark.String(out), nil
		}),
	})
}

func htpasswdModule() *starlarkstruct.Module {
	parseEntries := func(v starlark.Value) ([]HtpasswdEntry, error) {
		rows, err := starlarkMapSlice(v)
		if err != nil {
			return nil, err
		}
		entries := make([]HtpasswdEntry, 0, len(rows))
		for _, row := range rows {
			entries = append(entries, HtpasswdEntry{Username: asString(row["username"]), Password: asString(row["password"])})
		}
		return entries, nil
	}
	return module("htpasswd", starlark.StringDict{
		"bcrypt": starlark.NewBuiltin("htpasswd.bcrypt", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var v starlark.Value
			if err := starlark.UnpackArgs("htpasswd.bcrypt", args, kwargs, "entries", &v); err != nil {
				return nil, err
			}
			entries, err := parseEntries(v)
			if err != nil {
				return nil, err
			}
			out, err := HtpasswdBcrypt(entries)
			if err != nil {
				return nil, err
			}
			return starlark.String(out), nil
		}),
		"sha": starlark.NewBuiltin("htpasswd.sha", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var v starlark.Value
			if err := starlark.UnpackArgs("htpasswd.sha", args, kwargs, "entries", &v); err != nil {
				return nil, err
			}
			entries, err := parseEntries(v)
			if err != nil {
				return nil, err
			}
			return starlark.String(HtpasswdSHA(entries)), nil
		}),
		"apr1": starlark.NewBuiltin("htpasswd.apr1", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var entriesVal, saltsVal starlark.Value
			if err := starlark.UnpackArgs("htpasswd.apr1", args, kwargs, "entries", &entriesVal, "salts", &saltsVal); err != nil {
				return nil, err
			}
			entries, err := parseEntries(entriesVal)
			if err != nil {
				return nil, err
			}
			salts, err := starlarkStringSlice(saltsVal)
			if err != nil {
				return nil, err
			}
			out, err := HtpasswdAPR1(entries, salts)
			if err != nil {
				return nil, err
			}
			return starlark.String(out), nil
		}),
	})
}

func kubeconfigModule() *starlarkstruct.Module {
	return module("kubeconfig", starlark.StringDict{
		"from_service_account": starlark.NewBuiltin("kubeconfig.from_service_account", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var sa starlark.Value
			var clusterName, userName, contextName string
			if err := starlark.UnpackArgs("kubeconfig.from_service_account", args, kwargs,
				"serviceAccount", &sa, "clusterName?", &clusterName, "userName?", &userName, "contextName?", &contextName); err != nil {
				return nil, err
			}
			token, err := attrString(sa, "token")
			if err != nil {
				return nil, err
			}
			cluster, err := getAttr(sa, "cluster")
			if err != nil {
				return nil, err
			}
			server, err := attrString(cluster, "server")
			if err != nil {
				return nil, err
			}
			caCert, err := attrString(cluster, "caCert")
			if err != nil {
				return nil, err
			}
			out, err := KubeconfigFromServiceAccount(token, server, caCert, clusterName, userName, contextName)
			if err != nil {
				return nil, err
			}
			return starlark.String(out), nil
		}),
		"build": starlark.NewBuiltin("kubeconfig.build", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var p KubeconfigParams
			if err := starlark.UnpackArgs("kubeconfig.build", args, kwargs,
				"server?", &p.Server, "caCert?", &p.CACert, "token?", &p.Token,
				"clientCert?", &p.ClientCert, "clientKey?", &p.ClientKey,
				"clusterName?", &p.ClusterName, "userName?", &p.UserName,
				"contextName?", &p.ContextName, "namespace?", &p.Namespace); err != nil {
				return nil, err
			}
			out, err := KubeconfigBuild(p)
			if err != nil {
				return nil, err
			}
			return starlark.String(out), nil
		}),
		"merge": starlark.NewBuiltin("kubeconfig.merge", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var configsVal starlark.Value
			var currentContext string
			var strict bool
			if err := starlark.UnpackArgs("kubeconfig.merge", args, kwargs,
				"configs", &configsVal, "currentContext?", &currentContext, "strict?", &strict); err != nil {
				return nil, err
			}
			configs, err := starlarkStringSlice(configsVal)
			if err != nil {
				return nil, err
			}
			out, err := KubeconfigMerge(configs, currentContext, strict)
			if err != nil {
				return nil, err
			}
			return starlark.String(out), nil
		}),
	})
}

func jwtModule(generatedAt time.Time) *starlarkstruct.Module {
	return module("jwt", starlark.StringDict{
		"sign": starlark.NewBuiltin("jwt.sign", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var claimsVal starlark.Value
			var key, alg, kid, expiresIn, notBefore string
			if err := starlark.UnpackArgs("jwt.sign", args, kwargs,
				"claims", &claimsVal, "key", &key, "alg", &alg,
				"kid?", &kid, "expiresIn?", &expiresIn, "notBefore?", &notBefore); err != nil {
				return nil, err
			}
			claimsAny, err := fromStarlark(claimsVal)
			if err != nil {
				return nil, err
			}
			claims, ok := claimsAny.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("jwt.sign: claims must be a dict")
			}
			opts := JWTOptions{Kid: kid, IssuedAt: generatedAt}
			if expiresIn != "" {
				d, err := time.ParseDuration(expiresIn)
				if err != nil {
					return nil, fmt.Errorf("jwt.sign: invalid expiresIn %q: %w", expiresIn, err)
				}
				opts.ExpiresIn = d
			}
			if notBefore != "" {
				d, err := time.ParseDuration(notBefore)
				if err != nil {
					return nil, fmt.Errorf("jwt.sign: invalid notBefore %q: %w", notBefore, err)
				}
				opts.NotBefore = d
			}
			out, err := JWTSign(claims, key, alg, opts)
			if err != nil {
				return nil, err
			}
			return starlark.String(out), nil
		}),
		"decode": starlark.NewBuiltin("jwt.decode", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var token string
			if err := starlark.UnpackArgs("jwt.decode", args, kwargs, "token", &token); err != nil {
				return nil, err
			}
			header, claims, err := JWTDecode(token)
			if err != nil {
				return nil, err
			}
			headerVal, err := toStarlark(header)
			if err != nil {
				return nil, err
			}
			claimsVal, err := toStarlark(claims)
			if err != nil {
				return nil, err
			}
			return starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
				"header": headerVal,
				"claims": claimsVal,
			}), nil
		}),
	})
}

// ---- argument helpers ---------------------------------------------------

func starlarkToBytes(v starlark.Value) ([]byte, error) {
	switch t := v.(type) {
	case starlark.String:
		return []byte(t), nil
	case starlark.Bytes:
		return []byte(t), nil
	default:
		return nil, fmt.Errorf("expected string or bytes, got %s", v.Type())
	}
}

func starlarkStringSlice(v starlark.Value) ([]string, error) {
	decoded, err := fromStarlark(v)
	if err != nil {
		return nil, err
	}
	list, ok := decoded.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a list, got %s", v.Type())
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("expected a list of strings")
		}
		out = append(out, s)
	}
	return out, nil
}

func starlarkMapSlice(v starlark.Value) ([]map[string]any, error) {
	decoded, err := fromStarlark(v)
	if err != nil {
		return nil, err
	}
	list, ok := decoded.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a list, got %s", v.Type())
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected a list of dicts")
		}
		out = append(out, m)
	}
	return out, nil
}

func getAttr(v starlark.Value, name string) (starlark.Value, error) {
	ha, ok := v.(starlark.HasAttrs)
	if !ok {
		return nil, fmt.Errorf("value of type %s has no attributes", v.Type())
	}
	attr, err := ha.Attr(name)
	if err != nil || attr == nil {
		return nil, fmt.Errorf("missing attribute %q", name)
	}
	return attr, nil
}

func attrString(v starlark.Value, name string) (string, error) {
	attr, err := getAttr(v, name)
	if err != nil {
		return "", err
	}
	s, ok := starlark.AsString(attr)
	if !ok {
		return "", fmt.Errorf("attribute %q is not a string", name)
	}
	return s, nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
