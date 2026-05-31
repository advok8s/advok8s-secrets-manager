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
	"encoding/base64"
	"fmt"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// This file binds the Go recipe functions and base64 primitive as Starlark
// modules (tls.bundle, basicauth.credentials, jwt.sign, ...). Each builtin parses
// Starlark arguments into Go values, calls the engine-agnostic recipe, and returns
// a Starlark value.

func module(name string, members starlark.StringDict) *starlarkstruct.Module {
	return &starlarkstruct.Module{Name: name, Members: members}
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
		"fromServiceAccount": starlark.NewBuiltin("kubeconfig.fromServiceAccount", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var sa starlark.Value
			var clusterName, userName, contextName string
			if err := starlark.UnpackArgs("kubeconfig.fromServiceAccount", args, kwargs,
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
