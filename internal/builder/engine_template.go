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
	"bytes"
	"fmt"
	"sort"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
)

// TemplateEngine renders a per-key map of gotemplate templates. The dot context
// exposes the resolved inputs (.constants, .context, .secrets, .configMaps,
// .serviceAccount, .generated); the FuncMap is Sprig plus the recipe functions
// and the fail/retry/required outcome funcs. missingkey=error makes referencing
// an absent key a generation error rather than emitting "<no value>".
type TemplateEngine struct {
	Data           map[string]string // output key -> template source
	MaxOutputBytes int
}

// NewTemplateEngine returns an engine for the given per-key template map.
func NewTemplateEngine(data map[string]string) *TemplateEngine { return &TemplateEngine{Data: data} }

// Render executes each key's template. Labels and type are not produced here (the
// per-key data model has no place for them); the controller applies spec.output.
func (e *TemplateEngine) Render(in *ResolvedInputs) (*Result, error) {
	ctx := buildTemplateContext(in)
	funcs := templateFuncMap(in)

	maxOut := e.MaxOutputBytes
	if maxOut == 0 {
		maxOut = defaultMaxOutputBytes
	}

	result := &Result{Data: map[string][]byte{}, Labels: map[string]string{}}
	total := 0

	keys := make([]string, 0, len(e.Data))
	for k := range e.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		tmpl, err := template.New(key).Funcs(funcs).Option("missingkey=error").Parse(e.Data[key])
		if err != nil {
			return nil, fmt.Errorf("template[%q]: parse: %w", key, err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, ctx); err != nil {
			return nil, classifyEngineError(err)
		}
		total += buf.Len()
		if total > maxOut {
			return nil, fmt.Errorf("generated Secret data exceeds %d bytes", maxOut)
		}
		result.Data[key] = append([]byte(nil), buf.Bytes()...)
	}

	return result, nil
}

func buildTemplateContext(in *ResolvedInputs) map[string]any {
	secrets := map[string]any{}
	for handle, binding := range in.Secrets {
		if binding.IsList {
			list := make([]any, 0, len(binding.List))
			for _, s := range binding.List {
				list = append(list, secretToMap(s))
			}
			secrets[handle] = list
		} else if binding.Single != nil {
			secrets[handle] = secretToMap(binding.Single)
		}
	}

	configMaps := map[string]any{}
	for handle, binding := range in.ConfigMaps {
		if binding.IsList {
			list := make([]any, 0, len(binding.List))
			for _, c := range binding.List {
				list = append(list, configMapToMap(c))
			}
			configMaps[handle] = list
		} else if binding.Single != nil {
			configMaps[handle] = configMapToMap(binding.Single)
		}
	}

	ctx := map[string]any{
		"constants": in.Constants,
		"context": map[string]any{
			"namespace":   in.Context.Namespace,
			"name":        in.Context.Name,
			"labels":      in.Context.Labels,
			"annotations": in.Context.Annotations,
			"uid":         in.Context.UID,
			"generatedAt": in.Context.GeneratedAt,
		},
		"secrets":    secrets,
		"configMaps": configMaps,
		"generated":  in.Generated,
	}
	if in.ServiceAccount != nil {
		ctx["serviceAccount"] = map[string]any{
			"name":      in.ServiceAccount.Name,
			"namespace": in.ServiceAccount.Namespace,
			"token":     in.ServiceAccount.Token,
			"cluster": map[string]any{
				"server": in.ServiceAccount.ClusterServer,
				"caCert": in.ServiceAccount.ClusterCACert,
			},
		}
	} else {
		ctx["serviceAccount"] = nil
	}
	return ctx
}

func secretToMap(s *ResolvedSecret) map[string]any {
	return map[string]any{
		"name": s.Name, "type": s.Type, "uid": s.UID,
		"labels": s.Labels, "annotations": s.Annotations, "data": s.Data,
	}
}

func configMapToMap(c *ResolvedConfigMap) map[string]any {
	return map[string]any{
		"name": c.Name, "uid": c.UID,
		"labels": c.Labels, "annotations": c.Annotations,
		"data": c.Data, "binaryData": c.BinaryData,
	}
}

// templateFuncMap is Sprig plus outcome funcs (fail/retry/retryAfter/required) and
// the recipe functions (underscore-named, gotemplate's flat-namespace convention).
func templateFuncMap(in *ResolvedInputs) template.FuncMap {
	funcs := sprig.TxtFuncMap()

	funcs["fail"] = func(message string) (string, error) { return "", &FailError{Message: message} }
	funcs["retry"] = func(message string) (string, error) { return "", &RetryError{Message: message} }
	funcs["retryAfter"] = func(after, message string) (string, error) {
		d, err := time.ParseDuration(after)
		if err != nil {
			return "", fmt.Errorf("retryAfter: invalid duration %q: %w", after, err)
		}
		return "", &RetryError{Message: message, After: d}
	}
	funcs["required"] = func(message string, value any) (any, error) {
		if isEmptyValue(value) {
			return nil, fmt.Errorf("%s", message)
		}
		return value, nil
	}

	funcs["basicauth_credentials"] = BasicAuthCredentials
	funcs["basicauth_header"] = BasicAuthHeader
	funcs["tls_bundle"] = func(certs any) (string, error) {
		s, err := anyStringSlice(certs)
		if err != nil {
			return "", err
		}
		return TLSBundle(s)
	}
	funcs["dockerconfig_json"] = func(registries any) (string, error) {
		rows, err := anyMapSlice(registries)
		if err != nil {
			return "", err
		}
		regs := make([]DockerRegistry, 0, len(rows))
		for _, r := range rows {
			regs = append(regs, DockerRegistry{Registry: asString(r["registry"]), Username: asString(r["username"]), Password: asString(r["password"]), Email: asString(r["email"])})
		}
		return DockerConfigJSON(regs)
	}
	funcs["htpasswd_bcrypt"] = func(entries any) (string, error) {
		e, err := anyHtpasswdEntries(entries)
		if err != nil {
			return "", err
		}
		return HtpasswdBcrypt(e)
	}
	funcs["htpasswd_sha"] = func(entries any) (string, error) {
		e, err := anyHtpasswdEntries(entries)
		if err != nil {
			return "", err
		}
		return HtpasswdSHA(e), nil
	}
	funcs["htpasswd_apr1"] = func(entries, salts any) (string, error) {
		e, err := anyHtpasswdEntries(entries)
		if err != nil {
			return "", err
		}
		s, err := anyStringSlice(salts)
		if err != nil {
			return "", err
		}
		return HtpasswdAPR1(e, s)
	}
	funcs["kubeconfig_merge"] = func(configs any, currentContext string, strict bool) (string, error) {
		s, err := anyStringSlice(configs)
		if err != nil {
			return "", err
		}
		return KubeconfigMerge(s, currentContext, strict)
	}
	funcs["jwt_sign"] = func(claims any, key, alg string, opts ...map[string]any) (string, error) {
		claimsMap, ok := claims.(map[string]any)
		if !ok {
			return "", fmt.Errorf("jwt_sign: claims must be a dict")
		}
		jo := JWTOptions{IssuedAt: in.Context.GeneratedAt}
		if len(opts) > 0 {
			o := opts[0]
			jo.Kid = asString(o["kid"])
			if exp := asString(o["expiresIn"]); exp != "" {
				d, err := time.ParseDuration(exp)
				if err != nil {
					return "", fmt.Errorf("jwt_sign: invalid expiresIn %q: %w", exp, err)
				}
				jo.ExpiresIn = d
			}
			if nbf := asString(o["notBefore"]); nbf != "" {
				d, err := time.ParseDuration(nbf)
				if err != nil {
					return "", fmt.Errorf("jwt_sign: invalid notBefore %q: %w", nbf, err)
				}
				jo.NotBefore = d
			}
		}
		return JWTSign(claimsMap, key, alg, jo)
	}

	return funcs
}

func isEmptyValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	default:
		return false
	}
}

// anyStringSlice accepts a []string or a Sprig []any of strings.
func anyStringSlice(v any) ([]string, error) {
	switch t := v.(type) {
	case []string:
		return t, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("expected a list of strings")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected a list, got %T", v)
	}
}

func anyMapSlice(v any) ([]map[string]any, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a list, got %T", v)
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

func anyHtpasswdEntries(v any) ([]HtpasswdEntry, error) {
	rows, err := anyMapSlice(v)
	if err != nil {
		return nil, err
	}
	entries := make([]HtpasswdEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, HtpasswdEntry{Username: asString(r["username"]), Password: asString(r["password"])})
	}
	return entries, nil
}
