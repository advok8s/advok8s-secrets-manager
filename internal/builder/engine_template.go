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
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"sigs.k8s.io/yaml"
)

// TemplateEngine renders a per-key map of gotemplate templates. The dot context
// exposes the resolved inputs (.constants, .context, .secrets, .configMaps,
// .serviceAccount, .generated); the FuncMap is Sprig plus the recipe functions
// and the fail/retry/required outcome funcs. missingkey=error makes referencing
// an absent key a generation error rather than emitting "<no value>".
//
// For the ConfigMap output kind there is deliberately no binaryData support:
// templates render UTF-8 text (the template source itself lives in a CRD string
// field), so every rendered data value must be valid UTF-8 - splicing a binary
// secret value through a template is caught by the shared validation. Binary
// output requires the script generator, where raw bytes are first-class.
type TemplateEngine struct {
	Data           map[string]string // output key -> template source
	Type           string            // optional gotemplate for the Secret type (Secret kind only)
	Labels         map[string]string // optional label-value gotemplates
	Annotations    map[string]string // optional annotation-value gotemplates
	Kind           OutputKind        // output contract (default OutputSecret)
	MaxOutputBytes int
}

// NewTemplateEngine returns an engine for the given per-key template map.
func NewTemplateEngine(data map[string]string) *TemplateEngine { return &TemplateEngine{Data: data} }

// Render executes each data-key template, plus the optional type, label and
// annotation templates. type overrides spec.output.type; labels and annotations
// merge over spec.output.labels / spec.output.annotations (the controller
// applies that merge), mirroring the Starlark
// secret = {data, type, labels, annotations} contract.
func (e *TemplateEngine) Render(in *ResolvedInputs) (*Result, error) {
	ctx := buildTemplateContext(in)
	funcs := templateFuncMap(in)

	maxOut := e.MaxOutputBytes
	if maxOut == 0 {
		maxOut = defaultMaxOutputBytes
	}

	render := func(name, src string) (string, error) {
		tmpl, err := template.New(name).Funcs(funcs).Option("missingkey=error").Parse(src)
		if err != nil {
			return "", fmt.Errorf("template[%q]: parse: %w", name, err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, ctx); err != nil {
			return "", classifyEngineError(err)
		}
		return buf.String(), nil
	}

	result := &Result{Data: map[string][]byte{}, Labels: map[string]string{}}
	total := 0

	for _, key := range sortedKeys(e.Data) {
		out, err := render("data."+key, e.Data[key])
		if err != nil {
			return nil, err
		}
		total += len(out)
		if total > maxOut {
			return nil, fmt.Errorf("generated %s data exceeds %d bytes", e.Kind.name(), maxOut)
		}
		result.Data[key] = []byte(out)
	}

	if e.Kind != OutputConfigMap && e.Type != "" {
		t, err := render("type", e.Type)
		if err != nil {
			return nil, err
		}
		result.Type = t
	}

	for _, key := range sortedKeys(e.Labels) {
		v, err := render("labels."+key, e.Labels[key])
		if err != nil {
			return nil, err
		}
		result.Labels[key] = v
	}

	if len(e.Annotations) > 0 {
		result.Annotations = map[string]string{}
		for _, key := range sortedKeys(e.Annotations) {
			v, err := render("annotations."+key, e.Annotations[key])
			if err != nil {
				return nil, err
			}
			result.Annotations[key] = v
		}
		if err := validateAnnotations(result.Annotations, "template", e.Kind.reservedPrefix()); err != nil {
			return nil, err
		}
	}

	if e.Kind == OutputConfigMap {
		if err := validateConfigMapResult(result); err != nil {
			return nil, err
		}
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
// nonDeterministicSprigFuncs lists the Sprig template functions disabled to keep
// generation deterministic: those that read the wall clock (now/ago, and the date
// formatters that fall back to now when given an empty argument; durationRound
// reads the clock when given a time), use randomness (rand*, uuidv4, shuffle), or
// generate keys/certs/hashes with fresh entropy (gen*, bcrypt, htpasswd). Random
// material comes from inputs.generated; the frozen build time is
// .context.generatedAt (a time.Time, formattable via its .Format/.Unix methods).
// Deterministic date helpers that operate on a supplied value (toDate, dateModify,
// duration, unixEpoch) and derivePassword/buildCustomCert remain available.
var nonDeterministicSprigFuncs = []string{
	"now", "ago", "date", "dateInZone", "htmlDate", "htmlDateInZone", "durationRound",
	"randAlphaNum", "randAlpha", "randAscii", "randNumeric", "randBytes", "randInt",
	"uuidv4", "shuffle",
	"genPrivateKey", "genCA", "genCAWithKey",
	"genSelfSignedCert", "genSelfSignedCertWithKey",
	"genSignedCert", "genSignedCertWithKey",
	"bcrypt", "htpasswd",
}

// disabledTemplateFunc returns a stub that errors when called, used to neutralise a
// non-deterministic Sprig function while keeping a clear message.
func disabledTemplateFunc(name string) func(...any) (any, error) {
	return func(...any) (any, error) {
		return nil, fmt.Errorf("template function %q is disabled to keep generation deterministic; "+
			"use inputs.generated for random material and .context.generatedAt for time", name)
	}
}

func templateFuncMap(in *ResolvedInputs) template.FuncMap {
	funcs := sprig.TxtFuncMap()

	// Enforce determinism: neutralise Sprig's clock/randomness/entropy functions so
	// a template cannot make the output churn between reconciles.
	for _, name := range nonDeterministicSprigFuncs {
		funcs[name] = disabledTemplateFunc(name)
	}

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

	// Sprig provides toJson/fromJson but not YAML; add them over sigs.k8s.io/yaml
	// (YAML<->JSON) so decoded maps carry string keys usable with template field
	// access. toYaml trims the trailing newline (the Helm convention).
	funcs["toYaml"] = func(v any) (string, error) {
		out, err := yaml.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("toYaml: %w", err)
		}
		return strings.TrimSuffix(string(out), "\n"), nil
	}
	funcs["fromYaml"] = func(s string) (any, error) {
		var v any
		if err := yaml.Unmarshal([]byte(s), &v); err != nil {
			return nil, fmt.Errorf("fromYaml: %w", err)
		}
		return v, nil
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
	funcs["kubeconfig_build"] = func(params map[string]any) (string, error) {
		return KubeconfigBuild(KubeconfigParams{
			Server:      asString(params["server"]),
			CACert:      asString(params["caCert"]),
			Token:       asString(params["token"]),
			ClientCert:  asString(params["clientCert"]),
			ClientKey:   asString(params["clientKey"]),
			ClusterName: asString(params["clusterName"]),
			UserName:    asString(params["userName"]),
			ContextName: asString(params["contextName"]),
			Namespace:   asString(params["namespace"]),
		})
	}
	funcs["kubeconfig_from_service_account"] = func(sa any, opts ...map[string]any) (string, error) {
		m, ok := sa.(map[string]any)
		if !ok {
			return "", fmt.Errorf("kubeconfig_from_service_account: serviceAccount must be a map")
		}
		var server, caCert string
		if cl, ok := m["cluster"].(map[string]any); ok {
			server = asString(cl["server"])
			caCert = asString(cl["caCert"])
		}
		var clusterName, userName, contextName string
		if len(opts) > 0 {
			o := opts[0]
			clusterName = asString(o["clusterName"])
			userName = asString(o["userName"])
			contextName = asString(o["contextName"])
		}
		return KubeconfigFromServiceAccount(asString(m["token"]), server, caCert, clusterName, userName, contextName)
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
