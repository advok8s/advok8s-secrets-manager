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
	"errors"
	"fmt"
	"time"

	starlarkjson "go.starlark.net/lib/json"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

// starlarkFileOptions selects standard Starlark syntax (no nonstandard dialect
// features) for both the script and any loaded libraries.
var starlarkFileOptions = &syntax.FileOptions{}

// defaultMaxOutputBytes caps the total size of the produced Secret data, bounding
// a runaway generator. defaultMaxSteps bounds execution.
const (
	defaultMaxOutputBytes = 1 << 20 // 1 MiB
	defaultMaxSteps       = 100_000_000
)

// StarlarkEngine renders a Starlark script. The script reads the predeclared
// `input` and recipe modules, may load() declared libraries, and must set a
// `secret = {"data": {...}, "labels": {...}, "type": "..."}` global. It is
// sandboxed: no I/O, no clock (generatedAt is the only time source), a step cap
// and an output-size cap.
type StarlarkEngine struct {
	Script string
	// MaxSteps overrides the execution-step cap (0 = default).
	MaxSteps uint64
	// MaxOutputBytes overrides the output-size cap (0 = default).
	MaxOutputBytes int
}

// NewStarlarkEngine returns an engine for the given script source.
func NewStarlarkEngine(script string) *StarlarkEngine { return &StarlarkEngine{Script: script} }

// Render executes the script against the resolved inputs.
func (e *StarlarkEngine) Render(in *ResolvedInputs) (*Result, error) {
	inputValue, err := buildInputValue(in)
	if err != nil {
		return nil, err
	}

	predeclared := starlark.StringDict{
		"input":        inputValue,
		"fail":         starlark.NewBuiltin("fail", builtinFail),
		"retry":        starlark.NewBuiltin("retry", builtinRetry),
		"json":         starlarkjson.Module,
		"base64":       base64Module(),
		"tls":          tlsModule(),
		"basicauth":    basicAuthModule(),
		"dockerconfig": dockerConfigModule(),
		"htpasswd":     htpasswdModule(),
		"kubeconfig":   kubeconfigModule(),
		"jwt":          jwtModule(in.Context.GeneratedAt),
	}

	maxSteps := e.MaxSteps
	if maxSteps == 0 {
		maxSteps = defaultMaxSteps
	}

	loaded := map[string]starlark.StringDict{}
	var thread *starlark.Thread
	thread = &starlark.Thread{
		Name: "secretbuilder",
		Load: func(_ *starlark.Thread, module string) (starlark.StringDict, error) {
			if g, ok := loaded[module]; ok {
				return g, nil
			}
			src, ok := in.Libraries[module]
			if !ok {
				return nil, fmt.Errorf("load(%q): no such library", module)
			}
			g, err := starlark.ExecFileOptions(starlarkFileOptions, thread, module, src, libraryPredeclared(predeclared))
			if err != nil {
				return nil, err
			}
			loaded[module] = g
			return g, nil
		},
	}
	thread.SetMaxExecutionSteps(maxSteps)

	globals, err := starlark.ExecFileOptions(starlarkFileOptions, thread, "secretbuilder.star", e.Script, predeclared)
	if err != nil {
		return nil, classifyStarlarkError(err)
	}

	secretVal, ok := globals["secret"]
	if !ok || secretVal == starlark.None {
		return nil, fmt.Errorf("script did not set the 'secret' global")
	}

	maxOut := e.MaxOutputBytes
	if maxOut == 0 {
		maxOut = defaultMaxOutputBytes
	}
	return parseSecretOutput(secretVal, maxOut)
}

// classifyStarlarkError unwraps a Starlark evaluation error to surface a script
// fail()/retry() as the corresponding sentinel; anything else is returned as-is.
func classifyStarlarkError(err error) error {
	var fe *FailError
	if errors.As(err, &fe) {
		return fe
	}
	var re *RetryError
	if errors.As(err, &re) {
		return re
	}
	return err
}

func builtinFail(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var msg string
	if err := starlark.UnpackArgs("fail", args, kwargs, "message", &msg); err != nil {
		return nil, err
	}
	return nil, &FailError{Message: msg}
}

func builtinRetry(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var msg, after string
	if err := starlark.UnpackArgs("retry", args, kwargs, "message", &msg, "after?", &after); err != nil {
		return nil, err
	}
	var dur time.Duration
	if after != "" {
		d, err := time.ParseDuration(after)
		if err != nil {
			return nil, fmt.Errorf("retry: invalid after %q: %w", after, err)
		}
		dur = d
	}
	return nil, &RetryError{Message: msg, After: dur}
}

func parseSecretOutput(value starlark.Value, maxBytes int) (*Result, error) {
	out, err := fromStarlark(value)
	if err != nil {
		return nil, fmt.Errorf("reading 'secret': %w", err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'secret' must be a dict, got %T", out)
	}

	result := &Result{Data: map[string][]byte{}, Labels: map[string]string{}}

	dataRaw, ok := m["data"]
	if !ok {
		return nil, fmt.Errorf("'secret' must have a 'data' field")
	}
	dataMap, ok := dataRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'secret.data' must be a dict")
	}
	total := 0
	for _, k := range sortedKeys(dataMap) {
		b, err := toBytes(dataMap[k])
		if err != nil {
			return nil, fmt.Errorf("secret.data[%q]: %w", k, err)
		}
		total += len(b)
		if total > maxBytes {
			return nil, fmt.Errorf("generated Secret data exceeds %d bytes", maxBytes)
		}
		result.Data[k] = b
	}

	if labelsRaw, ok := m["labels"]; ok && labelsRaw != nil {
		labelsMap, ok := labelsRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("'secret.labels' must be a dict")
		}
		for k, v := range labelsMap {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("secret.labels[%q] must be a string", k)
			}
			result.Labels[k] = s
		}
	}

	if typeRaw, ok := m["type"]; ok && typeRaw != nil {
		s, ok := typeRaw.(string)
		if !ok {
			return nil, fmt.Errorf("'secret.type' must be a string")
		}
		result.Type = s
	}

	return result, nil
}

func toBytes(v any) ([]byte, error) {
	switch t := v.(type) {
	case string:
		return []byte(t), nil
	case []byte:
		return t, nil
	default:
		return nil, fmt.Errorf("must be a string or bytes, got %T", v)
	}
}

// ---- input binding ------------------------------------------------------

func buildInputValue(in *ResolvedInputs) (*starlarkstruct.Struct, error) {
	constants, err := structFromMap(in.Constants)
	if err != nil {
		return nil, fmt.Errorf("binding constants: %w", err)
	}

	context := starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
		"namespace":       starlark.String(in.Context.Namespace),
		"name":            starlark.String(in.Context.Name),
		"labels":          dictFromStringMap(in.Context.Labels),
		"annotations":     dictFromStringMap(in.Context.Annotations),
		"uid":             starlark.String(in.Context.UID),
		"generatedAt":     starlark.String(in.Context.GeneratedAt.UTC().Format(time.RFC3339)),
		"generatedAtUnix": starlark.MakeInt64(in.Context.GeneratedAt.Unix()),
	})

	secrets := starlark.StringDict{}
	for handle, binding := range in.Secrets {
		if binding.IsList {
			items := make([]starlark.Value, 0, len(binding.List))
			for _, s := range binding.List {
				items = append(items, secretToStarlark(s))
			}
			secrets[handle] = starlark.NewList(items)
		} else if binding.Single != nil {
			secrets[handle] = secretToStarlark(binding.Single)
		}
	}

	configMaps := starlark.StringDict{}
	for handle, binding := range in.ConfigMaps {
		if binding.IsList {
			items := make([]starlark.Value, 0, len(binding.List))
			for _, c := range binding.List {
				items = append(items, configMapToStarlark(c))
			}
			configMaps[handle] = starlark.NewList(items)
		} else if binding.Single != nil {
			configMaps[handle] = configMapToStarlark(binding.Single)
		}
	}

	generated := starlark.StringDict{}
	for handle, attrs := range in.Generated {
		attrMap, ok := attrs.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("generated %q has unexpected shape %T", handle, attrs)
		}
		s, err := structFromMap(attrMap)
		if err != nil {
			return nil, fmt.Errorf("binding generated %q: %w", handle, err)
		}
		generated[handle] = s
	}

	fields := starlark.StringDict{
		"constants":  constants,
		"context":    context,
		"secrets":    starlarkstruct.FromStringDict(starlarkstruct.Default, secrets),
		"configMaps": starlarkstruct.FromStringDict(starlarkstruct.Default, configMaps),
		"generated":  starlarkstruct.FromStringDict(starlarkstruct.Default, generated),
	}

	if in.ServiceAccount != nil {
		sa := in.ServiceAccount
		fields["serviceAccount"] = starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
			"name":      starlark.String(sa.Name),
			"namespace": starlark.String(sa.Namespace),
			"token":     starlark.String(sa.Token),
			"cluster": starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
				"server": starlark.String(sa.ClusterServer),
				"caCert": starlark.String(sa.ClusterCACert),
			}),
		})
	} else {
		fields["serviceAccount"] = starlark.None
	}

	return starlarkstruct.FromStringDict(starlarkstruct.Default, fields), nil
}

func secretToStarlark(s *ResolvedSecret) *starlarkstruct.Struct {
	return starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
		"name":        starlark.String(s.Name),
		"type":        starlark.String(s.Type),
		"uid":         starlark.String(s.UID),
		"labels":      dictFromStringMap(s.Labels),
		"annotations": dictFromStringMap(s.Annotations),
		"data":        dictFromStringMap(s.Data),
	})
}

func configMapToStarlark(c *ResolvedConfigMap) *starlarkstruct.Struct {
	return starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
		"name":        starlark.String(c.Name),
		"uid":         starlark.String(c.UID),
		"labels":      dictFromStringMap(c.Labels),
		"annotations": dictFromStringMap(c.Annotations),
		"data":        dictFromStringMap(c.Data),
		"binaryData":  dictFromBytesMap(c.BinaryData),
	})
}

func structFromMap(m map[string]any) (*starlarkstruct.Struct, error) {
	dict := starlark.StringDict{}
	for k, v := range m {
		sv, err := toStarlark(v)
		if err != nil {
			return nil, err
		}
		dict[k] = sv
	}
	return starlarkstruct.FromStringDict(starlarkstruct.Default, dict), nil
}

func dictFromStringMap(m map[string]string) *starlark.Dict {
	d := starlark.NewDict(len(m))
	for _, k := range sortedKeys(m) {
		_ = d.SetKey(starlark.String(k), starlark.String(m[k]))
	}
	return d
}

func dictFromBytesMap(m map[string][]byte) *starlark.Dict {
	d := starlark.NewDict(len(m))
	for _, k := range sortedKeysBytes(m) {
		_ = d.SetKey(starlark.String(k), starlark.Bytes(m[k]))
	}
	return d
}

// ---- value conversion ---------------------------------------------------

func toStarlark(v any) (starlark.Value, error) {
	switch t := v.(type) {
	case nil:
		return starlark.None, nil
	case string:
		return starlark.String(t), nil
	case bool:
		return starlark.Bool(t), nil
	case int:
		return starlark.MakeInt(t), nil
	case int64:
		return starlark.MakeInt64(t), nil
	case float64:
		return starlark.Float(t), nil
	case []byte:
		return starlark.Bytes(t), nil
	case []any:
		items := make([]starlark.Value, 0, len(t))
		for _, e := range t {
			sv, err := toStarlark(e)
			if err != nil {
				return nil, err
			}
			items = append(items, sv)
		}
		return starlark.NewList(items), nil
	case map[string]any:
		d := starlark.NewDict(len(t))
		for _, k := range sortedKeys(t) {
			sv, err := toStarlark(t[k])
			if err != nil {
				return nil, err
			}
			_ = d.SetKey(starlark.String(k), sv)
		}
		return d, nil
	case map[string]string:
		return dictFromStringMap(t), nil
	default:
		return nil, fmt.Errorf("unsupported value type %T", v)
	}
}

func fromStarlark(v starlark.Value) (any, error) {
	switch t := v.(type) {
	case starlark.NoneType:
		return nil, nil
	case starlark.String:
		return string(t), nil
	case starlark.Bool:
		return bool(t), nil
	case starlark.Int:
		i, _ := t.Int64()
		return i, nil
	case starlark.Float:
		return float64(t), nil
	case starlark.Bytes:
		return []byte(t), nil
	case *starlark.List:
		return iterableToSlice(t)
	case starlark.Tuple:
		return iterableToSlice(t)
	case *starlark.Dict:
		out := map[string]any{}
		for _, item := range t.Items() {
			key, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("dict key must be a string, got %s", item[0].Type())
			}
			val, err := fromStarlark(item[1])
			if err != nil {
				return nil, err
			}
			out[key] = val
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported Starlark type %s", v.Type())
	}
}

func iterableToSlice(it starlark.Iterable) ([]any, error) {
	var out []any
	iter := it.Iterate()
	defer iter.Done()
	var x starlark.Value
	for iter.Next(&x) {
		val, err := fromStarlark(x)
		if err != nil {
			return nil, err
		}
		out = append(out, val)
	}
	return out, nil
}

// libraryPredeclared gives loaded libraries the recipe/primitive surface but not
// the per-build `input`/fail/retry (libraries are reusable function definitions).
func libraryPredeclared(base starlark.StringDict) starlark.StringDict {
	out := starlark.StringDict{}
	for k, v := range base {
		switch k {
		case "input", "fail", "retry":
			continue
		default:
			out[k] = v
		}
	}
	return out
}
