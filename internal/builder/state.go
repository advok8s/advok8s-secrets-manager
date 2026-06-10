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
	"encoding/json"
	"fmt"
	"strconv"
)

// CompanionSecretName is the name of the owned Secret that persists a builder's
// generated material and frozen generatedAt, so a refresh (onInputChange) replays
// the same material and a keep-entropy rotation can reuse it. Generated material
// cannot be regenerated identically (Go's crypto injects randomness), so it must
// be persisted rather than recomputed.
func CompanionSecretName(builderName string) string {
	return builderName + "-secretbuilder-state"
}

// CompanionConfigMapBuilderStateName is the companion for a ConfigMapBuilder.
// The companion is always a Secret regardless of the output kind: generated
// material is entropy and must never land in a ConfigMap.
func CompanionConfigMapBuilderStateName(builderName string) string {
	return builderName + "-configmapbuilder-state"
}

// RegenerateAnnotation, when set on a SecretBuilder to a new value, triggers a
// manual rotation (the kubectl rollout-restart idiom). The controller records the
// last-handled value in status so each new value rotates exactly once.
const RegenerateAnnotation = "secrets.advok8s.io/regenerate"

// persistedValue is a type-tagged serialisation of a generated attribute, so a
// round-trip preserves whether a value was a string, raw bytes, or an integer.
type persistedValue struct {
	T string `json:"t"` // "s" string, "b" bytes (base64), "i" int64
	V string `json:"v"`
}

// SerializeGenerated encodes generated material for storage in the companion
// Secret, preserving value types.
func SerializeGenerated(generated map[string]map[string]any) ([]byte, error) {
	out := make(map[string]map[string]persistedValue, len(generated))
	for handle, attrs := range generated {
		m := make(map[string]persistedValue, len(attrs))
		for key, value := range attrs {
			pv, err := encodePersistedValue(value)
			if err != nil {
				return nil, fmt.Errorf("generated %q attr %q: %w", handle, key, err)
			}
			m[key] = pv
		}
		out[handle] = m
	}
	return json.Marshal(out)
}

// DeserializeGenerated decodes material previously stored by SerializeGenerated.
func DeserializeGenerated(data []byte) (map[string]map[string]any, error) {
	var in map[string]map[string]persistedValue
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}
	out := make(map[string]map[string]any, len(in))
	for handle, attrs := range in {
		m := make(map[string]any, len(attrs))
		for key, pv := range attrs {
			value, err := decodePersistedValue(pv)
			if err != nil {
				return nil, fmt.Errorf("generated %q attr %q: %w", handle, key, err)
			}
			m[key] = value
		}
		out[handle] = m
	}
	return out, nil
}

func encodePersistedValue(value any) (persistedValue, error) {
	switch t := value.(type) {
	case string:
		return persistedValue{T: "s", V: t}, nil
	case []byte:
		return persistedValue{T: "b", V: base64.StdEncoding.EncodeToString(t)}, nil
	case int64:
		return persistedValue{T: "i", V: strconv.FormatInt(t, 10)}, nil
	case int:
		return persistedValue{T: "i", V: strconv.FormatInt(int64(t), 10)}, nil
	default:
		return persistedValue{}, fmt.Errorf("unsupported value type %T", value)
	}
}

func decodePersistedValue(pv persistedValue) (any, error) {
	switch pv.T {
	case "s":
		return pv.V, nil
	case "b":
		return base64.StdEncoding.DecodeString(pv.V)
	case "i":
		return strconv.ParseInt(pv.V, 10, 64)
	default:
		return nil, fmt.Errorf("unknown persisted type %q", pv.T)
	}
}
