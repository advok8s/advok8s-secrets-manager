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
	"strings"
	"time"
	"unicode/utf8"
)

// OutputKind selects which output object a generator engine produces, and with
// it the output contract: a Secret (the script's `secret` global / a per-key
// template map with an optional type) or a ConfigMap (the script's `configMap`
// global with separate data and binaryData dicts, no type).
type OutputKind int

const (
	// OutputSecret is the SecretBuilder contract (the default).
	OutputSecret OutputKind = iota
	// OutputConfigMap is the ConfigMapBuilder contract.
	OutputConfigMap
)

// name returns the kind for use in error messages.
func (k OutputKind) name() string {
	if k == OutputConfigMap {
		return "ConfigMap"
	}
	return "Secret"
}

// classifyEngineError surfaces a script/template fail() or retry() as the
// corresponding sentinel (both engines wrap them in their own evaluation error,
// which Unwraps); any other error is returned unchanged for the controller to map
// to GeneratorError.
func classifyEngineError(err error) error {
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

// Result is what a generator engine produces: the output's data (decoded - the
// engine works in raw values, serialization base64-encodes on the wire), plus
// any labels and annotations and, per output kind, the Secret type (Secret
// only) or binaryData (ConfigMap only - raw bytes, never base64-encoded by the
// author).
type Result struct {
	Data        map[string][]byte
	BinaryData  map[string][]byte
	Labels      map[string]string
	Annotations map[string]string
	Type        string
}

// The operator-owned annotation prefixes (secret/configMap) and the keys under
// them live in annotations.go; OutputKind.reservedPrefix() returns the prefix
// reserved for a given output kind.

// validateAnnotations rejects generator-produced annotation keys in the
// operator-owned namespace. Shared by both engines so the error is identical
// whichever generator produced the output; kind is the output dict/field name
// for the message ("secret" or "configMap") and prefix is the reserved
// namespace for the output kind.
func validateAnnotations(annotations map[string]string, kind, prefix string) error {
	for _, key := range sortedKeys(annotations) {
		if strings.HasPrefix(key, prefix) {
			return fmt.Errorf("%s.annotations[%q]: the %q annotation prefix is reserved for the operator", kind, key, prefix)
		}
	}
	return nil
}

// validateConfigMapResult enforces the parts of the ConfigMap output contract
// that the Kubernetes API makes real: values landing in data must be valid
// UTF-8 (binary content belongs in binaryData - relying on the API server is
// unsafe, as invalid UTF-8 in a string can be silently corrupted during JSON
// serialization), and a key must not appear in both data and binaryData (the
// API server rejects the duplicate). Shared by both engines so the errors are
// identical whichever generator produced the output.
func validateConfigMapResult(result *Result) error {
	for _, key := range sortedKeysBytes(result.Data) {
		if !utf8.Valid(result.Data[key]) {
			return fmt.Errorf("configMap data[%q] is not valid UTF-8; binary content belongs in binaryData", key)
		}
	}
	for _, key := range sortedKeysBytes(result.BinaryData) {
		if _, duplicate := result.Data[key]; duplicate {
			return fmt.Errorf("key %q appears in both configMap data and binaryData", key)
		}
	}
	return nil
}

// RetryError signals a script retry(): inputs exist but are not yet ready, so the
// controller should hold generation in AwaitingInput and requeue, optionally after
// the given delay. It is benign, not a failure.
type RetryError struct {
	Message string
	After   time.Duration
}

func (e *RetryError) Error() string {
	if e.After > 0 {
		return fmt.Sprintf("retry after %s: %s", e.After, e.Message)
	}
	return "retry: " + e.Message
}

// FailError signals a script fail(): the generator declared the configuration
// broken. The controller maps it to GeneratorError / Degraded.
type FailError struct {
	Message string
}

func (e *FailError) Error() string { return "fail: " + e.Message }

// Engine renders a generator (a Starlark script or a gotemplate template) against
// resolved inputs into a Result. A *RetryError or *FailError carries the script's
// retry()/fail() outcome; any other error is an ordinary generation failure
// (mapped to GeneratorError by the controller).
type Engine interface {
	Render(inputs *ResolvedInputs) (*Result, error)
}
