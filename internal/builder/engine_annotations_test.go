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
	"strings"
	"testing"
)

// These tests pin the dynamic annotations part of the output contract for both
// engines and kinds: scripts/templates may set annotations alongside labels,
// keys under the operator-owned secrets.advok8s.io/ prefix are rejected with a
// pointed error, and unknown keys in the script's output dict are an error
// rather than silently dropped.

func TestStarlarkSecretOutputAnnotations(t *testing.T) {
	result, err := render(t, `
secret = {
    "data": {"k": "v"},
    "annotations": {"example.com/expiry": "2030-01-01", "plain": "x"},
}
`)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if result.Annotations["example.com/expiry"] != "2030-01-01" || result.Annotations["plain"] != "x" {
		t.Errorf("annotations = %v", result.Annotations)
	}
}

func TestStarlarkConfigMapOutputAnnotations(t *testing.T) {
	result, err := renderConfigMapScript(t, `
configMap = {
    "data": {"k": "v"},
    "annotations": {"example.com/source": "upstream"},
}
`)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if result.Annotations["example.com/source"] != "upstream" {
		t.Errorf("annotations = %v", result.Annotations)
	}
}

func TestStarlarkAnnotationsValueMustBeString(t *testing.T) {
	_, err := render(t, `
secret = {"data": {"k": "v"}, "annotations": {"n": 1}}
`)
	if err == nil || !strings.Contains(err.Error(), `secret.annotations["n"] must be a string`) {
		t.Fatalf("expected non-string annotation value error, got %v", err)
	}
}

func TestStarlarkAnnotationsRejectReservedPrefix(t *testing.T) {
	_, err := render(t, `
secret = {"data": {"k": "v"}, "annotations": {"secrets.advok8s.io/revision": "tamper"}}
`)
	if err == nil || !strings.Contains(err.Error(), "reserved for the operator") {
		t.Fatalf("expected reserved-prefix error, got %v", err)
	}

	_, err = renderConfigMapScript(t, `
configMap = {"data": {"k": "v"}, "annotations": {"secrets.advok8s.io/x": "y"}}
`)
	if err == nil || !strings.Contains(err.Error(), "reserved for the operator") {
		t.Fatalf("expected reserved-prefix error, got %v", err)
	}
}

func TestStarlarkOutputRejectsUnknownKeys(t *testing.T) {
	// A typo is a pointed error, not silently dropped output.
	_, err := render(t, `
secret = {"data": {"k": "v"}, "lables": {"app": "x"}}
`)
	if err == nil || !strings.Contains(err.Error(), `unknown field "lables"`) {
		t.Fatalf("expected unknown-field error, got %v", err)
	}

	// type is not part of the ConfigMap contract.
	_, err = renderConfigMapScript(t, `
configMap = {"data": {"k": "v"}, "type": "Opaque"}
`)
	if err == nil || !strings.Contains(err.Error(), `unknown field "type"`) {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestTemplateAnnotationsRendered(t *testing.T) {
	engine := &TemplateEngine{
		Data:        map[string]string{"k": "v"},
		Annotations: map[string]string{"example.com/team": `{{ .context.labels.team }}`, "static": "x"},
	}
	result, err := engine.Render(sampleInputs())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if result.Annotations["example.com/team"] != teamName || result.Annotations["static"] != "x" {
		t.Errorf("annotations = %v", result.Annotations)
	}
}

func TestTemplateConfigMapKindAnnotationsRendered(t *testing.T) {
	engine := &TemplateEngine{
		Data:        map[string]string{"k": "v"},
		Annotations: map[string]string{"example.com/ns": `{{ .context.namespace }}`},
		Kind:        OutputConfigMap,
	}
	result, err := engine.Render(emptyInputs())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if result.Annotations["example.com/ns"] != "app" {
		t.Errorf("annotations = %v", result.Annotations)
	}
}

func TestTemplateAnnotationsRejectReservedPrefix(t *testing.T) {
	engine := &TemplateEngine{
		Data:        map[string]string{"k": "v"},
		Annotations: map[string]string{"secrets.advok8s.io/revision": "tamper"},
	}
	if _, err := engine.Render(sampleInputs()); err == nil || !strings.Contains(err.Error(), "reserved for the operator") {
		t.Fatalf("expected reserved-prefix error, got %v", err)
	}
}
