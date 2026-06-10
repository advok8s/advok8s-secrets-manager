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
	"time"
)

// These tests pin the ConfigMap output contract for both engines: placement
// decides the destination map, both dicts accept str or bytes raw (the author
// never base64-encodes), data values must be valid UTF-8, and a key must not
// appear in both dicts.

const helloText = "hello"

func emptyInputs() *ResolvedInputs {
	return &ResolvedInputs{
		Constants:  map[string]any{},
		Context:    Context{Namespace: "app", Name: "cm", GeneratedAt: time.Unix(1700000000, 0).UTC()},
		Secrets:    map[string]*SecretBinding{},
		ConfigMaps: map[string]*ConfigMapBinding{},
		Libraries:  map[string]string{},
		Generated:  map[string]any{},
	}
}

func renderConfigMapScript(t *testing.T, script string) (*Result, error) {
	t.Helper()
	engine := &StarlarkEngine{Script: script, Kind: OutputConfigMap}
	return engine.Render(emptyInputs())
}

func TestStarlarkConfigMapOutputRoutesByDict(t *testing.T) {
	result, err := renderConfigMapScript(t, `
configMap = {
    "data": {
        "text": "hello",
        "decoded": base64.decode("aGVsbG8="),  # bytes, but valid UTF-8
    },
    "binaryData": {
        "blob": hex.decode("ff0001"),
        "pem": "-----BEGIN X-----",  # a str into binaryData is fine
    },
    "labels": {"app": "demo"},
}
`)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(result.Data["text"]) != helloText || string(result.Data["decoded"]) != helloText {
		t.Errorf("data = %v", result.Data)
	}
	if string(result.BinaryData["blob"]) != string([]byte{0xff, 0x00, 0x01}) {
		t.Errorf("binaryData blob = %v", result.BinaryData["blob"])
	}
	if string(result.BinaryData["pem"]) != "-----BEGIN X-----" {
		t.Errorf("binaryData pem = %q", result.BinaryData["pem"])
	}
	if result.Labels["app"] != "demo" {
		t.Errorf("labels = %v", result.Labels)
	}
	if result.Type != "" {
		t.Errorf("unexpected type %q", result.Type)
	}
}

func TestStarlarkConfigMapOutputRejectsNonUTF8Data(t *testing.T) {
	_, err := renderConfigMapScript(t, `
configMap = {"data": {"blob": hex.decode("ff0001")}}
`)
	if err == nil {
		t.Fatal("expected error for non-UTF-8 data value")
	}
	if !strings.Contains(err.Error(), "not valid UTF-8") || !strings.Contains(err.Error(), "binaryData") {
		t.Errorf("error should name the problem and suggest binaryData: %v", err)
	}
}

func TestStarlarkConfigMapOutputRejectsDuplicateKey(t *testing.T) {
	_, err := renderConfigMapScript(t, `
configMap = {"data": {"k": "v"}, "binaryData": {"k": b"v"}}
`)
	if err == nil {
		t.Fatal("expected error for key in both data and binaryData")
	}
	if !strings.Contains(err.Error(), "both") {
		t.Errorf("error = %v", err)
	}
}

func TestStarlarkConfigMapOutputRequiresConfigMapGlobal(t *testing.T) {
	_, err := renderConfigMapScript(t, `x = 1`)
	if err == nil || !strings.Contains(err.Error(), "'configMap' global") {
		t.Fatalf("expected missing-global error, got %v", err)
	}

	// A script written for SecretBuilder gets a pointed error.
	_, err = renderConfigMapScript(t, `secret = {"data": {"k": "v"}}`)
	if err == nil || !strings.Contains(err.Error(), "set the 'configMap' global instead") {
		t.Fatalf("expected pointed secret-global error, got %v", err)
	}
}

func TestStarlarkConfigMapOutputRequiresSomeData(t *testing.T) {
	_, err := renderConfigMapScript(t, `configMap = {"labels": {"a": "1"}}`)
	if err == nil || !strings.Contains(err.Error(), "'data' or 'binaryData'") {
		t.Fatalf("expected missing data/binaryData error, got %v", err)
	}
}

func TestStarlarkConfigMapOutputSizeCapCountsBothMaps(t *testing.T) {
	engine := &StarlarkEngine{
		Script: `
configMap = {
    "data": {"a": "x" * 600},
    "binaryData": {"b": b"y" * 600},
}
`,
		Kind:           OutputConfigMap,
		MaxOutputBytes: 1000,
	}
	_, err := engine.Render(emptyInputs())
	if err == nil || !strings.Contains(err.Error(), "ConfigMap data exceeds") {
		t.Fatalf("expected size cap error counting both maps, got %v", err)
	}
}

func TestStarlarkSecretKindStillUsesSecretGlobal(t *testing.T) {
	engine := &StarlarkEngine{Script: `secret = {"data": {"k": "v"}}`}
	result, err := engine.Render(emptyInputs())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(result.Data["k"]) != "v" {
		t.Errorf("data = %v", result.Data)
	}
}

func TestTemplateConfigMapKindValidatesUTF8(t *testing.T) {
	// A binary secret value spliced through a template is the realistic way a
	// rendered data value ends up non-UTF-8.
	in := emptyInputs()
	in.Secrets["creds"] = &SecretBinding{Single: &ResolvedSecret{
		Name: "creds",
		Data: map[string]string{"blob": string([]byte{0xff, 0x00, 0x01})},
	}}

	engine := &TemplateEngine{
		Data: map[string]string{"out": `{{ .secrets.creds.data.blob }}`},
		Kind: OutputConfigMap,
	}
	_, err := engine.Render(in)
	if err == nil {
		t.Fatal("expected error for non-UTF-8 rendered data value")
	}
	if !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Errorf("error = %v", err)
	}
}

func TestTemplateConfigMapKindIgnoresType(t *testing.T) {
	engine := &TemplateEngine{
		Data: map[string]string{"out": helloText},
		Type: "should-be-ignored",
		Kind: OutputConfigMap,
	}
	result, err := engine.Render(emptyInputs())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if result.Type != "" {
		t.Errorf("type should be empty for ConfigMap kind, got %q", result.Type)
	}
	if string(result.Data["out"]) != helloText {
		t.Errorf("data = %v", result.Data)
	}
}

func TestConfigMapRevisionOfDomainSeparation(t *testing.T) {
	asData := ConfigMapRevisionOf(map[string]string{"k": "v"}, nil)
	asBinary := ConfigMapRevisionOf(nil, map[string][]byte{"k": []byte("v")})
	if asData == asBinary {
		t.Error("revision must change when a key moves between data and binaryData")
	}
	if ConfigMapRevisionOf(map[string]string{"k": "v"}, nil) != asData {
		t.Error("revision must be stable for identical input")
	}
}
