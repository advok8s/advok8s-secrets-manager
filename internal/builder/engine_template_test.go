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
	"strings"
	"testing"
	"time"
)

func renderTemplate(t *testing.T, data map[string]string) (*Result, error) {
	t.Helper()
	return NewTemplateEngine(data).Render(sampleInputs())
}

func TestTemplateSuccessAndContext(t *testing.T) {
	result, err := renderTemplate(t, map[string]string{
		"ns":        `{{ .context.namespace }}`,
		"greeting":  `{{ .constants.greeting }}`,
		"password":  `{{ .secrets.db.data.password }}`,
		"generated": `{{ .generated.pw.value }}`,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := map[string]string{"ns": "app", "greeting": "hello", "password": "s3cret", "generated": "generated-pw"}
	for k, v := range want {
		if string(result.Data[k]) != v {
			t.Errorf("data[%q] = %q, want %q", k, result.Data[k], v)
		}
	}
}

func TestTemplateFail(t *testing.T) {
	_, err := renderTemplate(t, map[string]string{"x": `{{ fail "broken" }}`})
	var fe *FailError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *FailError, got %v", err)
	}
	if fe.Message != "broken" {
		t.Errorf("message = %q", fe.Message)
	}
}

func TestTemplateRetry(t *testing.T) {
	_, err := renderTemplate(t, map[string]string{"x": `{{ retry "wait" }}`})
	var re *RetryError
	if !errors.As(err, &re) {
		t.Fatalf("expected *RetryError, got %v", err)
	}

	_, err = renderTemplate(t, map[string]string{"x": `{{ retryAfter "30s" "wait" }}`})
	if !errors.As(err, &re) || re.After != 30*time.Second {
		t.Fatalf("expected RetryError with 30s, got %v", err)
	}
}

func TestTemplateRequired(t *testing.T) {
	in := sampleInputs()
	in.Constants["blank"] = ""

	// Empty value -> required errors.
	_, err := NewTemplateEngine(map[string]string{"x": `{{ required "need blank" .constants.blank }}`}).Render(in)
	if err == nil {
		t.Fatalf("expected required error for empty value")
	}
	var fe *FailError
	var re *RetryError
	if errors.As(err, &fe) || errors.As(err, &re) {
		t.Errorf("required should be an ordinary error, not fail/retry")
	}

	// Present non-empty value -> passes through.
	result, err := NewTemplateEngine(map[string]string{"x": `{{ required "need greeting" .constants.greeting }}`}).Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(result.Data["x"]) != "hello" {
		t.Errorf("required passthrough = %q", result.Data["x"])
	}
}

func TestTemplateMissingKeyIsError(t *testing.T) {
	_, err := renderTemplate(t, map[string]string{"x": `{{ .constants.nonexistent }}`})
	if err == nil {
		t.Fatalf("expected missingkey error")
	}
	var fe *FailError
	var re *RetryError
	if errors.As(err, &fe) || errors.As(err, &re) {
		t.Errorf("missingkey should be an ordinary error, not fail/retry")
	}
}

func TestTemplateSprigAndRecipe(t *testing.T) {
	result, err := renderTemplate(t, map[string]string{
		"b64":  `{{ "hello" | b64enc }}`,
		"auth": `{{ basicauth_credentials "user" "pass" }}`,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(result.Data["b64"]) != "aGVsbG8=" {
		t.Errorf("b64enc = %q", result.Data["b64"])
	}
	if string(result.Data["auth"]) != "dXNlcjpwYXNz" {
		t.Errorf("basicauth_credentials = %q", result.Data["auth"])
	}
}

func TestTemplateDeterminism(t *testing.T) {
	data := map[string]string{"out": `{{ .constants.greeting }}-{{ .generated.pw.value }}`}
	a, err := renderTemplate(t, data)
	if err != nil {
		t.Fatalf("Render a: %v", err)
	}
	b, err := renderTemplate(t, data)
	if err != nil {
		t.Fatalf("Render b: %v", err)
	}
	if string(a.Data["out"]) != string(b.Data["out"]) || string(a.Data["out"]) != "hello-generated-pw" {
		t.Errorf("non-deterministic or wrong: %q vs %q", a.Data["out"], b.Data["out"])
	}
}

func TestTemplateOutputCap(t *testing.T) {
	engine := &TemplateEngine{
		Data:           map[string]string{"big": `{{ repeat 1000 "x" }}`},
		MaxOutputBytes: 100,
	}
	if _, err := engine.Render(sampleInputs()); err == nil {
		t.Fatalf("expected output-cap error")
	}
}

func TestTemplateTypeAndLabels(t *testing.T) {
	engine := &TemplateEngine{
		Data:   map[string]string{"k": "v"},
		Type:   `kubernetes.io/{{ .constants.greeting }}`,
		Labels: map[string]string{"team": `{{ .context.labels.team }}`, "static": "x"},
	}
	result, err := engine.Render(sampleInputs())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if result.Type != "kubernetes.io/hello" {
		t.Errorf("type = %q, want %q", result.Type, "kubernetes.io/hello")
	}
	if result.Labels["team"] != "platform" || result.Labels["static"] != "x" {
		t.Errorf("labels = %v", result.Labels)
	}
}

func TestTemplateKubeconfigFuncs(t *testing.T) {
	in := sampleInputs()
	in.ServiceAccount = &ResolvedServiceAccount{
		Name: "deployer", Namespace: "app", Token: "tok",
		ClusterServer: "https://api:6443", ClusterCACert: "CA",
	}
	result, err := NewTemplateEngine(map[string]string{
		"fromsa": `{{ kubeconfig_from_service_account .serviceAccount (dict "contextName" "ctx-sa") }}`,
		"built":  `{{ kubeconfig_build (dict "server" "https://b:6443" "token" "t2" "contextName" "ctx-build") }}`,
	}).Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(result.Data["fromsa"]), "ctx-sa") {
		t.Errorf("kubeconfig_from_service_account output missing its context:\n%s", result.Data["fromsa"])
	}
	if !strings.Contains(string(result.Data["built"]), "ctx-build") {
		t.Errorf("kubeconfig_build output missing its context:\n%s", result.Data["built"])
	}
}

func TestTemplateYAMLFuncs(t *testing.T) {
	result, err := renderTemplate(t, map[string]string{
		"roundtrip": `{{ "foo: bar" | fromYaml | toYaml }}`,
		"field":     `{{ index (fromYaml "a: 1\nb: two") "b" }}`,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got := string(result.Data["roundtrip"]); got != "foo: bar" {
		t.Errorf("roundtrip = %q, want %q", got, "foo: bar")
	}
	if got := string(result.Data["field"]); got != "two" {
		t.Errorf("field = %q, want %q", got, "two")
	}
}
