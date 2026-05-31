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
	"testing"
	"time"
)

// sampleInputs builds a resolved bundle covering constants, context, a single
// secret and a generated value, for the engine tests.
func sampleInputs() *ResolvedInputs {
	return &ResolvedInputs{
		Constants: map[string]any{"greeting": "hello", "replicas": float64(3)},
		Context: Context{
			Namespace:   "app",
			Name:        "my-secret",
			Labels:      map[string]string{"team": "platform"},
			GeneratedAt: fixedTime,
		},
		Secrets: map[string]*SecretBinding{
			"db": {Single: &ResolvedSecret{Name: "db-credentials", Type: "Opaque", Data: map[string]string{"password": "s3cret"}}},
		},
		ConfigMaps: map[string]*ConfigMapBinding{},
		Libraries:  map[string]string{},
		Generated:  map[string]any{"pw": map[string]any{"value": "generated-pw"}},
	}
}

func render(t *testing.T, script string) (*Result, error) {
	t.Helper()
	return NewStarlarkEngine(script).Render(sampleInputs())
}

func TestStarlarkSuccessAndInputBinding(t *testing.T) {
	script := `
secret = {
  "data": {
    "ns": input.context.namespace,
    "greeting": input.constants.greeting,
    "password": input.secrets.db.data["password"],
    "generated": input.generated.pw.value,
  },
  "labels": {"app": "dashboard"},
  "type": "Opaque",
}
`
	result, err := render(t, script)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := map[string]string{"ns": "app", "greeting": "hello", "password": "s3cret", "generated": "generated-pw"}
	for k, v := range want {
		if string(result.Data[k]) != v {
			t.Errorf("data[%q] = %q, want %q", k, result.Data[k], v)
		}
	}
	if result.Labels["app"] != "dashboard" {
		t.Errorf("labels = %v", result.Labels)
	}
	if result.Type != "Opaque" {
		t.Errorf("type = %q", result.Type)
	}
}

func TestStarlarkFail(t *testing.T) {
	_, err := render(t, `fail("configuration is broken")`)
	var fe *FailError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *FailError, got %v", err)
	}
	if fe.Message != "configuration is broken" {
		t.Errorf("message = %q", fe.Message)
	}
}

func TestStarlarkRetry(t *testing.T) {
	_, err := render(t, `retry("not ready", after="30s")`)
	var re *RetryError
	if !errors.As(err, &re) {
		t.Fatalf("expected *RetryError, got %v", err)
	}
	if re.After != 30*time.Second {
		t.Errorf("after = %v, want 30s", re.After)
	}
}

func TestStarlarkNoSecretGlobal(t *testing.T) {
	_, err := render(t, `x = 1`)
	if err == nil {
		t.Fatalf("expected error when 'secret' is not set")
	}
	var fe *FailError
	var re *RetryError
	if errors.As(err, &fe) || errors.As(err, &re) {
		t.Errorf("missing-secret should be an ordinary error, not fail/retry")
	}
}

func TestStarlarkDeterminism(t *testing.T) {
	script := `secret = {"data": {"out": input.constants.greeting + "-" + input.generated.pw.value}}`
	a, err := render(t, script)
	if err != nil {
		t.Fatalf("Render a: %v", err)
	}
	b, err := render(t, script)
	if err != nil {
		t.Fatalf("Render b: %v", err)
	}
	if string(a.Data["out"]) != string(b.Data["out"]) || string(a.Data["out"]) != "hello-generated-pw" {
		t.Errorf("non-deterministic or wrong output: %q vs %q", a.Data["out"], b.Data["out"])
	}
}

func TestStarlarkStepLimit(t *testing.T) {
	engine := &StarlarkEngine{
		Script:   `data = [i for i in range(100000000)]` + "\n" + `secret = {"data": {}}`,
		MaxSteps: 10000,
	}
	_, err := engine.Render(sampleInputs())
	if err == nil {
		t.Fatalf("expected step-limit error")
	}
	var fe *FailError
	var re *RetryError
	if errors.As(err, &fe) || errors.As(err, &re) {
		t.Errorf("step-limit should be an ordinary error, not fail/retry")
	}
}

func TestStarlarkOutputCap(t *testing.T) {
	engine := &StarlarkEngine{
		Script:         `secret = {"data": {"big": "x" * 1000}}`,
		MaxOutputBytes: 100,
	}
	if _, err := engine.Render(sampleInputs()); err == nil {
		t.Fatalf("expected output-cap error")
	}
}

func TestStarlarkLibraryLoad(t *testing.T) {
	in := sampleInputs()
	in.Libraries["util"] = "def shout(s):\n    return s + \"!\"\n"
	script := `
load("util", "shout")
secret = {"data": {"out": shout("hi")}}
`
	result, err := NewStarlarkEngine(script).Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(result.Data["out"]) != "hi!" {
		t.Errorf("library result = %q", result.Data["out"])
	}
}

func TestStarlarkRecipeWiring(t *testing.T) {
	script := `secret = {"data": {"auth": basicauth.credentials("user", "pass")}}`
	result, err := render(t, script)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(result.Data["auth"]) != "dXNlcjpwYXNz" {
		t.Errorf("basicauth.credentials = %q", result.Data["auth"])
	}
}
