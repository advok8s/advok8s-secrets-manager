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

package copyengine

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These tests pin the managed-subset semantics of rule-supplied target
// annotations: they are applied and reconciled exactly like target labels
// (re-asserted, removed when previously managed and no longer expected) while
// annotations outside the managed set - the operator's own tracking
// annotations and anything set by third parties - are never compared or
// touched. Source annotations are never copied.

func TestSourceChangedAnnotationDrift(t *testing.T) {
	source := &corev1.Secret{}
	expected := map[string]string{"example.com/team": "a"}

	cases := []struct {
		name              string
		targetAnnotations map[string]string
		extraAnnotations  map[string]string
		expectChanged     bool
	}{
		{
			name:              "expected annotation missing",
			targetAnnotations: map[string]string{},
			extraAnnotations:  expected,
			expectChanged:     true,
		},
		{
			name:              "expected annotation wrong value",
			targetAnnotations: map[string]string{"example.com/team": "b", AnnotationManagedAnnotations: "example.com/team"},
			extraAnnotations:  expected,
			expectChanged:     true,
		},
		{
			name:              "managed-then-dropped annotation still present",
			targetAnnotations: map[string]string{"example.com/team": "a", AnnotationManagedAnnotations: "example.com/team"},
			extraAnnotations:  nil,
			expectChanged:     true,
		},
		{
			name:              "foreign annotations are invisible",
			targetAnnotations: map[string]string{"kyverno.io/injected": "x", AnnotationManagedAnnotations: ""},
			extraAnnotations:  nil,
			expectChanged:     false,
		},
		{
			name:              "in sync",
			targetAnnotations: map[string]string{"example.com/team": "a", "third.party/x": "y", AnnotationManagedAnnotations: "example.com/team"},
			extraAnnotations:  expected,
			expectChanged:     false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: c.targetAnnotations}}
			if got := SourceChanged(source, target, nil, c.extraAnnotations); got != c.expectChanged {
				t.Errorf("SourceChanged() = %v, want %v", got, c.expectChanged)
			}
		})
	}
}

func testAnnotatedSecretRequest(source *corev1.Secret, annotations map[string]string) Request {
	return Request{
		Source:            source,
		SourceNamespace:   source.Namespace,
		SourceName:        source.Name,
		TargetNamespace:   "tenant",
		TargetName:        source.Name,
		TargetAnnotations: annotations,
		ManagedByValue:    "secretcopier/test",
	}
}

func TestCopySecretTargetAnnotationsLifecycle(t *testing.T) {
	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "creds",
			Namespace:   "platform",
			Annotations: map[string]string{"source.only/note": "never-copied"},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"k": []byte("v")},
	}
	c := fake.NewClientBuilder().WithScheme(configMapTestScheme(t)).Build()
	engine := Engine{Client: c}
	ctx := context.Background()

	// Create: rule annotations applied and recorded; source annotations not copied.
	req := testAnnotatedSecretRequest(source, map[string]string{"example.com/team": "a", "example.com/tier": "1"})
	if outcome := engine.CopySecret(ctx, req); outcome != InSync {
		t.Fatalf("initial copy = %v, want InSync", outcome)
	}

	var target corev1.Secret
	key := client.ObjectKey{Namespace: "tenant", Name: "creds"}
	if err := c.Get(ctx, key, &target); err != nil {
		t.Fatalf("target not created: %v", err)
	}
	if target.Annotations["example.com/team"] != "a" || target.Annotations["example.com/tier"] != "1" {
		t.Errorf("rule annotations not applied: %v", target.Annotations)
	}
	if target.Annotations[AnnotationManagedAnnotations] != "example.com/team,example.com/tier" {
		t.Errorf("managed-annotations record = %q", target.Annotations[AnnotationManagedAnnotations])
	}
	if _, copied := target.Annotations["source.only/note"]; copied {
		t.Errorf("source annotation must not be copied: %v", target.Annotations)
	}

	// A third party adds an annotation; steady state must not churn.
	target.Annotations["third.party/x"] = "y"
	if err := c.Update(ctx, &target); err != nil {
		t.Fatalf("simulating third-party annotation: %v", err)
	}
	steadyVersion := target.ResourceVersion
	if outcome := engine.CopySecret(ctx, req); outcome != InSync {
		t.Fatalf("steady-state copy = %v, want InSync", outcome)
	}
	if err := c.Get(ctx, key, &target); err != nil {
		t.Fatalf("target gone: %v", err)
	}
	if target.ResourceVersion != steadyVersion {
		t.Errorf("steady-state copy churned the target (resourceVersion %s -> %s)", steadyVersion, target.ResourceVersion)
	}

	// Tampering with a managed annotation is repaired.
	target.Annotations["example.com/team"] = "tampered"
	if err := c.Update(ctx, &target); err != nil {
		t.Fatalf("simulating tamper: %v", err)
	}
	if outcome := engine.CopySecret(ctx, req); outcome != InSync {
		t.Fatalf("repair copy = %v, want InSync", outcome)
	}
	if err := c.Get(ctx, key, &target); err != nil {
		t.Fatalf("target gone: %v", err)
	}
	if target.Annotations["example.com/team"] != "a" {
		t.Errorf("tampered managed annotation not repaired: %v", target.Annotations)
	}

	// The rule drops one key and changes another: the dropped key is removed,
	// the foreign and tracking annotations survive, the record shrinks.
	req = testAnnotatedSecretRequest(source, map[string]string{"example.com/team": "b"})
	if outcome := engine.CopySecret(ctx, req); outcome != InSync {
		t.Fatalf("re-copy = %v, want InSync", outcome)
	}
	if err := c.Get(ctx, key, &target); err != nil {
		t.Fatalf("target gone: %v", err)
	}
	if target.Annotations["example.com/team"] != "b" {
		t.Errorf("managed annotation not updated: %v", target.Annotations)
	}
	if _, present := target.Annotations["example.com/tier"]; present {
		t.Errorf("managed-then-dropped annotation remains: %v", target.Annotations)
	}
	if target.Annotations["third.party/x"] != "y" {
		t.Errorf("foreign annotation clobbered: %v", target.Annotations)
	}
	if target.Annotations[AnnotationManagedBy] != "secretcopier/test" || target.Annotations[AnnotationSourceResource] != "platform/creds" {
		t.Errorf("tracking annotations damaged: %v", target.Annotations)
	}
	if target.Annotations[AnnotationManagedAnnotations] != "example.com/team" {
		t.Errorf("managed-annotations record = %q", target.Annotations[AnnotationManagedAnnotations])
	}
}

func TestCopyConfigMapTargetAnnotations(t *testing.T) {
	source := testSourceConfigMap()
	c := fake.NewClientBuilder().WithScheme(configMapTestScheme(t)).Build()
	engine := Engine{Client: c}
	ctx := context.Background()

	req := testConfigMapRequest(source)
	req.TargetAnnotations = map[string]string{"example.com/origin": "platform"}
	if outcome := engine.CopyConfigMap(ctx, req); outcome != InSync {
		t.Fatalf("initial copy = %v, want InSync", outcome)
	}

	var target corev1.ConfigMap
	key := client.ObjectKey{Namespace: "tenant", Name: "app-config"}
	if err := c.Get(ctx, key, &target); err != nil {
		t.Fatalf("target not created: %v", err)
	}
	if target.Annotations["example.com/origin"] != "platform" {
		t.Errorf("rule annotation not applied: %v", target.Annotations)
	}
	if target.Annotations[AnnotationManagedAnnotations] != "example.com/origin" {
		t.Errorf("managed-annotations record = %q", target.Annotations[AnnotationManagedAnnotations])
	}

	// Dropping the annotation from the rule removes it from the copy.
	req.TargetAnnotations = nil
	if outcome := engine.CopyConfigMap(ctx, req); outcome != InSync {
		t.Fatalf("re-copy = %v, want InSync", outcome)
	}
	if err := c.Get(ctx, key, &target); err != nil {
		t.Fatalf("target gone: %v", err)
	}
	if _, present := target.Annotations["example.com/origin"]; present {
		t.Errorf("managed-then-dropped annotation remains: %v", target.Annotations)
	}
	if target.Annotations[AnnotationManagedBy] == "" || target.Annotations[AnnotationSourceResource] == "" {
		t.Errorf("tracking annotations damaged: %v", target.Annotations)
	}
}
