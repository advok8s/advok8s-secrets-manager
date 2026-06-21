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
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestConfigMapSourceChanged(t *testing.T) {
	data := func(v string) map[string]string { return map[string]string{"k": v} }
	binary := func(v string) map[string][]byte { return map[string][]byte{"b": []byte(v)} }

	cases := []struct {
		name              string
		extraLabels       map[string]string
		sourceData        map[string]string
		targetData        map[string]string
		sourceBinary      map[string][]byte
		targetBinary      map[string][]byte
		sourceLabels      map[string]string
		targetLabels      map[string]string
		targetManagedKeys string
		expected          bool
	}{
		{
			name:       "identical data, binaryData and labels -> no change",
			sourceData: data("v"), targetData: data("v"),
			sourceBinary: binary("x"), targetBinary: binary("x"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1"},
			targetManagedKeys: "a",
			expected:          false,
		},
		{
			// Regression guards for nil-vs-empty on both maps: a configmap
			// stored with no data/binaryData reads back as nil maps.
			name:       "nil data and binaryData both sides -> no change",
			sourceData: nil, targetData: nil,
			sourceBinary: nil, targetBinary: nil,
			expected: false,
		},
		{
			name:       "empty non-nil source data vs nil target data -> no change",
			sourceData: map[string]string{}, targetData: nil,
			sourceBinary: map[string][]byte{}, targetBinary: nil,
			expected: false,
		},
		{
			name:       "different data value -> changed",
			sourceData: data("v2"), targetData: data("v"),
			expected: true,
		},
		{
			name:       "different binaryData value -> changed",
			sourceData: data("v"), targetData: data("v"),
			sourceBinary: binary("x2"), targetBinary: binary("x"),
			expected: true,
		},
		{
			name:       "extra binaryData key in source -> changed",
			sourceData: data("v"), targetData: data("v"),
			sourceBinary: map[string][]byte{"b": []byte("x"), "b2": []byte("y")}, targetBinary: binary("x"),
			expected: true,
		},
		{
			// A key that moved from data to binaryData in the source must be
			// seen as drift on both maps.
			name:       "key migrated from data to binaryData -> changed",
			sourceData: map[string]string{}, targetData: map[string]string{"k": "v"},
			sourceBinary: map[string][]byte{"k": []byte("v")}, targetBinary: nil,
			expected: true,
		},
		{
			name:       "foreign extra label on target -> no change (webhook injection guard)",
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1", "team": "x"},
			targetManagedKeys: "a",
			expected:          false,
		},
		{
			name:       "stale managed label on target -> changed",
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1", "b": "2"},
			targetManagedKeys: "a,b",
			expected:          true,
		},
		{
			name:        "extra label missing from target -> changed",
			extraLabels: map[string]string{"managed": "x"},
			sourceData:  data("v"), targetData: data("v"),
			expected: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var annotations map[string]string
			if c.targetManagedKeys != "" {
				annotations = map[string]string{ConfigMapAnnotationManagedLabels: c.targetManagedKeys}
			}
			source := &corev1.ConfigMap{
				Data:       c.sourceData,
				BinaryData: c.sourceBinary,
				ObjectMeta: metav1.ObjectMeta{Labels: c.sourceLabels},
			}
			target := &corev1.ConfigMap{
				Data:       c.targetData,
				BinaryData: c.targetBinary,
				ObjectMeta: metav1.ObjectMeta{Labels: c.targetLabels, Annotations: annotations},
			}
			if got := ConfigMapSourceChanged(source, target, c.extraLabels, nil); got != c.expected {
				t.Errorf("ConfigMapSourceChanged() = %v, want %v", got, c.expected)
			}
		})
	}
}

// ---- CopyConfigMap flow tests against a fake client ------------------------

func configMapTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("building scheme: %v", err)
	}
	return scheme
}

func testSourceConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-config",
			Namespace: "platform",
			Labels:    map[string]string{"app": "demo"},
		},
		Data:       map[string]string{"settings": "value"},
		BinaryData: map[string][]byte{"logo": {0xff, 0x00, 0x01}},
	}
}

func testConfigMapRequest(source *corev1.ConfigMap) ConfigMapRequest {
	return ConfigMapRequest{
		Source:          source,
		SourceNamespace: source.Namespace,
		SourceName:      source.Name,
		TargetNamespace: "tenant",
		TargetName:      source.Name,
		TargetLabels:    map[string]string{"copied": "true"},
		ManagedByValue:  "configmapcopier/test",
	}
}

func TestCopyConfigMapCreates(t *testing.T) {
	source := testSourceConfigMap()
	c := fake.NewClientBuilder().WithScheme(configMapTestScheme(t)).Build()
	engine := Engine{Client: c}

	if outcome := engine.CopyConfigMap(context.Background(), testConfigMapRequest(source)); outcome != InSync {
		t.Fatalf("CopyConfigMap() = %v, want InSync", outcome)
	}

	var target corev1.ConfigMap
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "tenant", Name: "app-config"}, &target); err != nil {
		t.Fatalf("target not created: %v", err)
	}
	if target.Data["settings"] != "value" || string(target.BinaryData["logo"]) != string([]byte{0xff, 0x00, 0x01}) {
		t.Errorf("target payload mismatch: %v / %v", target.Data, target.BinaryData)
	}
	if target.Labels["app"] != "demo" || target.Labels["copied"] != "true" {
		t.Errorf("target labels mismatch: %v", target.Labels)
	}
	if target.Annotations[ConfigMapAnnotationManagedBy] != "configmapcopier/test" {
		t.Errorf("managed-by annotation = %q", target.Annotations[ConfigMapAnnotationManagedBy])
	}
	if target.Annotations[ConfigMapAnnotationSourceResource] != "platform/app-config" {
		t.Errorf("source annotation = %q", target.Annotations[ConfigMapAnnotationSourceResource])
	}
	if target.Annotations[ConfigMapAnnotationManagedLabels] != "app,copied" {
		t.Errorf("managed-labels annotation = %q", target.Annotations[ConfigMapAnnotationManagedLabels])
	}
}

func TestCopyConfigMapUpdatesOnDrift(t *testing.T) {
	source := testSourceConfigMap()
	c := fake.NewClientBuilder().WithScheme(configMapTestScheme(t)).Build()
	engine := Engine{Client: c}
	ctx := context.Background()

	if outcome := engine.CopyConfigMap(ctx, testConfigMapRequest(source)); outcome != InSync {
		t.Fatalf("initial copy = %v, want InSync", outcome)
	}

	// Source changes: data value updated, a label removed, a binary key moved
	// to data. The target must converge on all of it.
	source.Data = map[string]string{"settings": "new", "logo": "now-text"}
	source.BinaryData = nil
	source.Labels = nil

	if outcome := engine.CopyConfigMap(ctx, testConfigMapRequest(source)); outcome != InSync {
		t.Fatalf("re-copy = %v, want InSync", outcome)
	}

	var target corev1.ConfigMap
	if err := c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "app-config"}, &target); err != nil {
		t.Fatalf("target gone: %v", err)
	}
	if target.Data["settings"] != "new" || target.Data["logo"] != "now-text" {
		t.Errorf("target data not converged: %v", target.Data)
	}
	if len(target.BinaryData) != 0 {
		t.Errorf("stale binaryData remains: %v", target.BinaryData)
	}
	if _, exists := target.Labels["app"]; exists {
		t.Errorf("stale managed label %q remains: %v", "app", target.Labels)
	}
	if target.Labels["copied"] != "true" {
		t.Errorf("target label from rule missing: %v", target.Labels)
	}
	if target.Annotations[ConfigMapAnnotationManagedLabels] != "copied" {
		t.Errorf("managed-labels annotation = %q, want %q", target.Annotations[ConfigMapAnnotationManagedLabels], "copied")
	}
}

func TestCopyConfigMapPreservesForeignLabels(t *testing.T) {
	source := testSourceConfigMap()
	c := fake.NewClientBuilder().WithScheme(configMapTestScheme(t)).Build()
	engine := Engine{Client: c}
	ctx := context.Background()

	if outcome := engine.CopyConfigMap(ctx, testConfigMapRequest(source)); outcome != InSync {
		t.Fatalf("initial copy = %v, want InSync", outcome)
	}

	// Simulate a mutating admission webhook stamping a label on the copy.
	var target corev1.ConfigMap
	if err := c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "app-config"}, &target); err != nil {
		t.Fatalf("target gone: %v", err)
	}
	target.Labels["team"] = "x"
	if err := c.Update(ctx, &target); err != nil {
		t.Fatalf("simulating webhook label: %v", err)
	}
	injectedVersion := target.ResourceVersion

	// A steady-state copy must not update (no churn against the webhook).
	if outcome := engine.CopyConfigMap(ctx, testConfigMapRequest(source)); outcome != InSync {
		t.Fatalf("steady-state copy = %v, want InSync", outcome)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "app-config"}, &target); err != nil {
		t.Fatalf("target gone: %v", err)
	}
	if target.ResourceVersion != injectedVersion {
		t.Errorf("steady-state copy churned the target (resourceVersion %s -> %s)", injectedVersion, target.ResourceVersion)
	}

	// A genuine source change updates the target but keeps the foreign label.
	source.Data["settings"] = "changed"
	if outcome := engine.CopyConfigMap(ctx, testConfigMapRequest(source)); outcome != InSync {
		t.Fatalf("re-copy = %v, want InSync", outcome)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "app-config"}, &target); err != nil {
		t.Fatalf("target gone: %v", err)
	}
	if target.Labels["team"] != "x" {
		t.Errorf("foreign label clobbered: %v", target.Labels)
	}
	if target.Data["settings"] != "changed" {
		t.Errorf("data not converged: %v", target.Data)
	}
}

func TestCopyConfigMapConflict(t *testing.T) {
	source := testSourceConfigMap()
	foreign := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "app-config", Namespace: "tenant"},
		Data:       map[string]string{"theirs": "data"},
	}
	c := fake.NewClientBuilder().WithScheme(configMapTestScheme(t)).WithObjects(foreign).Build()
	engine := Engine{Client: c}

	if outcome := engine.CopyConfigMap(context.Background(), testConfigMapRequest(source)); outcome != Conflict {
		t.Fatalf("CopyConfigMap() = %v, want Conflict", outcome)
	}

	var target corev1.ConfigMap
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "tenant", Name: "app-config"}, &target); err != nil {
		t.Fatalf("foreign target gone: %v", err)
	}
	if target.Data["theirs"] != "data" {
		t.Errorf("foreign configmap was modified: %v", target.Data)
	}
}

func TestCopyConfigMapSameNamespaceSkipped(t *testing.T) {
	source := testSourceConfigMap()
	c := fake.NewClientBuilder().WithScheme(configMapTestScheme(t)).Build()
	engine := Engine{Client: c}

	req := testConfigMapRequest(source)
	req.TargetNamespace = source.Namespace

	if outcome := engine.CopyConfigMap(context.Background(), req); outcome != Skipped {
		t.Fatalf("CopyConfigMap() = %v, want Skipped", outcome)
	}
}
