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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// These are pure-function unit tests: the helpers take plain objects and return
// a bool, so they need no API server.

func TestSourceChanged(t *testing.T) {
	opaque := corev1.SecretTypeOpaque
	data := func(v string) map[string][]byte { return map[string][]byte{"k": []byte(v)} }

	cases := []struct {
		name              string
		extraLabels       map[string]string
		sourceType        corev1.SecretType
		targetType        corev1.SecretType
		sourceData        map[string][]byte
		targetData        map[string][]byte
		sourceLabels      map[string]string
		targetLabels      map[string]string
		targetManagedKeys string // value of the managed-labels annotation on the target
		expected          bool
	}{
		{
			name:       "identical type, data and labels -> no change",
			sourceType: opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1"},
			targetManagedKeys: "a",
			expected:          false,
		},
		{
			// Regression: a copy with no labels reads back with nil labels, while
			// the computed label set is an empty (non-nil) map. These must be
			// equal, otherwise a label-less copy is updated on every reconcile.
			name:       "no labels source and nil labels target -> no change",
			sourceType: opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: nil, targetLabels: nil,
			expected: false,
		},
		{
			name:       "different type -> changed",
			sourceType: opaque, targetType: corev1.SecretTypeTLS,
			sourceData: data("v"), targetData: data("v"),
			expected: true,
		},
		{
			name:       "different data value -> changed",
			sourceType: opaque, targetType: opaque,
			sourceData: data("v2"), targetData: data("v"),
			expected: true,
		},
		{
			name:       "extra data key in source -> changed",
			sourceType: opaque, targetType: opaque,
			sourceData: map[string][]byte{"k": []byte("v"), "k2": []byte("v2")}, targetData: data("v"),
			expected: true,
		},
		{
			name:       "source gained a label, data unchanged -> changed (regression guard)",
			sourceType: opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1", "b": "2"}, targetLabels: map[string]string{"a": "1"},
			targetManagedKeys: "a",
			expected:          true,
		},
		{
			// Managed-subset semantics: a label on the target that the operator
			// never managed (e.g. injected by a mutating admission webhook) is
			// invisible to the comparison. This is the no-reconcile-loop guard.
			name:       "foreign extra label on target -> no change (webhook injection guard)",
			sourceType: opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1", "team": "x"},
			targetManagedKeys: "a",
			expected:          false,
		},
		{
			// A label the operator previously managed but which is no longer
			// expected (removed from the source) must be removed: drift.
			name:       "stale managed label on target -> changed",
			sourceType: opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1", "b": "2"},
			targetManagedKeys: "a,b",
			expected:          true,
		},
		{
			name:        "extra label already present on target -> no change (no perpetual churn)",
			extraLabels: map[string]string{"managed": "x"},
			sourceType:  opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1", "managed": "x"},
			targetManagedKeys: "a,managed",
			expected:          false,
		},
		{
			name:        "extra label missing from target -> changed",
			extraLabels: map[string]string{"managed": "x"},
			sourceType:  opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1"},
			targetManagedKeys: "a",
			expected:          true,
		},
		{
			name:       "managed label value overwritten on target -> changed (re-asserted)",
			sourceType: opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "tampered"},
			targetManagedKeys: "a",
			expected:          true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var annotations map[string]string
			if c.targetManagedKeys != "" {
				annotations = map[string]string{AnnotationManagedLabels: c.targetManagedKeys}
			}
			source := &corev1.Secret{
				Type:       c.sourceType,
				Data:       c.sourceData,
				ObjectMeta: metav1.ObjectMeta{Labels: c.sourceLabels},
			}
			target := &corev1.Secret{
				Type:       c.targetType,
				Data:       c.targetData,
				ObjectMeta: metav1.ObjectMeta{Labels: c.targetLabels, Annotations: annotations},
			}
			if got := SourceChanged(source, target, c.extraLabels); got != c.expected {
				t.Errorf("SourceChanged() = %v, want %v", got, c.expected)
			}
		})
	}
}

func TestTargetManagedBy(t *testing.T) {
	const managedBy = "copier-x"
	const sourceRef = "src-ns/src-secret"

	cases := []struct {
		name        string
		annotations map[string]string
		expected    bool
	}{
		{
			name: "matching managed-by and source annotations -> managed",
			annotations: map[string]string{
				AnnotationManagedBy:      managedBy,
				AnnotationSourceResource: sourceRef,
			},
			expected: true,
		},
		{
			name:        "no annotations -> not managed",
			annotations: nil,
			expected:    false,
		},
		{
			name: "wrong managed-by value -> not managed",
			annotations: map[string]string{
				AnnotationManagedBy:      "someone-else",
				AnnotationSourceResource: sourceRef,
			},
			expected: false,
		},
		{
			name: "wrong source -> not managed",
			annotations: map[string]string{
				AnnotationManagedBy:      managedBy,
				AnnotationSourceResource: "other-ns/other-secret",
			},
			expected: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: c.annotations}}
			if got := TargetManagedBy(target, managedBy, sourceRef); got != c.expected {
				t.Errorf("TargetManagedBy() = %v, want %v", got, c.expected)
			}
		})
	}
}

func TestApplyManagedLabels(t *testing.T) {
	cases := []struct {
		name        string
		current     map[string]string
		managedKeys string
		expected    map[string]string
		want        map[string]string
	}{
		{
			name:        "foreign label preserved, expected applied",
			current:     map[string]string{"team": "x", "a": "old"},
			managedKeys: "a",
			expected:    map[string]string{"a": "1"},
			want:        map[string]string{"team": "x", "a": "1"},
		},
		{
			name:        "stale managed key removed, foreign untouched",
			current:     map[string]string{"team": "x", "a": "1", "b": "2"},
			managedKeys: "a,b",
			expected:    map[string]string{"a": "1"},
			want:        map[string]string{"team": "x", "a": "1"},
		},
		{
			name:        "no previously managed keys -> additive only",
			current:     map[string]string{"team": "x"},
			managedKeys: "",
			expected:    map[string]string{"a": "1"},
			want:        map[string]string{"team": "x", "a": "1"},
		},
		{
			name:        "managed key colliding with webhook value re-asserted",
			current:     map[string]string{"a": "webhook"},
			managedKeys: "a",
			expected:    map[string]string{"a": "1"},
			want:        map[string]string{"a": "1"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var annotations map[string]string
			if c.managedKeys != "" {
				annotations = map[string]string{AnnotationManagedLabels: c.managedKeys}
			}
			target := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Labels: c.current, Annotations: annotations}}
			got := applyManagedLabels(target, c.expected)
			if !mapStringStringEqual(got, c.want) {
				t.Errorf("applyManagedLabels() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestEncodeManagedLabelKeys(t *testing.T) {
	got := encodeManagedLabelKeys(map[string]string{"b": "2", "a": "1", "c/d": "3"})
	if got != "a,b,c/d" {
		t.Errorf("encodeManagedLabelKeys() = %q, want %q", got, "a,b,c/d")
	}
	if got := encodeManagedLabelKeys(nil); got != "" {
		t.Errorf("encodeManagedLabelKeys(nil) = %q, want empty", got)
	}
}
