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
		name         string
		extraLabels  map[string]string
		sourceType   corev1.SecretType
		targetType   corev1.SecretType
		sourceData   map[string][]byte
		targetData   map[string][]byte
		sourceLabels map[string]string
		targetLabels map[string]string
		expected     bool
	}{
		{
			name:       "identical type, data and labels -> no change",
			sourceType: opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1"},
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
			expected: true,
		},
		{
			name:       "target has a stale extra label -> changed",
			sourceType: opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1", "c": "3"},
			expected: true,
		},
		{
			name:        "extra label already present on target -> no change (no perpetual churn)",
			extraLabels: map[string]string{"managed": "x"},
			sourceType:  opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1", "managed": "x"},
			expected: false,
		},
		{
			name:        "extra label missing from target -> changed",
			extraLabels: map[string]string{"managed": "x"},
			sourceType:  opaque, targetType: opaque,
			sourceData: data("v"), targetData: data("v"),
			sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1"},
			expected: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			source := &corev1.Secret{
				Type:       c.sourceType,
				Data:       c.sourceData,
				ObjectMeta: metav1.ObjectMeta{Labels: c.sourceLabels},
			}
			target := &corev1.Secret{
				Type:       c.targetType,
				Data:       c.targetData,
				ObjectMeta: metav1.ObjectMeta{Labels: c.targetLabels},
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
				AnnotationManagedBy:    managedBy,
				AnnotationSourceSecret: sourceRef,
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
				AnnotationManagedBy:    "someone-else",
				AnnotationSourceSecret: sourceRef,
			},
			expected: false,
		},
		{
			name: "wrong source -> not managed",
			annotations: map[string]string{
				AnnotationManagedBy:    managedBy,
				AnnotationSourceSecret: "other-ns/other-secret",
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
