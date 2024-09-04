/*
Copyright Graham Dumpleton 2024.

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

package selectors

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLabelSelector_Matches(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		s      LabelSelector
		want   bool
	}{
		{
			name: "EmptySelector: nothing to match",
			labels: map[string]string{
				"app": "myapp",
			},
			s:    LabelSelector{},
			want: false,
		},
		{
			name: "MatchLabels: single label match",
			labels: map[string]string{
				"app": "myapp",
			},
			s: LabelSelector{
				MatchLabels: map[string]string{
					"app": "myapp",
				},
			},
			want: true,
		},
		{
			name: "MatchLabels: single label no match",
			labels: map[string]string{
				"app": "myapp",
			},
			s: LabelSelector{
				MatchLabels: map[string]string{
					"app": "otherapp",
				},
			},
			want: false,
		},
		{
			name: "MatchLabels: multiple labels match",
			labels: map[string]string{
				"app":  "myapp",
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchLabels: map[string]string{
					"app":  "myapp",
					"tier": "frontend",
				},
			},
			want: true,
		},
		{
			name: "MatchLabels: multiple labels no match",
			labels: map[string]string{
				"app":  "myapp",
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchLabels: map[string]string{
					"app":  "otherapp",
					"tier": "backend",
				},
			},
			want: false,
		},
		{
			name: "MatchExpressions: In operator match",
			labels: map[string]string{
				"app":  "myapp",
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "In",
						Values:   []string{"myapp", "otherapp"},
					},
				},
			},
			want: true,
		},
		{
			name: "MatchExpressions: In operator no match",
			labels: map[string]string{
				"app":  "myapp",
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "In",
						Values:   []string{"otherapp"},
					},
				},
			},
			want: false,
		},
		{
			name:   "MatchExpressions: NotIn no labels",
			labels: map[string]string{},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "NotIn",
						Values:   []string{"otherapp"},
					},
				},
			},
			want: true,
		},
		{
			name: "MatchExpressions: NotIn operator match",
			labels: map[string]string{
				"app":  "myapp",
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "NotIn",
						Values:   []string{"otherapp"},
					},
				},
			},
			want: true,
		},
		{
			name: "MatchExpressions: NotIn operator no match",
			labels: map[string]string{
				"app":  "myapp",
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "NotIn",
						Values:   []string{"myapp", "otherapp"},
					},
				},
			},
			want: false,
		},
		{
			name: "MatchExpressions: Exists operator match",
			labels: map[string]string{
				"app":  "myapp",
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "Exists",
					},
				},
			},
			want: true,
		},
		{
			name: "MatchExpressions: Exists operator no match",
			labels: map[string]string{
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "Exists",
					},
				},
			},
			want: false,
		},
		{
			name: "MatchExpressions: DoesNotExist operator match",
			labels: map[string]string{
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "DoesNotExist",
					},
				},
			},
			want: true,
		},
		{
			name: "MatchExpressions: DoesNotExist operator no match",
			labels: map[string]string{
				"app":  "myapp",
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "DoesNotExist",
					},
				},
			},
			want: false,
		},
		{
			name: "MatchExpressions: multiple expressions match",
			labels: map[string]string{
				"app":  "myapp",
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "In",
						Values:   []string{"myapp", "otherapp"},
					},
					{
						Key:      "tier",
						Operator: "Exists",
					},
				},
			},
			want: true,
		},
		{
			name: "MatchExpressions: multiple expressions no match",
			labels: map[string]string{
				"app":  "myapp",
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "In",
						Values:   []string{"otherapp"},
					},
					{
						Key:      "tier",
						Operator: "DoesNotExist",
					},
				},
			},
			want: false,
		},
		{
			name: "MatchExpressions: label not found",
			labels: map[string]string{
				"tier": "frontend",
			},
			s: LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "In",
						Values:   []string{"myapp", "otherapp"},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.Matches(tt.labels); got != tt.want {
				t.Errorf("LabelSelector.Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
