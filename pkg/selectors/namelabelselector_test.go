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

package selectors

import "testing"

func TestNameLabelSelector_Matches(t *testing.T) {
	names := func(n ...string) *NameSelector { return &NameSelector{MatchNames: n} }
	labels := func(m map[string]string) *LabelSelector { return &LabelSelector{MatchLabels: m} }

	tests := []struct {
		name     string
		selector NameLabelSelector
		input    string
		labels   map[string]string
		want     bool
	}{
		{
			name:     "empty selector matches everything",
			selector: NameLabelSelector{},
			input:    "anything",
			want:     true,
		},
		{
			name:     "name in set matches",
			selector: NameLabelSelector{NameSelector: names("foo", "bar")},
			input:    "bar",
			want:     true,
		},
		{
			name:     "name not in set does not match",
			selector: NameLabelSelector{NameSelector: names("foo", "bar")},
			input:    "qux",
			want:     false,
		},
		{
			name:     "name matching is exact, not glob",
			selector: NameLabelSelector{NameSelector: names("foo-*")},
			input:    "foo-suffix",
			want:     false,
		},
		{
			name:     "literal glob-looking name matches itself",
			selector: NameLabelSelector{NameSelector: names("foo-*")},
			input:    "foo-*",
			want:     true,
		},
		{
			name:     "label match",
			selector: NameLabelSelector{LabelSelector: labels(map[string]string{"team": "backend"})},
			input:    "ignored",
			labels:   map[string]string{"team": "backend"},
			want:     true,
		},
		{
			name:     "label mismatch",
			selector: NameLabelSelector{LabelSelector: labels(map[string]string{"team": "backend"})},
			input:    "ignored",
			labels:   map[string]string{"team": "frontend"},
			want:     false,
		},
		{
			name:     "name and label both required - both match",
			selector: NameLabelSelector{NameSelector: names("creds"), LabelSelector: labels(map[string]string{"team": "backend"})},
			input:    "creds",
			labels:   map[string]string{"team": "backend"},
			want:     true,
		},
		{
			name:     "name and label both required - name matches, label does not",
			selector: NameLabelSelector{NameSelector: names("creds"), LabelSelector: labels(map[string]string{"team": "backend"})},
			input:    "creds",
			labels:   map[string]string{"team": "frontend"},
			want:     false,
		},
		{
			name:     "name and label both required - label matches, name does not",
			selector: NameLabelSelector{NameSelector: names("creds"), LabelSelector: labels(map[string]string{"team": "backend"})},
			input:    "other",
			labels:   map[string]string{"team": "backend"},
			want:     false,
		},
		{
			name:     "nil name selector with empty match names ignored",
			selector: NameLabelSelector{NameSelector: &NameSelector{}, LabelSelector: labels(map[string]string{"team": "backend"})},
			input:    "anything",
			labels:   map[string]string{"team": "backend"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.selector.Matches(tt.input, tt.labels)
			if got != tt.want {
				t.Errorf("NameLabelSelector.Matches(%q, %v) = %v, want %v", tt.input, tt.labels, got, tt.want)
			}
		})
	}
}

func TestNameLabelSelector_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		selector NameLabelSelector
		want     bool
	}{
		{
			name:     "both nil",
			selector: NameLabelSelector{},
			want:     true,
		},
		{
			name:     "empty sub-selectors",
			selector: NameLabelSelector{NameSelector: &NameSelector{}, LabelSelector: &LabelSelector{}},
			want:     true,
		},
		{
			name:     "name set",
			selector: NameLabelSelector{NameSelector: &NameSelector{MatchNames: []string{"foo"}}},
			want:     false,
		},
		{
			name:     "label set",
			selector: NameLabelSelector{LabelSelector: &LabelSelector{MatchLabels: map[string]string{"a": "b"}}},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.selector.IsEmpty(); got != tt.want {
				t.Errorf("NameLabelSelector.IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}
