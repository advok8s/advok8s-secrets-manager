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

import "testing"

func TestNameSelector_Matches(t *testing.T) {
	tests := []struct {
		name     string
		selector NameSelector
		input    string
		want     bool
	}{
		{
			name: "Empty selector",
			selector: NameSelector{
				MatchNames: []string{},
			},
			input: "foo",
			want:  false,
		},
		{
			name: "Match single include",
			selector: NameSelector{
				MatchNames: []string{"foo"},
			},
			input: "foo",
			want:  true,
		},
		{
			name: "Match one of multiple includes",
			selector: NameSelector{
				MatchNames: []string{"foo", "bar", "baz"},
			},
			input: "bar",
			want:  true,
		},
		{
			name: "No match of multiple includes",
			selector: NameSelector{
				MatchNames: []string{"foo", "bar", "baz"},
			},
			input: "qux",
			want:  false,
		},
		{
			name: "Match single exclude",
			selector: NameSelector{
				MatchNames: []string{"!foo"},
			},
			input: "foo",
			want:  false,
		},
		{
			name: "Match one of multiple excludes",
			selector: NameSelector{
				MatchNames: []string{"!foo", "!bar", "!baz"},
			},
			input: "bar",
			want:  false,
		},
		{
			name: "No match of multiple excludes",
			selector: NameSelector{
				MatchNames: []string{"!foo", "!bar", "!baz"},
			},
			input: "qux",
			want:  true,
		},
		{
			name: "Exclude match if mixed list",
			selector: NameSelector{
				MatchNames: []string{"foo", "!bar", "baz"},
			},
			input: "bar",
			want:  false,
		},
		{
			name: "Include match of mixed list",
			selector: NameSelector{
				MatchNames: []string{"!foo", "bar", "!baz"},
			},
			input: "bar",
			want:  true,
		},
		{
			name: "Match of glob include",
			selector: NameSelector{
				MatchNames: []string{"foo-*"},
			},
			input: "foo-suffix",
			want:  true,
		},
		{
			name: "Match of glob exclude",
			selector: NameSelector{
				MatchNames: []string{"!foo-*"},
			},
			input: "foo-suffix",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.selector.Matches(tt.input)
			if got != tt.want {
				t.Errorf("NameSelector.Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
