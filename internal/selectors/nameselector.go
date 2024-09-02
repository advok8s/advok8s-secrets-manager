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
	"path/filepath"
	"strings"
)

// NameSelector is a selector which matches on name.
// +k8s:deepcopy-gen=true
type NameSelector struct {
	// List of names to match on.
	MatchNames []string `json:"matchNames"`
}

// Test whether selector is empty.
func (s NameSelector) IsEmpty() bool {
	return len(s.MatchNames) == 0
}

// Matches against a name.
func (s NameSelector) Matches(name string) bool {
	// Empty set will never be matched.

	if len(s.MatchNames) == 0 {
		return false
	}

	// Split names into include and exclude lists.

	var matchExcludeNames []string
	var matchIncludeNames []string

	for _, name := range s.MatchNames {
		if strings.HasPrefix(name, "!") {
			matchExcludeNames = append(matchExcludeNames, name[1:])
		} else {
			matchIncludeNames = append(matchIncludeNames, name)
		}
	}

	// Function to match name against list of names using glob expression.

	globMatchName := func(name string, items []string) bool {
		for _, item := range items {
			if ok, _ := filepath.Match(item, name); ok {
				return true
			}
		}
		return false
	}

	// If there are any include names, but don't match any then return false.

	if len(matchIncludeNames) > 0 && !globMatchName(name, matchIncludeNames) {
		return false
	}

	// If there are any exclude names, and match any then return false.

	if len(matchExcludeNames) > 0 && globMatchName(name, matchExcludeNames) {
		return false
	}

	return true
}
