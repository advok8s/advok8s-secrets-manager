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

// NameLabelSelector matches a resource by name and/or labels. It is used by
// SecretInjector to select the source secrets and the service accounts to
// inject them into.
//
// Unlike NameSelector as used for namespaces, name matching here is exact set
// membership - a name matches when it appears verbatim in MatchNames, with no
// glob patterns or "!" exclusions. When both a name selector and a label
// selector are given, both must match. An empty selector (neither set) matches
// everything.
//
// The sub-selectors are pointers so each is omitted from the serialised object
// when unset, avoiding the schema requirement that a present nameSelector carry
// matchNames.
// +k8s:deepcopy-gen=true
type NameLabelSelector struct {
	// NameSelector matches the resource name by exact set membership.
	// +optional
	NameSelector *NameSelector `json:"nameSelector,omitempty"`

	// LabelSelector matches the resource labels.
	// +optional
	LabelSelector *LabelSelector `json:"labelSelector,omitempty"`
}

// IsEmpty reports whether no name or label criteria are set, in which case the
// selector matches everything.
func (s NameLabelSelector) IsEmpty() bool {
	return (s.NameSelector == nil || len(s.NameSelector.MatchNames) == 0) &&
		(s.LabelSelector == nil || s.LabelSelector.IsEmpty())
}

// Matches reports whether a resource with the given name and labels satisfies
// the selector.
func (s NameLabelSelector) Matches(name string, labels map[string]string) bool {
	if s.NameSelector != nil && len(s.NameSelector.MatchNames) > 0 {
		found := false
		for _, candidate := range s.NameSelector.MatchNames {
			if candidate == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if s.LabelSelector != nil && !s.LabelSelector.IsEmpty() && !s.LabelSelector.Matches(labels) {
		return false
	}

	return true
}
