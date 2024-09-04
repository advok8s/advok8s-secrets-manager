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

// UIDSelector is a selector which matches on UID.
// +k8s:deepcopy-gen=true
type UIDSelector struct {
	// List of UIDs to match on.
	MatchUids []string `json:"matchUids"`
}

// Test whether selector is empty.
func (s UIDSelector) IsEmpty() bool {
	return len(s.MatchUids) == 0
}

// Matches against a uid.
func (s UIDSelector) Matches(uid string) bool {
	for _, name := range s.MatchUids {
		if name == uid {
			return true
		}
	}

	return false
}
