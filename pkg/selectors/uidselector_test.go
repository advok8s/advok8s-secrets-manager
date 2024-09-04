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
)

func TestUIDSelector_Matches(t *testing.T) {
	selector := UIDSelector{
		MatchUids: []string{"uid1", "uid2", "uid3"},
	}

	// Test that a matching UID returns true.
	if !selector.Matches("uid2") {
		t.Errorf("Expected UID selector to match uid2, but it did not.")
	}

	// Test that a non-matching UID returns false.
	if selector.Matches("uid4") {
		t.Errorf("Expected UID selector to not match uid4, but it did.")
	}
}
