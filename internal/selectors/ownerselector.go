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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// OwnerReference is a reference to an owner.
// +k8s:deepcopy-gen=true
type OwnerReference struct {
	// API version of the owner.
	APIVersion string `json:"apiVersion"`

	// Resource kind of the owner.
	Kind string `json:"kind"`

	// Name of the owner.
	Name string `json:"name"`

	// UID of the owner.
	UID types.UID `json:"uid"`
}

// OwnerSelector is a selector which matches on owner.
// +k8s:deepcopy-gen=true
type OwnerSelector struct {
	// List of owners to match on.
	MatchOwners []OwnerReference `json:"matchOwners"`
}

// Test whether selector is empty.
func (s OwnerSelector) IsEmpty() bool {
	return len(s.MatchOwners) == 0
}

// Matches against an owner.
func (s OwnerSelector) Matches(ownerReferences []metav1.OwnerReference) bool {
	for _, ownerReference := range ownerReferences {
		for _, matchOwner := range s.MatchOwners {
			if matchOwner.APIVersion == ownerReference.APIVersion &&
				matchOwner.Kind == ownerReference.Kind &&
				matchOwner.Name == ownerReference.Name &&
				matchOwner.UID == ownerReference.UID {
				return true
			}
		}
	}

	return false
}
