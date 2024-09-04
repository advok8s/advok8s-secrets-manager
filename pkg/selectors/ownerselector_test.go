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

func TestOwnerSelector_Matches(t *testing.T) {
	owner1 := metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "Secret",
		Name:       "my-secret",
		UID:        "1234",
	}

	owner2 := metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Name:       "my-configmap",
		UID:        "5678",
	}

	selector := OwnerSelector{
		MatchOwners: []OwnerReference{
			{
				APIVersion: "v1",
				Kind:       "Secret",
				Name:       "my-secret",
				UID:        "1234",
			},
		},
	}

	if !selector.Matches([]metav1.OwnerReference{owner1}) {
		t.Errorf("Expected owner1 to match selector, but it did not")
	}

	if selector.Matches([]metav1.OwnerReference{owner2}) {
		t.Errorf("Expected owner2 to not match selector, but it did")
	}
}
