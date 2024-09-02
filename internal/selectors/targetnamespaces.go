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
	corev1 "k8s.io/api/core/v1"
)

// TargetNamespaces are matchers for namespaces to copy to.
// +k8s:deepcopy-gen=true
type TargetNamespaces struct {
	// List of namespaces to match by name.
	NameSelector NameSelector `json:"nameSelector,omitempty"`

	// List of namespaces to match by UID.
	UIDSelector UIDSelector `json:"uidSelector,omitempty"`

	// List of namespaces to match by owner.
	OwnerSelector OwnerSelector `json:"ownerSelector,omitempty"`

	// List of namespaces to match by label.
	LabelSelector LabelSelector `json:"labelSelector,omitempty"`
}

// Matches against a namespace. As soon as one of the matchers fails we
// give up and return false.
func (s TargetNamespaces) Matches(namespace corev1.Namespace) bool {
	// If there is no name selector, then match on all but Kubernetes
	// system namespaces. Otherwise match on name selector.

	if s.NameSelector.IsEmpty() {
		tmpNameSelector := NameSelector{[]string{"!kube-*"}}

		if !tmpNameSelector.Matches(namespace.Name) {
			return false
		}
	} else {
		if !s.NameSelector.Matches(namespace.Name) {
			return false
		}
	}

	// If there are UIDs to match on, then match on them.

	if !s.UIDSelector.IsEmpty() && !s.UIDSelector.Matches(string(namespace.GetUID())) {
		return false
	}

	// If there are owners to match on, then match on them.

	if !s.OwnerSelector.IsEmpty() && !s.OwnerSelector.Matches(namespace.GetOwnerReferences()) {
		return false
	}

	// If there are labels to match on, then match on them.

	if !s.LabelSelector.IsEmpty() && !s.LabelSelector.Matches(namespace.GetLabels()) {
		return false
	}

	// If we get here, then all matchers have passed.

	return true
}
