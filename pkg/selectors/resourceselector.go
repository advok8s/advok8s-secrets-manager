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

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourceSelector matches a resource by any combination of name, labels, owner
// references and UID. It is the richest selector in the family: a superset of
// NameLabelSelector that adds owner and uid matching, used for the builder's
// Secret and ConfigMap inputs and for SecretInjector's source secrets.
//
// The sub-selectors are pointers so each is omitted from the serialised object
// when unset (the same pointer-for-omitempty pattern as NameLabelSelector),
// avoiding the schema requirement that a present sub-selector carry its match
// list. When more than one sub-selector is set they are ANDed - the resource
// must satisfy every one. An empty selector (none set) matches everything.
//
// Name matching uses NameSelector, which supports shell-style globs and "!"
// exclusions; a plain literal name with no glob metacharacters matches exactly,
// so this remains a behavioural superset of NameLabelSelector's exact matching.
// +k8s:deepcopy-gen=true
type ResourceSelector struct {
	// NameSelector matches the resource name (supports globs and "!" exclusions).
	// +optional
	NameSelector *NameSelector `json:"nameSelector,omitempty"`

	// LabelSelector matches the resource labels.
	// +optional
	LabelSelector *LabelSelector `json:"labelSelector,omitempty"`

	// OwnerSelector matches the resource's owner references.
	// +optional
	OwnerSelector *OwnerSelector `json:"ownerSelector,omitempty"`

	// UIDSelector matches the resource UID.
	// +optional
	UIDSelector *UIDSelector `json:"uidSelector,omitempty"`
}

// IsEmpty reports whether no criteria are set, in which case the selector matches
// everything.
func (s ResourceSelector) IsEmpty() bool {
	return (s.NameSelector == nil || s.NameSelector.IsEmpty()) &&
		(s.LabelSelector == nil || s.LabelSelector.IsEmpty()) &&
		(s.OwnerSelector == nil || s.OwnerSelector.IsEmpty()) &&
		(s.UIDSelector == nil || s.UIDSelector.IsEmpty())
}

// Matches reports whether the given object satisfies every set sub-selector. A
// sub-selector that is unset or empty imposes no constraint, so an empty
// ResourceSelector matches any object.
func (s ResourceSelector) Matches(object metav1.Object) bool {
	if s.NameSelector != nil && !s.NameSelector.IsEmpty() && !s.NameSelector.Matches(object.GetName()) {
		return false
	}

	if s.LabelSelector != nil && !s.LabelSelector.IsEmpty() && !s.LabelSelector.Matches(object.GetLabels()) {
		return false
	}

	if s.OwnerSelector != nil && !s.OwnerSelector.IsEmpty() && !s.OwnerSelector.Matches(object.GetOwnerReferences()) {
		return false
	}

	if s.UIDSelector != nil && !s.UIDSelector.IsEmpty() && !s.UIDSelector.Matches(string(object.GetUID())) {
		return false
	}

	return true
}
