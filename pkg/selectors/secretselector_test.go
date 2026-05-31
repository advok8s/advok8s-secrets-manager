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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// object builds an ObjectMeta the SecretSelector can match against. A
// *metav1.ObjectMeta satisfies metav1.Object, so no concrete kind is needed.
func object() *metav1.ObjectMeta {
	return &metav1.ObjectMeta{
		Name:   "registry-credentials",
		Labels: map[string]string{"app": "web", "tier": "frontend"},
		UID:    types.UID("uid-123"),
		OwnerReferences: []metav1.OwnerReference{
			{APIVersion: "v1", Kind: "ConfigMap", Name: "owner", UID: types.UID("owner-uid")},
		},
	}
}

func TestSecretSelectorIsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		selector SecretSelector
		want     bool
	}{
		{name: "nothing set", selector: SecretSelector{}, want: true},
		{name: "all set but empty", selector: SecretSelector{
			NameSelector:  &NameSelector{},
			LabelSelector: &LabelSelector{},
			OwnerSelector: &OwnerSelector{},
			UIDSelector:   &UIDSelector{},
		}, want: true},
		{name: "name set", selector: SecretSelector{NameSelector: &NameSelector{MatchNames: []string{"x"}}}, want: false},
		{name: "labels set", selector: SecretSelector{LabelSelector: &LabelSelector{MatchLabels: map[string]string{"a": "b"}}}, want: false},
		{name: "owner set", selector: SecretSelector{OwnerSelector: &OwnerSelector{MatchOwners: []OwnerReference{{Name: "o"}}}}, want: false},
		{name: "uid set", selector: SecretSelector{UIDSelector: &UIDSelector{MatchUids: []string{"u"}}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.selector.IsEmpty(); got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSecretSelectorMatches(t *testing.T) {
	tests := []struct {
		name     string
		selector SecretSelector
		want     bool
	}{
		{
			name:     "empty selector matches everything",
			selector: SecretSelector{},
			want:     true,
		},
		{
			name:     "set-but-empty sub-selectors impose no constraint",
			selector: SecretSelector{NameSelector: &NameSelector{}, LabelSelector: &LabelSelector{}},
			want:     true,
		},
		{
			name:     "name matches literally",
			selector: SecretSelector{NameSelector: &NameSelector{MatchNames: []string{"registry-credentials"}}},
			want:     true,
		},
		{
			name:     "name matches by glob",
			selector: SecretSelector{NameSelector: &NameSelector{MatchNames: []string{"registry-*"}}},
			want:     true,
		},
		{
			name:     "name does not match",
			selector: SecretSelector{NameSelector: &NameSelector{MatchNames: []string{"other"}}},
			want:     false,
		},
		{
			name:     "labels match",
			selector: SecretSelector{LabelSelector: &LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
			want:     true,
		},
		{
			name:     "labels do not match",
			selector: SecretSelector{LabelSelector: &LabelSelector{MatchLabels: map[string]string{"app": "api"}}},
			want:     false,
		},
		{
			name: "owner matches",
			selector: SecretSelector{OwnerSelector: &OwnerSelector{MatchOwners: []OwnerReference{
				{APIVersion: "v1", Kind: "ConfigMap", Name: "owner", UID: types.UID("owner-uid")},
			}}},
			want: true,
		},
		{
			name: "owner does not match",
			selector: SecretSelector{OwnerSelector: &OwnerSelector{MatchOwners: []OwnerReference{
				{APIVersion: "v1", Kind: "ConfigMap", Name: "different", UID: types.UID("owner-uid")},
			}}},
			want: false,
		},
		{
			name:     "uid matches",
			selector: SecretSelector{UIDSelector: &UIDSelector{MatchUids: []string{"uid-123"}}},
			want:     true,
		},
		{
			name:     "uid does not match",
			selector: SecretSelector{UIDSelector: &UIDSelector{MatchUids: []string{"uid-999"}}},
			want:     false,
		},
		{
			name: "all set and all match (ANDed)",
			selector: SecretSelector{
				NameSelector:  &NameSelector{MatchNames: []string{"registry-*"}},
				LabelSelector: &LabelSelector{MatchLabels: map[string]string{"tier": "frontend"}},
				OwnerSelector: &OwnerSelector{MatchOwners: []OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "owner", UID: types.UID("owner-uid")}}},
				UIDSelector:   &UIDSelector{MatchUids: []string{"uid-123"}},
			},
			want: true,
		},
		{
			name: "all set but one fails (ANDed)",
			selector: SecretSelector{
				NameSelector:  &NameSelector{MatchNames: []string{"registry-*"}},
				LabelSelector: &LabelSelector{MatchLabels: map[string]string{"tier": "frontend"}},
				UIDSelector:   &UIDSelector{MatchUids: []string{"wrong-uid"}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.selector.Matches(object()); got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
