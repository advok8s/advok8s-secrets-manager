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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestTargetNamespaces_Matches(t *testing.T) {
	tests := []struct {
		name      string
		namespace corev1.Namespace
		selector  TargetNamespaces
		want      bool
	}{
		{
			name: "match by default",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			},
			selector: TargetNamespaces{},
			want:     true,
		},
		{
			name: "don't match on system namespace",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kube-system",
				},
			},
			selector: TargetNamespaces{},
			want:     false,
		},
		{
			name: "matches by name",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			},
			selector: TargetNamespaces{
				NameSelector: NameSelector{
					MatchNames: []string{"test-namespace"},
				},
			},
			want: true,
		},
		{
			name: "does not match by name",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			},
			selector: TargetNamespaces{
				NameSelector: NameSelector{
					MatchNames: []string{"other-namespace"},
				},
			},
			want: false,
		},
		{
			name: "exclude match by name",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			},
			selector: TargetNamespaces{
				NameSelector: NameSelector{
					MatchNames: []string{"!test-namespace"},
				},
			},
			want: false,
		},
		{
			name: "matches by label",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						"app": "test",
					},
				},
			},
			selector: TargetNamespaces{
				LabelSelector: LabelSelector{
					MatchLabels: map[string]string{
						"app": "test",
					},
				},
			},
			want: true,
		},
		{
			name: "does not match by label",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						"app": "test",
					},
				},
			},
			selector: TargetNamespaces{
				LabelSelector: LabelSelector{
					MatchLabels: map[string]string{
						"app": "other",
					},
				},
			},
			want: false,
		},
		{
			name: "matches by uid",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					UID:  "uid",
				},
			},
			selector: TargetNamespaces{
				UIDSelector: UIDSelector{
					MatchUids: []string{"uid"},
				},
			},
			want: true,
		},
		{
			name: "does not match by uid",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			},
			selector: TargetNamespaces{
				UIDSelector: UIDSelector{
					MatchUids: []string{"uid"},
				},
			},
			want: false,
		},
		{
			name: "matches by owner",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "v1",
							Kind:       "Namespace",
							Name:       "test-namespace",
							UID:        types.UID([]byte("uid")),
						},
					},
				},
			},
			selector: TargetNamespaces{
				OwnerSelector: OwnerSelector{
					MatchOwners: []OwnerReference{
						{
							APIVersion: "v1",
							Kind:       "Namespace",
							Name:       "test-namespace",
							UID:        "uid",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "does not match by owner",
			namespace: corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "v1",
							Kind:       "Namespace",
							Name:       "other-namespace",
							UID:        types.UID([]byte("uid")),
						},
					},
				},
			},
			selector: TargetNamespaces{
				OwnerSelector: OwnerSelector{
					MatchOwners: []OwnerReference{
						{
							APIVersion: "v1",
							Kind:       "Namespace",
							Name:       "test-namespace",
							UID:        "uid",
						},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.selector.Matches(&tt.namespace); got != tt.want {
				t.Errorf("TargetNamespaces.Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
