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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LabelSelector is a selector which matches on labels.
// +k8s:deepcopy-gen=true
type LabelSelector struct {
	// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
	// map is equivalent to an element of matchExpressions, whose key field is "key", the
	// operator is "In", and the values array contains only "value". The requirements are ANDed.
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// matchExpressions is a list of label selector requirements. The requirements are ANDed.
	MatchExpressions []metav1.LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// Test whether selector is empty.
func (s LabelSelector) IsEmpty() bool {
	return len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0
}

// Matches against a set of labels.
func (s LabelSelector) Matches(labels map[string]string) bool {
	// Empty set will never be matched.

	if len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 {
		return false
	}

	// Function to match label against list of labels using glob expression.

	globMatchLabel := func(label string, items []string) bool {
		for _, item := range items {
			if match, _ := filepath.Match(item, label); match {
				return true
			}
		}
		return false
	}

	// Match labels against matchLabels.

	for key, value := range s.MatchLabels {
		if label, ok := labels[key]; !ok || label != value {
			return false
		}
	}

	// Match labels against matchExpressions.

	for _, matchExpression := range s.MatchExpressions {
		if label, ok := labels[matchExpression.Key]; ok {
			switch matchExpression.Operator {
			case "In":
				if !globMatchLabel(label, matchExpression.Values) {
					return false
				}
			case "NotIn":
				if globMatchLabel(label, matchExpression.Values) {
					return false
				}
			case "Exists":
				// Do nothing.
			case "DoesNotExist":
				return false
			}
		} else {
			switch matchExpression.Operator {
			case "In":
				return false
			case "NotIn":
				// Do nothing.
			case "Exists":
				return false
			case "DoesNotExist":
				// Do nothing.
			}
		}
	}

	return true
}
