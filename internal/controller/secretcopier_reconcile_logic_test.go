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

package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// These are pure-function unit tests: the helpers below take plain objects and
// return a bool, so they need no API server. We drive them through an empty
// reconciler (they do not use the client).
var _ = Describe("SecretCopier reconcile decision helpers", func() {
	r := &SecretCopierReconciler{}

	Describe("sourceSecretHasBeenUpdated", func() {
		type updatedCase struct {
			ruleLabels   map[string]string
			sourceType   corev1.SecretType
			targetType   corev1.SecretType
			sourceData   map[string][]byte
			targetData   map[string][]byte
			sourceLabels map[string]string
			targetLabels map[string]string
			expected     bool
		}

		opaque := corev1.SecretTypeOpaque
		data := func(v string) map[string][]byte { return map[string][]byte{"k": []byte(v)} }

		DescribeTable("decides whether the target needs re-syncing",
			func(c updatedCase) {
				rule := &secretsv1beta1.SecretCopierRule{
					TargetSecret: secretsv1beta1.TargetSecret{Labels: c.ruleLabels},
				}
				source := &corev1.Secret{
					Type:       c.sourceType,
					Data:       c.sourceData,
					ObjectMeta: metav1.ObjectMeta{Labels: c.sourceLabels},
				}
				target := &corev1.Secret{
					Type:       c.targetType,
					Data:       c.targetData,
					ObjectMeta: metav1.ObjectMeta{Labels: c.targetLabels},
				}
				Expect(r.sourceSecretHasBeenUpdated(rule, source, target)).To(Equal(c.expected))
			},
			Entry("identical type, data and labels -> no update", updatedCase{
				sourceType: opaque, targetType: opaque,
				sourceData: data("v"), targetData: data("v"),
				sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1"},
				expected: false,
			}),
			Entry("different type -> update", updatedCase{
				sourceType: opaque, targetType: corev1.SecretTypeTLS,
				sourceData: data("v"), targetData: data("v"),
				expected: true,
			}),
			Entry("different data value -> update", updatedCase{
				sourceType: opaque, targetType: opaque,
				sourceData: data("v2"), targetData: data("v"),
				expected: true,
			}),
			Entry("extra data key in source -> update", updatedCase{
				sourceType: opaque, targetType: opaque,
				sourceData: map[string][]byte{"k": []byte("v"), "k2": []byte("v2")}, targetData: data("v"),
				expected: true,
			}),
			Entry("source gained a label, data unchanged -> update (regression guard)", updatedCase{
				sourceType: opaque, targetType: opaque,
				sourceData: data("v"), targetData: data("v"),
				sourceLabels: map[string]string{"a": "1", "b": "2"}, targetLabels: map[string]string{"a": "1"},
				expected: true,
			}),
			Entry("target has a stale extra label -> update", updatedCase{
				sourceType: opaque, targetType: opaque,
				sourceData: data("v"), targetData: data("v"),
				sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1", "c": "3"},
				expected: true,
			}),
			Entry("rule label already present on target -> no update (no perpetual churn)", updatedCase{
				ruleLabels: map[string]string{"managed": "x"},
				sourceType: opaque, targetType: opaque,
				sourceData: data("v"), targetData: data("v"),
				sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1", "managed": "x"},
				expected: false,
			}),
			Entry("rule label missing from target -> update", updatedCase{
				ruleLabels: map[string]string{"managed": "x"},
				sourceType: opaque, targetType: opaque,
				sourceData: data("v"), targetData: data("v"),
				sourceLabels: map[string]string{"a": "1"}, targetLabels: map[string]string{"a": "1"},
				expected: true,
			}),
		)
	})

	Describe("targetSecretManagedBySecretCopier", func() {
		const copierName = "copier-x"
		const sourceNamespace = "src-ns"
		const sourceName = "src-secret"

		inputs := func(annotations map[string]string) (*secretsv1beta1.SecretCopier, *secretsv1beta1.SecretCopierRule, *corev1.Secret) {
			copier := &secretsv1beta1.SecretCopier{ObjectMeta: metav1.ObjectMeta{Name: copierName}}
			rule := &secretsv1beta1.SecretCopierRule{
				SourceSecret: secretsv1beta1.SourceSecret{Namespace: sourceNamespace, Name: sourceName},
			}
			target := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: annotations}}
			return copier, rule, target
		}

		DescribeTable("recognises only the secrets it created from this source",
			func(annotations map[string]string, expected bool) {
				copier, rule, target := inputs(annotations)
				Expect(r.targetSecretManagedBySecretCopier(copier, rule, target)).To(Equal(expected))
			},
			Entry("matching copier and source annotations -> managed", map[string]string{
				annotationSecretCopier: copierName,
				annotationSecretName:   sourceNamespace + "/" + sourceName,
			}, true),
			Entry("no annotations -> not managed", map[string]string(nil), false),
			Entry("wrong copier name -> not managed", map[string]string{
				annotationSecretCopier: "someone-else",
				annotationSecretName:   sourceNamespace + "/" + sourceName,
			}, false),
			Entry("wrong source -> not managed", map[string]string{
				annotationSecretCopier: copierName,
				annotationSecretName:   "other-ns/other-secret",
			}, false),
		)
	})
})
