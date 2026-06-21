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
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
	"github.com/advok8s/advok8s-secrets-manager/internal/copyengine"
)

// How the target secret is shaped: name (rename), labels (source labels
// overlaid with rule labels) and the tracking annotations.
var _ = Describe("SecretCopier shaping the target secret", func() {
	Context("when the rule renames the target and adds labels", func() {
		It("creates the copy with the new name, merged labels and tracking annotations", func() {
			createNamespace("shape-src")
			createNamespace("shape-tgt")
			createOpaqueSecret("shape-src", "original-name",
				map[string]string{"key1": "value1"}, map[string]string{"env": "prod"})

			createSecretCopier("shape-copier", copyRule(ruleOptions{
				SourceNamespace: "shape-src",
				SourceName:      "original-name",
				TargetName:      "renamed-secret",
				TargetLabels:    map[string]string{"managed-by": "advok8s", "env": "override"},
				MatchNames:      []string{"shape-tgt"},
			}))

			target := eventuallyGetSecret("shape-tgt", "renamed-secret")

			// Renamed.
			Expect(target.Name).To(Equal("renamed-secret"))
			// Source labels overlaid with rule labels (rule wins on "env").
			Expect(target.Labels).To(Equal(map[string]string{"env": "override", "managed-by": "advok8s"}))
			// Tracking annotations.
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.SecretAnnotationManagedBy, "secretcopier/shape-copier"))
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.SecretAnnotationSourceResource, "shape-src/original-name"))

			// The source secret itself is left untouched.
			source := eventuallyGetSecret("shape-src", "original-name")
			Expect(source.Labels).To(Equal(map[string]string{"env": "prod"}))
		})
	})

	Context("when the rule sets target annotations", func() {
		It("applies them as a managed subset and reconciles rule edits", func() {
			createNamespace("annot-src")
			createNamespace("annot-tgt")
			createOpaqueSecret("annot-src", defaultSourceSecretName,
				map[string]string{"key1": "value1"}, nil)

			copier := createSecretCopier("annot-copier", copyRule(ruleOptions{
				SourceNamespace:   "annot-src",
				SourceName:        defaultSourceSecretName,
				TargetName:        defaultTargetSecretName,
				TargetAnnotations: map[string]string{"example.com/team": "a", "example.com/tier": "1"},
				MatchNames:        []string{"annot-tgt"},
			}))

			// The copy carries the rule's annotations, records them as managed,
			// and never copies the source's own annotations.
			target := eventuallyGetSecret("annot-tgt", defaultTargetSecretName)
			Expect(target.Annotations).To(HaveKeyWithValue("example.com/team", "a"))
			Expect(target.Annotations).To(HaveKeyWithValue("example.com/tier", "1"))
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.SecretAnnotationManagedAnnotations, "example.com/team,example.com/tier"))

			// Editing the rule reconciles the managed subset: the dropped key is
			// removed, the changed key updated, tracking annotations intact.
			// (Re-fetch and retry: the controller's status writes race this update.)
			Eventually(func(g Gomega) {
				fresh := &secretsv1beta1.SecretCopier{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(copier), fresh)).To(Succeed())
				fresh.Spec.Rules[0].TargetSecret.Annotations = map[string]string{"example.com/team": "b"}
				g.Expect(k8sClient.Update(ctx, fresh)).To(Succeed())
			}, secretCreatedTimeout).Should(Succeed())

			Eventually(func(g Gomega) {
				updated := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{
					Namespace: "annot-tgt",
					Name:      defaultTargetSecretName,
				}, updated)).To(Succeed())
				g.Expect(updated.Annotations).To(HaveKeyWithValue("example.com/team", "b"))
				g.Expect(updated.Annotations).ToNot(HaveKey("example.com/tier"))
				g.Expect(updated.Annotations).To(HaveKeyWithValue(copyengine.SecretAnnotationManagedBy, "secretcopier/annot-copier"))
			}, secretCreatedTimeout).Should(Succeed())
		})

		It("rejects annotation keys under the operator-owned prefix at admission", func() {
			copier := &secretsv1beta1.SecretCopier{
				ObjectMeta: metav1.ObjectMeta{Name: "annot-reserved"},
				Spec: secretsv1beta1.SecretCopierSpec{Rules: []secretsv1beta1.SecretCopierRule{
					copyRule(ruleOptions{
						SourceNamespace:   "annot-src",
						SourceName:        defaultSourceSecretName,
						TargetName:        defaultTargetSecretName,
						TargetAnnotations: map[string]string{"secrets.advok8s.io/resource": "spoof"},
						MatchNames:        []string{"annot-tgt"},
					}),
				}},
			}
			err := k8sClient.Create(ctx, copier)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("secrets.advok8s.io/ prefix"))
		})
	})

	Context("when only the source secret's labels change", func() {
		It("propagates the label change to the target", func() {
			createNamespace("relabel-src")
			createNamespace("relabel-tgt")
			source := createOpaqueSecret("relabel-src", defaultSourceSecretName,
				map[string]string{"key1": "value1"}, map[string]string{"a": "1"})
			createSecretCopier("relabel-copier",
				nameSelectorRule("relabel-src", defaultSourceSecretName, defaultTargetSecretName, "relabel-tgt"))

			// The initial copy carries the source label.
			target := eventuallyGetSecret("relabel-tgt", defaultTargetSecretName)
			Expect(target.Labels).To(Equal(map[string]string{"a": "1"}))

			// Change ONLY the labels on the source (data unchanged).
			source.Labels = map[string]string{"a": "1", "b": "2"}
			Expect(k8sClient.Update(ctx, source)).To(Succeed())

			// The target's labels should be re-synced to match.
			Eventually(func(g Gomega) {
				updated := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{
					Namespace: "relabel-tgt",
					Name:      defaultTargetSecretName,
				}, updated)).To(Succeed())
				g.Expect(updated.Labels).To(Equal(map[string]string{"a": "1", "b": "2"}))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})
})
