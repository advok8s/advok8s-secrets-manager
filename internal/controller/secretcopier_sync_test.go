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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These specs exercise keeping a target secret in sync with its source after
// the initial copy.
var _ = Describe("SecretCopier keeping a target secret in sync", func() {
	Context("when the source secret's data and labels are updated", func() {
		It("propagates the changes to the target secret", func() {
			createNamespace("source-namespace-5")
			createNamespace("target-namespace-5")
			createSecretCopier("secret-copier-5",
				nameSelectorRule("source-namespace-5", defaultSourceSecretName, defaultTargetSecretName, "target-namespace-5"))

			sourceSecret := createOpaqueSecret(
				"source-namespace-5", defaultSourceSecretName,
				map[string]string{"data-key1": "data-value1"},
				map[string]string{"label-key1": "label-value1"},
			)

			// The initial copy should carry the source secret's data and labels.
			targetSecret := eventuallyGetSecret("target-namespace-5", defaultTargetSecretName)
			Expect(targetSecret.Data).To(Equal(sourceSecret.Data))
			Expect(targetSecret.Labels).To(Equal(sourceSecret.Labels))

			// Update the source secret's data and labels.
			sourceSecret.Data = map[string][]byte{}
			sourceSecret.StringData = map[string]string{
				"data-key1": "data-value1",
				"data-key2": "data-value2",
			}
			sourceSecret.Labels = map[string]string{
				"label-key1": "label-value1",
				"label-key2": "label-value2",
			}
			Expect(k8sClient.Update(ctx, sourceSecret)).To(Succeed())

			// Re-read the source secret so its Data reflects the update.
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Namespace: "source-namespace-5",
					Name:      defaultSourceSecretName,
				}, sourceSecret)
			}).Should(Succeed())

			// The controller should re-sync the target secret with the new
			// data and labels. The polled Gomega (g) retries the comparisons
			// until the controller has processed the source update.
			Eventually(func(g Gomega) {
				updated := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{
					Namespace: "target-namespace-5",
					Name:      defaultTargetSecretName,
				}, updated)).To(Succeed())
				g.Expect(updated.Data).To(Equal(sourceSecret.Data))
				g.Expect(updated.Labels).To(Equal(sourceSecret.Labels))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})

	Context("when a secret with the target name already exists but is not managed by the copier", func() {
		It("does not overwrite the unmanaged secret", func() {
			createNamespace("guard-src")
			createNamespace("guard-tgt")
			createOpaqueSecret("guard-src", defaultSourceSecretName, map[string]string{"src": "data"}, nil)
			// A pre-existing, unmanaged secret occupying the target name.
			createOpaqueSecret("guard-tgt", defaultTargetSecretName, map[string]string{"pre": "existing"}, nil)

			createSecretCopier("guard-copier",
				nameSelectorRule("guard-src", defaultSourceSecretName, defaultTargetSecretName, "guard-tgt"))

			// The unmanaged secret must be left untouched: its data is unchanged
			// and it never gains the copier's tracking annotation.
			Consistently(func(g Gomega) {
				existing := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{
					Namespace: "guard-tgt",
					Name:      defaultTargetSecretName,
				}, existing)).To(Succeed())
				g.Expect(existing.Data).To(HaveKeyWithValue("pre", []byte("existing")))
				g.Expect(existing.Annotations).NotTo(HaveKey(annotationSecretCopier))
			}, 2*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	})

	Context("when the source secret does not exist", func() {
		It("does not create a target secret and does not error", func() {
			createNamespace("missing-tgt")
			createSecretCopier("missing-copier",
				nameSelectorRule("missing-src-ns", "missing-secret", defaultTargetSecretName, "missing-tgt"))

			consistentlySecretAbsent("missing-tgt", defaultTargetSecretName)
		})
	})
})
