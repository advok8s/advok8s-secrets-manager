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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// These specs exercise the observed-state the controller writes back to the
// SecretCopier .status: the observedGeneration, the Ready/Degraded conditions,
// and the bounded summary/per-rule counts (in sync, conflicts, failures).
var _ = Describe("SecretCopier status", func() {
	sourceData := map[string]string{"key1": "value1"}

	// eventuallyCopierStatus reconciles-and-reads until assert passes against
	// the freshly fetched SecretCopier, bounded by secretCreatedTimeout.
	eventuallyCopierStatus := func(name string, assert func(g Gomega, copier *secretsv1beta1.SecretCopier)) {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			copier := &secretsv1beta1.SecretCopier{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, copier)).To(Succeed())
			assert(g, copier)
		}, secretCreatedTimeout).Should(Succeed())
	}

	Context("after a clean sync", func() {
		It("reports Ready, observedGeneration, and in-sync counts", func() {
			createNamespace("status-src-1")
			createNamespace("status-tgt-1")
			createOpaqueSecret("status-src-1", defaultSourceSecretName, sourceData, nil)
			createSecretCopier("status-copier-1",
				nameSelectorRule("status-src-1", defaultSourceSecretName, defaultTargetSecretName, "status-tgt-1"))

			eventuallyGetSecret("status-tgt-1", defaultTargetSecretName)

			eventuallyCopierStatus("status-copier-1", func(g Gomega, copier *secretsv1beta1.SecretCopier) {
				g.Expect(copier.Status.ObservedGeneration).To(Equal(copier.Generation))
				g.Expect(copier.Status.ObservedGeneration).To(BeNumerically(">", 0))

				g.Expect(copier.Status.Summary.TargetNamespaces).To(Equal(1))
				g.Expect(copier.Status.Summary.SecretsInSync).To(Equal(1))
				g.Expect(copier.Status.Summary.Conflicts).To(BeZero())
				g.Expect(copier.Status.Summary.Failures).To(BeZero())

				g.Expect(copier.Status.Rules).To(HaveLen(1))
				g.Expect(copier.Status.Rules[0].SourceSecret).To(Equal("status-src-1/" + defaultSourceSecretName))
				g.Expect(copier.Status.Rules[0].SourceExists).To(BeTrue())
				g.Expect(copier.Status.Rules[0].TargetNamespaces).To(Equal(1))
				g.Expect(copier.Status.Rules[0].SecretsInSync).To(Equal(1))

				g.Expect(meta.IsStatusConditionTrue(copier.Status.Conditions, secretsv1beta1.ConditionReady)).To(BeTrue())
				g.Expect(meta.IsStatusConditionFalse(copier.Status.Conditions, secretsv1beta1.ConditionDegraded)).To(BeTrue())
			})
		})
	})

	Context("when the source secret is missing", func() {
		It("records SourceExists=false and stays Ready (not a failure)", func() {
			createNamespace("status-tgt-2")
			// Deliberately create neither the source namespace nor its secret.
			createSecretCopier("status-copier-2",
				nameSelectorRule("status-src-2", defaultSourceSecretName, defaultTargetSecretName, "status-tgt-2"))

			eventuallyCopierStatus("status-copier-2", func(g Gomega, copier *secretsv1beta1.SecretCopier) {
				g.Expect(copier.Status.ObservedGeneration).To(Equal(copier.Generation))

				g.Expect(copier.Status.Rules).To(HaveLen(1))
				g.Expect(copier.Status.Rules[0].SourceExists).To(BeFalse())
				g.Expect(copier.Status.Rules[0].TargetNamespaces).To(BeZero())

				g.Expect(copier.Status.Summary.SecretsInSync).To(BeZero())
				g.Expect(copier.Status.Summary.Failures).To(BeZero())

				// A missing source means nothing to copy, not a failure.
				g.Expect(meta.IsStatusConditionTrue(copier.Status.Conditions, secretsv1beta1.ConditionReady)).To(BeTrue())
				g.Expect(meta.IsStatusConditionFalse(copier.Status.Conditions, secretsv1beta1.ConditionDegraded)).To(BeTrue())
			})
		})
	})

	Context("when a foreign secret already owns the target name", func() {
		It("counts a conflict, leaves the secret untouched, and stays Ready", func() {
			createNamespace("status-src-3")
			createNamespace("status-tgt-3")
			createOpaqueSecret("status-src-3", defaultSourceSecretName, sourceData, nil)

			// Pre-create a secret with the target name that the controller did
			// not create (no copier annotations), so it must not be overwritten.
			foreign := createOpaqueSecret("status-tgt-3", defaultTargetSecretName,
				map[string]string{"owner": "someone-else"}, nil)

			createSecretCopier("status-copier-3",
				nameSelectorRule("status-src-3", defaultSourceSecretName, defaultTargetSecretName, "status-tgt-3"))

			eventuallyCopierStatus("status-copier-3", func(g Gomega, copier *secretsv1beta1.SecretCopier) {
				g.Expect(copier.Status.Summary.Conflicts).To(Equal(1))
				g.Expect(copier.Status.Summary.SecretsInSync).To(BeZero())
				g.Expect(copier.Status.Summary.Failures).To(BeZero())

				g.Expect(copier.Status.Rules).To(HaveLen(1))
				g.Expect(copier.Status.Rules[0].Conflicts).To(Equal(1))

				// A conflict is a misconfiguration signal, not a hard failure.
				g.Expect(meta.IsStatusConditionTrue(copier.Status.Conditions, secretsv1beta1.ConditionReady)).To(BeTrue())
			})

			// The foreign secret's data must remain as it was created.
			Consistently(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "status-tgt-3", Name: defaultTargetSecretName}, secret)).To(Succeed())
				g.Expect(secret.Data).To(Equal(foreign.Data))
			}, 2*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	})

	Context("when the spec changes", func() {
		It("advances observedGeneration to match the new generation", func() {
			createNamespace("status-src-4")
			createNamespace("status-tgt-4")
			createOpaqueSecret("status-src-4", defaultSourceSecretName, sourceData, nil)
			createSecretCopier("status-copier-4",
				nameSelectorRule("status-src-4", defaultSourceSecretName, defaultTargetSecretName, "status-tgt-4"))

			eventuallyCopierStatus("status-copier-4", func(g Gomega, copier *secretsv1beta1.SecretCopier) {
				g.Expect(copier.Status.ObservedGeneration).To(Equal(copier.Generation))
			})

			// Mutate the spec so .metadata.generation increments, then confirm
			// the controller catches the status back up.
			Eventually(func(g Gomega) {
				copier := &secretsv1beta1.SecretCopier{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "status-copier-4"}, copier)).To(Succeed())
				copier.Spec.SyncPeriod = &metav1.Duration{Duration: 45 * time.Second}
				g.Expect(k8sClient.Update(ctx, copier)).To(Succeed())
			}).Should(Succeed())

			eventuallyCopierStatus("status-copier-4", func(g Gomega, copier *secretsv1beta1.SecretCopier) {
				g.Expect(copier.Generation).To(BeNumerically(">", 1))
				g.Expect(copier.Status.ObservedGeneration).To(Equal(copier.Generation))
			})
		})
	})
})
