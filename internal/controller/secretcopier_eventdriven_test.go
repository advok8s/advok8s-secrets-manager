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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// Convergence is event-driven: watches cover source secrets, target secrets
// (deletion, tampering, conflict clearance) and importers, with a fixed
// internal backstop requeue as a safety net for missed events. These specs
// pin the event-driven behaviours; the timeouts are well under the 5 minute
// backstop, so a passing spec proves the watch fired, not the timer.
var _ = Describe("SecretCopier event-driven convergence", func() {
	sourceData := map[string]string{"key1": "value1"}

	It("returns the fixed backstop requeue from Reconcile", func() {
		createNamespace("ev-backstop-tgt")
		createSecretCopier("ev-backstop",
			nameSelectorRule("ev-backstop-src", defaultSourceSecretName, defaultTargetSecretName, "ev-backstop-tgt"))

		reconciler := &SecretCopierReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "ev-backstop"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(backstopRequeue))
	})

	Context("when the target secret is deleted", func() {
		It("recreates it from the deletion event, without waiting for the backstop", func() {
			createNamespace("ev-del-src")
			createNamespace("ev-del-tgt")
			createOpaqueSecret("ev-del-src", defaultSourceSecretName, sourceData, nil)
			createSecretCopier("ev-del-copier",
				nameSelectorRule("ev-del-src", defaultSourceSecretName, defaultTargetSecretName, "ev-del-tgt"))

			target := eventuallyGetSecret("ev-del-tgt", defaultTargetSecretName)
			originalUID := target.UID

			Expect(k8sClient.Delete(ctx, target)).To(Succeed())

			Eventually(func(g Gomega) {
				recreated := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "ev-del-tgt", Name: defaultTargetSecretName}, recreated)).To(Succeed())
				g.Expect(recreated.UID).NotTo(Equal(originalUID))
				g.Expect(recreated.Data).To(HaveKeyWithValue("key1", []byte("value1")))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})

	Context("when a foreign secret occupying the target name is deleted", func() {
		It("claims the name from the deletion event (conflict clearance)", func() {
			createNamespace("ev-conf-src")
			createNamespace("ev-conf-tgt")
			createOpaqueSecret("ev-conf-src", defaultSourceSecretName, sourceData, nil)
			// A pre-existing, unmanaged secret occupying the target name.
			foreign := createOpaqueSecret("ev-conf-tgt", defaultTargetSecretName, map[string]string{"pre": "existing"}, nil)

			createSecretCopier("ev-conf-copier",
				nameSelectorRule("ev-conf-src", defaultSourceSecretName, defaultTargetSecretName, "ev-conf-tgt"))

			// The conflict is reported, the foreign secret untouched.
			Eventually(func(g Gomega) {
				copier := &secretsv1beta1.SecretCopier{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "ev-conf-copier"}, copier)).To(Succeed())
				g.Expect(copier.Status.Summary.Conflicts).To(Equal(1))
			}, secretCreatedTimeout).Should(Succeed())

			// Deleting the foreign secret must trigger the copy via the watch.
			Expect(k8sClient.Delete(ctx, foreign)).To(Succeed())

			Eventually(func(g Gomega) {
				claimed := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "ev-conf-tgt", Name: defaultTargetSecretName}, claimed)).To(Succeed())
				g.Expect(claimed.Data).To(HaveKeyWithValue("key1", []byte("value1")))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})

	Context("when the authorizing SecretImporter is created after the copier", func() {
		It("copies as soon as the importer appears, without waiting for the backstop", func() {
			createNamespace("ev-imp-src")
			createNamespace("ev-imp-tgt")
			createOpaqueSecret("ev-imp-src", defaultSourceSecretName, sourceData, nil)

			rule := nameSelectorRule("ev-imp-src", defaultSourceSecretName, defaultTargetSecretName, "ev-imp-tgt")
			rule.CopyAuthorization = secretsv1beta1.CopyAuthorization{SharedSecret: "ev-imp-shared"}
			createSecretCopier("ev-imp-copier", rule)

			// Awaiting authorization: no importer yet, so no copy.
			Eventually(func(g Gomega) {
				copier := &secretsv1beta1.SecretCopier{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "ev-imp-copier"}, copier)).To(Succeed())
				g.Expect(copier.Status.Summary.AwaitingAuthorization).To(Equal(1))
			}, secretCreatedTimeout).Should(Succeed())
			consistentlySecretAbsent("ev-imp-tgt", defaultTargetSecretName)

			// Creating the importer must trigger the copy via the importer watch.
			createSecretImporter("ev-imp-tgt", defaultTargetSecretName, "ev-imp-shared")

			target := eventuallyGetSecret("ev-imp-tgt", defaultTargetSecretName)
			Expect(target.Data).To(HaveKeyWithValue("key1", []byte("value1")))
		})
	})

	Context("when the target secret is tampered with", func() {
		It("re-syncs the managed data from the update event", func() {
			createNamespace("ev-tamper-src")
			createNamespace("ev-tamper-tgt")
			createOpaqueSecret("ev-tamper-src", defaultSourceSecretName, sourceData, nil)
			createSecretCopier("ev-tamper-copier",
				nameSelectorRule("ev-tamper-src", defaultSourceSecretName, defaultTargetSecretName, "ev-tamper-tgt"))

			target := eventuallyGetSecret("ev-tamper-tgt", defaultTargetSecretName)

			// Hand-edit the copy's data.
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "ev-tamper-tgt", Name: defaultTargetSecretName}, target)).To(Succeed())
				target.Data = map[string][]byte{"key1": []byte("tampered")}
				g.Expect(k8sClient.Update(ctx, target)).To(Succeed())
			}).Should(Succeed())

			// The tampering update event re-enqueues the copier, which repairs it.
			Eventually(func(g Gomega) {
				repaired := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "ev-tamper-tgt", Name: defaultTargetSecretName}, repaired)).To(Succeed())
				g.Expect(repaired.Data).To(HaveKeyWithValue("key1", []byte("value1")))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})

	Context("when a foreign label is injected onto the target", func() {
		It("leaves it alone and does not churn the target (managed-subset labels)", func() {
			createNamespace("ev-label-src")
			createNamespace("ev-label-tgt")
			createOpaqueSecret("ev-label-src", defaultSourceSecretName, sourceData, map[string]string{"app": "demo"})
			createSecretCopier("ev-label-copier",
				nameSelectorRule("ev-label-src", defaultSourceSecretName, defaultTargetSecretName, "ev-label-tgt"))

			target := eventuallyGetSecret("ev-label-tgt", defaultTargetSecretName)

			// Simulate a mutating admission webhook stamping a label on the copy.
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "ev-label-tgt", Name: defaultTargetSecretName}, target)).To(Succeed())
				target.Labels["team"] = "x"
				g.Expect(k8sClient.Update(ctx, target)).To(Succeed())
			}).Should(Succeed())
			injectedVersion := target.ResourceVersion

			// The label-injection update event re-enqueues the copier; under
			// managed-subset semantics it must conclude there is no drift and
			// leave the target untouched - no churn loop.
			Consistently(func(g Gomega) {
				current := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "ev-label-tgt", Name: defaultTargetSecretName}, current)).To(Succeed())
				g.Expect(current.ResourceVersion).To(Equal(injectedVersion))
				g.Expect(current.Labels).To(HaveKeyWithValue("team", "x"))
			}, "2s", "250ms").Should(Succeed())

			// A genuine source label change still reconciles managed labels,
			// while the foreign label survives.
			source := &corev1.Secret{}
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "ev-label-src", Name: defaultSourceSecretName}, source)).To(Succeed())
				source.Labels = map[string]string{"app": "demo2"}
				g.Expect(k8sClient.Update(ctx, source)).To(Succeed())
			}).Should(Succeed())

			Eventually(func(g Gomega) {
				current := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "ev-label-tgt", Name: defaultTargetSecretName}, current)).To(Succeed())
				g.Expect(current.Labels).To(HaveKeyWithValue("app", "demo2"))
				g.Expect(current.Labels).To(HaveKeyWithValue("team", "x"))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})
})

// The exporter shares the event-driven model; pin its target-deletion path.
var _ = Describe("SecretExporter event-driven convergence", func() {
	It("recreates a deleted exported copy from the deletion event", func() {
		createNamespace("ev-exp-src")
		createNamespace("ev-exp-tgt")

		exporter := createSecretExporter("ev-exp-src", "ev-exp-secret",
			exporterRule("", "ev-exp-shared", "ev-exp-tgt"))
		_ = exporter
		createOpaqueSecret("ev-exp-src", "ev-exp-secret", map[string]string{"key1": "value1"}, nil)
		createSecretImporter("ev-exp-tgt", "ev-exp-secret", "ev-exp-shared")

		target := eventuallyGetSecret("ev-exp-tgt", "ev-exp-secret")
		originalUID := target.UID

		Expect(k8sClient.Delete(ctx, target)).To(Succeed())

		Eventually(func(g Gomega) {
			recreated := &corev1.Secret{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "ev-exp-tgt", Name: "ev-exp-secret"}, recreated)).To(Succeed())
			g.Expect(recreated.UID).NotTo(Equal(originalUID))
			g.Expect(recreated.Data).To(HaveKeyWithValue("key1", []byte("value1")))
		}, secretCreatedTimeout).Should(Succeed())
	})

	It("returns the fixed backstop requeue from Reconcile", func() {
		createNamespace("ev-exp-backstop")
		createSecretExporter("ev-exp-backstop", "ev-exp-bs-secret",
			exporterRule("", "shared", "nowhere"))

		reconciler := &SecretExporterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		result, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: client.ObjectKey{Namespace: "ev-exp-backstop", Name: "ev-exp-bs-secret"},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(backstopRequeue))
	})
})
