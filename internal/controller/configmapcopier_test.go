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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
	"github.com/advok8s/advok8s-secrets-manager/internal/copyengine"
)

// ---- helpers ---------------------------------------------------------------

// createConfigMap creates a ConfigMap with the given data, binaryData and
// labels (any may be nil) and waits until it can be read back.
func createConfigMap(namespace, name string, data map[string]string, binaryData map[string][]byte, labels map[string]string) *corev1.ConfigMap {
	GinkgoHelper()

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Data:       data,
		BinaryData: binaryData,
	}
	Expect(k8sClient.Create(ctx, configMap)).To(Succeed())

	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, configMap)
	}).Should(Succeed())

	return configMap
}

// configMapCopyRule builds a ConfigMapCopierRule selecting target namespaces by
// exact name.
func configMapCopyRule(sourceNamespace, sourceName, targetName string, reclaim secretsv1beta1.ReclaimPolicy, targetNamespaces ...string) secretsv1beta1.ConfigMapCopierRule {
	if reclaim == "" {
		reclaim = secretsv1beta1.ReclaimDelete
	}
	return secretsv1beta1.ConfigMapCopierRule{
		SourceConfigMap: secretsv1beta1.SourceConfigMap{
			Namespace: sourceNamespace,
			Name:      sourceName,
		},
		TargetNamespaces: nameTargetNamespaces(targetNamespaces...),
		TargetConfigMap: secretsv1beta1.TargetConfigMap{
			Name: targetName,
		},
		ReclaimPolicy: reclaim,
	}
}

// createConfigMapCopier creates a ConfigMapCopier with the given rules and
// waits until it can be read back.
func createConfigMapCopier(name string, rules ...secretsv1beta1.ConfigMapCopierRule) *secretsv1beta1.ConfigMapCopier {
	GinkgoHelper()

	copier := &secretsv1beta1.ConfigMapCopier{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       secretsv1beta1.ConfigMapCopierSpec{Rules: rules},
	}
	Expect(k8sClient.Create(ctx, copier)).To(Succeed())

	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Name: name}, copier)
	}).Should(Succeed())

	return copier
}

// eventuallyGetConfigMap waits for the named configmap to exist and returns it.
func eventuallyGetConfigMap(namespace, name string) *corev1.ConfigMap {
	GinkgoHelper()

	configMap := &corev1.ConfigMap{}
	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, configMap)
	}, secretCreatedTimeout).Should(Succeed())

	return configMap
}

// ---- specs -----------------------------------------------------------------

var _ = Describe("ConfigMapCopier", func() {
	sourceData := map[string]string{"settings": "value"}
	sourceBinary := map[string][]byte{"logo": {0xff, 0x00, 0x01}}

	Context("with a basic rule", func() {
		It("copies data, binaryData and labels into the target namespace", func() {
			createNamespace("cmc-src-1")
			createNamespace("cmc-tgt-1")
			createConfigMap("cmc-src-1", "app-config", sourceData, sourceBinary, map[string]string{"app": "demo"})

			createConfigMapCopier("cmc-copier-1",
				configMapCopyRule("cmc-src-1", "app-config", "", "", "cmc-tgt-1"))

			// The target name defaults to the source name.
			target := eventuallyGetConfigMap("cmc-tgt-1", "app-config")
			Expect(target.Data).To(HaveKeyWithValue("settings", "value"))
			Expect(target.BinaryData).To(HaveKeyWithValue("logo", []byte{0xff, 0x00, 0x01}))
			Expect(target.Labels).To(HaveKeyWithValue("app", "demo"))
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.AnnotationManagedBy, "configmapcopier/cmc-copier-1"))
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.AnnotationSourceResource, "cmc-src-1/app-config"))

			// Delete reclaim: the copier owns the copy.
			Expect(target.OwnerReferences).To(HaveLen(1))
			Expect(target.OwnerReferences[0].Kind).To(Equal("ConfigMapCopier"))
		})
	})

	Context("when the source changes", func() {
		It("re-syncs both maps on the target, including key migration", func() {
			createNamespace("cmc-src-2")
			createNamespace("cmc-tgt-2")
			source := createConfigMap("cmc-src-2", "app-config", sourceData, sourceBinary, nil)

			createConfigMapCopier("cmc-copier-2",
				configMapCopyRule("cmc-src-2", "app-config", "", "", "cmc-tgt-2"))

			eventuallyGetConfigMap("cmc-tgt-2", "app-config")

			// Move the binary key into data and change a value.
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmc-src-2", Name: "app-config"}, source)).To(Succeed())
				source.Data = map[string]string{"settings": "updated", "logo": "now-text"}
				source.BinaryData = nil
				g.Expect(k8sClient.Update(ctx, source)).To(Succeed())
			}).Should(Succeed())

			Eventually(func(g Gomega) {
				target := &corev1.ConfigMap{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmc-tgt-2", Name: "app-config"}, target)).To(Succeed())
				g.Expect(target.Data).To(HaveKeyWithValue("settings", "updated"))
				g.Expect(target.Data).To(HaveKeyWithValue("logo", "now-text"))
				g.Expect(target.BinaryData).To(BeEmpty())
			}, secretCreatedTimeout).Should(Succeed())
		})
	})

	Context("with a renamed target and extra labels", func() {
		It("creates the copy under the target name with overlaid labels", func() {
			createNamespace("cmc-src-3")
			createNamespace("cmc-tgt-3")
			createConfigMap("cmc-src-3", "app-config", sourceData, nil, map[string]string{"app": "demo"})

			rule := configMapCopyRule("cmc-src-3", "app-config", "renamed-config", "", "cmc-tgt-3")
			rule.TargetConfigMap.Labels = map[string]string{"copied": "true"}
			createConfigMapCopier("cmc-copier-3", rule)

			target := eventuallyGetConfigMap("cmc-tgt-3", "renamed-config")
			Expect(target.Labels).To(HaveKeyWithValue("app", "demo"))
			Expect(target.Labels).To(HaveKeyWithValue("copied", "true"))
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.AnnotationManagedLabels, "app,copied"))
		})
	})

	Context("with target annotations on the rule", func() {
		It("applies them as a managed subset and reconciles rule edits", func() {
			createNamespace("cmc-src-annot")
			createNamespace("cmc-tgt-annot")
			createConfigMap("cmc-src-annot", "app-config", sourceData, nil, nil)

			rule := configMapCopyRule("cmc-src-annot", "app-config", "", "", "cmc-tgt-annot")
			rule.TargetConfigMap.Annotations = map[string]string{"example.com/origin": "platform", "example.com/tier": "1"}
			copier := createConfigMapCopier("cmc-copier-annot", rule)

			target := eventuallyGetConfigMap("cmc-tgt-annot", "app-config")
			Expect(target.Annotations).To(HaveKeyWithValue("example.com/origin", "platform"))
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.AnnotationManagedAnnotations, "example.com/origin,example.com/tier"))

			// Editing the rule reconciles the managed subset on the copy.
			// (Re-fetch and retry: the controller's status writes race this update.)
			Eventually(func(g Gomega) {
				fresh := &secretsv1beta1.ConfigMapCopier{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(copier), fresh)).To(Succeed())
				fresh.Spec.Rules[0].TargetConfigMap.Annotations = map[string]string{"example.com/origin": "updated"}
				g.Expect(k8sClient.Update(ctx, fresh)).To(Succeed())
			}, secretCreatedTimeout).Should(Succeed())

			Eventually(func(g Gomega) {
				updated := &corev1.ConfigMap{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmc-tgt-annot", Name: "app-config"}, updated)).To(Succeed())
				g.Expect(updated.Annotations).To(HaveKeyWithValue("example.com/origin", "updated"))
				g.Expect(updated.Annotations).ToNot(HaveKey("example.com/tier"))
			}, secretCreatedTimeout).Should(Succeed())
		})

		It("rejects annotation keys under the operator-owned prefix at admission", func() {
			rule := configMapCopyRule("cmc-src-annot", "app-config", "", "", "cmc-tgt-annot")
			rule.TargetConfigMap.Annotations = map[string]string{"secrets.advok8s.io/copier-rule": "spoof"}
			copier := &secretsv1beta1.ConfigMapCopier{
				ObjectMeta: metav1.ObjectMeta{Name: "cmc-annot-reserved"},
				Spec:       secretsv1beta1.ConfigMapCopierSpec{Rules: []secretsv1beta1.ConfigMapCopierRule{rule}},
			}
			err := k8sClient.Create(ctx, copier)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("secrets.advok8s.io/ prefix"))
		})
	})

	Context("with the Retain reclaim policy", func() {
		It("creates the copy without an owner reference", func() {
			createNamespace("cmc-src-4")
			createNamespace("cmc-tgt-4")
			createConfigMap("cmc-src-4", "app-config", sourceData, nil, nil)

			createConfigMapCopier("cmc-copier-4",
				configMapCopyRule("cmc-src-4", "app-config", "", secretsv1beta1.ReclaimRetain, "cmc-tgt-4"))

			target := eventuallyGetConfigMap("cmc-tgt-4", "app-config")
			Expect(target.OwnerReferences).To(BeEmpty())
		})
	})

	Context("when a foreign configmap owns the target name", func() {
		It("reports a conflict and leaves it untouched, then claims the name when it is deleted", func() {
			createNamespace("cmc-src-5")
			createNamespace("cmc-tgt-5")
			createConfigMap("cmc-src-5", "app-config", sourceData, nil, nil)
			foreign := createConfigMap("cmc-tgt-5", "app-config", map[string]string{"theirs": "data"}, nil, nil)

			createConfigMapCopier("cmc-copier-5",
				configMapCopyRule("cmc-src-5", "app-config", "", "", "cmc-tgt-5"))

			Eventually(func(g Gomega) {
				copier := &secretsv1beta1.ConfigMapCopier{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "cmc-copier-5"}, copier)).To(Succeed())
				g.Expect(copier.Status.Summary.Conflicts).To(Equal(1))
				// A conflict is a misconfiguration signal, not a failure.
				g.Expect(meta.IsStatusConditionTrue(copier.Status.Conditions, secretsv1beta1.ConditionReady)).To(BeTrue())
			}, secretCreatedTimeout).Should(Succeed())

			Consistently(func(g Gomega) {
				existing := &corev1.ConfigMap{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmc-tgt-5", Name: "app-config"}, existing)).To(Succeed())
				g.Expect(existing.Data).To(HaveKeyWithValue("theirs", "data"))
				g.Expect(existing.Annotations).NotTo(HaveKey(copyengine.AnnotationManagedBy))
			}, 2*time.Second, 250*time.Millisecond).Should(Succeed())

			// Conflict clearance is event-driven: deleting the foreign configmap
			// triggers the copy via the watch.
			Expect(k8sClient.Delete(ctx, foreign)).To(Succeed())

			Eventually(func(g Gomega) {
				claimed := &corev1.ConfigMap{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmc-tgt-5", Name: "app-config"}, claimed)).To(Succeed())
				g.Expect(claimed.Data).To(HaveKeyWithValue("settings", "value"))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})

	Context("when the target configmap is deleted", func() {
		It("recreates it from the deletion event", func() {
			createNamespace("cmc-src-6")
			createNamespace("cmc-tgt-6")
			createConfigMap("cmc-src-6", "app-config", sourceData, nil, nil)
			createConfigMapCopier("cmc-copier-6",
				configMapCopyRule("cmc-src-6", "app-config", "", "", "cmc-tgt-6"))

			target := eventuallyGetConfigMap("cmc-tgt-6", "app-config")
			originalUID := target.UID

			Expect(k8sClient.Delete(ctx, target)).To(Succeed())

			Eventually(func(g Gomega) {
				recreated := &corev1.ConfigMap{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmc-tgt-6", Name: "app-config"}, recreated)).To(Succeed())
				g.Expect(recreated.UID).NotTo(Equal(originalUID))
				g.Expect(recreated.Data).To(HaveKeyWithValue("settings", "value"))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})

	Context("when a foreign label is injected onto the target", func() {
		It("leaves it alone and does not churn the target (managed-subset labels)", func() {
			createNamespace("cmc-src-7")
			createNamespace("cmc-tgt-7")
			createConfigMap("cmc-src-7", "app-config", sourceData, nil, map[string]string{"app": "demo"})
			createConfigMapCopier("cmc-copier-7",
				configMapCopyRule("cmc-src-7", "app-config", "", "", "cmc-tgt-7"))

			target := eventuallyGetConfigMap("cmc-tgt-7", "app-config")

			// Simulate a mutating admission webhook stamping a label on the copy.
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmc-tgt-7", Name: "app-config"}, target)).To(Succeed())
				target.Labels["team"] = "x"
				g.Expect(k8sClient.Update(ctx, target)).To(Succeed())
			}).Should(Succeed())
			injectedVersion := target.ResourceVersion

			Consistently(func(g Gomega) {
				current := &corev1.ConfigMap{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmc-tgt-7", Name: "app-config"}, current)).To(Succeed())
				g.Expect(current.ResourceVersion).To(Equal(injectedVersion))
				g.Expect(current.Labels).To(HaveKeyWithValue("team", "x"))
			}, "2s", "250ms").Should(Succeed())
		})
	})

	Context("status reporting", func() {
		It("reports observedGeneration, counts and Ready, and the backstop requeue", func() {
			createNamespace("cmc-src-8")
			createNamespace("cmc-tgt-8")
			createConfigMap("cmc-src-8", "app-config", sourceData, nil, nil)
			createConfigMapCopier("cmc-copier-8",
				configMapCopyRule("cmc-src-8", "app-config", "", "", "cmc-tgt-8"))

			Eventually(func(g Gomega) {
				copier := &secretsv1beta1.ConfigMapCopier{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "cmc-copier-8"}, copier)).To(Succeed())
				g.Expect(copier.Status.ObservedGeneration).To(Equal(copier.Generation))
				g.Expect(copier.Status.Summary.TargetNamespaces).To(Equal(1))
				g.Expect(copier.Status.Summary.ConfigMapsInSync).To(Equal(1))
				g.Expect(copier.Status.Rules).To(HaveLen(1))
				g.Expect(copier.Status.Rules[0].SourceConfigMap).To(Equal("cmc-src-8/app-config"))
				g.Expect(copier.Status.Rules[0].SourceExists).To(BeTrue())
				g.Expect(meta.IsStatusConditionTrue(copier.Status.Conditions, secretsv1beta1.ConditionReady)).To(BeTrue())
			}, secretCreatedTimeout).Should(Succeed())

			reconciler := &ConfigMapCopierReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "cmc-copier-8"}})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(backstopRequeue))
		})

		It("records sourceExists=false when the source is missing", func() {
			createNamespace("cmc-tgt-9")
			createConfigMapCopier("cmc-copier-9",
				configMapCopyRule("cmc-src-9-missing", "app-config", "", "", "cmc-tgt-9"))

			Eventually(func(g Gomega) {
				copier := &secretsv1beta1.ConfigMapCopier{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "cmc-copier-9"}, copier)).To(Succeed())
				g.Expect(copier.Status.Rules).To(HaveLen(1))
				g.Expect(copier.Status.Rules[0].SourceExists).To(BeFalse())
				g.Expect(meta.IsStatusConditionTrue(copier.Status.Conditions, secretsv1beta1.ConditionReady)).To(BeTrue())
			}, secretCreatedTimeout).Should(Succeed())

			Consistently(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmc-tgt-9", Name: "app-config"}, &corev1.ConfigMap{})
				return apierrors.IsNotFound(err)
			}, 2*time.Second, 250*time.Millisecond).Should(BeTrue())
		})
	})
})
