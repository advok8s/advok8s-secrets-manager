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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
)

// The SecretImporter performs no copying; it reports observable status about
// whether the requested secret has been imported and what is exporting it.
var _ = Describe("SecretImporter status", func() {
	sourceData := map[string]string{"key1": "value1"}

	readyCondition := func(namespace, name string) *metav1.Condition {
		importer := &secretsv1beta1.SecretImporter{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, importer); err != nil {
			return nil
		}
		return meta.FindStatusCondition(importer.Status.Conditions, secretsv1beta1.ConditionReady)
	}

	Context("when nothing exports to it", func() {
		It("reports Ready=False with reason NoMatchingExporter", func() {
			createNamespace("imp-alone")
			createSecretImporter("imp-alone", "lonely", "shared")

			Eventually(func(g Gomega) {
				cond := readyCondition("imp-alone", "lonely")
				g.Expect(cond).NotTo(BeNil())
				g.Expect(cond.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(cond.Reason).To(Equal("NoMatchingExporter"))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})

	Context("when a paired exporter copies the secret in", func() {
		It("reports Imported=True and binds to the exporter", func() {
			createNamespace("imp-src")
			createNamespace("imp-tgt")
			createOpaqueSecret("imp-src", "creds", sourceData, nil)

			createSecretImporter("imp-tgt", "creds", "shared")
			createSecretExporter("imp-src", "creds",
				exporterRule("", "shared", "imp-tgt"))

			// The copy should arrive...
			eventuallyGetSecret("imp-tgt", "creds")

			// ...and the importer status should reflect it.
			Eventually(func(g Gomega) {
				importer := &secretsv1beta1.SecretImporter{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "imp-tgt", Name: "creds"}, importer)).To(Succeed())
				g.Expect(importer.Status.Imported).To(BeTrue())
				g.Expect(importer.Status.TargetSecretName).To(Equal("creds"))
				g.Expect(importer.Status.BoundTo).To(ContainSubstring("secretexporter/creds"))

				cond := meta.FindStatusCondition(importer.Status.Conditions, secretsv1beta1.ConditionReady)
				g.Expect(cond).NotTo(BeNil())
				g.Expect(cond.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(cond.Reason).To(Equal("Imported"))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})
})
