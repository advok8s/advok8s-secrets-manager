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

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
	"github.com/advok8s/advok8s-secrets-manager/internal/copyengine"
)

// When more than one rule targets the same secret name in a namespace, the first
// to create the copy owns it; others must leave it untouched and report a
// conflict. Ownership is tracked by the copier-rule (kind/name) and secret-name
// annotations, so this holds across resource kinds as well as within one kind.
var _ = Describe("Conflicting rules targeting the same secret", func() {
	// consistentlyOwnedBy asserts that for a short window the target secret keeps
	// the given copier-rule annotation and source data, i.e. it was not
	// overwritten by a conflicting rule.
	consistentlyOwnedBy := func(namespace, name, copierRule, dataOwner string) {
		GinkgoHelper()
		Consistently(func(g Gomega) {
			secret := &corev1.Secret{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret)).To(Succeed())
			g.Expect(secret.Annotations).To(HaveKeyWithValue(copyengine.SecretAnnotationManagedBy, copierRule))
			g.Expect(secret.Data).To(HaveKeyWithValue("owner", []byte(dataOwner)))
		}, 2*time.Second, 250*time.Millisecond).Should(Succeed())
	}

	Context("when a SecretExporter targets a name a SecretCopier already owns", func() {
		It("does not overwrite the copy and records a conflict", func() {
			createNamespace("conf-copier-src")
			createNamespace("conf-exp-src")
			createNamespace("conf-tgt")

			// The copier establishes the copy first.
			createOpaqueSecret("conf-copier-src", "shared-cred", map[string]string{"owner": "copier"}, nil)
			createSecretCopier("conf-winner",
				nameSelectorRule("conf-copier-src", "shared-cred", "shared-cred", "conf-tgt"))

			target := eventuallyGetSecret("conf-tgt", "shared-cred")
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.SecretAnnotationManagedBy, "secretcopier/conf-winner"))

			// Now an exporter (with an authorizing importer) targets the same name.
			createOpaqueSecret("conf-exp-src", "shared-cred", map[string]string{"owner": "exporter"}, nil)
			createSecretImporter("conf-tgt", "shared-cred", "shh")
			createSecretExporter("conf-exp-src", "shared-cred",
				exporterRule("", "shh", "conf-tgt"))

			// The copier keeps ownership; the exporter never overwrites it.
			consistentlyOwnedBy("conf-tgt", "shared-cred", "secretcopier/conf-winner", "copier")

			Eventually(func(g Gomega) {
				exporter := &secretsv1beta1.SecretExporter{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "conf-exp-src", Name: "shared-cred"}, exporter)).To(Succeed())
				g.Expect(exporter.Status.Summary.Conflicts).To(BeNumerically(">=", 1))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})

	Context("when two SecretCopiers target the same name", func() {
		It("the first owns the copy and the second records a conflict", func() {
			createNamespace("conf2-src-a")
			createNamespace("conf2-src-b")
			createNamespace("conf2-tgt")

			createOpaqueSecret("conf2-src-a", "dup", map[string]string{"owner": "a"}, nil)
			createSecretCopier("conf2-copier-a",
				nameSelectorRule("conf2-src-a", "dup", "dup", "conf2-tgt"))

			target := eventuallyGetSecret("conf2-tgt", "dup")
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.SecretAnnotationSourceResource, "conf2-src-a/dup"))

			createOpaqueSecret("conf2-src-b", "dup", map[string]string{"owner": "b"}, nil)
			createSecretCopier("conf2-copier-b",
				nameSelectorRule("conf2-src-b", "dup", "dup", "conf2-tgt"))

			consistentlyOwnedBy("conf2-tgt", "dup", "secretcopier/conf2-copier-a", "a")

			Eventually(func(g Gomega) {
				copier := &secretsv1beta1.SecretCopier{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "conf2-copier-b"}, copier)).To(Succeed())
				g.Expect(copier.Status.Summary.Conflicts).To(BeNumerically(">=", 1))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})
})
