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

	"github.com/advok8s/advok8s-secrets-manager/internal/copyengine"
)

// A SecretExporter copies the secret named the same as itself into target
// namespaces, but only where a paired SecretImporter authorizes the copy.
var _ = Describe("SecretExporter exporting a secret", func() {
	sourceData := map[string]string{"key1": "value1"}

	Context("when a matching SecretImporter exists in the target namespace", func() {
		It("copies the secret and makes the importer its owner", func() {
			createNamespace("exp-src-1")
			createNamespace("exp-tgt-1")
			createOpaqueSecret("exp-src-1", "regcred-1", sourceData, nil)

			importer := createSecretImporter("exp-tgt-1", "regcred-1", "shared-1")
			createSecretExporter("exp-src-1", "regcred-1",
				exporterRule("", "shared-1", "exp-tgt-1"))

			target := eventuallyGetSecret("exp-tgt-1", "regcred-1")

			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.SecretAnnotationManagedBy, "secretexporter/regcred-1"))
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.SecretAnnotationSourceResource, "exp-src-1/regcred-1"))

			Expect(target.OwnerReferences).To(HaveLen(1))
			owner := target.OwnerReferences[0]
			Expect(owner.Kind).To(Equal("SecretImporter"))
			Expect(owner.Name).To(Equal("regcred-1"))
			Expect(owner.UID).To(Equal(importer.UID))
			Expect(owner.Controller).To(HaveValue(BeTrue()))
		})
	})

	Context("when no SecretImporter exists in the target namespace", func() {
		It("does not copy the secret", func() {
			createNamespace("exp-src-2")
			createNamespace("exp-tgt-2")
			createOpaqueSecret("exp-src-2", "regcred-2", sourceData, nil)

			createSecretExporter("exp-src-2", "regcred-2",
				exporterRule("", "shared-2", "exp-tgt-2"))

			consistentlySecretAbsent("exp-tgt-2", "regcred-2")
		})
	})

	Context("when the SecretImporter's shared secret does not match", func() {
		It("does not copy the secret", func() {
			createNamespace("exp-src-3")
			createNamespace("exp-tgt-3")
			createOpaqueSecret("exp-src-3", "regcred-3", sourceData, nil)

			createSecretImporter("exp-tgt-3", "regcred-3", "wrong-secret")
			createSecretExporter("exp-src-3", "regcred-3",
				exporterRule("", "shared-3", "exp-tgt-3"))

			consistentlySecretAbsent("exp-tgt-3", "regcred-3")
		})
	})

	Context("when the rule omits a shared secret", func() {
		It("requires the importer to carry the exporter's UID", func() {
			createNamespace("exp-src-4")
			createNamespace("exp-tgt-4")
			createOpaqueSecret("exp-src-4", "regcred-4", sourceData, nil)

			// Create the exporter first so its UID is known, then create an
			// importer carrying that UID as the shared secret.
			exporter := createSecretExporter("exp-src-4", "regcred-4",
				exporterRule("", "", "exp-tgt-4"))
			createSecretImporter("exp-tgt-4", "regcred-4", string(exporter.UID))

			target := eventuallyGetSecret("exp-tgt-4", "regcred-4")
			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.SecretAnnotationManagedBy, "secretexporter/regcred-4"))
		})
	})

	Context("when the importer restricts source namespaces", func() {
		It("does not copy from an excluded source namespace", func() {
			createNamespace("exp-src-5")
			createNamespace("exp-tgt-5")
			createOpaqueSecret("exp-src-5", "regcred-5", sourceData, nil)

			// Importer only accepts copies originating from "other-source".
			createSecretImporter("exp-tgt-5", "regcred-5", "shared-5", "other-source")
			createSecretExporter("exp-src-5", "regcred-5",
				exporterRule("", "shared-5", "exp-tgt-5"))

			consistentlySecretAbsent("exp-tgt-5", "regcred-5")
		})
	})
})
