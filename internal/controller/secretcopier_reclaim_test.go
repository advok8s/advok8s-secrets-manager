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

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// The reclaim policy controls whether copies are garbage-collected with the
// SecretCopier. envtest runs only the API server + etcd (no garbage collector),
// so we assert the owner reference is set/absent; the actual cascade-delete is
// left to the e2e suite.
var _ = Describe("SecretCopier reclaim policy", func() {
	sourceData := map[string]string{"key1": "value1"}

	Context("when the reclaim policy is Delete", func() {
		It("sets a controller owner reference on the copied secret", func() {
			createNamespace("reclaim-src-delete")
			createNamespace("reclaim-tgt-delete")
			createOpaqueSecret("reclaim-src-delete", defaultSourceSecretName, sourceData, nil)
			copier := createSecretCopier("reclaim-copier-delete",
				nameSelectorRuleWithReclaim("reclaim-src-delete", defaultSourceSecretName,
					defaultTargetSecretName, secretsv1beta1.ReclaimDelete, "reclaim-tgt-delete"))

			target := eventuallyGetSecret("reclaim-tgt-delete", defaultTargetSecretName)

			Expect(target.OwnerReferences).To(HaveLen(1))
			owner := target.OwnerReferences[0]
			Expect(owner.Name).To(Equal(copier.Name))
			Expect(owner.UID).To(Equal(copier.UID))
			Expect(owner.Controller).To(HaveValue(BeTrue()))
			Expect(owner.BlockOwnerDeletion).To(HaveValue(BeTrue()))
			// apiVersion and kind must be populated for the garbage collector to
			// resolve the owner; the API server also requires them to be non-empty.
			Expect(owner.APIVersion).To(Equal("secrets.advok8s.io/v1beta1"))
			Expect(owner.Kind).To(Equal("SecretCopier"))
		})
	})

	Context("when the reclaim policy is Retain", func() {
		It("does not set an owner reference on the copied secret", func() {
			createNamespace("reclaim-src-retain")
			createNamespace("reclaim-tgt-retain")
			createOpaqueSecret("reclaim-src-retain", defaultSourceSecretName, sourceData, nil)
			createSecretCopier("reclaim-copier-retain",
				nameSelectorRuleWithReclaim("reclaim-src-retain", defaultSourceSecretName,
					defaultTargetSecretName, secretsv1beta1.ReclaimRetain, "reclaim-tgt-retain"))

			target := eventuallyGetSecret("reclaim-tgt-retain", defaultTargetSecretName)

			Expect(target.OwnerReferences).To(BeEmpty())
		})
	})
})
