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
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
	"github.com/advok8s/advok8s-secrets-manager/internal/copyengine"
)

// A SecretCopier rule may also require a SecretImporter to authorize the copy.
// Unlike the exporter path, the SecretCopier remains the owner of the copy.
var _ = Describe("SecretCopier with copyAuthorization", func() {
	sourceData := map[string]string{"key1": "value1"}

	copyAuthRule := func(sourceNamespace, sourceName, sharedSecret string, targetNamespaces ...string) secretsv1beta1.SecretCopierRule {
		rule := copyRule(ruleOptions{
			SourceNamespace: sourceNamespace,
			SourceName:      sourceName,
			MatchNames:      targetNamespaces,
		})
		rule.CopyAuthorization = secretsv1beta1.CopyAuthorization{SharedSecret: sharedSecret}
		return rule
	}

	Context("when a matching SecretImporter exists", func() {
		It("copies the secret, still owned by the SecretCopier", func() {
			createNamespace("ca-src-1")
			createNamespace("ca-tgt-1")
			createOpaqueSecret("ca-src-1", defaultSourceSecretName, sourceData, nil)

			createSecretImporter("ca-tgt-1", defaultSourceSecretName, "ca-shared-1")
			copier := createSecretCopier("ca-copier-1",
				copyAuthRule("ca-src-1", defaultSourceSecretName, "ca-shared-1", "ca-tgt-1"))

			target := eventuallyGetSecret("ca-tgt-1", defaultSourceSecretName)

			Expect(target.Annotations).To(HaveKeyWithValue(copyengine.AnnotationManagedBy, "secretcopier/ca-copier-1"))

			// The copier, not the importer, owns the copy.
			Expect(target.OwnerReferences).To(HaveLen(1))
			Expect(target.OwnerReferences[0].Name).To(Equal(copier.Name))
			Expect(target.OwnerReferences[0].UID).To(Equal(copier.UID))
		})
	})

	Context("when no SecretImporter authorizes the copy", func() {
		It("does not copy the secret and records it as awaiting authorization", func() {
			createNamespace("ca-src-2")
			createNamespace("ca-tgt-2")
			createOpaqueSecret("ca-src-2", defaultSourceSecretName, sourceData, nil)

			createSecretCopier("ca-copier-2",
				copyAuthRule("ca-src-2", defaultSourceSecretName, "ca-shared-2", "ca-tgt-2"))

			consistentlySecretAbsent("ca-tgt-2", defaultSourceSecretName)

			Eventually(func(g Gomega) {
				copier := &secretsv1beta1.SecretCopier{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "ca-copier-2"}, copier)).To(Succeed())
				g.Expect(copier.Status.Summary.AwaitingAuthorization).To(BeNumerically(">=", 1))
			}, secretCreatedTimeout).Should(Succeed())
		})
	})
})
