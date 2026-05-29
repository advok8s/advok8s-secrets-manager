/*
Copyright 2024 Graham Dumpleton.

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
)

// These specs exercise the core copy behaviour: a source secret is copied
// (and renamed) into a target namespace selected by name. Each scenario varies
// the order in which the source namespace, source secret, target namespace and
// SecretCopier are created. In every ordering the controller must converge and
// create the target secret.
var _ = Describe("SecretCopier copying a secret to a target namespace", func() {
	sourceData := map[string]string{"key1": "value1"}

	Context("when the SecretCopier is created before the source secret exists", func() {
		It("copies the secret to the target namespace", func() {
			createNamespace("source-namespace-1")
			createNamespace("target-namespace-1")
			createSecretCopier("secret-copier-1",
				nameSelectorRule("source-namespace-1", defaultSourceSecretName, defaultTargetSecretName, "target-namespace-1"))

			createOpaqueSecret("source-namespace-1", defaultSourceSecretName, sourceData, nil)

			eventuallyGetSecret("target-namespace-1", defaultTargetSecretName)
		})
	})

	Context("when the source secret exists before the SecretCopier is created", func() {
		It("copies the secret to the target namespace", func() {
			createNamespace("source-namespace-2")
			createNamespace("target-namespace-2")
			createOpaqueSecret("source-namespace-2", defaultSourceSecretName, sourceData, nil)

			createSecretCopier("secret-copier-2",
				nameSelectorRule("source-namespace-2", defaultSourceSecretName, defaultTargetSecretName, "target-namespace-2"))

			eventuallyGetSecret("target-namespace-2", defaultTargetSecretName)
		})
	})

	Context("when the target namespace is created after the SecretCopier", func() {
		It("copies the secret once the target namespace appears", func() {
			createNamespace("source-namespace-3")
			createOpaqueSecret("source-namespace-3", defaultSourceSecretName, sourceData, nil)
			createSecretCopier("secret-copier-3",
				nameSelectorRule("source-namespace-3", defaultSourceSecretName, defaultTargetSecretName, "target-namespace-3"))

			createNamespace("target-namespace-3")

			eventuallyGetSecret("target-namespace-3", defaultTargetSecretName)
		})
	})

	Context("when the source secret and target namespace both exist before the SecretCopier", func() {
		It("copies the secret to the target namespace", func() {
			createNamespace("source-namespace-4")
			createOpaqueSecret("source-namespace-4", defaultSourceSecretName, sourceData, nil)
			createNamespace("target-namespace-4")

			createSecretCopier("secret-copier-4",
				nameSelectorRule("source-namespace-4", defaultSourceSecretName, defaultTargetSecretName, "target-namespace-4"))

			eventuallyGetSecret("target-namespace-4", defaultTargetSecretName)
		})
	})
})
