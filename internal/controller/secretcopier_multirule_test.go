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
)

// Breadth: more than one rule per SecretCopier, and more than one target
// namespace per rule.
var _ = Describe("SecretCopier with multiple rules and namespaces", func() {
	Context("when one SecretCopier has multiple rules", func() {
		It("copies each source secret according to its own rule", func() {
			createNamespace("multi-src")
			createNamespace("multi-tgt-a")
			createNamespace("multi-tgt-b")
			createOpaqueSecret("multi-src", "secret-a", map[string]string{"a": "1"}, nil)
			createOpaqueSecret("multi-src", "secret-b", map[string]string{"b": "2"}, nil)

			createSecretCopier("multi-rule-copier",
				nameSelectorRule("multi-src", "secret-a", "copied-a", "multi-tgt-a"),
				nameSelectorRule("multi-src", "secret-b", "copied-b", "multi-tgt-b"),
			)

			eventuallyGetSecret("multi-tgt-a", "copied-a")
			eventuallyGetSecret("multi-tgt-b", "copied-b")
		})
	})

	Context("when one rule targets multiple namespaces", func() {
		It("copies the secret to every matching namespace", func() {
			createNamespace("fanout-src")
			createNamespace("fanout-tgt-1")
			createNamespace("fanout-tgt-2")
			createOpaqueSecret("fanout-src", defaultSourceSecretName, map[string]string{"k": "v"}, nil)

			createSecretCopier("fanout-copier",
				nameSelectorRule("fanout-src", defaultSourceSecretName, defaultTargetSecretName,
					"fanout-tgt-1", "fanout-tgt-2"))

			eventuallyGetSecret("fanout-tgt-1", defaultTargetSecretName)
			eventuallyGetSecret("fanout-tgt-2", defaultTargetSecretName)
		})
	})
})
