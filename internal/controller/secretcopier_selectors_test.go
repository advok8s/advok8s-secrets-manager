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

// Selecting target namespaces by label (rather than by name). The per-selector
// matching logic is unit-tested in pkg/selectors; this checks the selection is
// honoured end-to-end by the reconciler.
var _ = Describe("SecretCopier selecting target namespaces by label", func() {
	It("copies only to namespaces matching the label selector", func() {
		createNamespace("labelsel-src")
		createOpaqueSecret("labelsel-src", defaultSourceSecretName, map[string]string{"key1": "value1"}, nil)

		// Unique label so the empty-name-selector match cannot pick up
		// namespaces created by other specs.
		createNamespaceWithLabels("labelsel-match", map[string]string{"advok8s-copy-test": "yes"})
		createNamespaceWithLabels("labelsel-nomatch", map[string]string{"advok8s-copy-test": "no"})

		createSecretCopier("labelsel-copier", copyRule(ruleOptions{
			SourceNamespace: "labelsel-src",
			SourceName:      defaultSourceSecretName,
			TargetName:      defaultTargetSecretName,
			MatchLabels:     map[string]string{"advok8s-copy-test": "yes"},
		}))

		// The matching namespace receives the copy.
		eventuallyGetSecret("labelsel-match", defaultTargetSecretName)
		// The non-matching namespace does not.
		consistentlySecretAbsent("labelsel-nomatch", defaultTargetSecretName)
	})
})
