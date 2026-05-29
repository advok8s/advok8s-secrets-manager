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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// saHasSecret / saHasImagePullSecret check whether a reference is present.
func saHasSecret(name string) func(*corev1.ServiceAccount) bool {
	return func(sa *corev1.ServiceAccount) bool {
		for _, ref := range sa.Secrets {
			if ref.Name == name {
				return true
			}
		}
		return false
	}
}

func saHasImagePullSecret(name string) func(*corev1.ServiceAccount) bool {
	return func(sa *corev1.ServiceAccount) bool {
		for _, ref := range sa.ImagePullSecrets {
			if ref.Name == name {
				return true
			}
		}
		return false
	}
}

// A SecretInjector injects references to matching secrets into matching service
// accounts: image pull secrets into imagePullSecrets, others into secrets.
var _ = Describe("SecretInjector injecting secret references", func() {
	Context("for an opaque secret and a named service account", func() {
		It("injects the reference into the service account's secrets", func() {
			createNamespace("inj-1")
			createOpaqueSecret("inj-1", "app-token", map[string]string{"k": "v"}, nil)
			createServiceAccount("inj-1", "builder", nil)

			createSecretInjector("inj-copier-1",
				injectorRule([]string{"app-token"}, []string{"builder"}, []string{"inj-1"}))

			sa := eventuallyServiceAccountHas("inj-1", "builder", saHasSecret("app-token"))
			Expect(saHasImagePullSecret("app-token")(sa)).To(BeFalse())
		})
	})

	Context("for a dockerconfigjson secret", func() {
		It("injects the reference into the service account's imagePullSecrets", func() {
			createNamespace("inj-2")
			pullSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "regcred", Namespace: "inj-2"},
				Type:       corev1.SecretTypeDockerConfigJson,
				StringData: map[string]string{".dockerconfigjson": "{}"},
			}
			Expect(k8sClient.Create(ctx, pullSecret)).To(Succeed())
			createServiceAccount("inj-2", "builder", nil)

			createSecretInjector("inj-copier-2",
				injectorRule([]string{"regcred"}, []string{"builder"}, []string{"inj-2"}))

			eventuallyServiceAccountHas("inj-2", "builder", saHasImagePullSecret("regcred"))
		})
	})

	Context("with no service account selector", func() {
		It("injects into every service account in the namespace", func() {
			createNamespace("inj-3")
			createOpaqueSecret("inj-3", "shared", map[string]string{"k": "v"}, nil)
			createServiceAccount("inj-3", "sa-a", nil)
			createServiceAccount("inj-3", "sa-b", nil)

			createSecretInjector("inj-copier-3",
				injectorRule([]string{"shared"}, nil, []string{"inj-3"}))

			eventuallyServiceAccountHas("inj-3", "sa-a", saHasSecret("shared"))
			eventuallyServiceAccountHas("inj-3", "sa-b", saHasSecret("shared"))
		})
	})

	Context("when the reference is already present", func() {
		It("does not add a duplicate", func() {
			createNamespace("inj-4")
			createOpaqueSecret("inj-4", "once", map[string]string{"k": "v"}, nil)
			createServiceAccount("inj-4", "builder", nil)

			createSecretInjector("inj-copier-4",
				injectorRule([]string{"once"}, []string{"builder"}, []string{"inj-4"}))

			eventuallyServiceAccountHas("inj-4", "builder", saHasSecret("once"))

			// The reference should remain present exactly once and not accumulate.
			Consistently(func(g Gomega) {
				sa := &corev1.ServiceAccount{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "inj-4", Name: "builder"}, sa)).To(Succeed())
				count := 0
				for _, ref := range sa.Secrets {
					if ref.Name == "once" {
						count++
					}
				}
				g.Expect(count).To(Equal(1))
			}, 2*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	})

	Context("when the secret does not match the source selector", func() {
		It("does not inject anything", func() {
			createNamespace("inj-5")
			createOpaqueSecret("inj-5", "other", map[string]string{"k": "v"}, nil)
			createServiceAccount("inj-5", "builder", nil)

			createSecretInjector("inj-copier-5",
				injectorRule([]string{"wanted"}, []string{"builder"}, []string{"inj-5"}))

			Consistently(func(g Gomega) {
				sa := &corev1.ServiceAccount{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "inj-5", Name: "builder"}, sa)).To(Succeed())
				g.Expect(sa.Secrets).To(BeEmpty())
			}, 2*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	})
})
