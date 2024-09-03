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
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
	"github.com/advok8s/advok8s-secrets-manager/internal/selectors"
)

var _ = Describe("SecretCopier Controller", func() {
	ctx := context.Background()

	BeforeEach(func() {
		// Setup steps that needs to be executed before each test.
	})

	AfterEach(func() {
		// Teardown steps that needs to be executed after each test.
	})

	Context("Copy secret to target namespace", func() {
		It("should copy secret to target namespace", func() {
			sourceNamespaceName := "source-namespace-1"
			sourceSecretName := "source-secret-1"
			targetNamespaceName := "target-namespace-1"
			targetSecretName := "target-secret-1"

			// Create source namespace.

			sourceNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: sourceNamespaceName,
				},
			}
			Expect(k8sClient.Create(ctx, sourceNamespace)).To(Succeed())

			// Verify that the source namespace was created.

			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{
					Name: sourceNamespaceName,
				}, sourceNamespace)
				return err == nil
			}).Should(BeTrue())

			// Create target namespace.

			targetNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: targetNamespaceName,
				},
			}
			Expect(k8sClient.Create(ctx, targetNamespace)).To(Succeed())

			// Verify that the target namespace was created.

			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{
					Name: targetNamespaceName,
				}, targetNamespace)
				return err == nil
			}).Should(BeTrue())

			// Create the custom resource for the Kind SecretCopier.

			secretCopier := &secretsv1beta1.SecretCopier{
				ObjectMeta: metav1.ObjectMeta{
					Name: "secret-copier-1",
				},
				Spec: secretsv1beta1.SecretCopierSpec{
					Rules: []secretsv1beta1.SecretCopierRule{
						{
							SourceSecret: secretsv1beta1.SourceSecret{
								Namespace: sourceNamespaceName,
								Name:      sourceSecretName,
							},
							TargetNamespaces: selectors.TargetNamespaces{
								NameSelector: selectors.NameSelector{
									MatchNames: []string{targetNamespaceName},
								},
								OwnerSelector: selectors.OwnerSelector{
									MatchOwners: []selectors.OwnerReference{},
								},
								UIDSelector: selectors.UIDSelector{
									MatchUids: []string{},
								},
								LabelSelector: selectors.LabelSelector{
									MatchLabels: map[string]string{},
								},
							},
							TargetSecret: secretsv1beta1.TargetSecret{
								Name: targetSecretName,
							},
							ReclaimPolicy: secretsv1beta1.ReclaimDelete,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, secretCopier)).To(Succeed())

			// Verify that the secret copier was created.

			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{
					Namespace: secretCopier.Namespace,
					Name:      secretCopier.Name,
				}, secretCopier)
				return err == nil
			}).Should(BeTrue())

			// Create source secret in source namespace.

			sourceSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      sourceSecretName,
					Namespace: sourceNamespaceName,
				},
				Type: corev1.SecretTypeOpaque,
				StringData: map[string]string{
					"key1": "value1",
				},
			}
			Expect(k8sClient.Create(ctx, sourceSecret)).To(Succeed())

			// Verify that the source secret was created.

			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{
					Namespace: sourceNamespaceName,
					Name:      sourceSecretName,
				}, sourceSecret)
				return err == nil
			}).Should(BeTrue())

			// Wait for the target secret to be created in the target namespace.

			Eventually(func() bool {
				targetSecret := &corev1.Secret{}
				err := k8sClient.Get(ctx, client.ObjectKey{
					Namespace: targetNamespaceName,
					Name:      targetSecretName,
				}, targetSecret)
				return err == nil
			}, 5*time.Second).Should(BeTrue())
		})
	})
})
