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
	"github.com/advok8s/advok8s-secrets-manager/pkg/selectors"
)

var _ = Describe("SecretCopier Controller", func() {
	ctx := context.Background()

	BeforeEach(func() {
		// Setup steps that needs to be executed before each test.
	})

	AfterEach(func() {
		// Teardown steps that needs to be executed after each test.
	})

	// Test copying a secret to a target namespace where the secret copier is
	// created after creating source and target namespaces, but prior to the
	// source secret being created. The target secret is renamed when being
	// copied to the target namespace.

	Context("Copy secret to target namespace #1", func() {
		It("should copy secret to target namespace", func() {
			sourceNamespaceName := "source-namespace-1"
			sourceSecretName := "source-secret-1"
			targetNamespaceName := "target-namespace-1"
			targetSecretName := "target-secret-1"
			secretCopierName := "secret-copier-1"

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

			// Create the secret copier custom resource.

			secretCopier := &secretsv1beta1.SecretCopier{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretCopierName,
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

	// Test copying a secret to a target namespace where the secret copier is
	// created after creating source and target namespaces, and after the source
	// secret has been created. The target secret is renamed when being copied
	// to the target namespace.

	Context("Copy secret to target namespace #2", func() {
		It("should copy secret to target namespace", func() {
			sourceNamespaceName := "source-namespace-2"
			sourceSecretName := "source-secret-1"
			targetNamespaceName := "target-namespace-2"
			targetSecretName := "target-secret-1"
			secretCopierName := "secret-copier-2"

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

			// Create the secret copier custom resource.

			secretCopier := &secretsv1beta1.SecretCopier{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretCopierName,
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

	// Test copying a secret to a target namespace where the secret copier is
	// created after creating source namespace and source secret, but prior to
	// creating the target namespace. The target secret is renamed when being
	// copied to the target namespace.

	Context("Copy secret to target namespace #3", func() {
		It("should copy secret to target namespace", func() {
			sourceNamespaceName := "source-namespace-3"
			sourceSecretName := "source-secret-1"
			targetNamespaceName := "target-namespace-3"
			targetSecretName := "target-secret-1"
			secretCopierName := "secret-copier-3"

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

			// Create the secret copier custom resource.

			secretCopier := &secretsv1beta1.SecretCopier{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretCopierName,
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

	// Test copying a secret to a target namespace where the secret copier is
	// created after creating source namespace and source secret, and after
	// creating the target namespace. The target secret is renamed when being
	// copied to the target namespace.

	Context("Copy secret to target namespace #4", func() {
		It("should copy secret to target namespace", func() {
			sourceNamespaceName := "source-namespace-4"
			sourceSecretName := "source-secret-1"
			targetNamespaceName := "target-namespace-4"
			targetSecretName := "target-secret-1"
			secretCopierName := "secret-copier-4"

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

			// Create the secret copier custom resource.

			secretCopier := &secretsv1beta1.SecretCopier{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretCopierName,
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

		// Test that after copying the source secret to the target namespace,
		// that the data and labels are the same. Then update the data and
		// labels in the source secret and verify that the target secret is
		// updated with the new data and labels.

		Context("Copy secret to target namespace #5", func() {
			It("should copy secret to target namespace", func() {
				sourceNamespaceName := "source-namespace-5"
				sourceSecretName := "source-secret-1"
				targetNamespaceName := "target-namespace-5"
				targetSecretName := "target-secret-1"
				secretCopierName := "secret-copier-5"

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

				// Create the secret copier custom resource.

				secretCopier := &secretsv1beta1.SecretCopier{
					ObjectMeta: metav1.ObjectMeta{
						Name: secretCopierName,
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
						Labels: map[string]string{
							"label-key1": "label-value1",
						},
					},
					Type: corev1.SecretTypeOpaque,
					StringData: map[string]string{
						"data-key1": "data-value1",
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

				// Wait for the target secret to be created in the target
				// namespace.

				Eventually(func() bool {
					targetSecret := &corev1.Secret{}
					err := k8sClient.Get(ctx, client.ObjectKey{
						Namespace: targetNamespaceName,
						Name:      targetSecretName,
					}, targetSecret)
					return err == nil
				}, 5*time.Second).Should(BeTrue())

				// Verify that the target secret which was created has the same
				// data as the source secret.

				targetSecret := &corev1.Secret{}

				Expect(k8sClient.Get(ctx, client.ObjectKey{
					Namespace: targetNamespaceName,
					Name:      targetSecretName,
				}, targetSecret)).To(Succeed())

				// Verify that the target secret has the same data as the source
				// secret.

				Expect(targetSecret.Data).To(Equal(sourceSecret.Data))

				// Verify that the target secret has the labels that were
				// specified in the target secret.

				Expect(targetSecret.ObjectMeta.Labels).To(Equal(sourceSecret.ObjectMeta.Labels))

				// Update the data and labels in the source secret.

				sourceSecret.Data = map[string][]byte{}

				sourceSecret.StringData = map[string]string{
					"data-key1": "data-value1",
					"data-key2": "data-value2",
				}

				sourceSecret.ObjectMeta.Labels = map[string]string{
					"label-key1": "label-value1",
					"label-key2": "label-value2",
				}

				Expect(k8sClient.Update(ctx, sourceSecret)).To(Succeed())

				// Read back the source secret to verify that the update was
				// successful.

				Eventually(func() bool {
					err := k8sClient.Get(ctx, client.ObjectKey{
						Namespace: sourceNamespaceName,
						Name:      sourceSecretName,
					}, sourceSecret)
					return err == nil
				}).Should(BeTrue())

				// Verify that the target secret is updated with the new data
				// and labels. We need keep checking until the target secret is
				// updated as the controller may not have processed the update
				// to the source secret yet. So need to do the comparisons for
				// data and labels in the context of the Eventually block.

				Eventually(func() bool {
					err := k8sClient.Get(ctx, client.ObjectKey{
						Namespace: targetNamespaceName,
						Name:      targetSecretName,
					}, targetSecret)
					if err != nil {
						return false
					}

					// Verify that the target secret has the updated data.

					if !Expect(targetSecret.Data).To(Equal(sourceSecret.Data)) {
						return false
					}

					// Verify that the target secret has the updated labels.

					if !Expect(targetSecret.ObjectMeta.Labels).To(Equal(sourceSecret.ObjectMeta.Labels)) {
						return false
					}

					return true
				}, 5*time.Second).Should(BeTrue())
			})
		})
	})
})
