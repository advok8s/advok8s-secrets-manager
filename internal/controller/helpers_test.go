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

// This file holds shared helpers for the controller test suite. The specs
// themselves live in behaviour-grouped files so it is clear where new tests
// belong as coverage grows, for example:
//
//   secretcopier_copy_test.go    - copying a source secret into target
//                                  namespaces (creation / ordering scenarios)
//   secretcopier_sync_test.go    - keeping target secrets in sync when the
//                                  source secret changes
//
// Future areas (reclaim policy Delete vs Retain, target secret renaming and
// labelling, namespace selection by label/owner/uid, multiple rules, error
// and edge cases) should each get their own secretcopier_<behaviour>_test.go
// file and reuse the builders below.

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
	"github.com/advok8s/advok8s-secrets-manager/pkg/selectors"
)

const (
	defaultSourceSecretName = "source-secret-1"
	defaultTargetSecretName = "target-secret-1"
)

// secretCreatedTimeout bounds how long a spec waits for the controller to
// reconcile a target secret into existence (or to re-sync it).
const secretCreatedTimeout = 5 * time.Second

// createNamespace creates a namespace and waits until it can be read back.
func createNamespace(name string) *corev1.Namespace {
	GinkgoHelper()

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	Expect(k8sClient.Create(ctx, namespace)).To(Succeed())

	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Name: name}, namespace)
	}).Should(Succeed())

	return namespace
}

// createOpaqueSecret creates an Opaque secret with the given string data and
// labels (labels may be nil) and waits until it can be read back. The returned
// secret is the re-fetched copy, so its Data field and ResourceVersion are
// populated ready for comparisons or updates.
func createOpaqueSecret(namespace, name string, stringData, labels map[string]string) *corev1.Secret {
	GinkgoHelper()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: stringData,
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())

	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret)
	}).Should(Succeed())

	return secret
}

// nameSelectorRule builds a copy rule that selects target namespaces by exact
// name and copies the source secret into them under targetSecretName, with the
// reclaim policy set to Delete.
func nameSelectorRule(sourceNamespace, sourceName, targetSecretName string, targetNamespaces ...string) secretsv1beta1.SecretCopierRule {
	return secretsv1beta1.SecretCopierRule{
		SourceSecret: secretsv1beta1.SourceSecret{
			Namespace: sourceNamespace,
			Name:      sourceName,
		},
		TargetNamespaces: selectors.TargetNamespaces{
			NameSelector: selectors.NameSelector{
				MatchNames: targetNamespaces,
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
	}
}

// createSecretCopier creates a SecretCopier with the given rules and waits
// until it can be read back.
func createSecretCopier(name string, rules ...secretsv1beta1.SecretCopierRule) *secretsv1beta1.SecretCopier {
	GinkgoHelper()

	secretCopier := &secretsv1beta1.SecretCopier{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       secretsv1beta1.SecretCopierSpec{Rules: rules},
	}
	Expect(k8sClient.Create(ctx, secretCopier)).To(Succeed())

	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Name: name}, secretCopier)
	}).Should(Succeed())

	return secretCopier
}

// eventuallyGetSecret waits for the named secret to exist and returns it.
func eventuallyGetSecret(namespace, name string) *corev1.Secret {
	GinkgoHelper()

	secret := &corev1.Secret{}
	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret)
	}, secretCreatedTimeout).Should(Succeed())

	return secret
}
