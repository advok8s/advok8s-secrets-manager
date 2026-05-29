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

// This file holds shared helpers for the controller test suite. The specs
// themselves live in behaviour-grouped files so it is clear where new tests
// belong as coverage grows:
//
//   secretcopier_copy_test.go            - copying a source secret into target
//                                          namespaces (creation / ordering)
//   secretcopier_sync_test.go            - keeping target secrets in sync and
//                                          the guards around updating them
//   secretcopier_reclaim_test.go         - reclaim policy (owner references)
//   secretcopier_targetsecret_test.go    - target rename, labels, annotations
//   secretcopier_selectors_test.go       - selecting target namespaces
//   secretcopier_multirule_test.go       - multiple rules / namespaces
//   secretcopier_syncperiod_test.go      - requeue-after behaviour
//   secretcopier_status_test.go          - observed state written to .status
//                                          (observedGeneration, conditions,
//                                          summary / per-rule counts)
//
// The pure-function copy decisions (whether a target has drifted, whether a
// target is managed by a rule) live with the shared copy engine and are unit
// tested there: internal/copyengine/engine_test.go.
//
// New behaviour areas should each get their own secretcopier_<behaviour>_test.go
// file and reuse the builders below.

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	return createNamespaceWithLabels(name, nil)
}

// createNamespaceWithLabels creates a labelled namespace and waits until it can
// be read back.
func createNamespaceWithLabels(name string, labels map[string]string) *corev1.Namespace {
	GinkgoHelper()

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
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

// ruleOptions configures copyRule. An empty Reclaim defaults to Delete; leave
// MatchNames or MatchLabels unset to omit that selector.
type ruleOptions struct {
	SourceNamespace string
	SourceName      string
	TargetName      string
	TargetLabels    map[string]string
	Reclaim         secretsv1beta1.ReclaimPolicy
	MatchNames      []string
	MatchLabels     map[string]string
}

// copyRule builds a SecretCopierRule from options. The matchNames, matchUids
// and matchOwners selector fields are required by the CRD schema, so they are
// always emitted as non-nil (empty) slices even when unused.
func copyRule(o ruleOptions) secretsv1beta1.SecretCopierRule {
	reclaim := o.Reclaim
	if reclaim == "" {
		reclaim = secretsv1beta1.ReclaimDelete
	}

	matchNames := o.MatchNames
	if matchNames == nil {
		matchNames = []string{}
	}

	return secretsv1beta1.SecretCopierRule{
		SourceSecret: secretsv1beta1.SourceSecret{
			Namespace: o.SourceNamespace,
			Name:      o.SourceName,
		},
		TargetNamespaces: selectors.TargetNamespaces{
			NameSelector:  selectors.NameSelector{MatchNames: matchNames},
			UIDSelector:   selectors.UIDSelector{MatchUids: []string{}},
			OwnerSelector: selectors.OwnerSelector{MatchOwners: []selectors.OwnerReference{}},
			LabelSelector: selectors.LabelSelector{MatchLabels: o.MatchLabels},
		},
		TargetSecret: secretsv1beta1.TargetSecret{
			Name:   o.TargetName,
			Labels: o.TargetLabels,
		},
		ReclaimPolicy: reclaim,
	}
}

// nameSelectorRule builds a copy rule that selects target namespaces by exact
// name and copies the source secret into them under targetSecretName, with the
// reclaim policy set to Delete.
func nameSelectorRule(sourceNamespace, sourceName, targetSecretName string, targetNamespaces ...string) secretsv1beta1.SecretCopierRule {
	return copyRule(ruleOptions{
		SourceNamespace: sourceNamespace,
		SourceName:      sourceName,
		TargetName:      targetSecretName,
		MatchNames:      targetNamespaces,
	})
}

// nameSelectorRuleWithReclaim is nameSelectorRule with an explicit reclaim policy.
func nameSelectorRuleWithReclaim(sourceNamespace, sourceName, targetSecretName string, reclaim secretsv1beta1.ReclaimPolicy, targetNamespaces ...string) secretsv1beta1.SecretCopierRule {
	return copyRule(ruleOptions{
		SourceNamespace: sourceNamespace,
		SourceName:      sourceName,
		TargetName:      targetSecretName,
		Reclaim:         reclaim,
		MatchNames:      targetNamespaces,
	})
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

// nameTargetNamespaces builds a TargetNamespaces selecting by exact name. The
// matchUids and matchOwners fields are required by the CRD schema, so they are
// always emitted as non-nil (empty) slices even when unused.
func nameTargetNamespaces(names ...string) selectors.TargetNamespaces {
	if names == nil {
		names = []string{}
	}

	return selectors.TargetNamespaces{
		NameSelector:  selectors.NameSelector{MatchNames: names},
		UIDSelector:   selectors.UIDSelector{MatchUids: []string{}},
		OwnerSelector: selectors.OwnerSelector{MatchOwners: []selectors.OwnerReference{}},
	}
}

// exporterRule builds a SecretExporterRule selecting target namespaces by name,
// with the given target secret name (empty defaults to the exporter name) and
// shared secret (empty leaves copyAuthorization unset, defaulting to the
// exporter UID).
func exporterRule(targetName, sharedSecret string, targetNamespaces ...string) secretsv1beta1.SecretExporterRule {
	return secretsv1beta1.SecretExporterRule{
		TargetNamespaces:  nameTargetNamespaces(targetNamespaces...),
		TargetSecret:      secretsv1beta1.TargetSecret{Name: targetName},
		CopyAuthorization: secretsv1beta1.CopyAuthorization{SharedSecret: sharedSecret},
	}
}

// createSecretExporter creates a SecretExporter and waits until it can be read
// back (so its UID is populated).
func createSecretExporter(namespace, name string, rules ...secretsv1beta1.SecretExporterRule) *secretsv1beta1.SecretExporter {
	GinkgoHelper()

	exporter := &secretsv1beta1.SecretExporter{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       secretsv1beta1.SecretExporterSpec{Rules: rules},
	}
	Expect(k8sClient.Create(ctx, exporter)).To(Succeed())

	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, exporter)
	}).Should(Succeed())

	return exporter
}

// createSecretImporter creates a SecretImporter with the given shared secret and
// optional source-namespace name selector, and waits until it can be read back.
func createSecretImporter(namespace, name, sharedSecret string, sourceNamespaceNames ...string) *secretsv1beta1.SecretImporter {
	GinkgoHelper()

	importer := &secretsv1beta1.SecretImporter{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: secretsv1beta1.SecretImporterSpec{
			CopyAuthorization: secretsv1beta1.CopyAuthorization{SharedSecret: sharedSecret},
		},
	}
	if len(sourceNamespaceNames) > 0 {
		importer.Spec.SourceNamespaces = &secretsv1beta1.ImporterSourceNamespaces{
			NameSelector: selectors.NameSelector{MatchNames: sourceNamespaceNames},
		}
	}
	Expect(k8sClient.Create(ctx, importer)).To(Succeed())

	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, importer)
	}).Should(Succeed())

	return importer
}

// createServiceAccount creates a service account and waits until it can be read
// back. envtest does not run the service-account controller, so the default
// service account is not created automatically; tests create the ones they need.
func createServiceAccount(namespace, name string, labels map[string]string) *corev1.ServiceAccount {
	GinkgoHelper()

	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
	}
	Expect(k8sClient.Create(ctx, serviceAccount)).To(Succeed())

	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, serviceAccount)
	}).Should(Succeed())

	return serviceAccount
}

// injectorRule builds a SecretInjectorRule selecting source secrets, target
// namespaces and service accounts by exact name. Empty slices leave that
// selector unset (which matches everything for source/service-account
// selectors, and all non-kube-* namespaces for target namespaces).
func injectorRule(sourceSecretNames, serviceAccountNames, targetNamespaces []string) secretsv1beta1.SecretInjectorRule {
	rule := secretsv1beta1.SecretInjectorRule{
		TargetNamespaces: nameTargetNamespaces(targetNamespaces...),
	}
	if len(sourceSecretNames) > 0 {
		rule.SourceSecrets = selectors.NameLabelSelector{
			NameSelector: &selectors.NameSelector{MatchNames: sourceSecretNames},
		}
	}
	if len(serviceAccountNames) > 0 {
		rule.ServiceAccounts = selectors.NameLabelSelector{
			NameSelector: &selectors.NameSelector{MatchNames: serviceAccountNames},
		}
	}
	return rule
}

// createSecretInjector creates a SecretInjector and waits until it can be read
// back.
func createSecretInjector(name string, rules ...secretsv1beta1.SecretInjectorRule) *secretsv1beta1.SecretInjector {
	GinkgoHelper()

	injector := &secretsv1beta1.SecretInjector{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       secretsv1beta1.SecretInjectorSpec{Rules: rules},
	}
	Expect(k8sClient.Create(ctx, injector)).To(Succeed())

	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Name: name}, injector)
	}).Should(Succeed())

	return injector
}

// eventuallyGetServiceAccount waits for a service account to carry the given
// reference in the expected field and returns it.
func eventuallyServiceAccountHas(namespace, name string, check func(*corev1.ServiceAccount) bool) *corev1.ServiceAccount {
	GinkgoHelper()

	serviceAccount := &corev1.ServiceAccount{}
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, serviceAccount)).To(Succeed())
		g.Expect(check(serviceAccount)).To(BeTrue())
	}, secretCreatedTimeout).Should(Succeed())

	return serviceAccount
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

// consistentlySecretAbsent asserts that, for a short window, the named secret
// does not exist. Used for negative cases where the controller should not copy.
func consistentlySecretAbsent(namespace, name string) {
	GinkgoHelper()

	Consistently(func() bool {
		err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &corev1.Secret{})
		return apierrors.IsNotFound(err)
	}, 2*time.Second, 250*time.Millisecond).Should(BeTrue())
}
