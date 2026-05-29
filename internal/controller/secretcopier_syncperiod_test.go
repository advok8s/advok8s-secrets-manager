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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// The reconciler reschedules itself via Result.RequeueAfter using the
// SecretCopier's syncPeriod. Because that value is returned synchronously we
// can assert it with a direct Reconcile call (no waiting on the timer).
var _ = Describe("SecretCopier sync period requeue", func() {
	// reconcileResult invokes the reconciler directly and returns its Result.
	reconcileResult := func(name string) ctrl.Result {
		GinkgoHelper()
		reconciler := &SecretCopierReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: name}})
		Expect(err).NotTo(HaveOccurred())
		return result
	}

	// createCopier creates a SecretCopier verbatim and waits until it can be
	// read back.
	createCopier := func(copier *secretsv1beta1.SecretCopier) {
		GinkgoHelper()
		Expect(k8sClient.Create(ctx, copier)).To(Succeed())
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: copier.Name}, copier)
		}).Should(Succeed())
	}

	It("requeues after the default sync period when syncPeriod is omitted", func() {
		// A typed client always serialises syncPeriod's zero value ("0s"), which
		// suppresses the CRD default. Create via an unstructured object that
		// omits the field entirely so the API server applies the "1m" default,
		// mirroring a kubectl-apply manifest that leaves syncPeriod unset.
		u := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "secrets.advok8s.io/v1beta1",
			"kind":       "SecretCopier",
			"metadata":   map[string]any{"name": "sp-default"},
			"spec": map[string]any{
				"rules": []any{map[string]any{
					"sourceSecret": map[string]any{"namespace": "sp-default-src", "name": defaultSourceSecretName},
					"targetNamespaces": map[string]any{
						"nameSelector": map[string]any{"matchNames": []any{"sp-default-tgt"}},
					},
					"targetSecret": map[string]any{"name": defaultTargetSecretName},
				}},
			},
		}}
		Expect(k8sClient.Create(ctx, u)).To(Succeed())

		copier := &secretsv1beta1.SecretCopier{}
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: "sp-default"}, copier)
		}).Should(Succeed())

		Expect(copier.Spec.SyncPeriod.Duration).To(Equal(time.Minute))
		Expect(reconcileResult("sp-default").RequeueAfter).To(Equal(time.Minute))
	})

	It("requeues after an explicit sync period", func() {
		createCopier(&secretsv1beta1.SecretCopier{
			ObjectMeta: metav1.ObjectMeta{Name: "sp-explicit"},
			Spec: secretsv1beta1.SecretCopierSpec{
				SyncPeriod: metav1.Duration{Duration: 30 * time.Second},
				Rules: []secretsv1beta1.SecretCopierRule{
					nameSelectorRule("sp-explicit-src", defaultSourceSecretName, defaultTargetSecretName, "sp-explicit-tgt"),
				},
			},
		})

		Expect(reconcileResult("sp-explicit").RequeueAfter).To(Equal(30 * time.Second))
	})

	It("does not requeue when the sync period is zero", func() {
		createCopier(&secretsv1beta1.SecretCopier{
			ObjectMeta: metav1.ObjectMeta{Name: "sp-zero"},
			Spec: secretsv1beta1.SecretCopierSpec{
				SyncPeriod: metav1.Duration{Duration: 0},
				Rules: []secretsv1beta1.SecretCopierRule{
					nameSelectorRule("sp-zero-src", defaultSourceSecretName, defaultTargetSecretName, "sp-zero-tgt"),
				},
			},
		})

		Expect(reconcileResult("sp-zero").RequeueAfter).To(BeZero())
	})

	It("does not requeue when there are no rules", func() {
		createCopier(&secretsv1beta1.SecretCopier{
			ObjectMeta: metav1.ObjectMeta{Name: "sp-norules"},
			Spec:       secretsv1beta1.SecretCopierSpec{},
		})

		Expect(reconcileResult("sp-norules").RequeueAfter).To(BeZero())
	})
})
