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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
	builderpkg "github.com/advok8s/advok8s-secrets-manager/internal/builder"
)

var _ = Describe("SecretBuilder generate-once", func() {
	const timeout = 10 * time.Second
	const interval = 200 * time.Millisecond

	newScriptBuilder := func(ns, name, script string) *secretsv1beta1.SecretBuilder {
		return &secretsv1beta1.SecretBuilder{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: secretsv1beta1.SecretBuilderSpec{
				Generator: secretsv1beta1.SecretBuilderGenerator{Script: ptr.To(script)},
			},
		}
	}

	makeSecret := func(ns, name string, data map[string]string) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Type:       corev1.SecretTypeOpaque,
			StringData: data,
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	}

	getOutput := func(ns, name string) (*corev1.Secret, error) {
		var s corev1.Secret
		err := k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &s)
		return &s, err
	}

	readyReason := func(ns, name string) string {
		var b secretsv1beta1.SecretBuilder
		if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &b); err != nil {
			return ""
		}
		if c := meta.FindStatusCondition(b.Status.Conditions, secretsv1beta1.ConditionReady); c != nil {
			return string(c.Status) + "/" + c.Reason
		}
		return ""
	}

	It("derives a Secret from an input Secret and stamps owner + revision", func() {
		createNamespace("sb-derive")
		makeSecret("sb-derive", "db-credentials", map[string]string{"password": "pw"})

		b := newScriptBuilder("sb-derive", "my-secret", `
db = input.secrets.db.data["password"]
secret = {"data": {"derived": db + "-x"}, "labels": {"app": "demo"}, "type": "Opaque"}
`)
		b.Spec.Inputs.Secrets = []secretsv1beta1.SecretInput{{Name: "db", SecretRef: &corev1.LocalObjectReference{Name: "db-credentials"}}}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func(g Gomega) {
			out, err := getOutput("sb-derive", "my-secret")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(string(out.Data["derived"])).To(Equal("pw-x"))
			g.Expect(out.Labels["app"]).To(Equal("demo"))
			g.Expect(out.Annotations).To(HaveKey(builderpkg.RevisionAnnotation))
			g.Expect(out.OwnerReferences).To(HaveLen(1))
			g.Expect(out.OwnerReferences[0].Kind).To(Equal("SecretBuilder"))
			g.Expect(*out.OwnerReferences[0].Controller).To(BeTrue())
		}, timeout, interval).Should(Succeed())
	})

	It("generates from a gotemplate template", func() {
		createNamespace("sb-template")
		b := &secretsv1beta1.SecretBuilder{
			ObjectMeta: metav1.ObjectMeta{Name: "tmpl-secret", Namespace: "sb-template"},
			Spec: secretsv1beta1.SecretBuilderSpec{
				Inputs: secretsv1beta1.SecretBuilderInputs{Constants: rawJSON(`{"greeting":"hello"}`)},
				Generator: secretsv1beta1.SecretBuilderGenerator{
					Template: &secretsv1beta1.TemplateGenerator{Data: map[string]string{"msg": `{{ .constants.greeting }}-world`}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func(g Gomega) {
			out, err := getOutput("sb-template", "tmpl-secret")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(string(out.Data["msg"])).To(Equal("hello-world"))
		}, timeout, interval).Should(Succeed())
	})

	It("holds in AwaitingInput when a referenced Secret is absent", func() {
		createNamespace("sb-awaiting")
		b := newScriptBuilder("sb-awaiting", "needs-input", `secret = {"data": {"x": input.secrets.db.data["k"]}}`)
		b.Spec.Inputs.Secrets = []secretsv1beta1.SecretInput{{Name: "db", SecretRef: &corev1.LocalObjectReference{Name: "missing"}}}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func() string {
			return readyReason("sb-awaiting", "needs-input")
		}, timeout, interval).Should(Equal("False/AwaitingInput"))

		_, err := getOutput("sb-awaiting", "needs-input")
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "no Secret should be written while awaiting input")
	})

	It("reports GeneratorError when the script calls fail()", func() {
		createNamespace("sb-fail")
		b := newScriptBuilder("sb-fail", "broken", `fail("configuration invalid")`)
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func() string {
			return readyReason("sb-fail", "broken")
		}, timeout, interval).Should(Equal("False/GeneratorError"))
	})

	It("holds in AwaitingInput when the script calls retry()", func() {
		createNamespace("sb-retry")
		b := newScriptBuilder("sb-retry", "waiting", `retry("not ready yet")`)
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func() string {
			return readyReason("sb-retry", "waiting")
		}, timeout, interval).Should(Equal("False/AwaitingInput"))
	})

	It("does not regenerate once the Secret exists (generate-once)", func() {
		createNamespace("sb-once")
		b := newScriptBuilder("sb-once", "stable", `secret = {"data": {"v": "original"}}`)
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func(g Gomega) {
			out, err := getOutput("sb-once", "stable")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(string(out.Data["v"])).To(Equal("original"))
		}, timeout, interval).Should(Succeed())

		// Hand-edit the output; generate-once must leave it alone even after the
		// SecretBuilder is reconciled again (spec change bumps generation).
		out, _ := getOutput("sb-once", "stable")
		out.Data["v"] = []byte("hand-edited")
		Expect(k8sClient.Update(ctx, out)).To(Succeed())

		var current secretsv1beta1.SecretBuilder
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "sb-once", Name: "stable"}, &current)).To(Succeed())
		current.Spec.Output.Labels = map[string]string{"touched": "true"}
		Expect(k8sClient.Update(ctx, &current)).To(Succeed())

		Consistently(func() string {
			out, err := getOutput("sb-once", "stable")
			if err != nil {
				return ""
			}
			return string(out.Data["v"])
		}, 2*time.Second, interval).Should(Equal("hand-edited"))
	})

	It("mints a ServiceAccount token and exposes it", func() {
		createNamespace("sb-sa")
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "deployer", Namespace: "sb-sa"}}
		Expect(k8sClient.Create(ctx, sa)).To(Succeed())

		b := newScriptBuilder("sb-sa", "sa-secret", `secret = {"data": {"token": input.serviceAccount.token}}`)
		b.Spec.Inputs.ServiceAccount = &secretsv1beta1.ServiceAccountInput{ServiceAccountRef: corev1.LocalObjectReference{Name: "deployer"}}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func(g Gomega) {
			out, err := getOutput("sb-sa", "sa-secret")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out.Data["token"]).ToNot(BeEmpty())
		}, timeout, interval).Should(Succeed())
	})
})

func rawJSON(s string) *runtime.RawExtension {
	return &runtime.RawExtension{Raw: []byte(s)}
}
