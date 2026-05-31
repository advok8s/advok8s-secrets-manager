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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

var _ = Describe("SecretBuilder regeneration", func() {
	const timeout = 15 * time.Second
	const interval = 200 * time.Millisecond

	scriptBuilder := func(ns, name, script string) *secretsv1beta1.SecretBuilder {
		return &secretsv1beta1.SecretBuilder{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: secretsv1beta1.SecretBuilderSpec{
				Generator: secretsv1beta1.SecretBuilderGenerator{Script: ptr.To(script)},
			},
		}
	}

	dataValue := func(ns, name, key string) func() string {
		return func() string {
			var s corev1.Secret
			if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &s); err != nil {
				return ""
			}
			return string(s.Data[key])
		}
	}

	It("refreshes on input change but keeps generated material stable", func() {
		createNamespace("sb-refresh")
		src := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "sb-refresh"},
			Type:       corev1.SecretTypeOpaque,
			StringData: map[string]string{"v": "one"},
		}
		Expect(k8sClient.Create(ctx, src)).To(Succeed())

		b := scriptBuilder("sb-refresh", "derived", `
secret = {"data": {
  "from_input": input.secrets.src.data["v"],
  "from_gen": input.generated.pw.value,
}}
`)
		b.Spec.Inputs.Secrets = []secretsv1beta1.SecretInput{{Name: "src", SecretRef: &corev1.LocalObjectReference{Name: "source"}}}
		b.Spec.Inputs.Generated = []secretsv1beta1.GeneratedValue{{Name: "pw", Password: &secretsv1beta1.PasswordSpec{Length: 16}}}
		b.Spec.Regeneration = secretsv1beta1.Regeneration{OnInputChange: true}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(dataValue("sb-refresh", "derived", "from_input"), timeout, interval).Should(Equal("one"))
		generatedBefore := dataValue("sb-refresh", "derived", "from_gen")()
		Expect(generatedBefore).ToNot(BeEmpty())

		// Change the input; the builder should refresh.
		var current corev1.Secret
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "sb-refresh", Name: "source"}, &current)).To(Succeed())
		current.Data = map[string][]byte{"v": []byte("two")}
		Expect(k8sClient.Update(ctx, &current)).To(Succeed())

		Eventually(dataValue("sb-refresh", "derived", "from_input"), timeout, interval).Should(Equal("two"))
		// The generated value must be replayed unchanged across the refresh.
		Expect(dataValue("sb-refresh", "derived", "from_gen")()).To(Equal(generatedBefore))
	})

	It("rotates and re-rolls entropy on rotateEvery", func() {
		createNamespace("sb-rotate")
		b := scriptBuilder("sb-rotate", "rotating", `secret = {"data": {"v": input.generated.pw.value}}`)
		b.Spec.Inputs.Generated = []secretsv1beta1.GeneratedValue{{Name: "pw", Password: &secretsv1beta1.PasswordSpec{Length: 16}}}
		b.Spec.Regeneration = secretsv1beta1.Regeneration{
			RotateEvery:     &metav1.Duration{Duration: time.Second},
			RotateGenerated: true,
		}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(dataValue("sb-rotate", "rotating", "v"), timeout, interval).ShouldNot(BeEmpty())
		first := dataValue("sb-rotate", "rotating", "v")()

		// The rotateEvery requeue should re-roll the password within a few seconds.
		Eventually(dataValue("sb-rotate", "rotating", "v"), timeout, interval).ShouldNot(Equal(first))
	})

	It("rotates on the manual regenerate annotation", func() {
		createNamespace("sb-manual")
		b := scriptBuilder("sb-manual", "manual", `secret = {"data": {"v": input.generated.pw.value}}`)
		b.Spec.Inputs.Generated = []secretsv1beta1.GeneratedValue{{Name: "pw", Password: &secretsv1beta1.PasswordSpec{Length: 16}}}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(dataValue("sb-manual", "manual", "v"), timeout, interval).ShouldNot(BeEmpty())
		first := dataValue("sb-manual", "manual", "v")()

		var current secretsv1beta1.SecretBuilder
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "sb-manual", Name: "manual"}, &current)).To(Succeed())
		current.Annotations = map[string]string{"secrets.advok8s.io/regenerate": "1"}
		Expect(k8sClient.Update(ctx, &current)).To(Succeed())

		Eventually(dataValue("sb-manual", "manual", "v"), timeout, interval).ShouldNot(Equal(first))
	})

	It("propagates an upstream change down a builder chain", func() {
		createNamespace("sb-chain")

		// Upstream builder A produces a Secret from a generated password.
		a := scriptBuilder("sb-chain", "chain-a", `secret = {"data": {"v": input.generated.p.value}}`)
		a.Spec.Inputs.Generated = []secretsv1beta1.GeneratedValue{{Name: "p", Password: &secretsv1beta1.PasswordSpec{Length: 16}}}
		Expect(k8sClient.Create(ctx, a)).To(Succeed())

		// Downstream builder B derives from A's output and reacts to its changes.
		b := scriptBuilder("sb-chain", "chain-b", `secret = {"data": {"derived": input.secrets.a.data["v"]}}`)
		b.Spec.Inputs.Secrets = []secretsv1beta1.SecretInput{{Name: "a", SecretRef: &corev1.LocalObjectReference{Name: "chain-a"}}}
		b.Spec.Regeneration = secretsv1beta1.Regeneration{OnInputChange: true}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(dataValue("sb-chain", "chain-a", "v"), timeout, interval).ShouldNot(BeEmpty())
		Eventually(func() string {
			return dataValue("sb-chain", "chain-b", "derived")()
		}, timeout, interval).Should(Equal(dataValue("sb-chain", "chain-a", "v")()))

		// Rotate A; B should follow once A's output (and its revision) changes.
		aValueBefore := dataValue("sb-chain", "chain-a", "v")()
		var currentA secretsv1beta1.SecretBuilder
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "sb-chain", Name: "chain-a"}, &currentA)).To(Succeed())
		currentA.Annotations = map[string]string{"secrets.advok8s.io/regenerate": "1"}
		Expect(k8sClient.Update(ctx, &currentA)).To(Succeed())

		Eventually(dataValue("sb-chain", "chain-a", "v"), timeout, interval).ShouldNot(Equal(aValueBefore))
		Eventually(func() string {
			return dataValue("sb-chain", "chain-b", "derived")()
		}, timeout, interval).Should(Equal(dataValue("sb-chain", "chain-a", "v")()))
	})
})
