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

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
)

// A SecretBuilder with onInputChange must refresh when a ConfigMap input
// changes, exactly as it does for Secret inputs - the ConfigMap watch makes
// builder chains through ConfigMaps event-driven.
var _ = Describe("SecretBuilder ConfigMap input watch", func() {
	const timeout = 10 * time.Second
	const interval = 200 * time.Millisecond

	It("refreshes the output when a referenced ConfigMap changes (onInputChange)", func() {
		createNamespace("sb-cm-watch")
		createConfigMap("sb-cm-watch", "app-settings", map[string]string{"setting": "v1"}, nil, nil)

		b := &secretsv1beta1.SecretBuilder{
			ObjectMeta: metav1.ObjectMeta{Name: "derived", Namespace: "sb-cm-watch"},
			Spec: secretsv1beta1.SecretBuilderSpec{
				Inputs: secretsv1beta1.SecretBuilderInputs{
					ConfigMaps: []secretsv1beta1.ConfigMapInput{
						{Name: "settings", ConfigMapRef: &corev1.LocalObjectReference{Name: "app-settings"}},
					},
				},
				Generator: secretsv1beta1.SecretBuilderGenerator{
					Script: ptr.To(`secret = {"data": {"derived": input.configMaps.settings.data["setting"]}}`),
				},
				Regeneration: secretsv1beta1.Regeneration{OnInputChange: true},
			},
		}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func(g Gomega) {
			var out corev1.Secret
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "sb-cm-watch", Name: "derived"}, &out)).To(Succeed())
			g.Expect(string(out.Data["derived"])).To(Equal("v1"))
		}, timeout, interval).Should(Succeed())

		// Update the ConfigMap input; the ConfigMap watch must refresh the
		// builder without any change to the SecretBuilder itself.
		Eventually(func(g Gomega) {
			var cm corev1.ConfigMap
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "sb-cm-watch", Name: "app-settings"}, &cm)).To(Succeed())
			cm.Data["setting"] = "v2"
			g.Expect(k8sClient.Update(ctx, &cm)).To(Succeed())
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			var out corev1.Secret
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "sb-cm-watch", Name: "derived"}, &out)).To(Succeed())
			g.Expect(string(out.Data["derived"])).To(Equal("v2"))
		}, timeout, interval).Should(Succeed())
	})
})
