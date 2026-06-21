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
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
	"github.com/advok8s/advok8s-secrets-manager/pkg/selectors"
)

// These tests exercise the SecretBuilder CRD's CEL validation rules directly
// against the envtest API server. No SecretBuilder controller is running yet
// (that arrives in a later phase); admission validation is enforced by the API
// server independently of any controller.
var _ = Describe("SecretBuilder CRD validation", func() {
	// validBuilder returns a minimal, schema-valid SecretBuilder: a script
	// generator and nothing else (inputs are optional).
	validBuilder := func(name string) *secretsv1beta1.SecretBuilder {
		return &secretsv1beta1.SecretBuilder{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: secretsv1beta1.SecretBuilderSpec{
				Generator: secretsv1beta1.SecretBuilderGenerator{
					Script: ptr.To(`secret = {"data": {}}`),
				},
			},
		}
	}

	create := func(builder *secretsv1beta1.SecretBuilder) error {
		err := k8sClient.Create(ctx, builder)
		if err == nil {
			DeferCleanup(func() {
				Expect(k8sClient.Delete(ctx, builder)).To(Succeed())
			})
		}
		return err
	}

	It("accepts a minimal valid builder", func() {
		Expect(create(validBuilder("valid-minimal"))).To(Succeed())
	})

	It("accepts a selector input with one sub-selector and a template generator", func() {
		b := validBuilder("valid-selector-template")
		b.Spec.Generator = secretsv1beta1.SecretBuilderGenerator{
			Template: &secretsv1beta1.TemplateGenerator{Data: map[string]string{"k": "{{ 1 }}"}},
		}
		b.Spec.Inputs.Secrets = []secretsv1beta1.SecretInput{{
			Name: "users",
			Selector: &selectors.ResourceSelector{
				NameSelector: &selectors.NameSelector{MatchNames: []string{"user-*"}},
			},
		}}
		Expect(create(b)).To(Succeed())
	})

	It("rejects an input with both secretRef and selector", func() {
		b := validBuilder("invalid-both-sources")
		b.Spec.Inputs.Secrets = []secretsv1beta1.SecretInput{{
			Name:      "db",
			SecretRef: &corev1.LocalObjectReference{Name: "db-credentials"},
			Selector:  &selectors.ResourceSelector{NameSelector: &selectors.NameSelector{MatchNames: []string{"x"}}},
		}}
		Expect(create(b)).ToNot(Succeed())
	})

	It("rejects an input with neither secretRef nor selector", func() {
		b := validBuilder("invalid-no-source")
		b.Spec.Inputs.Secrets = []secretsv1beta1.SecretInput{{Name: "db"}}
		Expect(create(b)).ToNot(Succeed())
	})

	It("rejects a selector with no sub-selector set", func() {
		b := validBuilder("invalid-empty-selector")
		b.Spec.Inputs.Secrets = []secretsv1beta1.SecretInput{{
			Name:     "db",
			Selector: &selectors.ResourceSelector{},
		}}
		Expect(create(b)).ToNot(Succeed())
	})

	It("rejects a generator with both script and template", func() {
		b := validBuilder("invalid-both-engines")
		b.Spec.Generator.Template = &secretsv1beta1.TemplateGenerator{Data: map[string]string{"k": "v"}}
		Expect(create(b)).ToNot(Succeed())
	})

	It("rejects a generator with neither script nor template", func() {
		b := validBuilder("invalid-no-engine")
		b.Spec.Generator = secretsv1beta1.SecretBuilderGenerator{}
		Expect(create(b)).ToNot(Succeed())
	})

	It("rejects a generated value with two kinds set", func() {
		b := validBuilder("invalid-two-generated-kinds")
		b.Spec.Inputs.Generated = []secretsv1beta1.GeneratedValue{{
			Name:     "x",
			Password: &secretsv1beta1.PasswordSpec{Length: 16},
			Token:    &secretsv1beta1.TokenSpec{Length: 16},
		}}
		Expect(create(b)).ToNot(Succeed())
	})

	It("rejects a generated value with no kind set", func() {
		b := validBuilder("invalid-no-generated-kind")
		b.Spec.Inputs.Generated = []secretsv1beta1.GeneratedValue{{Name: "x"}}
		Expect(create(b)).ToNot(Succeed())
	})
})
