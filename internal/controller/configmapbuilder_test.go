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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	configmapsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/configmaps/v1beta1"
	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
	builderpkg "github.com/advok8s/advok8s-secrets-manager/internal/builder"
)

// applyRawManifest creates a resource from raw YAML with strict server-side
// field validation, so an unknown field is an admission error rather than
// being silently pruned. Used to prove the CRD schema rejects fields that
// exist on SecretBuilder but are deliberately absent from ConfigMapBuilder.
func applyRawManifest(manifest string) error {
	var obj unstructured.Unstructured
	if err := yaml.Unmarshal([]byte(manifest), &obj.Object); err != nil {
		return err
	}
	return k8sClient.Create(ctx, &obj, &client.CreateOptions{
		Raw: &metav1.CreateOptions{FieldValidation: metav1.FieldValidationStrict},
	})
}

var _ = Describe("ConfigMapBuilder", func() {
	const timeout = 10 * time.Second
	const interval = 200 * time.Millisecond

	newScriptBuilder := func(ns, name, script string) *configmapsv1beta1.ConfigMapBuilder {
		return &configmapsv1beta1.ConfigMapBuilder{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: configmapsv1beta1.ConfigMapBuilderSpec{
				Generator: configmapsv1beta1.ConfigMapBuilderGenerator{Script: ptr.To(script)},
			},
		}
	}

	getOutput := func(ns, name string) (*corev1.ConfigMap, error) {
		var cm corev1.ConfigMap
		err := k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &cm)
		return &cm, err
	}

	readyReason := func(ns, name string) string {
		var b configmapsv1beta1.ConfigMapBuilder
		if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &b); err != nil {
			return ""
		}
		if c := meta.FindStatusCondition(b.Status.Conditions, secretsv1beta1.ConditionReady); c != nil {
			return string(c.Status) + "/" + c.Reason
		}
		return ""
	}

	It("generates a ConfigMap with data and binaryData from a script", func() {
		createNamespace("cmb-script")
		b := newScriptBuilder("cmb-script", "app-config", `
configMap = {
    "data": {"setting": "value"},
    "binaryData": {"blob": hex.decode("ff0001")},
    "labels": {"app": "demo"},
}
`)
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func(g Gomega) {
			out, err := getOutput("cmb-script", "app-config")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out.Data).To(HaveKeyWithValue("setting", "value"))
			g.Expect(out.BinaryData).To(HaveKeyWithValue("blob", []byte{0xff, 0x00, 0x01}))
			g.Expect(out.Labels).To(HaveKeyWithValue("app", "demo"))
			g.Expect(out.Annotations).To(HaveKey(builderpkg.ConfigMapRevisionAnnotation))
			g.Expect(out.OwnerReferences).To(HaveLen(1))
			g.Expect(out.OwnerReferences[0].Kind).To(Equal("ConfigMapBuilder"))
		}, timeout, interval).Should(Succeed())

		Eventually(func(g Gomega) {
			var current configmapsv1beta1.ConfigMapBuilder
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmb-script", Name: "app-config"}, &current)).To(Succeed())
			g.Expect(current.Status.Generated).To(BeTrue())
			g.Expect(current.Status.ConfigMapName).To(Equal("app-config"))
			g.Expect(current.Status.Revision).ToNot(BeEmpty())
			g.Expect(meta.IsStatusConditionTrue(current.Status.Conditions, secretsv1beta1.ConditionReady)).To(BeTrue())
		}, timeout, interval).Should(Succeed())
	})

	It("generates from a gotemplate template and derives from a Secret input", func() {
		createNamespace("cmb-derive")
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "db-credentials", Namespace: "cmb-derive"},
			Type:       corev1.SecretTypeOpaque,
			StringData: map[string]string{"username": "admin", "password": "supersecret"},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())

		b := &configmapsv1beta1.ConfigMapBuilder{
			ObjectMeta: metav1.ObjectMeta{Name: "db-info", Namespace: "cmb-derive"},
			Spec: configmapsv1beta1.ConfigMapBuilderSpec{
				Inputs: configmapsv1beta1.ConfigMapBuilderInputs{
					Secrets: []secretsv1beta1.SecretInput{
						{Name: "db", SecretRef: &corev1.LocalObjectReference{Name: "db-credentials"}},
					},
				},
				Generator: configmapsv1beta1.ConfigMapBuilderGenerator{
					Template: &configmapsv1beta1.ConfigMapTemplateGenerator{
						Data: map[string]string{"username": `{{ .secrets.db.data.username }}`},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func(g Gomega) {
			out, err := getOutput("cmb-derive", "db-info")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out.Data).To(HaveKeyWithValue("username", "admin"))
		}, timeout, interval).Should(Succeed())
	})

	It("merges template annotations over output annotations", func() {
		createNamespace("cmb-annotations")
		b := &configmapsv1beta1.ConfigMapBuilder{
			ObjectMeta: metav1.ObjectMeta{Name: "annotated", Namespace: "cmb-annotations"},
			Spec: configmapsv1beta1.ConfigMapBuilderSpec{
				Output: configmapsv1beta1.ConfigMapBuilderOutput{
					Annotations: map[string]string{"shared": "static", "static-only": "x"},
				},
				Generator: configmapsv1beta1.ConfigMapBuilderGenerator{
					Template: &configmapsv1beta1.ConfigMapTemplateGenerator{
						Data:        map[string]string{"k": "v"},
						Annotations: map[string]string{"example.com/ns": `{{ .context.namespace }}`, "shared": "dynamic"},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func(g Gomega) {
			out, err := getOutput("cmb-annotations", "annotated")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out.Annotations["example.com/ns"]).To(Equal("cmb-annotations"))
			g.Expect(out.Annotations["shared"]).To(Equal("dynamic"), "dynamic annotations win over spec.output.annotations")
			g.Expect(out.Annotations["static-only"]).To(Equal("x"))
			g.Expect(out.Annotations).To(HaveKey(builderpkg.ConfigMapRevisionAnnotation))
		}, timeout, interval).Should(Succeed())
	})

	It("reports GeneratorError when data is not valid UTF-8", func() {
		createNamespace("cmb-utf8")
		b := newScriptBuilder("cmb-utf8", "broken", `configMap = {"data": {"blob": hex.decode("ff0001")}}`)
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func() string {
			return readyReason("cmb-utf8", "broken")
		}, timeout, interval).Should(Equal("False/GeneratorError"))

		_, err := getOutput("cmb-utf8", "broken")
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "no ConfigMap should be written on a generator error")
	})

	It("holds in AwaitingInput when a referenced ConfigMap is absent", func() {
		createNamespace("cmb-awaiting")
		b := newScriptBuilder("cmb-awaiting", "needs-input", `configMap = {"data": {"x": input.configMaps.src.data["k"]}}`)
		b.Spec.Inputs.ConfigMaps = []secretsv1beta1.ConfigMapInput{
			{Name: "src", ConfigMapRef: &corev1.LocalObjectReference{Name: "missing"}},
		}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func() string {
			return readyReason("cmb-awaiting", "needs-input")
		}, timeout, interval).Should(Equal("False/AwaitingInput"))
	})

	It("does not regenerate once the ConfigMap exists (generate-once)", func() {
		createNamespace("cmb-once")
		b := newScriptBuilder("cmb-once", "stable", `configMap = {"data": {"v": "original"}}`)
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		Eventually(func(g Gomega) {
			out, err := getOutput("cmb-once", "stable")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out.Data).To(HaveKeyWithValue("v", "original"))
		}, timeout, interval).Should(Succeed())

		// Hand-edit the output; generate-once must leave it alone even after the
		// ConfigMapBuilder is reconciled again (spec change bumps generation).
		out, _ := getOutput("cmb-once", "stable")
		out.Data["v"] = "hand-edited"
		Expect(k8sClient.Update(ctx, out)).To(Succeed())

		var current configmapsv1beta1.ConfigMapBuilder
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmb-once", Name: "stable"}, &current)).To(Succeed())
		current.Spec.Output.Labels = map[string]string{"touched": "true"}
		Expect(k8sClient.Update(ctx, &current)).To(Succeed())

		Consistently(func() string {
			out, err := getOutput("cmb-once", "stable")
			if err != nil {
				return ""
			}
			return out.Data["v"]
		}, 2*time.Second, interval).Should(Equal("hand-edited"))
	})

	It("refreshes onInputChange and persists generated material in a companion Secret", func() {
		createNamespace("cmb-refresh")
		createConfigMap("cmb-refresh", "upstream", map[string]string{"k": "v1"}, nil, nil)

		b := newScriptBuilder("cmb-refresh", "derived", `
configMap = {"data": {
    "k": input.configMaps.src.data["k"],
    "id": input.generated.instance.value,
}}
`)
		b.Spec.Inputs.ConfigMaps = []secretsv1beta1.ConfigMapInput{
			{Name: "src", ConfigMapRef: &corev1.LocalObjectReference{Name: "upstream"}},
		}
		b.Spec.Inputs.Generated = []configmapsv1beta1.ConfigMapGeneratedValue{
			{Name: "instance", UUID: &secretsv1beta1.UUIDSpec{}},
		}
		b.Spec.Regeneration = secretsv1beta1.Regeneration{OnInputChange: true}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		var firstID string
		Eventually(func(g Gomega) {
			out, err := getOutput("cmb-refresh", "derived")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out.Data).To(HaveKeyWithValue("k", "v1"))
			g.Expect(out.Data["id"]).ToNot(BeEmpty())
			firstID = out.Data["id"]
		}, timeout, interval).Should(Succeed())

		// The companion state Secret exists and is a Secret, not a ConfigMap.
		var companion corev1.Secret
		Expect(k8sClient.Get(ctx, client.ObjectKey{
			Namespace: "cmb-refresh",
			Name:      builderpkg.CompanionConfigMapBuilderStateName("derived"),
		}, &companion)).To(Succeed())
		Expect(companion.Data).To(HaveKey("generated"))

		// Change the input: the output refreshes but replays the same generated
		// material (a refresh, not a rotation).
		Eventually(func(g Gomega) {
			var cm corev1.ConfigMap
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmb-refresh", Name: "upstream"}, &cm)).To(Succeed())
			cm.Data["k"] = "v2"
			g.Expect(k8sClient.Update(ctx, &cm)).To(Succeed())
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			out, err := getOutput("cmb-refresh", "derived")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out.Data).To(HaveKeyWithValue("k", "v2"))
			g.Expect(out.Data["id"]).To(Equal(firstID), "refresh must replay the same generated material")
		}, timeout, interval).Should(Succeed())
	})

	It("rotates on the regenerate annotation", func() {
		createNamespace("cmb-manual")
		b := newScriptBuilder("cmb-manual", "rotated", `configMap = {"data": {"id": input.generated.instance.value}}`)
		b.Spec.Inputs.Generated = []configmapsv1beta1.ConfigMapGeneratedValue{
			{Name: "instance", UUID: &secretsv1beta1.UUIDSpec{}},
		}
		b.Spec.Regeneration = secretsv1beta1.Regeneration{OnInputChange: true, RotateGenerated: true}
		Expect(k8sClient.Create(ctx, b)).To(Succeed())

		var firstID string
		Eventually(func(g Gomega) {
			out, err := getOutput("cmb-manual", "rotated")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out.Data["id"]).ToNot(BeEmpty())
			firstID = out.Data["id"]
		}, timeout, interval).Should(Succeed())

		Eventually(func(g Gomega) {
			var current configmapsv1beta1.ConfigMapBuilder
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmb-manual", Name: "rotated"}, &current)).To(Succeed())
			if current.Annotations == nil {
				current.Annotations = map[string]string{}
			}
			current.Annotations[builderpkg.ConfigMapRegenerateAnnotation] = "1"
			g.Expect(k8sClient.Update(ctx, &current)).To(Succeed())
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			out, err := getOutput("cmb-manual", "rotated")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out.Data["id"]).ToNot(Equal(firstID), "manual rotation must re-roll generated material")
		}, timeout, interval).Should(Succeed())
	})

	Context("CRD schema enforcement (curated inputs)", func() {
		It("rejects a generated password kind (not in the curated union)", func() {
			createNamespace("cmb-schema")
			raw := `
apiVersion: configmaps.advok8s.io/v1beta1
kind: ConfigMapBuilder
metadata:
  name: bad-generated
  namespace: cmb-schema
spec:
  inputs:
    generated:
    - name: pw
      password:
        length: 16
  generator:
    script: |
      configMap = {"data": {}}
`
			err := applyRawManifest(raw)
			Expect(err).To(HaveOccurred())
		})

		It("prunes a serviceAccount input (the field does not exist in the schema)", func() {
			createNamespace("cmb-schema2")
			raw := `
apiVersion: configmaps.advok8s.io/v1beta1
kind: ConfigMapBuilder
metadata:
  name: no-sa
  namespace: cmb-schema2
spec:
  inputs:
    serviceAccount:
      serviceAccountRef:
        name: deployer
  generator:
    script: |
      configMap = {"data": {"k": "v"}}
`
			// Custom resources prune unknown fields against the structural
			// schema rather than rejecting them, so the guarantee to pin is
			// that a serviceAccount input can never be persisted.
			Expect(applyRawManifest(raw)).To(Succeed())

			var stored unstructured.Unstructured
			stored.SetAPIVersion("configmaps.advok8s.io/v1beta1")
			stored.SetKind("ConfigMapBuilder")
			Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "cmb-schema2", Name: "no-sa"}, &stored)).To(Succeed())
			_, found, err := unstructured.NestedMap(stored.Object, "spec", "inputs", "serviceAccount")
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(BeFalse(), "serviceAccount must be pruned by the schema")
		})

		It("rejects a name longer than 230 characters", func() {
			createNamespace("cmb-schema3")
			longName := strings.Repeat("a", 231)
			b := newScriptBuilder("cmb-schema3", longName, `configMap = {"data": {}}`)
			err := k8sClient.Create(ctx, b)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("230"))
		})
	})
})
