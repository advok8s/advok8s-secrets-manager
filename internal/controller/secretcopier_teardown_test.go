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
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
)

// When a rule's source namespace is terminating or gone it is filtered out of
// the active namespace set, so the source secret is being torn down with it.
// The reconciler should skip such a rule without even fetching the source
// secret (an unnecessary check that only produces teardown log noise), while
// still recording the rule with sourceExists=false. When the source namespace
// is active, a missing source secret is a real condition worth checking for, so
// the fetch must still happen.

// countingSourceGets builds a fake client that counts Get calls for a source
// secret of the given name, delegating through to the real fake behaviour.
func countingSourceGets(scheme *runtime.Scheme, sourceName string, count *int, objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&secretsv1beta1.SecretCopier{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Secret); ok && key.Name == sourceName {
					*count++
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
}

func TestReconcileSkipsSourceFetchWhenSourceNamespaceGone(t *testing.T) {
	scheme := deletionTestScheme(t)

	copier := &secretsv1beta1.SecretCopier{
		ObjectMeta: metav1.ObjectMeta{Name: "copier", Generation: 1},
		Spec: secretsv1beta1.SecretCopierSpec{
			Rules: []secretsv1beta1.SecretCopierRule{{
				SourceSecret: secretsv1beta1.SourceSecret{Name: "registry-credentials", Namespace: "gone-source-ns"},
			}},
		},
	}

	// No Namespace object exists for gone-source-ns, so it is absent from the
	// active set - the same as it being terminating.
	gets := 0
	c := countingSourceGets(scheme, "registry-credentials", &gets, copier)

	r := &SecretCopierReconciler{Client: c, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), requestFor(copier)); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if gets != 0 {
		t.Errorf("source secret was fetched %d time(s); expected 0 when source namespace is gone", gets)
	}

	var got secretsv1beta1.SecretCopier
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(copier), &got); err != nil {
		t.Fatalf("get copier: %v", err)
	}
	if len(got.Status.Rules) != 1 || got.Status.Rules[0].SourceExists {
		t.Errorf("expected one rule with sourceExists=false, got %+v", got.Status.Rules)
	}
	if got.Status.Summary.Failures != 0 {
		t.Errorf("expected no failures for a torn-down source, got %d", got.Status.Summary.Failures)
	}
}

func TestReconcileFetchesSourceWhenNamespaceActive(t *testing.T) {
	scheme := deletionTestScheme(t)

	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "live-source-ns"}}
	copier := &secretsv1beta1.SecretCopier{
		ObjectMeta: metav1.ObjectMeta{Name: "copier", Generation: 1},
		Spec: secretsv1beta1.SecretCopierSpec{
			Rules: []secretsv1beta1.SecretCopierRule{{
				SourceSecret: secretsv1beta1.SourceSecret{Name: "registry-credentials", Namespace: "live-source-ns"},
			}},
		},
	}

	// The namespace is active but the source secret does not exist: a real
	// missing-source condition the reconciler should still check for.
	gets := 0
	c := countingSourceGets(scheme, "registry-credentials", &gets, namespace, copier)

	r := &SecretCopierReconciler{Client: c, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), requestFor(copier)); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if gets != 1 {
		t.Errorf("source secret was fetched %d time(s); expected 1 when source namespace is active", gets)
	}

	var got secretsv1beta1.SecretCopier
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(copier), &got); err != nil {
		t.Fatalf("get copier: %v", err)
	}
	if len(got.Status.Rules) != 1 || got.Status.Rules[0].SourceExists {
		t.Errorf("expected one rule with sourceExists=false, got %+v", got.Status.Rules)
	}
}
