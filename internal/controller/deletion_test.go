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
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// When a custom resource has been marked for deletion, reconcilers should skip
// it: there are no finalizers and nothing to clean up, so doing work (and in
// particular writing status) would only fight the deletion. These are plain Go
// tests using a fake client. A finalizer is set on each object so the fake
// retains it with a deletion timestamp rather than removing it immediately,
// which is the window the guard is there to handle.

func deletionTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add client-go scheme: %v", err)
	}
	if err := secretsv1beta1.AddToScheme(scheme); err != nil {
		t.Fatalf("add secrets scheme: %v", err)
	}

	return scheme
}

// deleting returns object metadata marked for deletion, with a finalizer so a
// fake client retains the object instead of removing it on create.
func deleting(name, namespace string) metav1.ObjectMeta {
	deletionTime := metav1.Time{Time: metav1.Now().Time}

	return metav1.ObjectMeta{
		Name:              name,
		Namespace:         namespace,
		Generation:        1,
		DeletionTimestamp: &deletionTime,
		Finalizers:        []string{"test.advok8s.io/retain"},
	}
}

func requestFor(obj client.Object) ctrl.Request {
	return ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
}

func TestReconcileSkipsDeletedSecretCopier(t *testing.T) {
	scheme := deletionTestScheme(t)

	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "src", Namespace: "source-ns"},
		Data:       map[string][]byte{"k": []byte("v")},
	}
	copier := &secretsv1beta1.SecretCopier{
		ObjectMeta: deleting("being-deleted", ""),
		Spec: secretsv1beta1.SecretCopierSpec{
			Rules: []secretsv1beta1.SecretCopierRule{{
				SourceSecret: secretsv1beta1.SourceSecret{Name: "src", Namespace: "source-ns"},
			}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(source, copier).
		WithStatusSubresource(copier).
		Build()

	r := &SecretCopierReconciler{Client: c, Scheme: scheme}

	result, err := r.Reconcile(context.Background(), requestFor(copier))
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if result != (reconcile.Result{}) {
		t.Errorf("expected empty result, got %+v", result)
	}

	var got secretsv1beta1.SecretCopier
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(copier), &got); err != nil {
		t.Fatalf("get copier: %v", err)
	}
	if got.Status.ObservedGeneration != 0 || len(got.Status.Conditions) != 0 {
		t.Errorf("status was written for a deleted copier: %+v", got.Status)
	}
}

func TestReconcileSkipsDeletedSecretExporter(t *testing.T) {
	scheme := deletionTestScheme(t)

	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "exp", Namespace: "exp-ns"},
		Data:       map[string][]byte{"k": []byte("v")},
	}
	exporter := &secretsv1beta1.SecretExporter{
		ObjectMeta: deleting("exp", "exp-ns"),
		Spec: secretsv1beta1.SecretExporterSpec{
			Rules: []secretsv1beta1.SecretExporterRule{{}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(source, exporter).
		WithStatusSubresource(exporter).
		Build()

	r := &SecretExporterReconciler{Client: c, Scheme: scheme}

	result, err := r.Reconcile(context.Background(), requestFor(exporter))
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if result != (reconcile.Result{}) {
		t.Errorf("expected empty result, got %+v", result)
	}

	var got secretsv1beta1.SecretExporter
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(exporter), &got); err != nil {
		t.Fatalf("get exporter: %v", err)
	}
	if got.Status.ObservedGeneration != 0 || len(got.Status.Conditions) != 0 {
		t.Errorf("status was written for a deleted exporter: %+v", got.Status)
	}
}

func TestReconcileSkipsDeletedSecretImporter(t *testing.T) {
	scheme := deletionTestScheme(t)

	importer := &secretsv1beta1.SecretImporter{
		ObjectMeta: deleting("imp", "imp-ns"),
		Spec: secretsv1beta1.SecretImporterSpec{
			CopyAuthorization: secretsv1beta1.CopyAuthorization{SharedSecret: "s"},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(importer).
		WithStatusSubresource(importer).
		Build()

	r := &SecretImporterReconciler{Client: c, Scheme: scheme}

	result, err := r.Reconcile(context.Background(), requestFor(importer))
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if result != (reconcile.Result{}) {
		t.Errorf("expected empty result, got %+v", result)
	}

	var got secretsv1beta1.SecretImporter
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(importer), &got); err != nil {
		t.Fatalf("get importer: %v", err)
	}
	if got.Status.ObservedGeneration != 0 || len(got.Status.Conditions) != 0 {
		t.Errorf("status was written for a deleted importer: %+v", got.Status)
	}
}

func TestReconcileSkipsDeletedSecretInjector(t *testing.T) {
	scheme := deletionTestScheme(t)

	injector := &secretsv1beta1.SecretInjector{
		ObjectMeta: deleting("being-deleted", ""),
		Spec: secretsv1beta1.SecretInjectorSpec{
			Rules: []secretsv1beta1.SecretInjectorRule{{}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(injector).
		WithStatusSubresource(injector).
		Build()

	r := &SecretInjectorReconciler{Client: c, Scheme: scheme}

	result, err := r.Reconcile(context.Background(), requestFor(injector))
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if result != (reconcile.Result{}) {
		t.Errorf("expected empty result, got %+v", result)
	}

	var got secretsv1beta1.SecretInjector
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(injector), &got); err != nil {
		t.Fatalf("get injector: %v", err)
	}
	if got.Status.ObservedGeneration != 0 || len(got.Status.Conditions) != 0 {
		t.Errorf("status was written for a deleted injector: %+v", got.Status)
	}
}
