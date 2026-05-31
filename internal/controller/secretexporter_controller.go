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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
	"github.com/advok8s/advok8s-secrets-manager/internal/copyengine"
)

// SecretExporterReconciler reconciles a SecretExporter object. A SecretExporter
// copies the secret named the same as itself, from its own namespace, into the
// target namespaces named by its rules. Each copy requires a paired
// SecretImporter in the target namespace (which becomes the owner of the copy),
// so the copy is always created with the Delete reclaim behaviour.
type SecretExporterReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
}

// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretexporters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretexporters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretexporters/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile copies the exporter's secret into the namespaces matched by its
// rules, subject to a matching SecretImporter authorizing each copy.
func (r *SecretExporterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var exporter secretsv1beta1.SecretExporter

	if err := r.Get(ctx, req.NamespacedName, &exporter); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Deleted. Copies are owned by their SecretImporters, so the garbage
			// collector deals with them; nothing to do here.
			log.V(1).Info("SecretExporter has been deleted", "name", req.NamespacedName)
			return ctrl.Result{}, nil
		}

		log.Error(err, "Unable to fetch SecretExporter", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	// Being deleted: there are no finalizers and copies are garbage-collected via
	// their SecretImporter owners, so there is nothing to do; skip rather than do
	// work and fight the deletion with a status update.
	if !exporter.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	prevDegraded := conditionStatus(exporter.Status.Conditions, secretsv1beta1.ConditionDegraded)

	status := secretsv1beta1.SecretExporterStatus{
		ObservedGeneration: exporter.Generation,
		Conditions:         exporter.Status.Conditions,
	}

	// The source secret is the secret named the same as the exporter, in the
	// exporter's own namespace.

	var source corev1.Secret

	sourceErr := r.Get(ctx, client.ObjectKey{Namespace: exporter.Namespace, Name: exporter.Name}, &source)

	switch {
	case sourceErr != nil && client.IgnoreNotFound(sourceErr) != nil:
		log.Error(sourceErr, "Unable to fetch source secret for SecretExporter", "name", req.NamespacedName)
		return ctrl.Result{}, sourceErr
	case sourceErr == nil:
		status.SourceExists = true
	}

	// Only attempt copies when the source secret exists and there are rules.

	if status.SourceExists && len(exporter.Spec.Rules) > 0 {
		namespaces := &corev1.NamespaceList{}

		if err := r.List(ctx, namespaces, &client.ListOptions{}); err != nil {
			log.Error(err, "Unable to list namespaces")
			return ctrl.Result{}, err
		}

		activeNamespaces := copyengine.FilterActiveNamespaces(namespaces.Items)

		for i := range exporter.Spec.Rules {
			rule := exporter.Spec.Rules[i]

			ruleStatus := secretsv1beta1.SecretExporterCounts{}

			for j := range activeNamespaces {
				namespace := activeNamespaces[j]

				if namespace.Name == exporter.Namespace || !rule.TargetNamespaces.Matches(&namespace) {
					continue
				}

				ruleStatus.TargetNamespaces++

				switch r.copySecretToNamespace(ctx, &exporter, &rule, &source, namespace.Name) {
				case copyengine.InSync:
					ruleStatus.SecretsInSync++
				case copyengine.Conflict:
					ruleStatus.Conflicts++
				case copyengine.AwaitingAuthorization:
					ruleStatus.AwaitingAuthorization++
				case copyengine.Failed:
					ruleStatus.Failures++
				case copyengine.Skipped:
				}
			}

			status.Summary.TargetNamespaces += ruleStatus.TargetNamespaces
			status.Summary.SecretsInSync += ruleStatus.SecretsInSync
			status.Summary.Conflicts += ruleStatus.Conflicts
			status.Summary.AwaitingAuthorization += ruleStatus.AwaitingAuthorization
			status.Summary.Failures += ruleStatus.Failures
			status.Rules = append(status.Rules, ruleStatus)
		}
	}

	r.setConditions(&status, &exporter)

	if !equality.Semantic.DeepEqual(exporter.Status, status) {
		exporter.Status = status

		if err := r.Status().Update(ctx, &exporter); err != nil {
			if !apierrors.IsConflict(err) {
				log.Error(err, "Unable to update SecretExporter status", "name", req.NamespacedName)
				return ctrl.Result{}, err
			}

			log.V(1).Info("Conflict updating SecretExporter status; another reconcile won, continuing", "name", req.NamespacedName)
		}
	}

	recordDegradedTransition(r.Recorder, &exporter, "Export", prevDegraded, status.Conditions)

	if exporter.Spec.SyncPeriod != nil && exporter.Spec.SyncPeriod.Duration > 0 {
		return ctrl.Result{RequeueAfter: exporter.Spec.SyncPeriod.Duration}, nil
	}

	return ctrl.Result{}, nil
}

// setConditions derives the Ready and Degraded conditions from the reconcile
// outcome recorded in status.
func (r *SecretExporterReconciler) setConditions(status *secretsv1beta1.SecretExporterStatus, exporter *secretsv1beta1.SecretExporter) {
	switch {
	case !status.SourceExists:
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: exporter.Generation,
			Reason:             "SourceSecretNotFound",
			Message:            fmt.Sprintf("No secret named %q in namespace %q to export", exporter.Name, exporter.Namespace),
		})
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionDegraded,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: exporter.Generation,
			Reason:             "SourceSecretNotFound",
			Message:            "Nothing to export",
		})
	case status.Summary.Failures > 0:
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: exporter.Generation,
			Reason:             "CopyFailures",
			Message:            fmt.Sprintf("%d copy failure(s)", status.Summary.Failures),
		})
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionDegraded,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: exporter.Generation,
			Reason:             "CopyFailures",
			Message:            fmt.Sprintf("%d secret(s) could not be copied", status.Summary.Failures),
		})
	default:
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionReady,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: exporter.Generation,
			Reason:             "AllSecretsInSync",
			Message:            fmt.Sprintf("%d secret(s) in sync across %d namespace match(es), %d awaiting authorization", status.Summary.SecretsInSync, status.Summary.TargetNamespaces, status.Summary.AwaitingAuthorization),
		})
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionDegraded,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: exporter.Generation,
			Reason:             "NoFailures",
			Message:            "All copies succeeded",
		})
	}
}

// copySecretToNamespace authorizes and performs a single copy of the exporter's
// secret into one target namespace via the shared copy engine. Authorization
// requires a SecretImporter named the same as the target secret, carrying the
// rule's shared secret (defaulting to the exporter's UID when unset). When
// authorized, that importer becomes the owner of the copy.
func (r *SecretExporterReconciler) copySecretToNamespace(ctx context.Context, exporter *secretsv1beta1.SecretExporter, rule *secretsv1beta1.SecretExporterRule, secret *corev1.Secret, targetNamespace string) copyengine.Outcome {
	log := logf.FromContext(ctx)

	// The target secret defaults to the exporter's own name.

	targetSecretName := rule.TargetSecret.Name

	if targetSecretName == "" {
		targetSecretName = exporter.Name
	}

	// The shared secret the importer must carry defaults to the exporter's UID
	// when the rule does not specify one, so that an importer cannot be created
	// blindly - whoever creates it must know the exporter's UID.

	requiredSharedSecret := rule.CopyAuthorization.SharedSecret

	if requiredSharedSecret == "" {
		requiredSharedSecret = string(exporter.UID)
	}

	importer, authorized, err := authorizeCopyTarget(ctx, r.Client, targetNamespace, targetSecretName, exporter.Namespace, requiredSharedSecret)

	if err != nil {
		log.Error(err, "Unable to read SecretImporter for copy authorization", "targetSecret", targetSecretName, "targetNamespace", targetNamespace)
		return copyengine.Failed
	}

	// When authorized the importer (which always exists in that case, as a
	// shared secret is always required) owns the copy so it is garbage-collected
	// with the importer.

	var ownerReferences []metav1.OwnerReference

	if authorized && importer != nil {
		ownerReferences = append(ownerReferences, metav1.OwnerReference{
			APIVersion:         secretsv1beta1.GroupVersion.String(),
			Kind:               "SecretImporter",
			Name:               importer.Name,
			UID:                importer.UID,
			Controller:         ptr.To(true),
			BlockOwnerDeletion: ptr.To(true),
		})
	}

	engine := copyengine.Engine{Client: r.Client}

	return engine.CopySecret(ctx, copyengine.Request{
		Source:          secret,
		SourceNamespace: exporter.Namespace,
		SourceName:      exporter.Name,
		TargetNamespace: targetNamespace,
		TargetName:      targetSecretName,
		TargetLabels:    rule.TargetSecret.Labels,
		ManagedByValue:  "secretexporter/" + exporter.Name,
		OwnerReferences: ownerReferences,
		Authorize:       func(context.Context) bool { return authorized },
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretExporterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Only reconcile on spec changes, not on our own status writes.
		For(&secretsv1beta1.SecretExporter{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findExportersMatchingSourceSecret),
		).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.findExportersMatchingTargetNamespace),
		).
		Watches(
			&secretsv1beta1.SecretImporter{},
			handler.EnqueueRequestsFromMapFunc(r.findExportersForImporter),
		).
		Named("secretexporter").
		Complete(r)
}

// findExportersMatchingSourceSecret enqueues the exporter whose source secret
// (the secret named the same as the exporter, in its namespace) is this secret.
func (r *SecretExporterReconciler) findExportersMatchingSourceSecret(ctx context.Context, secret client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	var exporters secretsv1beta1.SecretExporterList

	if err := r.List(ctx, &exporters, &client.ListOptions{}); err != nil {
		log.Error(err, "Unable to list SecretExporter objects")
		return nil
	}

	var requests []reconcile.Request

	for _, exporter := range exporters.Items {
		if exporter.Namespace == secret.GetNamespace() && exporter.Name == secret.GetName() {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&exporter)})
		}
	}

	return requests
}

// findExportersMatchingTargetNamespace enqueues exporters with a rule whose
// target namespaces match the changed namespace.
func (r *SecretExporterReconciler) findExportersMatchingTargetNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	namespace, ok := object.(*corev1.Namespace)

	if !ok {
		log.Error(nil, "Object is not a Namespace", "object", object)
		return nil
	}

	var exporters secretsv1beta1.SecretExporterList

	if err := r.List(ctx, &exporters, &client.ListOptions{}); err != nil {
		log.Error(err, "Unable to list SecretExporter objects")
		return nil
	}

	var requests []reconcile.Request

	for _, exporter := range exporters.Items {
		for _, rule := range exporter.Spec.Rules {
			if exporter.Namespace != namespace.Name && rule.TargetNamespaces.Matches(namespace) {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&exporter)})
				break
			}
		}
	}

	return requests
}

// findExportersForImporter enqueues exporters that could copy into the changed
// importer's namespace under the importer's name (its target secret name), so a
// newly created or updated importer triggers any pending copy.
func (r *SecretExporterReconciler) findExportersForImporter(ctx context.Context, object client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	importer, ok := object.(*secretsv1beta1.SecretImporter)

	if !ok {
		log.Error(nil, "Object is not a SecretImporter", "object", object)
		return nil
	}

	var exporters secretsv1beta1.SecretExporterList

	if err := r.List(ctx, &exporters, &client.ListOptions{}); err != nil {
		log.Error(err, "Unable to list SecretExporter objects")
		return nil
	}

	var requests []reconcile.Request

	for _, exporter := range exporters.Items {
		for _, rule := range exporter.Spec.Rules {
			targetSecretName := rule.TargetSecret.Name
			if targetSecretName == "" {
				targetSecretName = exporter.Name
			}

			if targetSecretName == importer.Name {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&exporter)})
				break
			}
		}
	}

	return requests
}
