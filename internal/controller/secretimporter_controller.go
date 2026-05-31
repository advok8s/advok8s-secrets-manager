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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
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

// SecretImporterReconciler reconciles a SecretImporter object. A SecretImporter
// performs no copying itself - it authorizes a paired SecretExporter or
// SecretCopier to copy a secret into its namespace. This reconciler exists only
// to report observable status: whether the requested secret has been imported,
// and what is exporting it.
type SecretImporterReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretimporters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretimporters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretimporters/finalizers,verbs=update
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretexporters,verbs=get;list;watch
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretcopiers,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile computes the observed status of a SecretImporter.
func (r *SecretImporterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var importer secretsv1beta1.SecretImporter

	if err := r.Get(ctx, req.NamespacedName, &importer); err != nil {
		if client.IgnoreNotFound(err) == nil {
			log.V(1).Info("SecretImporter has been deleted", "name", req.NamespacedName)
			return ctrl.Result{}, nil
		}

		log.Error(err, "Unable to fetch SecretImporter", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	// Being deleted: this reconciler only reports status and registers no
	// finalizers, so there is nothing to do; skip rather than fight the deletion
	// with a status update.
	if !importer.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	// The importer manages the secret named the same as itself, in its own
	// namespace.

	prevReady := conditionStatus(importer.Status.Conditions, secretsv1beta1.ConditionReady)

	status := secretsv1beta1.SecretImporterStatus{
		ObservedGeneration: importer.Generation,
		Conditions:         importer.Status.Conditions,
		TargetSecretName:   importer.Name,
	}

	// Determine whether the secret has been imported: a secret of the importer's
	// name exists in its namespace and is one of our managed copies.

	var secret corev1.Secret

	secretErr := r.Get(ctx, client.ObjectKey{Namespace: importer.Namespace, Name: importer.Name}, &secret)

	switch {
	case secretErr != nil && client.IgnoreNotFound(secretErr) != nil:
		log.Error(secretErr, "Unable to fetch imported secret", "name", req.NamespacedName)
		return ctrl.Result{}, secretErr
	case secretErr == nil && secret.Annotations[copyengine.AnnotationManagedBy] != "":
		status.Imported = true
		status.BoundTo = boundToDescription(&secret)
	}

	r.setReady(ctx, &status, &importer)

	if !equality.Semantic.DeepEqual(importer.Status, status) {
		importer.Status = status

		if err := r.Status().Update(ctx, &importer); err != nil {
			if !apierrors.IsConflict(err) {
				log.Error(err, "Unable to update SecretImporter status", "name", req.NamespacedName)
				return ctrl.Result{}, err
			}

			log.V(1).Info("Conflict updating SecretImporter status; another reconcile won, continuing", "name", req.NamespacedName)
		}
	}

	recordImportedTransition(r.Recorder, &importer, prevReady, status.Conditions)

	return ctrl.Result{}, nil
}

// setReady sets the Ready condition: True when imported, otherwise False with a
// reason that distinguishes "something is exporting but the copy has not yet
// arrived" from "nothing is exporting to me".
func (r *SecretImporterReconciler) setReady(ctx context.Context, status *secretsv1beta1.SecretImporterStatus, importer *secretsv1beta1.SecretImporter) {
	condition := metav1.Condition{
		Type:               secretsv1beta1.ConditionReady,
		ObservedGeneration: importer.Generation,
	}

	switch {
	case status.Imported:
		condition.Status = metav1.ConditionTrue
		condition.Reason = "Imported"
		condition.Message = "Secret imported from " + status.BoundTo
	case r.hasMatchingExportOrCopy(ctx, importer):
		condition.Status = metav1.ConditionFalse
		condition.Reason = "AwaitingAuthorization"
		condition.Message = "A rule targets this namespace but the secret has not been copied (check the shared secret and that the source secret exists)"
	default:
		condition.Status = metav1.ConditionFalse
		condition.Reason = "NoMatchingExporter"
		condition.Message = "No SecretExporter or SecretCopier currently targets this namespace with this name"
	}

	meta.SetStatusCondition(&status.Conditions, condition)
}

// hasMatchingExportOrCopy reports whether some SecretExporter or SecretCopier
// rule targets the importer's namespace with the importer's name as the target
// secret name, regardless of whether authorization currently succeeds.
func (r *SecretImporterReconciler) hasMatchingExportOrCopy(ctx context.Context, importer *secretsv1beta1.SecretImporter) bool {
	log := logf.FromContext(ctx)

	var namespace corev1.Namespace

	if err := r.Get(ctx, client.ObjectKey{Name: importer.Namespace}, &namespace); err != nil {
		log.V(1).Info("Unable to fetch namespace for SecretImporter status", "namespace", importer.Namespace)
		return false
	}

	var exporters secretsv1beta1.SecretExporterList

	if err := r.List(ctx, &exporters, &client.ListOptions{}); err == nil {
		for _, exporter := range exporters.Items {
			if exporter.Namespace == importer.Namespace {
				continue
			}

			for _, rule := range exporter.Spec.Rules {
				targetName := rule.TargetSecret.Name
				if targetName == "" {
					targetName = exporter.Name
				}

				if targetName == importer.Name && rule.TargetNamespaces.Matches(&namespace) {
					return true
				}
			}
		}
	}

	var copiers secretsv1beta1.SecretCopierList

	if err := r.List(ctx, &copiers, &client.ListOptions{}); err == nil {
		for _, copier := range copiers.Items {
			for _, rule := range copier.Spec.Rules {
				targetName := rule.TargetSecret.Name
				if targetName == "" {
					targetName = rule.SourceSecret.Name
				}

				if targetName == importer.Name && rule.SourceSecret.Namespace != importer.Namespace && rule.TargetNamespaces.Matches(&namespace) {
					return true
				}
			}
		}
	}

	return false
}

// boundToDescription derives a human-readable identifier of what exported a
// secret, from the tracking annotations on the imported copy.
func boundToDescription(secret *corev1.Secret) string {
	owner := secret.Annotations[copyengine.AnnotationManagedBy]
	source := secret.Annotations[copyengine.AnnotationSourceSecret]

	if source != "" {
		return owner + " (" + source + ")"
	}

	return owner
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretImporterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Only reconcile on spec changes, not on our own status writes; secret,
		// exporter and copier changes still come through the watches below.
		For(&secretsv1beta1.SecretImporter{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findImporterForSecret),
		).
		Watches(
			&secretsv1beta1.SecretExporter{},
			handler.EnqueueRequestsFromMapFunc(r.findImportersForExporter),
		).
		Watches(
			&secretsv1beta1.SecretCopier{},
			handler.EnqueueRequestsFromMapFunc(r.findImportersForCopier),
		).
		Named("secretimporter").
		Complete(r)
}

// findImporterForSecret enqueues the importer named the same as a changed secret
// in the same namespace, so its imported status tracks the copy arriving or
// being removed. Most secrets in a cluster have no like-named importer, so it
// only enqueues when one actually exists - otherwise every secret event would
// trigger a no-op reconcile. The lookup is served from the controller's cache.
func (r *SecretImporterReconciler) findImporterForSecret(ctx context.Context, secret client.Object) []reconcile.Request {
	key := client.ObjectKey{Namespace: secret.GetNamespace(), Name: secret.GetName()}

	if err := r.Get(ctx, key, &secretsv1beta1.SecretImporter{}); err != nil {
		return nil
	}

	return []reconcile.Request{{NamespacedName: key}}
}

// findImportersForExporter enqueues importers whose name matches an effective
// target secret name of the changed exporter.
func (r *SecretImporterReconciler) findImportersForExporter(ctx context.Context, object client.Object) []reconcile.Request {
	exporter, ok := object.(*secretsv1beta1.SecretExporter)
	if !ok {
		return nil
	}

	names := make(map[string]struct{})
	for _, rule := range exporter.Spec.Rules {
		name := rule.TargetSecret.Name
		if name == "" {
			name = exporter.Name
		}
		names[name] = struct{}{}
	}

	return r.importersWithNames(ctx, names)
}

// findImportersForCopier enqueues importers whose name matches an effective
// target secret name of the changed copier.
func (r *SecretImporterReconciler) findImportersForCopier(ctx context.Context, object client.Object) []reconcile.Request {
	copier, ok := object.(*secretsv1beta1.SecretCopier)
	if !ok {
		return nil
	}

	names := make(map[string]struct{})
	for _, rule := range copier.Spec.Rules {
		name := rule.TargetSecret.Name
		if name == "" {
			name = rule.SourceSecret.Name
		}
		names[name] = struct{}{}
	}

	return r.importersWithNames(ctx, names)
}

// importersWithNames lists all importers and returns reconcile requests for
// those whose name is in the given set.
func (r *SecretImporterReconciler) importersWithNames(ctx context.Context, names map[string]struct{}) []reconcile.Request {
	log := logf.FromContext(ctx)

	if len(names) == 0 {
		return nil
	}

	var importers secretsv1beta1.SecretImporterList

	if err := r.List(ctx, &importers, &client.ListOptions{}); err != nil {
		log.Error(err, "Unable to list SecretImporter objects")
		return nil
	}

	var requests []reconcile.Request

	for _, importer := range importers.Items {
		if _, ok := names[importer.Name]; ok {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&importer)})
		}
	}

	return requests
}
