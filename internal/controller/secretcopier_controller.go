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

// SecretCopierReconciler reconciles a SecretCopier object
type SecretCopierReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
}

// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretcopiers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretcopiers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretcopiers/finalizers,verbs=update
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretimporters,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the SecretCopier object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/reconcile
func (r *SecretCopierReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the named SecretCopier object.

	var secretCopier secretsv1beta1.SecretCopier

	if err := r.Get(ctx, req.NamespacedName, &secretCopier); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Custom resource has been deleted. We can ignore this because if
			// any secrets had been created, they will be automatically deleted
			// when necessary by the garbage collector since we will add the
			// secret copier as an owner reference to the secret if the reclaim
			// policy is marked as Delete.

			log.V(1).Info("SecretCopier has been deleted", "name", req.NamespacedName)

			return ctrl.Result{}, nil
		}

		// Error reading the object. Requeue the request and see if things will
		// resolve themselves on the next reconciliation loop.

		log.Error(err, "Unable to fetch SecretCopier", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	// Being deleted: there are no finalizers and copies are garbage-collected via
	// owner references, so there is nothing to do; skip rather than do work and
	// fight the deletion with a status update.
	if !secretCopier.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	log.V(1).Info("Fetched SecretCopier", "secretCopier", &secretCopier)

	// If there are no rules defined, there is nothing to do.

	if len(secretCopier.Spec.Rules) == 0 {
		log.V(1).Info("No rules to process for SecretCopier", "name", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// Query the set of namespaces in the Kubernetes cluster and filter out
	// those in the terminating state. We still need to deal with errors if we
	// can't later create a secret in a namespace that is terminating, but skip
	// what we can for now to avoid noise in the logs.

	namespaces := &corev1.NamespaceList{}

	err := r.List(ctx, namespaces, &client.ListOptions{})

	if err != nil {
		log.Error(err, "Unable to list namespaces")
		return ctrl.Result{}, err
	}

	activeNamespaces := copyengine.FilterActiveNamespaces(namespaces.Items)

	// Generate a list of just the names of the active namespaces so we can log
	// them for debugging.

	activeNamespaceNames := make([]string, 0)
	activeNamespaceSet := make(map[string]struct{}, len(activeNamespaces))

	for _, namespace := range activeNamespaces {
		activeNamespaceNames = append(activeNamespaceNames, namespace.Name)
		activeNamespaceSet[namespace.Name] = struct{}{}
	}

	log.V(1).Info("Active namespaces", "namespaces", activeNamespaceNames)

	// Iterate over the set of rules defined for the SecretCopier object and
	// determine which target namespaces match the rule, copying the source
	// secret into each while accumulating an outcome summary for the status.
	// The status records counts only, never the individual target namespaces,
	// so its size is bounded by the number of rules rather than the size of the
	// cluster.

	prevDegraded := conditionStatus(secretCopier.Status.Conditions, secretsv1beta1.ConditionDegraded)

	status := secretsv1beta1.SecretCopierStatus{
		ObservedGeneration: secretCopier.Generation,
		Conditions:         secretCopier.Status.Conditions, // seed so transition times are preserved
	}

	for i := range secretCopier.Spec.Rules {
		rule := secretCopier.Spec.Rules[i]

		ruleStatus := secretsv1beta1.RuleStatus{
			SourceSecret: rule.SourceSecret.Namespace + "/" + rule.SourceSecret.Name,
		}

		// If the source namespace is terminating or gone it has been filtered out
		// of the active set. The source secret is therefore being torn down with
		// it, so skip without fetching: there is nothing to copy, and we must not
		// copy from a source secret that still lingers in a terminating namespace.
		// The rule is still recorded with sourceExists=false so the status
		// reflects that the source is gone.

		if _, active := activeNamespaceSet[rule.SourceSecret.Namespace]; !active {
			status.Rules = append(status.Rules, ruleStatus)
			continue
		}

		// Fetch the source secret once for the rule. If it does not exist there
		// is nothing to copy; if it cannot be read that is a failure.

		var source corev1.Secret

		err := r.Get(ctx, client.ObjectKey{Namespace: rule.SourceSecret.Namespace, Name: rule.SourceSecret.Name}, &source)

		switch {
		case err != nil && client.IgnoreNotFound(err) == nil:
			// The source secret does not exist. This is a normal, expected state
			// (the source has not been created yet, or has been deleted), not an
			// error, so it is not logged: the rule is recorded with
			// sourceExists=false, which is where this is observable.
			status.Rules = append(status.Rules, ruleStatus)
			continue
		case err != nil:
			log.Error(err, "Unable to fetch source secret", "sourceSecret", rule.SourceSecret)
			ruleStatus.Failures++
			status.Summary.Failures++
			status.Rules = append(status.Rules, ruleStatus)
			continue
		}

		ruleStatus.SourceExists = true

		for j := range activeNamespaces {
			namespace := activeNamespaces[j]

			if namespace.Name == rule.SourceSecret.Namespace || !rule.TargetNamespaces.Matches(&namespace) {
				continue
			}

			log.V(1).Info("Matched target Namespace against SecretCopier", "name", req.NamespacedName, "rule", rule, "namespace", namespace.Name)

			ruleStatus.TargetNamespaces++

			switch r.copySecretToNamespace(ctx, &secretCopier, &rule, &source, namespace.Name) {
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

	// Derive the resource conditions from the aggregate failure count, then
	// write the status back, but only when it has actually changed so the
	// periodic requeue below does not churn the resourceVersion every sync.

	if status.Summary.Failures == 0 {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionReady,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: secretCopier.Generation,
			Reason:             "AllSecretsInSync",
			Message:            fmt.Sprintf("%d secret(s) in sync across %d namespace match(es)", status.Summary.SecretsInSync, status.Summary.TargetNamespaces),
		})
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionDegraded,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: secretCopier.Generation,
			Reason:             "NoFailures",
			Message:            "All copies succeeded",
		})
	} else {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: secretCopier.Generation,
			Reason:             "CopyFailures",
			Message:            fmt.Sprintf("%d copy failure(s)", status.Summary.Failures),
		})
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionDegraded,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: secretCopier.Generation,
			Reason:             "CopyFailures",
			Message:            fmt.Sprintf("%d secret(s) could not be copied", status.Summary.Failures),
		})
	}

	if !equality.Semantic.DeepEqual(secretCopier.Status, status) {
		secretCopier.Status = status

		if err := r.Status().Update(ctx, &secretCopier); err != nil {
			if !apierrors.IsConflict(err) {
				log.Error(err, "Unable to update SecretCopier status", "name", req.NamespacedName)
				return ctrl.Result{}, err
			}

			// The object was modified by a concurrent reconcile. That pass saw
			// the same cluster state and computed the same status, so the
			// conflict is benign; fall through and requeue as normal.

			log.V(1).Info("Conflict updating SecretCopier status; another reconcile won, continuing", "name", req.NamespacedName)
		}
	}

	recordDegradedTransition(r.Recorder, &secretCopier, "Copy", prevDegraded, status.Conditions)

	// Convergence is event-driven (watches cover source secrets, namespaces,
	// importers, and target secrets); the fixed backstop requeue only bounds
	// the staleness caused by a missed event.

	return ctrl.Result{RequeueAfter: backstopRequeue}, nil
}

// SetupWithManager sets up the controller with the Manager. Convergence is
// event-driven: secrets are watched (metadata only) both as rule sources and as
// copy targets, namespaces for new/changed match candidates, and importers so a
// copy gated by copyAuthorization proceeds as soon as its importer appears.
func (r *SecretCopierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Only reconcile on spec changes (generation bumps), not on our own
		// status writes, which would otherwise trigger a redundant reconcile.
		For(&secretsv1beta1.SecretCopier{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findSecretCopiersForSecret),
			builder.OnlyMetadata,
		).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.findSecretCopiersMatchingTargetNamespace),
		).
		Watches(
			&secretsv1beta1.SecretImporter{},
			handler.EnqueueRequestsFromMapFunc(r.findSecretCopiersForImporter),
		).
		Named("secretcopier").
		Complete(r)
}

// findSecretCopiersForSecret enqueues copiers for which the changed secret is a
// rule's source, or carries a rule's effective target name. The source match
// triggers copies when sources appear or change; the target-name match makes
// target deletion, tampering and conflict clearance (a foreign secret occupying
// the target name being removed) event-driven. Matching by name rather than by
// the managed-by annotation may over-enqueue (a same-named secret in a
// non-target namespace causes a no-op reconcile), which is harmless. The watch
// delivers metadata only, so only ObjectMeta accessors may be used here.
func (r *SecretCopierReconciler) findSecretCopiersForSecret(ctx context.Context, secret client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	// Fetch the list of SecretCopier objects.

	var secretCopiers secretsv1beta1.SecretCopierList

	err := r.List(ctx, &secretCopiers, &client.ListOptions{})

	if err != nil {
		log.Error(err, "Unable to list SecretCopier objects")
		return nil
	}

	// Iterate over the list of SecretCopier objects and determine if any match
	// on it as a source secret or by effective target name.

	var requests []reconcile.Request

	for _, secretCopier := range secretCopiers.Items {
		for _, rule := range secretCopier.Spec.Rules {
			sourceMatch := rule.SourceSecret.Name == secret.GetName() && rule.SourceSecret.Namespace == secret.GetNamespace()

			targetName := rule.TargetSecret.Name
			if targetName == "" {
				targetName = rule.SourceSecret.Name
			}
			targetMatch := targetName == secret.GetName()

			if sourceMatch || targetMatch {
				log.V(1).Info("Queue reconcile for Secret against SecretCopier", "name", secretCopier.Name, "secret", secret.GetName(), "namespace", secret.GetNamespace())

				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&secretCopier)})

				// We only need to match on one rule for the secret, so break out
				// of the loop once we have found one.

				break
			}
		}
	}

	return requests
}

// findSecretCopiersForImporter enqueues copiers having a rule whose effective
// target secret name matches the changed importer, so a copy held in
// AwaitingAuthorization proceeds as soon as a matching importer appears or is
// corrected, without waiting for the backstop.
func (r *SecretCopierReconciler) findSecretCopiersForImporter(ctx context.Context, object client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	var secretCopiers secretsv1beta1.SecretCopierList

	if err := r.List(ctx, &secretCopiers, &client.ListOptions{}); err != nil {
		log.Error(err, "Unable to list SecretCopier objects")
		return nil
	}

	var requests []reconcile.Request

	for _, secretCopier := range secretCopiers.Items {
		for _, rule := range secretCopier.Spec.Rules {
			targetName := rule.TargetSecret.Name
			if targetName == "" {
				targetName = rule.SourceSecret.Name
			}

			if targetName == object.GetName() {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&secretCopier)})
				break
			}
		}
	}

	return requests
}

// Handler function to find SecretCopier objects that match a target namespace.
// This is used to trigger a reconciliation of the SecretCopier object when a
// namespace is created. This is necessary as we need to determine if the
// namespace is one that the SecretCopier is interested in and copy secrets to
// it if it is.
func (r *SecretCopierReconciler) findSecretCopiersMatchingTargetNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	// Convert the object to a Namespace object.

	namespace, ok := object.(*corev1.Namespace)

	if !ok {
		log.Error(nil, "Object is not a Namespace", "object", object)
		return nil
	}

	// Fetch the list of SecretCopier objects.

	var secretCopiers secretsv1beta1.SecretCopierList

	err := r.List(ctx, &secretCopiers, &client.ListOptions{})

	if err != nil {
		log.Error(err, "Unable to list SecretCopier objects")
		return nil
	}

	// Iterate over the list of SecretCopier objects and determine if any match
	// on it as the target namespace. Make sure the source and target namespaces
	// are different as we don't need to copy a secret to the same namespace it
	// is in.

	var requests []reconcile.Request

	for _, secretCopier := range secretCopiers.Items {
		for _, rule := range secretCopier.Spec.Rules {
			if rule.SourceSecret.Namespace != namespace.Name && rule.TargetNamespaces.Matches(namespace) {
				log.V(1).Info("Queue reconcile for target Namespace against SecretCopier", "name", secretCopier.Name, "rule", rule, "namespace", namespace.GetName())

				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&secretCopier)})

				// We only need to match on one rule for the namespace, so break
				// out of the loop once we have found one.

				break
			}
		}
	}

	return requests
}

// copySecretToNamespace translates a SecretCopier rule and its already-fetched
// source secret into a copy request for the shared copy engine, then runs it.
// The controller owns the SecretCopier-specific decisions — the target name
// (defaulting to the source name), the tracking identity stamped on copies, and
// the owner reference derived from the reclaim policy — while the engine
// performs the create/update/skip and reports the outcome.
func (r *SecretCopierReconciler) copySecretToNamespace(ctx context.Context, secretCopier *secretsv1beta1.SecretCopier, rule *secretsv1beta1.SecretCopierRule, secret *corev1.Secret, targetNamespace string) copyengine.Outcome {
	sourceSecret := rule.SourceSecret

	// Determine the target secret name, defaulting to the source secret name.

	targetSecretName := rule.TargetSecret.Name

	if targetSecretName == "" {
		targetSecretName = sourceSecret.Name
	}

	// Resolve any SecretImporter gating the copy into the target namespace. A
	// SecretCopier owns its own copies, so the importer here only authorizes the
	// copy (its shared secret and source-namespace constraints); it does not
	// become the owner. With no copyAuthorization and no importer present this
	// is a no-op that authorizes the copy.

	_, authorized, err := authorizeCopyTarget(ctx, r.Client, targetNamespace, targetSecretName, sourceSecret.Namespace, rule.CopyAuthorization.SharedSecret)

	if err != nil {
		logf.FromContext(ctx).Error(err, "Unable to read SecretImporter for copy authorization", "targetSecret", targetSecretName, "targetNamespace", targetNamespace)
		return copyengine.Failed
	}

	// When the reclaim policy is Delete, make the SecretCopier the owner of the
	// copy so the garbage collector removes it when the SecretCopier is deleted.

	var ownerReferences []metav1.OwnerReference

	if rule.ReclaimPolicy == secretsv1beta1.ReclaimDelete {
		ownerReferences = append(ownerReferences, metav1.OwnerReference{
			APIVersion:         secretCopier.APIVersion,
			Kind:               secretCopier.Kind,
			Name:               secretCopier.Name,
			UID:                secretCopier.UID,
			Controller:         ptr.To(true),
			BlockOwnerDeletion: ptr.To(true),
		})
	}

	engine := copyengine.Engine{Client: r.Client}

	return engine.CopySecret(ctx, copyengine.Request{
		Source:          secret,
		SourceNamespace: sourceSecret.Namespace,
		SourceName:      sourceSecret.Name,
		TargetNamespace: targetNamespace,
		TargetName:      targetSecretName,
		TargetLabels:    rule.TargetSecret.Labels,
		ManagedByValue:  "secretcopier/" + secretCopier.Name,
		OwnerReferences: ownerReferences,
		Authorize:       func(context.Context) bool { return authorized },
	})
}
