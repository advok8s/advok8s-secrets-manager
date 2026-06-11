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

// SecretInjectorReconciler reconciles a SecretInjector object. It injects
// references to matching secrets into matching service accounts within matching
// namespaces: image pull secrets into imagePullSecrets, other secret types into
// secrets. Injections are only added, never removed.
type SecretInjectorReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
}

// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretinjectors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretinjectors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretinjectors/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile injects secret references into the service accounts matched by the
// SecretInjector's rules.
func (r *SecretInjectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var injector secretsv1beta1.SecretInjector

	if err := r.Get(ctx, req.NamespacedName, &injector); err != nil {
		if client.IgnoreNotFound(err) == nil {
			log.V(1).Info("SecretInjector has been deleted", "name", req.NamespacedName)
			return ctrl.Result{}, nil
		}

		log.Error(err, "Unable to fetch SecretInjector", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	// Being deleted: there are no finalizers and nothing to clean up (injections
	// are additive and left in place), so skip rather than do work and fight the
	// deletion with a status update.
	if !injector.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	prevDegraded := conditionStatus(injector.Status.Conditions, secretsv1beta1.ConditionDegraded)

	status := secretsv1beta1.SecretInjectorStatus{
		ObservedGeneration: injector.Generation,
		Conditions:         injector.Status.Conditions,
	}

	if len(injector.Spec.Rules) > 0 {
		namespaces := &corev1.NamespaceList{}

		if err := r.List(ctx, namespaces, &client.ListOptions{}); err != nil {
			log.Error(err, "Unable to list namespaces")
			return ctrl.Result{}, err
		}

		activeNamespaces := copyengine.FilterActiveNamespaces(namespaces.Items)

		for i := range injector.Spec.Rules {
			rule := injector.Spec.Rules[i]

			ruleStatus := secretsv1beta1.SecretInjectorCounts{}

			for j := range activeNamespaces {
				namespace := activeNamespaces[j]

				if !rule.TargetNamespaces.Matches(&namespace) {
					continue
				}

				ruleStatus.TargetNamespaces++

				r.reconcileNamespace(ctx, &rule, namespace.Name, &ruleStatus)
			}

			status.Summary.TargetNamespaces += ruleStatus.TargetNamespaces
			status.Summary.ServiceAccountsMatched += ruleStatus.ServiceAccountsMatched
			status.Summary.InjectionsInSync += ruleStatus.InjectionsInSync
			status.Summary.Failures += ruleStatus.Failures
			status.Rules = append(status.Rules, ruleStatus)
		}
	}

	r.setConditions(&status, &injector)

	if !equality.Semantic.DeepEqual(injector.Status, status) {
		injector.Status = status

		if err := r.Status().Update(ctx, &injector); err != nil {
			if !apierrors.IsConflict(err) {
				log.Error(err, "Unable to update SecretInjector status", "name", req.NamespacedName)
				return ctrl.Result{}, err
			}

			log.V(1).Info("Conflict updating SecretInjector status; another reconcile won, continuing", "name", req.NamespacedName)
		}
	}

	recordDegradedTransition(r.Recorder, &injector, "Inject", prevDegraded, status.Conditions)

	// Convergence is event-driven (secret, service account and namespace
	// watches); the fixed backstop bounds staleness from any missed event and
	// retries any failures counted above.
	return ctrl.Result{RequeueAfter: backstopRequeue}, nil
}

// reconcileNamespace applies one rule within one namespace: it injects every
// matched secret into every matched service account, accumulating counts.
func (r *SecretInjectorReconciler) reconcileNamespace(ctx context.Context, rule *secretsv1beta1.SecretInjectorRule, namespace string, ruleStatus *secretsv1beta1.SecretInjectorCounts) {
	log := logf.FromContext(ctx)

	var secretList corev1.SecretList
	if err := r.List(ctx, &secretList, client.InNamespace(namespace)); err != nil {
		log.Error(err, "Unable to list secrets", "namespace", namespace)
		ruleStatus.Failures++
		return
	}

	var matchedSecrets []corev1.Secret
	for k := range secretList.Items {
		secret := secretList.Items[k]
		if rule.SourceSecrets.Matches(&secret.ObjectMeta) {
			matchedSecrets = append(matchedSecrets, secret)
		}
	}

	if len(matchedSecrets) == 0 {
		return
	}

	var serviceAccounts corev1.ServiceAccountList
	if err := r.List(ctx, &serviceAccounts, client.InNamespace(namespace)); err != nil {
		log.Error(err, "Unable to list service accounts", "namespace", namespace)
		ruleStatus.Failures++
		return
	}

	for k := range serviceAccounts.Items {
		serviceAccount := serviceAccounts.Items[k]

		if !rule.ServiceAccounts.Matches(serviceAccount.Name, serviceAccount.Labels) {
			continue
		}

		ruleStatus.ServiceAccountsMatched++

		// Add any missing references, then update the service account once.

		present := 0
		added := 0

		for s := range matchedSecrets {
			secret := matchedSecrets[s]
			alreadyPresent, addedNow := injectReference(&serviceAccount, secret.Name, secret.Type)
			switch {
			case alreadyPresent:
				present++
			case addedNow:
				added++
			}
		}

		if added == 0 {
			ruleStatus.InjectionsInSync += present
			continue
		}

		if err := r.Update(ctx, &serviceAccount); err != nil {
			log.Error(err, "Unable to update service account", "serviceAccount", serviceAccount.Name, "namespace", namespace)
			ruleStatus.Failures++
			// References that were already present remain in sync.
			ruleStatus.InjectionsInSync += present
			continue
		}

		log.V(1).Info("Injected secret references into service account", "serviceAccount", serviceAccount.Name, "namespace", namespace, "added", added)
		ruleStatus.InjectionsInSync += present + added
	}
}

// injectReference adds a reference to secretName into the service account's
// imagePullSecrets (for image pull secrets) or secrets (otherwise), if not
// already present. It reports whether the reference was already present and
// whether it was added by this call.
func injectReference(serviceAccount *corev1.ServiceAccount, secretName string, secretType corev1.SecretType) (alreadyPresent, added bool) {
	if secretType == corev1.SecretTypeDockerConfigJson {
		for _, ref := range serviceAccount.ImagePullSecrets {
			if ref.Name == secretName {
				return true, false
			}
		}
		serviceAccount.ImagePullSecrets = append(serviceAccount.ImagePullSecrets, corev1.LocalObjectReference{Name: secretName})
		return false, true
	}

	for _, ref := range serviceAccount.Secrets {
		if ref.Name == secretName {
			return true, false
		}
	}
	serviceAccount.Secrets = append(serviceAccount.Secrets, corev1.ObjectReference{Name: secretName})
	return false, true
}

// setConditions derives the Ready and Degraded conditions from the reconcile
// outcome recorded in status.
func (r *SecretInjectorReconciler) setConditions(status *secretsv1beta1.SecretInjectorStatus, injector *secretsv1beta1.SecretInjector) {
	if status.Summary.Failures == 0 {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionReady,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: injector.Generation,
			Reason:             "AllInjectionsInSync",
			Message:            fmt.Sprintf("%d injection(s) in sync across %d service account match(es)", status.Summary.InjectionsInSync, status.Summary.ServiceAccountsMatched),
		})
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionDegraded,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: injector.Generation,
			Reason:             "NoFailures",
			Message:            "All injections succeeded",
		})
	} else {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: injector.Generation,
			Reason:             "InjectionFailures",
			Message:            fmt.Sprintf("%d service account(s) could not be updated", status.Summary.Failures),
		})
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionDegraded,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: injector.Generation,
			Reason:             "InjectionFailures",
			Message:            fmt.Sprintf("%d service account(s) could not be updated", status.Summary.Failures),
		})
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretInjectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Only reconcile on spec changes, not on our own status writes.
		For(&secretsv1beta1.SecretInjector{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findInjectorsMatchingSecret),
			builder.OnlyMetadata,
		).
		Watches(
			&corev1.ServiceAccount{},
			handler.EnqueueRequestsFromMapFunc(r.findInjectorsMatchingServiceAccount),
		).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.findInjectorsMatchingNamespace),
		).
		Named("secretinjector").
		Complete(r)
}

// findInjectorsMatchingSecret enqueues injectors with a rule whose source
// secret selector matches the changed secret. The watch delivers metadata only,
// so only ObjectMeta accessors may be used.
func (r *SecretInjectorReconciler) findInjectorsMatchingSecret(ctx context.Context, object client.Object) []reconcile.Request {
	return r.injectorsMatching(ctx, func(rule *secretsv1beta1.SecretInjectorRule) bool {
		return rule.SourceSecrets.Matches(object)
	})
}

// findInjectorsMatchingServiceAccount enqueues injectors with a rule whose
// service account selector matches the changed service account.
func (r *SecretInjectorReconciler) findInjectorsMatchingServiceAccount(ctx context.Context, object client.Object) []reconcile.Request {
	serviceAccount, ok := object.(*corev1.ServiceAccount)
	if !ok {
		return nil
	}

	return r.injectorsMatching(ctx, func(rule *secretsv1beta1.SecretInjectorRule) bool {
		return rule.ServiceAccounts.Matches(serviceAccount.Name, serviceAccount.Labels)
	})
}

// findInjectorsMatchingNamespace enqueues injectors with a rule whose target
// namespaces match the changed namespace.
func (r *SecretInjectorReconciler) findInjectorsMatchingNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	namespace, ok := object.(*corev1.Namespace)
	if !ok {
		return nil
	}

	return r.injectorsMatching(ctx, func(rule *secretsv1beta1.SecretInjectorRule) bool {
		return rule.TargetNamespaces.Matches(namespace)
	})
}

// injectorsMatching lists all injectors and returns reconcile requests for those
// with at least one rule satisfying the predicate.
func (r *SecretInjectorReconciler) injectorsMatching(ctx context.Context, ruleMatches func(*secretsv1beta1.SecretInjectorRule) bool) []reconcile.Request {
	log := logf.FromContext(ctx)

	var injectors secretsv1beta1.SecretInjectorList

	if err := r.List(ctx, &injectors, &client.ListOptions{}); err != nil {
		log.Error(err, "Unable to list SecretInjector objects")
		return nil
	}

	var requests []reconcile.Request

	for _, injector := range injectors.Items {
		for k := range injector.Spec.Rules {
			if ruleMatches(&injector.Spec.Rules[k]) {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&injector)})
				break
			}
		}
	}

	return requests
}
