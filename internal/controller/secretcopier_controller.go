/*
Copyright 2024 Graham Dumpleton.

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
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// SecretCopierReconciler reconciles a SecretCopier object
type SecretCopierReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretcopiers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretcopiers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretcopiers/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the SecretCopier object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *SecretCopierReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

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

	activeNamespaces := make([]corev1.Namespace, 0)

	for _, ns := range namespaces.Items {
		if ns.Status.Phase != corev1.NamespaceTerminating {
			activeNamespaces = append(activeNamespaces, ns)
		}
	}

	// Generate a list of just the names of the active namespaces so we can log
	// them for debugging.

	activeNamespaceNames := make([]string, 0)

	for _, ns := range activeNamespaces {
		activeNamespaceNames = append(activeNamespaceNames, ns.Name)
	}

	log.V(1).Info("Active namespaces", "namespaces", activeNamespaceNames)

	// Iterate over the set of active namespaces and work out which rules match
	// it as as the target namespace for copying secrets to.

	for _, ns := range activeNamespaces {
		for _, rule := range secretCopier.Spec.Rules {
			if rule.TargetNamespaces.Matches(ns) {
				log.V(1).Info("Matched rule for SecretCopier", "name", req.NamespacedName, "rule", rule, "namespace", ns.Name)
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretCopierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.SecretCopier{}).
		Complete(r)
}
