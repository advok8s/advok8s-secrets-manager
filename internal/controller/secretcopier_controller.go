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
	"bytes"
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// SecretCopierReconciler reconciles a SecretCopier object
type SecretCopierReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=secrets-manager.advok8s.io,resources=secretcopiers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets-manager.advok8s.io,resources=secretcopiers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets-manager.advok8s.io,resources=secretcopiers/finalizers,verbs=update

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

	for _, namespace := range namespaces.Items {
		if namespace.Status.Phase != corev1.NamespaceTerminating {
			activeNamespaces = append(activeNamespaces, namespace)
		}
	}

	// Generate a list of just the names of the active namespaces so we can log
	// them for debugging.

	activeNamespaceNames := make([]string, 0)

	for _, namespace := range activeNamespaces {
		activeNamespaceNames = append(activeNamespaceNames, namespace.Name)
	}

	log.V(1).Info("Active namespaces", "namespaces", activeNamespaceNames)

	// Iterate over the set of rules defined for the SecretCopier object and
	// determine which target namespaces match the rule.

	for _, rule := range secretCopier.Spec.Rules {
		targetNamespaces := make([]string, 0)

		for _, namespace := range activeNamespaces {
			if namespace.Name != rule.SourceSecret.Namespace && rule.TargetNamespaces.Matches(&namespace) {
				log.V(1).Info("Matched target Namespace against SecretCopier", "name", req.NamespacedName, "rule", rule, "namespace", namespace.Name)

				targetNamespaces = append(targetNamespaces, namespace.Name)
			}
		}

		// If there are no target namespaces that match the rule, there is
		// nothing to do.

		if len(targetNamespaces) == 0 {
			log.V(1).Info("No target namespaces to process for SecretCopier", "name", req.NamespacedName, "rule", rule)
			continue
		}

		log.V(1).Info("Target namespaces to process for SecretCopier", "name", req.NamespacedName, "rule", rule, "targetNamespaces", targetNamespaces)

		// Copy the source secret to each of the target namespaces that match
		// the rule. The copy operation will check itself if the source secret
		// exists and copy it if the target secret does not exist, or update it
		// if it does and the source secret has changed.

		for _, targetNamespace := range targetNamespaces {
			if targetNamespace != rule.SourceSecret.Namespace {
				r.copySecretToNamespace(ctx, &secretCopier, &rule, targetNamespace)
			}
		}
	}

	// Requeue the request based on the synchronizaion period defined for the
	// SecretCopier. This is to ensure that we periodically check for case where
	// the target secret has been deleted and we need to recreate it. We do this
	// on an interval rather than detecting the deletion of the target secret
	// and recreating it immediately to avoid thrashing the system.

	if secretCopier.Spec.SyncPeriod.Duration > 0 {
		return ctrl.Result{RequeueAfter: secretCopier.Spec.SyncPeriod.Duration}, nil
	}

	// No need to requeue the request.

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretCopierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.SecretCopier{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findSecretCopiersMatchingSourceSecret),
		).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.findSecretCopiersMatchingTargetNamespace),
		).
		Complete(r)
}

// Handler function to find SecretCopier objects that match a source secret.
// This is used to trigger a reconciliation of the SecretCopier object when a
// secret is created or updated. This is necessary as we need to determine if
// the secret is one that the SecretCopier is interested in and copy it to any
// target namespaces if it is.
func (r *SecretCopierReconciler) findSecretCopiersMatchingSourceSecret(ctx context.Context, secret client.Object) []reconcile.Request {
	log := log.FromContext(ctx)

	// Fetch the list of SecretCopier objects.

	var secretCopiers secretsv1beta1.SecretCopierList

	err := r.List(ctx, &secretCopiers, &client.ListOptions{})

	if err != nil {
		log.Error(err, "Unable to list SecretCopier objects")
		return nil
	}

	// Iterate over the list of SecretCopier objects and determine if any match
	// on it as the source secret.

	var requests []reconcile.Request

	for _, secretCopier := range secretCopiers.Items {
		for _, rule := range secretCopier.Spec.Rules {
			if rule.SourceSecret.Name == secret.GetName() && rule.SourceSecret.Namespace == secret.GetNamespace() {
				log.V(1).Info("Queue reconcile for source Secret against SecretCopier", "name", secretCopier.Name, "rule", rule, "secret", secret.GetName(), "namespace", secret.GetNamespace())

				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&secretCopier)})

				// We only need to match on one rule for the secret, so break out
				// of the loop once we have found one.

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
	log := log.FromContext(ctx)

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

// Copy the source secret to the target namespace. The copy operation will check
// itself if the source secret exists and copy it if the target secret does not
// exist, or update it if it does and the source secret has changed. Also check
// again that we are not trying to copy the secret to the same namespace it is
// in.
func (r *SecretCopierReconciler) copySecretToNamespace(ctx context.Context, secretCopier *secretsv1beta1.SecretCopier, rule *secretsv1beta1.SecretCopierRule, targetNamespace string) {
	log := log.FromContext(ctx)

	// Check that we are not trying to copy the secret to the same namespace it
	// is in.

	sourceSecret := rule.SourceSecret

	if sourceSecret.Namespace == targetNamespace {
		log.V(1).Info("Skipping copy of secret to same namespace", "sourceSecret", sourceSecret, "targetNamespace", targetNamespace)
		return
	}

	// Fetch the source secret.

	targetSecretName := rule.TargetSecret.Name

	if targetSecretName == "" {
		targetSecretName = sourceSecret.Name
	}

	var secret corev1.Secret

	err := r.Get(ctx, client.ObjectKey{Namespace: sourceSecret.Namespace, Name: sourceSecret.Name}, &secret)

	if err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Source secret does not exist, so there is nothing to do.

			log.V(1).Info("Source secret does not exist", "sourceSecret", sourceSecret)
			return
		}

		// Error reading the source secret. Log the error and return.

		log.Error(err, "Unable to fetch source secret", "sourceSecret", sourceSecret)
		return
	}

	log.V(1).Info("Fetched source secret", "sourceSecret", sourceSecret)

	// Fetch the target secret.

	var targetSecret corev1.Secret

	err = r.Get(ctx, client.ObjectKey{Namespace: targetNamespace, Name: targetSecretName}, &targetSecret)

	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			// Error reading the target secret. Log the error and return.

			log.Error(err, "Unable to fetch target secret", "targetSecret", targetSecretName, "targetNamespace", targetNamespace)
			return
		}
	}

	log.V(1).Info("Fetched target secret", "targetSecret", targetSecretName, "targetNamespace", targetNamespace)

	// If the target secret does not exist, create it.

	if err != nil {
		// The metadata for the target secret must use calculated target secret
		// name and namespace. Labels need to be a copy of those from the source
		// secret, overlaid with any additional labels specified in the rule for
		// the target secret. Annotations need to be added to the target secret
		// to indicate that it is managed by the SecretCopier object and was
		// created from the source secret. If the retention policy is set to
		// Delete, the SecretCopier object will be added as an owner reference
		// to the target secret so that it will be automatically deleted when
		// the SecretCopier object is deleted.

		log.V(1).Info("Creating target secret", "targetSecret", targetSecret, "targetNamespace", targetNamespace)

		targetSecretLabels := make(map[string]string)

		for key, value := range secret.Labels {
			targetSecretLabels[key] = value
		}

		for key, value := range rule.TargetSecret.Labels {
			targetSecretLabels[key] = value
		}

		ownerReferences := []metav1.OwnerReference{}

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

		targetSecret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      targetSecretName,
				Namespace: targetNamespace,
				Labels:    targetSecretLabels,
				Annotations: map[string]string{
					"secrets-manager.advok8s.io/secret-copier": secretCopier.Name,
					"secrets-manager.advok8s.io/secret-name":   sourceSecret.Namespace + "/" + sourceSecret.Name,
				},
				OwnerReferences: ownerReferences,
			},
			Type: secret.Type,
			Data: secret.Data,
		}

		targetSecret.Namespace = targetNamespace

		err = r.Create(ctx, &targetSecret)

		if err != nil {
			log.Error(err, "Unable to create target secret", "targetSecret", targetSecretName, "targetNamespace", targetNamespace)
			return
		}

		log.V(1).Info("Created target secret", "targetSecret", targetSecretName, "targetNamespace", targetNamespace)

		return
	}

	// Check that the target secret is managed by the SecretCopier object and
	// was created from the same source secret originally. If it is not, don't
	// update it.

	if !r.targetSecretManagedBySecretCopier(secretCopier, rule, &targetSecret) {
		log.V(1).Info("Skipping update of target secret as not managed by SecretCopier", "targetSecret", targetSecretName, "targetNamespace", targetNamespace)
		return
	}

	// If the target secret exists, check if it is different to the source
	// secret and if it is, update it. Labels need to be a copy of those from
	// the source secret, overlaid with any additional labels specified in the
	// rule for the target secret.

	if r.sourceSecretHasBeenUpdated(rule, &secret, &targetSecret) {
		log.V(1).Info("Updating target secret", "targetSecret", targetSecretName, "targetNamespace", targetNamespace)

		targetSecretLabels := make(map[string]string)

		for key, value := range secret.Labels {
			targetSecretLabels[key] = value
		}

		for key, value := range rule.TargetSecret.Labels {
			targetSecretLabels[key] = value
		}

		targetSecret.ObjectMeta.Labels = targetSecretLabels

		targetSecret.Data = secret.Data
		targetSecret.Type = secret.Type

		err = r.Update(ctx, &targetSecret)

		if err != nil {
			log.Error(err, "Unable to update target secret", "targetSecret", targetSecretName, "targetNamespace", targetNamespace)
			return
		}

		log.V(1).Info("Updated target secret", "targetSecret", targetSecretName, "targetNamespace", targetNamespace)
	}
}

// Verify that an existing target secret was originally created from the source
// secret and by the same SecretCopier object. This is done by checking the
// annotations on the target secret.
func (r *SecretCopierReconciler) targetSecretManagedBySecretCopier(secretCopier *secretsv1beta1.SecretCopier, rule *secretsv1beta1.SecretCopierRule, targetSecret *corev1.Secret) bool {
	if targetSecret.Annotations["secrets-manager.advok8s.io/secret-copier"] != secretCopier.Name {
		return false
	}

	if targetSecret.Annotations["secrets-manager.advok8s.io/secret-name"] != rule.SourceSecret.Namespace+"/"+rule.SourceSecret.Name {
		return false
	}

	return true
}

// Determine if the source secret has been updated by comparing the type, data
// and labels of the source and target secrets.
func (r *SecretCopierReconciler) sourceSecretHasBeenUpdated(rule *secretsv1beta1.SecretCopierRule, sourceSecret, targetSecret *corev1.Secret) bool {
	if sourceSecret.Type != targetSecret.Type {
		return true
	}

	mapStringBytesEqual := func(a map[string][]byte, b map[string][]byte) bool {
		if a == nil && b == nil {
			return true
		}
		if a == nil || b == nil {
			return false
		}
		if len(a) != len(b) {
			return false
		}
		for key, valueA := range a {
			if valueB, ok := b[key]; !ok || !bytes.Equal(valueA, valueB) {
				return false
			}
		}
		return true
	}

	if !mapStringBytesEqual(sourceSecret.Data, targetSecret.Data) {
		return true
	}

	targetSecretLabels := make(map[string]string)

	for key, value := range sourceSecret.Labels {
		targetSecretLabels[key] = value
	}

	for key, value := range rule.TargetSecret.Labels {
		targetSecretLabels[key] = value
	}

	mapStringStringEqual := func(a map[string]string, b map[string]string) bool {
		if a == nil && b == nil {
			return true
		}
		if a == nil || b == nil {
			return false
		}
		if len(a) != len(b) {
			return false
		}
		for key, valueA := range a {
			if valueB, ok := b[key]; !ok || valueA != valueB {
				return false
			}
		}
		return true
	}

	if !mapStringStringEqual(sourceSecret.Labels, targetSecretLabels) {
		return true
	}

	return false
}
