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

// ConfigMapCopierReconciler reconciles a ConfigMapCopier object. It is the
// ConfigMap counterpart of SecretCopier, minus authorization: there is no
// ConfigMapImporter handshake, so a rule copies wherever its target namespaces
// match (conflict detection still protects foreign configmaps occupying a
// target name).
type ConfigMapCopierReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
}

// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=configmapcopiers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=configmapcopiers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=configmapcopiers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile copies each rule's source configmap into the namespaces the rule
// matches, accumulating an outcome summary for status.
func (r *ConfigMapCopierReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var copier secretsv1beta1.ConfigMapCopier

	if err := r.Get(ctx, req.NamespacedName, &copier); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Deleted: copies with the Delete reclaim policy are owned by the
			// copier and garbage-collected; nothing to do here.
			log.V(1).Info("ConfigMapCopier has been deleted", "name", req.NamespacedName)
			return ctrl.Result{}, nil
		}

		log.Error(err, "Unable to fetch ConfigMapCopier", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	// Being deleted: there are no finalizers and copies are garbage-collected
	// via owner references, so there is nothing to do.
	if !copier.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	// If there are no rules defined, there is nothing to do.
	if len(copier.Spec.Rules) == 0 {
		log.V(1).Info("No rules to process for ConfigMapCopier", "name", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	namespaces := &corev1.NamespaceList{}

	if err := r.List(ctx, namespaces, &client.ListOptions{}); err != nil {
		log.Error(err, "Unable to list namespaces")
		return ctrl.Result{}, err
	}

	activeNamespaces := copyengine.FilterActiveNamespaces(namespaces.Items)

	activeNamespaceSet := make(map[string]struct{}, len(activeNamespaces))
	for _, namespace := range activeNamespaces {
		activeNamespaceSet[namespace.Name] = struct{}{}
	}

	prevDegraded := conditionStatus(copier.Status.Conditions, secretsv1beta1.ConditionDegraded)

	status := secretsv1beta1.ConfigMapCopierStatus{
		ObservedGeneration: copier.Generation,
		Conditions:         copier.Status.Conditions, // seed so transition times are preserved
	}

	for i := range copier.Spec.Rules {
		rule := copier.Spec.Rules[i]

		ruleStatus := secretsv1beta1.ConfigMapRuleStatus{
			SourceConfigMap: rule.SourceConfigMap.Namespace + "/" + rule.SourceConfigMap.Name,
		}

		// A terminating or absent source namespace means the source configmap
		// is being torn down with it: skip without fetching, recording
		// sourceExists=false.
		if _, active := activeNamespaceSet[rule.SourceConfigMap.Namespace]; !active {
			status.Rules = append(status.Rules, ruleStatus)
			continue
		}

		var source corev1.ConfigMap

		err := r.Get(ctx, client.ObjectKey{Namespace: rule.SourceConfigMap.Namespace, Name: rule.SourceConfigMap.Name}, &source)

		switch {
		case err != nil && client.IgnoreNotFound(err) == nil:
			// The source configmap does not exist: a normal, expected state,
			// observable via sourceExists=false.
			status.Rules = append(status.Rules, ruleStatus)
			continue
		case err != nil:
			log.Error(err, "Unable to fetch source configmap", "sourceConfigMap", rule.SourceConfigMap)
			ruleStatus.Failures++
			status.Summary.Failures++
			status.Rules = append(status.Rules, ruleStatus)
			continue
		}

		ruleStatus.SourceExists = true

		for j := range activeNamespaces {
			namespace := activeNamespaces[j]

			if namespace.Name == rule.SourceConfigMap.Namespace || !rule.TargetNamespaces.Matches(&namespace) {
				continue
			}

			ruleStatus.TargetNamespaces++

			switch r.copyConfigMapToNamespace(ctx, &copier, &rule, &source, namespace.Name) {
			case copyengine.InSync:
				ruleStatus.ConfigMapsInSync++
			case copyengine.Conflict:
				ruleStatus.Conflicts++
			case copyengine.Failed:
				ruleStatus.Failures++
			case copyengine.Skipped, copyengine.AwaitingAuthorization:
			}
		}

		status.Summary.TargetNamespaces += ruleStatus.TargetNamespaces
		status.Summary.ConfigMapsInSync += ruleStatus.ConfigMapsInSync
		status.Summary.Conflicts += ruleStatus.Conflicts
		status.Summary.Failures += ruleStatus.Failures
		status.Rules = append(status.Rules, ruleStatus)
	}

	if status.Summary.Failures == 0 {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionReady,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: copier.Generation,
			Reason:             "AllConfigMapsInSync",
			Message:            fmt.Sprintf("%d configmap(s) in sync across %d namespace match(es)", status.Summary.ConfigMapsInSync, status.Summary.TargetNamespaces),
		})
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionDegraded,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: copier.Generation,
			Reason:             "NoFailures",
			Message:            "All copies succeeded",
		})
	} else {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: copier.Generation,
			Reason:             "CopyFailures",
			Message:            fmt.Sprintf("%d copy failure(s)", status.Summary.Failures),
		})
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:               secretsv1beta1.ConditionDegraded,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: copier.Generation,
			Reason:             "CopyFailures",
			Message:            fmt.Sprintf("%d configmap(s) could not be copied", status.Summary.Failures),
		})
	}

	if !equality.Semantic.DeepEqual(copier.Status, status) {
		copier.Status = status

		if err := r.Status().Update(ctx, &copier); err != nil {
			if !apierrors.IsConflict(err) {
				log.Error(err, "Unable to update ConfigMapCopier status", "name", req.NamespacedName)
				return ctrl.Result{}, err
			}

			log.V(1).Info("Conflict updating ConfigMapCopier status; another reconcile won, continuing", "name", req.NamespacedName)
		}
	}

	recordDegradedTransition(r.Recorder, &copier, "Copy", prevDegraded, status.Conditions)

	// Convergence is event-driven (watches cover source configmaps, target
	// configmaps and namespaces); the fixed backstop requeue only bounds the
	// staleness caused by a missed event.

	return ctrl.Result{RequeueAfter: backstopRequeue}, nil
}

// SetupWithManager sets up the controller with the Manager. Convergence is
// event-driven: configmaps are watched (metadata only) both as rule sources and
// as copy targets, and namespaces for new/changed match candidates.
func (r *ConfigMapCopierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Only reconcile on spec changes, not on our own status writes.
		For(&secretsv1beta1.ConfigMapCopier{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findCopiersForConfigMap),
			builder.OnlyMetadata,
		).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.findCopiersMatchingTargetNamespace),
		).
		Named("configmapcopier").
		Complete(r)
}

// findCopiersForConfigMap enqueues copiers for which the changed configmap is a
// rule's source, or carries a rule's effective target name. The target-name
// match makes target deletion, tampering and conflict clearance event-driven;
// it may over-enqueue (a same-named configmap in a non-target namespace causes
// a no-op reconcile), which is harmless. The watch delivers metadata only, so
// only ObjectMeta accessors may be used here.
func (r *ConfigMapCopierReconciler) findCopiersForConfigMap(ctx context.Context, configMap client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	var copiers secretsv1beta1.ConfigMapCopierList

	if err := r.List(ctx, &copiers, &client.ListOptions{}); err != nil {
		log.Error(err, "Unable to list ConfigMapCopier objects")
		return nil
	}

	var requests []reconcile.Request

	for _, copier := range copiers.Items {
		for _, rule := range copier.Spec.Rules {
			sourceMatch := rule.SourceConfigMap.Name == configMap.GetName() && rule.SourceConfigMap.Namespace == configMap.GetNamespace()

			targetName := rule.TargetConfigMap.Name
			if targetName == "" {
				targetName = rule.SourceConfigMap.Name
			}
			targetMatch := targetName == configMap.GetName()

			if sourceMatch || targetMatch {
				log.V(1).Info("Queue reconcile for ConfigMap against ConfigMapCopier", "name", copier.Name, "configMap", configMap.GetName(), "namespace", configMap.GetNamespace())

				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&copier)})
				break
			}
		}
	}

	return requests
}

// findCopiersMatchingTargetNamespace enqueues copiers with a rule whose target
// namespaces match the changed namespace.
func (r *ConfigMapCopierReconciler) findCopiersMatchingTargetNamespace(ctx context.Context, object client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	namespace, ok := object.(*corev1.Namespace)

	if !ok {
		log.Error(nil, "Object is not a Namespace", "object", object)
		return nil
	}

	var copiers secretsv1beta1.ConfigMapCopierList

	if err := r.List(ctx, &copiers, &client.ListOptions{}); err != nil {
		log.Error(err, "Unable to list ConfigMapCopier objects")
		return nil
	}

	var requests []reconcile.Request

	for _, copier := range copiers.Items {
		for _, rule := range copier.Spec.Rules {
			if rule.SourceConfigMap.Namespace != namespace.Name && rule.TargetNamespaces.Matches(namespace) {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&copier)})
				break
			}
		}
	}

	return requests
}

// copyConfigMapToNamespace translates a ConfigMapCopier rule and its
// already-fetched source configmap into a copy request for the shared copy
// engine, then runs it. The controller owns the rule-specific decisions - the
// target name (defaulting to the source name), the tracking identity stamped on
// copies, and the owner reference derived from the reclaim policy - while the
// engine performs the create/update/skip and reports the outcome.
func (r *ConfigMapCopierReconciler) copyConfigMapToNamespace(ctx context.Context, copier *secretsv1beta1.ConfigMapCopier, rule *secretsv1beta1.ConfigMapCopierRule, configMap *corev1.ConfigMap, targetNamespace string) copyengine.Outcome {
	sourceConfigMap := rule.SourceConfigMap

	targetName := rule.TargetConfigMap.Name

	if targetName == "" {
		targetName = sourceConfigMap.Name
	}

	// When the reclaim policy is Delete, make the ConfigMapCopier the owner of
	// the copy so the garbage collector removes it when the copier is deleted.

	var ownerReferences []metav1.OwnerReference

	if rule.ReclaimPolicy == secretsv1beta1.ReclaimDelete {
		ownerReferences = append(ownerReferences, metav1.OwnerReference{
			APIVersion:         secretsv1beta1.GroupVersion.String(),
			Kind:               "ConfigMapCopier",
			Name:               copier.Name,
			UID:                copier.UID,
			Controller:         ptr.To(true),
			BlockOwnerDeletion: ptr.To(true),
		})
	}

	engine := copyengine.Engine{Client: r.Client}

	return engine.CopyConfigMap(ctx, copyengine.ConfigMapRequest{
		Source:          configMap,
		SourceNamespace: sourceConfigMap.Namespace,
		SourceName:      sourceConfigMap.Name,
		TargetNamespace: targetNamespace,
		TargetName:      targetName,
		TargetLabels:    rule.TargetConfigMap.Labels,
		ManagedByValue:  "configmapcopier/" + copier.Name,
		OwnerReferences: ownerReferences,
	})
}
