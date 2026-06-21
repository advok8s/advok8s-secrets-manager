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
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlbuilder "sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configmapsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/configmaps/v1beta1"
	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
	sb "github.com/advok8s/advok8s-secrets-manager/internal/builder"
)

// ConfigMapBuilderReconciler reconciles a ConfigMapBuilder by resolving its
// inputs, generating any (non-secret) random material, running its
// script/template, and writing the resulting ConfigMap. It shares the
// SecretBuilder regeneration model: generate-once by default, with optional
// onInputChange refresh, rotateEvery rotation, and a manual regenerate
// annotation. Generated material is persisted in an owned companion Secret
// (always a Secret, regardless of the output kind - generated material is
// entropy) so a refresh replays it identically.
type ConfigMapBuilderReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// Rand is the entropy source for generated material (defaults to crypto/rand).
	Rand io.Reader
}

// +kubebuilder:rbac:groups=configmaps.advok8s.io,resources=configmapbuilders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=configmaps.advok8s.io,resources=configmapbuilders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=configmaps.advok8s.io,resources=configmapbuilders/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile produces (and regenerates) the ConfigMap for a ConfigMapBuilder.
func (r *ConfigMapBuilderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var builder configmapsv1beta1.ConfigMapBuilder
	if err := r.Get(ctx, req.NamespacedName, &builder); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !builder.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil // owned output/companion are GC'd via ownerReferences
	}

	prev := capturePrev(builder.Status.Conditions)
	status := copyConfigMapBuilderStatus(&builder)

	regen := builder.Spec.Regeneration
	regenEnabled := regen.OnInputChange || regen.RotateEvery != nil

	var existing corev1.ConfigMap
	getErr := r.Get(ctx, client.ObjectKey{Namespace: builder.Namespace, Name: builder.Name}, &existing)
	if getErr != nil && client.IgnoreNotFound(getErr) != nil {
		return ctrl.Result{}, getErr
	}
	outputExists := getErr == nil

	// Resolve inputs (provisional generatedAt = now; only Context.GeneratedAt
	// depends on it and is fixed once the action is known).
	now := metav1.Now()
	resolver := &sb.Resolver{Client: r.Client}
	resolved, pending, err := resolver.Resolve(ctx, sb.ResolveRequest{
		Object:      &builder,
		Inputs:      sb.InputsForConfigMapBuilder(&builder.Spec.Inputs),
		GeneratedAt: now.Time,
	})
	if err != nil {
		setConfigMapBuilderConditions(&status, builder.Generation, metav1.ConditionFalse, "InvalidInput", err.Error(),
			metav1.ConditionTrue, "InvalidInput", err.Error())
		return r.finish(ctx, &builder, status, prev, ctrl.Result{})
	}
	if len(pending) > 0 {
		reason := pendingReason(pending)
		msg := pending[0].Message
		setConfigMapBuilderConditions(&status, builder.Generation, metav1.ConditionFalse, reason, msg,
			metav1.ConditionFalse, reason, msg)
		log.V(1).Info("ConfigMapBuilder awaiting inputs", "name", req.NamespacedName, "reason", reason)
		return r.finish(ctx, &builder, status, prev, ctrl.Result{RequeueAfter: awaitingRequeue})
	}
	fingerprint := resolved.Fingerprint()

	// Load persisted material if regeneration is enabled and we have generated before.
	var companionGen map[string]map[string]any
	var companionAt time.Time
	companionExists := false
	if regenEnabled && status.Generated {
		companionGen, companionAt, companionExists, err = r.loadCompanion(ctx, &builder)
		if err != nil {
			return r.fail(ctx, &builder, &status, prev, fmt.Errorf("reading companion state: %w", err))
		}
	}

	manualToken := builder.Annotations[sb.ConfigMapRegenerateAnnotation]
	manualChanged := manualToken != "" && manualToken != status.ObservedRegenerateToken

	action := decideAction(regenState{
		generated:         status.Generated,
		lastGeneratedTime: status.LastGeneratedTime,
		inputFingerprint:  status.InputFingerprint,
	}, regen, outputExists, companionExists, manualChanged, fingerprint, now)

	if action == actionStable {
		setConfigMapGenerated(&status, &builder)
		result, nextRotation := rotationRequeue(status.LastGeneratedTime, regen)
		status.NextRotationTime = nextRotation
		return r.finish(ctx, &builder, status, prev, result)
	}

	return r.generateWriteAndFinish(ctx, &builder, &status, prev, resolved,
		action, companionGen, companionAt, now, fingerprint, manualToken)
}

// generateWriteAndFinish carries out a non-stable action: it produces (or
// replays) the generated material, runs the engine, writes the output
// ConfigMap and companion state, then updates status.
func (r *ConfigMapBuilderReconciler) generateWriteAndFinish(ctx context.Context,
	builder *configmapsv1beta1.ConfigMapBuilder, status *configmapsv1beta1.ConfigMapBuilderStatus, prev prevConditions,
	resolved *sb.ResolvedInputs, action genAction, companionGen map[string]map[string]any,
	companionAt time.Time, now metav1.Time, fingerprint, manualToken string) (ctrl.Result, error) {
	regen := builder.Spec.Regeneration
	regenEnabled := regen.OnInputChange || regen.RotateEvery != nil

	// Determine the generation time and material for the chosen action.
	var finalAt metav1.Time
	var generated map[string]map[string]any
	var err error
	switch action {
	case actionGenerateFresh, actionRotateFresh:
		finalAt = now
		generated, err = sb.GenerateAll(sb.InputsForConfigMapBuilder(&builder.Spec.Inputs).Generated, r.randReader(), finalAt.Time, resolved)
		if err != nil {
			return r.fail(ctx, builder, status, prev, err)
		}
	case actionRotateKeep:
		finalAt = now
		generated = companionGen
	case actionRefresh:
		finalAt = metav1.Time{Time: companionAt}
		generated = companionGen
	}

	resolved.Context.GeneratedAt = finalAt.Time
	for handle, attrs := range generated {
		resolved.Generated[handle] = attrs
	}

	engine, err := r.engineFor(builder)
	if err != nil {
		setConfigMapBuilderConditions(status, builder.Generation, metav1.ConditionFalse, "InvalidInput", err.Error(),
			metav1.ConditionTrue, "InvalidInput", err.Error())
		return r.finish(ctx, builder, *status, prev, ctrl.Result{})
	}

	result, err := engine.Render(resolved)
	if err != nil {
		return r.handleRenderError(ctx, builder, status, prev, err)
	}

	// The engine validated data values as UTF-8; convert for the ConfigMap.
	data := make(map[string]string, len(result.Data))
	for key, value := range result.Data {
		data[key] = string(value)
	}

	// Write the output ConfigMap.
	revision := sb.ConfigMapRevisionOf(data, result.BinaryData)
	if err := sb.WriteConfigMap(ctx, r.Client, r.Scheme, builder, sb.ConfigMapWriteRequest{
		Name:        builder.Name,
		Namespace:   builder.Namespace,
		Labels:      mergeStringMaps(builder.Spec.Output.Labels, result.Labels),
		Annotations: mergeStringMaps(builder.Spec.Output.Annotations, result.Annotations),
		Data:        data,
		BinaryData:  result.BinaryData,
		Revision:    revision,
	}); err != nil {
		return r.fail(ctx, builder, status, prev, err)
	}

	// Persist the companion state (a Secret - generated material is entropy)
	// so a future refresh/keep-entropy rotation can replay this exact material
	// and generatedAt.
	if regenEnabled {
		if err := r.writeCompanion(ctx, builder, generated, finalAt.Time); err != nil {
			return r.fail(ctx, builder, status, prev, fmt.Errorf("writing companion state: %w", err))
		}
	}

	status.Generated = true
	status.LastGeneratedTime = &finalAt
	status.Revision = revision
	status.InputFingerprint = fingerprint
	if manualToken != "" {
		status.ObservedRegenerateToken = manualToken
	}
	setConfigMapGenerated(status, builder)

	requeue, nextRotation := rotationRequeue(status.LastGeneratedTime, regen)
	status.NextRotationTime = nextRotation
	return r.finish(ctx, builder, *status, prev, requeue)
}

// handleRenderError maps an engine render error to the right terminal condition:
// a RetryError holds in AwaitingInput and requeues, anything else degrades.
func (r *ConfigMapBuilderReconciler) handleRenderError(ctx context.Context, builder *configmapsv1beta1.ConfigMapBuilder,
	status *configmapsv1beta1.ConfigMapBuilderStatus, prev prevConditions, err error) (ctrl.Result, error) {
	var retryErr *sb.RetryError
	if errors.As(err, &retryErr) {
		msg := retryErr.Message
		setConfigMapBuilderConditions(status, builder.Generation, metav1.ConditionFalse, "AwaitingInput", msg,
			metav1.ConditionFalse, "AwaitingInput", msg)
		after := retryErr.After
		if after <= 0 {
			after = awaitingRequeue
		}
		return r.finish(ctx, builder, *status, prev, ctrl.Result{RequeueAfter: after})
	}
	return r.fail(ctx, builder, status, prev, err)
}

// loadCompanion reads the persisted generated material and frozen generatedAt.
func (r *ConfigMapBuilderReconciler) loadCompanion(ctx context.Context, builder *configmapsv1beta1.ConfigMapBuilder) (map[string]map[string]any, time.Time, bool, error) {
	var companion corev1.Secret
	err := r.Get(ctx, client.ObjectKey{Namespace: builder.Namespace, Name: sb.CompanionConfigMapBuilderStateName(builder.Name)}, &companion)
	if apierrors.IsNotFound(err) {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, err
	}
	generated, err := sb.DeserializeGenerated(companion.Data["generated"])
	if err != nil {
		return nil, time.Time{}, false, err
	}
	generatedAt, err := time.Parse(time.RFC3339, string(companion.Data["generatedAt"]))
	if err != nil {
		return nil, time.Time{}, false, err
	}
	return generated, generatedAt, true, nil
}

func (r *ConfigMapBuilderReconciler) writeCompanion(ctx context.Context, builder *configmapsv1beta1.ConfigMapBuilder, generated map[string]map[string]any, generatedAt time.Time) error {
	data, err := sb.SerializeGenerated(generated)
	if err != nil {
		return err
	}
	return sb.WriteSecret(ctx, r.Client, r.Scheme, builder, sb.WriteRequest{
		Name:      sb.CompanionConfigMapBuilderStateName(builder.Name),
		Namespace: builder.Namespace,
		Data: map[string][]byte{
			"generated":   data,
			"generatedAt": []byte(generatedAt.UTC().Format(time.RFC3339)),
		},
	})
}

func (r *ConfigMapBuilderReconciler) fail(ctx context.Context, builder *configmapsv1beta1.ConfigMapBuilder, status *configmapsv1beta1.ConfigMapBuilderStatus, prev prevConditions, err error) (ctrl.Result, error) {
	const reason = "GeneratorError"
	setConfigMapBuilderConditions(status, builder.Generation, metav1.ConditionFalse, reason, err.Error(),
		metav1.ConditionTrue, reason, err.Error())
	return r.finish(ctx, builder, *status, prev, ctrl.Result{})
}

func (r *ConfigMapBuilderReconciler) finish(ctx context.Context, builder *configmapsv1beta1.ConfigMapBuilder, status configmapsv1beta1.ConfigMapBuilderStatus, prev prevConditions, result ctrl.Result) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	r.emitEvents(builder, prev, status.Conditions)

	if !equality.Semantic.DeepEqual(builder.Status, status) {
		builder.Status = status
		if err := r.Status().Update(ctx, builder); err != nil {
			if !apierrors.IsConflict(err) {
				log.Error(err, "Unable to update ConfigMapBuilder status", "name", builder.Name)
				return ctrl.Result{}, err
			}
			log.V(1).Info("Conflict updating ConfigMapBuilder status; another reconcile won, continuing", "name", builder.Name)
		}
	}
	return result, nil
}

func (r *ConfigMapBuilderReconciler) emitEvents(builder *configmapsv1beta1.ConfigMapBuilder, prev prevConditions, conditions []metav1.Condition) {
	if r.Recorder == nil {
		return
	}

	const action = "Generate"

	degraded := meta.FindStatusCondition(conditions, secretsv1beta1.ConditionDegraded)
	if degraded != nil && degraded.Status != prev.degradedStatus {
		if degraded.Status == metav1.ConditionTrue {
			emitNote(r.Recorder, builder, corev1.EventTypeWarning, degraded.Reason, action, degraded.Message)
		} else if prev.degradedStatus == metav1.ConditionTrue {
			emitNote(r.Recorder, builder, corev1.EventTypeNormal, "Recovered", action, degraded.Message)
		}
	}

	ready := meta.FindStatusCondition(conditions, secretsv1beta1.ConditionReady)
	if ready == nil {
		return
	}
	switch {
	case ready.Status == metav1.ConditionTrue && prev.readyStatus != metav1.ConditionTrue:
		emitNote(r.Recorder, builder, corev1.EventTypeNormal, ready.Reason, action, ready.Message)
	case ready.Status != metav1.ConditionTrue && isWaitingReason(ready.Reason) && ready.Reason != prev.readyReason:
		emitNote(r.Recorder, builder, corev1.EventTypeNormal, ready.Reason, action, ready.Message)
	}
}

func (r *ConfigMapBuilderReconciler) engineFor(builder *configmapsv1beta1.ConfigMapBuilder) (sb.Engine, error) {
	g := builder.Spec.Generator
	switch {
	case g.Script != nil:
		return &sb.StarlarkEngine{Script: *g.Script, Kind: sb.OutputConfigMap}, nil
	case g.Template != nil:
		return &sb.TemplateEngine{Data: g.Template.Data, Labels: g.Template.Labels, Annotations: g.Template.Annotations, Kind: sb.OutputConfigMap}, nil
	default:
		return nil, fmt.Errorf("generator sets neither script nor template")
	}
}

func (r *ConfigMapBuilderReconciler) randReader() io.Reader {
	if r.Rand != nil {
		return r.Rand
	}
	return rand.Reader
}

// SetupWithManager sets up the controller with the Manager. It reconciles on
// spec changes and on the regenerate annotation, and watches Secrets and
// ConfigMaps so a changed input (including an upstream builder's output)
// refreshes dependent builders. There is deliberately no watch on the builder's
// own output (the generate-and-own drift model).
func (r *ConfigMapBuilderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configmapsv1beta1.ConfigMapBuilder{}, ctrlbuilder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}))).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.findBuildersForSecret), ctrlbuilder.OnlyMetadata).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.findBuildersForConfigMap), ctrlbuilder.OnlyMetadata).
		Named("configmapbuilder").
		Complete(r)
}

// findBuildersForSecret enqueues onInputChange builders whose secret inputs
// match the changed Secret. The watch delivers metadata only.
func (r *ConfigMapBuilderReconciler) findBuildersForSecret(ctx context.Context, object client.Object) []reconcile.Request {
	var builders configmapsv1beta1.ConfigMapBuilderList
	if err := r.List(ctx, &builders); err != nil {
		return nil
	}

	var requests []reconcile.Request
	for i := range builders.Items {
		b := builders.Items[i]
		if !b.Spec.Regeneration.OnInputChange || b.Namespace != object.GetNamespace() {
			continue
		}
		for j := range b.Spec.Inputs.Secrets {
			if matchesSecretInput(&b.Spec.Inputs.Secrets[j], object) {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&b)})
				break
			}
		}
	}
	return requests
}

// findBuildersForConfigMap enqueues onInputChange builders whose configMap
// inputs match the changed ConfigMap, carrying upstream-revision propagation
// through ConfigMapBuilder chains.
func (r *ConfigMapBuilderReconciler) findBuildersForConfigMap(ctx context.Context, object client.Object) []reconcile.Request {
	var builders configmapsv1beta1.ConfigMapBuilderList
	if err := r.List(ctx, &builders); err != nil {
		return nil
	}

	var requests []reconcile.Request
	for i := range builders.Items {
		b := builders.Items[i]
		if !b.Spec.Regeneration.OnInputChange || b.Namespace != object.GetNamespace() {
			continue
		}
		for j := range b.Spec.Inputs.ConfigMaps {
			if matchesConfigMapInput(&b.Spec.Inputs.ConfigMaps[j], object) {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&b)})
				break
			}
		}
	}
	return requests
}

// ---- helpers ------------------------------------------------------------

func copyConfigMapBuilderStatus(builder *configmapsv1beta1.ConfigMapBuilder) configmapsv1beta1.ConfigMapBuilderStatus {
	return configmapsv1beta1.ConfigMapBuilderStatus{
		ObservedGeneration:      builder.Generation,
		Conditions:              builder.Status.Conditions,
		ConfigMapName:           builder.Name,
		Generated:               builder.Status.Generated,
		LastGeneratedTime:       builder.Status.LastGeneratedTime,
		NextRotationTime:        builder.Status.NextRotationTime,
		ObservedRegenerateToken: builder.Status.ObservedRegenerateToken,
		InputFingerprint:        builder.Status.InputFingerprint,
		Revision:                builder.Status.Revision,
	}
}

func setConfigMapGenerated(status *configmapsv1beta1.ConfigMapBuilderStatus, builder *configmapsv1beta1.ConfigMapBuilder) {
	setConfigMapBuilderConditions(status, builder.Generation, metav1.ConditionTrue, "Generated",
		fmt.Sprintf("ConfigMap %q generated", builder.Name), metav1.ConditionFalse, "Generated", "ConfigMap generated")
}

func setConfigMapBuilderConditions(status *configmapsv1beta1.ConfigMapBuilderStatus, generation int64,
	ready metav1.ConditionStatus, readyReason, readyMsg string,
	degraded metav1.ConditionStatus, degradedReason, degradedMsg string) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type: secretsv1beta1.ConditionReady, Status: ready, ObservedGeneration: generation, Reason: readyReason, Message: truncateMessage(readyMsg),
	})
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type: secretsv1beta1.ConditionDegraded, Status: degraded, ObservedGeneration: generation, Reason: degradedReason, Message: truncateMessage(degradedMsg),
	})
}
