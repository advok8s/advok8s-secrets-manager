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
	"maps"
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

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
	sb "github.com/advok8s/advok8s-secrets-manager/internal/builder"
)

// awaitingRequeue is how often a builder waiting on absent inputs retries beyond
// the input watch (a backstop for inputs the watch does not cover).
const awaitingRequeue = 15 * time.Second

// genAction is the decision of what to do this reconcile.
type genAction int

const (
	actionStable        genAction = iota // output present and current; do nothing
	actionGenerateFresh                  // first generation (or generate-once recovery): new material, now
	actionRefresh                        // re-run with persisted material + frozen generatedAt
	actionRotateFresh                    // re-stamp generatedAt now, re-roll entropy
	actionRotateKeep                     // re-stamp generatedAt now, reuse persisted entropy
)

// SecretBuilderReconciler reconciles a SecretBuilder by resolving its inputs,
// generating any random material, running its script/template, and writing the
// resulting Secret. It implements the regeneration model: generate-once by
// default, with optional onInputChange refresh, rotateEvery rotation, and a manual
// regenerate annotation. Generated material is persisted in an owned companion
// Secret so a refresh replays it identically.
type SecretBuilderReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	TokenMinter   sb.TokenMinter
	ClusterServer string

	// Rand is the entropy source for generated material (defaults to crypto/rand).
	Rand io.Reader
}

// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretbuilders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretbuilders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.advok8s.io,resources=secretbuilders/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile produces (and regenerates) the Secret for a SecretBuilder.
func (r *SecretBuilderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var builder secretsv1beta1.SecretBuilder
	if err := r.Get(ctx, req.NamespacedName, &builder); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !builder.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil // owned output/companion are GC'd via ownerReferences
	}

	prev := capturePrev(builder.Status.Conditions)
	status := copyStatus(&builder)

	regen := builder.Spec.Regeneration
	regenEnabled := regen.OnInputChange || regen.RotateEvery != nil

	var existing corev1.Secret
	getErr := r.Get(ctx, client.ObjectKey{Namespace: builder.Namespace, Name: builder.Name}, &existing)
	if getErr != nil && client.IgnoreNotFound(getErr) != nil {
		return ctrl.Result{}, getErr
	}
	outputExists := getErr == nil

	// Resolve inputs (provisional generatedAt = now; only Context.GeneratedAt
	// depends on it and is fixed once the action is known).
	now := metav1.Now()
	resolver := &sb.Resolver{Client: r.Client, TokenMinter: r.TokenMinter, ClusterServer: r.ClusterServer}
	resolved, pending, err := resolver.Resolve(ctx, &builder, now.Time)
	if err != nil {
		setConditions(&status, builder.Generation, metav1.ConditionFalse, "InvalidInput", err.Error(),
			metav1.ConditionTrue, "InvalidInput", err.Error())
		return r.finish(ctx, &builder, status, prev, ctrl.Result{})
	}
	if len(pending) > 0 {
		reason := pendingReason(pending)
		msg := pending[0].Message
		setConditions(&status, builder.Generation, metav1.ConditionFalse, reason, msg,
			metav1.ConditionFalse, reason, msg)
		log.V(1).Info("SecretBuilder awaiting inputs", "name", req.NamespacedName, "reason", reason)
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

	manualToken := builder.Annotations[sb.RegenerateAnnotation]
	manualChanged := manualToken != "" && manualToken != status.ObservedRegenerateToken

	action := decideAction(status, regen, outputExists, companionExists, manualChanged, fingerprint, now)

	if action == actionStable {
		setGenerated(&status, &builder)
		return r.finish(ctx, &builder, status, prev, rotationRequeue(&status, regen))
	}

	return r.generateWriteAndFinish(ctx, &builder, &status, prev, resolved,
		action, companionGen, companionAt, now, fingerprint, manualToken)
}

// decideAction picks what this reconcile should do, given the current status and
// what exists (output Secret, companion material) plus any manual trigger.
func decideAction(status secretsv1beta1.SecretBuilderStatus, regen secretsv1beta1.Regeneration,
	outputExists, companionExists, manualChanged bool, fingerprint string, now metav1.Time) genAction {
	rotate := func() genAction {
		if regen.RotateGenerated || !companionExists {
			return actionRotateFresh
		}
		return actionRotateKeep
	}

	switch {
	case !status.Generated:
		return actionGenerateFresh
	case !outputExists:
		// The output was deleted. Restore from persisted material when we have it
		// (no surprise rotation); otherwise (generate-once) regenerate fresh - the
		// only copy of the entropy went away with the Secret.
		if companionExists {
			return actionRefresh
		}
		return actionGenerateFresh
	case manualChanged:
		return rotate()
	case regen.RotateEvery != nil && status.LastGeneratedTime != nil &&
		!now.Time.Before(status.LastGeneratedTime.Add(regen.RotateEvery.Duration)):
		return rotate()
	case regen.OnInputChange && companionExists && fingerprint != status.InputFingerprint:
		return actionRefresh
	default:
		return actionStable
	}
}

// rotationRequeue records the next rotateEvery rotation time on status and returns
// the requeue delay until then, or a zero Result when rotation is not configured.
func rotationRequeue(status *secretsv1beta1.SecretBuilderStatus, regen secretsv1beta1.Regeneration) ctrl.Result {
	if regen.RotateEvery == nil || status.LastGeneratedTime == nil {
		return ctrl.Result{}
	}
	next := status.LastGeneratedTime.Add(regen.RotateEvery.Duration)
	status.NextRotationTime = &metav1.Time{Time: next}
	if d := time.Until(next); d > 0 {
		return ctrl.Result{RequeueAfter: d}
	}
	return ctrl.Result{RequeueAfter: time.Second}
}

// generateWriteAndFinish carries out a non-stable action: it produces (or replays)
// the generated material, runs the engine, writes the output Secret and companion
// state, then updates status.
func (r *SecretBuilderReconciler) generateWriteAndFinish(ctx context.Context,
	builder *secretsv1beta1.SecretBuilder, status *secretsv1beta1.SecretBuilderStatus, prev prevConditions,
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
		generated, err = sb.GenerateAll(builder.Spec.Inputs.Generated, r.randReader(), finalAt.Time, resolved)
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
		setConditions(status, builder.Generation, metav1.ConditionFalse, "InvalidInput", err.Error(),
			metav1.ConditionTrue, "InvalidInput", err.Error())
		return r.finish(ctx, builder, *status, prev, ctrl.Result{})
	}

	result, err := engine.Render(resolved)
	if err != nil {
		return r.handleRenderError(ctx, builder, status, prev, err)
	}

	// Write the output Secret.
	revision := sb.RevisionOf(result.Data)
	secretType := result.Type
	if secretType == "" {
		secretType = string(builder.Spec.Output.Type)
	}
	if err := sb.WriteSecret(ctx, r.Client, r.Scheme, builder, sb.WriteRequest{
		Name:        builder.Name,
		Namespace:   builder.Namespace,
		Type:        secretType,
		Labels:      mergeLabels(builder.Spec.Output.Labels, result.Labels),
		Annotations: builder.Spec.Output.Annotations,
		Data:        result.Data,
		Revision:    revision,
	}); err != nil {
		return r.fail(ctx, builder, status, prev, err)
	}

	// Persist the companion state so a future refresh/keep-entropy rotation can
	// replay this exact material and generatedAt.
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
	setGenerated(status, builder)

	return r.finish(ctx, builder, *status, prev, rotationRequeue(status, regen))
}

// handleRenderError maps an engine render error to the right terminal condition:
// a RetryError holds in AwaitingInput and requeues, anything else degrades.
func (r *SecretBuilderReconciler) handleRenderError(ctx context.Context, builder *secretsv1beta1.SecretBuilder,
	status *secretsv1beta1.SecretBuilderStatus, prev prevConditions, err error) (ctrl.Result, error) {
	var retryErr *sb.RetryError
	if errors.As(err, &retryErr) {
		msg := retryErr.Message
		setConditions(status, builder.Generation, metav1.ConditionFalse, "AwaitingInput", msg,
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
func (r *SecretBuilderReconciler) loadCompanion(ctx context.Context, builder *secretsv1beta1.SecretBuilder) (map[string]map[string]any, time.Time, bool, error) {
	var companion corev1.Secret
	err := r.Get(ctx, client.ObjectKey{Namespace: builder.Namespace, Name: sb.CompanionSecretName(builder.Name)}, &companion)
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

func (r *SecretBuilderReconciler) writeCompanion(ctx context.Context, builder *secretsv1beta1.SecretBuilder, generated map[string]map[string]any, generatedAt time.Time) error {
	data, err := sb.SerializeGenerated(generated)
	if err != nil {
		return err
	}
	return sb.WriteSecret(ctx, r.Client, r.Scheme, builder, sb.WriteRequest{
		Name:      sb.CompanionSecretName(builder.Name),
		Namespace: builder.Namespace,
		Data: map[string][]byte{
			"generated":   data,
			"generatedAt": []byte(generatedAt.UTC().Format(time.RFC3339)),
		},
	})
}

func (r *SecretBuilderReconciler) fail(ctx context.Context, builder *secretsv1beta1.SecretBuilder, status *secretsv1beta1.SecretBuilderStatus, prev prevConditions, err error) (ctrl.Result, error) {
	const reason = "GeneratorError"
	setConditions(status, builder.Generation, metav1.ConditionFalse, reason, err.Error(),
		metav1.ConditionTrue, reason, err.Error())
	return r.finish(ctx, builder, *status, prev, ctrl.Result{})
}

func (r *SecretBuilderReconciler) finish(ctx context.Context, builder *secretsv1beta1.SecretBuilder, status secretsv1beta1.SecretBuilderStatus, prev prevConditions, result ctrl.Result) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	r.emitEvents(builder, prev, status.Conditions)

	if !equality.Semantic.DeepEqual(builder.Status, status) {
		builder.Status = status
		if err := r.Status().Update(ctx, builder); err != nil {
			if !apierrors.IsConflict(err) {
				log.Error(err, "Unable to update SecretBuilder status", "name", builder.Name)
				return ctrl.Result{}, err
			}
			log.V(1).Info("Conflict updating SecretBuilder status; another reconcile won, continuing", "name", builder.Name)
		}
	}
	return result, nil
}

func (r *SecretBuilderReconciler) emitEvents(builder *secretsv1beta1.SecretBuilder, prev prevConditions, conditions []metav1.Condition) {
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

func (r *SecretBuilderReconciler) engineFor(builder *secretsv1beta1.SecretBuilder) (sb.Engine, error) {
	g := builder.Spec.Generator
	switch {
	case g.Script != nil:
		return sb.NewStarlarkEngine(*g.Script), nil
	case g.Template != nil:
		return sb.NewTemplateEngine(g.Template.Data), nil
	default:
		return nil, fmt.Errorf("generator sets neither script nor template")
	}
}

func (r *SecretBuilderReconciler) randReader() io.Reader {
	if r.Rand != nil {
		return r.Rand
	}
	return rand.Reader
}

// SetupWithManager sets up the controller with the Manager. It reconciles on spec
// changes and on the regenerate annotation, and watches Secrets so a changed input
// (including an upstream builder's output) refreshes dependent builders. There is
// deliberately no watch on the builder's own output (see the design's drift model).
func (r *SecretBuilderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.SecretBuilder{}, ctrlbuilder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}))).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.findBuildersForSecret)).
		Named("secretbuilder").
		Complete(r)
}

// findBuildersForSecret enqueues onInputChange builders whose secret inputs match
// the changed Secret, carrying upstream-revision propagation through the chain.
func (r *SecretBuilderReconciler) findBuildersForSecret(ctx context.Context, object client.Object) []reconcile.Request {
	secret, ok := object.(*corev1.Secret)
	if !ok {
		return nil
	}

	var builders secretsv1beta1.SecretBuilderList
	if err := r.List(ctx, &builders); err != nil {
		return nil
	}

	var requests []reconcile.Request
	for i := range builders.Items {
		b := builders.Items[i]
		if !b.Spec.Regeneration.OnInputChange || b.Namespace != secret.Namespace {
			continue
		}
		for j := range b.Spec.Inputs.Secrets {
			if matchesSecretInput(&b.Spec.Inputs.Secrets[j], secret) {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&b)})
				break
			}
		}
	}
	return requests
}

func matchesSecretInput(input *secretsv1beta1.SecretInput, secret *corev1.Secret) bool {
	if input.SecretRef != nil {
		return input.SecretRef.Name == secret.Name
	}
	if input.Selector != nil {
		return input.Selector.Matches(&secret.ObjectMeta)
	}
	return false
}

// ---- helpers ------------------------------------------------------------

type prevConditions struct {
	readyStatus    metav1.ConditionStatus
	readyReason    string
	degradedStatus metav1.ConditionStatus
}

func capturePrev(conditions []metav1.Condition) prevConditions {
	p := prevConditions{}
	if ready := meta.FindStatusCondition(conditions, secretsv1beta1.ConditionReady); ready != nil {
		p.readyStatus = ready.Status
		p.readyReason = ready.Reason
	}
	if degraded := meta.FindStatusCondition(conditions, secretsv1beta1.ConditionDegraded); degraded != nil {
		p.degradedStatus = degraded.Status
	}
	return p
}

func copyStatus(builder *secretsv1beta1.SecretBuilder) secretsv1beta1.SecretBuilderStatus {
	return secretsv1beta1.SecretBuilderStatus{
		ObservedGeneration:      builder.Generation,
		Conditions:              builder.Status.Conditions,
		SecretName:              builder.Name,
		Generated:               builder.Status.Generated,
		LastGeneratedTime:       builder.Status.LastGeneratedTime,
		NextRotationTime:        builder.Status.NextRotationTime,
		ObservedRegenerateToken: builder.Status.ObservedRegenerateToken,
		InputFingerprint:        builder.Status.InputFingerprint,
		Revision:                builder.Status.Revision,
	}
}

func setGenerated(status *secretsv1beta1.SecretBuilderStatus, builder *secretsv1beta1.SecretBuilder) {
	setConditions(status, builder.Generation, metav1.ConditionTrue, "Generated",
		fmt.Sprintf("Secret %q generated", builder.Name), metav1.ConditionFalse, "Generated", "Secret generated")
}

func setConditions(status *secretsv1beta1.SecretBuilderStatus, generation int64,
	ready metav1.ConditionStatus, readyReason, readyMsg string,
	degraded metav1.ConditionStatus, degradedReason, degradedMsg string) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type: secretsv1beta1.ConditionReady, Status: ready, ObservedGeneration: generation, Reason: readyReason, Message: truncateMessage(readyMsg),
	})
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type: secretsv1beta1.ConditionDegraded, Status: degraded, ObservedGeneration: generation, Reason: degradedReason, Message: truncateMessage(degradedMsg),
	})
}

func pendingReason(pending []sb.Pending) string {
	for _, p := range pending {
		if p.Reason == sb.ReasonMissingServiceAcc {
			return "MissingServiceAccount"
		}
	}
	return "AwaitingInput"
}

func isWaitingReason(reason string) bool {
	return reason == "AwaitingInput" || reason == "MissingServiceAccount"
}

func mergeLabels(base, extra map[string]string) map[string]string {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := map[string]string{}
	maps.Copy(out, base)
	maps.Copy(out, extra)
	return out
}

func truncateMessage(msg string) string {
	const max = 1024
	if len(msg) > max {
		return msg[:max] + "…"
	}
	return msg
}
