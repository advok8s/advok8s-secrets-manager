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
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlbuilder "sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
	sb "github.com/advok8s/advok8s-secrets-manager/internal/builder"
)

// awaitingRequeue is how often a builder waiting on absent inputs retries while it
// has no watch on those inputs. Input watches (a later phase) make this a backstop.
const awaitingRequeue = 15 * time.Second

// SecretBuilderReconciler reconciles a SecretBuilder by resolving its inputs,
// generating any random material, running its script/template, and writing the
// resulting Secret. This phase implements the generate-once policy: the Secret is
// produced when absent and then left alone.
type SecretBuilderReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// TokenMinter mints ServiceAccount tokens (required only for builders with a
	// serviceAccount input). ClusterServer is exposed as serviceAccount.cluster.server.
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

// Reconcile produces the Secret for a SecretBuilder.
func (r *SecretBuilderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var builder secretsv1beta1.SecretBuilder
	if err := r.Get(ctx, req.NamespacedName, &builder); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Being deleted: the output Secret is owned via ownerReference and garbage
	// collected, and there are no finalizers, so there is nothing to do.
	if !builder.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	prev := capturePrev(builder.Status.Conditions)

	status := secretsv1beta1.SecretBuilderStatus{
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

	// Generate-once gate: once the output Secret exists, it is left untouched
	// (drift and deletion handling and regeneration triggers arrive in a later
	// phase). A hand-edit or deletion is therefore not corrected here.
	var existing corev1.Secret
	getErr := r.Get(ctx, client.ObjectKey{Namespace: builder.Namespace, Name: builder.Name}, &existing)
	if getErr != nil && client.IgnoreNotFound(getErr) != nil {
		return ctrl.Result{}, getErr
	}
	if getErr == nil && status.Generated {
		setConditions(&status, builder.Generation, metav1.ConditionTrue, "Generated",
			fmt.Sprintf("Secret %q generated", builder.Name), metav1.ConditionFalse, "Generated", "Secret generated")
		return r.finish(ctx, &builder, status, prev, ctrl.Result{})
	}

	// Resolve inputs.
	resolver := &sb.Resolver{Client: r.Client, TokenMinter: r.TokenMinter, ClusterServer: r.ClusterServer}
	generatedAt := metav1.Now()
	resolved, pending, err := resolver.Resolve(ctx, &builder, generatedAt.Time)
	if err != nil {
		setConditions(&status, builder.Generation, metav1.ConditionFalse, "InvalidInput", err.Error(),
			metav1.ConditionTrue, "InvalidInput", err.Error())
		return r.finish(ctx, &builder, status, prev, ctrl.Result{})
	}
	if len(pending) > 0 {
		reason := secretsv1beta1ReasonFor(pending)
		msg := pending[0].Message
		setConditions(&status, builder.Generation, metav1.ConditionFalse, reason, msg,
			metav1.ConditionFalse, reason, msg)
		log.V(1).Info("SecretBuilder awaiting inputs", "name", req.NamespacedName, "reason", reason)
		return r.finish(ctx, &builder, status, prev, ctrl.Result{RequeueAfter: awaitingRequeue})
	}

	// Generate random material and fold it into the inputs.
	generated, err := sb.GenerateAll(builder.Spec.Inputs.Generated, r.randReader(), generatedAt.Time, resolved)
	if err != nil {
		return r.fail(ctx, &builder, &status, prev, "GeneratorError", err)
	}
	for handle, attrs := range generated {
		resolved.Generated[handle] = attrs
	}

	// Run the generator.
	engine, err := r.engineFor(&builder)
	if err != nil {
		setConditions(&status, builder.Generation, metav1.ConditionFalse, "InvalidInput", err.Error(),
			metav1.ConditionTrue, "InvalidInput", err.Error())
		return r.finish(ctx, &builder, status, prev, ctrl.Result{})
	}

	result, err := engine.Render(resolved)
	if err != nil {
		var retryErr *sb.RetryError
		if errors.As(err, &retryErr) {
			msg := retryErr.Message
			setConditions(&status, builder.Generation, metav1.ConditionFalse, "AwaitingInput", msg,
				metav1.ConditionFalse, "AwaitingInput", msg)
			after := retryErr.After
			if after <= 0 {
				after = awaitingRequeue
			}
			return r.finish(ctx, &builder, status, prev, ctrl.Result{RequeueAfter: after})
		}
		var failErr *sb.FailError
		if errors.As(err, &failErr) {
			return r.fail(ctx, &builder, &status, prev, "GeneratorError", failErr)
		}
		return r.fail(ctx, &builder, &status, prev, "GeneratorError", err)
	}

	// Assemble and write the output Secret.
	revision := sb.RevisionOf(result.Data)
	secretType := result.Type
	if secretType == "" {
		secretType = string(builder.Spec.Output.Type)
	}
	writeErr := sb.WriteSecret(ctx, r.Client, r.Scheme, &builder, sb.WriteRequest{
		Name:        builder.Name,
		Namespace:   builder.Namespace,
		Type:        secretType,
		Labels:      mergeLabels(builder.Spec.Output.Labels, result.Labels),
		Annotations: builder.Spec.Output.Annotations,
		Data:        result.Data,
		Revision:    revision,
	})
	if writeErr != nil {
		return r.fail(ctx, &builder, &status, prev, "GeneratorError", writeErr)
	}

	status.Generated = true
	status.LastGeneratedTime = &generatedAt
	status.Revision = revision
	status.InputFingerprint = resolved.Fingerprint()
	setConditions(&status, builder.Generation, metav1.ConditionTrue, "Generated",
		fmt.Sprintf("Secret %q generated", builder.Name), metav1.ConditionFalse, "Generated", "Secret generated")

	return r.finish(ctx, &builder, status, prev, ctrl.Result{})
}

// fail records a generator/internal failure as Degraded/<reason> and returns.
func (r *SecretBuilderReconciler) fail(ctx context.Context, builder *secretsv1beta1.SecretBuilder, status *secretsv1beta1.SecretBuilderStatus, prev prevConditions, reason string, err error) (ctrl.Result, error) {
	// The message is the error class/location; generated values are never echoed.
	setConditions(status, builder.Generation, metav1.ConditionFalse, reason, err.Error(),
		metav1.ConditionTrue, reason, err.Error())
	return r.finish(ctx, builder, *status, prev, ctrl.Result{})
}

// finish writes status (only when changed), emits transition events, and returns
// the requeue result.
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

// emitEvents emits events on Ready/Degraded transitions: a Warning when becoming
// Degraded, a Normal "Generated" when first Ready, and a Normal event when
// entering a waiting state (AwaitingInput / MissingServiceAccount).
func (r *SecretBuilderReconciler) emitEvents(builder *secretsv1beta1.SecretBuilder, prev prevConditions, conditions []metav1.Condition) {
	if r.Recorder == nil {
		return
	}

	degraded := meta.FindStatusCondition(conditions, secretsv1beta1.ConditionDegraded)
	if degraded != nil && degraded.Status != prev.degradedStatus {
		if degraded.Status == metav1.ConditionTrue {
			r.Recorder.Event(builder, corev1.EventTypeWarning, degraded.Reason, degraded.Message)
		} else if prev.degradedStatus == metav1.ConditionTrue {
			r.Recorder.Event(builder, corev1.EventTypeNormal, "Recovered", degraded.Message)
		}
	}

	ready := meta.FindStatusCondition(conditions, secretsv1beta1.ConditionReady)
	if ready == nil {
		return
	}
	switch {
	case ready.Status == metav1.ConditionTrue && prev.readyStatus != metav1.ConditionTrue:
		r.Recorder.Event(builder, corev1.EventTypeNormal, ready.Reason, ready.Message)
	case ready.Status != metav1.ConditionTrue && isWaitingReason(ready.Reason) && ready.Reason != prev.readyReason:
		r.Recorder.Event(builder, corev1.EventTypeNormal, ready.Reason, ready.Message)
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

// SetupWithManager sets up the controller with the Manager.
func (r *SecretBuilderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.SecretBuilder{}, ctrlbuilder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("secretbuilder").
		Complete(r)
}

// ---- helpers ------------------------------------------------------------

// prevConditions snapshots the prior Ready/Degraded states so finish can emit
// events only on transitions.
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

func secretsv1beta1ReasonFor(pending []sb.Pending) string {
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
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// truncateMessage keeps condition messages concise (verbose detail goes to logs).
func truncateMessage(msg string) string {
	const max = 1024
	if len(msg) > max {
		return msg[:max] + "…"
	}
	return msg
}
