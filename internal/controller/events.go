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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// emitNote records a single event via the events.k8s.io recorder. The message is
// passed as a format argument (not the format string) so a literal '%' in a
// condition message cannot be misinterpreted. related is always nil here: our
// events concern a single primary object. action is the machine-readable verb
// (UpperCamelCase) describing the operation the reconciler was performing.
func emitNote(recorder events.EventRecorder, object runtime.Object, eventtype, reason, action, message string) {
	recorder.Eventf(object, nil, eventtype, reason, action, "%s", message)
}

// conditionStatus returns the status of the named condition, or the empty string
// when the condition is absent. Capturing this value before the conditions are
// recomputed gives a stable "before" to compare against, even though
// meta.SetStatusCondition may update the condition slice in place.
func conditionStatus(conditions []metav1.Condition, conditionType string) metav1.ConditionStatus {
	if condition := meta.FindStatusCondition(conditions, conditionType); condition != nil {
		return condition.Status
	}
	return ""
}

// recordDegradedTransition emits an event when the Degraded condition changes
// state: a Warning when the resource becomes Degraded, and a Normal "Recovered"
// event when it leaves the Degraded state. Nothing is emitted when the state is
// unchanged, so a steady reconcile produces no event noise. Recorder is nil in
// unit contexts that do not exercise events, so guard against it. action is the
// reconciler's verb (e.g. "Copy", "Inject"), recorded on the event.
func recordDegradedTransition(recorder events.EventRecorder, object runtime.Object, action string, previous metav1.ConditionStatus, conditions []metav1.Condition) {
	if recorder == nil {
		return
	}

	degraded := meta.FindStatusCondition(conditions, secretsv1beta1.ConditionDegraded)
	if degraded == nil || degraded.Status == previous {
		return
	}

	switch {
	case degraded.Status == metav1.ConditionTrue:
		emitNote(recorder, object, corev1.EventTypeWarning, degraded.Reason, action, degraded.Message)
	case previous == metav1.ConditionTrue:
		emitNote(recorder, object, corev1.EventTypeNormal, "Recovered", action, degraded.Message)
	}
}

// recordImportedTransition emits a Normal event when a SecretImporter first
// observes its secret as imported (the Ready condition becoming True). The other
// Ready=False states (awaiting authorization, no matching exporter) are benign
// waiting states rather than errors, so they intentionally produce no event.
func recordImportedTransition(recorder events.EventRecorder, object runtime.Object, action string, previous metav1.ConditionStatus, conditions []metav1.Condition) {
	if recorder == nil {
		return
	}

	ready := meta.FindStatusCondition(conditions, secretsv1beta1.ConditionReady)
	if ready == nil || ready.Status != metav1.ConditionTrue || previous == metav1.ConditionTrue {
		return
	}

	emitNote(recorder, object, corev1.EventTypeNormal, ready.Reason, action, ready.Message)
}
