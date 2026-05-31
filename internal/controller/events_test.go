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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/v1beta1"
)

// condition builds a single-element condition slice for the given type/status.
func condition(conditionType string, status metav1.ConditionStatus, reason, message string) []metav1.Condition {
	return []metav1.Condition{{Type: conditionType, Status: status, Reason: reason, Message: message}}
}

// assertEvent checks that exactly the expected event string was recorded (or, for
// an empty want, that none was). record.FakeRecorder formats an event as
// "<type> <reason> <message>".
func assertEvent(t *testing.T, recorder *record.FakeRecorder, want string) {
	t.Helper()
	select {
	case got := <-recorder.Events:
		switch {
		case want == "":
			t.Errorf("unexpected event recorded: %q", got)
		case got != want:
			t.Errorf("event = %q, want %q", got, want)
		}
	default:
		if want != "" {
			t.Errorf("no event recorded, want %q", want)
		}
	}
}

func TestRecordDegradedTransition(t *testing.T) {
	const degraded = secretsv1beta1.ConditionDegraded

	tests := []struct {
		name       string
		previous   metav1.ConditionStatus
		conditions []metav1.Condition
		want       string
	}{
		{
			name:       "became degraded emits Warning",
			previous:   metav1.ConditionFalse,
			conditions: condition(degraded, metav1.ConditionTrue, "CopyFailures", "boom"),
			want:       "Warning CopyFailures boom",
		},
		{
			name:       "first reconcile already degraded emits Warning",
			previous:   "",
			conditions: condition(degraded, metav1.ConditionTrue, "CopyFailures", "boom"),
			want:       "Warning CopyFailures boom",
		},
		{
			name:       "recovered emits Normal",
			previous:   metav1.ConditionTrue,
			conditions: condition(degraded, metav1.ConditionFalse, "NoFailures", "all good"),
			want:       "Normal Recovered all good",
		},
		{
			name:       "still degraded emits nothing",
			previous:   metav1.ConditionTrue,
			conditions: condition(degraded, metav1.ConditionTrue, "CopyFailures", "boom"),
			want:       "",
		},
		{
			name:       "steady healthy emits nothing",
			previous:   metav1.ConditionFalse,
			conditions: condition(degraded, metav1.ConditionFalse, "NoFailures", "all good"),
			want:       "",
		},
		{
			name:       "first reconcile healthy emits nothing",
			previous:   "",
			conditions: condition(degraded, metav1.ConditionFalse, "NoFailures", "all good"),
			want:       "",
		},
		{
			name:       "no degraded condition emits nothing",
			previous:   "",
			conditions: nil,
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := record.NewFakeRecorder(1)
			recordDegradedTransition(recorder, &secretsv1beta1.SecretCopier{}, tt.previous, tt.conditions)
			assertEvent(t, recorder, tt.want)
		})
	}
}

func TestRecordImportedTransition(t *testing.T) {
	const ready = secretsv1beta1.ConditionReady

	tests := []struct {
		name       string
		previous   metav1.ConditionStatus
		conditions []metav1.Condition
		want       string
	}{
		{
			name:       "first import emits Normal",
			previous:   "",
			conditions: condition(ready, metav1.ConditionTrue, "Imported", "Secret imported from secretexporter ns/x"),
			want:       "Normal Imported Secret imported from secretexporter ns/x",
		},
		{
			name:       "recovered to imported emits Normal",
			previous:   metav1.ConditionFalse,
			conditions: condition(ready, metav1.ConditionTrue, "Imported", "imported"),
			want:       "Normal Imported imported",
		},
		{
			name:       "already imported emits nothing",
			previous:   metav1.ConditionTrue,
			conditions: condition(ready, metav1.ConditionTrue, "Imported", "imported"),
			want:       "",
		},
		{
			name:       "awaiting authorization emits nothing",
			previous:   "",
			conditions: condition(ready, metav1.ConditionFalse, "AwaitingAuthorization", "waiting"),
			want:       "",
		},
		{
			name:       "no ready condition emits nothing",
			previous:   "",
			conditions: nil,
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := record.NewFakeRecorder(1)
			recordImportedTransition(recorder, &secretsv1beta1.SecretImporter{}, tt.previous, tt.conditions)
			assertEvent(t, recorder, tt.want)
		})
	}
}

// TestRecordTransitionsNilRecorder ensures the helpers are safe when no recorder
// is configured (the guard used by unit contexts that do not exercise events).
func TestRecordTransitionsNilRecorder(t *testing.T) {
	recordDegradedTransition(nil, &secretsv1beta1.SecretCopier{}, "", condition(secretsv1beta1.ConditionDegraded, metav1.ConditionTrue, "X", "y"))
	recordImportedTransition(nil, &secretsv1beta1.SecretImporter{}, "", condition(secretsv1beta1.ConditionReady, metav1.ConditionTrue, "Imported", "y"))
}
