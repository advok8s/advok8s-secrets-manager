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

package builder

// Operator-owned annotation keys and the reserved prefixes they live under.
// Each builder output kind owns the prefix matching its API group: a Secret
// output uses secrets.advok8s.io/, a ConfigMap output uses configmaps.advok8s.io/.
// The revision stamp lives under the owning prefix, the manual regenerate
// trigger is read from there on the builder, and generator-produced annotations
// under it are rejected (see validateAnnotations).
const (
	// secretReservedAnnotationPrefix / configMapReservedAnnotationPrefix are the
	// annotation namespaces the operator owns on a Secret / ConfigMap output.
	secretReservedAnnotationPrefix    = "secrets.advok8s.io/"
	configMapReservedAnnotationPrefix = "configmaps.advok8s.io/"

	// SecretRevisionAnnotation / ConfigMapRevisionAnnotation are stamped on a
	// produced Secret / ConfigMap with a content-derived hash so downstream
	// builders observe upstream changes. The resolver reads each input's
	// revision under the annotation matching that input's kind and folds it into
	// the input fingerprint.
	SecretRevisionAnnotation    = secretReservedAnnotationPrefix + "revision"
	ConfigMapRevisionAnnotation = configMapReservedAnnotationPrefix + "revision"

	// SecretRegenerateAnnotation / ConfigMapRegenerateAnnotation, when set on a
	// SecretBuilder / ConfigMapBuilder to a new value, trigger a manual rotation
	// (the kubectl rollout-restart idiom). The controller records the
	// last-handled value in status so each new value rotates exactly once.
	SecretRegenerateAnnotation    = secretReservedAnnotationPrefix + "regenerate"
	ConfigMapRegenerateAnnotation = configMapReservedAnnotationPrefix + "regenerate"
)

// reservedPrefix returns the operator-owned annotation prefix for this output
// kind.
func (k OutputKind) reservedPrefix() string {
	if k == OutputConfigMap {
		return configMapReservedAnnotationPrefix
	}
	return secretReservedAnnotationPrefix
}
