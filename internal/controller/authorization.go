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

	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/advok8s/advok8s-secrets-manager/api/secrets/v1beta1"
)

// authorizeCopyTarget resolves the SecretImporter (if any) named targetName in
// targetNamespace and reports whether copying a secret from sourceNamespace into
// that namespace is authorized.
//
// The rules mirror the Python operator:
//
//   - When requiredSharedSecret is non-empty (the rule demands authorization),
//     a SecretImporter must exist and its copyAuthorization.sharedSecret must
//     match, otherwise the copy is not authorized.
//   - When a SecretImporter exists (whether or not a shared secret was required),
//     its sourceNamespaces.nameSelector must admit the source namespace. An empty
//     selector admits any source namespace.
//
// The importer is returned (nil when none exists) so the caller can use it as
// the owner of the copy where appropriate (the SecretExporter path). A non
// not-found error reading the importer is returned so the caller can treat it
// as a failure rather than silently denying authorization.
func authorizeCopyTarget(ctx context.Context, c client.Client, targetNamespace, targetName, sourceNamespace, requiredSharedSecret string) (importer *secretsv1beta1.SecretImporter, authorized bool, err error) {
	var found secretsv1beta1.SecretImporter

	getErr := c.Get(ctx, client.ObjectKey{Namespace: targetNamespace, Name: targetName}, &found)

	switch {
	case getErr != nil && client.IgnoreNotFound(getErr) == nil:
		// No importer with that name in the target namespace.
		importer = nil
	case getErr != nil:
		return nil, false, getErr
	default:
		importer = &found
	}

	// When the rule requires a shared secret, an importer must exist and carry a
	// matching one.

	if requiredSharedSecret != "" {
		if importer == nil {
			return nil, false, nil
		}

		if importer.Spec.CopyAuthorization.SharedSecret != requiredSharedSecret {
			return importer, false, nil
		}
	}

	// When an importer exists it may further restrict the source namespaces it
	// will accept a copy from. An absent or empty selector accepts any source
	// namespace.

	if importer != nil && importer.Spec.SourceNamespaces != nil {
		selector := importer.Spec.SourceNamespaces.NameSelector

		if !selector.IsEmpty() && !selector.Matches(sourceNamespace) {
			return importer, false, nil
		}
	}

	return importer, true, nil
}
