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

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// WriteRequest is the assembled output for WriteSecret. The controller owns the
// merge of spec.output with the engine Result before calling.
type WriteRequest struct {
	Name        string
	Namespace   string
	Type        string // Secret type; defaults to Opaque. Immutable after creation.
	Labels      map[string]string
	Annotations map[string]string
	Data        map[string][]byte
	Revision    string
}

// WriteSecret creates or updates the output Secret owned by owner. The Secret type
// is set only on creation (it is immutable in Kubernetes); labels, annotations
// (including the revision) and data are reconciled on every write. This is the
// Secret-specific output writer; a future ConfigMapBuilder would supply its own.
func WriteSecret(ctx context.Context, c client.Client, scheme *runtime.Scheme, owner client.Object, req WriteRequest) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: req.Name, Namespace: req.Namespace},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, c, secret, func() error {
		if secret.UID == "" { // creating
			if req.Type != "" {
				secret.Type = corev1.SecretType(req.Type)
			} else {
				secret.Type = corev1.SecretTypeOpaque
			}
			if err := controllerutil.SetControllerReference(owner, secret, scheme); err != nil {
				return err
			}
		} else if req.Type != "" && string(secret.Type) != req.Type {
			return fmt.Errorf("cannot change immutable Secret type from %q to %q; delete the Secret to recreate it", secret.Type, req.Type)
		}

		if secret.Labels == nil {
			secret.Labels = map[string]string{}
		}
		for k, v := range req.Labels {
			secret.Labels[k] = v
		}

		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		for k, v := range req.Annotations {
			secret.Annotations[k] = v
		}
		if req.Revision != "" {
			secret.Annotations[RevisionAnnotation] = req.Revision
		}

		secret.Data = req.Data
		return nil
	})
	return err
}

// RevisionOf is a stable, content-derived revision of the produced data. It is
// stamped on the output Secret so downstream builders observe changes and is
// recorded in status. It changes only when the produced data changes.
func RevisionOf(data map[string][]byte) string {
	h := sha256.New()
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "%s=", k)
		h.Write(data[k])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
