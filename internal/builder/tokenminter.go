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

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ClientsetTokenMinter mints bound ServiceAccount tokens via the TokenRequest API
// using a typed clientset (the controller-runtime client does not service the
// token subresource). It is the production implementation of TokenMinter.
type ClientsetTokenMinter struct {
	Clientset kubernetes.Interface
}

// MintToken requests a bound token for the named ServiceAccount, passing audiences
// and expirationSeconds straight through to the TokenRequest.
func (m *ClientsetTokenMinter) MintToken(ctx context.Context, namespace, serviceAccount string, audiences []string, expirationSeconds *int64) (string, error) {
	tr := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: expirationSeconds,
		},
	}
	out, err := m.Clientset.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, serviceAccount, tr, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	return out.Status.Token, nil
}
