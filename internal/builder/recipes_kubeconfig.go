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
	"fmt"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// KubeconfigFromServiceAccount builds a single-context kubeconfig YAML for a
// ServiceAccount token, the common "give this SA a kubeconfig" case. Empty names
// default sensibly. caCert (PEM) is optional.
func KubeconfigFromServiceAccount(token, server, caCert, clusterName, userName, contextName string) (string, error) {
	if clusterName == "" {
		clusterName = "cluster"
	}
	if userName == "" {
		userName = "user"
	}
	if contextName == "" {
		contextName = clusterName
	}

	cfg := clientcmdapi.NewConfig()

	cluster := clientcmdapi.NewCluster()
	cluster.Server = server
	if caCert != "" {
		cluster.CertificateAuthorityData = []byte(caCert)
	}
	cfg.Clusters[clusterName] = cluster

	auth := clientcmdapi.NewAuthInfo()
	auth.Token = token
	cfg.AuthInfos[userName] = auth

	kctx := clientcmdapi.NewContext()
	kctx.Cluster = clusterName
	kctx.AuthInfo = userName
	cfg.Contexts[contextName] = kctx

	cfg.CurrentContext = contextName

	out, err := clientcmd.Write(*cfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// KubeconfigMerge unions several kubeconfig YAML documents into one. On a clashing
// cluster/user/context name the default is first-wins (the earliest document's
// entry is kept); strict makes a clash an error instead. currentContext, when set,
// overrides the merged current-context (otherwise the first non-empty one wins).
func KubeconfigMerge(configs []string, currentContext string, strict bool) (string, error) {
	merged := clientcmdapi.NewConfig()

	for i, raw := range configs {
		cfg, err := clientcmd.Load([]byte(raw))
		if err != nil {
			return "", fmt.Errorf("kubeconfig %d: %w", i, err)
		}

		for name, v := range cfg.Clusters {
			if _, exists := merged.Clusters[name]; exists {
				if strict {
					return "", fmt.Errorf("conflicting cluster %q", name)
				}
				continue // first-wins
			}
			merged.Clusters[name] = v
		}
		for name, v := range cfg.AuthInfos {
			if _, exists := merged.AuthInfos[name]; exists {
				if strict {
					return "", fmt.Errorf("conflicting user %q", name)
				}
				continue
			}
			merged.AuthInfos[name] = v
		}
		for name, v := range cfg.Contexts {
			if _, exists := merged.Contexts[name]; exists {
				if strict {
					return "", fmt.Errorf("conflicting context %q", name)
				}
				continue
			}
			merged.Contexts[name] = v
		}

		if merged.CurrentContext == "" {
			merged.CurrentContext = cfg.CurrentContext
		}
	}

	if currentContext != "" {
		merged.CurrentContext = currentContext
	}

	out, err := clientcmd.Write(*merged)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
