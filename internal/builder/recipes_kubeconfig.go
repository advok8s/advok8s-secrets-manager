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

// KubeconfigParams is the full set of pieces KubeconfigBuild assembles into a
// single-context kubeconfig: a cluster (name, server, CA), a user (a token, or a
// client cert+key), and a context (name, optional namespace). Empty names default
// sensibly; CA, namespace and the credential fields are optional.
type KubeconfigParams struct {
	Server      string // API server URL
	CACert      string // cluster CA (PEM), optional
	Token       string // bearer token credential, optional
	ClientCert  string // client certificate (PEM), optional
	ClientKey   string // client key (PEM), optional
	ClusterName string // defaults to "cluster"
	UserName    string // defaults to "user"
	ContextName string // defaults to ClusterName
	Namespace   string // context namespace, optional
}

// KubeconfigBuild assembles a single-context kubeconfig YAML from explicit pieces.
// It is the general constructor; KubeconfigFromServiceAccount is the convenience
// for the SA-token case.
func KubeconfigBuild(p KubeconfigParams) (string, error) {
	clusterName := p.ClusterName
	if clusterName == "" {
		clusterName = "cluster"
	}
	userName := p.UserName
	if userName == "" {
		userName = "user"
	}
	contextName := p.ContextName
	if contextName == "" {
		contextName = clusterName
	}

	cfg := clientcmdapi.NewConfig()

	cluster := clientcmdapi.NewCluster()
	cluster.Server = p.Server
	if p.CACert != "" {
		cluster.CertificateAuthorityData = []byte(p.CACert)
	}
	cfg.Clusters[clusterName] = cluster

	auth := clientcmdapi.NewAuthInfo()
	auth.Token = p.Token
	if p.ClientCert != "" {
		auth.ClientCertificateData = []byte(p.ClientCert)
	}
	if p.ClientKey != "" {
		auth.ClientKeyData = []byte(p.ClientKey)
	}
	cfg.AuthInfos[userName] = auth

	kctx := clientcmdapi.NewContext()
	kctx.Cluster = clusterName
	kctx.AuthInfo = userName
	kctx.Namespace = p.Namespace
	cfg.Contexts[contextName] = kctx

	cfg.CurrentContext = contextName

	out, err := clientcmd.Write(*cfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// KubeconfigFromServiceAccount builds a single-context kubeconfig YAML for a
// ServiceAccount token, the common "give this SA a kubeconfig" case. Empty names
// default sensibly. caCert (PEM) is optional.
func KubeconfigFromServiceAccount(token, server, caCert, clusterName, userName, contextName string) (string, error) {
	return KubeconfigBuild(KubeconfigParams{
		Server:      server,
		CACert:      caCert,
		Token:       token,
		ClusterName: clusterName,
		UserName:    userName,
		ContextName: contextName,
	})
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
