# advok8s-secrets-manager

A Kubernetes operator that copies Secrets from a source namespace into one or
more target namespaces and keeps the copies in sync.

## Description

`advok8s-secrets-manager` removes the need to manually duplicate shared Secrets
(image pull secrets, TLS certificates, API tokens, etc.) across namespaces. You
describe what to copy and where using a cluster-scoped `SecretCopier` custom
resource (API group `secrets.advok8s.io/v1beta1`), and the controller does the
rest.

A `SecretCopier` holds a list of rules. Each rule defines:

- **A source secret** — the Secret to copy, identified by name and namespace.
- **Target namespaces** — which namespaces receive a copy, chosen by one or more
  selectors: by name (`nameSelector`), by labels (`labelSelector`), by owner
  reference (`ownerSelector`), or by namespace UID (`uidSelector`).
- **A target secret** — the name to give the copy (allowing a rename) and any
  extra labels to apply to it.
- **A reclaim policy** — `Delete` (default) or `Retain`, controlling whether
  copies are garbage-collected.

For every namespace that matches a rule, the controller creates a Secret with
the source Secret's type and data, merges the source Secret's labels with any
labels named in the rule, and stamps tracking annotations
(`secrets.advok8s.io/secret-copier` and `secrets.advok8s.io/secret-name`) so it
can recognise and update its own copies. When the reclaim policy is `Delete`, it
sets an owner reference on each copy so Kubernetes garbage-collects the copies
automatically when the `SecretCopier` is removed.

Copies are kept current: the controller re-reconciles on a configurable interval
(`spec.syncPeriod`, default `1m`) and also reacts to changes in source Secrets
and namespaces, so copies update when a source Secret changes and new copies
appear when a matching namespace is created.

### Example

```yaml
apiVersion: secrets.advok8s.io/v1beta1
kind: SecretCopier
metadata:
  name: distribute-pull-secret
spec:
  syncPeriod: 1m
  rules:
  - sourceSecret:
      namespace: platform
      name: registry-credentials
    targetNamespaces:
      labelSelector:
        matchLabels:
          team: backend
    targetSecret:
      name: registry-credentials
      labels:
        managed-by: advok8s-secrets-manager
    reclaimPolicy: Delete
```

This copies the `registry-credentials` Secret from the `platform` namespace into
every namespace labelled `team=backend`, and re-creates or updates those copies
whenever the source changes or a new matching namespace appears.

## Getting Started

### Prerequisites
- go version v1.25.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/advok8s-secrets-manager:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/advok8s-secrets-manager:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/advok8s-secrets-manager:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/advok8s-secrets-manager/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
kubebuilder edit --plugins=helm/v2-alpha
```

2. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## Contributing

Contributions are welcome. Please open an issue to discuss substantial changes
before submitting a pull request, and make sure `make test` and `make lint` pass
before opening one. The project is scaffolded with [Kubebuilder](https://book.kubebuilder.io/);
after editing API types or markers, run `make manifests generate` to regenerate
the CRDs, RBAC, and DeepCopy code.

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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

