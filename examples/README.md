# Examples

Self-contained, runnable scenarios for trying the operator by hand. Unlike
[`config/samples/`](../config/samples/) — which holds minimal, one-CR-per-kind
templates wired into the kustomize build — each file here bundles **all** the
resources a scenario needs (its own namespaces, secrets, and custom resources)
so it can be applied and removed as a unit:

```sh
kubectl apply  -f examples/<scenario>.yaml
kubectl delete -f examples/<scenario>.yaml
```

Each scenario uses its own uniquely named `demo-*` namespaces, so scenarios do
not collide and deleting the file deletes everything it created (namespaced
resources are removed when their namespace is deleted; the cluster-scoped
SecretCopier is removed directly). Nothing here is referenced by a kustomization,
so `make install` / `make deploy` never apply these.

Prerequisites: the CRDs installed (`make install`) and the operator running
(`make deploy IMG=...`, or run locally).

## Scenarios

| File | Demonstrates |
|------|--------------|
| [secretcopier-basic.yaml](secretcopier-basic.yaml) | Copy a secret to a target namespace selected by exact name; reclaimPolicy Delete. |
| [secretcopier-label-selector.yaml](secretcopier-label-selector.yaml) | Copy to namespaces selected by label, renaming the copy and adding a label. |
| [secretcopier-with-importer.yaml](secretcopier-with-importer.yaml) | A SecretCopier whose copy is gated by a matching SecretImporter (copyAuthorization). |
| [secretexporter-basic.yaml](secretexporter-basic.yaml) | A namespaced SecretExporter exporting its like-named secret to a target namespace that consents via a SecretImporter; the importer owns the copy (deleting it garbage-collects the copy). |
| [secretexporter-source-namespaces.yaml](secretexporter-source-namespaces.yaml) | A SecretImporter that further restricts which source namespaces it accepts, plus target renaming; one of two competing exporters is refused. |
| [secretinjector-serviceaccount.yaml](secretinjector-serviceaccount.yaml) | A SecretInjector adding an image pull secret to a named (non-default) ServiceAccount's imagePullSecrets, leaving the default service account untouched. |
| [secretbuilder-derive.yaml](secretbuilder-derive.yaml) | A SecretBuilder deriving a connection string from an existing Secret (no generated material; output is a pure function of the input). |
| [secretbuilder-password-htpasswd.yaml](secretbuilder-password-htpasswd.yaml) | A SecretBuilder generating a password and using it three ways: plaintext, a bcrypt htpasswd entry, and an HTTP Basic header. |
| [secretbuilder-tls.yaml](secretbuilder-tls.yaml) | A SecretBuilder generating a CA and a CA-signed TLS leaf, publishing a fullchain `tls.crt` (type `kubernetes.io/tls`). |
| [secretbuilder-jwt.yaml](secretbuilder-jwt.yaml) | A SecretBuilder signing a JWT with a generated RSA key, rotated before expiry (`rotateEvery`) while keeping the signing key. |
| [secretbuilder-template.yaml](secretbuilder-template.yaml) | A SecretBuilder using the gotemplate engine (`template:`) with Sprig functions instead of a Starlark script. |
| [secretbuilder-chaining.yaml](secretbuilder-chaining.yaml) | Two chained SecretBuilders: an upstream password change propagates to a downstream builder via `onInputChange`. |
| [secretbuilder-kubeconfig-merge.yaml](secretbuilder-kubeconfig-merge.yaml) | Two ServiceAccounts, each turned into a single-context kubeconfig (`kubeconfig.fromServiceAccount`, distinct context names), then merged into one multi-context kubeconfig by a third builder (`kubeconfig.merge`). |

Each file's header comment lists the exact apply / verify / clean-up commands
for that scenario.
