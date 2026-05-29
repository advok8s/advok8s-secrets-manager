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

Each file's header comment lists the exact apply / verify / clean-up commands
for that scenario.
