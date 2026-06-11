ConfigMap Copier
================

The ``ConfigMapCopier`` custom resource copies ConfigMaps from a source
namespace into one or more target namespaces and keeps the copies in sync. It
is the ConfigMap counterpart of ``SecretCopier``, **minus authorization**:
there is no ConfigMapImporter/ConfigMapExporter handshake. ConfigMaps carry no
secret material, so cross-namespace distribution is an admin-operated
mechanism — the ``ConfigMapCopier`` is cluster-scoped, and whoever can create
one decides where config flows. Namespace-owner-to-namespace-owner sharing
with consent stays Secret-only (``SecretExporter`` / ``SecretImporter``), where
the handshake is actually motivated; and *derived* non-secret config is better
built in place with a [``ConfigMapBuilder``](config-map-builder.md), pulling
non-secret fields out of Secrets that crossed the namespace boundary under the
existing authorized machinery.

The raw custom resource definition can be viewed by running:

```shell
kubectl get crd/configmapcopiers.secrets.advok8s.io -o yaml
```

The field-level reference:

```shell
kubectl explain configmapcopier.spec
```

Rules
-----

```yaml
apiVersion: secrets.advok8s.io/v1beta1
kind: ConfigMapCopier
metadata:
  name: org-defaults
spec:
  rules:
  - sourceConfigMap:            # required: namespace + name
      namespace: platform
      name: shared-settings
    targetNamespaces:           # the same selector family as SecretCopier
      labelSelector:
        matchLabels:
          team: backend
    targetConfigMap:            # optional
      name: settings            # defaults to the source name
      labels:                   # extra labels overlaid on the copy
        managed-by: advok8s-secrets-manager
      annotations:              # annotations applied to the copy
        example.com/origin: platform
    reclaimPolicy: Delete       # Delete (default) | Retain
```

There is deliberately **no ``copyAuthorization`` field** — the concept does not
exist for ConfigMaps, rather than being carried as a dead field.

Copy semantics
--------------

A copy is a full replacement, continuously converged:

- **Both payload maps move together.** ``data`` and ``binaryData`` are compared
  and replaced as a pair, so a key migrating between the two maps in the source
  (a value that used to be text becoming binary, say) converges cleanly on the
  target. Both directions reconcile: keys added to the target are removed, keys
  removed from the source are removed.
- **The source's ``immutable`` flag is ignored.** The copy is a new object the
  operator owns and controls; the source's immutability is its own business.
  (Conversely, hand-marking a *target* immutable makes updates fail, reported
  as failures in status.)
- **Labels are reconciled as a managed subset.** The operator records the label
  keys it manages (source labels plus the rule's ``targetConfigMap.labels``) in
  the ``secrets.advok8s.io/managed-labels`` annotation and reconciles exactly
  that set: a managed label removed from the source is removed from the copy,
  while labels added to the copy by anything else — for example a Kyverno or
  Gatekeeper mutating policy stamping labels at admission — are neither
  compared nor touched, so the operator never fights an admission webhook in a
  reconcile loop.
- **Annotations follow the same managed-subset model.** Source annotations are
  **never** copied (annotations are often controller-specific instructions
  that must not propagate verbatim); the rule's ``targetConfigMap.annotations``
  are applied explicitly, recorded in the
  ``secrets.advok8s.io/managed-annotations`` annotation, and reconciled exactly
  like managed labels — re-asserted when tampered with, removed when dropped
  from the rule. Keys under the operator-owned ``secrets.advok8s.io/`` prefix
  are rejected at admission. Annotations outside the managed set are never
  compared or rewritten, so third-party annotations persist. The sharp edge:
  the tracking annotations live in that same unguarded space — stripping
  ``secrets.advok8s.io/copier-rule`` or ``secrets.advok8s.io/resource`` from a
  copy orphans it (the operator reports a conflict and stops updating it).

Conflicts
---------

A target name already occupied by a ConfigMap the operator did not create (or
created from a different source / rule) is **never overwritten**: the rule
records a conflict in status and leaves the object alone. If the foreign
ConfigMap is later deleted, the copy claims the name immediately (the deletion
event triggers it).

Reclaim policy
--------------

``Delete`` (the default) makes the ConfigMapCopier the owner of its copies, so
deleting the copier garbage-collects them. ``Retain`` creates copies with no
owner reference; they survive the copier.

Convergence model
-----------------

Convergence is event-driven: watches cover source ConfigMap changes, namespace
lifecycle (a new or newly-labelled namespace receives its copies immediately),
and the targets themselves — deleting or hand-editing a copy triggers repair
from the event, as does conflict clearance. A fixed internal 5-minute
per-instance backstop requeue bounds the staleness caused by any missed event;
there is no user-facing sync period. Terminating namespaces are skipped.

Status and observability
------------------------

Mirrors ``SecretCopier`` (without ``awaitingAuthorization``, which cannot
occur): ``observedGeneration``, ``Ready`` / ``Degraded`` conditions, a
``summary`` (target namespaces matched, ``configMapsInSync``, conflicts,
failures) and per-rule counts including ``sourceExists``. Counts only are
recorded — never the individual namespaces — so status size is bounded by the
number of rules, not the cluster. Events are emitted on Degraded transitions.

```shell
kubectl get configmapcopiers
# NAME           READY   NAMESPACES   IN SYNC   FAILURES   AGE
# org-defaults   True    2            2         0          30s
```
