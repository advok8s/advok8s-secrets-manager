# Differences from the Educates implementation

This operator is a Go reimplementation of the Educates `secrets-manager`
operator. The custom resources are intended to be functionally equivalent to the
originals, whose behaviour is documented authoritatively in the Educates project:

- [secret-copier](https://github.com/educates/educates-training-platform/blob/develop/project-docs/custom-resources/secret-copier.md)
- [secret-exporter](https://github.com/educates/educates-training-platform/blob/develop/project-docs/custom-resources/secret-exporter.md)
- [secret-importer](https://github.com/educates/educates-training-platform/blob/develop/project-docs/custom-resources/secret-importer.md)
- [secret-injector](https://github.com/educates/educates-training-platform/blob/develop/project-docs/custom-resources/secret-injector.md)

This document records only how this implementation **diverges** from those docs.
For field-level detail, use `kubectl explain <kind>.spec` against an installed
CRD — field descriptions are generated from the API types and stay in sync with
the code.

This file describes the **shipped** resources only. For resources not yet ported
and the plan for adding them, see the porting plan kept alongside the repository.

## Naming / GVK

- **API group** is `secrets.advok8s.io` (not `secrets.educates.dev`). The
  version is `v1beta1`.
- **Tracking annotations** on copied resources follow the same rename:
  `secrets.advok8s.io/copier-rule` (value `kind/name`, e.g. `secretcopier/x`,
  `secretexporter/y` or `configmapcopier/z`) and `secrets.advok8s.io/resource`
  (value `namespace/name` of the source) — the `secrets.educates.dev/...`
  equivalents. A third annotation, `secrets.advok8s.io/managed-labels`, records
  the label keys the operator manages on each copy (see the label semantics
  below).

Because the group differs, secrets copied by the Educates operator are not
recognised as managed by this one, and vice versa. This matters only if both
operators are ever run against the same cluster, or during a migration.

## Copy semantics (SecretCopier, SecretExporter, ConfigMapCopier)

### Changed: event-driven convergence, no `spec.syncPeriod`

The Educates implementation re-reconciles on a fixed internal 60-second timer.
This implementation is event-driven: watches cover source changes, namespace
lifecycle, importer changes, and target deletion / tampering / conflict
clearance, so copies converge in response to the change rather than on a clock.
A fixed internal 5-minute per-instance backstop requeue bounds the staleness
caused by any missed event. There is no user-facing `syncPeriod` field on the
copy-side resources.

### Changed: managed-subset label reconciliation

The labels on a copy are reconciled as a managed subset rather than as the
whole label map. The operator records the label keys it manages (source labels
plus the rule's target labels) in the `secrets.advok8s.io/managed-labels`
annotation, re-asserts exactly those keys, and removes a key only when it was
previously managed and is no longer expected. Labels outside the managed set —
for example labels injected at admission by a Kyverno or Gatekeeper mutating
policy — are neither compared nor touched, so the operator never fights an
admission webhook in a reconcile loop. The practical behaviour is unchanged for
clusters without label-injecting webhooks.

Annotations on a copy are never compared or rewritten after creation, so
third-party annotations persist. Note the sharp edge this implies: stripping
the tracking annotations from a copy orphans it (the operator reports a
conflict and stops updating it).

## SecretCopier

### Added: populated `status`

The Educates implementation leaves `status` unmanaged. This implementation
populates it (see `kubectl explain secretcopier.status` for the field list):

- `observedGeneration`,
- `Ready` / `Degraded` conditions,
- a `summary` block (matched target namespaces, secrets in sync, conflicts,
  awaiting authorization, failures),
- per-rule status.

## SecretExporter

Behaviourally equivalent to the Educates resource (the exporter's own name is the
source secret; each copy requires a paired SecretImporter, which becomes the
copy's owner; an omitted shared secret defaults to the exporter's UID).

### Added: populated `status`

As for SecretCopier, a populated `status` (`observedGeneration`,
`Ready`/`Degraded` conditions, `sourceExists`, and summary / per-rule counts
including `awaitingAuthorization`). The Educates implementation leaves status
unmanaged. Convergence is event-driven (see the copy semantics section above).

## SecretImporter

Behaviourally equivalent: it performs no copying, only authorizing a paired
SecretExporter or SecretCopier (named the same as the target secret, with a
matching shared secret, and an optional source-namespace restriction).

### Added: populated `status`

The Educates implementation leaves status unmanaged. This implementation runs a
status-only reconciler that reports `observedGeneration`, a `Ready` condition
(reason `Imported`, `AwaitingAuthorization`, or `NoMatchingExporter`),
`imported`, `boundTo` (what is exporting the secret), and `targetSecretName`.

### Removed: `spec.sourceSecret`

The Educates `SecretImporter` CRD declares a `sourceSecret.name` field, but the
Python controller never reads it — it appears to be a copy-paste leftover. This
implementation omits it. Authorization keys off the importer's name, shared
secret, and source-namespace selector.

## SecretInjector

Behaviourally equivalent: it injects references to matching secrets into matching
service accounts within matching namespaces — image pull secrets
(`kubernetes.io/dockerconfigjson`) into `imagePullSecrets`, other types into
`secrets` — adding references idempotently and never removing them. Service-account
name matching is exact set membership (no globs), as in the Python operator;
source-secret matching is a superset (see below).

### Added: `spec.syncPeriod` and populated `status`

As for the other resources: a configurable `syncPeriod` (default `1m`, `"0s"` to
disable) and a populated `status` (`observedGeneration`, `Ready`/`Degraded`
conditions, and summary / per-rule counts: target namespaces, service accounts
matched, injections in sync, failures). `injectionsInSync` counts references that
are present, not a reconciled-to-exact total, because injections are never
removed. The Educates implementation leaves status unmanaged.

### Superset: richer `sourceSecrets` and `targetNamespaces` selectors

`targetNamespaces` reuses the same selector as SecretCopier, which includes
`ownerSelector` (and `uidSelector`); the Educates CRD offers only name / uid /
label selectors for namespaces.

`sourceSecrets` uses the shared `SecretSelector` (name / label / **owner** /
**uid**) rather than the Educates name+label-only selector, and its name matching
supports shell-style globs and `!` exclusions (the `NameSelector` form) instead of
exact set membership.

Both are **harmless supersets**: a rule that uses only name / label selectors with
plain (non-glob) names behaves identically to the Educates operator. The added
`ownerSelector` / `uidSelector` and glob support only take effect when used.

## SecretBuilder

### Added: a net-new resource with no Educates equivalent

The Educates `secrets-manager` has no builder/generator resource. `SecretBuilder`
is new in this implementation: a namespaced resource that generates a `Secret`
named the same as itself by running a Starlark script or gotemplate template over
declared inputs (constants, referenced Secrets/ConfigMaps, a minted ServiceAccount
token, and operator-generated random material such as passwords, keys and
certificates). It is documented in `docs/secret-builder.md`.

Unlike the other resources in this file, there is no original to diverge from, so
nothing here is a behavioural difference — the whole resource is the addition. It
shares the family's selector vocabulary (`SecretSelector`) and conventions
(populated status, `Ready`/`Degraded` conditions, events, ownerReference-based
garbage collection of its output).

## ConfigMapCopier and ConfigMapBuilder

### Added: net-new resources with no Educates equivalent

The Educates `secrets-manager` manages Secrets only. This implementation adds
ConfigMap counterparts for two of the patterns:

- **`ConfigMapCopier`** — cluster-scoped, admin-operated distribution of
  ConfigMaps across namespaces, mirroring SecretCopier **minus authorization**:
  there is no ConfigMapImporter/ConfigMapExporter and no `copyAuthorization`
  field. ConfigMaps carry no secret material, so the consent handshake that
  motivates the Secret import/export machinery does not apply; tenant-level
  sharing stays Secret-only by design. Documented in
  `docs/config-map-copier.md`.
- **`ConfigMapBuilder`** — generates a ConfigMap from declared inputs via a
  Starlark script or gotemplate template, mirroring SecretBuilder with the
  ConfigMap output contract (separate `data`/`binaryData`, no type) and
  deliberately curated inputs: no `serviceAccount`, and `generated` restricted
  to `uuid`/`randomInt`. Secret material is generated with a SecretBuilder and
  its non-secret parts pulled in via a `secrets` input. Documented in
  `docs/config-map-builder.md`.

As with SecretBuilder, these are additions rather than divergences.
