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
- **Tracking annotations** on copied secrets follow the same rename:
  `secrets.advok8s.io/copier-rule` (value `kind/name`, e.g. `secretcopier/x` or
  `secretexporter/y`) and `secrets.advok8s.io/secret-name` (value
  `namespace/name` of the source) — the `secrets.educates.dev/...` equivalents.

Because the group differs, secrets copied by the Educates operator are not
recognised as managed by this one, and vice versa. This matters only if both
operators are ever run against the same cluster, or during a migration.

## SecretCopier

### Added: `spec.syncPeriod`

The Educates implementation re-reconciles on a fixed internal timer. This
implementation exposes the interval as `spec.syncPeriod` (a duration string):

- unset → defaults to `1m`,
- `"0s"` → disables periodic re-sync (copies still update in response to source
  secret and namespace changes),
- a positive value → re-reconcile at that interval.

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

### Added: `spec.syncPeriod` and populated `status`

As for SecretCopier: a configurable `syncPeriod` (default `1m`, `"0s"` to
disable), and a populated `status` (`observedGeneration`, `Ready`/`Degraded`
conditions, `sourceExists`, and summary / per-rule counts including
`awaitingAuthorization`). The Educates implementation leaves status unmanaged.

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
`secrets` — adding references idempotently and never removing them. Source-secret
and service-account name matching is exact set membership (no globs), as in the
Python operator.

### Added: `spec.syncPeriod` and populated `status`

As for the other resources: a configurable `syncPeriod` (default `1m`, `"0s"` to
disable) and a populated `status` (`observedGeneration`, `Ready`/`Degraded`
conditions, and summary / per-rule counts: target namespaces, service accounts
matched, injections in sync, failures). `injectionsInSync` counts references that
are present, not a reconciled-to-exact total, because injections are never
removed. The Educates implementation leaves status unmanaged.

### Superset: `targetNamespaces` also supports `ownerSelector`

The injector reuses the same target-namespace selector as SecretCopier, which
includes `ownerSelector` (and `uidSelector`). The Educates `SecretInjector` CRD
offers only name / uid / label selectors for namespaces, so this is a (harmless)
superset; rules that do not use `ownerSelector` behave identically.
