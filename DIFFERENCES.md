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
  `secrets.advok8s.io/secret-copier` and `secrets.advok8s.io/secret-name`
  (not the `secrets.educates.dev/...` equivalents).

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
  failures),
- per-rule status.

## Not yet implemented

`SecretExporter`, `SecretImporter`, and `SecretInjector` are not yet ported. When
they land, their differences (including the `copyAuthorization` handshake and
their own status fields) will be recorded here.
