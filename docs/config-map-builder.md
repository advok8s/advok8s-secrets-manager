ConfigMap Builder
=================

The ``ConfigMapBuilder`` custom resource generates a ``ConfigMap``, named the
same as the resource, by running a script or template over a set of declared
inputs. It is a namespaced resource, and the generated ``ConfigMap`` is created
in the same namespace. It is the ConfigMap counterpart of
[``SecretBuilder``](secret-builder.md) and shares its machinery — inputs,
generator engines, recipes, and the regeneration model — differing only where
Secrets and ConfigMaps differ. This page documents the differences; everything
not covered here behaves exactly as documented for ``SecretBuilder``.

The raw custom resource definition can be viewed by running:

```shell
kubectl get crd/configmapbuilders.secrets.advok8s.io -o yaml
```

The field-level reference is generated from the API types and stays in sync
with the code, so the authoritative description of any field is:

```shell
kubectl explain configmapbuilder.spec
```

The simplest builder has just a generator:

```yaml
apiVersion: secrets.advok8s.io/v1beta1
kind: ConfigMapBuilder
metadata:
  name: app-config
  namespace: app
spec:
  generator:
    script: |
      configMap = {"data": {"hello": "world"}}
```

The whole spec has this shape:

```yaml
spec:
  inputs:                 # what the generator can read (all optional)
    constants: {...}        # plaintext typed config
    secrets: [...]          # existing Secrets in this namespace (decoded)
    configMaps: [...]       # existing ConfigMaps in this namespace
    generated: [...]        # operator-generated material: uuid, randomInt only
    libraries: [...]        # Starlark-only: load() modules from a ConfigMap
  output:                 # shape of the produced ConfigMap (optional)
    labels: {...}           # no type - ConfigMaps have none
    annotations: {...}
  generator:              # required: exactly one engine
    script: |               # Starlark
      ...
    # or:
    # template:             # gotemplate (per-key template map)
    #   data: {...}
    #   labels: {...}
  regeneration:           # optional; default = generate once, never again
    onInputChange: true
    rotateEvery: 720h
    rotateGenerated: false
```

The output contract: data and binaryData
----------------------------------------

A ``ConfigMap`` carries two payload maps: ``data`` (string values, which must
be valid UTF-8) and ``binaryData`` (arbitrary bytes). The Starlark script sets
a ``configMap`` global with **separate dicts** — placement decides where a key
lands:

```python
logo = base64.decode(input.configMaps.artwork.data["logo.b64"])

configMap = {
    "data": {
        "title": input.constants.title,      # str
        "report": yaml.encode({"a": 1}),     # str
    },
    "binaryData": {
        "logo.png": logo,                    # bytes
    },
    "labels": {"app": "demo"},
}
```

The rules, enforced identically whichever engine produced the output:

- **Values are raw.** Both dicts accept ``str`` or ``bytes``; the author never
  base64-encodes anything (wire encoding of ``binaryData`` is handled by the
  cluster, exactly as Secret data is). A ``str`` placed in ``binaryData`` is
  stored as its bytes; ``bytes`` placed in ``data`` are fine **if** they are
  valid UTF-8.
- **``data`` values must be valid UTF-8.** A non-UTF-8 value in ``data`` is a
  generation error naming the key and pointing at ``binaryData``. The value's
  Starlark type is deliberately *not* the gate — a binary value read from a
  Secret input arrives as a ``str``, and ``base64.decode`` returns ``bytes``
  that may well be text; only the content matters.
- **A key may not appear in both dicts** (the API server rejects the duplicate).
- At least one of ``data`` / ``binaryData`` must be present (either may be
  empty), and there is no ``type`` — ConfigMaps have none.
- The combined size of both maps is capped at 1 MiB (the API server enforces
  the same limit).

A script written for ``SecretBuilder`` that sets a ``secret`` global gets a
pointed error telling it to set ``configMap`` instead.

### The template engine renders text only

The ``template`` generator has ``data`` and ``labels`` — **no ``binaryData``
field exists**. Templates are UTF-8 text living in a CRD string field, so raw
binary cannot even be authored in one; rather than invent a special encoding
convention for templates that would differ from the script's "never encode"
rule, binary output simply requires the script generator. Rendered ``data``
values pass the same UTF-8 gate (splicing a binary Secret value through a
template is caught with the same error as the script path).

```yaml
generator:
  template:
    data:
      app.properties: |
        name={{ .constants.appName }}
        region={{ .configMaps.cluster.data.region }}
    labels:
      app: '{{ .constants.appName }}'
```

Inputs: what is different from SecretBuilder
--------------------------------------------

``constants``, ``configMaps``, ``secrets`` and ``libraries`` behave exactly as
for ``SecretBuilder``. The differences are deliberate restrictions:

- **No ``serviceAccount`` input.** A minted ServiceAccount token must never
  land in a world-readable ConfigMap, so the field does not exist in the
  schema.
- **``generated`` is curated to ``uuid`` and ``randomInt``.** Every other kind
  (passwords, tokens, random bytes, private keys, certificates) either *is*
  secret material or is only useful when its secret half lives somewhere
  usable. Generate those with a ``SecretBuilder`` and pull the non-secret
  parts in via a ``secrets`` input — the extra step is the useful prompt to
  ask why a value is going into a ConfigMap at all.

```yaml
inputs:
  generated:
  - name: instance
    uuid: {}            # input.generated.instance.value
  - name: shard
    randomInt:          # input.generated.shard.value
      min: 0
      max: 9
```

- **``secrets`` inputs are kept, with care.** The legitimate pattern is
  deriving *non-secret* fields — a username, a ``ca.crt`` from a TLS secret —
  into config. Everything the generator reads *can* be written to the output,
  and the output is world-readable; nothing stops a script publishing a
  password except the author. See
  [`examples/configmapbuilder-derive-from-secret.yaml`](../examples/configmapbuilder-derive-from-secret.yaml)
  for the canonical shape.

Regeneration, companion state and chaining
------------------------------------------

The regeneration model is ``SecretBuilder``'s, unchanged: generate-once by
default; ``onInputChange`` refresh replaying persisted material; ``rotateEvery``
(with ``rotateGenerated``) and the manual ``secrets.advok8s.io/regenerate``
annotation for rotation. Two points worth calling out:

- **The companion state is a Secret** — ``<name>-configmapbuilder-state`` —
  regardless of the output kind, because generated material is entropy. (This
  is also why builder names are capped at 230 characters, enforced at
  admission: the companion name must fit the 253-character object name limit.)
- **The revision annotation is shared.** The output ConfigMap is stamped with
  ``secrets.advok8s.io/revision`` (a content hash covering both ``data`` and
  ``binaryData``), the same key SecretBuilder uses — so builder chains work
  across kinds in both directions: a ConfigMapBuilder output can feed a
  SecretBuilder's ``configMaps`` input and vice versa, with ``onInputChange``
  picking up the upstream revision change.

There is no ``output.immutable``: immutability conflicts with the regeneration
model (any refresh would need delete-and-recreate).

Drift model
-----------

As with ``SecretBuilder``, the builder deliberately does **not** watch its own
output: a hand-edited generated ConfigMap stays edited until the next
generation event (a spec change, an input change under ``onInputChange``, a
rotation, or the regenerate annotation). Builders generate-and-own; the
continuously-converging behaviour belongs to the copiers.

Status and observability
------------------------

Identical to ``SecretBuilder`` with ``configMapName`` in place of
``secretName``: conditions (``Ready`` / ``Degraded`` with reasons such as
``AwaitingInput``, ``GeneratorError``), ``generated``, ``lastGeneratedTime``,
``nextRotationTime``, ``inputFingerprint`` and ``revision``, plus events on
condition transitions.

```shell
kubectl get configmapbuilders
# NAME         READY   GENERATED   LAST GENERATED   AGE
# app-config   True    true        10s              12s
```
