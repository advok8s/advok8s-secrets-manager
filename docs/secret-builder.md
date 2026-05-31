Secret Builder
==============

The ``SecretBuilder`` custom resource generates a ``Secret``, named the same as
the resource, by running a script or template over a set of declared inputs. It
is a namespaced resource, and the generated ``Secret`` is created in the same
namespace.

The raw custom resource definition for the ``SecretBuilder`` custom resource can
be viewed by running:

```shell
kubectl get crd/secretbuilders.secrets.advok8s.io -o yaml
```

A ``SecretBuilder`` brings together four things: **inputs** (what the generator
may read), an **output** shape, a **generator** (exactly one of a Starlark script
or a gotemplate template), and an optional **regeneration** policy. The simplest
builder has just a generator:

```yaml
apiVersion: secrets.advok8s.io/v1beta1
kind: SecretBuilder
metadata:
  name: my-secret
  namespace: app
spec:
  generator:
    script: |
      secret = {"data": {"hello": "world"}}
```

This creates a ``Secret`` named ``my-secret`` in namespace ``app`` with a single
key ``hello``. The script sets a ``secret`` global with a ``data`` map; the
operator base64-encodes the values when it writes the ``Secret``, so the script
always works in plaintext.

Determinism
-----------

A ``SecretBuilder`` is deterministic: given the same inputs it produces the same
output. Two things that would otherwise break that — randomness and time — are
provided by the operator and persisted, never read live:

- All random material is declared under ``inputs.generated`` and produced by the
  operator. The script cannot roll its own randomness.
- The "current time" is ``input.context.generatedAt``, stamped once and frozen
  (re-stamped only on a rotation), so time-bound output such as a JWT ``exp`` is
  reproducible across refreshes.

Inputs: constants and context
------------------------------

``inputs.constants`` is a free-form map of non-secret, typed configuration the
generator can reference. Values keep their YAML type (string, int, bool, list,
map):

```yaml
spec:
  inputs:
    constants:
      realm: Demo Dashboard
      replicas: 3
      tls: true
  generator:
    script: |
      secret = {"data": {"realm": input.constants.realm}}
```

Constants live in the spec in plaintext, so they must hold only non-sensitive
knobs (realms, hostnames, counts) — secret material comes from ``inputs.secrets``
or ``inputs.generated``.

``input.context`` exposes the resource's own metadata without any declaration:
``input.context.namespace``, ``.name``, ``.labels``, ``.annotations``, ``.uid``,
and ``.generatedAt``.

Inputs: existing Secrets and ConfigMaps
---------------------------------------

``inputs.secrets`` references existing Secrets in the same namespace, decoded so
the script never sees base64. Each entry has a ``name`` handle (a dash-free
identifier) and a source in one of two forms.

A ``secretRef`` binds exactly one Secret as a single value:

```yaml
spec:
  inputs:
    secrets:
    - name: db
      secretRef:
        name: db-credentials
  generator:
    script: |
      secret = {"data": {"password": input.secrets.db.data["password"]}}
```

A ``selector`` matches a set and binds a list (sorted by name), using the same
name/label/owner/uid selectors as the rest of the family:

```yaml
spec:
  inputs:
    secrets:
    - name: users
      selector:
        nameSelector:
          matchNames: ["user-*", "!user-test"]
  generator:
    script: |
      names = [s.name for s in input.secrets.users]
      secret = {"data": {"count": str(len(names))}}
```

By default a selector must match at least one Secret, otherwise the build holds
in ``AwaitingInput``; set ``allowEmpty: true`` to permit zero matches.

``inputs.configMaps`` works the same way (``configMapRef`` or ``selector``) for
non-secret data; ``.data`` is plaintext and ``.binaryData`` is decoded bytes.

Inputs: a ServiceAccount token
------------------------------

``inputs.serviceAccount`` mints a bound token for a ServiceAccount via the
TokenRequest API, for kubeconfig-style outputs:

```yaml
spec:
  inputs:
    serviceAccount:
      serviceAccountRef:
        name: deployer-sa
      expirationSeconds: 86400
  generator:
    script: |
      secret = {"data": {"token": input.serviceAccount.token}}
```

``audiences`` and ``expirationSeconds`` pass through to the TokenRequest. Because
the token is embedded in the output Secret, set a ``rotateEvery`` below
``expirationSeconds`` so it is re-minted before it expires. Also available are
``input.serviceAccount.namespace`` and ``input.serviceAccount.cluster`` (``server``
from the ``--cluster-api-server`` flag, ``caCert`` from ``kube-root-ca.crt``).

Inputs: generated material
--------------------------

``inputs.generated`` declares operator-produced random material. Each entry has a
``name`` handle and exactly one kind. The kinds are ``password``, ``token``,
``randomInt``, ``bytes``, ``uuid``, ``rsaPrivateKey``, ``ecdsaPrivateKey``,
``sshKeyPair``, ``caCertificate`` and ``tlsCertificate``:

```yaml
spec:
  inputs:
    generated:
    - name: adminPassword
      password:
        length: 24
        symbols: true
        minDigits: 2
    - name: hostKey
      sshKeyPair:
        algorithm: Ed25519
```

Each value exposes attributes to the generator — for example a ``password``
exposes ``.value``, ``.bcrypt`` and ``.sha256``; an ``sshKeyPair`` exposes
``.privatePEM``, ``.publicOpenSSH`` and ``.fingerprintSHA256``; certificates
expose ``.certPEM``/``.keyPEM`` (and ``.caPEM`` for a CA-signed leaf). A
``tlsCertificate`` with an ``issuerRef`` is signed by a CA (a ``caCertificate``
generated earlier in the same builder, or one in an input Secret); without an
``issuerRef`` it is self-signed.

The generator: script or template
----------------------------------

``spec.generator`` selects exactly one engine.

A ``script`` is a Starlark program that sets a ``secret = {"data": ..., "labels":
..., "type": ...}`` global. It can ``load()`` modules declared under
``inputs.libraries`` and call recipe modules: ``tls.bundle``, ``basicauth``,
``dockerconfig``, ``htpasswd``, ``kubeconfig`` and ``jwt``, plus ``base64`` and
``json``.

A ``template`` is a per-key map of gotemplate templates, with Sprig functions and
``missingkey=error``:

```yaml
spec:
  generator:
    template:
      data:
        message: '{{ .constants.greeting }} from {{ .constants.env }}'
        encoded: '{{ .constants.greeting | b64enc }}'
```

Both engines are sandboxed (no I/O, no clock, bounded execution and output size)
and expose the same inputs.

Signalling not-ready or broken
------------------------------

A generator can signal two non-success outcomes:

- ``fail("message")`` (or ``{{ fail "message" }}``) marks the configuration
  broken: the resource goes ``Degraded`` with reason ``GeneratorError``.
- ``retry("message")`` (or ``{{ retry "message" }}`` / ``{{ retryAfter "30s"
  "message" }}``) signals that inputs exist but are not yet ready: the resource
  holds in ``AwaitingInput`` and is retried, without raising an alarm.

Output
------

``spec.output`` sets the Secret ``type`` (default ``Opaque``), and ``labels`` and
``annotations`` to merge onto the generated Secret. The Secret name is always the
SecretBuilder's name and is not configurable.

```yaml
spec:
  output:
    type: kubernetes.io/tls
    labels:
      app: demo
```

Regeneration
------------

By default a SecretBuilder is **generate-once**: the Secret is produced when
absent and then left alone — a hand-edit is not reverted, and inputs changing
does not regenerate it. Everything else is opt-in under ``spec.regeneration``:

```yaml
spec:
  regeneration:
    onInputChange: true     # re-run when inputs change, keeping generated material stable
    rotateEvery: 50m        # rotate this long after the material was generated
    rotateGenerated: true   # on a rotate, also re-roll the random material
```

There are two distinct verbs. A **refresh** (``onInputChange``) re-runs the
generator with the *same* persisted generated material and frozen
``generatedAt`` — output changes only because an input did. A **rotate**
(``rotateEvery`` or the manual trigger) re-stamps ``generatedAt``; with
``rotateGenerated: true`` it also re-rolls entropy.

A rotation can be triggered manually with an annotation (the
``kubectl rollout restart`` idiom):

```shell
kubectl annotate secretbuilder/my-secret \
  secrets.advok8s.io/regenerate="$(date +%s)" --overwrite
```

When ``onInputChange`` is set, a SecretBuilder also reacts to changes in the
Secrets it references — including another SecretBuilder's output — so a change can
propagate down a chain of builders. The operator stamps a content-derived
``secrets.advok8s.io/revision`` annotation on each generated Secret for this.

Status
------

The status reports ``observedGeneration``, ``conditions`` (``Ready`` and
``Degraded``), ``secretName``, ``generated``, ``lastGeneratedTime``,
``nextRotationTime`` and ``revision``. The ``Ready`` condition's reason is one of
``Generated``, ``AwaitingInput`` (waiting on inputs, benign),
``MissingServiceAccount``, ``InvalidInput`` (bad spec) or ``GeneratorError``
(script/template failure). The same information is summarised by ``kubectl get``:

```shell
kubectl get secretbuilder my-secret
# NAME        READY   GENERATED   LAST GENERATED   AGE
# my-secret   True    true        10s              12s
```

Generated values and error detail are never written to status or events (both are
broadly readable); verbose detail goes to the operator logs.
