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

The field-level reference is generated from the API types and stays in sync with
the code, so the authoritative description of any field is:

```shell
kubectl explain secretbuilder.spec
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

The whole spec, with every section, has this shape:

```yaml
spec:
  inputs:                 # what the generator can read (all optional)
    constants: {...}        # plaintext typed config (non-secret knobs)
    secrets: [...]          # existing Secrets in this namespace (decoded)
    configMaps: [...]       # existing ConfigMaps (non-secret data)
    serviceAccount: {...}   # a ServiceAccount + a freshly-minted token
    generated: [...]        # operator-generated random material
    libraries: [...]        # Starlark-only: load() modules from a ConfigMap
  output:                 # shape of the produced Secret (optional)
    type: Opaque
    labels: {...}
    annotations: {...}
  generator:              # required: exactly one engine
    script: |               # Starlark
      ...
    # or
    template:               # gotemplate (per-key template map)
      data: {...}
  regeneration:           # optional; default = generate once, never again
    onInputChange: false
    rotateEvery: 50m
    rotateGenerated: false
```

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

The script/template sandbox enforces this: no I/O, no live clock, and bounded
execution (a step cap) and output size (a 1 MiB cap on the produced Secret data).

Inputs: constants
-----------------

``inputs.constants`` is a free-form map of non-secret, typed configuration the
generator can reference. Values keep their YAML type — string, int, bool, list,
map — so they arrive in the generator with their natural type, no string
conversions:

```yaml
spec:
  inputs:
    constants:
      realm: Demo Dashboard
      replicas: 3
      tls: true
      hosts: [app, app.local]
  generator:
    script: |
      secret = {"data": {
        "realm": input.constants.realm,
        "replicas": str(input.constants.replicas),
      }}
```

Constants live in the spec in plaintext, so they must hold only non-sensitive
knobs (realms, hostnames, issuer URLs, counts) — secret material comes from
``inputs.secrets`` or ``inputs.generated``. They are not validated or pruned
per-key (they are author-controlled literals), and they fold into the input
fingerprint, so changing one triggers a refresh under ``onInputChange``.

Inputs: context
---------------

``input.context`` exposes the resource's own metadata without any declaration (no
``spec.inputs`` entry, no RBAC). It carries only what the operator definitively
knows about the resource — its own metadata — not cluster-wide values like an
ingress or cluster domain, which should be supplied through ``inputs.constants``.

| Field (Starlark) | gotemplate | Value |
|---|---|---|
| ``input.context.namespace`` | ``.context.namespace`` | the SecretBuilder's (and output Secret's) namespace |
| ``input.context.name`` | ``.context.name`` | the SecretBuilder name (= output Secret name) |
| ``input.context.labels`` | ``.context.labels`` | the SecretBuilder's labels (map) |
| ``input.context.annotations`` | ``.context.annotations`` | the SecretBuilder's annotations (map) |
| ``input.context.uid`` | ``.context.uid`` | the SecretBuilder UID (changes on delete/recreate — using it risks churn) |
| ``input.context.generatedAt`` | ``.context.generatedAt`` | the frozen generation time (see Determinism) |
| ``input.context.generatedAtUnix`` | — | the same time as epoch seconds (int) |

In Starlark, ``generatedAt`` is an RFC 3339 string (UTC) and ``generatedAtUnix``
is the epoch-second integer for arithmetic. In gotemplate, ``.context.generatedAt``
is a Go ``time.Time`` (format it with Sprig's ``date``, or take ``.Unix``).

Inputs: existing Secrets and ConfigMaps
---------------------------------------

``inputs.secrets`` references existing Secrets in the same namespace, decoded so
the generator never sees base64. Each entry has a ``name`` handle — a dash-free
identifier used as the binding, deliberately distinct from the referenced
Secret's real name — and a source in one of two forms. Exactly one of ``secretRef``
or ``selector`` must be set per entry.

**``secretRef`` binds exactly one Secret as a single value:**

```yaml
spec:
  inputs:
    secrets:
    - name: db                  # handle -> a single value (no [0])
      secretRef:
        name: db-credentials    # the Secret's real name
  generator:
    script: |
      secret = {"data": {"password": input.secrets.db.data["password"]}}
```

**``selector`` matches a set and binds a list** (sorted by name, so iteration
order — and therefore output — is stable). The sub-selectors are the same
name/label/owner/uid selectors used across the family and are ANDed:

```yaml
spec:
  inputs:
    secrets:
    - name: users               # handle -> a LIST
      selector:
        nameSelector:
          matchNames: ["user-*", "!user-test"]   # globs; "!" excludes
        labelSelector:
          matchLabels: { app: dashboard }
  generator:
    script: |
      names = [s.name for s in input.secrets.users]
      secret = {"data": {"count": str(len(names))}}
```

By default a selector must match at least one Secret, otherwise the build holds
in ``AwaitingInput``; set ``allowEmpty: true`` on the entry to permit zero matches
(binding an empty list). Handles must be unique within the list (enforced at
admission), but ``inputs.secrets`` and ``inputs.generated`` are separate
namespaces, so the same handle may appear in each.

Each resolved Secret exposes these attributes:

| Attribute | Value |
|---|---|
| ``.name`` | ``metadata.name`` |
| ``.data["key"]`` | the decoded value as a string (never base64) |
| ``.type`` | the Secret type |
| ``.uid`` | ``metadata.uid`` |
| ``.labels`` / ``.annotations`` | the source metadata maps |

``inputs.configMaps`` works the same way — a ``name`` handle with ``configMapRef``
(single) or ``selector`` (set), ``allowEmpty``, same-namespace only. A resolved
ConfigMap exposes ``.name``, ``.uid``, ``.labels``, ``.annotations``, ``.data``
(plaintext strings) and ``.binaryData`` (base64 on the wire, surfaced as decoded
bytes):

```yaml
spec:
  inputs:
    configMaps:
    - name: bundles
      selector:
        labelSelector: { matchLabels: { role: ca-bundle } }
  generator:
    script: |
      cas = [c.data["ca.crt"] for c in input.configMaps.bundles]
      secret = {"data": {"ca.crt": tls.bundle(cas)}}
```

Inputs: a ServiceAccount token
------------------------------

``inputs.serviceAccount`` mints a bound token for a ServiceAccount via the
TokenRequest API, for kubeconfig-style outputs. It is a single object — no handle
and no list (compose chained builders if more than one identity is needed):

```yaml
spec:
  inputs:
    serviceAccount:
      serviceAccountRef:
        name: deployer-sa
      audiences: ["https://kubernetes.default.svc"]   # optional
      expirationSeconds: 86400                          # optional (min 600)
  generator:
    script: |
      secret = {"data": {"token": input.serviceAccount.token}}
```

``audiences`` and ``expirationSeconds`` pass straight through to the TokenRequest:
``audiences`` sets the token's ``aud`` (omit for the API server's default
audience, the kubeconfig/cluster case); ``expirationSeconds`` is the TTL (clamped
to ``[600, the API server's configured maximum]``). Because the token is embedded
in the output Secret, set a ``rotateEvery`` below ``expirationSeconds`` so it is
re-minted before it expires.

The resolved object exposes:

| Field | Value |
|---|---|
| ``input.serviceAccount.token`` | the freshly-minted bound token |
| ``input.serviceAccount.namespace`` | the ServiceAccount's namespace |
| ``input.serviceAccount.cluster.server`` | the **in-cluster** API server URL |
| ``input.serviceAccount.cluster.caCert`` | the cluster CA (PEM), from the ``kube-root-ca.crt`` ConfigMap |

``cluster.server`` is the **internal** API server endpoint, derived from the
operator pod's ``KUBERNETES_SERVICE_HOST`` / ``KUBERNETES_SERVICE_PORT``
environment variables, falling back to ``https://kubernetes.default.svc`` when
they are unset. The operator does not try to discover an external API server
address, so a generated kubeconfig targets the cluster from **inside** it; for
external use, override the server in your generator (e.g. from an
``inputs.constants`` value). A bound token is tied to the ServiceAccount's name
**and UID**, so when validated by the API server, deleting the ServiceAccount
effectively revokes the token on next use, and delete-then-recreate gives a new
UID that rejects old tokens. A token consumed by an external service that only
checks signature + ``exp`` + ``aud`` will not
notice the deletion — there only ``expirationSeconds`` bounds it.

Inputs: generated material
--------------------------

``inputs.generated`` declares operator-produced random material. Each entry has a
``name`` handle and exactly one kind. All entropy lives here so the generator
stays deterministic.

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

The kinds, their fields, and what each exposes to the generator follow.

### ``password`` — human-facing password with composition rules

| Field | Default | Meaning |
|---|---|---|
| ``length`` | (required) | total length |
| ``upper`` / ``lower`` / ``digits`` / ``symbols`` | ``true`` | which character classes form the alphabet |
| ``minUpper`` / ``minLower`` / ``minDigits`` / ``minSymbols`` | ``0`` | minimum count from each class ("must include …" rules) |
| ``symbolSet`` | a safe default set | which symbols are allowed |
| ``excludeAmbiguous`` | ``false`` | drop look-alikes (``0 O 1 l I``) |
| ``excludeCharacters`` | ``""`` | explicit characters to forbid |
| ``allowRepeat`` | ``true`` | if ``false``, no repeated characters |
| ``charset`` | — | escape hatch: a literal alphabet, overriding the class toggles |

Exposes ``.value`` (the password), ``.bcrypt`` (an operator-computed bcrypt hash,
salt persisted) and ``.sha256`` (hex).

### ``token`` — machine-facing API key / access token

A uniform alphabet with no composition rules and an optional fixed prefix (the
``ghp_`` / ``sk_live_`` convention):

| Field | Default | Meaning |
|---|---|---|
| ``length`` | (required) | number of random characters (excludes the prefix) |
| ``alphabet`` | ``alphanumeric`` | ``alphanumeric`` (base62), ``lowerAlphanumeric`` (base36), ``hex``, ``base32``, ``base64url``, or ``custom`` |
| ``charset`` | — | the alphabet when ``alphabet: custom`` |
| ``prefix`` | ``""`` | fixed string prepended verbatim (include any separator, e.g. ``mytool_``) |

Exposes ``.value`` (prefix + random body).

### ``randomInt`` — a bounded random integer

| Field | Default | Meaning |
|---|---|---|
| ``max`` | (required) | inclusive upper bound |
| ``min`` | ``0`` | inclusive lower bound (may be negative) |

Exposes ``.value`` as an integer (``crypto/rand`` with rejection sampling, no
modulo bias). For a fixed-width numeric PIN prefer a digit-only ``password``
(preserves leading zeros).

### ``bytes`` — raw random key material

| Field | Default | Meaning |
|---|---|---|
| ``length`` | (required) | number of random bytes |
| ``encoding`` | ``base64`` | how ``.value`` is rendered: ``base64``, ``base64url``, ``hex`` or ``base32`` |

Exposes ``.value`` (the encoded string) and ``.bytes`` (the raw bytes). Output
auto-encoding still applies, so put ``.bytes`` in ``secret.data`` when the Secret
should hold the raw material rather than the encoded string.

### ``uuid`` — a random UUID

| Field | Default | Meaning |
|---|---|---|
| ``version`` | ``4`` | ``4`` (fully random) or ``7`` (time-ordered, taking its timestamp from ``generatedAt``) |

Exposes ``.value`` (canonical lowercase hyphenated form).

### ``rsaPrivateKey`` / ``ecdsaPrivateKey`` — a bare private key (no certificate)

For uses like JWT signing or application keys.

| Kind | Field | Default | Meaning |
|---|---|---|---|
| ``rsaPrivateKey`` | ``rsaBits`` | ``2048`` | modulus size |
| ``ecdsaPrivateKey`` | ``ecdsaCurve`` | ``P256`` | curve (``P256``/``P384``/``P521``) |

Each exposes ``.privatePEM`` (PKCS#8) and ``.publicPEM`` (PKIX/SPKI).

### ``sshKeyPair`` — an OpenSSH keypair

| Field | Default | Meaning |
|---|---|---|
| ``algorithm`` | ``Ed25519`` | ``Ed25519``, ``RSA`` or ``ECDSA`` |
| ``rsaBits`` | ``2048`` | modulus size when ``algorithm: RSA`` |
| ``ecdsaCurve`` | ``P256`` | curve when ``algorithm: ECDSA`` |
| ``comment`` | ``""`` | trailing comment on the public key |

Exposes ``.privatePEM`` (OpenSSH format), ``.publicOpenSSH`` (the
``authorized_keys`` line) and ``.fingerprintSHA256``.

### ``caCertificate`` and ``tlsCertificate`` — X.509 certificates

``caCertificate`` is a CA (``CA:TRUE``, ``keyCertSign``), for signing other certs;
``tlsCertificate`` is a leaf. Whether a leaf is self-signed or CA-signed depends
on ``issuerRef`` (omitted ⇒ self-signed, dev only; set ⇒ CA-signed, recommended).

Fields common to both:

| Field | Default | Meaning |
|---|---|---|
| ``commonName`` | — | subject Common Name |
| ``subject`` | — | optional DN parts, each a list: ``organizations``, ``organizationalUnits``, ``countries``, ``localities``, ``provinces``, ``postalCodes`` |
| ``duration`` | leaf ``8760h`` (1y) / CA ``87600h`` (10y) | validity; ``notBefore = generatedAt``, ``notAfter = notBefore + duration`` |
| ``algorithm`` | ``RSA`` | key type: ``RSA``, ``ECDSA`` or ``Ed25519`` |
| ``rsaBits`` | ``2048`` | modulus size when ``algorithm: RSA`` |
| ``ecdsaCurve`` | ``P256`` | curve when ``algorithm: ECDSA`` |
| ``issuerRef`` | — (self-signed) | sign with a CA: ``{ generated: <name> }`` (a ``caCertificate`` in this builder) or ``{ secret: <name> }`` (an in-namespace CA Secret with ``tls.crt`` + ``tls.key``) |

``caCertificate`` additionally takes ``maxPathLen`` (bounds the number of
intermediate CAs below it). ``tlsCertificate`` additionally takes ``dnsNames``,
``ipAddresses``, ``uris``, ``emailAddresses`` (SANs) and ``usages`` (key
usages / extended key usages, default ``digitalSignature``, ``keyEncipherment``,
``serverAuth``).

Both expose ``.certPEM`` and ``.keyPEM``. A CA-signed ``tlsCertificate`` also
exposes ``.caPEM`` (the issuing CA certificate, to publish the chain). For a
``caCertificate``, ``.certPEM`` / ``.keyPEM`` are the CA's own cert and key.

> These cert kinds are a deliberately small subset — roughly cert-manager's
> ``SelfSigned`` and ``CA`` issuers — for ephemeral/internal TLS, not a
> replacement for cert-manager. Generate-once certs expire without renewing
> (``rotateEvery`` is time-based, not ``notAfter``-aware).

Inputs: libraries (Starlark only)
---------------------------------

``inputs.libraries`` lets a Starlark ``script`` ``load()`` user-authored helper
modules, so functions can be shared across many SecretBuilders. Each module is
sourced from a key of a referenced ConfigMap — declare the ConfigMap under
``inputs.configMaps``, then map a clean ``load()`` name to that handle and a key:

```yaml
spec:
  inputs:
    configMaps:
    - name: lib
      configMapRef: { name: gen-lib }     # holds a key "naming.star"
    libraries:
    - name: naming      # the load() module name (a clean identifier)
      from: lib         # an inputs.configMaps handle (ConfigMaps only)
      key: naming.star  # the data key holding the module source
  generator:
    script: |
      load("naming", "build_name", fqdn="build_fqdn")   # symbol rename is allowed
      secret = {"data": {"host": build_name(input.context.name)}}
```

Loaded code runs in the same sandbox and can do nothing the inline script cannot
(it has the recipe/primitive modules but not the per-build ``input``, ``fail`` or
``retry``). ``load()`` is available **only in the top-level script** — a loaded
library cannot itself ``load()`` another library (which keeps the load graph flat
and makes load cycles impossible). Library content folds into the input
fingerprint, so editing a shared module refreshes every dependent builder under
``onInputChange``.

The generator: script vs template
----------------------------------

``spec.generator`` selects **exactly one** engine, both running against the same
resolved inputs:

- **``script``** — a **Starlark** program. Imperative; best for computed output
  (many keys, iteration, conditionals, nested structures). The primary engine.
- **``template``** — **gotemplate** (``text/template`` + Sprig). Text-substitution;
  best for output that is mostly fixed text with a few holes (a connection string,
  a config file).

### Output contract

A ``script`` assigns a single ``secret`` global:

```python
secret = {
  "data":   { "key": "value" },   # required: str -> str (or bytes); operator base64-encodes
  "labels": { ... },               # optional: merged over output.labels
  "type":   "Opaque",              # optional: overrides output.type
}
```

(A single ``secret`` dict rather than separate globals, because a global ``type``
would shadow Starlark's ``type()`` builtin.)

A ``template`` is a per-key map of ``data`` templates, with optional ``type`` and
``labels`` — the gotemplate analogue of the Starlark ``secret`` global. Each data
value renders as plaintext and is base64-encoded by the operator. ``type`` and
each ``labels`` value are themselves gotemplates (so a literal works and a
computed value is possible); as in a script, ``type`` overrides ``spec.output.type``
and ``labels`` merge over ``spec.output.labels``:

```yaml
spec:
  generator:
    template:
      type: Opaque                                 # optional; a gotemplate
      labels:
        app: '{{ .constants.appName }}'            # optional; gotemplate values
      data:
        message: '{{ .constants.greeting }} from {{ .constants.env }}'
        encoded: '{{ .constants.greeting | b64enc }}'
```

A missing key reference is an error (``missingkey=error``), not an empty string —
a typo'd ``.data.passwrd`` fails the build rather than silently emitting ``""``.

**base64 principle.** Inputs arrive decoded and ``data`` is encoded by the
operator, so you never base64 the Secret envelope yourself. The ``base64`` helper
(Starlark) / ``b64enc`` (Sprig) is only for genuinely nested encoding — e.g.
``certificate-authority-data`` inside a kubeconfig.

### Starlark: predeclared globals

The Starlark script has these predeclared (no ``load`` needed). All are
deterministic — no I/O, no randomness, no live clock.

| Name | What it is |
|---|---|
| ``input`` | the resolved inputs: ``input.constants``, ``.context``, ``.secrets``, ``.configMaps``, ``.serviceAccount``, ``.generated`` |
| ``fail(message)`` | abort as broken (see *Signalling* below) |
| ``retry(message, after="")`` | abort as not-ready-yet |

The **recipe modules** (``tls``, ``basicauth``, ``dockerconfig``, ``htpasswd``,
``kubeconfig`` and ``jwt``) are documented under *Recipes* below. The
lower-level **primitive modules** are:

| Module | Functions |
|---|---|
| ``json`` | ``json.encode(v)`` → str, ``json.decode(s)`` → value, ``json.indent(s)`` → str (go.starlark.net's json module) |
| ``yaml`` | ``yaml.encode(v)`` → str, ``yaml.decode(s)`` → value (via YAML↔JSON, so decoded maps carry string keys) |
| ``base64`` | ``base64.encode(value)`` → str, ``base64.decode(value)`` → bytes (standard encoding) |
| ``hex`` | ``hex.encode(value)`` → str, ``hex.decode(value)`` → bytes |
| ``hash`` | ``hash.sha256(value)``, ``hash.sha512(value)``, ``hash.sha1(value)`` → hex str; ``hash.hmac_sha256(key, value)`` → hex str |
| ``regexp`` | ``regexp.match(pattern, str)`` → bool, ``regexp.replace(pattern, str, repl)`` → str, ``regexp.find_all(pattern, str)`` → [str] (RE2 syntax) |
| ``url`` | ``url.query_escape(value)`` / ``query_unescape(value)`` / ``path_escape(value)`` / ``path_unescape(value)`` |

``encode``/``decode`` and the ``base64``/``hex`` helpers accept a string or
``bytes``; ``json``/``yaml`` ``decode`` numbers come back as floats. These are for
**data-inside-data** (e.g. CA bytes inside a kubeconfig, or emitting a YAML config
blob as one Secret value) — the Secret envelope itself is encoded by the operator.

Plus all Starlark language built-ins (``len``, ``range``, ``enumerate``,
``sorted``, ``min``, ``max``, ``sum``, ``any``, ``all``, ``str``, ``int``,
``dict``, ``list``, comprehensions, and the string/list/dict methods). There is no
``print``/I/O, and no clock module — time comes only from
``input.context.generatedAt``.

### gotemplate: dot context and functions

The dot context mirrors ``input``: ``.constants``, ``.context``, ``.secrets``,
``.configMaps``, ``.serviceAccount``, ``.generated`` (with the same per-entry
attributes — e.g. ``.secrets.db.data.password``, ``.generated.adminPassword.value``).

The function map is the **full Sprig** text/template library plus the outcome
functions (``fail``, ``retry``, ``retryAfter``, ``required``) and the recipe
functions (named with underscores, gotemplate's flat-namespace convention):
``basicauth_credentials``, ``basicauth_header``, ``tls_bundle``,
``dockerconfig_json``, ``htpasswd_bcrypt``, ``htpasswd_sha``, ``htpasswd_apr1``,
``kubeconfig_merge``, ``jwt_sign``.

Sprig already covers the primitives the Starlark engine exposes as modules —
``b64enc``/``b64dec``, ``toJson``/``fromJson``, ``sha256sum``/``sha1sum``,
``regexMatch``/``regexReplaceAll``, ``urlquery`` — so they are not re-added. The
one gap Sprig leaves, YAML, is filled with ``toYaml`` (a value → YAML string, the
Helm convention of trimming the trailing newline) and ``fromYaml`` (a YAML string
→ value).

> **Determinism caveat for templates.** Sprig includes non-deterministic
> functions (``now``, ``randAlphaNum``, ``uuidv4``, …). Using them defeats the
> determinism guarantee and will cause spurious changes on every reconcile — use
> ``inputs.generated`` for randomness and ``.context.generatedAt`` for time
> instead.

Recipes
-------

Recipes hide the fiddly, error-prone layout of common Secret formats (nested
base64, mandated keys, hashing). Signatures below are Starlark; the gotemplate
equivalent is the underscore-named function with positional arguments.

### ``tls`` — concatenate PEM certificates

``tls.bundle(certs)`` — given a list of PEM strings, returns them concatenated and
normalised, in order. Use it for a leaf+issuer **fullchain** (``tls.crt``, leaf
first) or a multi-CA **trust bundle** (``ca.crt``). gotemplate: ``tls_bundle``.

### ``basicauth`` — HTTP Basic credentials (encoding, not hashing)

| Function | Returns |
|---|---|
| ``basicauth.credentials(user, password)`` | ``base64(user:pass)`` — the bare, scheme-less form |
| ``basicauth.header(user, password)`` | ``"Basic " + credentials`` — an HTTP ``Authorization`` value |

gotemplate: ``basicauth_credentials``, ``basicauth_header``. These are reversible
encodings — to store a verifiable hash use ``htpasswd``.

### ``dockerconfig`` — image pull secret JSON

``dockerconfig.json(registries)`` — given a list of
``{registry, username, password, email}`` dicts, returns a
``.dockerconfigjson`` document (hiding the nested ``auth: base64(user:pass)``).
Pair it with ``output.type: kubernetes.io/dockerconfigjson`` and a
``.dockerconfigjson`` data key. gotemplate: ``dockerconfig_json``.

### ``htpasswd`` — htpasswd file content

Each takes ``entries`` — a list of ``{username, password}`` dicts — and returns
the file content (one line per entry):

| Function | Scheme |
|---|---|
| ``htpasswd.bcrypt(entries)`` | bcrypt (recommended; salts per call) |
| ``htpasswd.sha(entries)`` | ``{SHA}`` (unsalted; legacy) |
| ``htpasswd.apr1(entries, salts)`` | Apache apr1 (MD5); ``salts`` is a parallel list of salt strings |

gotemplate: ``htpasswd_bcrypt``, ``htpasswd_sha``, ``htpasswd_apr1``. Note bcrypt
salts each run, so under ``onInputChange``/rotate the hash changes every run; under
the default generate-once policy it is computed once and frozen.

### ``kubeconfig`` — build and merge kubeconfigs

| Function | Returns |
|---|---|
| ``kubeconfig.from_service_account(serviceAccount, clusterName="", userName="", contextName="")`` | a single-context kubeconfig YAML for a minted SA token |
| ``kubeconfig.build(server="", caCert="", token="", clientCert="", clientKey="", clusterName="", userName="", contextName="", namespace="")`` | a single-context kubeconfig YAML assembled from explicit pieces (token *or* client cert/key) |
| ``kubeconfig.merge(configs, currentContext="", strict=False)`` | several kubeconfig YAML strings unioned into one (the ``kubectl config view --flatten`` analogue) |

All three return a kubeconfig YAML **string**. ``from_service_account`` pulls the
server/CA/token out of an ``inputs.serviceAccount`` value; ``build`` is the
general constructor when you supply the pieces yourself (e.g. a client
certificate from a generated ``tlsCertificate``). Empty ``clusterName``/``userName``
default to ``cluster``/``user`` and ``contextName`` defaults to the cluster name.

``merge`` unions ``clusters``/``users``/``contexts`` by name, first-wins on
duplicates (list order = precedence); ``strict=True`` errors on same-name-but-
different entries; ``currentContext`` overrides (default: the first input's).
Resolve name collisions upstream by giving each ``from_service_account`` /
``build`` a distinct ``contextName``.

All three are available in gotemplate too: ``kubeconfig_merge configs
currentContext strict``; ``kubeconfig_build (dict "server" … "token" …)`` (a
single dict of the same fields); and ``kubeconfig_from_service_account
.serviceAccount (dict "contextName" …)`` (the SA value plus an optional trailing
options dict).

### ``jwt`` — sign and decode JSON Web Tokens

``jwt.sign(claims, key, alg, kid="", expiresIn="", notBefore="")`` returns a
compact signed JWT. Claims are built by the script; ``key`` is a PEM private key
(a generated ``rsaPrivateKey``/``ecdsaPrivateKey`` ``.privatePEM``) for ``RS*``/
``PS*``/``ES*``, or a shared secret for ``HS*``. Time is anchored at
``generatedAt``: ``iat`` is set to it, and ``expiresIn``/``notBefore`` (duration
strings like ``"1h"``) stamp ``exp``/``nbf`` from it — so a refresh recomputes the
identical token and a rotate produces a fresh one. ``EdDSA`` is not offered.

```python
token = jwt.sign(
  claims = {"iss": input.constants.issuer, "sub": input.constants.subject},
  key = input.generated.signingKey.privatePEM,
  alg = "RS256",
  expiresIn = "1h",   # exp = generatedAt + 1h
)
```

gotemplate: ``jwt_sign claims key alg (dict "expiresIn" "1h" "kid" "…")`` — the
optional parameters go in a trailing dict.

``jwt.decode(token)`` parses a token already held and returns ``{header, claims}``.
It does **not** verify the signature or ``exp``/``nbf`` — decoded claims carry no
more trust than any other input. Verification is deliberately out of scope (there
is no live clock to check ``exp`` against, and one-shot generation is not
continuous validation); trust decisions belong in the admission/policy layer or
the consuming app.

Signalling not-ready or broken
------------------------------

A generator run ends in one of three ways, and "waiting" is deliberately distinct
from "broken":

- **success** → the output Secret is written, ``Ready=True``.
- **``retry("message")``** (Starlark) / ``{{ retry "message" }}`` or
  ``{{ retryAfter "30s" "message" }}`` (gotemplate) — inputs exist but are not yet
  in the needed state. The build aborts fail-closed (no output), holds at
  ``Ready=False`` reason ``AwaitingInput`` (no alarm), emits a Normal event, and
  requeues. Requeue is event-driven (an input changing re-triggers); the optional
  ``after`` delay is a polling fallback for state the operator does not watch.
- **``fail("message")``** (Starlark) / ``{{ fail "message" }}`` or
  ``{{ required "message" .x }}`` (gotemplate) — the configuration is broken. The
  resource goes ``Degraded`` with reason ``GeneratorError`` and emits a Warning
  event. Any builtin/recipe raising, a missing ``dict[key]`` (Starlark), or a
  missing template key also lands here.

Both ``retry`` and ``fail`` abort fail-closed (the last-good output is preserved,
never a partial write). Neither message may embed secret values — status and
events are broadly readable plaintext.

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

A ``script`` may also set ``type`` and ``labels`` in its ``secret`` global, which
override / merge over ``spec.output``. The output Secret is owned by the
SecretBuilder (an ownerReference), so deleting the SecretBuilder garbage-collects
the Secret — no finalizers.

Regeneration
------------

By default a SecretBuilder is **generate-once**: the Secret is produced when
absent and then left alone — a hand-edit is not reverted, and inputs changing does
not regenerate it. Everything else is opt-in under ``spec.regeneration``:

```yaml
spec:
  regeneration:
    onInputChange: true     # re-run when inputs change, keeping generated material stable
    rotateEvery: 50m        # rotate this long after the material was generated
    rotateGenerated: true   # on a rotate, also re-roll the random material
```

There are two distinct verbs:

- A **refresh** (``onInputChange``) re-runs the generator with the *same* persisted
  generated material and the *same* frozen ``generatedAt`` — output changes only
  because an input did.
- A **rotate** (``rotateEvery`` or the manual trigger) re-stamps ``generatedAt``
  (so time-bound output like a JWT ``exp`` advances). With ``rotateGenerated: true``
  it also re-rolls entropy; with ``false`` the random material is kept (e.g. rotate
  a token's validity window while keeping its signing key).

``rotateEvery`` is relative to when the material was minted — it fires that long
after ``generatedAt``, and the operator requeues precisely. Set it from your
knowledge of the material's validity (a JWT with ``expiresIn: 1h`` →
``rotateEvery: 50m``, leaving a buffer).

A rotation can be triggered manually with an annotation (the
``kubectl rollout restart`` idiom); a new value triggers exactly one rotation:

```shell
kubectl annotate secretbuilder/my-secret \
  secrets.advok8s.io/regenerate="$(date +%s)" --overwrite
```

When ``onInputChange`` is set, a SecretBuilder also reacts to changes in the
Secrets it references — including another SecretBuilder's output — so a change can
propagate down a chain of builders. The operator stamps a content-derived
``secrets.advok8s.io/revision`` annotation on each generated Secret and folds each
input's revision into an input fingerprint; when the fingerprint changes, the
downstream builder refreshes. The graph must be acyclic.

**Drift and deletion.** A SecretBuilder is event-driven only — no periodic resync
and no watch on its own output. A hand-edited output value persists until the next
refresh/rotate trigger overwrites the whole output. A deleted output is not
recovered until the next trigger, and because the entropy lived only in the output
Secret (never in status), recreation mints **brand-new** random material. This is
a conscious divergence from SecretCopier (which re-derives from an authoritative
source): a SecretBuilder has no source to re-derive from, so silent recovery would
amount to an unannounced rotation.

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

kubectl get secretbuilder my-secret -o wide
# ... also shows NEXT ROTATION, REASON and REVISION
```

Generated values and error detail are never written to status or events (both are
broadly readable); verbose detail (including the Starlark backtrace or gotemplate
position on failure) goes to the operator logs.

Worked examples
---------------

**Derive a value from an existing Secret (no entropy):**

```yaml
spec:
  inputs:
    secrets:
    - name: db
      secretRef: { name: db-credentials }
  generator:
    script: |
      db = input.secrets.db.data
      secret = {"data": {
        "DATABASE_URL": "postgres://%s:%s@%s:5432/%s" % (
          db["username"], db["password"], db["host"], db["dbname"]),
      }}
```

**Generated password used three ways (plaintext, bcrypt htpasswd, Basic header):**

```yaml
spec:
  inputs:
    constants: { username: admin }
    generated:
    - name: adminPassword
      password: { length: 24, symbols: true }
  generator:
    script: |
      user = input.constants.username
      pw = input.generated.adminPassword.value
      secret = {"data": {
        "password": pw,
        "auth": htpasswd.bcrypt(entries = [{"username": user, "password": pw}]),
        "authHeader": basicauth.header(user, pw),
      }}
  regeneration:
    rotateEvery: 720h        # ~30d
    rotateGenerated: true
```

**CA-signed TLS leaf with a published fullchain:**

```yaml
spec:
  inputs:
    generated:
    - name: ca
      caCertificate: { commonName: "Example Internal CA", duration: 87600h }
    - name: serverCert
      tlsCertificate:
        commonName: app.example.com
        dnsNames: [app.example.com, app]
        duration: 8760h
        issuerRef: { generated: ca }   # signed by the CA above
  output: { type: kubernetes.io/tls }
  generator:
    script: |
      c = input.generated.serverCert
      secret = {"data": {
        "tls.crt": tls.bundle([c.certPEM, c.caPEM]),  # fullchain: leaf + issuer
        "tls.key": c.keyPEM,
        "ca.crt":  c.caPEM,                            # issuing CA, for clients to trust
      }}
```

**Signed JWT (RS256) with a generated key, rotated before expiry:**

```yaml
spec:
  inputs:
    constants: { issuer: "https://issuer.example", subject: account-123 }
    generated:
    - name: signingKey
      rsaPrivateKey: { rsaBits: 2048 }
  generator:
    script: |
      key = input.generated.signingKey
      token = jwt.sign(
        claims = {"iss": input.constants.issuer, "sub": input.constants.subject},
        key = key.privatePEM,
        alg = "RS256",
        expiresIn = "1h",            # exp = generatedAt + 1h
      )
      secret = {"data": {"token": token, "public.pem": key.publicPEM}}
  regeneration:
    rotateEvery: 50m                 # < expiresIn: re-mint before it expires
    rotateGenerated: false           # re-stamp generatedAt; keep the signing key
```

**A connection string with the gotemplate engine** (the same inputs block as the
first example):

```yaml
spec:
  generator:
    template:
      data:
        DATABASE_URL: >-
          postgres://{{ .secrets.db.data.username }}:{{ .secrets.db.data.password }}@{{ .secrets.db.data.host }}:5432/{{ .secrets.db.data.dbname }}
```

More self-contained, runnable scenarios — including a chaining pair and a
ServiceAccount-token kubeconfig merge — are in the repository's
[``examples/``](../examples/) directory.
