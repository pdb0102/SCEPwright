# SCEPwright - Design & Architecture

The enduring design reference for the SCEPwright SCEP testing suite. It consolidates the
"as-built" architecture, the crypto/protocol/storage internals, and the deliberate design
decisions (including accepted tradeoffs). For day-to-day usage see `scepclient-usage.md`,
`scepca-usage.md`, and `intune-simulator.md`; for what each test suite proves see
`coverage-matrix.md`; for open work see `Backlog.md`.

> Status note: this document describes the suite as it is built. Where an original spec called
> for something later changed during implementation, the as-built choice is recorded here and the
> superseded plan is not.

---

## 1. What SCEPwright is

Three distinct test surfaces - **not** "two sides of one wire":

- **`scepclient` (the crown jewel)** - an RFC 8894 SCEP **client**. Get a deployable
  certificate in one command, or stress-test any SCEP **server** for RFC compliance (every client
  mistake maps to an expected `failInfo`, leniency findings, timing/Jamf simulation, CI reports).
  Pluggable crypto, post-quantum subject keys, recipient-aware enveloping.
- **`scepca`** - a SCEP **server**: issues real certificates from a built-in, **untrusted**
  test CA. Stand it up to test any SCEP **client**; per-profile endpoints for every RSA/EC/ML-KEM
  recipient shape, fault injection, optional NDES emulation.
- **IntuneSimulator** - fakes the **Intune / AAD / Graph cloud chain** so a real SCEP **server**
  can validate its *Intune integration*. The niche tool; it is **not** a SCEP CA, and it does not
  test SCEP clients.

### Guiding principles

- **No exceptions for control flow.** Static `Create()`/`Load()` factories; sync APIs return a
  result enum + `out value` + `out string error`; async APIs return `ScepResult<T>`. (The
  `IScepCrypto` contract uses a bool-discriminated form: `bool` + `out value` + `out string error`.)
- **Full sync + async parity.** Genuine `HttpClient.Send`/`SendAsync` paths share a
  transport-agnostic core; never `.GetAwaiter().GetResult()`.
- **Domain objects are always valid.** `Pkcs10`/`PkiMessage` validate on set; faults are an
  isolated, opt-in channel, never a representable state of a normal object.
- **Be strict in what you emit, generous in what you accept** (Postel), with a hard floor:
  leniency never upgrades an invalid signature to valid.
- **Crypto is swappable.** All client cryptography is behind a tiny provider contract; the rest of
  the client code never names a crypto library.
- **Algorithms are open OID identifiers** tagged by kind, with a name<->OID registry.
- **PQ-ready by being algorithm-agnostic** rather than by special-casing.

---

## 2. Distribution - two downloads

| Download | Contents | Audience |
|---|---|---|
| **`scepwright-<rid>.zip`** | One directory, three executables: `scepwright` (dispatcher), `scepca` (server), `scepclient` (client), plus shared DLLs | Anyone testing SCEP from either side |
| **`IntuneSimulator-<rid>.zip`** | `IntuneSimulator.Host` | A server validating its Intune cloud integration |

Both are **self-contained, folder publishes - never single-file.** The BouncyCastle crypto
provider is loaded by filename from `AppContext.BaseDirectory`, so the provider DLL must sit on
disk beside the executable; a single-file bundle hides it and breaks default provider loading.
RIDs: `win-x64`, `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64`.

Casing: **SCEPwright** in prose, **ScepWright** for .NET namespaces/projects, **scepwright** for
the binary.

### Versioning

**One suite version, bumped together every release** - all assemblies (and IntuneSimulator) share
the single `<Version>` in the root `Directory.Build.props`, so there is no per-DLL version drift and
the `version` command reports one coherent number.

Two version sources, by build type:

- **Source builds** (someone clones or downloads the source ZIP) take the version from
  `Directory.Build.props`'s `<Version>`. A GitHub source ZIP carries no `.git` metadata, so
  tag-derived versioning cannot help here - the committed `<Version>` is the *only* version a source
  builder can see. It therefore **must be bumped in-source as part of every release**.
- **Official release artifacts** are stamped from the **git tag**: the release workflow (triggered
  by a `v*` tag) strips the leading `v` and passes `-p:Version=<tag>` to every publish, overriding
  the props fallback and setting AssemblyVersion/FileVersion + the clean `InformationalVersion` the
  `version` command reads.

**Release ritual:** bump `<Version>` in `Directory.Build.props` to the new version, commit, then
create the signed `v<version>` tag on that commit. CI fails the release fast if the tag does not
match the committed `<Version>` (so a source build and its release artifacts can never disagree).
Between releases the committed `<Version>` reads as the last released number; append a `-dev`/`-pre`
suffix if you want mid-cycle source builds to be visibly non-release.

Each shipping ScepWright assembly also emits its XML documentation file (`GenerateDocumentationFile`)
so IntelliSense shows the API docs to anyone referencing the libraries.

---

## 3. Architecture - dispatcher over libraries

Each tool is its own project; `scepwright` is a thin dispatcher that calls public entrypoints.
No logic is duplicated or merged.

**Shared - `ScepWright.*`:**
| Project | Role |
|---|---|
| `ScepWright.Crypto` | crypto contract: `IScepCrypto`, domain objects (`Pkcs10`, `PkiMessage`, `KeySpec`, algorithm/codec types, `CryptoCapabilities`, `FaultDirectives`). Dependency-free, crypto only (no storage). |
| `ScepWright.Crypto.BouncyCastle` | the built-in BouncyCastle provider - the only client project that touches BouncyCastle. |
| `ScepWright.Core` | the shared library: protocol, storage, domain objects, client orchestration (`ScepClient`), test engine, reporting. References only `ScepWright.Crypto`. |

**Tool-specific:**
| Project | Binary | SDK | Role |
|---|---|---|---|
| `ScepWright.Client` | `scepclient` | `Microsoft.NET.Sdk` (Exe) | client CLI; exposes `Run()`, `HelpUse()`, `HelpTest()` |
| `ScepWright.Server` | (library) | `Microsoft.NET.Sdk.Web` | SCEP server **library**: CA + endpoints + persistence (`ScepCa`, `ScepServerApp`). BouncyCastle + ASP.NET only; **no `ScepWright.Core` reference**. |
| `ScepWright.Server.Host` | `scepca` | `Microsoft.NET.Sdk.Web` (Exe) | the `scepca` executable: `ServerCli.Run`/`Help` + `web.config` for IIS |
| `ScepWright.Dispatcher` | `scepwright` | `Microsoft.NET.Sdk` (Exe) | umbrella dispatcher; references `ScepWright.Client` + `ScepWright.Server.Host` |
| `ScepWright.Tests` | - | test project | one suite test project, references all of the above |

IntuneSimulator stays `IntuneSimulator.*` - its own brand, namespaces, and download; not folded
under `ScepWright`. It keeps its modern .NET idioms (`var`, LINQ); the house style below applies to
`ScepWright.*` only.

**`scepwright` verbs:**
- `scepwright client <args>` -> `scepclient.Run(args)`; help door = `HelpUse()`.
- `scepwright test <args>` -> the same client engine; help door = `HelpTest()`.
- `scepwright server <args>` -> `scepca` (`ServerCli.Run`); help = server `Help()`.
- bare `scepwright` / `help` -> unified help (`HelpUse()` + `HelpTest()` + server `Help()`).

`client` and `test` are two doors over the **same** `scepclient` engine - they differ only in the
help surface. A command typed at the "wrong" door still runs; the standalone `scepclient` prints
both help surfaces and runs use-or-test freely.

---

## 4. The crypto provider model (client side)

- **`IScepCrypto`** - a flat driver interface: the crypto operations SCEP needs, plus a
  `Capabilities` property the provider fills in. That is the entire abstraction - no factories,
  registries, or attributes.
- **`ScepCrypto.Load(configuredDllPath, out crypto, out error)`** - load the configured provider
  DLL (or the shipped BouncyCastle one by known name from the app directory) and find the single
  `IScepCrypto` implementation. "Built-in" is just the default DLL.
- **`ScepClient.Crypto`** - the client resolves the provider once at `Create` time and holds it as
  a property. No global ambient provider, so two providers can coexist in one process. Domain
  objects stay stateless and receive an `IScepCrypto` explicitly when driven.
- **Isolation:** external providers load into a collectible `AssemblyLoadContext` with an
  `AssemblyDependencyResolver`; the `Load` override returns `null` for the `ScepWright.Crypto`
  assembly so it resolves to the host's already-loaded copy (preserving a single `IScepCrypto`
  type identity across the boundary) and resolves the provider's private deps from its own folder.
  Keeping the contract assembly tiny keeps the shared surface minimal.

### Algorithms as OID identifiers, tagged by kind

Every algorithm is an OID string; a static `Algorithms` registry maps name<->OID and tags each
entry with an `AlgorithmKind` (`Digest`, `Signature`, `ContentEncryption`, `KeyTransport`, `Kem`,
`AsymmetricKey`). A new algorithm (including every PQ one) is a new registry entry, never a
contract change.

`IScepCrypto.Capabilities` declares supported algorithms grouped by kind (`Digests`, `Signatures`,
`ContentEncryption`, `KeyTransport`, `Kem`, `AsymmetricKeys`) plus the PQ tiers it implements. This
drives the opinion layer, `probe` mode, and `servers suggest`, so behavior adapts to the loaded
provider. A provider-agnostic `CapabilityGuard` checks `Capabilities` for the requested recipient +
signer algorithms and returns a clean error (e.g. "loaded provider does not support ML-KEM
KEMRecipientInfo (Tier C)") before attempting, rather than letting an unsupported request throw.

---

## 5. Domain object model

- **`Pkcs10` / `PkiMessage`** carry structured data and expose symmetrical `Encode`/`Decode`. They
  contain no crypto and are stateless - `Encode`/`Decode` take an `IScepCrypto`. They live in
  `ScepWright.Crypto` because both providers and Core consume them. The provider does all byte
  production/consumption (CMS generation, signature verify, EnvelopedData decrypt).
- **`CodecOptions`** (one lib-wide `[Flags]` enum) is shared by every `Encode`/`Decode`: defaults
  encode Postel (`Encode` -> Strict, `Decode` -> LenientParsing). The security floor is structural:
  `SkipSignatureVerification` yields "not verified," never "valid"; `Strict` enforces the signature
  and a non-legacy digest.
- **`ConformanceNotes`** record non-fatal advisories (severity, what, where, RFC reference). `out
  string error` is reserved for hard failures only, so "failed" and "coped with sloppiness" never
  mix; notes flow into the trace/opinion stream and the compliance report.
- **Faults are not on the domain objects.** Only the builder produces `FaultDirectives`, applied by
  the provider at encode time only - so removing all test-only fault handling later is a handful of
  deletions, leaving a pristine production library.

---

## 6. `ScepClient` API & request builder

- **Construction:** `ScepClient.Create(...)` factories (one seeds renewal context from an existing
  cert + key). A client instance is reusable across operations and servers; it exposes `Crypto`.
- **Results:** sync `ScepClientResult Foo(..., out T, out string error)`; async
  `Task<ScepResult<T>> FooAsync(...)`.
- **Methods (sync + async):** high-level `GetNewCertificate()` / `RenewCertificate()` (caps ->
  cacert -> build -> submit -> poll); one-shot `GetCaCaps()`, `GetCaCert()`, `GetNextCaCert()`,
  `Enroll()` (PKCSReq 19), `Renew()` (RenewalReq 17), `Poll()` (CertPoll 20), `GetCert()` (21),
  `GetCrl()` (22).
- **Events (GUI-ready):** a `Trace` event carries `{ level, phase, message, timing, optional raw
  bytes }`; levels include `Opinion`. Sensitive bytes are shown as `sha256:<hex>`.
- **`ScepRequestBuilder`** is a fluent composer; fault methods are gated behind `.AllowFaults()`
  (well-formed-but-unusual inputs need no gate and the opinion layer comments on them;
  malformed/spec-violating ones require the gate and are captured as `FaultDirectives`).

### Recipient-aware enveloping (a recurring invariant)

SCEP allows split signing/encryption CA certs. Every client path that wraps a request to the CA
must envelope to the RA **encryption** recipient (an encryption-capable cert chosen by
`RecipientSelector` / `ScepClient.ResolveRecipientCert`), **never** the first/signing cert - for
split-RA and PQ CAs the signing cert (e.g. ML-DSA) cannot be an EnvelopedData recipient. When a new
send path is added, it must leave the recipient unset and resolve it centrally.

### Subject keys vs the transport signer (PQ)

A PQ **signature** subject key (ML-DSA/SLH-DSA) can sign the SCEP request but cannot decrypt the
enveloped CertRep (the response is enveloped to the requester's signer cert key). So a self-signed
PKCSReq with a PQ subject key uses a transient RSA transport signer; the issued cert still carries
the PQ subject key. This is not a PQ downgrade: the transient key protects only the (public)
response; the confidential request is enveloped to the CA RA cert (which may be ML-KEM). A KEM
cannot replace it because a KEM cannot produce the CMS signature.

---

## 7. SCEP protocol coverage (RFC 8894)

- **HTTP operations:** `GetCACaps`, `GetCACert` (incl. RA + chain / degenerate PKCS#7),
  `GetNextCACert` (rollover), `PKIOperation` (GET base64 + POST).
- **Message types:** PKCSReq (19), RenewalReq (17), CertPoll (20), GetCert (21), GetCRL (22),
  CertRep (3, inbound).
- **GetCACaps keywords -> `ScepCapabilities`:** `AES`, `DES3`, `GetNextCACert`, `POSTPKIOperation`,
  `Renewal`, `SHA-1`, `SHA-256`, `SHA-512`, `SCEPStandard`.
- **MTI baseline (Sec 2.9):** AES-128-CBC + SHA-256 + HTTP POST. Legacy permitted: 3DES, SHA-1,
  HTTP GET. Forbidden by RFC: single-DES, MD5 - the tool can still emit these (capability is never
  blocked; the RFC posture only shapes defaults and opinion).
- **pkiStatus:** SUCCESS (0), FAILURE (2), PENDING (3). **failInfo:** badAlg (0), badMessageCheck
  (1), badRequest (2), badTime (3), badCertId (4), plus optional `failInfoText`.
- **CMS content type (RFC 8894 §3.2):** the outer SignedData `encapContentInfo.eContentType` (and the
  matching `content-type` signed attribute) is `id-data` - the `envelopedData` OID belongs only to the
  inner pkcsPKIEnvelope's own `ContentInfo`, not the outer encapsulated content.
- **CertRep signature verification:** the response signature is checked against the certs embedded in
  the CertRep **and** the cached GetCACert bundle, so a valid signature whose signer cert the server did
  not embed is still confirmed. A mismatch/failure is diagnosed, not just flagged: the note reports the
  *claimed* signer (issuer+serial or subjectKeyIdentifier), the cert actually used to verify (and whether
  it came from the CertRep or GetCACert), and how many candidates were tried - so a server-implementor can
  tell a genuinely invalid signature from "we picked cert X but cert Y signed / the signer cert was not
  provided."

### PENDING enrollment lifecycle

When `get`/`enroll` returns PENDING the subject key and request metadata are persisted under
`servers/<id>/pending/<txn>/` (keyed by transaction id). A later `poll` reloads that key, signs the
CertPoll with it (RFC 8894 §3.3.2 - the GetCertInitial must be signed by the original enrollment key, so
the CA returns the certificate bound to it), and on success stores the issued cert paired with the key
(then clears the pending record) so it lists, renews, and exports like a synchronous enrollment.

### Renewal variants

`renew <cert-id>` defaults to variant 1; renewal context comes from the stored cert's metadata.

| # | Variant | messageType | CMS signed with | Inner CSR key |
|---|---|---|---|---|
| 1 | Proper renewal | RenewalReq | existing cert + key | new keypair |
| 2 | Re-enroll, same subject | PKCSReq | self-signed (new key) + challenge | new keypair |
| 3 | Renewal-shaped PKCSReq | PKCSReq | existing cert + key | new keypair |
| 4 | Same-key renewal | RenewalReq | existing cert + key | reuses existing keypair |
| 5 | Expired-cert renewal | RenewalReq | expired existing cert | new keypair |

---

## 8. Subject key specs

`KeySpec.Parse` accepts:
- `rsa:<bits>` (bits >= 1024),
- `ec:p256 | p384 | p521` (ECDSA CSR signature is curve-matched: P-256->SHA-256, P-384->SHA-384,
  P-521->SHA-512; the outer CMS SignerInfo stays on the server-negotiated digest, default SHA-256),
- `ml-dsa:44 | 65 | 87` (FIPS 204),
- `slh-dsa:128s|128f|192s|192f|256s|256f` (FIPS 205, SHA2 family).

**ML-KEM is deliberately rejected as a subject key**: a key-encapsulation mechanism cannot be a
certificate subject/signing key. ML-KEM is valid only as a *recipient/encryption* algorithm (the CA
RA cert, RFC 9629 KEMRecipientInfo) and that path does not go through `KeySpec`.

CSR attributes/extensions on `get`/`enroll`: full Subject DN; DNS SANs (IDNA/punycode-encoded for
non-ASCII names; empty/blank rejected) and UPN otherNames; MS SID security extension
(`1.3.6.1.4.1.311.25.2`, KB5014754 strong mapping); repeatable EKU (named or OID); arbitrary
`--extension <oid>=<value>` escape hatch. The challenge password rides in its PKCS#9 attribute.

### Post-quantum tiers

| Tier | What | Reality |
|---|---|---|
| A | PQ end-entity key (ML-DSA / SLH-DSA inner key; classical SCEP envelope) | works against a PQ-issuing CA |
| B | Catalyst/hybrid CSR (classical primary + PQ alt-key via `subjectAltPublicKeyInfo`, OID 2.5.29.72) | experimental probe - the alt public key is attached, but the built-in provider does **not** compute `altSignatureValue` and the alt key is not retained; disclosed at runtime and in help |
| C | PQ transport (ML-KEM EnvelopedData via RFC 9629 KEMRecipientInfo) | recipient-side only; built-in provider supports it (hand-rolled, since BouncyCastle 2.6.x has no CMS KEM-recipient generator) |

`IScepCrypto` slots all three tiers in additively (open OIDs + capability advertisement, opaque
`IScepKey` handles, extensible domain objects); no interface signature changed to add PQ.
Composite signatures remain vocabulary + opinion only (classified cutting-edge); there is no
built-in composite signing path.

---

## 9. Storage & state

Filesystem-based (no SQLite); human-pokeable and CI-parseable. The **client** owns
`ScepWright.Core` storage; the **server** resolves its own CA root independently (it has no Core
reference, see Sec 3). The two share the `~/.scepwright/` default but reach it by separate code.

Root resolution (both tools, same precedence): `--data-dir <path>` > `$SCEPWRIGHT_HOME` > breadcrumb
`~/.scepwright.json` > default `~/.scepwright/` (best-effort breadcrumb write; a transient override
writes no breadcrumb).

**Client layout** (server-scoped): `servers/<id>/{server.json, capabilities.json, cacerts/,
certificates/<cert-id>/{cert.pem, chain.pem, key.pkcs8[.enc], metadata.json}, history.jsonl}`; plus
`runs/<ts>-<server-id>-<mode>.{json,md}` reports. `metadata.json` records subject, serial, validity,
transactionId, timing, algorithms used, key-spec, `renewedFrom` lineage, status.

**Server layout:** `ca/<profile>/{ca.cert.der, ca.key.pkcs8[.enc], sigalg.txt}` (+
`ra.cert.der`/`ra.key.pkcs8[.enc]` for split-RA profiles). Advertised caps come from the `--caps`
flag at runtime, not a persisted file. On startup per profile: load the persisted CA if present,
else generate and persist it, giving a stable `GetCACert` across restarts.

**Key protection:** default plaintext PKCS#8 (test convenience); `--encrypt-keys` + `--key-pass`
(or `$SCEPWRIGHT_KEY_PASS` for the client, `$SCEPWRIGHT_CA_KEY_PASS` for the server) write encrypted
PKCS#8 (PBES2: PBKDF2-HMAC-SHA256 + AES-256-CBC). An encrypted key with no resolvable passphrase on
a non-interactive console fails with a clear message rather than prompting or hanging. PKCS#12
export defaults to modern PBES2/AES-256 bags + a SHA-256 MAC (`--legacy` emits classic SHA-1/RC2/3DES
for old importers). Private keys are never written to history/trace/reports; sensitive values are
redacted as `sha256:<hex>`.

---

## 10. Test modes, opinion & reporting

- **`lifecycle`** - GetCACaps -> GetCACert -> enroll -> poll-if-pending -> renew -> GetCRL. Fast
  happy-path smoke; a dependent step is Skipped only if its prerequisite genuinely failed. (`poll`
  is emitted only when enrollment returns PENDING.)
- **`full`** - the conformance matrix: a positive-control baseline enroll first (so a
  reject-everything CA cannot score all-green), then the negative fault-injection checks
  (rejection = pass) and leniency checks (accepting something the RFC permits rejecting = a
  Finding), a recipientNonce-echo check, and a replay probe. Never stops at the first failure. A
  check that gets **no SCEP response** (transport error / HTTP 500 / no envelope recipient) is
  Skipped/Inconclusive - never a false "rejected as expected."
- **`probe`** - deliberately tries things beyond advertised caps (SHA-256 on a SHA-1 server, POST
  when unadvertised, GetNextCACert, ML-DSA enroll) and reports what actually works.
- **`--dry-run`** - read-only (caps + cacert + recipient verdict + caps verdict + GetNextCACert);
  issues nothing.
- **`diagnose`** - read-only assessment of a server's CA/RA certs, recipient selectability, and
  enrollment caps, with a verdict; issues nothing.

Outcomes: **PASSED / Finding / Skipped / FAILED**. The opinion layer classifies algorithms
(MUST-NOT / legacy-weak / modern / cutting-edge), flags weak RSA, and `servers suggest` prints
ready-to-run commands for the algorithms a server actually supports.

Reports: JUnit XML (primary), TRX, JSON, Markdown, plus a console summary; selectable via
`--report-format` (repeatable). `--fail-on-findings` makes leniency findings drive a non-zero exit.
Reports embed attribution (generated-at, tool version, target URL, CA thumbprint) and a
**footprint** of every real certificate a run minted (serial + subject + expiry) for
cleanup/revocation. `coverage-matrix.md` (generated from `CoverageMatrixDoc`, drift-guarded by a
test) maps each emitted check to its RFC section.

### Challenge sources

A small `ChallengeSource` abstraction keeps the rest of the flow identical: explicit
`--challenge <pw>`; `--simulator <url>` (POST `<url>/challenge`, embed the returned password);
`--ndes` with `--ndes-user`/`--ndes-password` (fetch the Basic-auth `mscep_admin` page and scrape
the one-time challenge). The admin URL is derived as a sibling of the SCEP endpoint
(`<scep-url>/mscep_admin/`), overridable with `--ndes-admin-url`. `scepca` can emulate the NDES
admin page (`--ndes-user`/`--ndes-password`) so the whole NDES path is server-testable.

---

## 11. `scepca` - server surface

Wraps a built-in, **untrusted** BouncyCastle CA (stated plainly in help and docs). CLI: `--port`,
`--profile` (or serve all profiles at `/scep/<profile>`, default `/scep`), `--caps "<keywords>"`,
`--challenge`, `--pending`, `--ndes-user`/`--ndes-password`, `--export-ca <path>`, the storage
switches, and `version`. Per-profile CAs cover every RSA/EC/ML-KEM recipient shape and split-RA / PQ
combinations. Issued CA and leaf certs carry proper X.509 extensions (basicConstraints, keyUsage,
EKU, SKI/AKI) so `openssl verify` succeeds, and the issued leaf copies the CSR's requested SAN.
A SCEP server must never HTTP 500: malformed requests return a clean 400, and a recipient that
cannot receive an envelope (e.g. a PQ signing key) gets a signed failInfo, not a crash. Runs under
Kestrel standalone and under IIS via `web.config` (ASP.NET Core Module, in-process).

`scepca` keeps its own BouncyCastle CA and does **not** adopt the `IScepCrypto` provider model
(YAGNI; it is a self-contained CA).

---

## 12. Design decisions & accepted tradeoffs

- **`scepca` is a standalone library + host with zero `ScepWright.Core` reference** (decided during
  the suite restructure). This keeps the server a self-contained SCEP CA. The accepted cost is a
  deliberately **duplicated ML-KEM KEMRecipientInfo decrypt path**: `ScepWright.Crypto.BouncyCastle/
  {BcKemEnvelope,BcKemRecipientInfo}.cs` (client; encrypt + decrypt) vs
  `ScepWright.Server/KemEnvelopeDecrypt.cs` (server; decrypt only). RFC 9629 is standards-frozen, so
  churn risk is low. **Do not DRY-refactor this into a shared lib / cross-reference without
  re-deciding.**
- **No `StoreRole`.** The original plan parameterized one storage component by `StoreRole {Client,
  Server}`; because the server is standalone, this was not built - client and server own separate
  root resolution that happens to share the `~/.scepwright/` default.
- **Spec subject-mismatch end-to-end is documented, not built.** Driving the IntuneSimulator
  `/control` canned-error path (e.g. `SubjectNameMismatch`) is exercised by running `scepclient`
  (as the device) + IntuneSimulator against a **real** SCEP server: `--simulator <url>` fetches the
  challenge and the server's Intune connector validates back via `/ScepActions/validateRequest`.
  Building a `scepclient -> scepca -> simulator` loop would mean dragging MSAL/Graph/PKI-connector
  libraries into the deliberately-tiny `scepca`; that is the wrong trade. `scepca` has no Intune
  connector and never will.
- **Fixed CA serials (CA = 1, RA = 2) and lenient IntuneSimulator auth** are by-design for a test
  double, documented at their call sites and in the usage docs.

---

## 13. Carried engineering constraints

- **`.editorconfig` house style for all `ScepWright.*` code** (client/server/dispatcher/core/crypto/
  tests): never `var`; declare locals at the top of the block unassigned, blank line, then
  assignments; snake_case locals/params/fields; PascalCase for types/methods/properties and
  `const`/`static readonly`; same-line (K&R) braces; single-line statements (no wrapping). xUnit
  test method names keep their `Word_word_word` form. IntuneSimulator keeps its modern idioms.
- **No exceptions for control flow** in the client/server libraries (see Sec 1).
- **All client cryptography goes through `IScepCrypto`** (`ScepWright.Crypto.*`); never reference a
  crypto library elsewhere. The server's CA is the documented exception (BouncyCastle directly).
- **Folder publish, never single-file** (Sec 2).
- Full `dotnet test` (no `--filter`) before every commit; single working branch, squashed by the
  user before pushing via SmartGit.

---

## 14. Future work (out of scope today)

- A dedicated PKIX/ASN.1 library so the domain objects own the ASN.1 encoding and the crypto
  interface shrinks to pure `sign/verify/encrypt/decrypt` primitives. The seam is kept clean so this
  is possible later without an interface break.
- A GUI - the event model and no-throw library API are designed to support one.
- Composite (classical + PQ) signing in the built-in provider.

See `Backlog.md` for tracked, actionable items.
