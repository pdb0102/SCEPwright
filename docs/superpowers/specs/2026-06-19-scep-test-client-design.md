# ScepTestClient — Design Spec

**Date:** 2026-06-19
**Status:** Approved for planning (Phase 1)
**Repo:** added to the existing IntuneSimulator solution (reframed as a "SCEP testing suite")
**Target:** .NET 8 (`net8.0`, `RollForward Major`), cross-platform, minimal external dependencies

---

## 1. Purpose & goals

`ScepTestClient` is a cross-platform SCEP client that serves three distinct uses:

1. **Casual / real use** — "I need a new cert" or "renew this cert." A convenience tool that produces a genuinely deployable certificate with minimal typing.
2. **Per-operation testing** — exercise every individual SCEP action against a server, one at a time.
3. **Compliance & lifecycle testing** — drive a server through every mistake a client can make and verify the correct error is returned (or call out a non-compliant response); plus a fast full-lifecycle check that confirms the server's features actually work.

It follows **RFC 8894** (the current SCEP RFC, not just the older Cisco draft), supports all SCEP operations and message types, and is built to test **multiple servers** — including multiple endpoints on the same host (e.g. `http://host/scep/privpki/x` vs `http://host/scep/digicert/x`), which are treated as distinct servers. Received certificates always know which server they came from so renewal targets the right endpoint and key.

The library is designed so a CLI (this project) or a future GUI can sit on top: all progress is surfaced through an event, never `Console.WriteLine`.

### Guiding principles (cross-cutting)

- **No exceptions for control flow.** Static `Create(...)` factories instead of throwing constructors; a consistent `ScepClientResult` enum + `out string error` for sync APIs, and a `ScepResult<T>` return for async APIs.
- **Full sync + async parity.** Every public operation ships in both forms with the same name/params/semantics. No one is forced to contort. Genuine sync (`HttpClient.Send`) and async (`SendAsync`) paths share a transport-agnostic core — never `.GetAwaiter().GetResult()`.
- **Domain objects are always valid.** `Pkcs10`/`PkiMessage` validate on set and cannot represent a flawed state where it's checkable. Faults are an isolated, opt-in channel (see §5, §7).
- **Be strict in what you emit, generous in what you accept** (Postel), with a hard security floor: leniency never upgrades an invalid signature to valid.
- **Crypto is swappable.** All cryptography is behind a tiny provider contract; the rest of the code never names a crypto library.
- **OID strings identify every algorithm** (digest, symmetric, asymmetric, KEM), with a name↔OID registry for display/input.
- **PQ-ready from day one** by being algorithm-agnostic, even though PQ is implemented in Phase 4.

---

## 2. Solution / project structure

Five projects added to `IntuneSimulator.sln`:

| Project | Role | References |
|---|---|---|
| `ScepTestClient.CryptoApi` | The crypto **contract**: `IScepCrypto`, domain objects (`Pkcs10`, `PkiMessage`, `KeySpec`, algorithm/codec types, `CryptoCapabilities`, `FaultDirectives`). Dependency-free; tiny. | none |
| `ScepTestClient.Crypto.BouncyCastle` | The **built-in default provider** — the only project that touches BouncyCastle. Loaded through the same path as any external provider. | CryptoApi + BouncyCastle |
| `ScepTestClient.Core` | The library: `ScepClient`, builder, protocol, storage, reporting, opinion. References **only** CryptoApi; resolves whichever provider is active. | CryptoApi |
| `ScepTestClient.Cli` | The `sceptest` executable. Thin: parses args, drives `ScepClient`, renders the `Trace` stream. Ships the BC provider DLL alongside. | Core |
| `tests/ScepTestClient.Tests` | Unit + integration (incl. against the IntuneSimulator). | Core, providers |

**Why a separate `CryptoApi` assembly:** any provider — including a closed-source or third-party one — compiles against this small, stable contract rather than against all of Core. This keeps the provider's binding surface tiny and frozen, lets organizations supply their own crypto implementation without forking or rebuilding the tool, and makes AssemblyLoadContext type-identity sharing clean (see §4).

---

## 3. The crypto provider model

### 3.1 One interface, one loader (no pattern bloat)

- **`IScepCrypto`** — a flat driver interface: the crypto operations SCEP needs, plus a `Capabilities` property the provider fills in. That is the entire "abstraction" — no factory objects, no registries, no attributes.
- **`ScepCrypto.Load(string? configuredDllPath, out IScepCrypto crypto, out string error)`** — if a DLL path is configured, load it and find the single class implementing `IScepCrypto`; otherwise load the shipped BouncyCastle provider DLL by known name from the app directory. One code path; "built-in" is just the default DLL.
- **`ScepClient.Crypto`** (an `IScepCrypto`) — `ScepClient` resolves the provider once at `Create` time (via `ScepCrypto.Load` using the configured path) and **holds it as a property**. There is no global ambient provider: the driver is instance-scoped, so two providers (e.g. the built-in one and an external/alternative provider) can coexist in one process — which the `probe` and scenario-runner cases want. The domain objects stay stateless and receive an `IScepCrypto` explicitly (see §4.1); `ScepClient` passes its `Crypto` whenever it drives them.

### 3.2 Runtime loading & isolation (.NET 8 specifics)

External providers load into a **collectible `AssemblyLoadContext` (ALC)** so a provider's private dependencies (its own crypto deps, its own BouncyCastle version, etc.) don't clash with ours. The standard plugin plumbing: a small `AssemblyLoadContext` subclass + `AssemblyDependencyResolver`, whose `Load` override returns `null` for the **CryptoApi** assembly (so it resolves to the host's already-loaded copy — preserving a single `IScepCrypto` **Type identity** across the boundary) and resolves the provider's private deps from its own folder. Type identity in .NET = (assembly + ALC), which is why the contract assembly must be shared, not reloaded. Keeping it tiny keeps the shared surface minimal.

### 3.3 Algorithms as open OID identifiers, tagged by kind

Every algorithm — digest, symmetric, asymmetric, KEM — is an **OID string**. A static `Algorithms` registry maps name↔OID both ways (CLI accepts `SHA-256` or `2.16.840.1.101.3.4.2.1`; output shows the friendly name) **and tags each entry with an `AlgorithmKind`** so the tool never has to infer an OID's role:

```csharp
public enum AlgorithmKind {
    Digest,              // SignerInfo digestAlgorithm / messageDigest
    Signature,           // SignerInfo signatureAlgorithm (rsa/ecdsa/ml-dsa/composite)
    ContentEncryption,   // EnvelopedData symmetric content cipher (AES-128-CBC, 3DES…)
    KeyTransport,        // EnvelopedData recipient key transport (RSA)
    Kem,                 // EnvelopedData KEMRecipientInfo (ML-KEM, composite KEM)
    AsymmetricKey,       // subject keypair type (RSA, EC, ML-DSA, SLH-DSA, composite)
}
```

A new algorithm (including every PQ one) is a new registry entry — **never** a contract change. The OID carries the identity; the registry carries the kind.

### 3.4 Provider-advertised capabilities

`IScepCrypto.Capabilities` (a `CryptoCapabilities`) declares supported algorithms **grouped by `AlgorithmKind`** (categorized sets — `Digests`, `Signatures`, `ContentEncryption`, `KeyTransport`, `Kem`, `AsymmetricKeys`) plus the PQ tiers (A/B/C) it implements. So `--digest` is only ever offered digest OIDs, `--cipher` only content-encryption OIDs, etc. This drives:
- the **opinion** layer ("server advertises only SHA-1; you requested SHA-256 — supported by the loaded provider ✓"),
- `probe` mode (what to try beyond what the server advertises),
- `servers suggest` (which ready-to-run commands to print),

so the tool's behavior adapts to the loaded crypto (e.g. the built-in BC provider vs an external provider with broader algorithm coverage).

### 3.5 Future seam (not built now)

If a dedicated PKIX/ASN.1 library is introduced later, the objects can own the ASN.1 encoding and the crypto interface shrinks to pure `sign/verify/encrypt/decrypt` primitives (algorithm math, no format). The boundary is kept clean so this is possible later; we do **not** build it now (YAGNI). Today the provider does format + math together because real CMS libraries are monolithic.

---

## 4. Domain object model

### 4.1 `Pkcs10` and `PkiMessage` — data + ergonomic facade

Rich objects that carry structured info and expose symmetrical Encode/Decode. They **contain no crypto** and are **stateless** — Encode/Decode take an `IScepCrypto` parameter (normally `ScepClient.Crypto`, supplied by the client when it drives them; standalone callers pass whichever provider they loaded). They live in `CryptoApi` because both providers and Core consume them.

```csharp
var csr = new Pkcs10 {
    Subject = "CN=poodle", Key = key, Sans = {...}, Sid = "S-1-5-21-…",
    Ekus = {...}, ChallengePassword = pwd };

var pki = new PkiMessage {
    MessageType = MessageType.PkcsReq, RecipientCaCert = caCert,
    Signer = selfSigned, InnerCsr = csr,
    DigestAlgorithm = "2.16.840.1.101.3.4.2.1",        // SHA-256 OID
    ContentEncryptionAlgorithm = aesOid };

pki.Encode(client.Crypto, out byte[] der, out string error);     // provider builds the CMS

PkiMessage.Decode(client.Crypto, responseDer, recipientKey, CodecOptions.LenientParsing,
                  out PkiMessage resp, out string error);
// resp.PkiStatus, resp.FailInfo, resp.TransactionId, resp.SenderNonce,
// resp.DigestAlgorithm, resp.SignatureValid, resp.DecryptedContent,
// resp.IssuedCerts, resp.ConformanceNotes …
```

- `BuildPkiMessage` takes the `Pkcs10` **object** (which knows how to encode itself), not bytes.
- The provider does all byte production/consumption (CMS generation, signature verify, EnvelopedData decrypt).

### 4.2 `CodecOptions` — one lib-wide enum

Shared by every `Encode`/`Decode` on both objects:

```csharp
[Flags] public enum CodecOptions {
    Strict                    = 0,   // default for Encode
    LenientParsing            = 1,   // default for Decode
    SkipSignatureVerification = 2,   // explicit; result still reports NotVerified, never Valid
    AllowLegacyAlgorithms     = 4,   // accept MD5/DES inbound without hard-failing
    // grows additively
}
```

Defaults encode Postel: **Encode → Strict**, **Decode → LenientParsing**. Security floor is structural — leniency never marks a bad signature valid; `SkipSignatureVerification` yields "not verified," never "valid."

### 4.3 `ConformanceNotes` — non-fatal advisories

When a lenient operation accepts something nonconformant, it records a structured note (severity, what, where, RFC reference) in `ConformanceNotes` on the result/object. `out string error` is reserved for **hard failures only**, so "failed" and "coped with sloppiness" never mix. Notes flow into the `Trace`/`Opinion` stream and the compliance report automatically.

### 4.4 Faults are NOT on the domain objects

The objects cannot represent malformed state. Faults are a separate, opt-in channel (see §7): only the builder produces `FaultDirectives`, applied by the provider **at encode time only**. Removing all test-only fault handling later is three deletions: `FaultDirectives`, the builder's `AllowFaults()` path, and the provider's `if (faults != null)` branch — leaving a pristine production library.

---

## 5. `ScepClient` API

### 5.1 Construction & reuse

```csharp
ScepClient.Create(serverConfig, out ScepClient client, out string error);                 // → ScepClientResult
ScepClient.Create(X509Certificate2 existingCert, <key> matchingKey, serverConfig,
                  out ScepClient client, out string error);  // seeds renewal context
```

A client instance is reusable/iterative — reconfigure properties and run another operation against the same or a different server. It exposes **`Crypto`** (the loaded `IScepCrypto`, resolved at `Create` time; see §3.1) which it supplies to the domain objects when driving them.

### 5.2 Result conventions

- **Sync:** `ScepClientResult Foo(..., out T value, out string error)`.
- **Async:** `Task<ScepResult<T>> FooAsync(...)` where `ScepResult<T>` = `{ ScepClientResult Status; string Error; T Value; }`.

### 5.3 Methods (both sync + async)

- **High-level / orchestrating:** `GetNewCertificate()`, `RenewCertificate()` — internally do GetCACaps → GetCACert → build → submit → poll.
- **Intermediate / one-shot** (each maps to one SCEP operation): `GetCaCaps()`, `GetCaCert()`, `GetNextCaCert()`, `Enroll()` (PKCSReq 19), `Renew()` (RenewalReq 17), `Poll()` (CertPoll 20), `GetCert()` (21), `GetCrl()` (22).

### 5.4 Event model (GUI-ready)

`ScepClient` raises a `Trace` event (`IProgress`-style) carrying `{ level, phase, message, timing, optional raw bytes }`. Levels include **`Opinion`** for security commentary. The CLI subscribes and renders by verbosity; a future GUI subscribes to the same event. Sensitive bytes are shown as `sha256:<hex>` (see §10). Every method also returns a structured result (decoded fields + timing) for programmatic use and the use-records.

---

## 6. `ScepRequestBuilder` (fluent)

A readable composer for an operation, reusable by others, used by our own code:

```csharp
ScepRequestBuilder.For(server)
   .Subject("CN=host.corp").SanDns("host.corp").Sid("S-1-5-21-…")
   .Eku("clientAuth").KeySpec("rsa:2048").Digest("SHA-256").Cipher("AES-128")
   .Challenge(pwd)                          // or .Simulator(url)
   .Build(out PkiMessage msg, out string error);
```

Fault methods are gated by `.AllowFaults()` (Phase 3):

```csharp
ScepRequestBuilder.For(server).Subject("CN=poodle").Digest("SHA-256")
   .AllowFaults()
   .CorruptSignature().SigningTimeSkew(TimeSpan.FromHours(2))
   .Build(out PkiMessage msg, out FaultDirectives? faults, out string error);
```

Without `.AllowFaults()`, fault methods refuse. With it, the builder still sanity-checks everything not deliberately broken. Two fault categories:
- **Well-formed-but-unusual** (legacy algos, odd subjects): normal builder calls, no gate; the opinion layer comments.
- **Malformed / spec-violating** (corrupt signature, omit `transactionId`, `signingTime` skew, bad nonce, missing required attr): require `.AllowFaults()`, captured as `FaultDirectives`.

---

## 7. SCEP protocol coverage (RFC 8894)

**HTTP operations:** `GetCACaps`, `GetCACert` (incl. RA + chain / degenerate-PKCS#7), `GetNextCACert` (rollover), `PKIOperation`.

**Message types:** PKCSReq (19), RenewalReq (17), CertPoll (20), GetCert (21), GetCRL (22), CertRep (3, inbound).

**Transports:** GET (base64 `message`) and POST. Opinion note if the server lacks `POSTPKIOperation`.

**GetCACaps keywords parsed → `ScepCapabilities`:** `AES`, `DES3`, `GetNextCACert`, `POSTPKIOperation`, `Renewal`, `SHA-1`, `SHA-256`, `SHA-512`, `SCEPStandard`.

**MTI baseline (RFC 8894 §2.9):** AES-128-CBC encryption + SHA-256 digest + HTTP POST. Legacy permitted: 3DES, SHA-1, HTTP GET. Forbidden by RFC: single-DES, MD5 — **the tool can still emit these** (capability is never blocked; the RFC posture only shapes defaults and opinion messaging), both to test security and to talk to genuinely pre-RFC servers.

**pkiStatus:** SUCCESS (0), FAILURE (2), PENDING (3).
**failInfo:** badAlg (0), badMessageCheck (1), badRequest (2), badTime (3), badCertId (4), plus optional `failInfoText`.

---

## 8. Renewal variants

| # | Variant | messageType | CMS signed with | Inner CSR key | Tests |
|---|---|---|---|---|---|
| 1 | Proper renewal | RenewalReq (17) | existing cert + key | new keypair | RFC-correct path; needs `Renewal` cap |
| 2 | Naïve re-enroll, same subject | PKCSReq (19) | self-signed (new key) + challenge | new keypair | Same Subject DN as existing cert but enrolled as new — reject duplicate / issue / quietly renew? |
| 3 | Renewal-shaped PKCSReq | PKCSReq (19) | existing cert + key | new keypair | Historical ambiguity: renewal semantics on the enroll type |
| 4 | Same-key renewal | RenewalReq (17) | existing cert + key | **reuses existing keypair** | Does the server require a fresh key (PoP hygiene, RFC §7.6)? |
| 5 | Expired-cert renewal | RenewalReq (17) | **expired** existing cert | new keypair | Server should reject; validity-window enforcement on the signing cert |

High-level `renew <cert-id>` picks variant 1 by default. Renewal context (which server URL, which old key) comes from the stored cert's metadata (§9). `renewedFrom` chains lineage.

---

## 9. Storage & state model

Filesystem-based (no SQLite); human-pokeable and CI-parseable. Everything is **server-scoped**.

### 9.1 Root resolution (breadcrumb)

1. `--data-dir` / `$SCEPTESTCLIENT_HOME` if present (transient override; does **not** rewrite the breadcrumb).
2. else the breadcrumb file `~/.sceptest.json` if it exists → read `<root>`.
3. else default to `~/.sceptestclient`, and **best-effort** write the breadcrumb (never fail if home isn't writable).

`config set-root <path>` is the explicit way to persist a new root.

### 9.2 Layout

```
<root>/
  config.json                   global defaults (algorithms, key spec, timeout, security thresholds)
  servers/
    <server-id>/
      server.json               id, name, url, caIdentifier, transport, addedAt, notes
      capabilities.json         last GetCACaps result + timestamp
      cacerts/ca-<thumbprint>.cer
      certificates/
        <cert-id>/
          cert.pem  chain.pem
          key.pkcs8[.enc]       plaintext by default; encrypted PKCS#8 if opted in
          metadata.json         subject, serial, validity, transactionId, requested/issuedAt,
                                timingMs, algorithmsUsed, renewedFrom:<cert-id>, status
      history.jsonl             append-only use-record: one JSON line per operation
  runs/
    <ts>-<server-id>-<mode>.json   machine-readable report
    <ts>-<server-id>-<mode>.md     human-readable summary
```

### 9.3 Server identity

A server = a specific URL (+ optional CA identifier). Distinct URLs (even on the same host) are distinct entries with a short stable **`server-id`** used as CLI shorthand (named on add, else derived).

### 9.4 Use-records (`history.jsonl`)

One JSON line per operation: timestamp, server-id, operation, messageType, algorithms, request/response sizes, pkiStatus/failInfo, **timing** (total + time-to-first-byte + poll-cycle count/duration for PENDING), issued cert-id. This is the data for perf comparison over time and the jamf-style "took too long" check.

### 9.5 Defaults precedence

CLI flag → per-server (`server.json`) → global (`config.json`) → built-in good-test-defaults. Persisted via `config set`.

### 9.6 Key protection

Default = plaintext PKCS#8 (test convenience); `--encrypt-keys` → encrypted PKCS#8 (passphrase via prompt/env/file). Private keys are never written to `history.jsonl`, trace, or reports.

### 9.7 Sensitive-value redaction

A single redaction helper emits `sha256:<hex>` for anything sensitive (challenge password, private keys, decrypted payloads) wherever it would otherwise reach history/trace/reports — verifiable by someone who holds the real value, without exposure.

---

## 10. Test modes & opinion

- **`lifecycle`** — GetCACaps → GetCACert → enroll → poll-if-pending → renew → (GetCRL). Fast happy-path smoke; no fault injection. Skips a dependent step only if its prerequisite genuinely failed.
- **`full`** — the complete compliance/fault matrix; **never stops at the first failure**; skips only tests whose prerequisite failed.
- **`probe`** — deliberately tries things **beyond** advertised caps (SHA-256 on a SHA-1-only server, POST when unadvertised, PQ enroll, GetNextCACert) and reports what actually works (exposes under-advertisement).

### 10.1 Compliance / fault-injection matrix

Each test sends one deliberate fault and asserts the expected `failInfo`, reporting **expected vs got vs why**:

| Fault | Expected | Why (RFC 8894) |
|---|---|---|
| Forbidden/unsupported algo (MD5, single-DES, or algo not in GetCACaps) | `badAlg` | §2.9 forbids MD5/DES; unknown algo → badAlg |
| Corrupted CMS signature | `badMessageCheck` | integrity/signature check fails |
| `signingTime` skewed beyond window | `badTime` | signingTime not close to server time |
| Wrong/empty challenge password | FAILURE (server-specific) | PKCSReq authentication fails |
| `GetCert`/`CertPoll` with unknown serial/txn | `badCertId` | no matching certificate |
| Malformed PKCS#10 / missing required attrs | `badRequest` | transaction not permitted/supported |
| RenewalReq when `Renewal` not advertised | rejection (else Opinion: lenient) | renewal unsupported |

A server **more lenient** than the spec (accepts SHA-256 though only SHA-1 advertised; honors variant #3) is flagged as a **finding**, not necessarily a failure.

### 10.2 Security "opinion"

Algorithms classified MUST-NOT (MD5, single-DES) / legacy-weak (SHA-1, 3DES) / modern (SHA-256/512, AES) / cutting-edge (PQ); RSA < 2048 flagged. Thresholds live in `config.json`, overridable. The tool reports the server's posture and can print the exact command to request a cert with each algorithm the server actually supports (`servers suggest`).

### 10.3 Jamf simulation

`--jamf-max-wait <duration>`: if a cert isn't returned inline and the request goes PENDING (needing CertPoll), fail once the wait exceeds the threshold — reproducing Jamf's "doesn't poll properly" bug. Timing is recorded regardless.

---

## 11. Scenario / playlist files

A declarative JSON file of steps, each a command + args + an **`expect`** (`pass` / `fail` / a specific `failInfo`). The runner executes them in order and **aggregates everything into one report** (one JUnit suite, one summary) — ideal for chaining `probe` steps that each declare their expected outcome.

```json
{ "name": "privpki compliance sweep",
  "steps": [
    { "name": "caps", "run": "getcacaps", "server": "testhost-privpki", "expect": "pass" },
    { "name": "sha256 beyond advertised", "run": "probe", "args": { "digest": "SHA-256" }, "expect": "pass" },
    { "name": "md5 should be refused", "run": "enroll", "args": { "digest": "MD5" }, "expect": "badAlg" }
  ] }
```

---

## 12. Reporting

- **Primary interchange:** JUnit XML (ingested by Jenkins, GitLab, Azure DevOps, NUnit/vstest reporters).
- **Also:** TRX (vstest-native), rich JSON, Markdown summary.
- Selectable via `--report-format junit|trx|json|md` (repeatable).
- **Console summary** styled like a test runner (PASSED/FAILED/SKIPPED/FINDINGS, timings), with each failure stating expected/got/why and each finding explained.

```
SCEP test run — testhost-privpki — full          4.2s
  PASSED   18
  FAILED    2
  SKIPPED   1   (prerequisite enroll failed)
  FINDINGS  3   (server more lenient than RFC 8894)

FAILED:
  ✗ signingTime skew → expected badTime, got SUCCESS
      server accepted a request with a +2h signingTime  (RFC 8894 §3.2.1)
FINDINGS:
  • SHA-256 works though only SHA-1 is advertised (under-advertised capability)
```

---

## 13. Challenge sources & server integrations

The SCEP challenge password can come from several **sources**, modeled as a small `ChallengeSource` abstraction so the rest of the flow is identical:

- **Explicit** — `--challenge <pw>` (or a stored per-server value).
- **IntuneSimulator** — `--simulator <url>`: before building a PKCSReq, the client does `POST <url>/challenge`, reads `challengePassword` from the JSON, and embeds it automatically. The same flag unlocks subject-mismatch tests (request `CN=poodle` while the simulator expects otherwise; assert the error) by driving the simulator's canned-error controls in the same run.
- **NDES (Microsoft)** — `--ndes` with `--ndes-user`/`--ndes-password`: NDES hosts an `mscep_admin` web page (HTTP Basic auth) that returns a short-lived enrollment challenge. The client fetches it and **scrapes** the challenge from the HTML. The admin URL is **derived** from the SCEP endpoint URL by swapping the `mscep` path segment for `mscep_admin` (standard enrollment endpoint `…/certsrv/mscep/[pkiclient.exe]` → admin page `…/certsrv/mscep_admin/`); `--ndes-admin-url <url>` overrides for nonstandard deployments. The scraped challenge is treated like any other source's value (and redacted as `sha256:<hex>` in history/trace per §9.7).

---

## 14. Post-quantum & composite support

NIST PQ algorithms: **ML-DSA** (FIPS 204), **SLH-DSA** (FIPS 205) for signatures; **ML-KEM** (FIPS 203) for key establishment. **Composite** = IETF profile binding a classical + a PQ algorithm into one key/signature. The PQ "new certificate type" = **hybrid / "catalyst" dual-algorithm certificates** (X.509 2019 / draft-ietf-lamps-x509-alt) using `subjectAltPublicKeyInfo` / `altSignatureAlgorithm` / `altSignatureValue`.

| Tier | What | Flag | Reality |
|---|---|---|---|
| A | PQ/composite end-entity key (inner PKCS#10 carries the PQ key; SCEP envelope stays classical) | `--key-spec ml-dsa:65` / `slh-dsa:128s` / `mldsa65-ecdsa-p256` | Realistic near-term against a PQ-issuing CA |
| B | Catalyst/hybrid CSR (classical primary + PQ alt-key) | `--alt-key-spec ml-dsa:65` | Migration testing; the "new cert type" |
| C | PQ SCEP transport (sign CMS with a PQ cert; ML-KEM-encrypt EnvelopedData via CMS `KEMRecipientInfo`, RFC 9629) | auto when signer/recipient is PQ | Bleeding-edge; available when the loaded provider implements it |

GetCACaps has no PQ keywords, so PQ support is **empirically probed** and reported.

**Interface agnosticism guarantees PQ slots in additively (no signature changes):** (1) algorithms are open OID identifiers + capability advertisement; (2) keys are opaque `IScepKey` handles; (3) build/sign/encrypt take extensible options objects (alt-key, KEM scheme = new optional fields). **Phase 1 includes an explicit task: validate the `IScepCrypto` shape on paper against all three tiers (ML-DSA end-entity, catalyst alt-key, ML-KEM envelope) before finalizing it** — so the interface is right the first time without implementing PQ early.

---

## 15. CLI command surface

Binary `sceptest`; small custom subcommand router (no external CLI lib). Noun-verb grouping.

```
servers list | add <url> [--name][--ca-identifier][--transport] | show <id> | remove <id> | suggest <id>

getcacaps   <server>
getcacert   <server>
getnextcacert <server>
enroll      <server> --subject "CN=x" [--san-*][--san-upn][--sid][--eku][--key-usage]
                     [--template|--template-oid][--key-spec][--alt-key-spec]
                     [--digest][--cipher][--challenge <pw>|--simulator <url>|--ndes][--transport]
                     [--extension <oid>=<hex|utf8:…>]
poll        <cert-id|txn>
getcert     <server> --serial <s> --issuer <dn>
getcrl      <server> --serial <s> | --issuer <dn>
renew       <cert-id> [--variant proper|same-key|reenroll-same-subject|pkcsreq-old-cert|expired]

get         <server> --subject "CN=x" [all enroll options]   # casual high-level
renew       <cert-id>                                        # casual high-level

certs list [server] | show <cert-id> | export <cert-id> [--format pem|pfx]

test lifecycle <server>
test full      <server>
test probe     <server>
run <scenario.json>

config show | set <key> <value> | set-root <path>

crypto info | list

# Global: --data-dir  --timeout  --simulator <url>  -v/-vv  --report-format (repeatable)
#         --json  --crypto-provider <path>  --encrypt-keys
#         --ndes  --ndes-user <u>  --ndes-password <p>  --ndes-admin-url <url>
```

### CSR attributes/extensions (on `enroll`/`get`)

Full Subject DN; SANs (`--san-dns/-ip/-email/-uri`); UPN otherName (`1.3.6.1.4.1.311.20.2.3`); **MS SID security extension** (`--sid` → `szOID_NTDS_CA_SECURITY_EXT` `1.3.6.1.4.1.311.25.2`, the KB5014754 strong-mapping requirement); EKU (named/OID); KeyUsage; MS cert-template (V1 `…311.20.2` / V2 `…311.21.7`); key spec (RSA/EC/PQ); arbitrary `--extension <oid>=<value>` escape hatch. Challenge password rides in its PKCS#9 attribute (`1.2.840.113549.1.9.7`).

---

## 16. Defaults (good test defaults, all overridable)

- Key: RSA-2048. Digest: SHA-256. Cipher: AES-128-CBC. Transport: POST (fallback to GET if unadvertised). Network timeout: 30s. Key storage: plaintext PKCS#8. Report format: console + JUnit.

---

## 17. Phasing & PR plan

Develop on a branch per phase; **one PR per phase**; **nothing ships until the last phase** (release-script/doc changes deferred to the end).

| Phase | PR | Scope | Deliverable |
|---|---|---|---|
| **1 — Foundation & casual use** | #1 | Project restructure; `IScepCrypto` + domain objects + OID registry + `CodecOptions`/`ConformanceNotes`; **validate interface vs all 3 PQ tiers on paper**; BC provider (key-gen, CSR w/ DN+SAN+UPN+SID+EKU+template, CMS build/parse, degenerate-PKCS#7), classical algos; `ScepCrypto.Load` + `ScepClient.Crypto` provider-holding; protocol (GetCACaps+parse, GetCACert, GetNextCACert, PKCSReq, CertPoll, GET+POST); `ScepClient` (Create factories, sync+async parity, `ScepResult<T>`, Trace/Opinion); storage (breadcrumb, registry, cert store, `history.jsonl`, config/defaults, key protection, sha256 redaction); CLI (`servers`, `getcacaps`, `getcacert`, `enroll`, `poll`, `get`, `certs`, `config`); happy-path tests vs simulator | **Working "get me a cert" client, end to end** |
| **2 — Renewal & lineage** | #2 | RenewalReq, GetCert, GetCRL; the 5 renewal variants; `renewedFrom` lineage + `renew <cert-id>`; `ScepRequestBuilder` fluent API; renewal tests | Full renewal coverage |
| **3 — Test & compliance engine** | #3 | `FaultDirectives` + builder `AllowFaults()` + provider fault branch; compliance matrix (expected `failInfo`); `test full`/`lifecycle`/`probe`; opinion thresholds; `servers suggest`; jamf timing sim; report emitters (JUnit/TRX/JSON/MD + console summary); scenario-file runner; challenge sources (`--simulator` auto-challenge + subject-mismatch tests, `--ndes` mscep_admin scrape) | Thorough server-testing tool |
| **4 — PQ & composite + provider polish** | #4 | PQ vocabulary in capabilities; BC provider tiers A/B (ML-DSA/SLH-DSA/composite + catalyst alt-key) and tier C where BC allows (PQ-CMS, KEMRecipientInfo); capabilities driving opinion/probe/suggest; `crypto info/list`, `--crypto-provider`/config; external-provider ALC loading hardening; empirical PQ probe | Cutting-edge; external providers work |
| **5 — Ship** | #5 | Update release scripts (self-contained CLI builds); README + RELEASE-NOTES documenting the client and all abilities; usage docs | Release the suite |

---

## 18. Out of scope (for now)

- GUI (a future project; the event model and no-throw library API are designed to support it).
- A dedicated PKIX/ASN.1 library (future; the crypto seam is kept clean so the surface can later shrink to pure primitives).
