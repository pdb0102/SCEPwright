# scepclient - SCEP client usage

`scepclient` is an RFC 8894 SCEP client: get a deployable certificate in one command, or stress-test any SCEP server for compliance. Pluggable crypto, post-quantum, recipient-aware enveloping. (Runs standalone, or via `scepwright client …` / `scepwright test …`.)

## Use it - get and manage certificates
| Command | Purpose |
|---|---|
| `scepclient servers add <url> [--name <n>] [--ca-identifier <c>] [--transport get\|post]` | register a server |
| `scepclient servers list` / `servers show <id>` | inspect registered servers |
| `scepclient get <serverId> --subject "CN=x" [--dns <name> ...] [--upn <user@dom> ...] [--challenge <pw>] [--key-spec rsa:2048] [--alt-key-spec ml-dsa:65] [--digest SHA-256] [--cipher AES-128-CBC] [--encrypt-keys --key-pass <pw>] [--sid <s>] [-v]` | enroll a new cert (the private key is stored **plaintext** unless you pass `--encrypt-keys`; `get` prints a warning when it does). `--dns`/`--upn` (repeatable) request a SubjectAltName |
| `scepclient enroll <serverId> --subject "CN=x" [--challenge <pw> \| --simulator <url> \| --ndes --ndes-user <u> --ndes-password <p>] [--key-spec rsa:2048] [--digest SHA-256] [--cipher AES-128-CBC] [--encrypt-keys --key-pass <pw>]` | enroll (challenge sources) |
| `scepclient renew <certId> [--variant proper\|reenroll-same-subject\|pkcsreq-old-cert\|same-key\|expired] [--challenge <pw> \| --simulator <url> \| --ndes …] [--key-pass <pw>]` | renew (`certId` is `serverId/thumbprint` from `certs list`, or a bare thumbprint; pass `--challenge` for challenge-protected CAs; an encrypted key stays encrypted) |
| `scepclient certs list [serverId]` | list stored certs as a table: subject, key-spec, expiry, status, id |
| `scepclient certs show <certId>` | full metadata for one cert (subject, serial, validity, key-spec, status, at-rest protection) |
| `scepclient certs export <certId> [--out <path>] [--format pfx\|pem] [--legacy] [--key-pass <pw>]` | export a deployable PKCS#12 (default, PBES2/AES-256) or PEM bundle; `--legacy` emits an old-style SHA-1/RC2/3DES PFX for ancient importers |
| `scepclient config show` / `config set <key> <value>` | config (keys: `crypto-provider`, `key-spec`, `min-rsa-bits`, `timeout-seconds`) |
| `scepclient crypto info` / `crypto list` | post-quantum tier summary / full capability inventory |

Unknown flags are rejected (e.g. a typo'd `--keyspec` errors rather than silently falling back to defaults).

## Test with it - exercise a server for RFC 8894 compliance
| Command | Purpose |
|---|---|
| `scepclient diagnose <serverId> [-v]` | read-only health check: caps, CA/RA cert details, and whether requests can be enveloped (spot a wrong RA/CA cert without enrolling). On an HTTP error the server's response body is surfaced inline (so a 500 shows *why*, not a bare status); `-v` traces the resolved request URLs |
| `scepclient getcacaps <serverId>` | GetCACaps |
| `scepclient getcacert <serverId> [-v]` | GetCACert (`-v` prints full cert details: KeyUsage, EKU, validity, thumbprint) / `getnextcacert <serverId>` |
| `scepclient poll <serverId> --issuer <dn> --subject <dn> --txn <id> [--key-pass <pw>]` | CertPoll: completes a PENDING enrollment. Signs the poll with the original enrollment key (saved when `get`/`enroll` returned PENDING) and, on success, stores the issued cert+key so it appears in `certs list` and can be renewed/exported. `--key-pass` unlocks the saved key if it was encrypted |
| `scepclient getcert <serverId> --issuer <dn> --serial <hex>` | GetCert |
| `scepclient getcrl <serverId> --issuer <dn> --serial <hex>` | GetCRL |
| `scepclient servers suggest <id>` | capability/security advice |
| `scepclient full\|lifecycle\|probe <serverId> [--dry-run] [--report-format junit\|trx\|json\|md] [--jamf-max-wait <ms>] [--challenge <pw> \| --simulator <url> \| --ndes --ndes-user <u> --ndes-password <p>] [--fail-on-findings]` | compliance suites (also `test <verb> <serverId>`); `--dry-run` runs read-only checks only (issues no certificates - safe against a CA you don't own); pass a challenge source to drive a challenge-protected / NDES CA; exit non-zero on findings with `--fail-on-findings` |
| `scepclient run <scenario.json> <serverId> [--report-format junit\|trx\|json\|md] [--fail-on-findings]` | scenario playlist (see [Scenario files](#scenario-files)) |

Exit codes: `0` = all checks passed (findings allowed); `1` = a check FAILED, or findings with `--fail-on-findings`; `2` = usage/argument error. A compliant-but-strict server (e.g. no GetNextCACert, classical CA rejecting PQ, PENDING) scores SKIPPED/INFO, not FAILED.

For exactly what each suite proves - every check mapped to its RFC 8894 section - see the **[coverage matrix](coverage-matrix.md)**.

**Report fields (JSON/Markdown):** each result has an `outcome` (the verdict: `Passed`/`Failed`/`Skipped`/`Finding`) and a `pkiStatus` (the server's SCEP response status for that check). They are independent: a PASSED *negative* check shows `pkiStatus: "Failure"` because rejection is the pass condition - that's expected, not inverted.

**Footprint:** the live suites (`full`/`lifecycle`/`probe` without `--dry-run`) issue **real** certificates. Each run prints a `FOOTPRINT` list of every serial + subject it minted (also in the JSON/Markdown reports) so you can revoke / clean them up afterward.

## Testing a real SCEP server's Intune integration (with IntuneSimulator)

The separate **IntuneSimulator** download fakes the Microsoft **Intune cloud** - the side a SCEP server's connector calls to mint and validate enrollment challenges. It is **not** a SCEP server and issues no `CertRep`. Its job is to let you exercise a **real** SCEP server's Intune integration end to end, with `scepclient` standing in for the managed device:

```
scepclient (device)                    REAL SCEP server           IntuneSimulator (fake Intune cloud)
   │  --simulator <sim-url>                   │                                    │
   │ ── POST /challenge ─────────────────────────────────────────────────────────► │   mint a challenge password
   │ ◄─ challengePassword ──────────────────────────────────────────────────────── │
   │ ── SCEP PKCSReq (with that challenge) ─► │                                    │
   │                                          │ ── /ScepActions/validateRequest ─► │  validate the CSR
   │                                          │ ◄─ allow / reject ─────────────────│  (can be forced to fail)
   │ ◄─ SCEP CertRep (issued / failInfo) ─────│                                    │
```

`--simulator <sim-url>` makes `scepclient` fetch the challenge from the simulator's `/challenge` endpoint and present it to the SCEP server under test - exactly as a device provisioned by Intune would. The SCEP server's Intune connector then calls the simulator's `/ScepActions/validateRequest` to authorize the request; `scepclient` observes whatever SCEP response comes back.

```bash
# Enroll against the real SCEP server you are validating, pulling the challenge from the simulator:
scepclient enroll corp-scep --subject "CN=device-01" --simulator https://intune-sim.test:8443
```

`--simulator` is a challenge **source**, so it works anywhere a challenge does - `get`, `enroll`, `renew`, and the `full`/`lifecycle`/`probe` suites.

**Forcing a validation failure.** Point the simulator at a canned validation error to confirm the real server rejects (and that `scepclient` surfaces the failure). For example, to assert a subject-name mismatch is rejected (SCEPwright spec §13):

```bash
# On the simulator: force every validateRequest to report a subject-name mismatch
curl -s -X POST https://intune-sim.test:8443/control -H 'Content-Type: application/json' \
  -d '{"cannedScepCode":"SubjectNameMismatch"}'

# Then enroll - a correctly-integrated SCEP server returns a SCEP failure, which scepclient reports:
scepclient enroll corp-scep --subject "CN=device-01" --simulator https://intune-sim.test:8443

# Clear it when done:
curl -s -X POST https://intune-sim.test:8443/control -H 'Content-Type: application/json' -d '{"cannedScepCode":null}'
```

Other canned codes include `SubjectNameMissing`, `SubjectAltNameMismatch`, `KeyUsageMismatch`, `EnhancedKeyUsageMissing`, `SignatureValidationFailed`, and more - see the IntuneSimulator manual (`docs/intune-simulator.md`, "Control behavior") for the full list and the `/control` API. Note this loop runs against a **real** SCEP server: `scepca` is a standalone test CA with no Intune connector, so it does not participate in simulator validation.

## Crypto & post-quantum
- `--key-spec`: `rsa:<bits>` (e.g. `rsa:2048`), `ec:p256|p384|p521`, `ml-dsa:44|65|87`, `slh-dsa:128s|128f|192s|192f|256s|256f`. (ML-KEM is a key-encapsulation algorithm used for response enveloping only; it cannot be a certificate subject key.)
- `--alt-key-spec`: **experimental probe, not a usable second credential.** Attaches an extra (alt) public key to the CSR to see how a server handles catalyst/hybrid-shaped requests. The built-in provider does **not** compute `altSignatureValue`, so the request is non-conformant; most CAs strip the alt key, and the alt private key is **not** retained.
- `--crypto-provider <path>`: load an external `IScepCrypto` provider DLL (default is the built-in BouncyCastle provider beside the exe).
- `crypto list` prints the provider's full inventory - digests, signatures, content encryption, key transport, and KEM. `crypto info` summarizes the provider and its post-quantum **tier** support: **Tier A** = ML-DSA signatures (FIPS 204), **Tier B** = SLH-DSA signatures (FIPS 205), **Tier C** = ML-KEM enveloping via `KEMRecipientInfo` (RFC 9629).
- `--digest <name>` / `--cipher <name>`: choose the PKCS#7 signing digest (e.g. `SHA-256`, `SHA-512`) and the request's content-encryption cipher (e.g. `AES-128-CBC`, `DES-EDE3-CBC`) for `get`/`enroll`.
- **Stored files** (under `~/.scepwright/servers/<id>/certificates/<thumbprint>/`): `cert.pem` is the issued certificate; `key.pkcs8` is the private key in unencrypted PKCS#8, and `key.pkcs8.enc` is the same key in **encrypted** PKCS#8 (PBES2/AES-256, written instead of `key.pkcs8` when you pass `--encrypt-keys`); `metadata.json` records the subject, key-spec, and lineage. Use `certs export` to get a `.pfx`/PEM bundle for other tools.
- **Recipient-aware enveloping:** the client picks the CA encryption cert by KeyUsage and matches the recipient algorithm (RSA key-transport, EC ECDH key-agreement, ML-KEM `KEMRecipientInfo` per RFC 9629).
- **PQ signature keys and the SCEP transport:** ML-DSA / SLH-DSA are signature-only, so they cannot decrypt the SCEP `CertRep` the CA sends back (SCEP envelopes the response to the requester's signing certificate). For an `enroll` - or a `renew --variant reenroll-same-subject` - of a PQ key, the client signs the exchange with a **transient RSA transport key** and prints a disclosure. This is **not** a post-quantum downgrade: that key protects only the response, which carries your **issued (public) certificate** and no secret; your certified key stays ML-DSA/SLH-DSA, and the confidential request (CSR + challenge) is still enveloped to the CA's RA cert (which may be ML-KEM). A *proper* `RenewalReq` is signed by the existing cert, so it can't be enveloped back to a PQ signature cert - a conformant CA rejects it (clean `badRequest`, not a crash); use `--variant reenroll-same-subject` instead. ML-KEM can't substitute for the transient signer because a KEM cannot produce the CMS signature SCEP requires.

## Storage & secrets
- Root: `~/.scepwright/servers/<id>/…`. Override with `--data-dir <path>` or `$SCEPWRIGHT_HOME`; breadcrumb at `~/.scepwright.json`.
- `--encrypt-keys`: store private keys as encrypted PKCS#8 - **PBES2** (PBKDF2-HMAC-SHA256, AES-256-CBC). Renewing an encrypted cert keeps it encrypted (never silently downgraded to plaintext). Private keys are never written to history/trace/reports; sensitive values are `sha256:`-redacted in logs.
- **Passphrase entry** (for `--encrypt-keys`, `renew`, and `certs export`): precedence is `--key-pass <pw>` → `$SCEPWRIGHT_KEY_PASS` → an interactive hidden prompt (or one stdin line when input is piped). Prefer the env var or prompt over `--key-pass` so the secret never lands in shell history or the process table.

## Reports
`--report-format junit|trx|json|md` (repeatable) writes under `<root>/runs/`; each file's path is echoed when written. Use in CI to gate on `failInfo`/leniency findings.

## Scenario files
`scepclient run <scenario.json> <serverId>` replays an ordered playlist of steps and aggregates them into one report. A ready-to-run sample lives at [`examples/scenario.json`](../examples/scenario.json).

```jsonc
{
  "Name": "smoke",                       // label for the run
  "Steps": [
    {
      "Name": "enroll-rsa-sha256",       // label for this step
      "Run": "enroll",                   // one of: getcacaps | enroll | probe
      "Args": {                          // optional; keys: subject, challenge, digest, cipher
        "subject": "CN=scenario-01",
        "challenge": "s3cret",
        "digest": "SHA-256",
        "cipher": "AES-128-CBC"
      },
      "Expect": "pass"                   // pass | fail | badAlg | badMessageCheck | badTime | badRequest | badCertId
    }
  ]
}
```

- **`Run`** verbs: `getcacaps`, `enroll`, `probe` (`enroll` and `probe` share the same PKCSReq path). Unknown verbs are rejected when the file is parsed.
- **`Expect`**: `pass` requires `SUCCESS`; `fail` requires any non-success; a named `failInfo` requires that exact rejection code.
- All probes use a fixed `rsa:2048` key so the result reflects the server's handling of the chosen `digest`/`cipher`, not the key type.

## Examples
```bash
scepclient servers add https://ca.example.com/certsrv/mscep/mscep.dll --name corp
scepclient get corp --subject "CN=device-01" --challenge s3cret --key-spec rsa:2048
scepclient test full corp --report-format junit
```
