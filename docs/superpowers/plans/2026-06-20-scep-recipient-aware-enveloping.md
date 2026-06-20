# SCEP Recipient-Aware Enveloping + Cert-Usage Conformance — Plan

**Branch:** `feature/scep-recipient-aware` (off main after Phase 4 / PR #5 merged).
**Origin:** Designed collaboratively 2026-06-20 (post-Phase-4). Emerged from the realization that SCEP allows separate signing vs. encryption certificates, so the EnvelopedData recipient must be chosen by capability — and that an ML-DSA/SLH-DSA-only server has no encryption-capable key at all.

**Goal:** Make the client choose the SCEP EnvelopedData recipient from the `GetCACert` bundle correctly (by KeyUsage, with a positional mode), pick the `RecipientInfo` type by the recipient cert's algorithm (RSA `KeyTrans`, EC `KeyAgree`, ML-KEM `KEMRecipientInfo`), and surface conformance findings. Plumb the fake server to present every signing/encryption cert combination via parallel per-profile endpoints. **Out of scope:** generating an actual RFC 9629 `KEMRecipientInfo` (BC 2.5.0 has no generator) — built-in provider emits a capability-gated finding; the seam is left ready for an external provider or a future hand-roll, and for testing against a real ML-KEM server.

**Additive only:** no `IScepCrypto` signature change. `PkiMessage.RecipientCaCert` already carries the recipient; we only change *which* cert is selected and how the provider branches on it.

## Key facts established (see memory [[scep-bouncycastle-cms-reference]])
- RFC 8894 does **not** mandate position vs. KeyUsage for distinguishing RA signing/encryption certs — both are conventions. Default to KeyUsage; support positional; flag disagreement.
- A single dual-use cert is valid: RSA (`digitalSignature`+`keyEncipherment`) or EC (`digitalSignature`+`keyAgreement`).
- Recipient algorithm → RecipientInfo: RSA(`keyEncipherment`)→`KeyTrans`; EC(`keyAgreement`)→`KeyAgree`; ML-KEM(`keyEncipherment`)→`KEMRecipientInfo`; ML-DSA/SLH-DSA→none (signature-only, cannot be a recipient).
- BC 2.5.0: `AddKeyTransRecipient` ✓, `AddKeyAgreementRecipient` ✓, no KEM recipient generator (only the `KemRecipientInfo` ASN.1 type).

## Tasks (TDD, granular commits; implemented in-session)

1. **RecipientSelector (Core) + cert-usage classification.** Pure function: `(certs, strategy) → { SigningCert, EncryptionCert?, RecipientKind, Findings }`. Strategy = KeyUsage (default) | Positional. Classify each cert by SPKI OID → RSA/EC/ML-KEM/SignatureOnly and by KeyUsage bits. Findings: no encryption-capable cert; KeyUsage/position disagreement; missing KeyUsage extension. Tests cover single-RSA, single-EC, split combos, ML-DSA-only (→ finding), and disagreement. *(Server-agnostic; highest value first.)*
2. **Wire selection into the enroll path.** Replace blind `ca.Value[0]` recipient with `RecipientSelector` result; keep signing cert for response verification (unaffected). Surface findings via the existing Trace/Opinion + test report channels.
3. **Provider RecipientInfo branching (`BcPkiMessage`).** Branch envelope on recipient SPKI algorithm: RSA→`AddKeyTransRecipient` (have), EC→`AddKeyAgreementRecipient` (new), ML-KEM→error → Core finding. Capability flag in `CryptoCapabilities` so the finding is capability-driven.
4. **Fake server per-profile endpoints.** `/scep/{profile}` routes, each backed by a `TestCa` configured for a cert combo: `rsa-dual`, `ec-dual`, `ecdsa-rsa`, `ecdsa-ecdh`, `mldsa-rsa`, `mldsa-mlkem`, `mldsa-only` (+ KeyUsage/order variants). `TestCa` generates signing+encryption certs of chosen algorithms with chosen KeyUsage and assembles the degenerate PKCS#7 in chosen order. Server-side decryption: RSA (have) + EC ECDH (new); ML-KEM cert is *presented only*.
5. **End-to-end tests per endpoint.** RSA round-trip (have), EC round-trip (new), ML-DSA-sign+RSA-encrypt round-trip (the realistic PQ case), ML-KEM-presented → client finding, ML-DSA-only → "cannot envelope" finding. Plus a standalone "RA cert usage" conformance check (verifies a server set its KeyUsage bits correctly).

## Deferred
- RFC 9629 `KEMRecipientInfo` generation (client) + decapsulation (fake server) — the contained hand-roll, to be done when pointing at a real ML-KEM server or loading a KEM-capable provider.
