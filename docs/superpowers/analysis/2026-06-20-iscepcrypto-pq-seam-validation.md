# IScepCrypto seam validation vs PQ tiers (Phase 4 pre-flight)

Date: 2026-06-20. Re-validates the Phase-1 on-paper conclusion before writing PQ code.
Reference interface: `src/ScepTestClient.CryptoApi/IScepCrypto.cs` (unchanged by Phase 4).

## Conclusion: additive-only. No IScepCrypto signature changes.

Every PQ tier slots in through the three seams designed in Phase 1 — open OID identifiers +
capability advertisement, opaque `IScepKey` handles, and extensible domain objects. The
`IScepCrypto` interface itself is **not** modified. The only new public surface is additive
(new properties / new registry entries) that existing and external callers ignore.

## Tier A — PQ end-entity key (ML-DSA / SLH-DSA)

- `KeySpec.Parse` gains `ml-dsa:65` / `slh-dsa:128s` (new accepted inputs + a new `Parameter`
  property; existing `rsa:<bits>` callers unaffected, `Size` keeps working for RSA).
- `IScepCrypto.GenerateKey(KeySpec, out IScepKey, out string)` — **unchanged signature**; returns an
  `IScepKey` whose `AlgorithmOid` is the PQ OID.
- `IScepCrypto.EncodeCsr(Pkcs10, ...)` — **unchanged**; the provider emits a PQ
  `SubjectPublicKeyInfo` (`PqcSubjectPublicKeyInfoFactory`) and signs with the PQ signer.
- `ExportPrivateKeyPkcs8` / `ImportPrivateKeyPkcs8` — **unchanged**; PQ via
  `PqcPrivateKeyInfoFactory` / `PrivateKeyFactory`.
- BC 2.5.0: **FEASIBLE** (`MLDsaKeyPairGenerator`, `SlhDsaKeyPairGenerator`, `MLDsaParameters`,
  `SlhDsaParameters`, the Pqc SPKI/PKCS#8 factories all present).

## Tier B — Catalyst / hybrid alt-key (subjectAltPublicKeyInfo)

- New additive `Pkcs10.AltKey` (`IScepKey?`) property, defaulting null, ignored by existing callers.
- `EncodeCsr` emits the `subjectAltPublicKeyInfo` extension (OID `2.5.29.72`) carrying the alt
  key's `SubjectPublicKeyInfo`.
- **No interface change.**
- BC 2.5.0: emitting the alt PUBLIC KEY is **FEASIBLE**; computing a conformant
  `altSignatureValue` over the CSR is bleeding-edge and is **NOT** done by the built-in provider —
  recorded as a documented limitation (surfaced via this doc + `crypto info`).

## Tier C — PQ transport (ML-KEM EnvelopedData, RFC 9629 KEMRecipientInfo)

- `EncodePkiMessage` already takes the recipient via `PkiMessage.RecipientCaCert` — a PQ recipient
  WOULD trigger `KEMRecipientInfo` inside the provider. **No signature change.**
- BC 2.5.0: **NOT FEASIBLE.** The CMS layer exposes only KeyTrans / Kek / KeyAgree / Password
  recipient generators; `KemRecipientInfo` exists only as a raw ASN.1 type with no CMS generator,
  and the `MLKemKeyPairGenerator` / `*KemGenerator` types are low-level KEM primitives not wired
  into `CmsEnvelopedDataGenerator`. The built-in provider therefore advertises
  `CryptoCapabilities.PqTiers.TierC = false`; an external provider can implement it through the same
  seam without an interface change.

## Composite signatures

- BC 2.5.0 carries only the legacy Dilithium-draft composite OIDs (`id_Dilithium3_ECDSA_P256_SHA256`,
  etc.) and the bare `id_composite_key` OID — there is no current ML-DSA composite signing path.
- Scope: composite stays **vocabulary + opinion** (classified `CuttingEdge`); no BC signing
  implementation in Phase 4.

## New additive surface introduced by Phase 4

- `KeySpec.Parameter` (string); `KeySpec.Parse` PQ inputs.
- `CryptoCapabilities.PqTiers` (`TierA`/`TierB`/`TierC` bools) + PQ OIDs in
  `Signatures` / `AsymmetricKeys` / `Kem`.
- `Pkcs10.AltKey` (`IScepKey?`).
- `Algorithms` registry: ML-DSA-44/65/87, SLH-DSA-128s/192s/256s, ML-KEM-512/768/1024 entries.

None of the above alters an existing method signature; all are new members or new accepted input
values. The seam validated in Phase 1 holds.
