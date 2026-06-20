# ScepTestClient — Phase 2 (Renewal & Lineage) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers-extended-cc:subagent-driven-development (recommended) or superpowers-extended-cc:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add full renewal coverage (RenewalReq + the 5 renewal variants), `GetCert`/`GetCRL`/standalone `CertPoll`, a fluent `ScepRequestBuilder`, `renewedFrom` lineage with high-level `renew <cert-id>`, and encrypted PKCS#8 key storage — on top of the working Phase 1 enroll client.

**Architecture:** The BC provider's `EncodePkiMessage` generalizes from "PKCSReq only" to a single `EncodePkiOperation` that envelopes any inner payload (a CSR for PKCSReq/RenewalReq, an `IssuerAndSerialNumber` for GetCert/GetCRL, an `IssuerAndSubject` for CertPoll) and stamps the right SCEP `messageType`. A new `ScepRequestBuilder` composes the `PkiMessage` for every operation. `ScepClient` gains `Renew`/`GetCert`/`GetCrl`/`Poll` (sync+async) over one unified `SendPkiOperation` core — the CertRep is always enveloped to the request's signer cert, so decryption always uses `message.SignerKey`. Lineage lives in `CertStore` metadata (`RenewedFrom`) and a `Load`/key-import path lets a stored cert sign its own renewal.

**Tech Stack:** .NET 8 (`net8.0`, `RollForward Major`), C#, xUnit, BouncyCastle.Cryptography 2.5.0, `System.Security.Cryptography.X509Certificates`.

**User decisions (already made):**
- "no var; explicit types only" → enforced by `.editorconfig`; never `var`.
- "declare locals at the top of the block, unassigned, blank line, then assignments" → declare-at-top convention.
- Same-line braces (not Allman); single-line statements; snake_case locals/params/private fields; PascalCase methods/types/properties — all enforced by the scoped `.editorconfig`. **Write every new file in this style from the first keystroke; tell every implementer/test subagent the same. No reformat pass, no squash — keep granular task commits.**
- "no exceptions for control flow" → static `Create()`/`Load()`/`For()` factories; sync = result enum + `out value` + `out string error`; async = `ScepResult<T>`.
- "full sync + async parity" → every op in both forms; genuine `HttpClient.Send`/`SendAsync`, never `.GetAwaiter().GetResult()` on a network call.
- The design spec is authoritative and already approved: `docs/superpowers/specs/2026-06-19-scep-test-client-design.md` (§5.3, §6, §8, §9). Do NOT re-brainstorm.

---

## Phase 2 scope (spec §17 table, row "Phase 2")

RenewalReq (17), GetCert (21), GetCRL (22); the 5 renewal variants; `renewedFrom` lineage + `renew <cert-id>`; the `ScepRequestBuilder` fluent API; renewal tests. Plus the two Phase-1 deferrals folded in: standalone `CertPoll` (20) and encrypted PKCS#8 (`--encrypt-keys`).

## What already exists (Phase 1 — do not rebuild)

- `IScepCrypto` with `GenerateKey`, `EncodeCsr`, `EncodePkiMessage` (PKCSReq only — hard-rejects other types), `DecodePkiMessage` (CertRep only), `ParseCaCertificates`, `ExportPrivateKeyPkcs8`.
- `PkiMessage` (outbound + inbound fields), `Pkcs10`, `Algorithms` registry, `KeySpec`, `CodecOptions`, `ConformanceNote`.
- `BcPkiMessage.EncodePkcsReq` + `Decode`; `BcCsrBuilder`; `BcSelfSigned.ForKey`; `ScepAttributes` (OID consts).
- `ScepClient` (`Create`, `GetCaCaps`, `GetCaCert`, `GetNextCaCert`, `Enroll`, `GetNewCertificate`) sync+async, `Trace` event.
- `EnrollRequest`, `EnrollOutcome`, `CertStore.Save(server,cert,EnrollRequest,crypto)`, `UseRecordLog`, `ServerConfig`.
- Tests fakes: `TestCa` (`Create`, `Issue`, `CertificateBcl`, `BuildSuccessCertRep`, `HandlePkiOperation`), `FakeScepServer` (Kestrel loopback; GET GetCACaps/GetCACert, POST PKIOperation).
- CLI `CommandRouter`: `servers`, `getcacaps`, `get`, `certs`, `config`.

---

## File Structure (Phase 2)

```
src/ScepTestClient.CryptoApi/
  PkiMessage.cs            MODIFY  + IssuerName, SerialNumber, SubjectName, IssuedCrls
  IScepCrypto.cs           MODIFY  + ImportPrivateKeyPkcs8, ExportPrivateKeyPkcs8Encrypted, ImportPrivateKeyPkcs8Encrypted

src/ScepTestClient.Crypto.BouncyCastle/
  ScepAttributes.cs        MODIFY  + NumberFor(MessageType)
  BcPkiMessage.cs          MODIFY  EncodePkcsReq → EncodePkiOperation; IssuerAndSerial/IssuerAndSubject payloads; CRL extraction on Decode
  BouncyCastleScepCrypto.cs MODIFY EncodePkiMessage dispatch (Renewal/GetCert/GetCrl/CertPoll); key import + encrypted PKCS#8

src/ScepTestClient.Core/
  ScepRequestBuilder.cs    CREATE  fluent composer
  RenewalVariant.cs        CREATE  enum
  RenewRequest.cs          CREATE
  EnrollOutcome.cs         MODIFY  + SubjectKey
  ScepClient.cs            MODIFY  Renew/GetCert/GetCrl/Poll (+async); unified SendPkiOperation; Create(existingCert); RenewCertificate
  Storage/CertStore.cs     MODIFY  lineage metadata; core Save overload; Load; encrypted key files

src/ScepTestClient.Cli/
  CommandRouter.cs         MODIFY  getcacert/getnextcacert/enroll/renew/getcert/getcrl/poll + --encrypt-keys + usage

tests/ScepTestClient.Tests/
  Fakes/TestCa.cs          MODIFY  IssueExpired, GenerateCrl, EnvelopeAndSign refactor, BuildSuccessCrlRep, BuildFailureCertRep, HandleGetCert/HandleGetCrl/HandlePoll, PeekMessageType, issued-by-serial map
  Fakes/FakeScepServer.cs  MODIFY  route POST by messageType
  BcRenewalEncodeTests.cs  CREATE
  BcGetCertCrlEncodeTests.cs CREATE
  BcCrlDecodeTests.cs      CREATE
  ScepRequestBuilderTests.cs CREATE
  RenewalTests.cs          CREATE
  GetCertCrlTests.cs       CREATE
  PollTests.cs             CREATE
  CertStoreLineageTests.cs CREATE
  KeyImportTests.cs        CREATE
  RenewLifecycleTests.cs   CREATE
  EncryptedKeyTests.cs     CREATE
  CliRouterPhase2Tests.cs  CREATE
```

---

### Task 1: Generalized PKI-operation encode + RenewalReq (17)

**Goal:** Refactor the BC encoder so it can stamp any SCEP `messageType` over any enveloped payload, and make `EncodePkiMessage` accept `RenewalReq` (CSR enveloped + signed with the supplied signer cert/key).

**Files:**
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/ScepAttributes.cs`
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BcPkiMessage.cs`
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs`
- Test: `tests/ScepTestClient.Tests/BcRenewalEncodeTests.cs`

**Acceptance Criteria:**
- [ ] A `RenewalReq` `PkiMessage` (with `SignerCert`+`SignerKey` from an existing issued cert, `InnerCsr` on a new key) encodes to a CMS `SignedData` whose `messageType` signed attr == `"17"` and whose `SignedContentType` == EnvelopedData.
- [ ] The existing PKCSReq test (`BcEncodeTests`) still passes unchanged (messageType `"19"`).
- [ ] `ScepAttributes.NumberFor(MessageType.RenewalReq) == "17"` etc. for all six message types.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter "BcRenewalEncodeTests|BcEncodeTests"` → all pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/BcRenewalEncodeTests.cs`

```csharp
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class BcRenewalEncodeTests {
    private const string MessageTypeOid = "2.16.840.1.113733.1.9.2";

    [Fact]
    public void Encodes_renewalreq_signed_with_existing_cert() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey existing_key;
        IScepKey new_key;
        X509Certificate2 existing_cert;
        Pkcs10 csr;
        PkiMessage pki;
        byte[] der;
        string error;
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.Asn1.Cms.Attribute msg_type;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out existing_key, out _);
        crypto.GenerateKey(spec, out new_key, out _);

        // An existing cert issued by the CA over the existing key's public part.
        existing_cert = new X509Certificate2(
            ca.Issue(((BcKey)existing_key).KeyPair.Public, "CN=poodle").GetEncoded());

        csr = new Pkcs10 { Key = new_key };
        csr.SetSubject("CN=poodle", out _);

        pki = new PkiMessage {
            MessageType = MessageType.RenewalReq,
            InnerCsr = csr,
            SignerKey = existing_key,
            SignerCert = existing_cert,
            RecipientCaCert = ca.CertificateBcl,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        msg_type = signer.SignedAttributes[new DerObjectIdentifier(MessageTypeOid)];
        Assert.Equal("17", ((DerPrintableString)msg_type.AttrValues[0]).GetString());
        Assert.Equal(CmsObjectIdentifiers.EnvelopedData.Id, signed.SignedContentType.Id);
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `dotnet test tests/ScepTestClient.Tests --filter BcRenewalEncodeTests` → FAIL (`EncodePkiMessage` rejects non-PKCSReq).

- [ ] **Step 3: Add `NumberFor` to `ScepAttributes`** — append inside the class in `ScepAttributes.cs`:

```csharp
    public static string NumberFor(ScepTestClient.CryptoApi.MessageType type) {
        switch (type) {
            case ScepTestClient.CryptoApi.MessageType.CertRep: return "3";
            case ScepTestClient.CryptoApi.MessageType.RenewalReq: return "17";
            case ScepTestClient.CryptoApi.MessageType.PkcsReq: return "19";
            case ScepTestClient.CryptoApi.MessageType.CertPoll: return "20";
            case ScepTestClient.CryptoApi.MessageType.GetCert: return "21";
            case ScepTestClient.CryptoApi.MessageType.GetCrl: return "22";
            default: return ((int)type).ToString();
        }
    }
```

- [ ] **Step 4: Generalize the encoder in `BcPkiMessage.cs`** — rename `EncodePkcsReq` to `EncodePkiOperation` and take the message-type number + the already-built inner payload. Replace the method signature and the two hardcoded bits (`"19"` and the CSR enveloping is done by the caller now):

```csharp
    public static byte[] EncodePkiOperation(PkiMessage message, byte[] inner_payload_der, BcKey signer_key, string message_type_number) {
        CmsEnvelopedDataGenerator enveloped_gen;
        CmsEnvelopedData enveloped;
        CmsProcessable enveloped_content;
        Org.BouncyCastle.X509.X509Certificate signer_cert;
        CmsSignedDataGenerator signed_gen;
        Dictionary<DerObjectIdentifier, object> signed_attrs;
        AttributeTable signed_attr_table;
        CmsSignedData signed_data;
        IStore<Org.BouncyCastle.X509.X509Certificate> cert_store;
        string trans_id;
        byte[] sender_nonce;
        Org.BouncyCastle.X509.X509Certificate recipient_bc_cert;

        // --- 1. Envelope the inner payload to the CA recipient ---
        recipient_bc_cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(message.RecipientCaCert!.RawData);
        enveloped_gen = new CmsEnvelopedDataGenerator(Random);
        enveloped_gen.AddKeyTransRecipient(recipient_bc_cert);
        enveloped = enveloped_gen.Generate(new CmsProcessableByteArray(inner_payload_der), message.ContentEncryptionAlgorithmOid);

        // --- 2. Determine signer cert ---
        if (message.SignerCert != null) {
            signer_cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(message.SignerCert.RawData);
        } else {
            signer_cert = BcSelfSigned.ForKey(signer_key, "CN=SCEP-Client");
        }

        // --- 3. Build SCEP signed attributes ---
        trans_id = message.TransactionId ?? Guid.NewGuid().ToString("N");
        message.TransactionId = trans_id;

        sender_nonce = new byte[16];
        Random.NextBytes(sender_nonce);

        signed_attrs = new Dictionary<DerObjectIdentifier, object>();
        signed_attrs[new DerObjectIdentifier(ScepAttributes.MessageType)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(ScepAttributes.MessageType), new DerSet(new DerPrintableString(message_type_number)));
        signed_attrs[new DerObjectIdentifier(ScepAttributes.TransId)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(ScepAttributes.TransId), new DerSet(new DerPrintableString(trans_id)));
        signed_attrs[new DerObjectIdentifier(ScepAttributes.SenderNonce)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(ScepAttributes.SenderNonce), new DerSet(new DerOctetString(sender_nonce)));
        signed_attr_table = new AttributeTable(signed_attrs);

        // --- 4. Sign the enveloped data ---
        cert_store = CollectionUtilities.CreateStore(new[] { signer_cert });
        signed_gen = new CmsSignedDataGenerator(Random);
        signed_gen.AddSigner(signer_key.KeyPair.Private, signer_cert, message.DigestAlgorithmOid, signed_attr_table, null);
        signed_gen.AddCertificates(cert_store);

        enveloped_content = new CmsProcessableByteArray(enveloped.GetEncoded());
        signed_data = signed_gen.Generate(Org.BouncyCastle.Asn1.Cms.CmsObjectIdentifiers.EnvelopedData.Id, enveloped_content, true);

        return signed_data.GetEncoded();
    }
```

- [ ] **Step 5: Update the dispatch in `BouncyCastleScepCrypto.EncodePkiMessage`** — accept PKCSReq and RenewalReq; both envelope the CSR:

```csharp
    public bool EncodePkiMessage(PkiMessage message, FaultDirectives? faults, out byte[] der, out string error) {
        // faults: Phase-1 no-op stub; fault injection is wired up in Phase 3.
        byte[] csr_der;

        der = System.Array.Empty<byte>();
        error = string.Empty;

        if (message.SignerKey is not BcKey signer_key) {
            error = "SignerKey was not produced by this provider";
            return false;
        }

        if (message.RecipientCaCert == null) {
            error = "RecipientCaCert must be set";
            return false;
        }

        try {
            switch (message.MessageType) {
                case MessageType.PkcsReq:
                case MessageType.RenewalReq:
                    if (message.InnerCsr == null) {
                        error = $"InnerCsr must be set for {message.MessageType}";
                        return false;
                    }
                    if (!EncodeCsr(message.InnerCsr, out csr_der, out error)) {
                        return false;
                    }
                    der = BcPkiMessage.EncodePkiOperation(message, csr_der, signer_key, ScepAttributes.NumberFor(message.MessageType));
                    return true;
                default:
                    error = $"unsupported message type: {message.MessageType}";
                    return false;
            }
        } catch (System.Exception ex) {
            error = $"{message.MessageType} encode failed: {ex.Message}";
            return false;
        }
    }
```

- [ ] **Step 6: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter "BcRenewalEncodeTests|BcEncodeTests"` → PASS.

- [ ] **Step 7: Commit** — `git commit -am "BC provider: generalize PKI-operation encode; add RenewalReq (17)"`

---

### Task 2: GetCert (21) & GetCRL (22) encode + IssuerAndSerial on PkiMessage

**Goal:** Carry an issuer/serial on `PkiMessage` and encode GetCert/GetCRL as an `IssuerAndSerialNumber` enveloped to the CA and signed.

**Files:**
- Modify: `src/ScepTestClient.CryptoApi/PkiMessage.cs`
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BcPkiMessage.cs`
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs`
- Test: `tests/ScepTestClient.Tests/BcGetCertCrlEncodeTests.cs`

**Acceptance Criteria:**
- [ ] A `GetCert` `PkiMessage` (`IssuerName`, `SerialNumber`, transient `SignerKey`, `RecipientCaCert`) encodes to CMS `SignedData` with `messageType == "21"` and `SignedContentType` == EnvelopedData.
- [ ] A `GetCrl` message encodes with `messageType == "22"`.
- [ ] The enveloped inner payload decrypts (with the CA key) to a DER `IssuerAndSerialNumber` whose serial round-trips the supplied value.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter BcGetCertCrlEncodeTests` → pass.

**Steps:**

- [ ] **Step 1: Add fields to `PkiMessage.cs`** — in the outbound section, after `TransactionId`:

```csharp
    public string? IssuerName { get; set; }       // GetCert / GetCrl: issuer DN of the target cert's CA
    public string? SerialNumber { get; set; }      // GetCert / GetCrl: target cert serial, hex (X509Certificate2.SerialNumber form)
    public string? SubjectName { get; set; }       // CertPoll: subject DN being polled
```

And in the inbound section, after `IssuedCerts`:

```csharp
    public IReadOnlyList<byte[]> IssuedCrls { get; set; } = System.Array.Empty<byte[]>();
```

- [ ] **Step 2: Write the failing test** — `tests/ScepTestClient.Tests/BcGetCertCrlEncodeTests.cs`

```csharp
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class BcGetCertCrlEncodeTests {
    private const string MessageTypeOid = "2.16.840.1.113733.1.9.2";

    private static CmsSignedData EncodeAndParse(MessageType type, string serial_hex, out byte[] inner_der, TestCa ca) {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey signer_key;
        PkiMessage pki;
        byte[] der;
        string error;
        CmsSignedData signed;
        CmsEnvelopedData enveloped;
        MemoryStream ms;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out signer_key, out _);

        pki = new PkiMessage {
            MessageType = type,
            IssuerName = ca.Certificate.SubjectDN.ToString(),
            SerialNumber = serial_hex,
            SignerKey = signer_key,
            RecipientCaCert = ca.CertificateBcl,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);
        signed = new CmsSignedData(der);

        ms = new MemoryStream();
        signed.SignedContent.Write(ms);
        enveloped = new CmsEnvelopedData(ms.ToArray());
        inner_der = enveloped.GetRecipientInfos().GetRecipients().Cast<RecipientInformation>().First().GetContent(ca.KeyPair.Private);
        return signed;
    }

    [Fact]
    public void Encodes_getcert_with_issuer_and_serial() {
        TestCa ca;
        CmsSignedData signed;
        byte[] inner_der;
        SignerInformation signer;
        IssuerAndSerialNumber ias;

        ca = TestCa.Create();
        signed = EncodeAndParse(MessageType.GetCert, "0A", out inner_der, ca);

        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        Assert.Equal("21", ((DerPrintableString)signer.SignedAttributes[new DerObjectIdentifier(MessageTypeOid)].AttrValues[0]).GetString());
        Assert.Equal(CmsObjectIdentifiers.EnvelopedData.Id, signed.SignedContentType.Id);

        ias = IssuerAndSerialNumber.GetInstance(Asn1Object.FromByteArray(inner_der));
        Assert.Equal(10, ias.SerialNumber.Value.IntValue);
    }

    [Fact]
    public void Encodes_getcrl_message_type_22() {
        TestCa ca;
        CmsSignedData signed;
        byte[] inner_der;
        SignerInformation signer;

        ca = TestCa.Create();
        signed = EncodeAndParse(MessageType.GetCrl, "01", out inner_der, ca);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        Assert.Equal("22", ((DerPrintableString)signer.SignedAttributes[new DerObjectIdentifier(MessageTypeOid)].AttrValues[0]).GetString());
    }
}
```

- [ ] **Step 3: Add the IssuerAndSerial payload builder to `BcPkiMessage.cs`** — new method:

```csharp
    public static byte[] BuildIssuerAndSerial(string issuer_dn, string serial_hex) {
        Org.BouncyCastle.Asn1.X509.X509Name issuer;
        Org.BouncyCastle.Math.BigInteger serial;
        IssuerAndSerialNumber ias;

        issuer = new Org.BouncyCastle.Asn1.X509.X509Name(issuer_dn);
        serial = new Org.BouncyCastle.Math.BigInteger(serial_hex, 16);
        ias = new IssuerAndSerialNumber(issuer, serial);
        return ias.GetDerEncoded();
    }
```

(Note: `IssuerAndSerialNumber` lives in `Org.BouncyCastle.Asn1.Cms` — already imported in this file.)

- [ ] **Step 4: Extend the dispatch in `BouncyCastleScepCrypto.EncodePkiMessage`** — add cases inside the `switch` before `default`:

```csharp
                case MessageType.GetCert:
                case MessageType.GetCrl:
                    if (string.IsNullOrEmpty(message.IssuerName) || string.IsNullOrEmpty(message.SerialNumber)) {
                        error = $"IssuerName and SerialNumber must be set for {message.MessageType}";
                        return false;
                    }
                    der = BcPkiMessage.EncodePkiOperation(
                        message,
                        BcPkiMessage.BuildIssuerAndSerial(message.IssuerName!, message.SerialNumber!),
                        signer_key,
                        ScepAttributes.NumberFor(message.MessageType));
                    return true;
```

- [ ] **Step 5: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter BcGetCertCrlEncodeTests` → PASS.

- [ ] **Step 6: Commit** — `git commit -am "BC provider: GetCert/GetCRL encode with IssuerAndSerialNumber"`

---

### Task 3: GetCRL response decode (CRL extraction) + TestCa CRL helpers

**Goal:** Decode a CertRep whose enveloped degenerate PKCS#7 carries a CRL, populating `PkiMessage.IssuedCrls`. Add the test CA's CRL helpers + a shared envelope-and-sign refactor.

**Files:**
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BcPkiMessage.cs`
- Modify: `tests/ScepTestClient.Tests/Fakes/TestCa.cs`
- Test: `tests/ScepTestClient.Tests/BcCrlDecodeTests.cs`

**Acceptance Criteria:**
- [ ] Decoding a SUCCESS CertRep whose content is a degenerate PKCS#7 holding one CRL yields `IssuedCrls.Count == 1` and the bytes parse as an `X509Crl`.
- [ ] The existing cert-bearing CertRep decode (`BcDecodeTests`) still passes (`IssuedCerts` unaffected).

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter "BcCrlDecodeTests|BcDecodeTests"` → pass.

**Steps:**

- [ ] **Step 1: Refactor `TestCa` envelope+sign into a shared private method, then add CRL helpers** — in `TestCa.cs`, extract the envelope-and-sign tail of `BuildSuccessCertRep` (everything from "// 2. Envelope" onward, parameterized on the degenerate bytes and `messageType`/`pkiStatus`) into:

```csharp
    private byte[] EnvelopeAndSign(byte[] degenerate_bytes, X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce, string message_type, string pki_status) {
        const string OidMessageType = "2.16.840.1.113733.1.9.2";
        const string OidPkiStatus = "2.16.840.1.113733.1.9.3";
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        const string OidRecipientNonce = "2.16.840.1.113733.1.9.6";

        Org.BouncyCastle.X509.X509Certificate recipient_bc_cert;
        CmsEnvelopedDataGenerator enveloped_gen;
        CmsEnvelopedData enveloped;
        byte[] enveloped_bytes;
        Dictionary<DerObjectIdentifier, object> signed_attrs_dict;
        Org.BouncyCastle.Asn1.Cms.AttributeTable signed_attr_table;
        IStore<Org.BouncyCastle.X509.X509Certificate> ca_cert_store;
        CmsSignedDataGenerator signed_gen;
        CmsProcessable enveloped_content;
        CmsSignedData signed_data;

        recipient_bc_cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(recipient_cert.RawData);
        enveloped_gen = new CmsEnvelopedDataGenerator(new SecureRandom());
        enveloped_gen.AddKeyTransRecipient(recipient_bc_cert);
        enveloped = enveloped_gen.Generate(new CmsProcessableByteArray(degenerate_bytes), CmsEnvelopedGenerator.Aes128Cbc);
        enveloped_bytes = enveloped.GetEncoded();

        signed_attrs_dict = new Dictionary<DerObjectIdentifier, object>();
        signed_attrs_dict[new DerObjectIdentifier(OidMessageType)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidMessageType), new DerSet(new DerPrintableString(message_type)));
        signed_attrs_dict[new DerObjectIdentifier(OidPkiStatus)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidPkiStatus), new DerSet(new DerPrintableString(pki_status)));
        signed_attrs_dict[new DerObjectIdentifier(OidTransId)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidTransId), new DerSet(new DerPrintableString(trans_id)));
        signed_attrs_dict[new DerObjectIdentifier(OidRecipientNonce)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidRecipientNonce), new DerSet(new DerOctetString(recipient_nonce)));
        signed_attr_table = new Org.BouncyCastle.Asn1.Cms.AttributeTable(signed_attrs_dict);

        ca_cert_store = CollectionUtilities.CreateStore(new[] { Certificate });
        signed_gen = new CmsSignedDataGenerator(new SecureRandom());
        signed_gen.AddSigner(KeyPair.Private, Certificate, CmsSignedGenerator.DigestSha256, signed_attr_table, null);
        signed_gen.AddCertificates(ca_cert_store);

        enveloped_content = new CmsProcessableByteArray(enveloped_bytes);
        signed_data = signed_gen.Generate(Org.BouncyCastle.Asn1.Cms.CmsObjectIdentifiers.EnvelopedData.Id, enveloped_content, true);
        return signed_data.GetEncoded();
    }
```

Rewrite `BuildSuccessCertRep` to build the degenerate cert PKCS#7 then delegate:

```csharp
    public byte[] BuildSuccessCertRep(Org.BouncyCastle.X509.X509Certificate issued_cert, X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce) {
        CmsSignedDataGenerator degenerate_gen;
        IStore<Org.BouncyCastle.X509.X509Certificate> issued_cert_store;
        byte[] degenerate_bytes;

        issued_cert_store = CollectionUtilities.CreateStore(new[] { issued_cert });
        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_gen.AddCertificates(issued_cert_store);
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();
        return EnvelopeAndSign(degenerate_bytes, recipient_cert, trans_id, recipient_nonce, "3", "0");
    }
```

Add the CRL generator + CRL rep + failure rep (used in Tasks 5/6):

```csharp
    public Org.BouncyCastle.X509.X509Crl GenerateCrl() {
        X509V2CrlGenerator crl_gen;

        crl_gen = new X509V2CrlGenerator();
        crl_gen.SetIssuerDN(Certificate.SubjectDN);
        crl_gen.SetThisUpdate(DateTime.UtcNow.AddMinutes(-5));
        crl_gen.SetNextUpdate(DateTime.UtcNow.AddDays(7));
        crl_gen.AddCrlEntry(BigInteger.ValueOf(99), DateTime.UtcNow.AddMinutes(-1), Org.BouncyCastle.Asn1.X509.CrlReason.KeyCompromise);
        return crl_gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", KeyPair.Private));
    }

    public byte[] BuildSuccessCrlRep(Org.BouncyCastle.X509.X509Crl crl, X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce) {
        CmsSignedDataGenerator degenerate_gen;
        byte[] degenerate_bytes;

        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_gen.AddCrl(crl);
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();
        return EnvelopeAndSign(degenerate_bytes, recipient_cert, trans_id, recipient_nonce, "3", "0");
    }

    public byte[] BuildFailureCertRep(X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce, string fail_info) {
        const string OidFailInfo = "2.16.840.1.113733.1.9.4";
        byte[] base_rep;

        // FAILURE rep carries no payload; reuse the signed wrapper over an empty degenerate PKCS#7 and add failInfo.
        // Simplest path: build a FAILURE-status signed message with an extra failInfo attribute.
        CmsSignedDataGenerator degenerate_gen;
        byte[] degenerate_bytes;
        Dictionary<DerObjectIdentifier, object> attrs;
        const string OidMessageType = "2.16.840.1.113733.1.9.2";
        const string OidPkiStatus = "2.16.840.1.113733.1.9.3";
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        const string OidRecipientNonce = "2.16.840.1.113733.1.9.6";
        IStore<Org.BouncyCastle.X509.X509Certificate> ca_cert_store;
        CmsSignedDataGenerator signed_gen;
        CmsSignedData signed_data;

        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();

        attrs = new Dictionary<DerObjectIdentifier, object>();
        attrs[new DerObjectIdentifier(OidMessageType)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidMessageType), new DerSet(new DerPrintableString("3")));
        attrs[new DerObjectIdentifier(OidPkiStatus)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidPkiStatus), new DerSet(new DerPrintableString("2")));
        attrs[new DerObjectIdentifier(OidFailInfo)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidFailInfo), new DerSet(new DerPrintableString(fail_info)));
        attrs[new DerObjectIdentifier(OidTransId)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidTransId), new DerSet(new DerPrintableString(trans_id)));
        attrs[new DerObjectIdentifier(OidRecipientNonce)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidRecipientNonce), new DerSet(new DerOctetString(recipient_nonce)));

        ca_cert_store = CollectionUtilities.CreateStore(new[] { Certificate });
        signed_gen = new CmsSignedDataGenerator(new SecureRandom());
        signed_gen.AddSigner(KeyPair.Private, Certificate, CmsSignedGenerator.DigestSha256, new Org.BouncyCastle.Asn1.Cms.AttributeTable(attrs), null);
        signed_gen.AddCertificates(ca_cert_store);
        signed_data = signed_gen.Generate(new CmsProcessableByteArray(degenerate_bytes), true);
        base_rep = signed_data.GetEncoded();
        return base_rep;
    }
```

(Add `using Org.BouncyCastle.Asn1.X509;` if not present — `CrlReason`. `X509V2CrlGenerator` is in `Org.BouncyCastle.X509`, already imported.)

- [ ] **Step 2: Write the failing test** — `tests/ScepTestClient.Tests/BcCrlDecodeTests.cs`

```csharp
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class BcCrlDecodeTests {
    [Fact]
    public void Decodes_crl_from_certrep() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey recipient_key;
        System.Security.Cryptography.X509Certificates.X509Certificate2 recipient_cert;
        byte[] rep;
        PkiMessage decoded;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out recipient_key, out _);
        recipient_cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
            ca.Issue(((BcKey)recipient_key).KeyPair.Public, "CN=requester").GetEncoded());

        rep = ca.BuildSuccessCrlRep(ca.GenerateCrl(), recipient_cert, "tx", new byte[16]);

        Assert.True(crypto.DecodePkiMessage(rep, recipient_key, CodecOptions.LenientParsing, out decoded, out error), error);
        Assert.Single(decoded.IssuedCrls);
        Org.BouncyCastle.X509.X509Crl parsed;
        parsed = new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(decoded.IssuedCrls[0]);
        Assert.NotNull(parsed);
    }
}
```

- [ ] **Step 3: Extend `BcPkiMessage.Decode` to extract CRLs** — in the `if (pki_status_present && result.PkiStatus == PkiStatus.Success)` block, after `result.IssuedCerts = issued_certs.AsReadOnly();`, add:

```csharp
            result.IssuedCrls = ExtractCrlsFromDegeneratePkcs7(decrypted_bytes);
```

And add the helper:

```csharp
    private static IReadOnlyList<byte[]> ExtractCrlsFromDegeneratePkcs7(byte[] der) {
        CmsSignedData signed_data;
        IStore<Org.BouncyCastle.X509.X509Crl> crl_store;
        List<byte[]> crls;

        crls = new List<byte[]>();
        signed_data = new CmsSignedData(der);
        crl_store = signed_data.GetCrls();
        foreach (Org.BouncyCastle.X509.X509Crl crl in crl_store.EnumerateMatches(null)) {
            crls.Add(crl.GetEncoded());
        }
        return crls;
    }
```

- [ ] **Step 4: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter "BcCrlDecodeTests|BcDecodeTests"` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "BC provider: decode CRL from CertRep; TestCa CRL/failure helpers"`

---

### Task 4: `ScepRequestBuilder` fluent API

**Goal:** A readable composer that builds a ready-to-encode `PkiMessage` for any operation (PKCSReq, RenewalReq, GetCert, GetCrl, CertPoll), generating the subject/transient key when given a `KeySpec`, and surfacing that key.

**Files:**
- Create: `src/ScepTestClient.Core/ScepRequestBuilder.cs`
- Test: `tests/ScepTestClient.Tests/ScepRequestBuilderTests.cs`

**Acceptance Criteria:**
- [ ] `For(crypto).CaCertificate(ca).Subject("CN=h").KeySpec("rsa:2048").Digest("SHA-256").Cipher("AES-128").Challenge("pw").Build(out msg, out key, out err)` yields a PKCSReq whose `InnerCsr.Subject == "CN=h"`, `DigestAlgorithmOid` == SHA-256 OID, `ContentEncryptionAlgorithmOid` == AES-128-CBC OID, `InnerCsr.ChallengePassword == "pw"`, `SignerKey == key` (self-signed enroll), and `key != null`.
- [ ] `MessageType(RenewalReq).SignerCertificate(existing).SignerKey(existingKey)` produces a message with `SignerCert`/`SignerKey` set and `MessageType == RenewalReq`.
- [ ] `MessageType(GetCert).IssuerAndSerial("CN=CA","0A")` produces a message with `IssuerName`/`SerialNumber` set, a transient `SignerKey`, and no `InnerCsr`.
- [ ] `Build` returns `false` + non-empty error when a PKCSReq has no subject, or when neither `KeySpec` nor `SubjectKey` was supplied.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter ScepRequestBuilderTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/ScepRequestBuilderTests.cs`

```csharp
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class ScepRequestBuilderTests {
    [Fact]
    public void Builds_pkcsreq_self_signed() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        PkiMessage msg;
        IScepKey key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();

        bool ok;
        ok = ScepRequestBuilder.For(crypto)
            .CaCertificate(ca.CertificateBcl)
            .Subject("CN=h")
            .KeySpec("rsa:2048")
            .Digest("SHA-256")
            .Cipher("AES-128")
            .Challenge("pw")
            .Build(out msg, out key, out error);

        Assert.True(ok, error);
        Assert.Equal(MessageType.PkcsReq, msg.MessageType);
        Assert.Equal("CN=h", msg.InnerCsr!.Subject);
        Assert.Equal(Algorithms.OidFor("SHA-256"), msg.DigestAlgorithmOid);
        Assert.Equal(Algorithms.OidFor("AES-128-CBC"), msg.ContentEncryptionAlgorithmOid);
        Assert.Equal("pw", msg.InnerCsr.ChallengePassword);
        Assert.NotNull(key);
        Assert.Same(key, msg.SignerKey);
    }

    [Fact]
    public void Builds_renewalreq_with_existing_signer() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey existing_key;
        X509Certificate2 existing_cert;
        PkiMessage msg;
        IScepKey new_key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out existing_key, out _);
        existing_cert = new X509Certificate2(ca.Issue(((BcKey)existing_key).KeyPair.Public, "CN=h").GetEncoded());

        Assert.True(ScepRequestBuilder.For(crypto)
            .CaCertificate(ca.CertificateBcl)
            .MessageType(MessageType.RenewalReq)
            .Subject("CN=h")
            .KeySpec("rsa:2048")
            .SignerCertificate(existing_cert)
            .SignerKey(existing_key)
            .Build(out msg, out new_key, out error), error);

        Assert.Equal(MessageType.RenewalReq, msg.MessageType);
        Assert.Same(existing_cert, msg.SignerCert);
        Assert.Same(existing_key, msg.SignerKey);
        Assert.NotSame(existing_key, new_key);
    }

    [Fact]
    public void Builds_getcert_with_issuer_and_serial() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        PkiMessage msg;
        IScepKey key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();

        Assert.True(ScepRequestBuilder.For(crypto)
            .CaCertificate(ca.CertificateBcl)
            .MessageType(MessageType.GetCert)
            .KeySpec("rsa:2048")
            .IssuerAndSerial("CN=CA", "0A")
            .Build(out msg, out key, out error), error);

        Assert.Equal("CN=CA", msg.IssuerName);
        Assert.Equal("0A", msg.SerialNumber);
        Assert.Null(msg.InnerCsr);
        Assert.NotNull(msg.SignerKey);
    }

    [Fact]
    public void Pkcsreq_without_subject_fails() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        PkiMessage msg;
        IScepKey key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();

        Assert.False(ScepRequestBuilder.For(crypto)
            .CaCertificate(ca.CertificateBcl)
            .KeySpec("rsa:2048")
            .Build(out msg, out key, out error));
        Assert.NotEqual(string.Empty, error);
    }
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement `ScepRequestBuilder`** — `src/ScepTestClient.Core/ScepRequestBuilder.cs`

```csharp
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

/// <summary>
/// Fluent composer for a SCEP <see cref="PkiMessage"/>. Generates the subject/transient key from a
/// KeySpec (or accepts one via SubjectKey for same-key renewal). Holds no crypto beyond the provider
/// it was given; produces an always-valid message or a clear error. See design spec §6.
/// </summary>
public sealed class ScepRequestBuilder {
    private readonly IScepCrypto _crypto;
    private readonly List<string> _dns_names;
    private readonly List<string> _upns;
    private readonly List<string> _ekus;
    private MessageType _message_type;
    private X509Certificate2? _ca_cert;
    private X509Certificate2? _signer_cert;
    private IScepKey? _signer_key;
    private IScepKey? _subject_key;
    private string? _key_spec_text;
    private string? _subject;
    private string? _sid;
    private string? _challenge;
    private string? _issuer_name;
    private string? _serial;
    private string? _poll_subject;
    private string _digest_oid;
    private string _cipher_oid;

    private ScepRequestBuilder(IScepCrypto crypto) {
        _crypto = crypto;
        _dns_names = new List<string>();
        _upns = new List<string>();
        _ekus = new List<string>();
        _message_type = MessageType.PkcsReq;
        _digest_oid = Algorithms.OidFor("SHA-256")!;
        _cipher_oid = Algorithms.OidFor("AES-128-CBC")!;
    }

    public static ScepRequestBuilder For(IScepCrypto crypto) => new ScepRequestBuilder(crypto);

    public ScepRequestBuilder CaCertificate(X509Certificate2 ca_cert) { _ca_cert = ca_cert; return this; }
    public ScepRequestBuilder MessageType(MessageType type) { _message_type = type; return this; }
    public ScepRequestBuilder Subject(string subject) { _subject = subject; return this; }
    public ScepRequestBuilder SanDns(string dns) { _dns_names.Add(dns); return this; }
    public ScepRequestBuilder Upn(string upn) { _upns.Add(upn); return this; }
    public ScepRequestBuilder Eku(string eku) { _ekus.Add(eku); return this; }
    public ScepRequestBuilder Sid(string sid) { _sid = sid; return this; }
    public ScepRequestBuilder Challenge(string challenge) { _challenge = challenge; return this; }
    public ScepRequestBuilder KeySpec(string key_spec_text) { _key_spec_text = key_spec_text; return this; }
    public ScepRequestBuilder SubjectKey(IScepKey key) { _subject_key = key; return this; }
    public ScepRequestBuilder SignerCertificate(X509Certificate2 cert) { _signer_cert = cert; return this; }
    public ScepRequestBuilder SignerKey(IScepKey key) { _signer_key = key; return this; }
    public ScepRequestBuilder IssuerAndSerial(string issuer_name, string serial_hex) { _issuer_name = issuer_name; _serial = serial_hex; return this; }
    public ScepRequestBuilder IssuerAndSubject(string issuer_name, string subject_name) { _issuer_name = issuer_name; _poll_subject = subject_name; return this; }

    public ScepRequestBuilder Digest(string name_or_oid) {
        _digest_oid = Algorithms.OidFor(name_or_oid) ?? name_or_oid;
        return this;
    }

    public ScepRequestBuilder Cipher(string name_or_oid) {
        string? resolved;
        resolved = Algorithms.OidFor(name_or_oid) ?? Algorithms.OidFor(name_or_oid + "-CBC");
        _cipher_oid = resolved ?? name_or_oid;
        return this;
    }

    public bool Build(out PkiMessage message, out IScepKey subject_key, out string error) {
        message = null!;
        subject_key = null!;
        error = string.Empty;

        if (_ca_cert is null) {
            error = "CaCertificate must be set";
            return false;
        }

        if (!ResolveSubjectKey(out subject_key, out error)) {
            return false;
        }

        switch (_message_type) {
            case MessageType.PkcsReq:
            case MessageType.RenewalReq:
                return BuildCsrMessage(subject_key, out message, out error);
            case MessageType.GetCert:
            case MessageType.GetCrl:
                return BuildIssuerSerialMessage(subject_key, out message, out error);
            case MessageType.CertPoll:
                return BuildPollMessage(subject_key, out message, out error);
            default:
                error = $"unsupported message type: {_message_type}";
                return false;
        }
    }

    private bool ResolveSubjectKey(out IScepKey subject_key, out string error) {
        KeySpec spec;
        string spec_error;
        string gen_error;

        subject_key = null!;
        error = string.Empty;

        if (_subject_key is not null) {
            subject_key = _subject_key;
            return true;
        }

        if (string.IsNullOrEmpty(_key_spec_text)) {
            error = "either KeySpec or SubjectKey must be supplied";
            return false;
        }

        if (!CryptoApi.KeySpec.Parse(_key_spec_text!, out spec, out spec_error)) {
            error = spec_error;
            return false;
        }

        if (!_crypto.GenerateKey(spec, out subject_key, out gen_error)) {
            error = gen_error;
            return false;
        }

        return true;
    }

    private bool BuildCsrMessage(IScepKey subject_key, out PkiMessage message, out string error) {
        Pkcs10 csr;

        message = null!;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(_subject)) {
            error = "Subject must be set for an enroll/renewal request";
            return false;
        }

        if (_message_type == MessageType.RenewalReq && (_signer_cert is null || _signer_key is null)) {
            error = "RenewalReq requires SignerCertificate and SignerKey";
            return false;
        }

        csr = new Pkcs10 { Key = subject_key, ChallengePassword = _challenge, Sid = _sid };
        csr.SetSubject(_subject!, out _);
        foreach (string dns in _dns_names) { csr.DnsNames.Add(dns); }
        foreach (string upn in _upns) { csr.Upns.Add(upn); }
        foreach (string eku in _ekus) { csr.Ekus.Add(eku); }

        message = new PkiMessage {
            MessageType = _message_type,
            InnerCsr = csr,
            RecipientCaCert = _ca_cert,
            DigestAlgorithmOid = _digest_oid,
            ContentEncryptionAlgorithmOid = _cipher_oid,
            SignerCert = _signer_cert,
            SignerKey = _signer_key ?? subject_key,
            TransactionId = Guid.NewGuid().ToString("N"),
        };
        return true;
    }

    private bool BuildIssuerSerialMessage(IScepKey subject_key, out PkiMessage message, out string error) {
        message = null!;
        error = string.Empty;

        if (string.IsNullOrEmpty(_issuer_name) || string.IsNullOrEmpty(_serial)) {
            error = $"{_message_type} requires IssuerAndSerial";
            return false;
        }

        message = new PkiMessage {
            MessageType = _message_type,
            RecipientCaCert = _ca_cert,
            DigestAlgorithmOid = _digest_oid,
            ContentEncryptionAlgorithmOid = _cipher_oid,
            SignerCert = _signer_cert,
            SignerKey = _signer_key ?? subject_key,
            IssuerName = _issuer_name,
            SerialNumber = _serial,
            TransactionId = Guid.NewGuid().ToString("N"),
        };
        return true;
    }

    private bool BuildPollMessage(IScepKey subject_key, out PkiMessage message, out string error) {
        message = null!;
        error = string.Empty;

        if (string.IsNullOrEmpty(_issuer_name) || string.IsNullOrEmpty(_poll_subject)) {
            error = "CertPoll requires IssuerAndSubject";
            return false;
        }

        message = new PkiMessage {
            MessageType = _message_type,
            RecipientCaCert = _ca_cert,
            DigestAlgorithmOid = _digest_oid,
            ContentEncryptionAlgorithmOid = _cipher_oid,
            SignerCert = _signer_cert,
            SignerKey = _signer_key ?? subject_key,
            IssuerName = _issuer_name,
            SubjectName = _poll_subject,
            TransactionId = Guid.NewGuid().ToString("N"),
        };
        return true;
    }
}
```

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `git commit -am "Core: ScepRequestBuilder fluent request composer"`

---

### Task 5: `ScepClient.Renew` — the 5 renewal variants (sync+async)

**Goal:** Unify the send/decode path into one `SendPkiOperation`, surface the subject key on `EnrollOutcome`, and add `Renew(RenewRequest)` covering all five variants. Route the fake server's POST by message type and enforce signer-cert validity so the expired variant is rejected.

**Files:**
- Create: `src/ScepTestClient.Core/RenewalVariant.cs`, `src/ScepTestClient.Core/RenewRequest.cs`
- Modify: `src/ScepTestClient.Core/EnrollOutcome.cs`
- Modify: `src/ScepTestClient.Core/ScepClient.cs`
- Modify: `tests/ScepTestClient.Tests/Fakes/TestCa.cs`, `tests/ScepTestClient.Tests/Fakes/FakeScepServer.cs`
- Test: `tests/ScepTestClient.Tests/RenewalTests.cs`

**Acceptance Criteria:**
- [ ] `Renew`/`RenewAsync` each return a new certificate for variants `Proper`, `ReenrollSameSubject`, `RenewalShapedPkcsReq`, and `SameKey`.
- [ ] The `Expired` variant returns `ScepClientResult.ServerFailure` with `FailInfo == BadRequest` (server rejects an expired signer cert).
- [ ] `SameKey` reuses the existing key (the new cert's public key matches the existing key); the other renewal variants use a fresh key.
- [ ] Existing enroll end-to-end tests (`EndToEndTests`) still pass after the `SendPkiOperation` refactor.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter "RenewalTests|EndToEndTests"` → pass.

**Steps:**

- [ ] **Step 1: Add `RenewalVariant.cs`**

```csharp
namespace ScepTestClient.Core;

public enum RenewalVariant {
    Proper,                 // RenewalReq(17), signed by existing cert+key, new subject key
    ReenrollSameSubject,    // PKCSReq(19), self-signed new key + challenge, same Subject DN
    RenewalShapedPkcsReq,   // PKCSReq(19), signed by existing cert+key, new subject key
    SameKey,                // RenewalReq(17), signed by existing cert+key, reuses existing key
    Expired,                // RenewalReq(17), signed by an expired existing cert
}
```

- [ ] **Step 2: Add `RenewRequest.cs`**

```csharp
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

public sealed class RenewRequest {
    public required string Subject { get; init; }
    public required X509Certificate2 ExistingCertificate { get; init; }
    public required IScepKey ExistingKey { get; init; }
    public RenewalVariant Variant { get; init; } = RenewalVariant.Proper;
    public string? ChallengePassword { get; init; }
    public string KeySpecText { get; init; } = "rsa:2048";
    public string DigestOid { get; init; } = Algorithms.OidFor("SHA-256")!;
    public string ContentEncryptionOid { get; init; } = Algorithms.OidFor("AES-128-CBC")!;
    public List<string> DnsNames { get; } = new();
    public List<string> Upns { get; } = new();
    public List<string> Ekus { get; } = new();
    public string? Sid { get; init; }
    public X509Certificate2? CaCertificate { get; set; }
}
```

- [ ] **Step 3: Add `SubjectKey` to `EnrollOutcome.cs`** — add the property:

```csharp
    public IScepKey? SubjectKey { get; init; }
```

- [ ] **Step 4: Refactor `ScepClient` to a unified send path, then add `Renew`.** First replace the private `SendEnrollSync`/`SendEnrollAsync`/`DecodeEnrollResponse` trio so they accept an explicit subject key (recipient = `message.SignerKey`). Rename to `SendPkiOperationSync`/`SendPkiOperationAsync`/`DecodeResponse`, and update `Enroll`/`EnrollAsync` to call them with `request.Key`. The new bodies:

```csharp
    private ScepResult<EnrollOutcome> SendPkiOperationSync(PkiMessage pki_message, IScepKey subject_key) {
        byte[] der;
        string encode_error;
        ScepResult<byte[]> raw;
        Stopwatch sw;
        string trans_id;

        trans_id = pki_message.TransactionId!;

        if (!pki_message.Encode(Crypto, out der, out encode_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.CryptoError, encode_error);
        }

        sw = Stopwatch.StartNew();
        if (Server.PreferPost) {
            raw = _transport.Post("PKIOperation", der);
        } else {
            raw = _transport.Get("PKIOperation", Convert.ToBase64String(der));
        }
        sw.Stop();

        if (!raw.IsOk) {
            return ScepResult<EnrollOutcome>.Fail(raw.Status, raw.Error);
        }

        return DecodeResponse(raw.Value, pki_message.SignerKey!, subject_key, trans_id, sw.Elapsed);
    }

    private async Task<ScepResult<EnrollOutcome>> SendPkiOperationAsync(PkiMessage pki_message, IScepKey subject_key) {
        byte[] der;
        string encode_error;
        ScepResult<byte[]> raw;
        Stopwatch sw;
        string trans_id;

        trans_id = pki_message.TransactionId!;

        if (!pki_message.Encode(Crypto, out der, out encode_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.CryptoError, encode_error);
        }

        sw = Stopwatch.StartNew();
        if (Server.PreferPost) {
            raw = await _transport.PostAsync("PKIOperation", der).ConfigureAwait(false);
        } else {
            raw = await _transport.GetAsync("PKIOperation", Convert.ToBase64String(der)).ConfigureAwait(false);
        }
        sw.Stop();

        if (!raw.IsOk) {
            return ScepResult<EnrollOutcome>.Fail(raw.Status, raw.Error);
        }

        return DecodeResponse(raw.Value, pki_message.SignerKey!, subject_key, trans_id, sw.Elapsed);
    }

    private ScepResult<EnrollOutcome> DecodeResponse(byte[] response_bytes, IScepKey recipient_key, IScepKey subject_key, string trans_id, TimeSpan elapsed) {
        PkiMessage decoded;
        string decode_error;
        ScepClientResult mapped_status;
        X509Certificate2? cert;
        EnrollOutcome outcome;

        if (!PkiMessage.Decode(Crypto, response_bytes, recipient_key, CodecOptions.LenientParsing, out decoded, out decode_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.CryptoError, decode_error);
        }

        foreach (ConformanceNote note in decoded.ConformanceNotes) {
            Emit(TraceLevel.Opinion, "PkiOperation", $"conformance: [{note.Severity}] {note.What} ({note.Where}) {note.RfcReference}");
        }

        switch (decoded.PkiStatus) {
            case PkiStatus.Success:
                mapped_status = ScepClientResult.Ok;
                break;
            case PkiStatus.Pending:
                mapped_status = ScepClientResult.Pending;
                break;
            default:
                mapped_status = ScepClientResult.ServerFailure;
                break;
        }

        cert = decoded.IssuedCerts.Count > 0 ? decoded.IssuedCerts[0] : null;

        outcome = new EnrollOutcome {
            Status = mapped_status,
            PkiStatus = decoded.PkiStatus,
            FailInfo = decoded.FailInfo,
            Certificate = cert,
            SubjectKey = subject_key,
            TransactionId = trans_id,
            Elapsed = elapsed,
        };

        if (mapped_status == ScepClientResult.Ok) {
            return ScepResult<EnrollOutcome>.Ok(outcome);
        }

        return ScepResult<EnrollOutcome>.Fail(mapped_status, $"PKI status: {decoded.PkiStatus}");
    }
```

Update `Enroll` to set `request.Key` as subject key. Replace the `return SendEnrollSync(request, pki_message);` line with `return SendPkiOperationSync(pki_message, request.Key);` and the async equivalent with `return await SendPkiOperationAsync(pki_message, request.Key).ConfigureAwait(false);`. (The `BuildPkiMessage` helper already sets `SignerKey = request.Key`.)

- [ ] **Step 5: Add the `Renew` methods to `ScepClient`** (place after `EnrollAsync`):

```csharp
    public ScepResult<EnrollOutcome> Renew(RenewRequest request) {
        PkiMessage pki_message;
        IScepKey subject_key;
        string build_error;

        Emit(TraceLevel.Info, "Renew", $"renewing '{request.Subject}' via {request.Variant}");
        if (!BuildRenewMessage(request, out pki_message, out subject_key, out build_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, build_error);
        }
        return SendPkiOperationSync(pki_message, subject_key);
    }

    public async Task<ScepResult<EnrollOutcome>> RenewAsync(RenewRequest request) {
        PkiMessage pki_message;
        IScepKey subject_key;
        string build_error;

        Emit(TraceLevel.Info, "Renew", $"renewing '{request.Subject}' via {request.Variant}");
        if (!BuildRenewMessage(request, out pki_message, out subject_key, out build_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, build_error);
        }
        return await SendPkiOperationAsync(pki_message, subject_key).ConfigureAwait(false);
    }

    private bool BuildRenewMessage(RenewRequest request, out PkiMessage pki_message, out IScepKey subject_key, out string error) {
        ScepRequestBuilder builder;
        bool reenroll;

        pki_message = null!;
        subject_key = null!;
        error = string.Empty;

        if (request.CaCertificate is null) {
            error = "RenewRequest.CaCertificate must be set";
            return false;
        }

        reenroll = request.Variant == RenewalVariant.ReenrollSameSubject;

        builder = ScepRequestBuilder.For(Crypto)
            .CaCertificate(request.CaCertificate)
            .MessageType(reenroll || request.Variant == RenewalVariant.RenewalShapedPkcsReq ? MessageType.PkcsReq : MessageType.RenewalReq)
            .Subject(request.Subject)
            .Digest(request.DigestOid)
            .Cipher(request.ContentEncryptionOid);

        foreach (string dns in request.DnsNames) { builder.SanDns(dns); }
        foreach (string upn in request.Upns) { builder.Upn(upn); }
        foreach (string eku in request.Ekus) { builder.Eku(eku); }
        if (request.Sid is not null) { builder.Sid(request.Sid); }
        if (request.ChallengePassword is not null) { builder.Challenge(request.ChallengePassword); }

        // Variant 4 (SameKey) reuses the existing key for the inner CSR; the rest generate a fresh one.
        if (request.Variant == RenewalVariant.SameKey) {
            builder.SubjectKey(request.ExistingKey);
        } else {
            builder.KeySpec(request.KeySpecText);
        }

        // The naive re-enroll signs with a self-signed cert over a new key; all other variants
        // sign with the existing cert + key.
        if (!reenroll) {
            builder.SignerCertificate(request.ExistingCertificate).SignerKey(request.ExistingKey);
        }

        return builder.Build(out pki_message, out subject_key, out error);
    }
```

- [ ] **Step 6: Make the fake CA enforce signer validity + map issued certs by serial.** In `TestCa.cs`, add a field and record issued certs, and add an expired-issuer helper:

```csharp
    private readonly Dictionary<string, Org.BouncyCastle.X509.X509Certificate> _issued_by_serial = new Dictionary<string, Org.BouncyCastle.X509.X509Certificate>();
```

In `Issue(...)`, before `return`, capture the result so GetCert can find it later:

```csharp
        Org.BouncyCastle.X509.X509Certificate issued;
        issued = cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", KeyPair.Private));
        _issued_by_serial[issued.SerialNumber.ToString(16).ToUpperInvariant()] = issued;
        return issued;
```

Add an expired-cert issuer:

```csharp
    public Org.BouncyCastle.X509.X509Certificate IssueExpired(AsymmetricKeyParameter subject_public_key, string subject_dn) {
        X509V3CertificateGenerator cg;

        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks & 0x7fffffff));
        cg.SetIssuerDN(Certificate.SubjectDN);
        cg.SetSubjectDN(new X509Name(subject_dn));
        cg.SetNotBefore(DateTime.UtcNow.AddYears(-2));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(-1));
        cg.SetPublicKey(subject_public_key);
        return cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", KeyPair.Private));
    }
```

In `HandlePkiOperation`, after obtaining `signer_cert` (a `X509Certificate2`), reject an expired signer with a FAILURE rep. Add right before `issued = Issue(...)`:

```csharp
        if (signer_cert.NotAfter < DateTime.UtcNow) {
            // mirror a real CA refusing to renew off an expired cert
            byte[] failure;
            string tx_for_fail;
            byte[] nonce_for_fail;

            tx_for_fail = "tx";
            nonce_for_fail = new byte[16];
            signed_attrs = signer.SignedAttributes;
            if (signed_attrs is not null) {
                Org.BouncyCastle.Asn1.Cms.Attribute? tx_a = signed_attrs[new DerObjectIdentifier(OidTransId)];
                Org.BouncyCastle.Asn1.Cms.Attribute? n_a = signed_attrs[new DerObjectIdentifier(OidSenderNonce)];
                if (tx_a is not null) { tx_for_fail = ((DerPrintableString)tx_a.AttrValues[0]).GetString(); }
                if (n_a is not null) { nonce_for_fail = ((Asn1OctetString)n_a.AttrValues[0]).GetOctets(); }
            }
            failure = BuildFailureCertRep(signer_cert, tx_for_fail, nonce_for_fail, "2");
            return failure;
        }
```

(`OidTransId`/`OidSenderNonce` consts already exist in `HandlePkiOperation`; `signed_attrs` is declared there.)

- [ ] **Step 7: Route the fake server POST by message type.** In `FakeScepServer.cs`, replace the POST body with dispatch (add `PeekMessageType` to `TestCa` — see Tasks 6/7 add the other handlers; for Task 5 only PKIOperation/renewal is needed but add the switch now):

```csharp
        app.MapPost("/scep", async (HttpContext ctx) => {
            MemoryStream ms;
            byte[] request_der;
            byte[] response;
            string message_type;

            ms = new MemoryStream();
            await ctx.Request.Body.CopyToAsync(ms);
            request_der = ms.ToArray();
            message_type = ca.PeekMessageType(request_der);

            if (message_type == "21") { response = ca.HandleGetCert(request_der); }
            else if (message_type == "22") { response = ca.HandleGetCrl(request_der); }
            else if (message_type == "20") { response = ca.HandlePoll(request_der); }
            else { response = ca.HandlePkiOperation(request_der); }

            ctx.Response.ContentType = "application/x-pki-message";
            await ctx.Response.Body.WriteAsync(response);
        });
```

Add `PeekMessageType` to `TestCa` (Tasks 6/7 supply `HandleGetCert`/`HandleGetCrl`/`HandlePoll`; to keep the file compiling between tasks, add stub bodies that `throw new NotSupportedException()` now and fill them in Tasks 6/7):

```csharp
    public string PeekMessageType(byte[] der) {
        const string OidMessageType = "2.16.840.1.113733.1.9.2";
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.Asn1.Cms.Attribute? attr;

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        attr = signer.SignedAttributes?[new DerObjectIdentifier(OidMessageType)];
        return attr is null ? string.Empty : ((DerPrintableString)attr.AttrValues[0]).GetString();
    }

    public byte[] HandleGetCert(byte[] der) => throw new System.NotSupportedException("filled in Task 6");
    public byte[] HandleGetCrl(byte[] der) => throw new System.NotSupportedException("filled in Task 6");
    public byte[] HandlePoll(byte[] der) => throw new System.NotSupportedException("filled in Task 7");
```

> The three `NotSupportedException` stubs are scaffolding completed by Tasks 6–7 in this same plan; only PKIOperation/renewal is exercised by Task 5's tests.

- [ ] **Step 8: Write the renewal test** — `tests/ScepTestClient.Tests/RenewalTests.cs`

```csharp
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class RenewalTests {
    private static ScepClient MakeClient(FakeScepServer server, BouncyCastleScepCrypto crypto) {
        ScepClient client;
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
        return client;
    }

    [Theory]
    [InlineData(RenewalVariant.Proper)]
    [InlineData(RenewalVariant.ReenrollSameSubject)]
    [InlineData(RenewalVariant.RenewalShapedPkcsReq)]
    [InlineData(RenewalVariant.SameKey)]
    public async Task Renews_and_returns_a_certificate(RenewalVariant variant) {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey existing_key;
        X509Certificate2 existing_cert;
        ScepClient client;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out existing_key, out _);
        existing_cert = new X509Certificate2(server.Ca.Issue(((BcKey)existing_key).KeyPair.Public, "CN=poodle").GetEncoded());

        client = MakeClient(server, crypto);
        request = new RenewRequest {
            Subject = "CN=poodle",
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = variant,
            ChallengePassword = "pw",
            CaCertificate = server.Ca.CertificateBcl,
        };

        result = await client.RenewAsync(request);
        Assert.True(result.IsOk, result.Error);
        Assert.NotNull(result.Value.Certificate);
        Assert.Contains("poodle", result.Value.Certificate!.Subject);
    }

    [Fact]
    public void Expired_variant_is_rejected_sync() {
        Task.Run(async () => {
            await using FakeScepServer server = await FakeScepServer.StartAsync();
            BouncyCastleScepCrypto crypto;
            KeySpec spec;
            IScepKey existing_key;
            X509Certificate2 expired_cert;
            ScepClient client;
            RenewRequest request;
            ScepResult<EnrollOutcome> result;

            crypto = new BouncyCastleScepCrypto();
            KeySpec.Parse("rsa:2048", out spec, out _);
            crypto.GenerateKey(spec, out existing_key, out _);
            expired_cert = new X509Certificate2(server.Ca.IssueExpired(((BcKey)existing_key).KeyPair.Public, "CN=poodle").GetEncoded());

            client = MakeClient(server, crypto);
            request = new RenewRequest {
                Subject = "CN=poodle",
                ExistingCertificate = expired_cert,
                ExistingKey = existing_key,
                Variant = RenewalVariant.Expired,
                CaCertificate = server.Ca.CertificateBcl,
            };

            result = client.Renew(request);
            Assert.Equal(ScepClientResult.ServerFailure, result.Status);
            Assert.Equal(FailInfo.BadRequest, result.Value.FailInfo);
        }).GetAwaiter().GetResult();
    }
}
```

> Note on the sync test: `.GetAwaiter().GetResult()` here only awaits the in-memory test harness (server startup), not a SCEP network call — `client.Renew(request)` itself runs the genuine sync `HttpClient.Send` path. This is the allowed exception per the house rule.

- [ ] **Step 9: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter "RenewalTests|EndToEndTests"` → PASS.

- [ ] **Step 10: Commit** — `git commit -am "Core: Renew with 5 variants over unified SendPkiOperation; fake-server routing"`

---

### Task 6: `ScepClient.GetCert` (21) & `GetCrl` (22) (sync+async)

**Goal:** Retrieve an existing certificate by issuer+serial and fetch a CRL, end-to-end, with the fake CA handling both.

**Files:**
- Modify: `src/ScepTestClient.Core/ScepClient.cs`
- Modify: `tests/ScepTestClient.Tests/Fakes/TestCa.cs`
- Test: `tests/ScepTestClient.Tests/GetCertCrlTests.cs`

**Acceptance Criteria:**
- [ ] After an enroll, `GetCert(issuerDn, serialHex)` returns the same certificate (matching serial).
- [ ] `GetCrl(issuerDn, serialHex)` returns non-empty CRL DER that parses as an `X509Crl`.
- [ ] `GetCert` for an unknown serial returns `ScepClientResult.ServerFailure` (`badCertId`), not a throw.
- [ ] Both ship in sync and async form.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter GetCertCrlTests` → pass.

**Steps:**

- [ ] **Step 1: Implement the fake handlers in `TestCa.cs`** — replace the Task-5 stubs:

```csharp
    public byte[] HandleGetCert(byte[] der) {
        IssuerAndSerialNumber ias;
        X509Certificate2 requester_cert;
        string serial_key;
        string trans_id;
        byte[] nonce;

        DecodeRequest(der, out requester_cert, out trans_id, out nonce, out byte[] inner);
        ias = IssuerAndSerialNumber.GetInstance(Asn1Object.FromByteArray(inner));
        serial_key = ias.SerialNumber.Value.ToString(16).ToUpperInvariant();

        if (!_issued_by_serial.TryGetValue(serial_key, out Org.BouncyCastle.X509.X509Certificate? found)) {
            return BuildFailureCertRep(requester_cert, trans_id, nonce, "4");
        }
        return BuildSuccessCertRep(found, requester_cert, trans_id, nonce);
    }

    public byte[] HandleGetCrl(byte[] der) {
        X509Certificate2 requester_cert;
        string trans_id;
        byte[] nonce;

        DecodeRequest(der, out requester_cert, out trans_id, out nonce, out byte[] inner);
        return BuildSuccessCrlRep(GenerateCrl(), requester_cert, trans_id, nonce);
    }
```

Add the shared request decoder (used by GetCert/GetCrl/Poll) — it returns the requester's signer cert (the response recipient), echoes transId/senderNonce, and hands back the decrypted inner payload:

```csharp
    private void DecodeRequest(byte[] der, out X509Certificate2 requester_cert, out string trans_id, out byte[] sender_nonce, out byte[] inner_payload) {
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        const string OidSenderNonce = "2.16.840.1.113733.1.9.5";
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.X509.X509Certificate signer_bc_cert;
        MemoryStream env_stream;
        CmsEnvelopedData env;
        Org.BouncyCastle.Asn1.Cms.AttributeTable attrs;

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        signer_bc_cert = signed.GetCertificates().EnumerateMatches(signer.SignerID).Cast<Org.BouncyCastle.X509.X509Certificate>().First();
        requester_cert = new X509Certificate2(signer_bc_cert.GetEncoded());

        env_stream = new MemoryStream();
        signed.SignedContent.Write(env_stream);
        env = new CmsEnvelopedData(env_stream.ToArray());
        inner_payload = env.GetRecipientInfos().GetRecipients().Cast<RecipientInformation>().First().GetContent(KeyPair.Private);

        trans_id = "tx";
        sender_nonce = new byte[16];
        attrs = signer.SignedAttributes;
        if (attrs is not null) {
            Org.BouncyCastle.Asn1.Cms.Attribute? tx_a = attrs[new DerObjectIdentifier(OidTransId)];
            Org.BouncyCastle.Asn1.Cms.Attribute? n_a = attrs[new DerObjectIdentifier(OidSenderNonce)];
            if (tx_a is not null) { trans_id = ((DerPrintableString)tx_a.AttrValues[0]).GetString(); }
            if (n_a is not null) { sender_nonce = ((Asn1OctetString)n_a.AttrValues[0]).GetOctets(); }
        }
    }
```

(`IssuerAndSerialNumber` is in `Org.BouncyCastle.Asn1.Cms`, already imported.)

- [ ] **Step 2: Write the failing test** — `tests/ScepTestClient.Tests/GetCertCrlTests.cs`

```csharp
using System.IO;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class GetCertCrlTests {
    [Fact]
    public async Task GetCert_returns_previously_issued_cert() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        ScepClient client;
        string root;
        ScepResult<EnrollOutcome> enroll;
        string serial_hex;
        string issuer_dn;
        ScepResult<System.Security.Cryptography.X509Certificates.X509Certificate2> got;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);

        root = Directory.CreateTempSubdirectory().FullName;
        enroll = await client.GetNewCertificateAsync(
            new EnrollRequest { Subject = "CN=poodle", Key = key, ChallengePassword = "pw", CaCertificate = server.Ca.CertificateBcl },
            new CertStore(root), new UseRecordLog(root));
        Assert.True(enroll.IsOk, enroll.Error);

        serial_hex = enroll.Value.Certificate!.SerialNumber;
        issuer_dn = server.Ca.Certificate.SubjectDN.ToString();

        got = await client.GetCertAsync(issuer_dn, serial_hex);
        Assert.True(got.IsOk, got.Error);
        Assert.Equal(serial_hex, got.Value.SerialNumber);
    }

    [Fact]
    public async Task GetCrl_returns_a_crl() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        ScepClient client;
        ScepResult<byte[]> crl;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);

        crl = await client.GetCrlAsync(server.Ca.Certificate.SubjectDN.ToString(), "01");
        Assert.True(crl.IsOk, crl.Error);
        Assert.NotEmpty(crl.Value);
        Assert.NotNull(new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(crl.Value));
    }
}
```

- [ ] **Step 3: Implement `GetCert`/`GetCrl` on `ScepClient`** (place after the `Renew` methods). Both build via the builder with a transient signer key (which is also the response recipient), send, and project the decoded result:

```csharp
    public ScepResult<X509Certificate2> GetCert(string issuer_dn, string serial_hex) {
        return ProjectCert(RunIssuerSerial(MessageType.GetCert, issuer_dn, serial_hex, sync: true).GetAwaiter().GetResult());
    }

    public async Task<ScepResult<X509Certificate2>> GetCertAsync(string issuer_dn, string serial_hex) {
        return ProjectCert(await RunIssuerSerial(MessageType.GetCert, issuer_dn, serial_hex, sync: false).ConfigureAwait(false));
    }

    public ScepResult<byte[]> GetCrl(string issuer_dn, string serial_hex) {
        return ProjectCrl(RunIssuerSerial(MessageType.GetCrl, issuer_dn, serial_hex, sync: true).GetAwaiter().GetResult());
    }

    public async Task<ScepResult<byte[]>> GetCrlAsync(string issuer_dn, string serial_hex) {
        return ProjectCrl(await RunIssuerSerial(MessageType.GetCrl, issuer_dn, serial_hex, sync: false).ConfigureAwait(false));
    }
```

> **Implementer note — keep sync genuinely sync.** The four wrappers above must NOT funnel the sync path through `RunIssuerSerial(...).GetAwaiter().GetResult()` on a network call. Implement `RunIssuerSerial` as a builder step (no I/O) that returns the built message + recipient key, then call `SendPkiOperationSync` (sync) or `SendPkiOperationAsync` (async) explicitly. Concretely:

```csharp
    private (ScepResult<EnrollOutcome> Result, PkiMessage? Decoded) BuildIssuerSerial(MessageType type, string issuer_dn, string serial_hex, out PkiMessage message, out IScepKey signer_key) {
        string error;

        message = null!;
        signer_key = null!;
        if (!ScepRequestBuilder.For(Crypto)
                .CaCertificate(RequireCaCert())
                .MessageType(type)
                .KeySpec("rsa:2048")
                .IssuerAndSerial(issuer_dn, serial_hex)
                .Build(out message, out signer_key, out error)) {
            return (ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error), null);
        }
        return (ScepResult<EnrollOutcome>.Ok(null!), message);
    }
```

Because GetCert/GetCrl need the decoded `PkiMessage` (the cert AND the CRL list), do not reuse `SendPkiOperation` (which returns only `EnrollOutcome`). Instead add a small decoded-returning sender pair and project from the decoded message. Final shape:

```csharp
    private ScepResult<X509Certificate2> GetCert(string issuer_dn, string serial_hex) { /* see below */ }
```

Replace the four public wrappers + `RunIssuerSerial` with this concrete, non-sync-over-async implementation:

```csharp
    public ScepResult<X509Certificate2> GetCert(string issuer_dn, string serial_hex) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCert, issuer_dn, serial_hex, out message, out signer_key, out error)) {
            return ScepResult<X509Certificate2>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCert(SendDecodedSync(message));
    }

    public async Task<ScepResult<X509Certificate2>> GetCertAsync(string issuer_dn, string serial_hex) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCert, issuer_dn, serial_hex, out message, out signer_key, out error)) {
            return ScepResult<X509Certificate2>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCert(await SendDecodedAsync(message).ConfigureAwait(false));
    }

    public ScepResult<byte[]> GetCrl(string issuer_dn, string serial_hex) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCrl, issuer_dn, serial_hex, out message, out signer_key, out error)) {
            return ScepResult<byte[]>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCrl(SendDecodedSync(message));
    }

    public async Task<ScepResult<byte[]>> GetCrlAsync(string issuer_dn, string serial_hex) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCrl, issuer_dn, serial_hex, out message, out signer_key, out error)) {
            return ScepResult<byte[]>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCrl(await SendDecodedAsync(message).ConfigureAwait(false));
    }

    private bool BuildIssuerSerialMessage(MessageType type, string issuer_dn, string serial_hex, out PkiMessage message, out IScepKey signer_key, out string error) {
        X509Certificate2? ca_cert;

        message = null!;
        signer_key = null!;
        error = string.Empty;

        ca_cert = RenewalCertificate is not null ? null : null;  // placeholder; CA cert resolved below
        if (!ResolveCaCert(out X509Certificate2 resolved_ca, out error)) {
            return false;
        }

        return ScepRequestBuilder.For(Crypto)
            .CaCertificate(resolved_ca)
            .MessageType(type)
            .KeySpec("rsa:2048")
            .IssuerAndSerial(issuer_dn, serial_hex)
            .Build(out message, out signer_key, out error);
    }

    // Sends a built message and returns the FULLY DECODED PkiMessage (cert + CRL list), not just an outcome.
    private ScepResult<PkiMessage> SendDecodedSync(PkiMessage message) {
        byte[] der;
        string encode_error;
        ScepResult<byte[]> raw;
        PkiMessage decoded;
        string decode_error;

        if (!message.Encode(Crypto, out der, out encode_error)) {
            return ScepResult<PkiMessage>.Fail(ScepClientResult.CryptoError, encode_error);
        }
        raw = Server.PreferPost ? _transport.Post("PKIOperation", der) : _transport.Get("PKIOperation", Convert.ToBase64String(der));
        if (!raw.IsOk) {
            return ScepResult<PkiMessage>.Fail(raw.Status, raw.Error);
        }
        if (!PkiMessage.Decode(Crypto, raw.Value, message.SignerKey!, CodecOptions.LenientParsing, out decoded, out decode_error)) {
            return ScepResult<PkiMessage>.Fail(ScepClientResult.CryptoError, decode_error);
        }
        return ScepResult<PkiMessage>.Ok(decoded);
    }

    private async Task<ScepResult<PkiMessage>> SendDecodedAsync(PkiMessage message) {
        byte[] der;
        string encode_error;
        ScepResult<byte[]> raw;
        PkiMessage decoded;
        string decode_error;

        if (!message.Encode(Crypto, out der, out encode_error)) {
            return ScepResult<PkiMessage>.Fail(ScepClientResult.CryptoError, encode_error);
        }
        raw = Server.PreferPost
            ? await _transport.PostAsync("PKIOperation", der).ConfigureAwait(false)
            : await _transport.GetAsync("PKIOperation", Convert.ToBase64String(der)).ConfigureAwait(false);
        if (!raw.IsOk) {
            return ScepResult<PkiMessage>.Fail(raw.Status, raw.Error);
        }
        if (!PkiMessage.Decode(Crypto, raw.Value, message.SignerKey!, CodecOptions.LenientParsing, out decoded, out decode_error)) {
            return ScepResult<PkiMessage>.Fail(ScepClientResult.CryptoError, decode_error);
        }
        return ScepResult<PkiMessage>.Ok(decoded);
    }

    private static ScepResult<X509Certificate2> ProjectCert(ScepResult<PkiMessage> sent) {
        if (!sent.IsOk) {
            return ScepResult<X509Certificate2>.Fail(sent.Status, sent.Error);
        }
        if (sent.Value.PkiStatus != PkiStatus.Success || sent.Value.IssuedCerts.Count == 0) {
            return ScepResult<X509Certificate2>.Fail(ScepClientResult.ServerFailure, $"no certificate (pkiStatus {sent.Value.PkiStatus}, failInfo {sent.Value.FailInfo})");
        }
        return ScepResult<X509Certificate2>.Ok(sent.Value.IssuedCerts[0]);
    }

    private static ScepResult<byte[]> ProjectCrl(ScepResult<PkiMessage> sent) {
        if (!sent.IsOk) {
            return ScepResult<byte[]>.Fail(sent.Status, sent.Error);
        }
        if (sent.Value.IssuedCrls.Count == 0) {
            return ScepResult<byte[]>.Fail(ScepClientResult.ServerFailure, $"no CRL (pkiStatus {sent.Value.PkiStatus}, failInfo {sent.Value.FailInfo})");
        }
        return ScepResult<byte[]>.Ok(sent.Value.IssuedCrls[0]);
    }
```

Add the CA-cert resolver used above (auto-fetches `GetCACert` when no renewal context cert is set, caching it on the client). Add a private field `private X509Certificate2? _ca_cert_cache;` and:

```csharp
    private bool ResolveCaCert(out X509Certificate2 ca_cert, out string error) {
        ScepResult<IReadOnlyList<X509Certificate2>> ca_result;

        ca_cert = null!;
        error = string.Empty;

        if (_ca_cert_cache is not null) { ca_cert = _ca_cert_cache; return true; }

        ca_result = GetCaCert();
        if (!ca_result.IsOk || ca_result.Value.Count == 0) {
            error = ca_result.IsOk ? "server returned no CA certificate" : ca_result.Error;
            return false;
        }
        _ca_cert_cache = ca_result.Value[0];
        ca_cert = _ca_cert_cache;
        return true;
    }
```

> Implementer: delete the dead `ca_cert`/placeholder line inside `BuildIssuerSerialMessage` — it is shown only to make the CA-resolution seam explicit; the real body is the `ResolveCaCert` call + the builder.

- [ ] **Step 4: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter GetCertCrlTests` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "Core: GetCert/GetCrl (sync+async) with fake-CA handlers"`

---

### Task 7: Standalone `ScepClient.Poll` — CertPoll (20) (sync+async)

**Goal:** Encode CertPoll (`IssuerAndSubject` payload), add `Poll`/`PollAsync`, and let the fake CA satisfy a poll by issuing for the polled subject.

**Files:**
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BcPkiMessage.cs`, `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs`
- Modify: `src/ScepTestClient.Core/ScepClient.cs`
- Modify: `tests/ScepTestClient.Tests/Fakes/TestCa.cs`
- Test: `tests/ScepTestClient.Tests/PollTests.cs`

**Acceptance Criteria:**
- [ ] A `CertPoll` message encodes with `messageType == "20"` and an enveloped `IssuerAndSubject` SEQUENCE.
- [ ] `Poll(issuerDn, subjectDn, transId)` / `PollAsync(...)` return a certificate for the polled subject end-to-end.
- [ ] The transaction id supplied to `Poll` is the one stamped on the request.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter PollTests` → pass.

**Steps:**

- [ ] **Step 1: Add the `IssuerAndSubject` payload builder to `BcPkiMessage.cs`**

```csharp
    public static byte[] BuildIssuerAndSubject(string issuer_dn, string subject_dn) {
        Org.BouncyCastle.Asn1.X509.X509Name issuer;
        Org.BouncyCastle.Asn1.X509.X509Name subject;
        DerSequence seq;

        issuer = new Org.BouncyCastle.Asn1.X509.X509Name(issuer_dn);
        subject = new Org.BouncyCastle.Asn1.X509.X509Name(subject_dn);
        seq = new DerSequence(issuer, subject);
        return seq.GetDerEncoded();
    }
```

- [ ] **Step 2: Add the CertPoll case to `BouncyCastleScepCrypto.EncodePkiMessage`** — inside the `switch`, before `default`:

```csharp
                case MessageType.CertPoll:
                    if (string.IsNullOrEmpty(message.IssuerName) || string.IsNullOrEmpty(message.SubjectName)) {
                        error = "IssuerName and SubjectName must be set for CertPoll";
                        return false;
                    }
                    der = BcPkiMessage.EncodePkiOperation(
                        message,
                        BcPkiMessage.BuildIssuerAndSubject(message.IssuerName!, message.SubjectName!),
                        signer_key,
                        ScepAttributes.NumberFor(message.MessageType));
                    return true;
```

- [ ] **Step 3: Implement `HandlePoll` in `TestCa.cs`** — replace the Task-5 stub:

```csharp
    public byte[] HandlePoll(byte[] der) {
        X509Certificate2 requester_cert;
        string trans_id;
        byte[] nonce;
        Asn1Sequence ias;
        Org.BouncyCastle.Asn1.X509.X509Name subject_name;
        Org.BouncyCastle.X509.X509Certificate issued;

        DecodeRequest(der, out requester_cert, out trans_id, out nonce, out byte[] inner);
        ias = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(inner));
        subject_name = Org.BouncyCastle.Asn1.X509.X509Name.GetInstance(ias[1]);

        // Poll resolves by issuing for the polled subject, reusing the requester's public key.
        issued = Issue(new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(requester_cert.RawData).GetPublicKey(), subject_name.ToString());
        return BuildSuccessCertRep(issued, requester_cert, trans_id, nonce);
    }
```

- [ ] **Step 4: Implement `Poll` on `ScepClient`** (after `GetCrlAsync`):

```csharp
    public ScepResult<EnrollOutcome> Poll(string issuer_dn, string subject_dn, string transaction_id) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildPollMessage(issuer_dn, subject_dn, transaction_id, out message, out signer_key, out error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return SendPkiOperationSync(message, signer_key);
    }

    public async Task<ScepResult<EnrollOutcome>> PollAsync(string issuer_dn, string subject_dn, string transaction_id) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildPollMessage(issuer_dn, subject_dn, transaction_id, out message, out signer_key, out error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return await SendPkiOperationAsync(message, signer_key).ConfigureAwait(false);
    }

    private bool BuildPollMessage(string issuer_dn, string subject_dn, string transaction_id, out PkiMessage message, out IScepKey signer_key, out string error) {
        X509Certificate2 ca_cert;

        message = null!;
        signer_key = null!;

        if (!ResolveCaCert(out ca_cert, out error)) {
            return false;
        }

        if (!ScepRequestBuilder.For(Crypto)
                .CaCertificate(ca_cert)
                .MessageType(MessageType.CertPoll)
                .KeySpec("rsa:2048")
                .IssuerAndSubject(issuer_dn, subject_dn)
                .Build(out message, out signer_key, out error)) {
            return false;
        }

        message.TransactionId = transaction_id;
        return true;
    }
```

- [ ] **Step 5: Write the test** — `tests/ScepTestClient.Tests/PollTests.cs`

```csharp
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class PollTests {
    [Fact]
    public async Task Poll_returns_a_cert_for_the_subject() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        ScepResult<EnrollOutcome> result;

        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);

        result = await client.PollAsync(server.Ca.Certificate.SubjectDN.ToString(), "CN=poodle", "txn-123");
        Assert.True(result.IsOk, result.Error);
        Assert.NotNull(result.Value.Certificate);
        Assert.Contains("poodle", result.Value.Certificate!.Subject);
        Assert.Equal("txn-123", result.Value.TransactionId);
    }
}
```

- [ ] **Step 6: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter PollTests` → PASS.

- [ ] **Step 7: Commit** — `git commit -am "Core: standalone CertPoll (20) sync+async"`

---

### Task 8: Key import + `CertStore` lineage & `Load`

**Goal:** Let a stored cert sign its own renewal: import a PKCS#8 private key back into an `IScepKey`, persist `renewedFrom`/`transactionId`/`status` in cert metadata, expose a core `Save` overload + a `Load`/`FindServerForCert` retrieval path.

**Files:**
- Modify: `src/ScepTestClient.CryptoApi/IScepCrypto.cs`
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs`
- Modify: `src/ScepTestClient.Core/Storage/CertStore.cs`
- Test: `tests/ScepTestClient.Tests/KeyImportTests.cs`, `tests/ScepTestClient.Tests/CertStoreLineageTests.cs`

**Acceptance Criteria:**
- [ ] `ImportPrivateKeyPkcs8(ExportPrivateKeyPkcs8(key))` round-trips: same `AlgorithmOid`, `SizeBits`, and re-export yields byte-identical DER.
- [ ] `CertStore.Save(..., renewedFrom: "abc", transactionId: "tx")` writes `metadata.json` with `RenewedFrom == "abc"`, `TransactionId == "tx"`.
- [ ] `CertStore.Load(serverId, certId, crypto, ...)` returns the cert, an importable key, and the metadata record.
- [ ] `CertStore.FindServerForCert(certId)` returns the server id holding that cert (or null).
- [ ] The existing `Save(server, cert, EnrollRequest, crypto)` overload still compiles and behaves identically (delegates to the core overload with `renewedFrom: null`).

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter "KeyImportTests|CertStoreLineageTests"` → pass.

**Steps:**

- [ ] **Step 1: Add `ImportPrivateKeyPkcs8` to `IScepCrypto.cs`**

```csharp
    bool ImportPrivateKeyPkcs8(byte[] der, out IScepKey key, out string error);
```

- [ ] **Step 2: Implement it in `BouncyCastleScepCrypto.cs`**

```csharp
    public bool ImportPrivateKeyPkcs8(byte[] der, out IScepKey key, out string error) {
        Org.BouncyCastle.Crypto.AsymmetricKeyParameter priv;
        Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters rsa_priv;
        Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters pub;
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair;

        key = null!;
        error = string.Empty;

        try {
            priv = Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(der);
            if (priv is not Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters crt) {
                error = "only RSA PKCS#8 keys are supported by this provider";
                return false;
            }
            rsa_priv = crt;
            pub = new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(false, rsa_priv.Modulus, rsa_priv.PublicExponent);
            pair = new Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair(pub, priv);
            key = new BcKey(pair, BcAlgorithms.Rsa, rsa_priv.Modulus.BitLength);
            return true;
        } catch (System.Exception ex) {
            error = $"ImportPrivateKeyPkcs8 failed: {ex.Message}";
            return false;
        }
    }
```

- [ ] **Step 3: Write the key-import test** — `tests/ScepTestClient.Tests/KeyImportTests.cs`

```csharp
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using Xunit;

namespace ScepTestClient.Tests;

public class KeyImportTests {
    [Fact]
    public void Export_then_import_round_trips() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        byte[] der;
        IScepKey imported;
        byte[] der2;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        Assert.True(crypto.ExportPrivateKeyPkcs8(key, out der, out _));
        Assert.True(crypto.ImportPrivateKeyPkcs8(der, out imported, out string import_error), import_error);
        Assert.Equal(key.AlgorithmOid, imported.AlgorithmOid);
        Assert.Equal(2048, imported.SizeBits);

        Assert.True(crypto.ExportPrivateKeyPkcs8(imported, out der2, out _));
        Assert.Equal(der, der2);
    }
}
```

- [ ] **Step 4: Rework `CertStore.cs`** — make the metadata public, add the lineage fields, a core `Save` overload, `Load`, and `FindServerForCert`:

```csharp
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Storage;

public sealed class CertStore {
    private readonly string _root;

    public CertStore(string root) {
        _root = root;
    }

    // Phase 1 overload — unchanged signature, now delegates to the core overload.
    public string Save(string server_id, X509Certificate2 cert, EnrollRequest request, IScepCrypto crypto) {
        return Save(server_id, cert, request.Key, crypto,
            challenge_password: request.ChallengePassword, renewed_from: null, transaction_id: null);
    }

    public string Save(string server_id, X509Certificate2 cert, IScepKey key, IScepCrypto crypto,
                       string? challenge_password, string? renewed_from, string? transaction_id) {
        string cert_id;
        string cert_dir;
        byte[] key_der;
        string key_error;
        CertRecord metadata;

        cert_id = cert.Thumbprint.ToLowerInvariant();
        cert_dir = Path.Combine(_root, "servers", server_id, "certificates", cert_id);
        Directory.CreateDirectory(cert_dir);

        File.WriteAllText(Path.Combine(cert_dir, "cert.pem"), cert.ExportCertificatePem());

        if (crypto.ExportPrivateKeyPkcs8(key, out key_der, out key_error)) {
            File.WriteAllBytes(Path.Combine(cert_dir, "key.pkcs8"), key_der);
        }

        metadata = new CertRecord {
            Subject = cert.Subject,
            Serial = cert.SerialNumber,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Thumbprint = cert.Thumbprint,
            ChallengePasswordHash = challenge_password != null ? Redaction.Hash(challenge_password) : null,
            RenewedFrom = renewed_from,
            TransactionId = transaction_id,
            Status = "issued",
        };

        File.WriteAllText(Path.Combine(cert_dir, "metadata.json"), JsonSerializer.Serialize(metadata));
        return cert_id;
    }

    public bool Load(string server_id, string cert_id, IScepCrypto crypto,
                    out X509Certificate2 cert, out IScepKey key, out CertRecord record, out string error) {
        string cert_dir;
        string key_path;
        byte[] key_der;

        cert = null!;
        key = null!;
        record = null!;
        error = string.Empty;

        cert_dir = Path.Combine(_root, "servers", server_id, "certificates", cert_id);
        if (!Directory.Exists(cert_dir)) {
            error = $"no stored certificate '{cert_id}' under server '{server_id}'";
            return false;
        }

        cert = X509Certificate2.CreateFromPemFile(Path.Combine(cert_dir, "cert.pem"));

        key_path = Path.Combine(cert_dir, "key.pkcs8");
        if (!File.Exists(key_path)) {
            error = $"no stored key for certificate '{cert_id}'";
            return false;
        }
        key_der = File.ReadAllBytes(key_path);
        if (!crypto.ImportPrivateKeyPkcs8(key_der, out key, out error)) {
            return false;
        }

        record = JsonSerializer.Deserialize<CertRecord>(File.ReadAllText(Path.Combine(cert_dir, "metadata.json")))!;
        return true;
    }

    public string? FindServerForCert(string cert_id) {
        string servers_root;
        string[] server_dirs;

        servers_root = Path.Combine(_root, "servers");
        if (!Directory.Exists(servers_root)) {
            return null;
        }

        server_dirs = Directory.GetDirectories(servers_root);
        foreach (string server_dir in server_dirs) {
            if (Directory.Exists(Path.Combine(server_dir, "certificates", cert_id))) {
                return Path.GetFileName(server_dir);
            }
        }
        return null;
    }

    public sealed class CertRecord {
        public string Subject { get; set; } = string.Empty;
        public string Serial { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string Thumbprint { get; set; } = string.Empty;
        public string? ChallengePasswordHash { get; set; }
        public string? RenewedFrom { get; set; }
        public string? TransactionId { get; set; }
        public string Status { get; set; } = "issued";
    }
}
```

> Note: `X509Certificate2.CreateFromPemFile` is used to reload the cert (keeps parity with how `cert.pem` was written). `key.pkcs8` is read raw and imported via the provider.

- [ ] **Step 5: Write the lineage test** — `tests/ScepTestClient.Tests/CertStoreLineageTests.cs`

```csharp
using System.IO;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.Core.Storage;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class CertStoreLineageTests {
    [Fact]
    public void Save_records_lineage_and_load_round_trips() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey key;
        X509Certificate2 cert;
        CertStore store;
        string root;
        string cert_id;
        X509Certificate2 loaded_cert;
        IScepKey loaded_key;
        CertStore.CertRecord record;
        string error;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        cert = new X509Certificate2(ca.Issue(((BcKey)key).KeyPair.Public, "CN=poodle").GetEncoded());

        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        cert_id = store.Save("fake", cert, key, crypto, challenge_password: null, renewed_from: "old-id", transaction_id: "tx-1");

        Assert.True(store.Load("fake", cert_id, crypto, out loaded_cert, out loaded_key, out record, out error), error);
        Assert.Equal("old-id", record.RenewedFrom);
        Assert.Equal("tx-1", record.TransactionId);
        Assert.Equal(cert.Thumbprint, loaded_cert.Thumbprint);
        Assert.Equal(2048, loaded_key.SizeBits);
        Assert.Equal("fake", store.FindServerForCert(cert_id));
    }
}
```

- [ ] **Step 6: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter "KeyImportTests|CertStoreLineageTests"` → PASS. Also re-run `EndToEndTests` (the Phase-1 Save overload must still work).

- [ ] **Step 7: Commit** — `git commit -am "Storage: key import, cert lineage metadata, Load/FindServerForCert"`

---

### Task 9: `Create(existingCert)` factory + high-level `RenewCertificate` orchestration

**Goal:** Seed a renewal context from an existing cert/key and add the casual `renew <cert-id>` flow: load the stored cert+key, fetch the CA cert, renew via variant Proper, and store the new cert with `renewedFrom` set.

**Files:**
- Modify: `src/ScepTestClient.Core/ScepClient.cs`
- Test: `tests/ScepTestClient.Tests/RenewLifecycleTests.cs`

**Acceptance Criteria:**
- [ ] `ScepClient.Create(existingCert, matchingKey, server, crypto, handler, out client, out error)` returns a client whose `RenewalCertificate`/`RenewalKey` are set.
- [ ] `RenewCertificate(certId, store, log)` (sync+async) loads the stored cert+key, renews, stores the new cert, and the new cert's `metadata.json` has `RenewedFrom == certId`.
- [ ] On a failed renew, no new cert directory is written and the failing result is returned.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter RenewLifecycleTests` → pass.

**Steps:**

- [ ] **Step 1: Add the renewal-seed factory + properties to `ScepClient`** — add properties near `Crypto`:

```csharp
    public X509Certificate2? RenewalCertificate { get; private set; }
    public IScepKey? RenewalKey { get; private set; }
```

And the overload (after the existing `Create`):

```csharp
    public static ScepClientResult Create(X509Certificate2 existing_cert, IScepKey matching_key, ServerConfig server, IScepCrypto crypto, HttpMessageHandler? handler, out ScepClient client, out string error) {
        ScepClientResult result;

        result = Create(server, crypto, handler, out client, out error);
        if (result != ScepClientResult.Ok) {
            return result;
        }

        if (existing_cert is null || matching_key is null) {
            error = "existing certificate and matching key are required";
            return ScepClientResult.InvalidArgument;
        }

        client.RenewalCertificate = existing_cert;
        client.RenewalKey = matching_key;
        return ScepClientResult.Ok;
    }
```

- [ ] **Step 2: Add `RenewCertificate` (sync+async)** — loads, renews variant Proper, stores with lineage:

```csharp
    public async Task<ScepResult<EnrollOutcome>> RenewCertificateAsync(string cert_id, Storage.CertStore store, Storage.UseRecordLog log) {
        X509Certificate2 existing_cert;
        IScepKey existing_key;
        Storage.CertStore.CertRecord record;
        string load_error;
        X509Certificate2 ca_cert;
        string ca_error;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;
        EnrollOutcome outcome;

        if (!store.Load(Server.Id, cert_id, Crypto, out existing_cert, out existing_key, out record, out load_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.NotFound, load_error);
        }

        if (!ResolveCaCert(out ca_cert, out ca_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, ca_error);
        }

        request = new RenewRequest {
            Subject = record.Subject,
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = RenewalVariant.Proper,
            CaCertificate = ca_cert,
        };

        result = await RenewAsync(request).ConfigureAwait(false);
        if (!result.IsOk) {
            return result;
        }

        outcome = result.Value;
        if (outcome.Certificate is not null && outcome.SubjectKey is not null) {
            store.Save(Server.Id, outcome.Certificate, outcome.SubjectKey, Crypto,
                challenge_password: null, renewed_from: cert_id, transaction_id: outcome.TransactionId);
        }
        log.Append(Server.Id, outcome);
        return result;
    }

    public ScepResult<EnrollOutcome> RenewCertificate(string cert_id, Storage.CertStore store, Storage.UseRecordLog log) {
        X509Certificate2 existing_cert;
        IScepKey existing_key;
        Storage.CertStore.CertRecord record;
        string load_error;
        X509Certificate2 ca_cert;
        string ca_error;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;
        EnrollOutcome outcome;

        if (!store.Load(Server.Id, cert_id, Crypto, out existing_cert, out existing_key, out record, out load_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.NotFound, load_error);
        }

        if (!ResolveCaCert(out ca_cert, out ca_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, ca_error);
        }

        request = new RenewRequest {
            Subject = record.Subject,
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = RenewalVariant.Proper,
            CaCertificate = ca_cert,
        };

        result = Renew(request);
        if (!result.IsOk) {
            return result;
        }

        outcome = result.Value;
        if (outcome.Certificate is not null && outcome.SubjectKey is not null) {
            store.Save(Server.Id, outcome.Certificate, outcome.SubjectKey, Crypto,
                challenge_password: null, renewed_from: cert_id, transaction_id: outcome.TransactionId);
        }
        log.Append(Server.Id, outcome);
        return result;
    }
```

- [ ] **Step 3: Write the lifecycle test** — `tests/ScepTestClient.Tests/RenewLifecycleTests.cs`

```csharp
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Storage;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class RenewLifecycleTests {
    [Fact]
    public async Task Enroll_then_renew_chains_lineage() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        ScepClient client;
        string root;
        CertStore store;
        UseRecordLog log;
        ScepResult<EnrollOutcome> enroll;
        string original_id;
        ScepResult<EnrollOutcome> renew;
        string new_id;
        string meta_json;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);

        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        log = new UseRecordLog(root);

        enroll = await client.GetNewCertificateAsync(
            new EnrollRequest { Subject = "CN=poodle", Key = key, ChallengePassword = "pw", CaCertificate = server.Ca.CertificateBcl },
            store, log);
        Assert.True(enroll.IsOk, enroll.Error);
        original_id = enroll.Value.Certificate!.Thumbprint.ToLowerInvariant();

        renew = await client.RenewCertificateAsync(original_id, store, log);
        Assert.True(renew.IsOk, renew.Error);

        new_id = renew.Value.Certificate!.Thumbprint.ToLowerInvariant();
        meta_json = File.ReadAllText(Path.Combine(root, "servers", "fake", "certificates", new_id, "metadata.json"));
        using JsonDocument doc = JsonDocument.Parse(meta_json);
        Assert.Equal(original_id, doc.RootElement.GetProperty("RenewedFrom").GetString());
    }
}
```

- [ ] **Step 4: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter RenewLifecycleTests` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "Core: Create(existingCert) seed + high-level RenewCertificate with lineage"`

---

### Task 10: Encrypted PKCS#8 key storage (`--encrypt-keys`)

**Goal:** Add passphrase-encrypted PKCS#8 export/import to the provider and let `CertStore` write/read `key.pkcs8.enc` when a passphrase is supplied (spec §9.6).

**Files:**
- Modify: `src/ScepTestClient.CryptoApi/IScepCrypto.cs`
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs`
- Modify: `src/ScepTestClient.Core/Storage/CertStore.cs`
- Test: `tests/ScepTestClient.Tests/EncryptedKeyTests.cs`

**Acceptance Criteria:**
- [ ] `ImportPrivateKeyPkcs8Encrypted(ExportPrivateKeyPkcs8Encrypted(key, "pw"), "pw")` round-trips (same `AlgorithmOid`/`SizeBits`).
- [ ] Importing with the wrong passphrase returns `false` + non-empty error (no throw to caller).
- [ ] `CertStore.Save(..., passphrase: "pw")` writes `key.pkcs8.enc` and NOT `key.pkcs8`; `Load` reads it back and imports it.
- [ ] Default (no passphrase) behavior is unchanged — `key.pkcs8` plaintext.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter EncryptedKeyTests` → pass.

> **Implementer note (BouncyCastle 2.5.0):** The exact encrypted-PKCS#8 API is version-sensitive. **The round-trip test is the source of truth — adjust the BC call until it compiles and the test passes.** The shapes below are the intended path (`Pkcs8Generator` for export, `EncryptedPrivateKeyInfo` + `PrivateKeyFactory.DecryptKey` for import); if a symbol differs in 2.5.0, find the equivalent in `Org.BouncyCastle.Pkcs` / `Org.BouncyCastle.Asn1.Pkcs` rather than changing the contract.

**Steps:**

- [ ] **Step 1: Add the two contract methods to `IScepCrypto.cs`**

```csharp
    bool ExportPrivateKeyPkcs8Encrypted(IScepKey key, string passphrase, out byte[] der, out string error);

    bool ImportPrivateKeyPkcs8Encrypted(byte[] der, string passphrase, out IScepKey key, out string error);
```

- [ ] **Step 2: Implement them in `BouncyCastleScepCrypto.cs`**

```csharp
    public bool ExportPrivateKeyPkcs8Encrypted(IScepKey key, string passphrase, out byte[] der, out string error) {
        Org.BouncyCastle.Pkcs.Pkcs8Generator generator;
        Org.BouncyCastle.Utilities.IO.Pem.PemObject pem;

        der = System.Array.Empty<byte>();
        error = string.Empty;

        if (key is not BcKey bc_key) {
            error = "key was not produced by this provider";
            return false;
        }

        try {
            generator = new Org.BouncyCastle.Pkcs.Pkcs8Generator(
                Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(bc_key.KeyPair.Private),
                Org.BouncyCastle.Pkcs.Pkcs8Generator.PbeSha1_3DES);
            generator.Password = passphrase.ToCharArray();
            generator.SecureRandom = _random;
            pem = generator.Generate();
            der = pem.Content;   // DER of EncryptedPrivateKeyInfo
            return true;
        } catch (System.Exception ex) {
            error = $"ExportPrivateKeyPkcs8Encrypted failed: {ex.Message}";
            return false;
        }
    }

    public bool ImportPrivateKeyPkcs8Encrypted(byte[] der, string passphrase, out IScepKey key, out string error) {
        Org.BouncyCastle.Asn1.Pkcs.EncryptedPrivateKeyInfo enc_info;
        Org.BouncyCastle.Crypto.AsymmetricKeyParameter priv;
        byte[] plain_der;

        key = null!;
        error = string.Empty;

        try {
            enc_info = Org.BouncyCastle.Asn1.Pkcs.EncryptedPrivateKeyInfo.GetInstance(
                Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(der));
            priv = Org.BouncyCastle.Security.PrivateKeyFactory.DecryptKey(passphrase.ToCharArray(), enc_info);
            plain_der = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(priv).GetDerEncoded();
            return ImportPrivateKeyPkcs8(plain_der, out key, out error);
        } catch (System.Exception ex) {
            error = $"ImportPrivateKeyPkcs8Encrypted failed: {ex.Message}";
            return false;
        }
    }
```

- [ ] **Step 3: Teach `CertStore` to encrypt when a passphrase is given.** Add a `passphrase` parameter to the core `Save` and to `Load` detection. Update the core `Save` signature and key-write block:

```csharp
    public string Save(string server_id, X509Certificate2 cert, IScepKey key, IScepCrypto crypto,
                       string? challenge_password, string? renewed_from, string? transaction_id, string? passphrase = null) {
```

Replace the plaintext key-write with:

```csharp
        if (!string.IsNullOrEmpty(passphrase)) {
            if (crypto.ExportPrivateKeyPkcs8Encrypted(key, passphrase!, out key_der, out key_error)) {
                File.WriteAllBytes(Path.Combine(cert_dir, "key.pkcs8.enc"), key_der);
            }
        } else if (crypto.ExportPrivateKeyPkcs8(key, out key_der, out key_error)) {
            File.WriteAllBytes(Path.Combine(cert_dir, "key.pkcs8"), key_der);
        }
```

Update `Load` to add an optional `passphrase` and detect the encrypted file:

```csharp
    public bool Load(string server_id, string cert_id, IScepCrypto crypto,
                    out X509Certificate2 cert, out IScepKey key, out CertRecord record, out string error, string? passphrase = null) {
```

Replace the key-loading block in `Load` with:

```csharp
        string enc_path;

        key_path = Path.Combine(cert_dir, "key.pkcs8");
        enc_path = Path.Combine(cert_dir, "key.pkcs8.enc");
        if (File.Exists(enc_path)) {
            if (string.IsNullOrEmpty(passphrase)) {
                error = $"certificate '{cert_id}' has an encrypted key; a passphrase is required";
                return false;
            }
            if (!crypto.ImportPrivateKeyPkcs8Encrypted(File.ReadAllBytes(enc_path), passphrase!, out key, out error)) {
                return false;
            }
        } else if (File.Exists(key_path)) {
            if (!crypto.ImportPrivateKeyPkcs8(File.ReadAllBytes(key_path), out key, out error)) {
                return false;
            }
        } else {
            error = $"no stored key for certificate '{cert_id}'";
            return false;
        }
```

(Remove the old `key_der`/`key_path` lines this replaces.)

- [ ] **Step 4: Write the test** — `tests/ScepTestClient.Tests/EncryptedKeyTests.cs`

```csharp
using System.IO;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.Core.Storage;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class EncryptedKeyTests {
    [Fact]
    public void Encrypted_pkcs8_round_trips() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        byte[] enc;
        IScepKey imported;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        Assert.True(crypto.ExportPrivateKeyPkcs8Encrypted(key, "s3cret", out enc, out _));
        Assert.True(crypto.ImportPrivateKeyPkcs8Encrypted(enc, "s3cret", out imported, out string err), err);
        Assert.Equal(2048, imported.SizeBits);
        Assert.False(crypto.ImportPrivateKeyPkcs8Encrypted(enc, "wrong", out _, out _));
    }

    [Fact]
    public void Store_writes_encrypted_key_file() {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        KeySpec spec;
        IScepKey key;
        X509Certificate2 cert;
        string root;
        CertStore store;
        string cert_id;
        IScepKey loaded_key;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        cert = new X509Certificate2(ca.Issue(((BcKey)key).KeyPair.Public, "CN=poodle").GetEncoded());

        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        cert_id = store.Save("fake", cert, key, crypto, challenge_password: null, renewed_from: null, transaction_id: null, passphrase: "s3cret");

        string cert_dir;
        cert_dir = Path.Combine(root, "servers", "fake", "certificates", cert_id);
        Assert.True(File.Exists(Path.Combine(cert_dir, "key.pkcs8.enc")));
        Assert.False(File.Exists(Path.Combine(cert_dir, "key.pkcs8")));

        Assert.True(store.Load("fake", cert_id, crypto, out _, out loaded_key, out _, out string err, passphrase: "s3cret"), err);
        Assert.Equal(2048, loaded_key.SizeBits);
    }
}
```

- [ ] **Step 5: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter EncryptedKeyTests` → PASS.

- [ ] **Step 6: Commit** — `git commit -am "Storage: encrypted PKCS#8 key export/import (--encrypt-keys)"`

---

### Task 11: CLI wiring — getcacert, enroll, renew, getcert, getcrl, poll + `--encrypt-keys`

**Goal:** Expose the Phase-2 operations on the `sceptest` CLI and fill the remaining per-op gaps, with usage + an end-to-end routing test against a live fake server.

**Files:**
- Modify: `src/ScepTestClient.Cli/CommandRouter.cs`
- Test: `tests/ScepTestClient.Tests/CliRouterPhase2Tests.cs`

**Acceptance Criteria:**
- [ ] New `noun` cases route: `getcacert`, `getnextcacert`, `enroll`, `renew`, `getcert`, `getcrl`, `poll`.
- [ ] `renew <cert-id>` finds the owning server via `CertStore.FindServerForCert`, renews variant Proper (or `--variant`), and prints the new cert id; `--encrypt-keys` stores the new key encrypted (passphrase from `--key-pass`).
- [ ] `getcert <server> --issuer <dn> --serial <hex>` and `getcrl <server> --issuer <dn> --serial <hex>` print success/failure.
- [ ] Missing required args return exit code 2 with a usage line; `WriteUsage` lists every new command.
- [ ] An end-to-end test (`servers add <fakeUrl>` → `get` → `renew <id>`) exits 0 and reports the renewed cert.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter CliRouterPhase2Tests` → pass.

**Steps:**

- [ ] **Step 1: Add the new `noun` cases** in `RunInternal`'s `switch` (before `--help`):

```csharp
            case "getcacert":
                return RunGetCaCert(args, data_root, output);

            case "getnextcacert":
                return RunGetNextCaCert(args, data_root, output);

            case "enroll":
                return RunGet(args, data_root, output);   // enroll == get without lifecycle sugar; same options

            case "renew":
                return RunRenew(args, data_root, output);

            case "getcert":
                return RunGetCert(args, data_root, output);

            case "getcrl":
                return RunGetCrl(args, data_root, output);

            case "poll":
                return RunPoll(args, data_root, output);
```

- [ ] **Step 2: Add a shared client-builder helper** to remove duplication (registry lookup + crypto load + `ScepClient.Create`). Add to `CommandRouter`:

```csharp
    private static bool BuildClient(string server_id, string data_root, TextWriter output, out ScepClient client, out StoredServer stored) {
        ServerRegistry registry;
        StoredServer? found;
        IScepCrypto crypto;
        string crypto_error;
        ServerConfig config;
        string client_error;

        client = null!;
        stored = null!;

        registry = new ServerRegistry(data_root);
        found = registry.Get(server_id);
        if (found is null) {
            output.WriteLine($"unknown server '{server_id}'");
            return false;
        }
        stored = found;

        if (ScepCrypto.Load(null, out crypto, out crypto_error) != ScepClientResult.Ok) {
            output.WriteLine($"crypto load error: {crypto_error}");
            return false;
        }

        config = new ServerConfig {
            Id = stored.Id,
            Url = new Uri(stored.Url),
            CaIdentifier = stored.CaIdentifier,
            PreferPost = stored.PreferPost,
        };

        if (ScepClient.Create(config, crypto, null, out client, out client_error) != ScepClientResult.Ok) {
            output.WriteLine($"client create error: {client_error}");
            return false;
        }
        return true;
    }
```

- [ ] **Step 3: Add the command handlers.** All follow the existing snake_case/declare-at-top style:

```csharp
    private static int RunGetCaCert(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> result;

        if (args.Length < 2) { output.WriteLine("usage: getcacert <serverId>"); return 2; }
        if (!BuildClient(args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.GetCaCert();
        if (!result.IsOk) { output.WriteLine($"getcacert failed: {result.Status} {result.Error}"); return 1; }
        foreach (System.Security.Cryptography.X509Certificates.X509Certificate2 c in result.Value) {
            output.WriteLine(c.Subject);
        }
        return 0;
    }

    private static int RunGetNextCaCert(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> result;

        if (args.Length < 2) { output.WriteLine("usage: getnextcacert <serverId>"); return 2; }
        if (!BuildClient(args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.GetNextCaCert();
        if (!result.IsOk) { output.WriteLine($"getnextcacert failed: {result.Status} {result.Error}"); return 1; }
        foreach (System.Security.Cryptography.X509Certificates.X509Certificate2 c in result.Value) {
            output.WriteLine(c.Subject);
        }
        return 0;
    }

    private static int RunRenew(string[] args, string data_root, TextWriter output) {
        string cert_id;
        string? variant_text;
        string? passphrase;
        bool encrypt;
        CertStore store;
        string? server_id;
        ScepClient client;
        StoredServer stored;
        ScepResult<EnrollOutcome> result;
        RenewalVariant variant;

        if (args.Length < 2) { output.WriteLine("usage: renew <certId> [--variant proper|reenroll-same-subject|pkcsreq-old-cert|same-key|expired] [--encrypt-keys] [--key-pass <pw>]"); return 2; }

        cert_id = args[1];
        variant_text = Opt(args, "--variant");
        encrypt = HasFlag(args, "--encrypt-keys");
        passphrase = Opt(args, "--key-pass");
        variant = ParseVariant(variant_text);

        store = new CertStore(data_root);
        server_id = store.FindServerForCert(cert_id);
        if (server_id is null) { output.WriteLine($"no stored certificate '{cert_id}'"); return 2; }

        if (!BuildClient(server_id, data_root, output, out client, out stored)) { return 2; }

        if (variant == RenewalVariant.Proper) {
            result = client.RenewCertificate(cert_id, store, new UseRecordLog(data_root));
        } else {
            // Non-default variant: load + renew explicitly (lineage still recorded by RenewCertificate path only for Proper).
            result = RunRenewVariant(client, store, data_root, cert_id, variant, encrypt ? (passphrase ?? string.Empty) : null, output);
        }

        if (result.IsOk && result.Value.Certificate is not null) {
            output.WriteLine($"renewed: {result.Value.Certificate.Subject} -> {result.Value.Certificate.Thumbprint.ToLowerInvariant()}");
            return 0;
        }
        output.WriteLine($"FAILED: {result.Status} {result.Error} (failInfo {result.Value?.FailInfo})");
        return 1;
    }

    private static ScepResult<EnrollOutcome> RunRenewVariant(ScepClient client, CertStore store, string data_root, string cert_id, RenewalVariant variant, string? passphrase, TextWriter output) {
        System.Security.Cryptography.X509Certificates.X509Certificate2 existing_cert;
        IScepKey existing_key;
        CertStore.CertRecord record;
        string load_error;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> ca_result;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;

        if (!store.Load(client.Server.Id, cert_id, client.Crypto, out existing_cert, out existing_key, out record, out load_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.NotFound, load_error);
        }
        ca_result = client.GetCaCert();
        if (!ca_result.IsOk) { return ScepResult<EnrollOutcome>.Fail(ca_result.Status, ca_result.Error); }

        request = new RenewRequest {
            Subject = record.Subject,
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = variant,
            CaCertificate = ca_result.Value[0],
        };
        result = client.Renew(request);
        if (result.IsOk && result.Value.Certificate is not null && result.Value.SubjectKey is not null) {
            store.Save(client.Server.Id, result.Value.Certificate, result.Value.SubjectKey, client.Crypto,
                challenge_password: null, renewed_from: cert_id, transaction_id: result.Value.TransactionId, passphrase: passphrase);
        }
        return result;
    }

    private static int RunGetCert(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        string? issuer;
        string? serial;
        ScepResult<System.Security.Cryptography.X509Certificates.X509Certificate2> result;

        if (args.Length < 2) { output.WriteLine("usage: getcert <serverId> --issuer <dn> --serial <hex>"); return 2; }
        issuer = Opt(args, "--issuer");
        serial = Opt(args, "--serial");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(serial)) { output.WriteLine("--issuer and --serial are required"); return 2; }
        if (!BuildClient(args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.GetCert(issuer!, serial!);
        if (!result.IsOk) { output.WriteLine($"getcert failed: {result.Status} {result.Error}"); return 1; }
        output.WriteLine($"found: {result.Value.Subject} (serial {result.Value.SerialNumber})");
        return 0;
    }

    private static int RunGetCrl(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        string? issuer;
        string? serial;
        ScepResult<byte[]> result;

        if (args.Length < 2) { output.WriteLine("usage: getcrl <serverId> --issuer <dn> --serial <hex>"); return 2; }
        issuer = Opt(args, "--issuer");
        serial = Opt(args, "--serial");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(serial)) { output.WriteLine("--issuer and --serial are required"); return 2; }
        if (!BuildClient(args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.GetCrl(issuer!, serial!);
        if (!result.IsOk) { output.WriteLine($"getcrl failed: {result.Status} {result.Error}"); return 1; }
        output.WriteLine($"CRL: {result.Value.Length} bytes");
        return 0;
    }

    private static int RunPoll(string[] args, string data_root, TextWriter output) {
        ScepClient client;
        StoredServer stored;
        string? issuer;
        string? subject;
        string? txn;
        ScepResult<EnrollOutcome> result;

        if (args.Length < 2) { output.WriteLine("usage: poll <serverId> --issuer <dn> --subject <dn> --txn <id>"); return 2; }
        issuer = Opt(args, "--issuer");
        subject = Opt(args, "--subject");
        txn = Opt(args, "--txn");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject) || string.IsNullOrWhiteSpace(txn)) { output.WriteLine("--issuer, --subject and --txn are required"); return 2; }
        if (!BuildClient(args[1], data_root, output, out client, out stored)) { return 2; }

        result = client.Poll(issuer!, subject!, txn!);
        if (result.IsOk && result.Value.Certificate is not null) {
            output.WriteLine($"polled: {result.Value.Certificate.Subject}");
            return 0;
        }
        output.WriteLine($"poll status: {result.Status} (pkiStatus {result.Value?.PkiStatus})");
        return result.Status == ScepClientResult.Pending ? 0 : 1;
    }

    private static RenewalVariant ParseVariant(string? text) {
        switch (text) {
            case "reenroll-same-subject": return RenewalVariant.ReenrollSameSubject;
            case "pkcsreq-old-cert": return RenewalVariant.RenewalShapedPkcsReq;
            case "same-key": return RenewalVariant.SameKey;
            case "expired": return RenewalVariant.Expired;
            default: return RenewalVariant.Proper;
        }
    }

    private static bool HasFlag(string[] args, string flag) {
        int i;
        for (i = 0; i < args.Length; i++) {
            if (args[i] == flag) { return true; }
        }
        return false;
    }
```

- [ ] **Step 4: Pass `--encrypt-keys` through the `get`/`enroll` path.** In `RunGet`, read the flag and pass a passphrase to storage. Add near the other `Opt` reads:

```csharp
        bool encrypt_keys;
        string? key_pass;

        encrypt_keys = HasFlag(args, "--encrypt-keys");
        key_pass = Opt(args, "--key-pass");
```

`GetNewCertificate` stores via the Phase-1 Save overload (no passphrase). To honor `--encrypt-keys` here, after a successful `outcome`, when `encrypt_keys` is set, re-save the issued cert+key encrypted:

```csharp
        if (outcome.IsOk && encrypt_keys && outcome.Value.Certificate is not null) {
            new CertStore(data_root).Save(stored.Id, outcome.Value.Certificate, key, crypto,
                challenge_password: challenge, renewed_from: null, transaction_id: outcome.Value.TransactionId, passphrase: key_pass ?? string.Empty);
        }
```

(Place this just before the existing `if (outcome.IsOk) { ... return 0; }` block; the re-save overwrites the plaintext directory contents with the encrypted key.)

- [ ] **Step 5: Update `WriteUsage`** to list the new commands — add these lines before `config show`:

```csharp
        output.WriteLine("  getcacert <serverId>");
        output.WriteLine("  getnextcacert <serverId>");
        output.WriteLine("  enroll <serverId> --subject \"CN=x\" [--challenge <pw>] [--key-spec rsa:2048] [--encrypt-keys --key-pass <pw>]");
        output.WriteLine("  renew <certId> [--variant proper|reenroll-same-subject|pkcsreq-old-cert|same-key|expired] [--encrypt-keys --key-pass <pw>]");
        output.WriteLine("  getcert <serverId> --issuer <dn> --serial <hex>");
        output.WriteLine("  getcrl <serverId> --issuer <dn> --serial <hex>");
        output.WriteLine("  poll <serverId> --issuer <dn> --subject <dn> --txn <id>");
```

- [ ] **Step 6: Write the CLI test** — `tests/ScepTestClient.Tests/CliRouterPhase2Tests.cs`

```csharp
using System.IO;
using System.Threading.Tasks;
using ScepTestClient.Cli;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class CliRouterPhase2Tests {
    [Fact]
    public void Renew_without_args_returns_usage() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        code = CommandRouter.Run(new[] { "renew" }, root, outw);
        Assert.Equal(2, code);
        Assert.Contains("usage: renew", outw.ToString());
    }

    [Fact]
    public void Getcert_requires_issuer_and_serial() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", "http://host/scep", "--name", "h" }, root, outw);
        code = CommandRouter.Run(new[] { "getcert", "h" }, root, outw);
        Assert.Equal(2, code);
        Assert.Contains("required", outw.ToString());
    }

    [Fact]
    public async Task Get_then_renew_end_to_end() {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        string root;
        StringWriter outw;
        int add_code;
        int get_code;
        int renew_code;
        string listing;
        string cert_id;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        add_code = CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "fake" }, root, outw);
        get_code = CommandRouter.Run(new[] { "get", "fake", "--subject", "CN=poodle", "--challenge", "pw" }, root, outw);

        StringWriter list_out;
        list_out = new StringWriter();
        CommandRouter.Run(new[] { "certs", "list", "fake" }, root, list_out);
        listing = list_out.ToString().Trim();
        cert_id = listing.Substring(listing.IndexOf('/') + 1);

        StringWriter renew_out;
        renew_out = new StringWriter();
        renew_code = CommandRouter.Run(new[] { "renew", cert_id }, root, renew_out);

        Assert.Equal(0, add_code);
        Assert.Equal(0, get_code);
        Assert.Equal(0, renew_code);
        Assert.Contains("renewed:", renew_out.ToString());
    }
}
```

- [ ] **Step 7: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter CliRouterPhase2Tests` → PASS.

- [ ] **Step 8: Final full build + test sweep** — `dotnet build IntuneSimulator.sln -c Debug` (expect `Build succeeded`, 0 warnings) then `dotnet test IntuneSimulator.sln` (all ScepTestClient + IntuneSimulator tests green).

- [ ] **Step 9: Commit** — `git commit -am "CLI: getcacert/enroll/renew/getcert/getcrl/poll + --encrypt-keys"`

---

## Self-Review

**Spec coverage (§ → task):**
- §8 RenewalReq + 5 variants → Tasks 1, 4, 5.
- §7 GetCert(21)/GetCRL(22) → Tasks 2, 3, 6. CertPoll(20) standalone → Task 7 (Phase-1 deferral folded in).
- §6 `ScepRequestBuilder` → Task 4.
- §9.2 `renewedFrom` lineage + `renew <cert-id>` → Tasks 8, 9, 11.
- §9.6 `--encrypt-keys` → Task 10, 11 (Phase-1 deferral folded in).
- §5.3 `Renew`/`GetCert`/`GetCrl`/`Poll` sync+async parity → Tasks 5, 6, 7.
- §5.1 `Create(existingCert, key)` factory → Task 9.

**Type consistency:** `EnrollOutcome.SubjectKey` (added T5) is read in T6/T9/T11. `CertStore.Save(...passphrase)` (T10) extends the T8 core overload. `ResolveCaCert`/`_ca_cert_cache` introduced in T6, reused in T7/T9. `ScepRequestBuilder.Build(out msg, out key, out err)` signature is stable across T4–T7. `PkiMessage.IssuedCrls`/`IssuerName`/`SerialNumber`/`SubjectName` (T2/T3) consumed by T6/T7. `MessageType` enum values are unchanged from Phase 1.

**Deferred decisions:** none — the two optional Phase-1 deferrals (CertPoll, `--encrypt-keys`) are folded in per the user's explicit go-ahead; no open questions remain.

**Out of scope (Phase 3+, deliberately not here):** fault injection / `FaultDirectives` (the `faults` arg stays a no-op stub), compliance matrix, `test full/lifecycle/probe`, challenge sources (`--simulator`/`--ndes`), report emitters, PQ tiers. The expired-renewal rejection is exercised only against the in-test fake CA's validity check; real-server compliance assertions land in Phase 3.





