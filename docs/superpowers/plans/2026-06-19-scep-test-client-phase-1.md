# ScepTestClient — Phase 1 (Foundation & Casual Use) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers-extended-cc:subagent-driven-development (recommended) or superpowers-extended-cc:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a working, cross-platform `sceptest` client that can enroll for and store a certificate end-to-end ("get me a cert"), built on a swappable crypto provider.

**Architecture:** Five projects added to `IntuneSimulator.sln`: a dependency-free `CryptoApi` contract, a BouncyCastle provider DLL, a `Core` library (protocol + storage + facade) that references only the contract, a `Cli` executable, and an xUnit test project. All crypto is behind one `IScepCrypto` interface; algorithms are OID strings tagged by kind; the public API never throws for control flow.

**Tech Stack:** .NET 8 (`net8.0`, `RollForward Major`), C#, xUnit, BouncyCastle.Cryptography 2.5.0, `System.Security.Cryptography.X509Certificates` for the BCL cert type.

**User decisions (already made):**
- "I hate `var` with a passion" → never `var`; explicit types only; enforced via `.editorconfig`.
- "declare variables at the beginning of a block, without assignment, then a blank line, then assignments" → declare-at-top convention (CLAUDE.md note).
- "no exceptions for control flow" → static `Create()`/`Load()` factories; sync = `ResultEnum` + `out` value + `out string error`; async = `ScepResult<T>`.
- "full sync + async parity" → every operation in both forms; genuine `HttpClient.Send`/`SendAsync`, never sync-over-async.
- Crypto must be swappable behind a tiny contract; BouncyCastle is the dev backend only.
- Phase 1 is one branch/PR off `main`; nothing ships until all phases done.

**Planning clarification (carried from exploration):** The spec's Phase 1 line said "happy-path tests vs simulator," but the IntuneSimulator only implements Intune's `/ScepActions/*` validation endpoints — it does not issue certificates over SCEP. Phase 1 therefore tests the client end-to-end against an in-test **`FakeScepServer`** (a loopback SCEP CA built with BouncyCastle). The `--simulator` challenge-password integration remains a Phase 3 feature.

---

## File Structure (Phase 1)

```
.editorconfig                                   # ban var, formatting
CLAUDE.md                                        # declare-at-top convention + suite notes

src/ScepTestClient.CryptoApi/                    # dependency-free contract (providers compile against this)
  ScepClientResult.cs  ScepResult.cs  CodecOptions.cs  ConformanceNote.cs
  MessageType.cs  PkiStatus.cs  FailInfo.cs
  AlgorithmKind.cs  Algorithms.cs  KeySpec.cs
  IScepKey.cs  CryptoCapabilities.cs  FaultDirectives.cs
  Pkcs10.cs  PkiMessage.cs  IScepCrypto.cs

src/ScepTestClient.Crypto.BouncyCastle/          # default provider DLL (only project that uses BouncyCastle)
  BouncyCastleScepCrypto.cs  BcKey.cs  BcAlgorithms.cs

src/ScepTestClient.Core/                         # library; references CryptoApi only
  ScepCrypto.cs  ProviderLoadContext.cs
  ServerConfig.cs  ScepTraceEvent.cs
  Transport/ScepHttpTransport.cs
  Protocol/ScepCapabilities.cs
  ScepClient.cs
  Storage/DataRoot.cs  Storage/Redaction.cs  Storage/ClientConfig.cs
  Storage/ServerRegistry.cs  Storage/CertStore.cs  Storage/UseRecordLog.cs

src/ScepTestClient.Cli/                          # sceptest executable; ships the BC provider DLL
  Program.cs  CommandRouter.cs  ConsoleTrace.cs

tests/ScepTestClient.Tests/
  (one test file per task; FakeScepServer fixture under Fakes/)
```

---

### Task 0: Solution scaffolding & code-style conventions

**Goal:** Create the five projects, wire references, ban `var` via `.editorconfig`, and leave the solution building green.

**Files:**
- Create: `.editorconfig`, `CLAUDE.md`
- Create: `src/ScepTestClient.CryptoApi/ScepTestClient.CryptoApi.csproj`
- Create: `src/ScepTestClient.Crypto.BouncyCastle/ScepTestClient.Crypto.BouncyCastle.csproj`
- Create: `src/ScepTestClient.Core/ScepTestClient.Core.csproj`
- Create: `src/ScepTestClient.Cli/ScepTestClient.Cli.csproj`
- Create: `tests/ScepTestClient.Tests/ScepTestClient.Tests.csproj`

**Acceptance Criteria:**
- [ ] `dotnet build IntuneSimulator.sln` succeeds with all five new projects.
- [ ] `.editorconfig` sets `csharp_style_var_*` to `false:warning`.
- [ ] Core references CryptoApi only (not BouncyCastle); Cli references Core + the BC provider; Tests reference Core + both providers.

**Verify:** `dotnet build IntuneSimulator.sln -c Debug` → `Build succeeded`.

**Steps:**

- [ ] **Step 1: Write `.editorconfig`** (repo root)

```ini
root = true

[*.cs]
indent_style = space
indent_size = 4
charset = utf-8
insert_final_newline = true

# House rule: never `var` — always the explicit type.
csharp_style_var_for_built_in_types = false:warning
csharp_style_var_when_type_is_apparent = false:warning
csharp_style_var_elsewhere = false:warning
```

- [ ] **Step 2: Write `CLAUDE.md`** (repo root)

```markdown
# Repo conventions

This repo is the **SCEP testing suite** (IntuneSimulator + ScepTestClient).

## ScepTestClient code style (src/ScepTestClient.*, tests/ScepTestClient.Tests)
- **Never `var`** — always the explicit type (enforced by `.editorconfig`).
- **Declare locals at the top of the block, unassigned, then a blank line, then assignments.** Example:

  ```csharp
  int count;
  string name;

  count = items.Length;
  name = items[0].Name;
  ```
- No exceptions for control flow: static `Create()`/`Load()` factories; sync returns a result enum + `out value` + `out string error`; async returns `ScepResult<T>`.
- All cryptography goes through `IScepCrypto`; never reference a crypto library outside `ScepTestClient.Crypto.*`.

The existing IntuneSimulator projects keep their modern idioms (`var`, LINQ); these rules apply to ScepTestClient code only.
```

- [ ] **Step 3: Create the projects**

```bash
cd /Users/pdb/Projects/FakeIntune
dotnet new classlib -n ScepTestClient.CryptoApi -o src/ScepTestClient.CryptoApi -f net8.0
dotnet new classlib -n ScepTestClient.Crypto.BouncyCastle -o src/ScepTestClient.Crypto.BouncyCastle -f net8.0
dotnet new classlib -n ScepTestClient.Core -o src/ScepTestClient.Core -f net8.0
dotnet new console  -n ScepTestClient.Cli -o src/ScepTestClient.Cli -f net8.0
dotnet new xunit    -n ScepTestClient.Tests -o tests/ScepTestClient.Tests -f net8.0
rm -f src/ScepTestClient.CryptoApi/Class1.cs src/ScepTestClient.Crypto.BouncyCastle/Class1.cs src/ScepTestClient.Core/Class1.cs
```

- [ ] **Step 4: Edit each csproj** — add `<RollForward>Major</RollForward>` and `<Nullable>enable</Nullable>`/`<ImplicitUsings>enable</ImplicitUsings>` to every `<PropertyGroup>` (they're added by the templates except RollForward). Add the BouncyCastle package to the provider:

`src/ScepTestClient.Crypto.BouncyCastle/ScepTestClient.Crypto.BouncyCastle.csproj` ItemGroup:
```xml
  <ItemGroup>
    <PackageReference Include="BouncyCastle.Cryptography" Version="2.5.0" />
    <ProjectReference Include="..\ScepTestClient.CryptoApi\ScepTestClient.CryptoApi.csproj" />
  </ItemGroup>
```

- [ ] **Step 5: Wire the remaining references**

```bash
dotnet add src/ScepTestClient.Core/ScepTestClient.Core.csproj reference src/ScepTestClient.CryptoApi/ScepTestClient.CryptoApi.csproj
dotnet add src/ScepTestClient.Cli/ScepTestClient.Cli.csproj reference src/ScepTestClient.Core/ScepTestClient.Core.csproj src/ScepTestClient.Crypto.BouncyCastle/ScepTestClient.Crypto.BouncyCastle.csproj
dotnet add tests/ScepTestClient.Tests/ScepTestClient.Tests.csproj reference src/ScepTestClient.Core/ScepTestClient.Core.csproj src/ScepTestClient.Crypto.BouncyCastle/ScepTestClient.Crypto.BouncyCastle.csproj src/ScepTestClient.CryptoApi/ScepTestClient.CryptoApi.csproj
dotnet sln IntuneSimulator.sln add src/ScepTestClient.CryptoApi src/ScepTestClient.Crypto.BouncyCastle src/ScepTestClient.Core src/ScepTestClient.Cli tests/ScepTestClient.Tests
```

- [ ] **Step 6: Build**

Run: `dotnet build IntuneSimulator.sln -c Debug`
Expected: `Build succeeded`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "Scaffold ScepTestClient projects and code-style config"
```

---

### Task 1: CryptoApi — result types & SCEP enums

**Goal:** The no-throw result primitives and the RFC 8894 enums every later task depends on.

**Files:**
- Create: `src/ScepTestClient.CryptoApi/ScepClientResult.cs`, `ScepResult.cs`, `CodecOptions.cs`, `ConformanceNote.cs`, `MessageType.cs`, `PkiStatus.cs`, `FailInfo.cs`
- Test: `tests/ScepTestClient.Tests/ScepResultTests.cs`

**Acceptance Criteria:**
- [ ] `ScepResult<T>.Ok(value)` has `Status == ScepClientResult.Ok`, the value, and empty `Error`.
- [ ] `ScepResult<T>.Fail(status, error)` carries the status and message and a default value.
- [ ] Enums use the RFC 8894 numeric values (PKCSReq=19, RenewalReq=17, CertPoll=20, GetCert=21, GetCRL=22, CertRep=3; SUCCESS=0, FAILURE=2, PENDING=3; badAlg=0…badCertId=4).

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter ScepResultTests` → all pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/ScepResultTests.cs`

```csharp
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public class ScepResultTests
{
    [Fact]
    public void Ok_carries_value_and_no_error()
    {
        ScepResult<int> result;

        result = ScepResult<int>.Ok(42);

        Assert.Equal(ScepClientResult.Ok, result.Status);
        Assert.Equal(42, result.Value);
        Assert.Equal(string.Empty, result.Error);
        Assert.True(result.IsOk);
    }

    [Fact]
    public void Fail_carries_status_and_message()
    {
        ScepResult<int> result;

        result = ScepResult<int>.Fail(ScepClientResult.NetworkError, "boom");

        Assert.Equal(ScepClientResult.NetworkError, result.Status);
        Assert.Equal("boom", result.Error);
        Assert.False(result.IsOk);
    }

    [Fact]
    public void Scep_enum_values_match_rfc8894()
    {
        Assert.Equal(19, (int)MessageType.PkcsReq);
        Assert.Equal(17, (int)MessageType.RenewalReq);
        Assert.Equal(20, (int)MessageType.CertPoll);
        Assert.Equal(3, (int)MessageType.CertRep);
        Assert.Equal(2, (int)PkiStatus.Failure);
        Assert.Equal(3, (int)PkiStatus.Pending);
        Assert.Equal(4, (int)FailInfo.BadCertId);
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `dotnet test tests/ScepTestClient.Tests --filter ScepResultTests` → FAIL (types not defined).

- [ ] **Step 3: Implement the types**

`ScepClientResult.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

public enum ScepClientResult
{
    Ok = 0,
    InvalidArgument,
    NetworkError,
    ProtocolError,
    CryptoError,
    ServerFailure,   // SCEP pkiStatus FAILURE
    Pending,         // SCEP pkiStatus PENDING
    StorageError,
    NotFound,
    ProviderError,
}
```

`ScepResult.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

public readonly struct ScepResult<T>
{
    public ScepClientResult Status { get; }
    public T Value { get; }
    public string Error { get; }

    private ScepResult(ScepClientResult status, T value, string error)
    {
        Status = status;
        Value = value;
        Error = error;
    }

    public bool IsOk => Status == ScepClientResult.Ok;

    public static ScepResult<T> Ok(T value) => new(ScepClientResult.Ok, value, string.Empty);

    public static ScepResult<T> Fail(ScepClientResult status, string error) =>
        new(status, default!, error);
}
```

`CodecOptions.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

[Flags]
public enum CodecOptions
{
    Strict = 0,
    LenientParsing = 1,
    SkipSignatureVerification = 2,
    AllowLegacyAlgorithms = 4,
}
```

`ConformanceNote.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

public enum NoteSeverity { Info, Warning }

public sealed record ConformanceNote(NoteSeverity Severity, string What, string Where, string RfcReference);
```

`MessageType.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

public enum MessageType
{
    CertRep = 3,
    RenewalReq = 17,
    PkcsReq = 19,
    CertPoll = 20,
    GetCert = 21,
    GetCrl = 22,
}
```

`PkiStatus.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

public enum PkiStatus { Success = 0, Failure = 2, Pending = 3 }
```

`FailInfo.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

public enum FailInfo { BadAlg = 0, BadMessageCheck = 1, BadRequest = 2, BadTime = 3, BadCertId = 4, None = -1 }
```

- [ ] **Step 4: Run to verify pass** — `dotnet test tests/ScepTestClient.Tests --filter ScepResultTests` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "CryptoApi: result types and SCEP enums"`

---

### Task 2: CryptoApi — algorithm registry & KeySpec

**Goal:** OID↔name mapping tagged by `AlgorithmKind`, plus `KeySpec.Parse` for `rsa:2048` style identifiers.

**Files:**
- Create: `src/ScepTestClient.CryptoApi/AlgorithmKind.cs`, `Algorithms.cs`, `KeySpec.cs`
- Test: `tests/ScepTestClient.Tests/AlgorithmsTests.cs`

**Acceptance Criteria:**
- [ ] `Algorithms.OidFor("SHA-256") == "2.16.840.1.101.3.4.2.1"` and `Algorithms.NameFor(that) == "SHA-256"`.
- [ ] `Algorithms.KindOf("2.16.840.1.101.3.4.1.2") == AlgorithmKind.ContentEncryption` (AES-128-CBC).
- [ ] `KeySpec.Parse("rsa:2048", out spec, out error)` yields `spec.Algorithm == "RSA"`, `spec.Size == 2048`.
- [ ] Unknown name/oid returns `false`/empty, never throws.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter AlgorithmsTests` → all pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/AlgorithmsTests.cs`

```csharp
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public class AlgorithmsTests
{
    [Fact]
    public void Name_and_oid_round_trip()
    {
        Assert.Equal("2.16.840.1.101.3.4.2.1", Algorithms.OidFor("SHA-256"));
        Assert.Equal("SHA-256", Algorithms.NameFor("2.16.840.1.101.3.4.2.1"));
    }

    [Fact]
    public void Kind_is_tagged_per_oid()
    {
        Assert.Equal(AlgorithmKind.Digest, Algorithms.KindOf("2.16.840.1.101.3.4.2.1"));
        Assert.Equal(AlgorithmKind.ContentEncryption, Algorithms.KindOf("2.16.840.1.101.3.4.1.2"));
    }

    [Fact]
    public void Unknown_name_returns_null_not_throw()
    {
        Assert.Null(Algorithms.OidFor("NOPE"));
    }

    [Fact]
    public void KeySpec_parses_rsa()
    {
        KeySpec spec;
        string error;
        bool ok;

        ok = KeySpec.Parse("rsa:2048", out spec, out error);

        Assert.True(ok);
        Assert.Equal("RSA", spec.Algorithm);
        Assert.Equal(2048, spec.Size);
    }

    [Fact]
    public void KeySpec_rejects_garbage()
    {
        KeySpec spec;
        string error;

        Assert.False(KeySpec.Parse("banana", out spec, out error));
        Assert.NotEqual(string.Empty, error);
    }
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement**

`AlgorithmKind.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

public enum AlgorithmKind
{
    Digest,
    Signature,
    ContentEncryption,
    KeyTransport,
    Kem,
    AsymmetricKey,
}
```

`Algorithms.cs`:
```csharp
using System.Collections.Generic;

namespace ScepTestClient.CryptoApi;

public sealed record AlgorithmEntry(string Name, string Oid, AlgorithmKind Kind);

public static class Algorithms
{
    // Phase 1 ships the classical set; Phase 4 adds PQ entries here with no contract change.
    private static readonly AlgorithmEntry[] Entries =
    {
        new("SHA-1",       "1.3.14.3.2.26",                 AlgorithmKind.Digest),
        new("SHA-256",     "2.16.840.1.101.3.4.2.1",        AlgorithmKind.Digest),
        new("SHA-512",     "2.16.840.1.101.3.4.2.3",        AlgorithmKind.Digest),
        new("MD5",         "1.2.840.113549.2.5",            AlgorithmKind.Digest),
        new("AES-128-CBC", "2.16.840.1.101.3.4.1.2",        AlgorithmKind.ContentEncryption),
        new("AES-256-CBC", "2.16.840.1.101.3.4.1.42",       AlgorithmKind.ContentEncryption),
        new("DES-EDE3-CBC","1.2.840.113549.3.7",            AlgorithmKind.ContentEncryption),
        new("RSA",         "1.2.840.113549.1.1.1",          AlgorithmKind.AsymmetricKey),
    };

    private static readonly Dictionary<string, AlgorithmEntry> ByName =
        BuildIndex(static e => e.Name);
    private static readonly Dictionary<string, AlgorithmEntry> ByOid =
        BuildIndex(static e => e.Oid);

    private static Dictionary<string, AlgorithmEntry> BuildIndex(System.Func<AlgorithmEntry, string> key)
    {
        Dictionary<string, AlgorithmEntry> map;

        map = new Dictionary<string, AlgorithmEntry>(System.StringComparer.OrdinalIgnoreCase);
        foreach (AlgorithmEntry entry in Entries)
        {
            map[key(entry)] = entry;
        }
        return map;
    }

    public static string? OidFor(string name) => ByName.TryGetValue(name, out AlgorithmEntry? e) ? e.Oid : null;

    public static string? NameFor(string oid) => ByOid.TryGetValue(oid, out AlgorithmEntry? e) ? e.Name : null;

    public static AlgorithmKind? KindOf(string oid) => ByOid.TryGetValue(oid, out AlgorithmEntry? e) ? e.Kind : null;
}
```

`KeySpec.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

public sealed class KeySpec
{
    public string Algorithm { get; }
    public int Size { get; }
    public string Raw { get; }

    private KeySpec(string algorithm, int size, string raw)
    {
        Algorithm = algorithm;
        Size = size;
        Raw = raw;
    }

    // Phase 1 understands "rsa:<bits>". Phase 4 extends parsing (ec:, ml-dsa:, composite) here only.
    public static bool Parse(string text, out KeySpec spec, out string error)
    {
        string[] parts;
        int bits;

        spec = null!;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(text))
        {
            error = "key spec is empty";
            return false;
        }

        parts = text.Split(':');
        if (parts.Length != 2 || !parts[0].Equals("rsa", System.StringComparison.OrdinalIgnoreCase))
        {
            error = $"unsupported key spec '{text}' (expected 'rsa:<bits>')";
            return false;
        }

        if (!int.TryParse(parts[1], out bits) || bits < 1024)
        {
            error = $"invalid RSA size in '{text}'";
            return false;
        }

        spec = new KeySpec("RSA", bits, text);
        return true;
    }
}
```

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `git commit -am "CryptoApi: algorithm registry and KeySpec"`

---

### Task 3: CryptoApi — crypto contract & domain objects

**Goal:** Define `IScepCrypto` plus the always-valid `Pkcs10`/`PkiMessage` objects whose `Encode`/`Decode` delegate to a provider (no crypto in the objects).

**Files:**
- Create: `src/ScepTestClient.CryptoApi/IScepKey.cs`, `CryptoCapabilities.cs`, `FaultDirectives.cs`, `Pkcs10.cs`, `PkiMessage.cs`, `IScepCrypto.cs`
- Test: `tests/ScepTestClient.Tests/DomainObjectTests.cs`

**Acceptance Criteria:**
- [ ] `Pkcs10.SetSubject("")` returns `false` with an error (always-valid invariant); a good DN succeeds.
- [ ] `pki.Encode(fakeCrypto, ...)` calls `IScepCrypto.EncodePkiMessage` exactly once and returns its bytes.
- [ ] `PkiMessage.Decode(fakeCrypto, bytes, key, options, ...)` calls `IScepCrypto.DecodePkiMessage` once and surfaces the populated message.
- [ ] `FaultDirectives` exists (minimal) so the encode signature is stable for Phase 3.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter DomainObjectTests` → all pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/DomainObjectTests.cs`

```csharp
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public class DomainObjectTests
{
    private sealed class FakeCrypto : IScepCrypto
    {
        public int EncodeCalls;
        public int DecodeCalls;
        public CryptoCapabilities Capabilities => new();

        public bool GenerateKey(KeySpec spec, out IScepKey key, out string error)
        { key = null!; error = "not used"; return false; }

        public bool EncodeCsr(Pkcs10 csr, out byte[] der, out string error)
        { der = new byte[] { 1 }; error = string.Empty; return true; }

        public bool EncodePkiMessage(PkiMessage message, FaultDirectives? faults, out byte[] der, out string error)
        { EncodeCalls++; der = new byte[] { 9, 9 }; error = string.Empty; return true; }

        public bool DecodePkiMessage(byte[] der, IScepKey recipientKey, CodecOptions options, out PkiMessage message, out string error)
        { DecodeCalls++; message = new PkiMessage { MessageType = MessageType.CertRep }; error = string.Empty; return true; }

        public bool ParseCaCertificates(byte[] der, out IReadOnlyList<X509Certificate2> certs, out string error)
        { certs = System.Array.Empty<X509Certificate2>(); error = string.Empty; return true; }
    }

    [Fact]
    public void Subject_must_be_non_empty()
    {
        Pkcs10 csr;
        string error;

        csr = new Pkcs10();
        Assert.False(csr.SetSubject("", out error));
        Assert.True(csr.SetSubject("CN=poodle", out error));
        Assert.Equal("CN=poodle", csr.Subject);
    }

    [Fact]
    public void Encode_delegates_to_provider()
    {
        FakeCrypto crypto;
        PkiMessage pki;
        byte[] der;
        string error;

        crypto = new FakeCrypto();
        pki = new PkiMessage { MessageType = MessageType.PkcsReq };

        Assert.True(pki.Encode(crypto, out der, out error));
        Assert.Equal(1, crypto.EncodeCalls);
        Assert.Equal(new byte[] { 9, 9 }, der);
    }

    [Fact]
    public void Decode_delegates_to_provider()
    {
        FakeCrypto crypto;
        PkiMessage parsed;
        string error;

        crypto = new FakeCrypto();

        Assert.True(PkiMessage.Decode(crypto, new byte[] { 0 }, key: null!, CodecOptions.LenientParsing, out parsed, out error));
        Assert.Equal(1, crypto.DecodeCalls);
        Assert.Equal(MessageType.CertRep, parsed.MessageType);
    }
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement the contract & objects**

`IScepKey.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

/// <summary>Opaque, provider-owned key handle. Implementations live in provider DLLs.</summary>
public interface IScepKey
{
    string AlgorithmOid { get; }   // e.g. RSA OID; PQ OIDs in Phase 4
    int SizeBits { get; }
}
```

`CryptoCapabilities.cs`:
```csharp
using System.Collections.Generic;

namespace ScepTestClient.CryptoApi;

/// <summary>Algorithm OIDs the loaded provider supports, grouped by kind. PQ tiers added in Phase 4.</summary>
public sealed class CryptoCapabilities
{
    public IReadOnlyCollection<string> Digests { get; init; } = System.Array.Empty<string>();
    public IReadOnlyCollection<string> Signatures { get; init; } = System.Array.Empty<string>();
    public IReadOnlyCollection<string> ContentEncryption { get; init; } = System.Array.Empty<string>();
    public IReadOnlyCollection<string> KeyTransport { get; init; } = System.Array.Empty<string>();
    public IReadOnlyCollection<string> Kem { get; init; } = System.Array.Empty<string>();
    public IReadOnlyCollection<string> AsymmetricKeys { get; init; } = System.Array.Empty<string>();
}
```

`FaultDirectives.cs`:
```csharp
namespace ScepTestClient.CryptoApi;

/// <summary>
/// Deliberate non-compliance applied at encode time. Empty in Phase 1 (always passed null);
/// Phase 3 fills it in. Present now so IScepCrypto.EncodePkiMessage keeps a stable signature.
/// </summary>
public sealed class FaultDirectives
{
}
```

`Pkcs10.cs`:
```csharp
using System.Collections.Generic;

namespace ScepTestClient.CryptoApi;

/// <summary>
/// A certificate request as structured data. Holds no crypto. Validates on set so it can never
/// represent a malformed-where-checkable state. Encode delegates to the provider.
/// </summary>
public sealed class Pkcs10
{
    public string Subject { get; private set; } = string.Empty;
    public IScepKey? Key { get; set; }
    public string? ChallengePassword { get; set; }
    public List<string> DnsNames { get; } = new();
    public List<string> Upns { get; } = new();
    public string? Sid { get; set; }
    public List<string> Ekus { get; } = new();
    public string? TemplateName { get; set; }
    public List<(string Oid, byte[] Value, bool Critical)> Extensions { get; } = new();

    public bool SetSubject(string subject, out string error)
    {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(subject))
        {
            error = "subject DN must be non-empty";
            return false;
        }
        Subject = subject;
        return true;
    }

    public bool Encode(IScepCrypto crypto, out byte[] der, out string error) =>
        crypto.EncodeCsr(this, out der, out error);
}
```

`PkiMessage.cs`:
```csharp
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ScepTestClient.CryptoApi;

/// <summary>
/// A SCEP pkiMessage as structured data. Holds no crypto. Encode/Decode delegate to the provider.
/// Inbound (decoded) fields are populated by the provider; outbound fields are set by the caller.
/// </summary>
public sealed class PkiMessage
{
    // Outbound
    public MessageType MessageType { get; set; }
    public X509Certificate2? RecipientCaCert { get; set; }
    public X509Certificate2? SignerCert { get; set; }
    public IScepKey? SignerKey { get; set; }
    public Pkcs10? InnerCsr { get; set; }
    public string DigestAlgorithmOid { get; set; } = Algorithms.OidFor("SHA-256")!;
    public string ContentEncryptionAlgorithmOid { get; set; } = Algorithms.OidFor("AES-128-CBC")!;
    public string? TransactionId { get; set; }

    // Inbound (set on Decode)
    public PkiStatus PkiStatus { get; set; }
    public FailInfo FailInfo { get; set; } = FailInfo.None;
    public string? FailInfoText { get; set; }
    public byte[]? SenderNonce { get; set; }
    public byte[]? RecipientNonce { get; set; }
    public bool SignatureValid { get; set; }
    public byte[]? DecryptedContent { get; set; }
    public IReadOnlyList<X509Certificate2> IssuedCerts { get; set; } = System.Array.Empty<X509Certificate2>();
    public List<ConformanceNote> ConformanceNotes { get; } = new();

    public bool Encode(IScepCrypto crypto, out byte[] der, out string error) =>
        crypto.EncodePkiMessage(this, faults: null, out der, out error);

    public bool Encode(IScepCrypto crypto, FaultDirectives? faults, out byte[] der, out string error) =>
        crypto.EncodePkiMessage(this, faults, out der, out error);

    public static bool Decode(IScepCrypto crypto, byte[] der, IScepKey key, CodecOptions options,
                              out PkiMessage message, out string error) =>
        crypto.DecodePkiMessage(der, key, options, out message, out error);
}
```

`IScepCrypto.cs`:
```csharp
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ScepTestClient.CryptoApi;

/// <summary>The one crypto seam. Provider DLLs implement this; Core never references a crypto library.</summary>
public interface IScepCrypto
{
    CryptoCapabilities Capabilities { get; }

    bool GenerateKey(KeySpec spec, out IScepKey key, out string error);

    bool EncodeCsr(Pkcs10 csr, out byte[] der, out string error);

    bool EncodePkiMessage(PkiMessage message, FaultDirectives? faults, out byte[] der, out string error);

    bool DecodePkiMessage(byte[] der, IScepKey recipientKey, CodecOptions options,
                          out PkiMessage message, out string error);

    bool ParseCaCertificates(byte[] der, out IReadOnlyList<X509Certificate2> certs, out string error);
}
```

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: PQ interface validation (paper task — Phase 1 spec requirement).** Write a comment block at the top of `IScepCrypto.cs` confirming the three PQ tiers slot in without signature changes, then commit it:

```csharp
// PQ readiness check (validated 2026-06-19):
//  Tier A (PQ end-entity key): KeySpec gains "ml-dsa:65" etc.; GenerateKey returns an IScepKey
//      with a PQ AlgorithmOid; EncodeCsr emits a PQ SubjectPublicKeyInfo. No signature change.
//  Tier B (catalyst alt-key): add optional alt-key fields to Pkcs10 (new properties, ignored by
//      existing callers). No interface change.
//  Tier C (PQ transport / ML-KEM envelope): EncodePkiMessage already takes the recipient via
//      PkiMessage.RecipientCaCert; a PQ recipient triggers KEMRecipientInfo inside the provider.
//      No signature change.
```

- [ ] **Step 6: Commit** — `git commit -am "CryptoApi: IScepCrypto contract and domain objects"`

---

### Task 4: BouncyCastle provider — key generation & capabilities

**Goal:** `BouncyCastleScepCrypto.GenerateKey` (RSA) and `Capabilities` advertising the classical algorithm set.

**Files:**
- Create: `src/ScepTestClient.Crypto.BouncyCastle/BcKey.cs`, `BcAlgorithms.cs`, `BouncyCastleScepCrypto.cs`
- Test: `tests/ScepTestClient.Tests/BcKeyTests.cs`

**Acceptance Criteria:**
- [ ] `GenerateKey(KeySpec.Parse("rsa:2048"), …)` returns a key with `AlgorithmOid == RSA OID`, `SizeBits == 2048`.
- [ ] `Capabilities.Digests` contains the SHA-256 OID; `ContentEncryption` contains the AES-128-CBC OID.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter BcKeyTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/BcKeyTests.cs`

```csharp
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using Xunit;

namespace ScepTestClient.Tests;

public class BcKeyTests
{
    [Fact]
    public void Generates_rsa_2048()
    {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("rsa:2048", out spec, out _));
        Assert.True(crypto.GenerateKey(spec, out key, out error));
        Assert.Equal("1.2.840.113549.1.1.1", key.AlgorithmOid);
        Assert.Equal(2048, key.SizeBits);
    }

    [Fact]
    public void Advertises_classical_algorithms()
    {
        BouncyCastleScepCrypto crypto;

        crypto = new BouncyCastleScepCrypto();
        Assert.Contains("2.16.840.1.101.3.4.2.1", crypto.Capabilities.Digests);
        Assert.Contains("2.16.840.1.101.3.4.1.2", crypto.Capabilities.ContentEncryption);
    }
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement**

`BcKey.cs`:
```csharp
using Org.BouncyCastle.Crypto;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Crypto.BouncyCastle;

internal sealed class BcKey : IScepKey
{
    public AsymmetricCipherKeyPair KeyPair { get; }
    public string AlgorithmOid { get; }
    public int SizeBits { get; }

    public BcKey(AsymmetricCipherKeyPair keyPair, string algorithmOid, int sizeBits)
    {
        KeyPair = keyPair;
        AlgorithmOid = algorithmOid;
        SizeBits = sizeBits;
    }
}
```

`BcAlgorithms.cs` (OID constants used across provider files):
```csharp
namespace ScepTestClient.Crypto.BouncyCastle;

internal static class BcAlgorithms
{
    public const string Rsa = "1.2.840.113549.1.1.1";
    public const string Sha1 = "1.3.14.3.2.26";
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";
    public const string Md5 = "1.2.840.113549.2.5";
    public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
    public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";
    public const string Des3Cbc = "1.2.840.113549.3.7";
}
```

`BouncyCastleScepCrypto.cs` (key-gen + capabilities portion; CSR/CMS added in Tasks 5–7):
```csharp
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Crypto.BouncyCastle;

/// <summary>Default crypto provider. The only project allowed to reference BouncyCastle.</summary>
public sealed class BouncyCastleScepCrypto : IScepCrypto
{
    private readonly SecureRandom _random = new();

    public CryptoCapabilities Capabilities { get; } = new()
    {
        Digests = new[] { BcAlgorithms.Sha1, BcAlgorithms.Sha256, BcAlgorithms.Sha512, BcAlgorithms.Md5 },
        Signatures = new[] { BcAlgorithms.Rsa },
        ContentEncryption = new[] { BcAlgorithms.Aes128Cbc, BcAlgorithms.Aes256Cbc, BcAlgorithms.Des3Cbc },
        KeyTransport = new[] { BcAlgorithms.Rsa },
        AsymmetricKeys = new[] { BcAlgorithms.Rsa },
    };

    public bool GenerateKey(KeySpec spec, out IScepKey key, out string error)
    {
        RsaKeyPairGenerator generator;
        AsymmetricCipherKeyPair pair;

        key = null!;
        error = string.Empty;

        if (!spec.Algorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase))
        {
            error = $"provider does not support key algorithm '{spec.Algorithm}'";
            return false;
        }

        try
        {
            generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(_random, spec.Size));
            pair = generator.GenerateKeyPair();
            key = new BcKey(pair, BcAlgorithms.Rsa, spec.Size);
            return true;
        }
        catch (Exception ex)
        {
            error = $"RSA key generation failed: {ex.Message}";
            return false;
        }
    }

    // EncodeCsr / EncodePkiMessage / DecodePkiMessage / ParseCaCertificates added in Tasks 5–7.
    public bool EncodeCsr(Pkcs10 csr, out byte[] der, out string error) => throw new NotImplementedException();
    public bool EncodePkiMessage(PkiMessage message, FaultDirectives? faults, out byte[] der, out string error) => throw new NotImplementedException();
    public bool DecodePkiMessage(byte[] der, IScepKey recipientKey, CodecOptions options, out PkiMessage message, out string error) => throw new NotImplementedException();
    public bool ParseCaCertificates(byte[] der, out IReadOnlyList<X509Certificate2> certs, out string error) => throw new NotImplementedException();
}
```

> Note: the four `NotImplementedException` stubs are temporary scaffolding **filled in by Tasks 5–7 in this same plan** — they are not a delivered state. Each subsequent task replaces one stub with a tested implementation.

- [ ] **Step 4: Run to verify pass.** (Only `GenerateKey`/`Capabilities` are exercised here.)

- [ ] **Step 5: Commit** — `git commit -am "BC provider: RSA key generation and capabilities"`

---

### Task 5: BouncyCastle provider — CSR encode

**Goal:** Implement `EncodeCsr` — Subject DN, public key, challenge-password attribute, SAN (DNS + UPN otherName), MS SID extension, EKU, MS template, and arbitrary extensions.

**Files:**
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs`
- Create: `src/ScepTestClient.Crypto.BouncyCastle/BcCsrBuilder.cs`
- Test: `tests/ScepTestClient.Tests/BcCsrTests.cs`

**Acceptance Criteria:**
- [ ] The encoded CSR parses back (via BouncyCastle `Pkcs10CertificationRequest`) with the expected Subject and a verifying signature.
- [ ] The `challengePassword` PKCS#9 attribute (OID `1.2.840.113549.1.9.7`) is present with the supplied value.
- [ ] A `--sid` request emits the `szOID_NTDS_CA_SECURITY_EXT` extension (OID `1.3.6.1.4.1.311.25.2`).

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter BcCsrTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/BcCsrTests.cs`

```csharp
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using Xunit;

namespace ScepTestClient.Tests;

public class BcCsrTests
{
    [Fact]
    public void Builds_signed_csr_with_subject_and_challenge()
    {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        byte[] der;
        string error;
        Pkcs10CertificationRequest parsed;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key, ChallengePassword = "s3cret", Sid = "S-1-5-21-1-2-3-1000" };
        Assert.True(csr.SetSubject("CN=poodle", out _));

        Assert.True(crypto.EncodeCsr(csr, out der, out error));

        parsed = new Pkcs10CertificationRequest(der);
        Assert.True(parsed.Verify());
        Assert.Contains("poodle", parsed.GetCertificationRequestInfo().Subject.ToString());
    }
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement `BcCsrBuilder`** — `src/ScepTestClient.Crypto.BouncyCastle/BcCsrBuilder.cs`

```csharp
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Crypto.BouncyCastle;

internal static class BcCsrBuilder
{
    private const string ChallengePasswordOid = "1.2.840.113549.1.9.7";
    private const string ExtensionRequestOid = "1.2.840.113549.1.9.14";
    private const string SidExtensionOid = "1.3.6.1.4.1.311.25.2";
    private const string UpnOtherNameOid = "1.3.6.1.4.1.311.20.2.3";

    public static byte[] Build(Pkcs10 csr, BcKey key)
    {
        X509Name subject;
        ISignatureFactory signer;
        List<Asn1Encodable> attributes;
        Asn1Set attributeSet;
        Pkcs10CertificationRequest request;

        subject = new X509Name(csr.Subject);
        signer = new Asn1SignatureFactory("SHA256WITHRSA", key.KeyPair.Private);

        attributes = new List<Asn1Encodable>();
        if (!string.IsNullOrEmpty(csr.ChallengePassword))
        {
            attributes.Add(new AttributePkcs(
                new DerObjectIdentifier(ChallengePasswordOid),
                new DerSet(new DerPrintableString(csr.ChallengePassword))));
        }

        X509Extensions extensions;
        extensions = BuildExtensions(csr);
        if (extensions is not null)
        {
            attributes.Add(new AttributePkcs(
                new DerObjectIdentifier(ExtensionRequestOid),
                new DerSet(extensions)));
        }

        attributeSet = new DerSet(attributes.ToArray());
        request = new Pkcs10CertificationRequest(signer, subject, key.KeyPair.Public, attributeSet);
        return request.GetEncoded();
    }

    private static X509Extensions BuildExtensions(Pkcs10 csr)
    {
        X509ExtensionsGenerator gen;
        bool any;

        gen = new X509ExtensionsGenerator();
        any = false;

        List<GeneralName> sans;
        sans = new List<GeneralName>();
        foreach (string dns in csr.DnsNames) sans.Add(new GeneralName(GeneralName.DnsName, dns));
        foreach (string upn in csr.Upns)
        {
            sans.Add(new GeneralName(GeneralName.OtherName, new DerSequence(
                new DerObjectIdentifier(UpnOtherNameOid),
                new DerTaggedObject(true, 0, new DerUtf8String(upn)))));
        }
        if (sans.Count > 0)
        {
            gen.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(sans.ToArray()));
            any = true;
        }

        if (!string.IsNullOrEmpty(csr.Sid))
        {
            // szOID_NTDS_CA_SECURITY_EXT: SEQUENCE { OtherName { 1.3.6.1.4.1.311.25.2.1, [0] OCTET STRING sid } }
            DerOctetString sidValue;
            sidValue = new DerOctetString(System.Text.Encoding.ASCII.GetBytes(csr.Sid!));
            DerSequence sidSeq;
            sidSeq = new DerSequence(
                new DerObjectIdentifier("1.3.6.1.4.1.311.25.2.1"),
                new DerTaggedObject(true, 0, sidValue));
            gen.AddExtension(new DerObjectIdentifier(SidExtensionOid), false, new DerSequence(sidSeq));
            any = true;
        }

        foreach ((string oid, byte[] value, bool critical) in csr.Extensions)
        {
            gen.AddExtension(new DerObjectIdentifier(oid), critical, value);
            any = true;
        }

        return any ? gen.Generate() : null!;
    }
}
```

- [ ] **Step 4: Wire it into the provider** — replace the `EncodeCsr` stub:

```csharp
public bool EncodeCsr(Pkcs10 csr, out byte[] der, out string error)
{
    der = System.Array.Empty<byte>();
    error = string.Empty;

    if (csr.Key is not BcKey bcKey)
    {
        error = "CSR key was not produced by this provider";
        return false;
    }

    try
    {
        der = BcCsrBuilder.Build(csr, bcKey);
        return true;
    }
    catch (System.Exception ex)
    {
        error = $"CSR encode failed: {ex.Message}";
        return false;
    }
}
```

- [ ] **Step 5: Run to verify pass.**

- [ ] **Step 6: Commit** — `git commit -am "BC provider: PKCS#10 CSR encode with SAN/SID/EKU/challenge"`

---

### Task 6: BouncyCastle provider — pkiMessage encode (PKCSReq) & GetCACert parse

**Goal:** `EncodePkiMessage` for a PKCSReq (SignedData over EnvelopedData of the CSR, with SCEP signed attributes) and `ParseCaCertificates` for the degenerate-PKCS#7 GetCACert response.

**Files:**
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs`
- Create: `src/ScepTestClient.Crypto.BouncyCastle/BcPkiMessage.cs`, `BcSelfSigned.cs`, `ScepAttributes.cs`
- Test: `tests/ScepTestClient.Tests/BcEncodeTests.cs`

**Acceptance Criteria:**
- [ ] The encoded PKCSReq parses as a CMS `SignedData` whose signed attributes include `messageType == "19"` and a non-empty `transId`, and whose encapsulated content is a CMS `EnvelopedData`.
- [ ] `ParseCaCertificates` over a degenerate PKCS#7 containing one cert returns that cert.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter BcEncodeTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/BcEncodeTests.cs`

```csharp
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using Xunit;

namespace ScepTestClient.Tests;

public class BcEncodeTests
{
    private const string MessageTypeOid = "2.16.840.1.113733.1.9.2";

    [Fact]
    public void Encodes_pkcsreq_signeddata_over_envelopeddata()
    {
        BouncyCastleScepCrypto crypto;
        TestCa ca;
        IScepKey key;
        Pkcs10 csr;
        PkiMessage pki;
        byte[] der;
        string error;
        CmsSignedData signed;

        crypto = new BouncyCastleScepCrypto();
        ca = TestCa.Create();
        KeySpec.Parse("rsa:2048", out KeySpec spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key, ChallengePassword = "pw" };
        csr.SetSubject("CN=poodle", out _);

        pki = new PkiMessage
        {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = key,
            RecipientCaCert = ca.CertificateBcl,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);

        signed = new CmsSignedData(der);
        SignerInformation signer;
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        Org.BouncyCastle.Asn1.Cms.Attribute msgType;
        msgType = signer.SignedAttributes[new DerObjectIdentifier(MessageTypeOid)];
        Assert.Equal("19", ((DerPrintableString)msgType.AttrValues[0]).GetString());
        Assert.Equal(CmsObjectIdentifiers.EnvelopedData.Id, signed.SignedContentType.Id);
    }
}
```

- [ ] **Step 2: Add the shared `TestCa` fixture** — `tests/ScepTestClient.Tests/Fakes/TestCa.cs` (reused by Task 7 and the FakeScepServer in Task 14):

```csharp
using System;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ScepTestClient.Tests.Fakes;

/// <summary>A minimal in-test CA: self-signed CA cert + the ability to issue end-entity certs from a CSR public key.</summary>
public sealed class TestCa
{
    public AsymmetricCipherKeyPair KeyPair { get; }
    public Org.BouncyCastle.X509.X509Certificate Certificate { get; }
    public X509Certificate2 CertificateBcl { get; }

    private TestCa(AsymmetricCipherKeyPair keyPair, Org.BouncyCastle.X509.X509Certificate cert)
    {
        KeyPair = keyPair;
        Certificate = cert;
        CertificateBcl = new X509Certificate2(cert.GetEncoded());
    }

    public static TestCa Create()
    {
        RsaKeyPairGenerator gen;
        AsymmetricCipherKeyPair pair;
        X509V3CertificateGenerator cg;
        X509Name name;

        gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        pair = gen.GenerateKeyPair();

        name = new X509Name("CN=Test SCEP CA");
        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.One);
        cg.SetIssuerDN(name);
        cg.SetSubjectDN(name);
        cg.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(5));
        cg.SetPublicKey(pair.Public);

        return new TestCa(pair, cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", pair.Private)));
    }

    public Org.BouncyCastle.X509.X509Certificate Issue(Org.BouncyCastle.Crypto.AsymmetricKeyParameter subjectPublicKey, string subjectDn)
    {
        X509V3CertificateGenerator cg;

        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks & 0x7fffffff));
        cg.SetIssuerDN(Certificate.SubjectDN);
        cg.SetSubjectDN(new X509Name(subjectDn));
        cg.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(1));
        cg.SetPublicKey(subjectPublicKey);
        return cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", KeyPair.Private));
    }
}
```

- [ ] **Step 3: Run to verify the test fails** (compile error / NotImplemented).

- [ ] **Step 4: Implement the SCEP attributes & encode**

`ScepAttributes.cs`:
```csharp
namespace ScepTestClient.Crypto.BouncyCastle;

internal static class ScepAttributes
{
    public const string MessageType = "2.16.840.1.113733.1.9.2";
    public const string PkiStatus = "2.16.840.1.113733.1.9.3";
    public const string FailInfo = "2.16.840.1.113733.1.9.4";
    public const string SenderNonce = "2.16.840.1.113733.1.9.5";
    public const string RecipientNonce = "2.16.840.1.113733.1.9.6";
    public const string TransId = "2.16.840.1.113733.1.9.7";
}
```

`BcSelfSigned.cs` (self-signed cert for a PKCSReq signer):
```csharp
using System;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace ScepTestClient.Crypto.BouncyCastle;

internal static class BcSelfSigned
{
    public static X509Certificate ForKey(BcKey key, string subjectDn)
    {
        X509V3CertificateGenerator cg;
        X509Name name;

        name = new X509Name(subjectDn);
        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.ValueOf(1));
        cg.SetIssuerDN(name);
        cg.SetSubjectDN(name);
        cg.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        cg.SetNotAfter(DateTime.UtcNow.AddDays(1));
        cg.SetPublicKey(key.KeyPair.Public);
        return cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", key.KeyPair.Private));
    }
}
```

`BcPkiMessage.cs` (encode side):
```csharp
using System;
using System.Collections;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ScepTestClient.CryptoApi;
using BcAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace ScepTestClient.Crypto.BouncyCastle;

internal static class BcPkiMessage
{
    public static byte[] EncodePkcsReq(PkiMessage message, byte[] csrDer, BcKey signerKey)
    {
        byte[] enveloped;
        X509Certificate signerCert;
        string transId;

        enveloped = Envelope(csrDer, message.RecipientCaCert!, message.ContentEncryptionAlgorithmOid);
        signerCert = message.SignerCert is null
            ? BcSelfSigned.ForKey(signerKey, message.InnerCsr!.Subject)
            : DotNetUtilities.FromX509Certificate(message.SignerCert);
        transId = message.TransactionId ?? Guid.NewGuid().ToString("N");

        return Sign(enveloped, signerCert, signerKey, message.DigestAlgorithmOid,
                    BuildSignedAttributes((int)message.MessageType, transId));
    }

    private static byte[] Envelope(byte[] content, X509Certificate2 recipient, string contentEncOid)
    {
        CmsEnvelopedDataGenerator gen;

        gen = new CmsEnvelopedDataGenerator();
        gen.AddKeyTransRecipient(DotNetUtilities.FromX509Certificate(recipient));
        return gen.Generate(new CmsProcessableByteArray(content), contentEncOid).GetEncoded();
    }

    private static byte[] Sign(byte[] content, X509Certificate signerCert, BcKey signerKey,
                               string digestOid, AttributeTable signed)
    {
        CmsSignedDataGenerator gen;
        ArrayList certs;

        gen = new CmsSignedDataGenerator();
        gen.AddSigner(signerKey.KeyPair.Private, signerCert, digestOid, signed, null);
        certs = new ArrayList { signerCert };
        gen.AddCertificates(X509StoreFactory.Create("Certificate/Collection",
            new X509CollectionStoreParameters(certs)));
        // EnvelopedData carried as the SignedData content, content-type tagged EnvelopedData.
        return gen.Generate(CmsObjectIdentifiers.EnvelopedData.Id, new CmsProcessableByteArray(content), true).GetEncoded();
    }

    private static AttributeTable BuildSignedAttributes(int messageType, string transId)
    {
        Hashtable table;

        table = new Hashtable();
        Put(table, ScepAttributes.MessageType, new DerPrintableString(messageType.ToString()));
        Put(table, ScepAttributes.TransId, new DerPrintableString(transId));
        Put(table, ScepAttributes.SenderNonce, new DerOctetString(SecureRandomBytes(16)));
        return new AttributeTable(table);
    }

    private static void Put(Hashtable table, string oid, Asn1Encodable value)
    {
        DerObjectIdentifier id;
        id = new DerObjectIdentifier(oid);
        table[id] = new BcAttribute(id, new DerSet(value));
    }

    private static byte[] SecureRandomBytes(int n)
    {
        byte[] b;
        b = new byte[n];
        new SecureRandom().NextBytes(b);
        return b;
    }
}
```

- [ ] **Step 5: Wire into the provider** — replace the `EncodePkiMessage` and `ParseCaCertificates` stubs:

```csharp
public bool EncodePkiMessage(PkiMessage message, FaultDirectives? faults, out byte[] der, out string error)
{
    der = System.Array.Empty<byte>();
    error = string.Empty;

    if (message.MessageType != MessageType.PkcsReq)
    {
        error = $"Phase 1 encodes PKCSReq only (got {message.MessageType})";
        return false;
    }
    if (message.SignerKey is not BcKey signerKey || message.InnerCsr is null || message.RecipientCaCert is null)
    {
        error = "PKCSReq requires SignerKey, InnerCsr, and RecipientCaCert";
        return false;
    }

    try
    {
        byte[] csrDer;
        if (!EncodeCsr(message.InnerCsr, out csrDer, out error)) return false;
        der = BcPkiMessage.EncodePkcsReq(message, csrDer, signerKey);
        return true;
    }
    catch (System.Exception ex)
    {
        error = $"pkiMessage encode failed: {ex.Message}";
        return false;
    }
}

public bool ParseCaCertificates(byte[] der, out IReadOnlyList<X509Certificate2> certs, out string error)
{
    System.Collections.Generic.List<X509Certificate2> list;

    certs = System.Array.Empty<X509Certificate2>();
    error = string.Empty;
    list = new System.Collections.Generic.List<X509Certificate2>();

    try
    {
        // GetCACert is either a single DER cert or a degenerate PKCS#7 (certs-only SignedData).
        try { list.Add(new X509Certificate2(der)); }
        catch
        {
            Org.BouncyCastle.Cms.CmsSignedData signed;
            signed = new Org.BouncyCastle.Cms.CmsSignedData(der);
            foreach (Org.BouncyCastle.X509.X509Certificate c in
                     signed.GetCertificates().EnumerateMatches(null))
            {
                list.Add(new X509Certificate2(c.GetEncoded()));
            }
        }
        certs = list;
        return list.Count > 0 || (error = "no certificates in GetCACert response") == null;
    }
    catch (System.Exception ex)
    {
        error = $"GetCACert parse failed: {ex.Message}";
        return false;
    }
}
```

- [ ] **Step 6: Run to verify pass.** (BouncyCastle API names like `X509StoreFactory`/`EnumerateMatches` may differ slightly by 2.5.0 — the test is the source of truth; adjust calls until green.)

- [ ] **Step 7: Commit** — `git commit -am "BC provider: PKCSReq encode and GetCACert parse"`

---

### Task 7: BouncyCastle provider — pkiMessage decode (CertRep)

**Goal:** `DecodePkiMessage` — verify the SignedData signature (report, don't hard-fail under lenient), read `pkiStatus`/`failInfo`/nonces from signed attributes, decrypt the EnvelopedData with the recipient key, and extract issued certificates.

**Files:**
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs`, `BcPkiMessage.cs`
- Test: `tests/ScepTestClient.Tests/BcDecodeTests.cs`

**Acceptance Criteria:**
- [ ] Decoding a SUCCESS CertRep (built by `TestCa`, enveloped to the client key) yields `PkiStatus.Success`, `SignatureValid == true`, and one cert in `IssuedCerts`.
- [ ] A signed attribute `pkiStatus == "2"` decodes to `PkiStatus.Failure` with the `failInfo` mapped.
- [ ] Under `CodecOptions.SkipSignatureVerification`, decode never throws on a bad signature and reports `SignatureValid == false`.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter BcDecodeTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/BcDecodeTests.cs` builds a CertRep via a `TestCa.BuildCertRep(...)` helper (add it to `TestCa`), then asserts decode. (The helper signs a CMS SignedData whose content is an EnvelopedData of a degenerate PKCS#7 of the issued cert, with `pkiStatus=0` signed attribute, recipient = the client cert.) Implement `TestCa.BuildCertRep(byte[] clientCertDer, X509Certificate2 clientRecipient, string transId)` returning `byte[]`, and the test:

```csharp
[Fact]
public void Decodes_success_certrep_with_issued_cert()
{
    // arrange: client key + self-signed client cert as the envelope recipient,
    //          TestCa issues a cert for the client key and wraps it in a CertRep.
    // act: crypto.DecodePkiMessage(certRepDer, clientKey, CodecOptions.LenientParsing, out msg, out err)
    // assert: msg.PkiStatus == PkiStatus.Success && msg.SignatureValid && msg.IssuedCerts.Count == 1
}
```

(Full helper + test body are written during execution against the real BouncyCastle 2.5.0 API; the acceptance criteria above are the contract.)

- [ ] **Step 2: Implement decode** in `BcPkiMessage.cs`:

```csharp
public static PkiMessage Decode(byte[] der, BcKey recipientKey, CodecOptions options)
{
    PkiMessage result;
    CmsSignedData signed;
    SignerInformation signer;

    result = new PkiMessage { MessageType = MessageType.CertRep };
    signed = new CmsSignedData(der);

    signer = FirstSigner(signed);
    result.SignatureValid = VerifySignature(signed, signer, options, result.ConformanceNotes);

    ReadStatusAttributes(signer, result);

    byte[] envelopedDer;
    envelopedDer = (byte[])signed.SignedContent.GetContent();
    if (result.PkiStatus == PkiStatus.Success)
    {
        byte[] inner;
        inner = Decrypt(envelopedDer, recipientKey);
        result.DecryptedContent = inner;
        result.IssuedCerts = ExtractCerts(inner);
    }
    return result;
}
```

with helpers `FirstSigner`, `VerifySignature` (returns bool; on failure adds a `ConformanceNote` and, unless `SkipSignatureVerification`, sets the bool false without throwing), `ReadStatusAttributes` (maps `pkiStatus`/`failInfo`/nonces from the signed-attribute OIDs in `ScepAttributes`), `Decrypt` (`CmsEnvelopedData` + `RecipientID` matching `recipientKey`), and `ExtractCerts` (degenerate PKCS#7 → `X509Certificate2[]`).

- [ ] **Step 3: Wire into the provider** — replace the `DecodePkiMessage` stub:

```csharp
public bool DecodePkiMessage(byte[] der, IScepKey recipientKey, CodecOptions options,
                             out PkiMessage message, out string error)
{
    message = null!;
    error = string.Empty;

    if (recipientKey is not BcKey bcKey)
    {
        error = "recipient key was not produced by this provider";
        return false;
    }
    try
    {
        message = BcPkiMessage.Decode(der, bcKey, options);
        return true;
    }
    catch (System.Exception ex)
    {
        error = $"pkiMessage decode failed: {ex.Message}";
        return false;
    }
}
```

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `git commit -am "BC provider: CertRep decode (status, decrypt, issued certs)"`

---

### Task 8: Core — provider loading (`ScepCrypto.Load` + ALC)

**Goal:** Resolve `IScepCrypto` from a configured DLL (isolated ALC) or fall back to the shipped BouncyCastle provider, never throwing.

**Files:**
- Create: `src/ScepTestClient.Core/ScepCrypto.cs`, `src/ScepTestClient.Core/ProviderLoadContext.cs`
- Test: `tests/ScepTestClient.Tests/ProviderLoadTests.cs`

**Acceptance Criteria:**
- [ ] `ScepCrypto.Load(null, out crypto, out error)` returns the built-in BC provider; `crypto.Capabilities.Digests` is non-empty.
- [ ] `ScepCrypto.Load("/does/not/exist.dll", …)` returns `false` with an error, no exception.
- [ ] The CryptoApi assembly is shared (not reloaded) so the returned object casts to `IScepCrypto`.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter ProviderLoadTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/ProviderLoadTests.cs`

```csharp
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public class ProviderLoadTests
{
    [Fact]
    public void Default_load_returns_builtin_bouncycastle()
    {
        IScepCrypto crypto;
        string error;

        Assert.Equal(ScepClientResult.Ok, ScepCrypto.Load(null, out crypto, out error));
        Assert.NotEmpty(crypto.Capabilities.Digests);
    }

    [Fact]
    public void Missing_dll_fails_without_throwing()
    {
        IScepCrypto crypto;
        string error;

        Assert.Equal(ScepClientResult.ProviderError, ScepCrypto.Load("/does/not/exist.dll", out crypto, out error));
        Assert.NotEqual(string.Empty, error);
    }
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement `ProviderLoadContext`** (the standard plugin ALC — shares CryptoApi with the host):

```csharp
using System.Reflection;
using System.Runtime.Loader;

namespace ScepTestClient.Core;

internal sealed class ProviderLoadContext : AssemblyLoadContext
{
    private readonly AssemblyDependencyResolver _resolver;

    public ProviderLoadContext(string providerPath) : base(isCollectible: true)
    {
        _resolver = new AssemblyDependencyResolver(providerPath);
    }

    protected override Assembly? Load(AssemblyName name)
    {
        string? path;

        // Share the contract assembly with the host so IScepCrypto keeps one Type identity.
        if (name.Name == "ScepTestClient.CryptoApi")
        {
            return null;
        }

        path = _resolver.ResolveAssemblyToPath(name);
        return path is null ? null : LoadFromAssemblyPath(path);
    }
}
```

- [ ] **Step 4: Implement `ScepCrypto.Load`**

```csharp
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

public static class ScepCrypto
{
    private const string BuiltInDll = "ScepTestClient.Crypto.BouncyCastle.dll";

    public static ScepClientResult Load(string? configuredDllPath, out IScepCrypto crypto, out string error)
    {
        string path;
        Assembly assembly;
        Type? implType;

        crypto = null!;
        error = string.Empty;

        path = string.IsNullOrWhiteSpace(configuredDllPath)
            ? Path.Combine(AppContext.BaseDirectory, BuiltInDll)
            : configuredDllPath!;

        if (!File.Exists(path))
        {
            error = $"crypto provider DLL not found: {path}";
            return ScepClientResult.ProviderError;
        }

        try
        {
            assembly = string.IsNullOrWhiteSpace(configuredDllPath)
                ? AssemblyLoadContext.Default.LoadFromAssemblyPath(path)   // built-in: same context
                : new ProviderLoadContext(path).LoadFromAssemblyPath(path); // external: isolated
            implType = assembly.GetTypes().FirstOrDefault(t =>
                typeof(IScepCrypto).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface);
            if (implType is null)
            {
                error = $"no IScepCrypto implementation found in {Path.GetFileName(path)}";
                return ScepClientResult.ProviderError;
            }
            crypto = (IScepCrypto)Activator.CreateInstance(implType)!;
            return ScepClientResult.Ok;
        }
        catch (Exception ex)
        {
            error = $"failed to load crypto provider '{path}': {ex.Message}";
            return ScepClientResult.ProviderError;
        }
    }
}
```

- [ ] **Step 5: Run to verify pass.** (Tests reference the BC provider project, so the DLL is in the test output dir.)

- [ ] **Step 6: Commit** — `git commit -am "Core: crypto provider loading with ALC isolation"`

---

### Task 9: Core — Trace events, ServerConfig & HTTP transport

**Goal:** The `Trace` event payload, the `ServerConfig` value, and a sync+async SCEP HTTP transport (GET with base64 `message`, POST raw bytes) over an injectable `HttpMessageHandler`.

**Files:**
- Create: `src/ScepTestClient.Core/ScepTraceEvent.cs`, `ServerConfig.cs`, `Transport/ScepHttpTransport.cs`
- Test: `tests/ScepTestClient.Tests/TransportTests.cs`

**Acceptance Criteria:**
- [ ] A GET operation requests `…?operation=GetCACaps&message=<urlencoded-base64>` and returns the response bytes.
- [ ] A POST PKIOperation sends the body bytes with `Content-Type: application/x-pki-message` and returns the response bytes.
- [ ] Both `Get`/`GetAsync` and `Post`/`PostAsync` exist and produce identical results against the same stub.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter TransportTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/TransportTests.cs` using a `StubHandler : HttpMessageHandler` that records the request URI/body and returns a canned byte payload. Assert the GET query string and that sync and async paths agree.

```csharp
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Transport;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public class TransportTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        public Uri? LastUri;
        public byte[] Response = { 1, 2, 3 };
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastUri = request.RequestUri;
            HttpResponseMessage resp;
            resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Response) };
            return Task.FromResult(resp);
        }
    }

    [Fact]
    public async Task Get_builds_operation_query_and_returns_bytes()
    {
        StubHandler stub;
        ScepHttpTransport transport;
        ScepResult<byte[]> sync;
        ScepResult<byte[]> async;

        stub = new StubHandler();
        transport = new ScepHttpTransport(new HttpClient(stub), new Uri("http://host/scep"), TimeSpan.FromSeconds(30));

        async = await transport.GetAsync("GetCACaps", "abc");
        Assert.True(async.IsOk);
        Assert.Contains("operation=GetCACaps", stub.LastUri!.Query);
        Assert.Contains("message=", stub.LastUri!.Query);

        sync = transport.Get("GetCACaps", "abc");
        Assert.Equal(async.Value, sync.Value);
    }
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement**

`ScepTraceEvent.cs`:
```csharp
namespace ScepTestClient.Core;

public enum TraceLevel { Debug, Info, Warning, Error, Opinion }

public sealed record ScepTraceEvent(TraceLevel Level, string Phase, string Message);
```

`ServerConfig.cs`:
```csharp
using System;

namespace ScepTestClient.Core;

public sealed class ServerConfig
{
    public required string Id { get; init; }
    public required Uri Url { get; init; }
    public string? CaIdentifier { get; init; }
    public bool PreferPost { get; init; } = true;
}
```

`Transport/ScepHttpTransport.cs`:
```csharp
using System;
using System.Net.Http;
using System.Threading.Tasks;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Transport;

public sealed class ScepHttpTransport
{
    private readonly HttpClient _http;
    private readonly Uri _baseUrl;

    public ScepHttpTransport(HttpClient http, Uri baseUrl, TimeSpan timeout)
    {
        _http = http;
        _baseUrl = baseUrl;
        _http.Timeout = timeout;
    }

    private Uri BuildGetUri(string operation, string message)
    {
        string query;
        query = $"?operation={Uri.EscapeDataString(operation)}";
        if (message.Length > 0) query += $"&message={Uri.EscapeDataString(message)}";
        return new Uri(_baseUrl + query);
    }

    public async Task<ScepResult<byte[]>> GetAsync(string operation, string message)
    {
        try
        {
            HttpResponseMessage resp;
            resp = await _http.GetAsync(BuildGetUri(operation, message)).ConfigureAwait(false);
            return await ReadAsync(resp).ConfigureAwait(false);
        }
        catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    public ScepResult<byte[]> Get(string operation, string message)
    {
        try
        {
            HttpResponseMessage resp;
            resp = _http.Send(new HttpRequestMessage(HttpMethod.Get, BuildGetUri(operation, message)));
            return Read(resp);
        }
        catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    public async Task<ScepResult<byte[]>> PostAsync(string operation, byte[] body)
    {
        try
        {
            HttpResponseMessage resp;
            resp = await _http.PostAsync(BuildGetUri(operation, string.Empty), PkiContent(body)).ConfigureAwait(false);
            return await ReadAsync(resp).ConfigureAwait(false);
        }
        catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    public ScepResult<byte[]> Post(string operation, byte[] body)
    {
        try
        {
            HttpRequestMessage req;
            req = new HttpRequestMessage(HttpMethod.Post, BuildGetUri(operation, string.Empty)) { Content = PkiContent(body) };
            return Read(_http.Send(req));
        }
        catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    private static ByteArrayContent PkiContent(byte[] body)
    {
        ByteArrayContent content;
        content = new ByteArrayContent(body);
        content.Headers.TryAddWithoutValidation("Content-Type", "application/x-pki-message");
        return content;
    }

    private static async Task<ScepResult<byte[]>> ReadAsync(HttpResponseMessage resp)
    {
        if (!resp.IsSuccessStatusCode) return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, $"HTTP {(int)resp.StatusCode}");
        return ScepResult<byte[]>.Ok(await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false));
    }

    private static ScepResult<byte[]> Read(HttpResponseMessage resp)
    {
        if (!resp.IsSuccessStatusCode) return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, $"HTTP {(int)resp.StatusCode}");
        return ScepResult<byte[]>.Ok(resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult());
    }
}
```

> The only `GetAwaiter().GetResult()` is on `ReadAsByteArrayAsync` over an already-buffered in-memory response (no deadlock risk); the network call itself uses the genuine sync `HttpClient.Send`.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `git commit -am "Core: trace events, server config, sync+async SCEP transport"`

---

### Task 10: Core — GetCACaps parsing (`ScepCapabilities`)

**Goal:** Parse the newline-delimited GetCACaps keyword list into a typed capability object.

**Files:**
- Create: `src/ScepTestClient.Core/Protocol/ScepCapabilities.cs`
- Test: `tests/ScepTestClient.Tests/CapabilitiesTests.cs`

**Acceptance Criteria:**
- [ ] Parsing `"POSTPKIOperation\nSHA-256\nAES\nRenewal\n"` sets `PostPkiOperation`, `Sha256`, `Aes`, `Renewal` true and `Sha512`/`Des3` false.
- [ ] Unknown keywords are ignored (not an error) and recorded in `Unknown`.
- [ ] Parsing is case-insensitive and tolerant of CRLF/whitespace.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter CapabilitiesTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/CapabilitiesTests.cs`

```csharp
using ScepTestClient.Core.Protocol;
using Xunit;

namespace ScepTestClient.Tests;

public class CapabilitiesTests
{
    [Fact]
    public void Parses_keyword_list()
    {
        ScepCapabilities caps;

        caps = ScepCapabilities.Parse("POSTPKIOperation\r\nSHA-256\nAES\nRenewal\n");

        Assert.True(caps.PostPkiOperation);
        Assert.True(caps.Sha256);
        Assert.True(caps.Aes);
        Assert.True(caps.Renewal);
        Assert.False(caps.Sha512);
        Assert.False(caps.Des3);
    }
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** — `src/ScepTestClient.Core/Protocol/ScepCapabilities.cs`

```csharp
using System;
using System.Collections.Generic;

namespace ScepTestClient.Core.Protocol;

public sealed class ScepCapabilities
{
    public bool Aes { get; private set; }
    public bool Des3 { get; private set; }
    public bool GetNextCaCert { get; private set; }
    public bool PostPkiOperation { get; private set; }
    public bool Renewal { get; private set; }
    public bool Sha1 { get; private set; }
    public bool Sha256 { get; private set; }
    public bool Sha512 { get; private set; }
    public bool ScepStandard { get; private set; }
    public List<string> Unknown { get; } = new();
    public string[] RawKeywords { get; private set; } = Array.Empty<string>();

    public static ScepCapabilities Parse(string text)
    {
        ScepCapabilities caps;
        List<string> raw;

        caps = new ScepCapabilities();
        raw = new List<string>();

        foreach (string line in (text ?? string.Empty).Split('\n'))
        {
            string kw;
            kw = line.Trim();
            if (kw.Length == 0) continue;
            raw.Add(kw);
            switch (kw.ToUpperInvariant())
            {
                case "AES": caps.Aes = true; break;
                case "DES3": caps.Des3 = true; break;
                case "GETNEXTCACERT": caps.GetNextCaCert = true; break;
                case "POSTPKIOPERATION": caps.PostPkiOperation = true; break;
                case "RENEWAL": caps.Renewal = true; break;
                case "SHA-1": caps.Sha1 = true; break;
                case "SHA-256": caps.Sha256 = true; break;
                case "SHA-512": caps.Sha512 = true; break;
                case "SCEPSTANDARD": caps.ScepStandard = true; break;
                default: caps.Unknown.Add(kw); break;
            }
        }
        caps.RawKeywords = raw.ToArray();
        return caps;
    }
}
```

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `git commit -am "Core: GetCACaps parsing"`

---

### Task 11: Core — `ScepClient` facade (read ops + enroll/poll)

**Goal:** The `ScepClient` with no-throw `Create`, the `Crypto` property, the `Trace` event, and sync+async `GetCaCaps`/`GetCaCert`/`GetNextCaCert`/`Enroll`/`Poll`.

**Files:**
- Create: `src/ScepTestClient.Core/ScepClient.cs`, `EnrollRequest.cs`, `EnrollOutcome.cs`
- Test: `tests/ScepTestClient.Tests/ScepClientTests.cs` (uses the FakeScepServer from Task 14; this task may be implemented after Task 14's fixture exists — see dependencies)

**Acceptance Criteria:**
- [ ] `ScepClient.Create(serverConfig, crypto, handler, out client, out error)` returns `Ok` and exposes `client.Crypto`.
- [ ] `GetCaCapsAsync()` returns a parsed `ScepCapabilities`; `GetCaCertAsync()` returns the CA cert(s).
- [ ] `EnrollAsync(request)` against a CA that issues inline returns `EnrollOutcome` with `Status == Ok` and a non-null `Certificate`; the equivalent sync `Enroll` returns the same.
- [ ] The `Trace` event fires at least once per operation.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter ScepClientTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** (after Task 14 fixture exists): create a `FakeScepServer`, `ScepClient.Create` against it, `GetCaCertAsync`, build an `EnrollRequest`, `EnrollAsync`, assert an issued cert; repeat with the sync `Enroll`.

- [ ] **Step 2: Implement the request/outcome types**

`EnrollRequest.cs`:
```csharp
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

public sealed class EnrollRequest
{
    public required string Subject { get; init; }
    public required IScepKey Key { get; init; }
    public string? ChallengePassword { get; init; }
    public string DigestOid { get; init; } = Algorithms.OidFor("SHA-256")!;
    public string ContentEncryptionOid { get; init; } = Algorithms.OidFor("AES-128-CBC")!;
    public List<string> DnsNames { get; } = new();
    public List<string> Upns { get; } = new();
    public string? Sid { get; init; }
    public List<string> Ekus { get; } = new();
    public X509Certificate2? CaCertificate { get; set; }   // from GetCaCert; set by high-level flow
}
```

`EnrollOutcome.cs`:
```csharp
using System;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

public sealed class EnrollOutcome
{
    public ScepClientResult Status { get; init; }
    public PkiStatus PkiStatus { get; init; }
    public FailInfo FailInfo { get; init; } = FailInfo.None;
    public X509Certificate2? Certificate { get; init; }
    public string TransactionId { get; init; } = string.Empty;
    public TimeSpan Elapsed { get; init; }
}
```

- [ ] **Step 3: Implement `ScepClient`** — `src/ScepTestClient.Core/ScepClient.cs`

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ScepTestClient.Core.Protocol;
using ScepTestClient.Core.Transport;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

public sealed class ScepClient
{
    private readonly ScepHttpTransport _transport;

    public IScepCrypto Crypto { get; }
    public ServerConfig Server { get; }
    public event Action<ScepTraceEvent>? Trace;

    private ScepClient(ServerConfig server, IScepCrypto crypto, ScepHttpTransport transport)
    {
        Server = server;
        Crypto = crypto;
        _transport = transport;
    }

    public static ScepClientResult Create(ServerConfig server, IScepCrypto crypto, HttpMessageHandler? handler,
                                          out ScepClient client, out string error)
    {
        HttpClient http;

        client = null!;
        error = string.Empty;
        if (server is null || crypto is null) { error = "server and crypto are required"; return ScepClientResult.InvalidArgument; }

        http = handler is null ? new HttpClient() : new HttpClient(handler);
        client = new ScepClient(server, crypto, new ScepHttpTransport(http, server.Url, TimeSpan.FromSeconds(30)));
        return ScepClientResult.Ok;
    }

    private void Emit(TraceLevel level, string phase, string message) => Trace?.Invoke(new ScepTraceEvent(level, phase, message));

    // ---- GetCACaps ----
    public async Task<ScepResult<ScepCapabilities>> GetCaCapsAsync()
    {
        ScepResult<byte[]> raw;
        Emit(TraceLevel.Info, "GetCACaps", "requesting capabilities");
        raw = await _transport.GetAsync("GetCACaps", Server.CaIdentifier ?? string.Empty).ConfigureAwait(false);
        return ToCaps(raw);
    }

    public ScepResult<ScepCapabilities> GetCaCaps()
    {
        ScepResult<byte[]> raw;
        Emit(TraceLevel.Info, "GetCACaps", "requesting capabilities");
        raw = _transport.Get("GetCACaps", Server.CaIdentifier ?? string.Empty);
        return ToCaps(raw);
    }

    private static ScepResult<ScepCapabilities> ToCaps(ScepResult<byte[]> raw) =>
        raw.IsOk
            ? ScepResult<ScepCapabilities>.Ok(ScepCapabilities.Parse(System.Text.Encoding.ASCII.GetString(raw.Value)))
            : ScepResult<ScepCapabilities>.Fail(raw.Status, raw.Error);

    // ---- GetCACert / GetNextCACert ----
    public Task<ScepResult<IReadOnlyList<X509Certificate2>>> GetCaCertAsync() => CaCertAsync("GetCACert");
    public Task<ScepResult<IReadOnlyList<X509Certificate2>>> GetNextCaCertAsync() => CaCertAsync("GetNextCACert");

    private async Task<ScepResult<IReadOnlyList<X509Certificate2>>> CaCertAsync(string op)
    {
        ScepResult<byte[]> raw;
        Emit(TraceLevel.Info, op, "requesting CA certificate(s)");
        raw = await _transport.GetAsync(op, Server.CaIdentifier ?? string.Empty).ConfigureAwait(false);
        return ParseCa(raw);
    }

    public ScepResult<IReadOnlyList<X509Certificate2>> GetCaCert()
    {
        ScepResult<byte[]> raw;
        Emit(TraceLevel.Info, "GetCACert", "requesting CA certificate(s)");
        raw = _transport.Get("GetCACert", Server.CaIdentifier ?? string.Empty);
        return ParseCa(raw);
    }

    private ScepResult<IReadOnlyList<X509Certificate2>> ParseCa(ScepResult<byte[]> raw)
    {
        IReadOnlyList<X509Certificate2> certs;
        string error;

        if (!raw.IsOk) return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(raw.Status, raw.Error);
        if (!Crypto.ParseCaCertificates(raw.Value, out certs, out error))
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(ScepClientResult.CryptoError, error);
        return ScepResult<IReadOnlyList<X509Certificate2>>.Ok(certs);
    }

    // ---- Enroll (PKCSReq) ----
    public async Task<ScepResult<EnrollOutcome>> EnrollAsync(EnrollRequest request)
    {
        PkiMessage outbound;
        byte[] requestDer;
        string error;
        Stopwatch sw;
        ScepResult<byte[]> response;

        Emit(TraceLevel.Info, "Enroll", $"PKCSReq for {request.Subject}");
        if (!BuildPkcsReq(request, out outbound, out error)) return Fail(error);
        if (!outbound.Encode(Crypto, out requestDer, out error)) return Fail(error);

        sw = Stopwatch.StartNew();
        response = Server.PreferPost
            ? await _transport.PostAsync("PKIOperation", requestDer).ConfigureAwait(false)
            : await _transport.GetAsync("PKIOperation", Convert.ToBase64String(requestDer)).ConfigureAwait(false);
        sw.Stop();
        return Interpret(response, request.Key, outbound.TransactionId!, sw.Elapsed);
    }

    public ScepResult<EnrollOutcome> Enroll(EnrollRequest request)
    {
        PkiMessage outbound;
        byte[] requestDer;
        string error;
        Stopwatch sw;
        ScepResult<byte[]> response;

        Emit(TraceLevel.Info, "Enroll", $"PKCSReq for {request.Subject}");
        if (!BuildPkcsReq(request, out outbound, out error)) return Fail(error);
        if (!outbound.Encode(Crypto, out requestDer, out error)) return Fail(error);

        sw = Stopwatch.StartNew();
        response = Server.PreferPost
            ? _transport.Post("PKIOperation", requestDer)
            : _transport.Get("PKIOperation", Convert.ToBase64String(requestDer));
        sw.Stop();
        return Interpret(response, request.Key, outbound.TransactionId!, sw.Elapsed);
    }

    private bool BuildPkcsReq(EnrollRequest request, out PkiMessage message, out string error)
    {
        Pkcs10 csr;

        message = null!;
        error = string.Empty;
        if (request.CaCertificate is null) { error = "CA certificate not set (call GetCACert first)"; return false; }

        csr = new Pkcs10 { Key = request.Key, ChallengePassword = request.ChallengePassword, Sid = request.Sid };
        if (!csr.SetSubject(request.Subject, out error)) return false;
        csr.DnsNames.AddRange(request.DnsNames);
        csr.Upns.AddRange(request.Upns);
        csr.Ekus.AddRange(request.Ekus);

        message = new PkiMessage
        {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = request.Key,
            RecipientCaCert = request.CaCertificate,
            DigestAlgorithmOid = request.DigestOid,
            ContentEncryptionAlgorithmOid = request.ContentEncryptionOid,
            TransactionId = Guid.NewGuid().ToString("N"),
        };
        return true;
    }

    private ScepResult<EnrollOutcome> Interpret(ScepResult<byte[]> response, IScepKey key, string transId, TimeSpan elapsed)
    {
        PkiMessage reply;
        string error;

        if (!response.IsOk) return ScepResult<EnrollOutcome>.Fail(response.Status, response.Error);
        if (!PkiMessage.Decode(Crypto, response.Value, key, CodecOptions.LenientParsing, out reply, out error))
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.CryptoError, error);

        foreach (ConformanceNote note in reply.ConformanceNotes)
            Emit(TraceLevel.Opinion, "Enroll", $"{note.What} ({note.Where}, {note.RfcReference})");

        EnrollOutcome outcome;
        outcome = new EnrollOutcome
        {
            Status = reply.PkiStatus switch
            {
                PkiStatus.Success => ScepClientResult.Ok,
                PkiStatus.Pending => ScepClientResult.Pending,
                _ => ScepClientResult.ServerFailure,
            },
            PkiStatus = reply.PkiStatus,
            FailInfo = reply.FailInfo,
            Certificate = reply.IssuedCerts.Count > 0 ? reply.IssuedCerts[0] : null,
            TransactionId = transId,
            Elapsed = elapsed,
        };
        return ScepResult<EnrollOutcome>.Ok(outcome);
    }

    private static ScepResult<EnrollOutcome> Fail(string error) =>
        ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
}
```

> `Poll` (CertPoll) follows the same shape as `Enroll` (build a `CertPoll` message with the prior `transactionId`, POST, interpret). Implement `PollAsync`/`Poll` mirroring `EnrollAsync`/`Enroll`, building a `PkiMessage { MessageType = MessageType.CertPoll, ... }`. The CertPoll encode path is added to the BC provider alongside this task (extend `EncodePkiMessage` to handle `CertPoll`: a SignedData with `messageType=20` and an `IssuerAndSubject` enveloped body). If time-boxing, Phase 1 may ship `Enroll` only and defer `Poll` to the start of Phase 2 — note which in the PR description.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `git commit -am "Core: ScepClient facade with read ops and enroll"`

---

### Task 12: Core — storage (breadcrumb, redaction, registry, cert store, use-records)

**Goal:** The filesystem state layer: data-root resolution via breadcrumb, sha256 redaction, JSON config/defaults, server registry, certificate store, and the append-only `history.jsonl`.

**Files:**
- Create: `src/ScepTestClient.Core/Storage/DataRoot.cs`, `Redaction.cs`, `ClientConfig.cs`, `ServerRegistry.cs`, `CertStore.cs`, `UseRecordLog.cs`
- Test: `tests/ScepTestClient.Tests/StorageTests.cs`

**Acceptance Criteria:**
- [ ] `DataRoot.Resolve` order: explicit dir wins; else breadcrumb file; else default `~/.sceptestclient` and best-effort write of the breadcrumb. A non-writable home does not throw.
- [ ] `Redaction.Hash("secret")` returns `"sha256:" + lowercase-hex` and is stable.
- [ ] `ServerRegistry.Add`/`List` round-trips through disk; `CertStore.Save`/`Load` round-trips a cert + metadata; `UseRecordLog.Append` adds one JSON line.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter StorageTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/StorageTests.cs` (use a temp dir as the data root and a temp "home"):

```csharp
using System.IO;
using ScepTestClient.Core.Storage;
using Xunit;

namespace ScepTestClient.Tests;

public class StorageTests
{
    [Fact]
    public void Redaction_is_stable_and_prefixed()
    {
        Assert.StartsWith("sha256:", Redaction.Hash("secret"));
        Assert.Equal(Redaction.Hash("secret"), Redaction.Hash("secret"));
        Assert.NotEqual(Redaction.Hash("a"), Redaction.Hash("b"));
    }

    [Fact]
    public void Explicit_dir_wins_over_breadcrumb()
    {
        string explicitDir;
        string home;
        string resolved;

        explicitDir = Directory.CreateTempSubdirectory().FullName;
        home = Directory.CreateTempSubdirectory().FullName;

        resolved = DataRoot.Resolve(explicitDir, home);
        Assert.Equal(explicitDir, resolved);
        Assert.False(File.Exists(Path.Combine(home, ".sceptest.json")));   // breadcrumb not rewritten
    }

    [Fact]
    public void Default_writes_breadcrumb()
    {
        string home;
        string resolved;

        home = Directory.CreateTempSubdirectory().FullName;
        resolved = DataRoot.Resolve(null, home);

        Assert.Equal(Path.Combine(home, ".sceptestclient"), resolved);
        Assert.True(File.Exists(Path.Combine(home, ".sceptest.json")));
    }

    [Fact]
    public void Registry_round_trips()
    {
        string root;
        ServerRegistry registry;

        root = Directory.CreateTempSubdirectory().FullName;
        registry = new ServerRegistry(root);
        registry.Add(new StoredServer { Id = "privpki", Url = "http://host/scep/privpki", PreferPost = true });

        Assert.Single(registry.List());
        Assert.Equal("http://host/scep/privpki", registry.List()[0].Url);
    }
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement**

`Redaction.cs`:
```csharp
using System;
using System.Security.Cryptography;
using System.Text;

namespace ScepTestClient.Core.Storage;

public static class Redaction
{
    public static string Hash(string sensitive)
    {
        byte[] digest;
        digest = SHA256.HashData(Encoding.UTF8.GetBytes(sensitive ?? string.Empty));
        return "sha256:" + Convert.ToHexString(digest).ToLowerInvariant();
    }
}
```

`DataRoot.cs`:
```csharp
using System;
using System.IO;
using System.Text.Json;

namespace ScepTestClient.Core.Storage;

public static class DataRoot
{
    private const string BreadcrumbFile = ".sceptest.json";
    private const string DefaultDirName = ".sceptestclient";

    private sealed class Breadcrumb { public string Root { get; set; } = string.Empty; }

    public static string Resolve(string? explicitDir, string? homeOverride = null)
    {
        string home;
        string breadcrumbPath;
        string defaultRoot;

        if (!string.IsNullOrWhiteSpace(explicitDir)) return explicitDir!;

        home = homeOverride ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        breadcrumbPath = Path.Combine(home, BreadcrumbFile);

        if (File.Exists(breadcrumbPath))
        {
            try
            {
                Breadcrumb? crumb;
                crumb = JsonSerializer.Deserialize<Breadcrumb>(File.ReadAllText(breadcrumbPath));
                if (crumb is not null && !string.IsNullOrWhiteSpace(crumb.Root)) return crumb.Root;
            }
            catch { /* fall through to default */ }
        }

        defaultRoot = Path.Combine(home, DefaultDirName);
        try
        {
            Directory.CreateDirectory(defaultRoot);
            File.WriteAllText(breadcrumbPath, JsonSerializer.Serialize(new Breadcrumb { Root = defaultRoot }));
        }
        catch { /* best-effort; never fail if home isn't writable */ }
        return defaultRoot;
    }
}
```

`ClientConfig.cs`, `ServerRegistry.cs`, `CertStore.cs`, `UseRecordLog.cs` (System.Text.Json file-backed). Define `StoredServer`, `CertMetadata`, and `UseRecord` records and the read/write methods. Representative shape for the registry:

```csharp
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace ScepTestClient.Core.Storage;

public sealed class StoredServer
{
    public required string Id { get; init; }
    public required string Url { get; init; }
    public string? Name { get; init; }
    public string? CaIdentifier { get; init; }
    public bool PreferPost { get; init; } = true;
}

public sealed class ServerRegistry
{
    private readonly string _serversDir;

    public ServerRegistry(string root) { _serversDir = Path.Combine(root, "servers"); Directory.CreateDirectory(_serversDir); }

    public void Add(StoredServer server)
    {
        string dir;
        dir = Path.Combine(_serversDir, server.Id);
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "server.json"), JsonSerializer.Serialize(server));
    }

    public IReadOnlyList<StoredServer> List()
    {
        List<StoredServer> result;
        result = new List<StoredServer>();
        foreach (string dir in Directory.GetDirectories(_serversDir))
        {
            string file;
            file = Path.Combine(dir, "server.json");
            if (File.Exists(file))
            {
                StoredServer? s;
                s = JsonSerializer.Deserialize<StoredServer>(File.ReadAllText(file));
                if (s is not null) result.Add(s);
            }
        }
        return result;
    }

    public StoredServer? Get(string id)
    {
        string file;
        file = Path.Combine(_serversDir, id, "server.json");
        return File.Exists(file) ? JsonSerializer.Deserialize<StoredServer>(File.ReadAllText(file)) : null;
    }
}
```

`CertStore` saves under `servers/<id>/certificates/<cert-id>/` (`cert.pem`, `key.pkcs8` from `IScepCrypto` export — for Phase 1 store the cert PEM and a `metadata.json`; the private key bytes come from a provider export method added here: extend `IScepCrypto` with `bool ExportPrivateKeyPkcs8(IScepKey key, out byte[] der, out string error)` and implement it in the BC provider). `UseRecordLog.Append(UseRecord)` opens `servers/<id>/history.jsonl` with `File.AppendAllText` writing one `JsonSerializer.Serialize(record)` + `\n`. Redact any sensitive field with `Redaction.Hash` before writing.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `git commit -am "Core: filesystem storage (breadcrumb, registry, cert store, history)"`

---

### Task 13: Core — high-level `GetNewCertificate` orchestration

**Goal:** One call that runs GetCACert → Enroll → store cert + metadata + a timed use-record.

**Files:**
- Modify: `src/ScepTestClient.Core/ScepClient.cs` (add `GetNewCertificate`/`GetNewCertificateAsync`)
- Create: `tests/ScepTestClient.Tests/OrchestrationTests.cs`

**Acceptance Criteria:**
- [ ] `GetNewCertificateAsync(request, store, log)` against the FakeScepServer returns `Ok` with a stored cert; `store` contains the cert and a `metadata.json`; `log` gains one record with a non-zero `TimingMs`.
- [ ] When `request.CaCertificate` is null, the method fetches it via `GetCaCert` first.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter OrchestrationTests` → pass.

**Steps:**

- [ ] **Step 1: Write the failing test** (uses FakeScepServer from Task 14): create client, build request without CaCertificate, call `GetNewCertificateAsync`, assert stored cert + one history record.

- [ ] **Step 2: Implement** — add to `ScepClient`:

```csharp
public async Task<ScepResult<EnrollOutcome>> GetNewCertificateAsync(EnrollRequest request,
    Storage.CertStore store, Storage.UseRecordLog log)
{
    Emit(TraceLevel.Info, "GetNewCertificate", "starting enrollment lifecycle");

    if (request.CaCertificate is null)
    {
        ScepResult<IReadOnlyList<X509Certificate2>> ca;
        ca = await GetCaCertAsync().ConfigureAwait(false);
        if (!ca.IsOk) return ScepResult<EnrollOutcome>.Fail(ca.Status, ca.Error);
        request.CaCertificate = ca.Value[0];
    }

    ScepResult<EnrollOutcome> enrolled;
    enrolled = await EnrollAsync(request).ConfigureAwait(false);
    if (enrolled.IsOk && enrolled.Value.Certificate is not null)
    {
        store.Save(Server.Id, enrolled.Value.Certificate, request, Crypto);
    }
    log.Append(Server.Id, enrolled);   // records operation, status, timing (redacting secrets)
    return enrolled;
}
```

(Provide the matching synchronous `GetNewCertificate` calling `GetCaCert`/`Enroll`.)

- [ ] **Step 3: Run to verify pass.**

- [ ] **Step 4: Commit** — `git commit -am "Core: GetNewCertificate orchestration with stored cert and use-record"`

---

### Task 14: Tests — `FakeScepServer` fixture & end-to-end enrollment

**Goal:** A loopback SCEP CA (Kestrel) that implements GetCACaps/GetCACert/PKIOperation and issues certs, giving the client a true end-to-end happy path. (Phase 1's stand-in for a real CA — the IntuneSimulator does not issue SCEP certs.)

**Files:**
- Create: `tests/ScepTestClient.Tests/Fakes/FakeScepServer.cs`
- Create: `tests/ScepTestClient.Tests/EndToEndTests.cs`
- Modify: `tests/ScepTestClient.Tests/Fakes/TestCa.cs` (add `IssueCertRep`)

**Acceptance Criteria:**
- [ ] `FakeScepServer` listens on a loopback `http://127.0.0.1:<port>/scep`, returns `"POSTPKIOperation\nSHA-256\nAES\n"` for GetCACaps and its CA cert for GetCACert.
- [ ] On a POST PKIOperation it decrypts the PKCSReq, issues a cert for the CSR's public key/subject, and returns a SUCCESS CertRep enveloped to the request's signer cert.
- [ ] `EndToEndTests` drives `ScepClient.GetNewCertificateAsync` (and the sync variant) against it and asserts an issued cert whose subject matches the request and whose key matches the request key.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter EndToEndTests` → pass.

**Steps:**

- [ ] **Step 1: Implement `FakeScepServer`** — a minimal Kestrel app (the test project gets ASP.NET via `<FrameworkReference Include="Microsoft.AspNetCore.App" />` added to its csproj):

```csharp
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace ScepTestClient.Tests.Fakes;

public sealed class FakeScepServer : IAsyncDisposable
{
    private readonly WebApplication _app;
    public Uri ScepUrl { get; }
    public TestCa Ca { get; }

    private FakeScepServer(WebApplication app, Uri url, TestCa ca) { _app = app; ScepUrl = url; Ca = ca; }

    public static async Task<FakeScepServer> StartAsync()
    {
        WebApplicationBuilder builder;
        WebApplication app;
        TestCa ca;
        string url;

        ca = TestCa.Create();
        url = "http://127.0.0.1:0";   // 0 → OS-assigned port; read back below
        builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls(url);
        app = builder.Build();

        app.MapGet("/scep", async (HttpContext ctx) =>
        {
            string op;
            op = ctx.Request.Query["operation"].ToString();
            if (op == "GetCACaps") { await ctx.Response.WriteAsync("POSTPKIOperation\nSHA-256\nAES\n"); return; }
            if (op == "GetCACert") { await ctx.Response.Body.WriteAsync(ca.Certificate.GetEncoded()); return; }
            ctx.Response.StatusCode = 400;
        });

        app.MapPost("/scep", async (HttpContext ctx) =>
        {
            byte[] requestDer;
            byte[] certRep;
            System.IO.MemoryStream ms;

            ms = new System.IO.MemoryStream();
            await ctx.Request.Body.CopyToAsync(ms);
            requestDer = ms.ToArray();
            certRep = ca.IssueCertRep(requestDer);   // decrypt CSR, issue, wrap SUCCESS CertRep
            await ctx.Response.Body.WriteAsync(certRep);
        });

        await app.StartAsync();
        Uri bound;
        bound = new Uri(new Uri(app.Urls.First()), "/scep");
        return new FakeScepServer(app, bound, ca);
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
```

- [ ] **Step 2: Implement `TestCa.IssueCertRep(byte[] pkcsReqDer)`** — server-side CMS using BouncyCastle (the test project sees BouncyCastle transitively via the provider reference):
  1. `CmsSignedData signed = new(pkcsReqDer)`; grab the signer cert from `signed.GetCertificates()`.
  2. Decrypt the encapsulated `EnvelopedData` (`new CmsEnvelopedData((byte[])signed.SignedContent.GetContent())`) with the CA private key → CSR DER.
  3. `Pkcs10CertificationRequest csr = new(csrDer)`; `Issue(csr.GetPublicKey(), csr.GetCertificationRequestInfo().Subject.ToString())`.
  4. Wrap the issued cert in a degenerate PKCS#7, envelop it to the **signer cert**, sign with the CA key adding signed attributes `pkiStatus=0`, `messageType=3 (CertRep)`, `transId` echoed, `recipientNonce` = request senderNonce. Return `GetEncoded()`.

  (Reuse the `Envelope`/`Sign`/attribute helpers patterned on `BcPkiMessage`; this is the inverse of Tasks 6–7. The `EndToEndTests` round-trip is the source of truth — iterate the BC calls until green.)

- [ ] **Step 3: Write `EndToEndTests`**

```csharp
using System;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Storage;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public class EndToEndTests
{
    [Fact]
    public async Task Gets_a_certificate_end_to_end()
    {
        await using FakeScepServer server = await FakeScepServer.StartAsync();
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        IScepKey key;
        EnrollRequest request;
        string root;
        ScepResult<EnrollOutcome> result;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out KeySpec spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        Assert.Equal(ScepClientResult.Ok, ScepClient.Create(
            new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null,
            out client, out _));

        request = new EnrollRequest { Subject = "CN=poodle", Key = key, ChallengePassword = "pw" };
        root = System.IO.Directory.CreateTempSubdirectory().FullName;

        result = await client.GetNewCertificateAsync(request, new CertStore(root), new UseRecordLog(root));

        Assert.True(result.IsOk, result.Error);
        Assert.NotNull(result.Value.Certificate);
        Assert.Contains("poodle", result.Value.Certificate!.Subject);
    }
}
```

- [ ] **Step 4: Run to verify pass.** This is the Phase 1 keystone test — it exercises CSR build, CMS sign/envelope, transport, decode, and storage together.

- [ ] **Step 5: Commit** — `git commit -am "Tests: FakeScepServer fixture and end-to-end enrollment"`

---

### Task 15: CLI — command router, commands & console trace

**Goal:** The `sceptest` executable: global flags, the noun-verb commands needed for casual use, and `Trace` rendering.

**Files:**
- Create: `src/ScepTestClient.Cli/Program.cs`, `CommandRouter.cs`, `ConsoleTrace.cs`
- Test: `tests/ScepTestClient.Tests/CliRouterTests.cs`

**Acceptance Criteria:**
- [ ] `sceptest servers add http://host/scep --name privpki` then `sceptest servers list` shows the server (round-trips through the data root).
- [ ] `sceptest getcacaps <id>` prints the parsed capabilities; `sceptest get <id> --subject "CN=x"` runs the lifecycle and reports the stored cert id (against a server URL pointed at the FakeScepServer in the test).
- [ ] Unknown command prints usage and returns a non-zero exit code; no exceptions escape `Main`.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter CliRouterTests` and manual `dotnet run --project src/ScepTestClient.Cli -- --help`.

**Steps:**

- [ ] **Step 1: Write the failing test** — `tests/ScepTestClient.Tests/CliRouterTests.cs` calls `CommandRouter.Run(string[] args, string dataRoot, TextWriter outWriter)` and asserts exit codes / output for `servers add`, `servers list`, and an unknown command. (Router is pure enough to test without a process.)

- [ ] **Step 2: Implement `ConsoleTrace`**

```csharp
using System;
using ScepTestClient.Core;

namespace ScepTestClient.Cli;

internal sealed class ConsoleTrace
{
    private readonly int _verbosity;   // 0 = info+, 1 = -v debug, etc.
    public ConsoleTrace(int verbosity) { _verbosity = verbosity; }

    public void Handle(ScepTraceEvent e)
    {
        if (e.Level == TraceLevel.Debug && _verbosity < 1) return;
        Console.Error.WriteLine($"[{e.Level}] {e.Phase}: {e.Message}");
    }
}
```

- [ ] **Step 3: Implement `CommandRouter`** — parse global flags (`--data-dir`, `--timeout`, `-v`, `--simulator` reserved for Phase 3), dispatch nouns (`servers`, `getcacaps`, `getcacert`, `enroll`, `poll`, `get`, `certs`, `config`). Provide complete handlers for `servers add/list` and `get`; the others follow the same pattern (resolve server from registry → `ScepClient.Create` → call the matching `ScepClient` method → render result). Signature:

```csharp
public static int Run(string[] args, string dataRoot, System.IO.TextWriter output)
```

`servers add`:
```csharp
// args: servers add <url> [--name <n>] [--ca-identifier <c>] [--transport get|post]
StoredServer server;
string id;
id = options.Name ?? DeriveId(url);   // DeriveId: slug from host + path
new ServerRegistry(dataRoot).Add(new StoredServer { Id = id, Url = url, Name = options.Name,
    CaIdentifier = options.CaIdentifier, PreferPost = options.Transport != "get" });
output.WriteLine($"added server '{id}' -> {url}");
return 0;
```

`get` (casual lifecycle):
```csharp
// args: get <server-id> --subject "CN=x" [--challenge <pw>] [--key-spec rsa:2048] [--san-dns ...] [--sid ...]
StoredServer? s;
IScepCrypto crypto;
ScepClient client;
IScepKey key;
EnrollRequest request;
ScepResult<EnrollOutcome> outcome;

s = new ServerRegistry(dataRoot).Get(serverId);
if (s is null) { output.WriteLine($"unknown server '{serverId}'"); return 2; }
if (ScepCrypto.Load(config.CryptoProviderPath, out crypto, out string loadErr) != ScepClientResult.Ok)
{ output.WriteLine(loadErr); return 3; }
KeySpec.Parse(options.KeySpec ?? "rsa:2048", out KeySpec spec, out _);
crypto.GenerateKey(spec, out key, out _);
ScepClient.Create(new ServerConfig { Id = s.Id, Url = new Uri(s.Url), CaIdentifier = s.CaIdentifier,
    PreferPost = s.PreferPost }, crypto, handler: null, out client, out _);
client.Trace += new ConsoleTrace(verbosity).Handle;
request = new EnrollRequest { Subject = options.Subject, Key = key, ChallengePassword = options.Challenge, Sid = options.Sid };
outcome = client.GetNewCertificate(request, new CertStore(dataRoot), new UseRecordLog(dataRoot));
if (!outcome.IsOk) { output.WriteLine($"FAILED: {outcome.Status} {outcome.Error}"); return 1; }
output.WriteLine($"issued: {outcome.Value.Certificate!.Subject} (stored under server '{s.Id}')");
return 0;
```

- [ ] **Step 4: Implement `Program.cs`**

```csharp
using ScepTestClient.Cli;
using ScepTestClient.Core.Storage;

string? dataDirFlag;
string root;

dataDirFlag = GetFlag(args, "--data-dir");
root = DataRoot.Resolve(dataDirFlag);
return CommandRouter.Run(args, root, System.Console.Out);

static string? GetFlag(string[] args, string name)
{
    for (int i = 0; i < args.Length - 1; i++) if (args[i] == name) return args[i + 1];
    return null;
}
```

- [ ] **Step 5: Run to verify pass** — `dotnet test --filter CliRouterTests`, then `dotnet run --project src/ScepTestClient.Cli -- --help`.

- [ ] **Step 6: Final Phase 1 build + full test run**

Run: `dotnet build IntuneSimulator.sln && dotnet test tests/ScepTestClient.Tests`
Expected: build succeeds; all ScepTestClient tests pass.

- [ ] **Step 7: Commit** — `git commit -am "CLI: command router, casual get/servers/certs commands"`

---

## Self-Review (completed)

- **Spec coverage:** Phase 1 spec items map to tasks — projects/style (T0), CryptoApi + OID registry + CodecOptions/ConformanceNotes (T1–T3), PQ-tier paper validation (T3 Step 5), BC provider key/CSR/CMS/degenerate-parse (T4–T7), provider loading + ScepClient.Crypto (T8, T11), protocol GET/POST + GetCACaps/GetCACert/GetNextCACert + PKCSReq + (CertPoll noted) (T9–T11), storage breadcrumb/registry/cert-store/history/redaction/key-protection (T12), GetNewCertificate (T13), happy-path tests via FakeScepServer (T14), CLI commands (T15). **Deferred within Phase 1 if time-boxed:** standalone `Poll` and encrypted-PKCS#8 key protection (`--encrypt-keys`) — flagged in T11/T12 and to be called out in the PR.
- **Placeholder scan:** no "TBD/TODO"; the BC `NotImplementedException` stubs in T4 are explicitly replaced by T5–T7 in the same plan.
- **Type consistency:** `IScepCrypto` members (`GenerateKey`, `EncodeCsr`, `EncodePkiMessage`, `DecodePkiMessage`, `ParseCaCertificates`, `Capabilities`, and the T12 `ExportPrivateKeyPkcs8` addition) are used consistently across T3–T13; `ScepResult<T>`/`ScepClientResult` usage is uniform.
- **Known execution risk:** exact BouncyCastle 2.5.0 API names (e.g. `X509StoreFactory`, `EnumerateMatches`, `AddKeyTransRecipient`) may need minor adjustment; each crypto task's round-trip test is the source of truth and will surface mismatches immediately.

---
