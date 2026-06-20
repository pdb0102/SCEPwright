using System;
using System.IO;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public class ProviderLoadTests {
    [Fact]
    public void Default_load_returns_builtin_bouncycastle() {
        IScepCrypto crypto;
        string error;

        Assert.Equal(ScepClientResult.Ok, ScepCrypto.Load(null, out crypto, out error));
        Assert.NotEmpty(crypto.Capabilities.Digests);
    }

    [Fact]
    public void Missing_dll_fails_without_throwing() {
        IScepCrypto crypto;
        string error;

        Assert.Equal(ScepClientResult.ProviderError, ScepCrypto.Load("/does/not/exist.dll", out crypto, out error));
        Assert.NotEqual(string.Empty, error);
    }

    [Fact]
    public void Loads_provider_by_explicit_path_with_shared_contract() {
        string dll;
        IScepCrypto crypto;
        string error;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        byte[] der;

        dll = Path.Combine(AppContext.BaseDirectory, "ScepTestClient.Crypto.BouncyCastle.dll");
        Assert.Equal(ScepClientResult.Ok, ScepCrypto.Load(dll, out crypto, out error));
        Assert.True(crypto is IScepCrypto);
        Assert.True(KeySpec.Parse("rsa:2048", out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);   // shared IScepKey type identity
        csr = new Pkcs10 { Key = key };
        csr.SetSubject("CN=alc", out error);
        Assert.True(crypto.EncodeCsr(csr, out der, out error), error);
    }

    [Fact]
    public void Missing_impl_reports_no_implementation() {
        string dll;
        IScepCrypto crypto;
        string error;

        // An assembly with no IScepCrypto impl: use the contract assembly itself (CryptoApi has none).
        dll = Path.Combine(AppContext.BaseDirectory, "ScepTestClient.CryptoApi.dll");
        Assert.Equal(ScepClientResult.ProviderError, ScepCrypto.Load(dll, out crypto, out error));
        Assert.Contains("no IScepCrypto implementation", error);
    }

    [Fact]
    public void SelectImplType_with_no_candidates_reports_no_implementation() {
        Type? impl;
        string error;

        Assert.Equal(
            ScepClientResult.ProviderError,
            ScepCrypto.SelectImplType(Array.Empty<Type>(), "empty.dll", out impl, out error));
        Assert.Null(impl);
        Assert.Contains("no IScepCrypto implementation", error);
    }

    [Fact]
    public void SelectImplType_with_one_candidate_succeeds() {
        Type? impl;
        string error;

        Assert.Equal(
            ScepClientResult.Ok,
            ScepCrypto.SelectImplType(new[] { typeof(DummyCryptoA) }, "one.dll", out impl, out error));
        Assert.Equal(typeof(DummyCryptoA), impl);
        Assert.Equal(string.Empty, error);
    }

    [Fact]
    public void SelectImplType_with_multiple_candidates_reports_ambiguity() {
        Type? impl;
        string error;

        Assert.Equal(
            ScepClientResult.ProviderError,
            ScepCrypto.SelectImplType(new[] { typeof(DummyCryptoA), typeof(DummyCryptoB) }, "two.dll", out impl, out error));
        Assert.Null(impl);
        Assert.Contains("multiple IScepCrypto implementations", error);
    }

    // Two concrete IScepCrypto implementations used only to exercise the
    // ambiguity / single-impl selection logic deterministically (no second DLL needed).
    private abstract class DummyCryptoBase : IScepCrypto {
        public CryptoCapabilities Capabilities => throw new NotImplementedException();
        public bool GenerateKey(KeySpec spec, out IScepKey key, out string error) => throw new NotImplementedException();
        public bool EncodeCsr(Pkcs10 csr, out byte[] der, out string error) => throw new NotImplementedException();
        public bool EncodePkiMessage(PkiMessage message, FaultDirectives? faults, out byte[] der, out string error) => throw new NotImplementedException();
        public bool DecodePkiMessage(byte[] der, IScepKey recipient_key, CodecOptions options, out PkiMessage message, out string error) => throw new NotImplementedException();
        public bool ParseCaCertificates(byte[] der, out System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> certs, out string error) => throw new NotImplementedException();
        public bool ExportPrivateKeyPkcs8(IScepKey key, out byte[] der, out string error) => throw new NotImplementedException();
        public bool ImportPrivateKeyPkcs8(byte[] der, out IScepKey key, out string error) => throw new NotImplementedException();
        public bool ExportPrivateKeyPkcs8Encrypted(IScepKey key, string passphrase, out byte[] der, out string error) => throw new NotImplementedException();
        public bool ImportPrivateKeyPkcs8Encrypted(byte[] der, string passphrase, out IScepKey key, out string error) => throw new NotImplementedException();
    }

    private sealed class DummyCryptoA : DummyCryptoBase {
    }

    private sealed class DummyCryptoB : DummyCryptoBase {
    }
}
