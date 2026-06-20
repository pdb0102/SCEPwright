using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public class AlgorithmsTests {
    [Fact]
    public void Name_and_oid_round_trip() {
        Assert.Equal("2.16.840.1.101.3.4.2.1", Algorithms.OidFor("SHA-256"));
        Assert.Equal("SHA-256", Algorithms.NameFor("2.16.840.1.101.3.4.2.1"));
    }

    [Fact]
    public void Kind_is_tagged_per_oid() {
        Assert.Equal(AlgorithmKind.Digest, Algorithms.KindOf("2.16.840.1.101.3.4.2.1"));
        Assert.Equal(AlgorithmKind.ContentEncryption, Algorithms.KindOf("2.16.840.1.101.3.4.1.2"));
    }

    [Fact]
    public void Unknown_name_returns_null_not_throw() {
        Assert.Null(Algorithms.OidFor("NOPE"));
    }

    [Fact]
    public void KeySpec_parses_rsa() {
        KeySpec spec;
        string error;
        bool ok;

        ok = KeySpec.Parse("rsa:2048", out spec, out error);

        Assert.True(ok);
        Assert.Equal("RSA", spec.Algorithm);
        Assert.Equal(2048, spec.Size);
    }

    [Fact]
    public void KeySpec_rejects_garbage() {
        KeySpec spec;
        string error;

        Assert.False(KeySpec.Parse("banana", out spec, out error));
        Assert.NotEqual(string.Empty, error);
    }
}
