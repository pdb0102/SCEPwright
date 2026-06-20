using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqKeySpecTests {
    [Fact]
    public void Parses_ml_dsa() {
        KeySpec spec;
        string error;

        Assert.True(KeySpec.Parse("ml-dsa:65", out spec, out error));
        Assert.Equal("ML-DSA", spec.Algorithm);
        Assert.Equal("65", spec.Parameter);
        Assert.Equal(0, spec.Size);
    }

    [Fact]
    public void Parses_slh_dsa() {
        KeySpec spec;
        string error;

        Assert.True(KeySpec.Parse("slh-dsa:128s", out spec, out error));
        Assert.Equal("SLH-DSA", spec.Algorithm);
        Assert.Equal("128s", spec.Parameter);
    }

    [Fact]
    public void Rsa_unchanged() {
        KeySpec spec;
        string error;

        Assert.True(KeySpec.Parse("rsa:2048", out spec, out error));
        Assert.Equal("RSA", spec.Algorithm);
        Assert.Equal(2048, spec.Size);
        Assert.Equal(string.Empty, spec.Parameter);
    }

    [Theory]
    [InlineData("ec:p256")]
    [InlineData("ml-dsa:99")]
    [InlineData("slh-dsa:bogus")]
    public void Rejects_bad(string text) {
        KeySpec spec;
        string error;

        Assert.False(KeySpec.Parse(text, out spec, out error));
        Assert.NotEqual(string.Empty, error);
    }
}
