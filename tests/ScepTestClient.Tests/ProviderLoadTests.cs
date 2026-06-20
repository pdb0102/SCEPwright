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
}
