using ScepTestClient.Core;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Tests;

public sealed class AllowFaultsTests {
    [Fact]
    public void Builder_CarriesFaults() {
        IScepCrypto crypto;
        FaultDirectives faults;
        ScepRequestBuilder builder;

        crypto = new BouncyCastleScepCrypto();
        faults = new FaultDirectives { CorruptSignature = true };
        builder = ScepRequestBuilder.For(crypto).AllowFaults(faults);

        Assert.Same(faults, builder.Faults);
    }

    [Fact]
    public void Builder_NoFaults_NullByDefault() {
        IScepCrypto crypto;

        crypto = new BouncyCastleScepCrypto();
        Assert.Null(ScepRequestBuilder.For(crypto).Faults);
    }
}
