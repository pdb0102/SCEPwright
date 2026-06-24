using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public class BcCrlDecodeTests {
    [Fact]
    public void Decodes_crl_from_certrep() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        KeySpec spec;
        IScepKey recipient_key;
        System.Security.Cryptography.X509Certificates.X509Certificate2 recipient_cert;
        byte[] rep;
        PkiMessage decoded;
        string error;
        Org.BouncyCastle.X509.X509Crl parsed;

        crypto = new BouncyCastleScepCrypto();
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out recipient_key, out _);
        recipient_cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
            ca.Issue(((BcKey)recipient_key).KeyPair.Public, "CN=requester").GetEncoded());

        rep = ca.BuildSuccessCrlRep(ca.GenerateCrl(), recipient_cert, "tx", new byte[16]);

        Assert.True(crypto.DecodePkiMessage(rep, recipient_key, CodecOptions.LenientParsing, null, out decoded, out error), error);
        Assert.Single(decoded.IssuedCrls);
        parsed = new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(decoded.IssuedCrls[0]);
        Assert.NotNull(parsed);
    }
}
