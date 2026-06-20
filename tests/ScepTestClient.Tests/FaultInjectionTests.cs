using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using ScepTestClient.CryptoApi;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class FaultInjectionTests {
    private static IScepCrypto NewCrypto() {
        return new BouncyCastleScepCrypto();
    }

    private static PkiMessage BuildPkcsReq(IScepCrypto crypto, X509Certificate2 ca_cert, out IScepKey subject_key) {
        KeySpec spec;
        Pkcs10 csr;
        PkiMessage message;
        IScepKey key;

        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        subject_key = key;

        csr = new Pkcs10 { Key = key };
        csr.SetSubject("CN=fault-test", out _);

        message = new PkiMessage {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = key,
            RecipientCaCert = ca_cert,
            TransactionId = "TXNFAULT0001",
        };
        return message;
    }

    [Fact]
    public void NullFaults_LeavesBytesUnchanged() {
        IScepCrypto crypto;
        TestCa ca;
        PkiMessage message;
        IScepKey subject_key;
        byte[] a;
        byte[] b;
        string e1;
        string e2;

        crypto = NewCrypto();
        ca = TestCa.Create();
        message = BuildPkcsReq(crypto, ca.CertificateBcl, out subject_key);

        Assert.True(crypto.EncodePkiMessage(message, null, out a, out e1), e1);
        message.TransactionId = "TXNFAULT0001";
        Assert.True(crypto.EncodePkiMessage(message, new FaultDirectives(), out b, out e2), e2);
        // An all-false FaultDirectives must not add a signingTime attribute nor otherwise diverge in shape.
        Assert.Equal(SignedAttrCount(a), SignedAttrCount(b));
    }

    [Fact]
    public void CorruptSignature_DoesNotVerify() {
        IScepCrypto crypto;
        TestCa ca;
        PkiMessage message;
        IScepKey subject_key;
        byte[] der;
        string error;

        crypto = NewCrypto();
        ca = TestCa.Create();
        message = BuildPkcsReq(crypto, ca.CertificateBcl, out subject_key);

        Assert.True(crypto.EncodePkiMessage(message, new FaultDirectives { CorruptSignature = true }, out der, out error), error);
        Assert.False(ca.VerifyOuterSignature(der), "corrupted signature must not verify");
    }

    [Fact]
    public void SigningTimeSkew_AddsSkewedAttribute() {
        IScepCrypto crypto;
        TestCa ca;
        PkiMessage message;
        IScepKey subject_key;
        byte[] der;
        string error;
        System.DateTime? signing_time;

        crypto = NewCrypto();
        ca = TestCa.Create();
        message = BuildPkcsReq(crypto, ca.CertificateBcl, out subject_key);

        Assert.True(crypto.EncodePkiMessage(message, new FaultDirectives { SigningTimeSkew = System.TimeSpan.FromHours(2) }, out der, out error), error);
        signing_time = ca.ReadSigningTime(der);
        Assert.NotNull(signing_time);
        Assert.True(signing_time!.Value > System.DateTime.UtcNow.AddHours(1), "signingTime should be ~2h ahead");
    }

    [Fact]
    public void CorruptInnerContent_PkcsReqUnparseable() {
        IScepCrypto crypto;
        TestCa ca;
        PkiMessage message;
        IScepKey subject_key;
        byte[] der;
        string error;

        crypto = NewCrypto();
        ca = TestCa.Create();
        message = BuildPkcsReq(crypto, ca.CertificateBcl, out subject_key);

        Assert.True(crypto.EncodePkiMessage(message, new FaultDirectives { CorruptInnerContent = true }, out der, out error), error);
        Assert.False(ca.InnerCsrParses(der), "garbled inner payload must not parse as PKCS#10");
    }

    private static int SignedAttrCount(byte[] der) {
        CmsSignedData signed;
        SignerInformation signer;

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        return signer.SignedAttributes == null ? 0 : signer.SignedAttributes.Count;
    }
}
