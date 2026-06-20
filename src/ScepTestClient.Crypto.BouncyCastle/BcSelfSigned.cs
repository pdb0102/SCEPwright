using System;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace ScepTestClient.Crypto.BouncyCastle;

internal static class BcSelfSigned {
    public static X509Certificate ForKey(BcKey key, string subject_dn) {
        X509V3CertificateGenerator cg;
        X509Name name;

        name = new X509Name(subject_dn);
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
