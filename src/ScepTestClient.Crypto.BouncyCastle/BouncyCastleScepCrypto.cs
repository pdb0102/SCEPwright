using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Crypto.BouncyCastle;

public sealed class BouncyCastleScepCrypto : IScepCrypto {
    private readonly SecureRandom _random = new SecureRandom();

    public CryptoCapabilities Capabilities { get; } = new CryptoCapabilities {
        Digests = new[] { BcAlgorithms.Sha1, BcAlgorithms.Sha256, BcAlgorithms.Sha512, BcAlgorithms.Md5 },
        Signatures = new[] { BcAlgorithms.Rsa },
        ContentEncryption = new[] { BcAlgorithms.Aes128Cbc, BcAlgorithms.Aes256Cbc, BcAlgorithms.Des3Cbc },
        KeyTransport = new[] { BcAlgorithms.Rsa },
        AsymmetricKeys = new[] { BcAlgorithms.Rsa },
    };

    public bool GenerateKey(KeySpec spec, out IScepKey key, out string error) {
        RsaKeyPairGenerator generator;
        AsymmetricCipherKeyPair pair;

        key = null!;
        error = string.Empty;

        if (!spec.Algorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase)) {
            error = $"provider does not support key algorithm '{spec.Algorithm}'";
            return false;
        }

        try {
            generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(_random, spec.Size));
            pair = generator.GenerateKeyPair();
            key = new BcKey(pair, BcAlgorithms.Rsa, spec.Size);
            return true;
        } catch (Exception ex) {
            error = $"RSA key generation failed: {ex.Message}";
            return false;
        }
    }

    public bool EncodeCsr(Pkcs10 csr, out byte[] der, out string error) {
        der = System.Array.Empty<byte>();
        error = string.Empty;

        if (csr.Key is not BcKey bc_key) {
            error = "CSR key was not produced by this provider";
            return false;
        }

        try {
            der = BcCsrBuilder.Build(csr, bc_key);
            return true;
        } catch (System.Exception ex) {
            error = $"CSR encode failed: {ex.Message}";
            return false;
        }
    }
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
                default:
                    error = $"unsupported message type: {message.MessageType}";
                    return false;
            }
        } catch (System.Exception ex) {
            error = $"{message.MessageType} encode failed: {ex.Message}";
            return false;
        }
    }

    public bool DecodePkiMessage(byte[] der, IScepKey recipient_key, CodecOptions options, out PkiMessage message, out string error) {
        message = null!;
        error = string.Empty;

        if (recipient_key is not BcKey bc_key) {
            error = "recipientKey was not produced by this provider";
            return false;
        }

        try {
            message = BcPkiMessage.Decode(der, bc_key, options);
            return true;
        } catch (System.Exception ex) {
            error = $"DecodePkiMessage failed: {ex.Message}";
            return false;
        }
    }

    public bool ExportPrivateKeyPkcs8(IScepKey key, out byte[] der, out string error) {
        der = System.Array.Empty<byte>();
        error = string.Empty;

        if (key is not BcKey bc_key) {
            error = "key was not produced by this provider";
            return false;
        }

        try {
            der = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(bc_key.KeyPair.Private).GetDerEncoded();
            return true;
        } catch (System.Exception ex) {
            error = $"ExportPrivateKeyPkcs8 failed: {ex.Message}";
            return false;
        }
    }

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

    public bool ExportPrivateKeyPkcs8Encrypted(IScepKey key, string passphrase, out byte[] der, out string error) {
        Org.BouncyCastle.OpenSsl.Pkcs8Generator generator;
        Org.BouncyCastle.Utilities.IO.Pem.PemObject pem;

        der = System.Array.Empty<byte>();
        error = string.Empty;

        if (key is not BcKey bc_key) {
            error = "key was not produced by this provider";
            return false;
        }

        try {
            generator = new Org.BouncyCastle.OpenSsl.Pkcs8Generator(
                bc_key.KeyPair.Private,
                Org.BouncyCastle.OpenSsl.Pkcs8Generator.PbeSha1_3DES);
            generator.Password = passphrase.ToCharArray();
            generator.SecureRandom = _random;
            pem = generator.Generate();
            der = pem.Content;
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

    public bool ParseCaCertificates(byte[] der, out IReadOnlyList<X509Certificate2> certs, out string error) {
        List<X509Certificate2> result;

        certs = System.Array.Empty<X509Certificate2>();
        error = string.Empty;
        result = new List<X509Certificate2>();

        // Try single DER certificate first
        try {
            result.Add(new X509Certificate2(der));
            certs = result.AsReadOnly();
            return true;
        } catch {
            // fall through to degenerate PKCS#7 parse
        }

        // Try degenerate PKCS#7 SignedData (no signers, certs only)
        try {
            CmsSignedData signed_data;
            Org.BouncyCastle.Utilities.Collections.IStore<Org.BouncyCastle.X509.X509Certificate> cert_store;

            signed_data = new CmsSignedData(der);
            cert_store = signed_data.GetCertificates();
            foreach (Org.BouncyCastle.X509.X509Certificate bc_cert in cert_store.EnumerateMatches(null)) {
                result.Add(new X509Certificate2(bc_cert.GetEncoded()));
            }

            certs = result.AsReadOnly();
            return true;
        } catch (System.Exception ex) {
            error = $"ParseCaCertificates failed: {ex.Message}";
            return false;
        }
    }
}
