using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using ScepWright.Crypto;

namespace ScepWright.Crypto.BouncyCastle;

/// <summary>BouncyCastle-backed implementation of <see cref="IScepCrypto"/>, supporting classical and post-quantum algorithms.</summary>
public sealed class BouncyCastleScepCrypto : IScepCrypto {
    private readonly SecureRandom _random = new SecureRandom();

    /// <inheritdoc/>
    public CryptoCapabilities Capabilities { get; } = new CryptoCapabilities {
        Digests = new[] { BcAlgorithms.Sha1, BcAlgorithms.Sha256, BcAlgorithms.Sha384, BcAlgorithms.Sha512, BcAlgorithms.Md5 },
        Signatures = new[] { BcAlgorithms.Rsa, BcAlgorithms.EcPublicKey, BcAlgorithms.MlDsa44, BcAlgorithms.MlDsa65, BcAlgorithms.MlDsa87,
                             BcAlgorithms.SlhDsa128s, BcAlgorithms.SlhDsa128f, BcAlgorithms.SlhDsa192s,
                             BcAlgorithms.SlhDsa192f, BcAlgorithms.SlhDsa256s, BcAlgorithms.SlhDsa256f },
        ContentEncryption = new[] { BcAlgorithms.Aes128Cbc, BcAlgorithms.Aes256Cbc, BcAlgorithms.Des3Cbc },
        KeyTransport = new[] { BcAlgorithms.Rsa },
        KeyAgreement = new[] { BcAlgorithms.EcPublicKey },
        Kem = new[] { BcAlgorithms.MlKem512, BcAlgorithms.MlKem768, BcAlgorithms.MlKem1024 },
        AsymmetricKeys = new[] { BcAlgorithms.Rsa, BcAlgorithms.EcPublicKey, BcAlgorithms.MlDsa44, BcAlgorithms.MlDsa65, BcAlgorithms.MlDsa87,
                                 BcAlgorithms.SlhDsa128s, BcAlgorithms.SlhDsa128f, BcAlgorithms.SlhDsa192s,
                                 BcAlgorithms.SlhDsa192f, BcAlgorithms.SlhDsa256s, BcAlgorithms.SlhDsa256f },
        PqTiers = new PqTiers(TierA: true, TierB: true, TierC: true),
    };

    /// <inheritdoc/>
    public bool GenerateKey(KeySpec spec, out IScepKey key, out string error) {
        RsaKeyPairGenerator generator;
        AsymmetricCipherKeyPair pair;
        AsymmetricCipherKeyPair pq_pair;
        string pq_oid_name;
        string pq_error;

        key = null!;
        error = string.Empty;

        try {
            if (BcPqKeys.TryGenerate(spec, _random, out pq_pair, out pq_oid_name, out pq_error)) {
                key = new BcKey(pq_pair, Algorithms.OidFor(pq_oid_name)!, 0);
                return true;
            }
        } catch (Exception ex) {
            error = $"{spec.Algorithm} key generation failed: {ex.Message}";
            return false;
        }
        if (pq_error.Length > 0) {
            error = pq_error;
            return false;
        }

        if (spec.Algorithm.Equals("EC", StringComparison.OrdinalIgnoreCase)) {
            string curve_name;
            Org.BouncyCastle.Asn1.DerObjectIdentifier curve_oid;
            Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator ec_gen;
            AsymmetricCipherKeyPair ec_pair;

            try {
                // Use the named-curve OID (not explicit domain params) so the SubjectPublicKeyInfo
                // encodes the curve by OID — explicit ECC parameters are rejected by OpenSSL and many
                // TLS stacks.
                curve_name = spec.Size == 256 ? "P-256" : spec.Size == 384 ? "P-384" : "P-521";
                curve_oid = Org.BouncyCastle.Asn1.Nist.NistNamedCurves.GetOid(curve_name);
                ec_gen = new Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator();
                ec_gen.Init(new Org.BouncyCastle.Crypto.Parameters.ECKeyGenerationParameters(curve_oid, _random));
                ec_pair = ec_gen.GenerateKeyPair();
                key = new BcKey(ec_pair, BcAlgorithms.EcPublicKey, spec.Size);
                return true;
            } catch (Exception ex) {
                error = $"EC key generation failed: {ex.Message}";
                return false;
            }
        }

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

    /// <inheritdoc/>
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
    /// <inheritdoc/>
    public bool EncodePkiMessage(PkiMessage message, FaultDirectives? faults, out byte[] der, out string error) {
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
                    der = BcPkiMessage.EncodePkiOperation(message, csr_der, signer_key, ScepAttributes.NumberFor(message.MessageType), faults);
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
                        ScepAttributes.NumberFor(message.MessageType),
                        faults);
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
                        ScepAttributes.NumberFor(message.MessageType),
                        faults);
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

    /// <inheritdoc/>
    public bool DecodePkiMessage(byte[] der, IScepKey recipient_key, CodecOptions options, System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>? known_certs, out PkiMessage message, out string error) {
        message = null!;
        error = string.Empty;

        if (recipient_key is not BcKey bc_key) {
            error = "recipientKey was not produced by this provider";
            return false;
        }

        try {
            string decode_error;

            message = BcPkiMessage.Decode(der, bc_key, options, known_certs, out decode_error);
            if (decode_error.Length > 0) {
                error = decode_error;
                return false;
            }
            return true;
        } catch (System.Exception ex) {
            error = $"DecodePkiMessage failed: {ex.Message}";
            return false;
        }
    }

    /// <inheritdoc/>
    public bool ExportPrivateKeyPkcs8(IScepKey key, out byte[] der, out string error) {
        der = System.Array.Empty<byte>();
        error = string.Empty;

        if (key is not BcKey bc_key) {
            error = "key was not produced by this provider";
            return false;
        }

        try {
            // The mainline PrivateKeyInfoFactory handles both RSA and the BC 2.6.1
            // Org.BouncyCastle.Crypto.Parameters ML-DSA / SLH-DSA key types.
            der = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(bc_key.KeyPair.Private).GetDerEncoded();
            return true;
        } catch (System.Exception ex) {
            error = $"ExportPrivateKeyPkcs8 failed: {ex.Message}";
            return false;
        }
    }

    /// <inheritdoc/>
    public bool ImportPrivateKeyPkcs8(byte[] der, out IScepKey key, out string error) {
        Org.BouncyCastle.Crypto.AsymmetricKeyParameter priv;
        Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters rsa_priv;
        Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters pub;
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair;
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pq_pair;
        string pq_oid_name;
        string pq_error;

        key = null!;
        error = string.Empty;

        try {
            priv = Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(der);
            if (BcPqKeys.TryImport(priv, out pq_pair, out pq_oid_name, out pq_error)) {
                key = new BcKey(pq_pair, Algorithms.OidFor(pq_oid_name)!, 0);
                return true;
            }
            if (pq_error.Length > 0) {
                error = pq_error;
                return false;
            }
            if (priv is Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters ec_priv) {
                Org.BouncyCastle.Math.EC.ECPoint q;
                Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters ec_pub;
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair ec_pair;
                int size_bits;

                q = ec_priv.Parameters.G.Multiply(ec_priv.D).Normalize();
                ec_pub = new Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters(q, ec_priv.Parameters);
                ec_pair = new Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair(ec_pub, ec_priv);
                size_bits = ec_priv.Parameters.Curve.FieldSize;
                key = new BcKey(ec_pair, BcAlgorithms.EcPublicKey, size_bits);
                return true;
            }
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

    // At-rest key protection: PBES2 with a PBKDF2-HMAC-SHA256 KDF and an AES-256-CBC bulk cipher
    // (BouncyCastle's Pkcs8Generator only offers the legacy PBES1 SHA-1 + 3DES, so the PBES2
    // structure is assembled here from primitives). Import via DecryptKey reads any PBES1/PBES2 scheme,
    // so previously stored PBES1 keys still load.
    private const int Pkcs8IterationCount = 100_000;

    /// <inheritdoc/>
    public bool ExportPrivateKeyPkcs8Encrypted(IScepKey key, string passphrase, out byte[] der, out string error) {
        byte[] salt;
        byte[] iv;
        byte[] plain;
        Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator kdf_gen;
        Org.BouncyCastle.Crypto.Parameters.KeyParameter derived;
        Org.BouncyCastle.Crypto.IBufferedCipher cipher;
        byte[] encrypted;
        Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier prf;
        Org.BouncyCastle.Asn1.DerSequence pbkdf2_params;
        Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier kdf_alg;
        Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier enc_scheme;
        Org.BouncyCastle.Asn1.DerSequence pbes2_params;
        Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier alg_id;
        Org.BouncyCastle.Asn1.Pkcs.EncryptedPrivateKeyInfo enc_info;

        der = System.Array.Empty<byte>();
        error = string.Empty;

        if (key is not BcKey bc_key) {
            error = "key was not produced by this provider";
            return false;
        }

        try {
            salt = new byte[16];
            iv = new byte[16];
            _random.NextBytes(salt);
            _random.NextBytes(iv);

            plain = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(bc_key.KeyPair.Private).GetDerEncoded();

            kdf_gen = new Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
            kdf_gen.Init(Org.BouncyCastle.Crypto.PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(passphrase.ToCharArray()), salt, Pkcs8IterationCount);
            derived = (Org.BouncyCastle.Crypto.Parameters.KeyParameter)kdf_gen.GenerateDerivedParameters("AES", 256);

            cipher = Org.BouncyCastle.Security.CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
            cipher.Init(true, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(derived, iv));
            encrypted = cipher.DoFinal(plain);

            prf = new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(
                Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.IdHmacWithSha256, Org.BouncyCastle.Asn1.DerNull.Instance);
            pbkdf2_params = new Org.BouncyCastle.Asn1.DerSequence(
                new Org.BouncyCastle.Asn1.DerOctetString(salt),
                new Org.BouncyCastle.Asn1.DerInteger(Pkcs8IterationCount),
                prf);
            kdf_alg = new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(
                Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.IdPbkdf2, pbkdf2_params);
            enc_scheme = new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(
                Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers.IdAes256Cbc, new Org.BouncyCastle.Asn1.DerOctetString(iv));
            pbes2_params = new Org.BouncyCastle.Asn1.DerSequence(kdf_alg, enc_scheme);
            alg_id = new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(
                Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.IdPbeS2, pbes2_params);

            enc_info = new Org.BouncyCastle.Asn1.Pkcs.EncryptedPrivateKeyInfo(alg_id, encrypted);
            der = enc_info.GetEncoded();
            return true;
        } catch (System.Exception ex) {
            error = $"ExportPrivateKeyPkcs8Encrypted failed: {ex.Message}";
            return false;
        }
    }

    /// <inheritdoc/>
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

    /// <inheritdoc/>
    public bool ExportPkcs12(IScepKey key, X509Certificate2 leaf, IReadOnlyList<X509Certificate2> chain, string password, bool legacy, out byte[] der, out string error) {
        Org.BouncyCastle.X509.X509CertificateParser parser;
        List<Org.BouncyCastle.Pkcs.X509CertificateEntry> entries;
        Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder builder;
        Org.BouncyCastle.Pkcs.Pkcs12Store store;
        System.IO.MemoryStream buffer;
        string alias;

        der = System.Array.Empty<byte>();
        error = string.Empty;

        if (key is not BcKey bc_key) {
            error = "key was not produced by this provider";
            return false;
        }

        try {
            parser = new Org.BouncyCastle.X509.X509CertificateParser();
            entries = new List<Org.BouncyCastle.Pkcs.X509CertificateEntry>();
            entries.Add(new Org.BouncyCastle.Pkcs.X509CertificateEntry(parser.ReadCertificate(leaf.RawData)));
            foreach (X509Certificate2 chain_cert in chain) {
                entries.Add(new Org.BouncyCastle.Pkcs.X509CertificateEntry(parser.ReadCertificate(chain_cert.RawData)));
            }

            alias = leaf.GetNameInfo(X509NameType.SimpleName, false);
            if (string.IsNullOrEmpty(alias)) { alias = "scepwright"; }

            builder = new Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder();
            if (!legacy) {
                // Modern bags: PBES2 AES-256-CBC with a PBKDF2-HMAC-SHA256 PRF (the two-arg overload's
                // second parameter is the PRF's OID). Read natively by OpenSSL 3 (no -legacy) and modern
                // Windows/Intune.
                builder = builder
                    .SetKeyAlgorithm(Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers.IdAes256Cbc, Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.IdHmacWithSha256)
                    .SetCertAlgorithm(Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers.IdAes256Cbc, Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.IdHmacWithSha256);
            }
            // legacy=true leaves the builder on the classic SHA-1/RC2/3DES PKCS#12 bags for old importers.

            store = builder.Build();
            store.SetKeyEntry(alias, new Org.BouncyCastle.Pkcs.AsymmetricKeyEntry(bc_key.KeyPair.Private), entries.ToArray());

            buffer = new System.IO.MemoryStream();
            store.Save(buffer, password.ToCharArray(), _random);
            der = buffer.ToArray();
            // Pkcs12Store.Save always writes the integrity MAC with SHA-1; for the modern profile re-wrap
            // the PFX with a SHA-256 MAC so the whole artifact is SHA-2 (legacy keeps the SHA-1 MAC).
            if (!legacy) {
                der = ReMacSha256(der, password.ToCharArray());
            }
            return true;
        } catch (System.Exception ex) {
            error = $"ExportPkcs12 failed: {ex.Message}";
            return false;
        }
    }

    // BC's Pkcs12Store.Save has no MAC-algorithm knob (it always emits a SHA-1 MacData). Re-wrap the
    // saved PFX with a freshly computed SHA-256 MAC over the same AuthenticatedSafe — the bags are
    // untouched, so the key still loads; only the integrity MAC algorithm changes.
    private byte[] ReMacSha256(byte[] pfx_der, char[] password) {
        Org.BouncyCastle.Asn1.Pkcs.Pfx pfx;
        Org.BouncyCastle.Asn1.Pkcs.ContentInfo auth_safe;
        byte[] data;
        byte[] salt;
        int iterations;
        byte[] mac;
        Org.BouncyCastle.Asn1.X509.DigestInfo dig_info;
        Org.BouncyCastle.Asn1.Pkcs.MacData mac_data;

        pfx = Org.BouncyCastle.Asn1.Pkcs.Pfx.GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(pfx_der));
        auth_safe = pfx.AuthSafe;
        data = ((Org.BouncyCastle.Asn1.Asn1OctetString)auth_safe.Content).GetOctets();

        salt = new byte[20];
        _random.NextBytes(salt);
        iterations = 2048;
        mac = ComputePkcs12Mac(data, password, salt, iterations);

        dig_info = new Org.BouncyCastle.Asn1.X509.DigestInfo(
            new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers.IdSha256, Org.BouncyCastle.Asn1.DerNull.Instance), mac);
        mac_data = new Org.BouncyCastle.Asn1.Pkcs.MacData(dig_info, salt, iterations);
        return new Org.BouncyCastle.Asn1.Pkcs.Pfx(auth_safe, mac_data).GetEncoded(Org.BouncyCastle.Asn1.Asn1Encodable.Der);
    }

    // PKCS#12 integrity MAC: HMAC-SHA256 keyed by the PKCS#12 KDF (ID=3 / MAC purpose) over the
    // password+salt. Mirrors what an importer recomputes to verify the PFX.
    private static byte[] ComputePkcs12Mac(byte[] data, char[] password, byte[] salt, int iterations) {
        Org.BouncyCastle.Crypto.IDigest digest;
        Org.BouncyCastle.Crypto.Generators.Pkcs12ParametersGenerator generator;
        Org.BouncyCastle.Crypto.ICipherParameters key_param;
        Org.BouncyCastle.Crypto.Macs.HMac hmac;
        byte[] mac;

        digest = Org.BouncyCastle.Security.DigestUtilities.GetDigest("SHA-256");
        generator = new Org.BouncyCastle.Crypto.Generators.Pkcs12ParametersGenerator(digest);
        generator.Init(Org.BouncyCastle.Crypto.PbeParametersGenerator.Pkcs12PasswordToBytes(password), salt, iterations);
        key_param = generator.GenerateDerivedMacParameters(digest.GetDigestSize() * 8);

        hmac = new Org.BouncyCastle.Crypto.Macs.HMac(Org.BouncyCastle.Security.DigestUtilities.GetDigest("SHA-256"));
        hmac.Init(key_param);
        hmac.BlockUpdate(data, 0, data.Length);
        mac = new byte[hmac.GetMacSize()];
        hmac.DoFinal(mac, 0);
        return mac;
    }

    /// <inheritdoc/>
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
