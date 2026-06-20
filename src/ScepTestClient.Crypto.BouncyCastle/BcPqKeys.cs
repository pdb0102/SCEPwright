using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Crypto.BouncyCastle;

// Post-quantum (tier A) key generation and PKCS#8 import helpers, kept separate
// from BouncyCastleScepCrypto to keep the RSA paths readable.
internal static class BcPqKeys {
    // Returns true and sets pair/oid_name for an ML-DSA or SLH-DSA spec.
    // Returns false with an EMPTY error when the spec is not PQ (caller falls through to RSA).
    // Returns false WITH an error when a PQ algorithm is recognized but the parameter set is unsupported.
    public static bool TryGenerate(KeySpec spec, SecureRandom random, out AsymmetricCipherKeyPair pair, out string oid_name, out string error) {
        pair = null!;
        oid_name = string.Empty;
        error = string.Empty;

        if (spec.Algorithm.Equals("ML-DSA", StringComparison.OrdinalIgnoreCase)) {
            MLDsaParameters parameters;
            MLDsaKeyPairGenerator generator;

            switch (spec.Parameter) {
                case "44":
                    parameters = MLDsaParameters.ml_dsa_44;
                    oid_name = "ML-DSA-44";
                    break;
                case "65":
                    parameters = MLDsaParameters.ml_dsa_65;
                    oid_name = "ML-DSA-65";
                    break;
                case "87":
                    parameters = MLDsaParameters.ml_dsa_87;
                    oid_name = "ML-DSA-87";
                    break;
                default:
                    error = $"unsupported ML-DSA parameter set '{spec.Parameter}'";
                    return false;
            }

            generator = new MLDsaKeyPairGenerator();
            generator.Init(new MLDsaKeyGenerationParameters(random, parameters));
            pair = generator.GenerateKeyPair();
            return true;
        }

        if (spec.Algorithm.Equals("SLH-DSA", StringComparison.OrdinalIgnoreCase)) {
            SlhDsaParameters parameters;
            SlhDsaKeyPairGenerator generator;

            switch (spec.Parameter) {
                case "128s":
                    parameters = SlhDsaParameters.slh_dsa_sha2_128s;
                    oid_name = "SLH-DSA-128s";
                    break;
                case "128f":
                    parameters = SlhDsaParameters.slh_dsa_sha2_128f;
                    oid_name = "SLH-DSA-128f";
                    break;
                case "192s":
                    parameters = SlhDsaParameters.slh_dsa_sha2_192s;
                    oid_name = "SLH-DSA-192s";
                    break;
                case "192f":
                    parameters = SlhDsaParameters.slh_dsa_sha2_192f;
                    oid_name = "SLH-DSA-192f";
                    break;
                case "256s":
                    parameters = SlhDsaParameters.slh_dsa_sha2_256s;
                    oid_name = "SLH-DSA-256s";
                    break;
                case "256f":
                    parameters = SlhDsaParameters.slh_dsa_sha2_256f;
                    oid_name = "SLH-DSA-256f";
                    break;
                default:
                    error = $"unsupported SLH-DSA parameter set '{spec.Parameter}'";
                    return false;
            }

            generator = new SlhDsaKeyPairGenerator();
            generator.Init(new SlhDsaKeyGenerationParameters(random, parameters));
            pair = generator.GenerateKeyPair();
            return true;
        }

        return false;
    }

    // If priv is an ML-DSA / SLH-DSA private key, derive its public key, build the keypair,
    // and set oid_name from the parameter set. Returns false with an EMPTY error when priv is
    // not a PQ type (caller falls through to the RSA import path).
    public static bool TryImport(AsymmetricKeyParameter priv, out AsymmetricCipherKeyPair pair, out string oid_name, out string error) {
        pair = null!;
        oid_name = string.Empty;
        error = string.Empty;

        if (priv is MLDsaPrivateKeyParameters ml_priv) {
            MLDsaPublicKeyParameters ml_pub;

            ml_pub = ml_priv.GetPublicKey();
            oid_name = MlDsaNameFor(ml_priv.Parameters);
            if (oid_name.Length == 0) {
                error = $"unsupported ML-DSA parameter set '{ml_priv.Parameters.Name}'";
                return false;
            }
            pair = new AsymmetricCipherKeyPair(ml_pub, ml_priv);
            return true;
        }

        if (priv is SlhDsaPrivateKeyParameters slh_priv) {
            SlhDsaPublicKeyParameters slh_pub;

            slh_pub = slh_priv.GetPublicKey();
            oid_name = SlhDsaNameFor(slh_priv.Parameters);
            if (oid_name.Length == 0) {
                error = $"unsupported SLH-DSA parameter set '{slh_priv.Parameters.Name}'";
                return false;
            }
            pair = new AsymmetricCipherKeyPair(slh_pub, slh_priv);
            return true;
        }

        return false;
    }

    // True when the key is a post-quantum (ML-DSA / SLH-DSA) key. Detected via the
    // private key's runtime type, which is the most robust signal across import/keygen paths.
    public static bool IsPq(BcKey key) {
        return key.KeyPair.Private is MLDsaPrivateKeyParameters || key.KeyPair.Private is SlhDsaPrivateKeyParameters;
    }

    // Build a PQ ISignatureFactory for the key. Asn1SignatureFactory accepts a string that is either
    // a registered algorithm name OR a dotted OID. ML-DSA registers the friendly name ("ML-DSA-65"),
    // but SLH-DSA does NOT register "SLH-DSA-128f" et al. — only the OID resolves. BcKey.AlgorithmOid
    // is the dotted NIST OID for the (now correct) registry entry, which Asn1SignatureFactory accepts
    // for both families, so sign by OID uniformly. Emits the correct PQ AlgorithmIdentifier.
    public static ISignatureFactory SignatureFactory(BcKey key) {
        if (key.KeyPair.Private is not MLDsaPrivateKeyParameters && key.KeyPair.Private is not SlhDsaPrivateKeyParameters) {
            throw new InvalidOperationException("private key is not a supported post-quantum type");
        }

        return new Asn1SignatureFactory(key.AlgorithmOid, key.KeyPair.Private, new SecureRandom());
    }

    // Map a BC ML-DSA parameter set instance to the registry-friendly name.
    private static string MlDsaNameFor(MLDsaParameters parameters) {
        if (ReferenceEquals(parameters, MLDsaParameters.ml_dsa_44)) {
            return "ML-DSA-44";
        }
        if (ReferenceEquals(parameters, MLDsaParameters.ml_dsa_65)) {
            return "ML-DSA-65";
        }
        if (ReferenceEquals(parameters, MLDsaParameters.ml_dsa_87)) {
            return "ML-DSA-87";
        }
        return string.Empty;
    }

    // Map a BC SLH-DSA parameter set instance to the registry-friendly name.
    private static string SlhDsaNameFor(SlhDsaParameters parameters) {
        if (ReferenceEquals(parameters, SlhDsaParameters.slh_dsa_sha2_128s)) {
            return "SLH-DSA-128s";
        }
        if (ReferenceEquals(parameters, SlhDsaParameters.slh_dsa_sha2_128f)) {
            return "SLH-DSA-128f";
        }
        if (ReferenceEquals(parameters, SlhDsaParameters.slh_dsa_sha2_192s)) {
            return "SLH-DSA-192s";
        }
        if (ReferenceEquals(parameters, SlhDsaParameters.slh_dsa_sha2_192f)) {
            return "SLH-DSA-192f";
        }
        if (ReferenceEquals(parameters, SlhDsaParameters.slh_dsa_sha2_256s)) {
            return "SLH-DSA-256s";
        }
        if (ReferenceEquals(parameters, SlhDsaParameters.slh_dsa_sha2_256f)) {
            return "SLH-DSA-256f";
        }
        return string.Empty;
    }
}
