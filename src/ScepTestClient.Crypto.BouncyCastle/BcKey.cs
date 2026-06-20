using Org.BouncyCastle.Crypto;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Crypto.BouncyCastle;

internal sealed class BcKey : IScepKey {
    public AsymmetricCipherKeyPair KeyPair { get; }
    public string AlgorithmOid { get; }
    public int SizeBits { get; }

    public BcKey(AsymmetricCipherKeyPair key_pair, string algorithm_oid, int size_bits) {
        KeyPair = key_pair;
        AlgorithmOid = algorithm_oid;
        SizeBits = size_bits;
    }
}
