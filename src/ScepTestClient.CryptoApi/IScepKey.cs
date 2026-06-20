namespace ScepTestClient.CryptoApi;

public interface IScepKey {
    string AlgorithmOid { get; }
    int SizeBits { get; }
}
