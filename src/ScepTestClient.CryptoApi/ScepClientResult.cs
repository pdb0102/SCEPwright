namespace ScepTestClient.CryptoApi;

public enum ScepClientResult {
    Ok = 0,
    InvalidArgument,
    NetworkError,
    ProtocolError,
    CryptoError,
    ServerFailure,
    Pending,
    StorageError,
    NotFound,
    ProviderError,
}
