namespace ScepTestClient.CryptoApi;

public readonly struct ScepResult<T> {
    public ScepClientResult Status { get; }
    public T Value { get; }
    public string Error { get; }

    private ScepResult(ScepClientResult status, T value, string error) {
        Status = status;
        Value = value;
        Error = error;
    }

    public bool IsOk => Status == ScepClientResult.Ok;

    public static ScepResult<T> Ok(T value) => new(ScepClientResult.Ok, value, string.Empty);

    public static ScepResult<T> Fail(ScepClientResult status, string error) =>
        new(status, default!, error);

    public static ScepResult<T> Fail(ScepClientResult status, T value, string error) =>
        new(status, value, error);
}
