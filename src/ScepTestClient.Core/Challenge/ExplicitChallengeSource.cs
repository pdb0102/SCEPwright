using System.Threading.Tasks;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Challenge;

public sealed class ExplicitChallengeSource : IChallengeSource {
    private readonly string _value;

    public ExplicitChallengeSource(string value) { _value = value; }

    public bool TryGet(out string challenge, out string error) {
        challenge = _value;
        error = string.Empty;
        return true;
    }

    public Task<ScepResult<string>> GetAsync() => Task.FromResult(ScepResult<string>.Ok(_value));
}
