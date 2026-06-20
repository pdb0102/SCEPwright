using System.Threading.Tasks;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Challenge;

public interface IChallengeSource {
    bool TryGet(out string challenge, out string error);
    Task<ScepResult<string>> GetAsync();
}
