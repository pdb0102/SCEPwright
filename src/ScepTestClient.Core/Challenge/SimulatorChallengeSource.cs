using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Challenge;

public sealed class SimulatorChallengeSource : IChallengeSource {
    private readonly HttpClient _http;
    private readonly string _base_url;

    public SimulatorChallengeSource(HttpClient http, string base_url) {
        _http = http;
        _base_url = base_url.TrimEnd('/');
    }

    public bool TryGet(out string challenge, out string error) {
        ScepResult<string> result;

        result = GetAsync().GetAwaiter().GetResult();
        challenge = result.IsOk ? result.Value : string.Empty;
        error = result.Error;
        return result.IsOk;
    }

    public async Task<ScepResult<string>> GetAsync() {
        HttpResponseMessage response;
        string body;
        JsonDocument doc;
        System.Text.Json.JsonElement element;

        try {
            response = await _http.PostAsync(_base_url + "/challenge", new StringContent("{}", System.Text.Encoding.UTF8, "application/json")).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) {
                return ScepResult<string>.Fail(ScepClientResult.NetworkError, $"simulator returned {(int)response.StatusCode}");
            }
            body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("challengePassword", out element)) {
                return ScepResult<string>.Fail(ScepClientResult.ProtocolError, "no challengePassword in response");
            }
            return ScepResult<string>.Ok(element.GetString() ?? string.Empty);
        } catch (System.Exception ex) {
            return ScepResult<string>.Fail(ScepClientResult.NetworkError, ex.Message);
        }
    }
}
