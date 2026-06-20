using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Challenge;

public sealed class NdesChallengeSource : IChallengeSource {
    private readonly HttpClient _http;
    private readonly string _admin_url;
    private readonly string _user;
    private readonly string _password;

    public NdesChallengeSource(HttpClient http, string admin_url, string user, string password) {
        _http = http;
        _admin_url = admin_url;
        _user = user;
        _password = password;
    }

    public bool TryGet(out string challenge, out string error) {
        ScepResult<string> result;

        result = GetAsync().GetAwaiter().GetResult();
        challenge = result.IsOk ? result.Value : string.Empty;
        error = result.Error;
        return result.IsOk;
    }

    public async Task<ScepResult<string>> GetAsync() {
        HttpRequestMessage request;
        HttpResponseMessage response;
        string html;
        string token;

        try {
            request = new HttpRequestMessage(HttpMethod.Get, _admin_url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                System.Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_user}:{_password}")));
            response = await _http.SendAsync(request).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) {
                return ScepResult<string>.Fail(ScepClientResult.NetworkError, $"NDES admin returned {(int)response.StatusCode}");
            }
            html = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            token = Scrape(html);
            if (token.Length == 0) {
                return ScepResult<string>.Fail(ScepClientResult.ProtocolError, "no challenge found in NDES page");
            }
            return ScepResult<string>.Ok(token);
        } catch (System.Exception ex) {
            return ScepResult<string>.Fail(ScepClientResult.NetworkError, ex.Message);
        }
    }

    // The real NDES mscep_admin page reads:
    //   "The thumbprint (hash value) for the CA certificate is: <B> {thumbprint} </B>
    //    The enrollment challenge password is: <B> {challenge} </B>
    //    This password can be used only once and will expire within {n} minutes.
    //    ... Each enrollment requires a new challenge password."
    // The CA thumbprint is an earlier hex <B> block (a decoy), and "challenge password" recurs later,
    // so anchor to the FIRST "challenge password" label and take the next hex run after it. The lazy,
    // case-insensitive, single-line match tolerates light markup/whitespace changes (incl. the stray
    // 'B' from "<B>"). Fall back to the first hex run only when the label is absent.
    private static string Scrape(string html) {
        string source;
        Match anchored;
        Match m;

        source = html ?? string.Empty;

        anchored = Regex.Match(source, "challenge password.*?([0-9A-Fa-f]{8,64})", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        if (anchored.Success) { return anchored.Groups[1].Value; }

        m = Regex.Match(source, "([0-9A-Fa-f]{8,64})");
        return m.Success ? m.Groups[1].Value : string.Empty;
    }
}
