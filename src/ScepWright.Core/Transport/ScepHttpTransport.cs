using System;
using System.Net.Http;
using System.Threading.Tasks;
using ScepWright.Crypto;

namespace ScepWright.Core.Transport;

/// <summary>HTTP transport for SCEP operations: builds the query URLs and reads the binary responses.</summary>
public sealed class ScepHttpTransport {
    private readonly HttpClient _http;
    private readonly Uri _base_url;

    /// <summary>Creates a transport against the given base URL with the given request timeout.</summary>
    public ScepHttpTransport(HttpClient http, Uri base_url, TimeSpan timeout) {
        _http = http;
        _base_url = base_url;
        _http.Timeout = timeout;
    }

    private Uri BuildGetUri(string operation, string message) {
        string query;

        query = $"?operation={Uri.EscapeDataString(operation)}";
        if (message.Length > 0) { query += $"&message={Uri.EscapeDataString(message)}"; }
        return new Uri(_base_url + query);
    }

    /// <summary>
    /// Returns the fully-resolved GET URL for an operation, for diagnostic logging — so `diagnose -v`
    /// can show exactly what was requested without the caller re-deriving the query string.
    /// </summary>
    public string DescribeGet(string operation, string message) {
        return BuildGetUri(operation, message).ToString();
    }

    /// <summary>Issues a GET for the given SCEP operation with the message in the query string.</summary>
    public async Task<ScepResult<byte[]>> GetAsync(string operation, string message) {
        HttpResponseMessage resp;

        try {
            resp = await _http.GetAsync(BuildGetUri(operation, message)).ConfigureAwait(false);
            return await ReadAsync(resp).ConfigureAwait(false);
        } catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    /// <summary>Issues a GET for the given SCEP operation with the message in the query string.</summary>
    public ScepResult<byte[]> Get(string operation, string message) {
        HttpResponseMessage resp;

        try {
            resp = _http.Send(new HttpRequestMessage(HttpMethod.Get, BuildGetUri(operation, message)));
            return Read(resp);
        } catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    /// <summary>POSTs the binary PKI message body for the given SCEP operation.</summary>
    public async Task<ScepResult<byte[]>> PostAsync(string operation, byte[] body) {
        HttpResponseMessage resp;

        try {
            resp = await _http.PostAsync(BuildGetUri(operation, string.Empty), PkiContent(body)).ConfigureAwait(false);
            return await ReadAsync(resp).ConfigureAwait(false);
        } catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    /// <summary>POSTs the binary PKI message body for the given SCEP operation.</summary>
    public ScepResult<byte[]> Post(string operation, byte[] body) {
        HttpRequestMessage req;

        try {
            req = new HttpRequestMessage(HttpMethod.Post, BuildGetUri(operation, string.Empty)) { Content = PkiContent(body) };
            return Read(_http.Send(req));
        } catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    private static ByteArrayContent PkiContent(byte[] body) {
        ByteArrayContent content;

        content = new ByteArrayContent(body);
        content.Headers.TryAddWithoutValidation("Content-Type", "application/x-pki-message");
        return content;
    }

    /// <summary>
    /// Returns a friendly description of an HTTP error status. A bare "HTTP 404" tells a non-expert
    /// nothing; it almost always means the SCEP URL path is wrong.
    /// </summary>
    public static string DescribeHttpError(int status) {
        if (status == 404) {
            return "HTTP 404 (Not Found) — the SCEP endpoint path looks wrong; verify the server URL path (commonly /scep, /certsrv/mscep/mscep.dll, or /<app>/pkiclient.exe)";
        }
        return $"HTTP {status}";
    }

    /// <summary>
    /// As <see cref="DescribeHttpError(int)"/>, but folds in a snippet of the server's response body.
    /// A bare "HTTP 500" hides the real reason — for a 500 the cause is almost always in the body the
    /// server returned (an exception string, a stack, a Venafi error). The snippet is whitespace-collapsed
    /// and truncated so a multi-kilobyte HTML error page can't flood the console.
    /// </summary>
    public static string DescribeHttpError(int status, string body) {
        string baseline;
        string snippet;

        baseline = DescribeHttpError(status);
        snippet = Snippet(body);
        if (snippet.Length == 0) { return baseline; }
        return $"{baseline} — server said: {snippet}";
    }

    private const int BodySnippetMax = 200;

    private static string Snippet(string body) {
        string collapsed;

        if (string.IsNullOrWhiteSpace(body)) { return string.Empty; }
        collapsed = System.Text.RegularExpressions.Regex.Replace(body.Trim(), "\\s+", " ");
        if (collapsed.Length > BodySnippetMax) { return collapsed.Substring(0, BodySnippetMax) + "…"; }
        return collapsed;
    }

    private static ScepResult<byte[]> Read(HttpResponseMessage resp) {
        byte[] body;

        if (!resp.IsSuccessStatusCode) {
            body = resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, DescribeHttpError((int)resp.StatusCode, Decode(body)));
        }
        return ScepResult<byte[]>.Ok(resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult());
    }

    private static async Task<ScepResult<byte[]>> ReadAsync(HttpResponseMessage resp) {
        byte[] body;

        if (!resp.IsSuccessStatusCode) {
            body = await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, DescribeHttpError((int)resp.StatusCode, Decode(body)));
        }
        return ScepResult<byte[]>.Ok(await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false));
    }

    private static string Decode(byte[] body) {
        if (body is null || body.Length == 0) { return string.Empty; }
        return System.Text.Encoding.UTF8.GetString(body);
    }

}
