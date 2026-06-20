using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using ScepTestClient.Core.Protocol;
using ScepTestClient.Core.Transport;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

public sealed class ScepClient {
    private readonly ScepHttpTransport _transport;

    public IScepCrypto Crypto { get; }
    public ServerConfig Server { get; }
    public event Action<ScepTraceEvent>? Trace;

    private ScepClient(ServerConfig server, IScepCrypto crypto, ScepHttpTransport transport) {
        Server = server;
        Crypto = crypto;
        _transport = transport;
    }

    public static ScepClientResult Create(ServerConfig server, IScepCrypto crypto, HttpMessageHandler? handler, out ScepClient client, out string error) {
        HttpClient http;
        ScepHttpTransport transport;

        client = null!;
        error = string.Empty;

        if (server is null) {
            error = "server must not be null";
            return ScepClientResult.InvalidArgument;
        }

        if (crypto is null) {
            error = "crypto must not be null";
            return ScepClientResult.InvalidArgument;
        }

        http = handler is null ? new HttpClient() : new HttpClient(handler);
        transport = new ScepHttpTransport(http, server.Url, TimeSpan.FromSeconds(30));
        client = new ScepClient(server, crypto, transport);
        return ScepClientResult.Ok;
    }

    // -------------------------------------------------------------------------
    // GetCaCaps
    // -------------------------------------------------------------------------

    public ScepResult<ScepCapabilities> GetCaCaps() {
        ScepResult<byte[]> raw;
        string text;

        Emit(TraceLevel.Info, "GetCaCaps", "sending GetCACaps request");
        raw = _transport.Get("GetCACaps", Server.CaIdentifier ?? string.Empty);
        if (!raw.IsOk) {
            return ScepResult<ScepCapabilities>.Fail(raw.Status, raw.Error);
        }

        text = Encoding.ASCII.GetString(raw.Value);
        return ScepResult<ScepCapabilities>.Ok(ScepCapabilities.Parse(text));
    }

    public async Task<ScepResult<ScepCapabilities>> GetCaCapsAsync() {
        ScepResult<byte[]> raw;
        string text;

        Emit(TraceLevel.Info, "GetCaCaps", "sending GetCACaps request");
        raw = await _transport.GetAsync("GetCACaps", Server.CaIdentifier ?? string.Empty).ConfigureAwait(false);
        if (!raw.IsOk) {
            return ScepResult<ScepCapabilities>.Fail(raw.Status, raw.Error);
        }

        text = Encoding.ASCII.GetString(raw.Value);
        return ScepResult<ScepCapabilities>.Ok(ScepCapabilities.Parse(text));
    }

    // -------------------------------------------------------------------------
    // GetCaCert
    // -------------------------------------------------------------------------

    public ScepResult<IReadOnlyList<X509Certificate2>> GetCaCert() {
        ScepResult<byte[]> raw;
        IReadOnlyList<X509Certificate2> certs;
        string error;

        Emit(TraceLevel.Info, "GetCaCert", "sending GetCACert request");
        raw = _transport.Get("GetCACert", Server.CaIdentifier ?? string.Empty);
        if (!raw.IsOk) {
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(raw.Status, raw.Error);
        }

        if (!Crypto.ParseCaCertificates(raw.Value, out certs, out error)) {
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(ScepClientResult.CryptoError, error);
        }

        return ScepResult<IReadOnlyList<X509Certificate2>>.Ok(certs);
    }

    public async Task<ScepResult<IReadOnlyList<X509Certificate2>>> GetCaCertAsync() {
        ScepResult<byte[]> raw;
        IReadOnlyList<X509Certificate2> certs;
        string error;

        Emit(TraceLevel.Info, "GetCaCert", "sending GetCACert request");
        raw = await _transport.GetAsync("GetCACert", Server.CaIdentifier ?? string.Empty).ConfigureAwait(false);
        if (!raw.IsOk) {
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(raw.Status, raw.Error);
        }

        if (!Crypto.ParseCaCertificates(raw.Value, out certs, out error)) {
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(ScepClientResult.CryptoError, error);
        }

        return ScepResult<IReadOnlyList<X509Certificate2>>.Ok(certs);
    }

    // -------------------------------------------------------------------------
    // GetNextCaCert
    // -------------------------------------------------------------------------

    public ScepResult<IReadOnlyList<X509Certificate2>> GetNextCaCert() {
        ScepResult<byte[]> raw;
        IReadOnlyList<X509Certificate2> certs;
        string error;

        Emit(TraceLevel.Info, "GetNextCaCert", "sending GetNextCACert request");
        raw = _transport.Get("GetNextCACert", Server.CaIdentifier ?? string.Empty);
        if (!raw.IsOk) {
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(raw.Status, raw.Error);
        }

        if (!Crypto.ParseCaCertificates(raw.Value, out certs, out error)) {
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(ScepClientResult.CryptoError, error);
        }

        return ScepResult<IReadOnlyList<X509Certificate2>>.Ok(certs);
    }

    public async Task<ScepResult<IReadOnlyList<X509Certificate2>>> GetNextCaCertAsync() {
        ScepResult<byte[]> raw;
        IReadOnlyList<X509Certificate2> certs;
        string error;

        Emit(TraceLevel.Info, "GetNextCaCert", "sending GetNextCACert request");
        raw = await _transport.GetAsync("GetNextCACert", Server.CaIdentifier ?? string.Empty).ConfigureAwait(false);
        if (!raw.IsOk) {
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(raw.Status, raw.Error);
        }

        if (!Crypto.ParseCaCertificates(raw.Value, out certs, out error)) {
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(ScepClientResult.CryptoError, error);
        }

        return ScepResult<IReadOnlyList<X509Certificate2>>.Ok(certs);
    }

    // -------------------------------------------------------------------------
    // Enroll
    // -------------------------------------------------------------------------

    public ScepResult<EnrollOutcome> Enroll(EnrollRequest request) {
        PkiMessage pki_message;
        string build_error;
        ScepResult<EnrollOutcome> build_result;

        Emit(TraceLevel.Info, "Enroll", $"starting enroll for subject '{request.Subject}'");

        build_result = BuildPkiMessage(request, out pki_message, out build_error);
        if (!build_result.IsOk) {
            return build_result;
        }

        return SendEnrollSync(request, pki_message);
    }

    public async Task<ScepResult<EnrollOutcome>> EnrollAsync(EnrollRequest request) {
        PkiMessage pki_message;
        string build_error;
        ScepResult<EnrollOutcome> build_result;

        Emit(TraceLevel.Info, "Enroll", $"starting enroll for subject '{request.Subject}'");

        build_result = BuildPkiMessage(request, out pki_message, out build_error);
        if (!build_result.IsOk) {
            return build_result;
        }

        return await SendEnrollAsync(request, pki_message).ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // GetNewCertificate
    // -------------------------------------------------------------------------

    public async Task<ScepResult<EnrollOutcome>> GetNewCertificateAsync(EnrollRequest request, Storage.CertStore store, Storage.UseRecordLog log) {
        ScepResult<IReadOnlyList<X509Certificate2>> ca_result;
        ScepResult<EnrollOutcome> enroll_result;
        EnrollOutcome outcome;

        try {
            Emit(TraceLevel.Info, "GetNewCertificate", "starting enrollment lifecycle");

            if (request.CaCertificate is null) {
                ca_result = await GetCaCertAsync().ConfigureAwait(false);
                if (!ca_result.IsOk) {
                    return ScepResult<EnrollOutcome>.Fail(ca_result.Status, ca_result.Error);
                }
                request.CaCertificate = ca_result.Value[0];
            }

            enroll_result = await EnrollAsync(request).ConfigureAwait(false);

            if (enroll_result.IsOk) {
                outcome = enroll_result.Value;
                if (outcome.Certificate is not null) {
                    store.Save(Server.Id, outcome.Certificate, request, Crypto);
                }
                log.Append(Server.Id, outcome);
            }

            return enroll_result;
        } catch (Exception ex) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, ex.Message);
        }
    }

    public ScepResult<EnrollOutcome> GetNewCertificate(EnrollRequest request, Storage.CertStore store, Storage.UseRecordLog log) {
        ScepResult<IReadOnlyList<X509Certificate2>> ca_result;
        ScepResult<EnrollOutcome> enroll_result;
        EnrollOutcome outcome;

        try {
            Emit(TraceLevel.Info, "GetNewCertificate", "starting enrollment lifecycle");

            if (request.CaCertificate is null) {
                ca_result = GetCaCert();
                if (!ca_result.IsOk) {
                    return ScepResult<EnrollOutcome>.Fail(ca_result.Status, ca_result.Error);
                }
                request.CaCertificate = ca_result.Value[0];
            }

            enroll_result = Enroll(request);

            if (enroll_result.IsOk) {
                outcome = enroll_result.Value;
                if (outcome.Certificate is not null) {
                    store.Save(Server.Id, outcome.Certificate, request, Crypto);
                }
                log.Append(Server.Id, outcome);
            }

            return enroll_result;
        } catch (Exception ex) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, ex.Message);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private ScepResult<EnrollOutcome> BuildPkiMessage(EnrollRequest request, out PkiMessage pki_message, out string error) {
        Pkcs10 csr;

        pki_message = null!;
        error = string.Empty;

        if (request.CaCertificate is null) {
            error = "EnrollRequest.CaCertificate must be set";
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
        }

        csr = new Pkcs10();
        csr.SetSubject(request.Subject, out _);
        csr.Key = request.Key;
        csr.ChallengePassword = request.ChallengePassword;
        csr.Sid = request.Sid;

        foreach (string dns in request.DnsNames) {
            csr.DnsNames.Add(dns);
        }

        foreach (string upn in request.Upns) {
            csr.Upns.Add(upn);
        }

        foreach (string eku in request.Ekus) {
            csr.Ekus.Add(eku);
        }

        pki_message = new PkiMessage {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = request.Key,
            RecipientCaCert = request.CaCertificate,
            DigestAlgorithmOid = request.DigestOid,
            ContentEncryptionAlgorithmOid = request.ContentEncryptionOid,
            TransactionId = Guid.NewGuid().ToString("N"),
        };

        return ScepResult<EnrollOutcome>.Ok(null!);
    }

    private ScepResult<EnrollOutcome> SendEnrollSync(EnrollRequest request, PkiMessage pki_message) {
        byte[] der;
        string encode_error;
        ScepResult<byte[]> raw;
        Stopwatch sw;
        string trans_id;

        trans_id = pki_message.TransactionId!;

        if (!pki_message.Encode(Crypto, out der, out encode_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.CryptoError, encode_error);
        }

        sw = Stopwatch.StartNew();

        if (Server.PreferPost) {
            raw = _transport.Post("PKIOperation", der);
        } else {
            raw = _transport.Get("PKIOperation", Convert.ToBase64String(der));
        }

        sw.Stop();

        if (!raw.IsOk) {
            return ScepResult<EnrollOutcome>.Fail(raw.Status, raw.Error);
        }

        return DecodeEnrollResponse(raw.Value, request.Key, trans_id, sw.Elapsed);
    }

    private async Task<ScepResult<EnrollOutcome>> SendEnrollAsync(EnrollRequest request, PkiMessage pki_message) {
        byte[] der;
        string encode_error;
        ScepResult<byte[]> raw;
        Stopwatch sw;
        string trans_id;

        trans_id = pki_message.TransactionId!;

        if (!pki_message.Encode(Crypto, out der, out encode_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.CryptoError, encode_error);
        }

        sw = Stopwatch.StartNew();

        if (Server.PreferPost) {
            raw = await _transport.PostAsync("PKIOperation", der).ConfigureAwait(false);
        } else {
            raw = await _transport.GetAsync("PKIOperation", Convert.ToBase64String(der)).ConfigureAwait(false);
        }

        sw.Stop();

        if (!raw.IsOk) {
            return ScepResult<EnrollOutcome>.Fail(raw.Status, raw.Error);
        }

        return DecodeEnrollResponse(raw.Value, request.Key, trans_id, sw.Elapsed);
    }

    private ScepResult<EnrollOutcome> DecodeEnrollResponse(byte[] responseBytes, IScepKey recipientKey, string trans_id, TimeSpan elapsed) {
        PkiMessage decoded;
        string decode_error;
        ScepClientResult mapped_status;
        X509Certificate2? cert;

        if (!PkiMessage.Decode(Crypto, responseBytes, recipientKey, CodecOptions.LenientParsing, out decoded, out decode_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.CryptoError, decode_error);
        }

        foreach (ConformanceNote note in decoded.ConformanceNotes) {
            Emit(TraceLevel.Opinion, "Enroll", $"conformance: [{note.Severity}] {note.What} ({note.Where}) {note.RfcReference}");
        }

        switch (decoded.PkiStatus) {
            case PkiStatus.Success:
                mapped_status = ScepClientResult.Ok;
                break;
            case PkiStatus.Pending:
                mapped_status = ScepClientResult.Pending;
                break;
            default:
                mapped_status = ScepClientResult.ServerFailure;
                break;
        }

        cert = decoded.IssuedCerts.Count > 0 ? decoded.IssuedCerts[0] : null;

        EnrollOutcome outcome;
        outcome = new EnrollOutcome {
            Status = mapped_status,
            PkiStatus = decoded.PkiStatus,
            FailInfo = decoded.FailInfo,
            Certificate = cert,
            TransactionId = trans_id,
            Elapsed = elapsed,
        };

        if (mapped_status == ScepClientResult.Ok) {
            return ScepResult<EnrollOutcome>.Ok(outcome);
        }

        return ScepResult<EnrollOutcome>.Fail(mapped_status, $"PKI status: {decoded.PkiStatus}");
    }

    private void Emit(TraceLevel level, string phase, string message) {
        Trace?.Invoke(new ScepTraceEvent(level, phase, message));
    }
}
