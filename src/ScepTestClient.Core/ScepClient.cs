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
    private X509Certificate2? _ca_cert_cache;

    public IScepCrypto Crypto { get; }
    public ServerConfig Server { get; }
    public X509Certificate2? RenewalCertificate { get; private set; }
    public IScepKey? RenewalKey { get; private set; }
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

    public static ScepClientResult Create(X509Certificate2 existing_cert, IScepKey matching_key, ServerConfig server, IScepCrypto crypto, HttpMessageHandler? handler, out ScepClient client, out string error) {
        ScepClientResult result;

        result = Create(server, crypto, handler, out client, out error);
        if (result != ScepClientResult.Ok) {
            return result;
        }

        if (existing_cert is null || matching_key is null) {
            error = "existing certificate and matching key are required";
            return ScepClientResult.InvalidArgument;
        }

        client.RenewalCertificate = existing_cert;
        client.RenewalKey = matching_key;
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

        return SendPkiOperationSync(pki_message, request.Key);
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

        return await SendPkiOperationAsync(pki_message, request.Key).ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // SubmitPkiOperation (deliberate-fault path for the test/compliance engine)
    // -------------------------------------------------------------------------

    public ScepResult<EnrollOutcome> SubmitPkiOperation(PkiMessage message, IScepKey subject_key, FaultDirectives? faults = null) =>
        SendPkiOperationSync(message, subject_key, faults);

    public Task<ScepResult<EnrollOutcome>> SubmitPkiOperationAsync(PkiMessage message, IScepKey subject_key, FaultDirectives? faults = null) =>
        SendPkiOperationAsync(message, subject_key, faults);

    // -------------------------------------------------------------------------
    // Renew
    // -------------------------------------------------------------------------

    public ScepResult<EnrollOutcome> Renew(RenewRequest request) {
        PkiMessage pki_message;
        IScepKey subject_key;
        string build_error;

        Emit(TraceLevel.Info, "Renew", $"renewing '{request.Subject}' via {request.Variant}");
        if (!BuildRenewMessage(request, out pki_message, out subject_key, out build_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, build_error);
        }
        return SendPkiOperationSync(pki_message, subject_key);
    }

    public async Task<ScepResult<EnrollOutcome>> RenewAsync(RenewRequest request) {
        PkiMessage pki_message;
        IScepKey subject_key;
        string build_error;

        Emit(TraceLevel.Info, "Renew", $"renewing '{request.Subject}' via {request.Variant}");
        if (!BuildRenewMessage(request, out pki_message, out subject_key, out build_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, build_error);
        }
        return await SendPkiOperationAsync(pki_message, subject_key).ConfigureAwait(false);
    }

    private bool BuildRenewMessage(RenewRequest request, out PkiMessage pki_message, out IScepKey subject_key, out string error) {
        ScepRequestBuilder builder;
        bool reenroll;

        pki_message = null!;
        subject_key = null!;
        error = string.Empty;

        if (request.CaCertificate is null) {
            error = "RenewRequest.CaCertificate must be set";
            return false;
        }

        reenroll = request.Variant == RenewalVariant.ReenrollSameSubject;

        builder = ScepRequestBuilder.For(Crypto)
            .CaCertificate(request.CaCertificate)
            .MessageType(reenroll || request.Variant == RenewalVariant.RenewalShapedPkcsReq ? MessageType.PkcsReq : MessageType.RenewalReq)
            .Subject(request.Subject)
            .Digest(request.DigestOid)
            .Cipher(request.ContentEncryptionOid);

        foreach (string dns in request.DnsNames) { builder.SanDns(dns); }
        foreach (string upn in request.Upns) { builder.Upn(upn); }
        foreach (string eku in request.Ekus) { builder.Eku(eku); }
        if (request.Sid is not null) { builder.Sid(request.Sid); }
        if (request.ChallengePassword is not null) { builder.Challenge(request.ChallengePassword); }

        // Variant 4 (SameKey) reuses the existing key for the inner CSR; the rest generate a fresh one.
        if (request.Variant == RenewalVariant.SameKey) {
            builder.SubjectKey(request.ExistingKey);
        } else {
            builder.KeySpec(request.KeySpecText);
        }

        // The naive re-enroll signs with a self-signed cert over a new key; all other variants
        // sign with the existing cert + key.
        if (!reenroll) {
            builder.SignerCertificate(request.ExistingCertificate).SignerKey(request.ExistingKey);
        }

        return builder.Build(out pki_message, out subject_key, out error);
    }

    // -------------------------------------------------------------------------
    // RenewCertificate (high-level lifecycle with lineage)
    // -------------------------------------------------------------------------

    public async Task<ScepResult<EnrollOutcome>> RenewCertificateAsync(string cert_id, Storage.CertStore store, Storage.UseRecordLog log) {
        X509Certificate2 existing_cert;
        IScepKey existing_key;
        Storage.CertStore.CertRecord record;
        string load_error;
        X509Certificate2 ca_cert;
        string ca_error;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;
        EnrollOutcome outcome;

        if (!store.Load(Server.Id, cert_id, Crypto, out existing_cert, out existing_key, out record, out load_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.NotFound, load_error);
        }

        if (!ResolveCaCert(out ca_cert, out ca_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, ca_error);
        }

        request = new RenewRequest {
            Subject = record.Subject,
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = RenewalVariant.Proper,
            CaCertificate = ca_cert,
        };

        result = await RenewAsync(request).ConfigureAwait(false);
        if (!result.IsOk) {
            return result;
        }

        outcome = result.Value;
        if (outcome.Certificate is not null && outcome.SubjectKey is not null) {
            store.Save(Server.Id, outcome.Certificate, outcome.SubjectKey, Crypto,
                challenge_password: null, renewed_from: cert_id, transaction_id: outcome.TransactionId);
        }
        log.Append(Server.Id, outcome);
        return result;
    }

    public ScepResult<EnrollOutcome> RenewCertificate(string cert_id, Storage.CertStore store, Storage.UseRecordLog log) {
        X509Certificate2 existing_cert;
        IScepKey existing_key;
        Storage.CertStore.CertRecord record;
        string load_error;
        X509Certificate2 ca_cert;
        string ca_error;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;
        EnrollOutcome outcome;

        if (!store.Load(Server.Id, cert_id, Crypto, out existing_cert, out existing_key, out record, out load_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.NotFound, load_error);
        }

        if (!ResolveCaCert(out ca_cert, out ca_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, ca_error);
        }

        request = new RenewRequest {
            Subject = record.Subject,
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = RenewalVariant.Proper,
            CaCertificate = ca_cert,
        };

        result = Renew(request);
        if (!result.IsOk) {
            return result;
        }

        outcome = result.Value;
        if (outcome.Certificate is not null && outcome.SubjectKey is not null) {
            store.Save(Server.Id, outcome.Certificate, outcome.SubjectKey, Crypto,
                challenge_password: null, renewed_from: cert_id, transaction_id: outcome.TransactionId);
        }
        log.Append(Server.Id, outcome);
        return result;
    }

    // -------------------------------------------------------------------------
    // GetCert / GetCrl
    // -------------------------------------------------------------------------

    public ScepResult<X509Certificate2> GetCert(string issuer_dn, string serial_hex) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCert, issuer_dn, serial_hex, out message, out signer_key, out error)) {
            return ScepResult<X509Certificate2>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCert(SendDecodedSync(message));
    }

    public async Task<ScepResult<X509Certificate2>> GetCertAsync(string issuer_dn, string serial_hex) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCert, issuer_dn, serial_hex, out message, out signer_key, out error)) {
            return ScepResult<X509Certificate2>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCert(await SendDecodedAsync(message).ConfigureAwait(false));
    }

    public ScepResult<byte[]> GetCrl(string issuer_dn, string serial_hex) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCrl, issuer_dn, serial_hex, out message, out signer_key, out error)) {
            return ScepResult<byte[]>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCrl(SendDecodedSync(message));
    }

    public async Task<ScepResult<byte[]>> GetCrlAsync(string issuer_dn, string serial_hex) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCrl, issuer_dn, serial_hex, out message, out signer_key, out error)) {
            return ScepResult<byte[]>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCrl(await SendDecodedAsync(message).ConfigureAwait(false));
    }

    private bool BuildIssuerSerialMessage(MessageType type, string issuer_dn, string serial_hex, out PkiMessage message, out IScepKey signer_key, out string error) {
        X509Certificate2 ca_cert;

        message = null!;
        signer_key = null!;

        if (!ResolveCaCert(out ca_cert, out error)) {
            return false;
        }

        return ScepRequestBuilder.For(Crypto)
            .CaCertificate(ca_cert)
            .MessageType(type)
            .KeySpec("rsa:2048")
            .IssuerAndSerial(issuer_dn, serial_hex)
            .Build(out message, out signer_key, out error);
    }

    // -------------------------------------------------------------------------
    // Poll (CertPoll / 20)
    // -------------------------------------------------------------------------

    public ScepResult<EnrollOutcome> Poll(string issuer_dn, string subject_dn, string transaction_id) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildPollMessage(issuer_dn, subject_dn, transaction_id, out message, out signer_key, out error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return SendPkiOperationSync(message, signer_key);
    }

    public async Task<ScepResult<EnrollOutcome>> PollAsync(string issuer_dn, string subject_dn, string transaction_id) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildPollMessage(issuer_dn, subject_dn, transaction_id, out message, out signer_key, out error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return await SendPkiOperationAsync(message, signer_key).ConfigureAwait(false);
    }

    private bool BuildPollMessage(string issuer_dn, string subject_dn, string transaction_id, out PkiMessage message, out IScepKey signer_key, out string error) {
        X509Certificate2 ca_cert;

        message = null!;
        signer_key = null!;

        if (!ResolveCaCert(out ca_cert, out error)) {
            return false;
        }

        if (!ScepRequestBuilder.For(Crypto)
                .CaCertificate(ca_cert)
                .MessageType(MessageType.CertPoll)
                .KeySpec("rsa:2048")
                .IssuerAndSubject(issuer_dn, subject_dn)
                .Build(out message, out signer_key, out error)) {
            return false;
        }

        message.TransactionId = transaction_id;
        return true;
    }

    // Sends a built message and returns the FULLY DECODED PkiMessage (cert + CRL list), not just an outcome.
    private ScepResult<PkiMessage> SendDecodedSync(PkiMessage message) {
        byte[] der;
        string encode_error;
        ScepResult<byte[]> raw;
        PkiMessage decoded;
        string decode_error;

        if (!message.Encode(Crypto, out der, out encode_error)) {
            return ScepResult<PkiMessage>.Fail(ScepClientResult.CryptoError, encode_error);
        }
        raw = Server.PreferPost ? _transport.Post("PKIOperation", der) : _transport.Get("PKIOperation", Convert.ToBase64String(der));
        if (!raw.IsOk) {
            return ScepResult<PkiMessage>.Fail(raw.Status, raw.Error);
        }
        if (!PkiMessage.Decode(Crypto, raw.Value, message.SignerKey!, CodecOptions.LenientParsing, out decoded, out decode_error)) {
            return ScepResult<PkiMessage>.Fail(ScepClientResult.CryptoError, decode_error);
        }
        return ScepResult<PkiMessage>.Ok(decoded);
    }

    private async Task<ScepResult<PkiMessage>> SendDecodedAsync(PkiMessage message) {
        byte[] der;
        string encode_error;
        ScepResult<byte[]> raw;
        PkiMessage decoded;
        string decode_error;

        if (!message.Encode(Crypto, out der, out encode_error)) {
            return ScepResult<PkiMessage>.Fail(ScepClientResult.CryptoError, encode_error);
        }
        raw = Server.PreferPost
            ? await _transport.PostAsync("PKIOperation", der).ConfigureAwait(false)
            : await _transport.GetAsync("PKIOperation", Convert.ToBase64String(der)).ConfigureAwait(false);
        if (!raw.IsOk) {
            return ScepResult<PkiMessage>.Fail(raw.Status, raw.Error);
        }
        if (!PkiMessage.Decode(Crypto, raw.Value, message.SignerKey!, CodecOptions.LenientParsing, out decoded, out decode_error)) {
            return ScepResult<PkiMessage>.Fail(ScepClientResult.CryptoError, decode_error);
        }
        return ScepResult<PkiMessage>.Ok(decoded);
    }

    private static ScepResult<X509Certificate2> ProjectCert(ScepResult<PkiMessage> sent) {
        if (!sent.IsOk) {
            return ScepResult<X509Certificate2>.Fail(sent.Status, sent.Error);
        }
        if (sent.Value.PkiStatus != PkiStatus.Success || sent.Value.IssuedCerts.Count == 0) {
            return ScepResult<X509Certificate2>.Fail(ScepClientResult.ServerFailure, $"no certificate (pkiStatus {sent.Value.PkiStatus}, failInfo {sent.Value.FailInfo})");
        }
        return ScepResult<X509Certificate2>.Ok(sent.Value.IssuedCerts[0]);
    }

    private static ScepResult<byte[]> ProjectCrl(ScepResult<PkiMessage> sent) {
        if (!sent.IsOk) {
            return ScepResult<byte[]>.Fail(sent.Status, sent.Error);
        }
        if (sent.Value.IssuedCrls.Count == 0) {
            return ScepResult<byte[]>.Fail(ScepClientResult.ServerFailure, $"no CRL (pkiStatus {sent.Value.PkiStatus}, failInfo {sent.Value.FailInfo})");
        }
        return ScepResult<byte[]>.Ok(sent.Value.IssuedCrls[0]);
    }

    private bool ResolveCaCert(out X509Certificate2 ca_cert, out string error) {
        ScepResult<IReadOnlyList<X509Certificate2>> ca_result;

        ca_cert = null!;
        error = string.Empty;

        if (_ca_cert_cache is not null) {
            ca_cert = _ca_cert_cache;
            return true;
        }

        ca_result = GetCaCert();
        if (!ca_result.IsOk || ca_result.Value.Count == 0) {
            error = ca_result.IsOk ? "server returned no CA certificate" : ca_result.Error;
            return false;
        }
        _ca_cert_cache = ca_result.Value[0];
        ca_cert = _ca_cert_cache;
        return true;
    }

    // -------------------------------------------------------------------------
    // GetNewCertificate
    // -------------------------------------------------------------------------

    public async Task<ScepResult<EnrollOutcome>> GetNewCertificateAsync(EnrollRequest request, Storage.CertStore store, Storage.UseRecordLog log, string? key_passphrase = null) {
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
                    if (string.IsNullOrEmpty(key_passphrase)) {
                        store.Save(Server.Id, outcome.Certificate, request, Crypto);
                    } else {
                        store.Save(Server.Id, outcome.Certificate, request.Key, Crypto,
                            challenge_password: request.ChallengePassword, renewed_from: null, transaction_id: outcome.TransactionId, passphrase: key_passphrase);
                    }
                }
                log.Append(Server.Id, outcome);
            }

            return enroll_result;
        } catch (Exception ex) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, ex.Message);
        }
    }

    public ScepResult<EnrollOutcome> GetNewCertificate(EnrollRequest request, Storage.CertStore store, Storage.UseRecordLog log, string? key_passphrase = null) {
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
                    if (string.IsNullOrEmpty(key_passphrase)) {
                        store.Save(Server.Id, outcome.Certificate, request, Crypto);
                    } else {
                        store.Save(Server.Id, outcome.Certificate, request.Key, Crypto,
                            challenge_password: request.ChallengePassword, renewed_from: null, transaction_id: outcome.TransactionId, passphrase: key_passphrase);
                    }
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
        csr.AltKey = request.AltKey;
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

    private ScepResult<EnrollOutcome> SendPkiOperationSync(PkiMessage pki_message, IScepKey subject_key, FaultDirectives? faults = null) {
        byte[] der;
        string encode_error;
        ScepResult<byte[]> raw;
        Stopwatch sw;
        string trans_id;

        trans_id = pki_message.TransactionId!;

        if (!pki_message.Encode(Crypto, faults, out der, out encode_error)) {
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

        return DecodeResponse(raw.Value, pki_message.SignerKey!, subject_key, trans_id, sw.Elapsed);
    }

    private async Task<ScepResult<EnrollOutcome>> SendPkiOperationAsync(PkiMessage pki_message, IScepKey subject_key, FaultDirectives? faults = null) {
        byte[] der;
        string encode_error;
        ScepResult<byte[]> raw;
        Stopwatch sw;
        string trans_id;

        trans_id = pki_message.TransactionId!;

        if (!pki_message.Encode(Crypto, faults, out der, out encode_error)) {
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

        return DecodeResponse(raw.Value, pki_message.SignerKey!, subject_key, trans_id, sw.Elapsed);
    }

    private ScepResult<EnrollOutcome> DecodeResponse(byte[] response_bytes, IScepKey recipient_key, IScepKey subject_key, string trans_id, TimeSpan elapsed) {
        PkiMessage decoded;
        string decode_error;
        ScepClientResult mapped_status;
        X509Certificate2? cert;
        EnrollOutcome outcome;

        if (!PkiMessage.Decode(Crypto, response_bytes, recipient_key, CodecOptions.LenientParsing, out decoded, out decode_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.CryptoError, decode_error);
        }

        foreach (ConformanceNote note in decoded.ConformanceNotes) {
            Emit(TraceLevel.Opinion, "PkiOperation", $"conformance: [{note.Severity}] {note.What} ({note.Where}) {note.RfcReference}");
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

        outcome = new EnrollOutcome {
            Status = mapped_status,
            PkiStatus = decoded.PkiStatus,
            FailInfo = decoded.FailInfo,
            Certificate = cert,
            SubjectKey = subject_key,
            TransactionId = trans_id,
            Elapsed = elapsed,
        };

        if (mapped_status == ScepClientResult.Ok) {
            return ScepResult<EnrollOutcome>.Ok(outcome);
        }

        return ScepResult<EnrollOutcome>.Fail(mapped_status, outcome, $"PKI status: {decoded.PkiStatus}");
    }

    private void Emit(TraceLevel level, string phase, string message) {
        Trace?.Invoke(new ScepTraceEvent(level, phase, message));
    }
}
