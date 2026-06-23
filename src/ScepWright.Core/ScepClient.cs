using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using ScepWright.Core.Protocol;
using ScepWright.Core.Recipients;
using ScepWright.Core.Transport;
using ScepWright.Crypto;

namespace ScepWright.Core;

/// <summary>
/// A SCEP protocol client: performs GetCACaps/GetCACert(/Next), enrollment, renewal, polling, and
/// GetCert/GetCrl against a single configured server, driving all cryptography through an
/// <see cref="IScepCrypto"/> provider.
/// </summary>
public sealed class ScepClient {
    private readonly ScepHttpTransport _transport;
    private X509Certificate2? _recipient_cert_cache;

    /// <summary>Gets the crypto provider backing this client.</summary>
    public IScepCrypto Crypto { get; }
    /// <summary>Gets the configured server endpoint.</summary>
    public ServerConfig Server { get; }
    /// <summary>Raised for each diagnostic trace event during an operation.</summary>
    public event Action<ScepTraceEvent>? Trace;
    /// <summary>
    /// Raised for every certificate the server actually issues, carrying the issued leaf, so a test
    /// suite can record the real-world footprint it left behind.
    /// </summary>
    public event Action<X509Certificate2>? CertificateIssued;

    private ScepClient(ServerConfig server, IScepCrypto crypto, ScepHttpTransport transport) {
        Server = server;
        Crypto = crypto;
        _transport = transport;
    }

    /// <summary>
    /// Creates a client for the given server and crypto provider. Pass a custom
    /// <paramref name="handler"/> to inject transport (e.g. for tests); null uses a default HttpClient.
    /// Returns <see cref="ScepClientResult.Ok"/> on success.
    /// </summary>
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

    /// <summary>Fetches and parses the server's GetCACaps response.</summary>
    public ScepResult<ScepCapabilities> GetCaCaps() {
        ScepResult<byte[]> raw;
        string text;

        Emit(TraceLevel.Info, "GetCaCaps", "sending GetCACaps request");
        Emit(TraceLevel.Debug, "GetCaCaps", $"GET {_transport.DescribeGet("GetCACaps", Server.CaIdentifier ?? string.Empty)}");
        raw = _transport.Get("GetCACaps", Server.CaIdentifier ?? string.Empty);
        if (!raw.IsOk) {
            return ScepResult<ScepCapabilities>.Fail(raw.Status, raw.Error);
        }

        text = Encoding.ASCII.GetString(raw.Value);
        return ScepResult<ScepCapabilities>.Ok(ScepCapabilities.Parse(text));
    }

    /// <summary>Fetches and parses the server's GetCACaps response.</summary>
    public async Task<ScepResult<ScepCapabilities>> GetCaCapsAsync() {
        ScepResult<byte[]> raw;
        string text;

        Emit(TraceLevel.Info, "GetCaCaps", "sending GetCACaps request");
        Emit(TraceLevel.Debug, "GetCaCaps", $"GET {_transport.DescribeGet("GetCACaps", Server.CaIdentifier ?? string.Empty)}");
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

    /// <summary>Fetches and parses the CA/RA certificate bundle (GetCACert).</summary>
    public ScepResult<IReadOnlyList<X509Certificate2>> GetCaCert() {
        ScepResult<byte[]> raw;
        IReadOnlyList<X509Certificate2> certs;
        string error;

        Emit(TraceLevel.Info, "GetCaCert", "sending GetCACert request");
        Emit(TraceLevel.Debug, "GetCaCert", $"GET {_transport.DescribeGet("GetCACert", Server.CaIdentifier ?? string.Empty)}");
        raw = _transport.Get("GetCACert", Server.CaIdentifier ?? string.Empty);
        if (!raw.IsOk) {
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(raw.Status, raw.Error);
        }

        if (!Crypto.ParseCaCertificates(raw.Value, out certs, out error)) {
            return ScepResult<IReadOnlyList<X509Certificate2>>.Fail(ScepClientResult.CryptoError, error);
        }

        return ScepResult<IReadOnlyList<X509Certificate2>>.Ok(certs);
    }

    /// <summary>Fetches and parses the CA/RA certificate bundle (GetCACert).</summary>
    public async Task<ScepResult<IReadOnlyList<X509Certificate2>>> GetCaCertAsync() {
        ScepResult<byte[]> raw;
        IReadOnlyList<X509Certificate2> certs;
        string error;

        Emit(TraceLevel.Info, "GetCaCert", "sending GetCACert request");
        Emit(TraceLevel.Debug, "GetCaCert", $"GET {_transport.DescribeGet("GetCACert", Server.CaIdentifier ?? string.Empty)}");
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

    /// <summary>Fetches and parses the CA's next (rollover) certificate bundle (GetNextCACert).</summary>
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

    /// <summary>Fetches and parses the CA's next (rollover) certificate bundle (GetNextCACert).</summary>
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

    /// <summary>Builds and sends an initial enrollment (PKCSReq) and returns the outcome.</summary>
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

    /// <summary>Builds and sends an initial enrollment (PKCSReq) and returns the outcome.</summary>
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

    /// <summary>Sends a caller-built PKIOperation, optionally with injected faults (test/compliance path).</summary>
    public ScepResult<EnrollOutcome> SubmitPkiOperation(PkiMessage message, IScepKey subject_key, FaultDirectives? faults = null) =>
        SendPkiOperationSync(message, subject_key, faults);

    /// <summary>Sends a caller-built PKIOperation, optionally with injected faults (test/compliance path).</summary>
    public Task<ScepResult<EnrollOutcome>> SubmitPkiOperationAsync(PkiMessage message, IScepKey subject_key, FaultDirectives? faults = null) =>
        SendPkiOperationAsync(message, subject_key, faults);

    /// <summary>
    /// Anti-replay probe: encodes the message once and POSTs the byte-identical request twice. The
    /// senderNonce and transactionID are reused exactly, so a server honoring RFC 8894's nonce
    /// mechanism should reject the second send; one that re-issues is more lenient than intended.
    /// </summary>
    public ReplayProbe ProbeReplay(PkiMessage message, IScepKey subject_key) {
        byte[] der;
        string encode_error;
        ScepResult<EnrollOutcome> first;
        ScepResult<EnrollOutcome> second;

        if (!message.Encode(Crypto, out der, out encode_error)) {
            return new ReplayProbe(false, encode_error, PkiStatus.Failure, FailInfo.None, PkiStatus.Failure, FailInfo.None);
        }

        first = PostRawPkiOperation(der, message.SignerKey!, subject_key);
        if (first.Value is null) {
            return new ReplayProbe(false, first.Error, PkiStatus.Failure, FailInfo.None, PkiStatus.Failure, FailInfo.None);
        }

        second = PostRawPkiOperation(der, message.SignerKey!, subject_key);
        if (second.Value is null) {
            return new ReplayProbe(false, second.Error, first.Value.PkiStatus, first.Value.FailInfo, PkiStatus.Failure, FailInfo.None);
        }

        return new ReplayProbe(true, string.Empty, first.Value.PkiStatus, first.Value.FailInfo, second.Value.PkiStatus, second.Value.FailInfo);
    }

    // -------------------------------------------------------------------------
    // Renew
    // -------------------------------------------------------------------------

    /// <summary>Builds and sends a renewal request per <see cref="RenewRequest.Variant"/>.</summary>
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

    /// <summary>Builds and sends a renewal request per <see cref="RenewRequest.Variant"/>.</summary>
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
        X509Certificate2 recipient;
        string recipient_error;

        pki_message = null!;
        subject_key = null!;
        error = string.Empty;

        // Resolve the EnvelopedData recipient the same way enroll does: the RA encryption cert, NOT the
        // CA signing cert. For a split-RA / PQ CA those differ, and enveloping to the signing cert (e.g.
        // ML-DSA) fails. Honor an explicit CaCertificate if a caller set one; otherwise select it.
        if (request.CaCertificate is null) {
            if (!ResolveRecipientCert(out recipient, out recipient_error)) {
                error = recipient_error;
                return false;
            }
            request.CaCertificate = recipient;
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
            string resolved_spec;

            // Sole resolution point: an unset spec falls back to the rsa:2048 baseline.
            resolved_spec = string.IsNullOrEmpty(request.KeySpecText) ? "rsa:2048" : request.KeySpecText;
            builder.KeySpec(resolved_spec);
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

    /// <summary>
    /// High-level renewal lifecycle: loads the existing cert+key from the store, renews it, persists
    /// the new cert with lineage (renewed-from), and appends a use record.
    /// </summary>
    public async Task<ScepResult<EnrollOutcome>> RenewCertificateAsync(string cert_id, Storage.CertStore store, Storage.UseRecordLog log, string? key_spec_override = null, string? passphrase = null) {
        X509Certificate2 existing_cert;
        IScepKey existing_key;
        Storage.CertStore.CertRecord record;
        string load_error;
        X509Certificate2 ca_cert;
        string ca_error;
        string resolved_spec;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;
        EnrollOutcome outcome;

        if (!store.Load(Server.Id, cert_id, Crypto, out existing_cert, out existing_key, out record, out load_error, passphrase)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.NotFound, load_error);
        }

        if (!ResolveRecipientCert(out ca_cert, out ca_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, ca_error);
        }

        // Preserve the renewed certificate's algorithm: an explicit override wins, otherwise reuse
        // the key-spec recorded at enrollment. An empty result defers to the BuildRenewMessage baseline.
        resolved_spec = key_spec_override ?? record.KeySpec ?? string.Empty;

        request = new RenewRequest {
            Subject = record.Subject,
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = RenewalVariant.Proper,
            KeySpecText = resolved_spec,
            CaCertificate = ca_cert,
        };

        result = await RenewAsync(request).ConfigureAwait(false);
        if (!result.IsOk) {
            return result;
        }

        outcome = result.Value;
        if (outcome.Certificate is not null && outcome.SubjectKey is not null) {
            // Carry the at-rest passphrase forward so the renewed key keeps the same protection.
            store.Save(Server.Id, outcome.Certificate, outcome.SubjectKey, Crypto,
                challenge_password: null, renewed_from: cert_id, transaction_id: outcome.TransactionId, passphrase: passphrase,
                key_spec_text: string.IsNullOrEmpty(resolved_spec) ? null : resolved_spec);
        }
        log.Append(Server.Id, outcome);
        return result;
    }

    /// <summary>
    /// High-level renewal lifecycle: loads the existing cert+key from the store, renews it, persists
    /// the new cert with lineage (renewed-from), and appends a use record.
    /// </summary>
    public ScepResult<EnrollOutcome> RenewCertificate(string cert_id, Storage.CertStore store, Storage.UseRecordLog log, string? key_spec_override = null, string? passphrase = null, string? challenge = null) {
        X509Certificate2 existing_cert;
        IScepKey existing_key;
        Storage.CertStore.CertRecord record;
        string load_error;
        X509Certificate2 ca_cert;
        string ca_error;
        string resolved_spec;
        RenewRequest request;
        ScepResult<EnrollOutcome> result;
        EnrollOutcome outcome;

        if (!store.Load(Server.Id, cert_id, Crypto, out existing_cert, out existing_key, out record, out load_error, passphrase)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.NotFound, load_error);
        }

        if (!ResolveRecipientCert(out ca_cert, out ca_error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, ca_error);
        }

        // Preserve the renewed certificate's algorithm: an explicit override wins, otherwise reuse
        // the key-spec recorded at enrollment. An empty result defers to the BuildRenewMessage baseline.
        resolved_spec = key_spec_override ?? record.KeySpec ?? string.Empty;

        request = new RenewRequest {
            Subject = record.Subject,
            ExistingCertificate = existing_cert,
            ExistingKey = existing_key,
            Variant = RenewalVariant.Proper,
            KeySpecText = resolved_spec,
            CaCertificate = ca_cert,
            ChallengePassword = challenge,
        };

        result = Renew(request);
        if (!result.IsOk) {
            return result;
        }

        outcome = result.Value;
        if (outcome.Certificate is not null && outcome.SubjectKey is not null) {
            // Carry the at-rest passphrase forward so the renewed key keeps the same protection.
            store.Save(Server.Id, outcome.Certificate, outcome.SubjectKey, Crypto,
                challenge_password: null, renewed_from: cert_id, transaction_id: outcome.TransactionId, passphrase: passphrase,
                key_spec_text: string.IsNullOrEmpty(resolved_spec) ? null : resolved_spec);
        }
        log.Append(Server.Id, outcome);
        return result;
    }

    // -------------------------------------------------------------------------
    // GetCert / GetCrl
    // -------------------------------------------------------------------------

    /// <summary>Retrieves an already-issued certificate by issuer DN and serial (GetCert).</summary>
    public ScepResult<X509Certificate2> GetCert(string issuer_dn, string serial_hex) {
        PkiMessage message;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCert, issuer_dn, serial_hex, out message, out _, out error)) {
            return ScepResult<X509Certificate2>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCert(SendDecodedSync(message));
    }

    /// <summary>Retrieves an already-issued certificate by issuer DN and serial (GetCert).</summary>
    public async Task<ScepResult<X509Certificate2>> GetCertAsync(string issuer_dn, string serial_hex) {
        PkiMessage message;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCert, issuer_dn, serial_hex, out message, out _, out error)) {
            return ScepResult<X509Certificate2>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCert(await SendDecodedAsync(message).ConfigureAwait(false));
    }

    /// <summary>Retrieves the CRL covering the cert identified by issuer DN and serial (GetCRL).</summary>
    public ScepResult<byte[]> GetCrl(string issuer_dn, string serial_hex) {
        PkiMessage message;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCrl, issuer_dn, serial_hex, out message, out _, out error)) {
            return ScepResult<byte[]>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCrl(SendDecodedSync(message));
    }

    /// <summary>Retrieves the CRL covering the cert identified by issuer DN and serial (GetCRL).</summary>
    public async Task<ScepResult<byte[]>> GetCrlAsync(string issuer_dn, string serial_hex) {
        PkiMessage message;
        string error;

        if (!BuildIssuerSerialMessage(MessageType.GetCrl, issuer_dn, serial_hex, out message, out _, out error)) {
            return ScepResult<byte[]>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return ProjectCrl(await SendDecodedAsync(message).ConfigureAwait(false));
    }

    private bool BuildIssuerSerialMessage(MessageType type, string issuer_dn, string serial_hex, out PkiMessage message, out IScepKey signer_key, out string error) {
        X509Certificate2 ca_cert;

        message = null!;
        signer_key = null!;

        if (!ResolveRecipientCert(out ca_cert, out error)) {
            return false;
        }

        return ScepRequestBuilder.For(Crypto)
            .CaCertificate(ca_cert)
            .MessageType(type)
            // Deliberate fixed transport key: GetCert/GetCrl carry no subject key, so this is only the
            // transient signer that decrypts the CMS response; rsa:2048 is the safe baseline.
            .KeySpec("rsa:2048")
            .IssuerAndSerial(issuer_dn, serial_hex)
            .Build(out message, out signer_key, out error);
    }

    // -------------------------------------------------------------------------
    // Poll (CertPoll / 20)
    // -------------------------------------------------------------------------

    /// <summary>Polls for a pending request (CertPoll / GetCertInitial) by issuer, subject, and transaction id.</summary>
    /// <summary>
    /// Polls for a pending request (CertPoll / GetCertInitial) by issuer, subject, and transaction id.
    /// When <paramref name="original_key"/> is supplied (the key from the PENDING enrollment), the poll is
    /// signed with it per RFC 8894 §3.3.2 so the CA returns the cert bound to that key; otherwise a
    /// transient transport key is used (standalone manual poll, response decrypt only).
    /// </summary>
    public ScepResult<EnrollOutcome> Poll(string issuer_dn, string subject_dn, string transaction_id, IScepKey? original_key = null) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildPollMessage(issuer_dn, subject_dn, transaction_id, original_key, out message, out signer_key, out error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return SendPkiOperationSync(message, signer_key);
    }

    /// <summary>Polls for a pending request (CertPoll / GetCertInitial) by issuer, subject, and transaction id.</summary>
    public async Task<ScepResult<EnrollOutcome>> PollAsync(string issuer_dn, string subject_dn, string transaction_id, IScepKey? original_key = null) {
        PkiMessage message;
        IScepKey signer_key;
        string error;

        if (!BuildPollMessage(issuer_dn, subject_dn, transaction_id, original_key, out message, out signer_key, out error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return await SendPkiOperationAsync(message, signer_key).ConfigureAwait(false);
    }

    private bool BuildPollMessage(string issuer_dn, string subject_dn, string transaction_id, IScepKey? original_key, out PkiMessage message, out IScepKey signer_key, out string error) {
        X509Certificate2 ca_cert;
        ScepRequestBuilder builder;

        message = null!;
        signer_key = null!;

        if (!ResolveRecipientCert(out ca_cert, out error)) {
            return false;
        }

        builder = ScepRequestBuilder.For(Crypto)
            .CaCertificate(ca_cert)
            .MessageType(MessageType.CertPoll)
            .IssuerAndSubject(issuer_dn, subject_dn);
        if (original_key is not null) {
            // RFC 8894 §3.3.2: sign GetCertInitial with the original enrollment key so the CA returns
            // the certificate bound to it (and the response enveloped back is decryptable by it).
            builder.SubjectKey(original_key);
        } else {
            // Standalone manual poll: CertPoll carries no subject key, so this is only the transient
            // signer that decrypts the CMS response; rsa:2048 is the safe baseline.
            builder.KeySpec("rsa:2048");
        }

        if (!builder.Build(out message, out signer_key, out error)) {
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

    // Resolves the EnvelopedData *recipient* (the encryption-capable cert), not the signing cert —
    // for split-RA and PQ CAs these differ, and enveloping to the signing cert fails (e.g. an ML-DSA
    // signing key is not a valid encryption recipient). Renew/GetCert/GetCrl/Poll must use this, the
    // same selection enroll uses, so the whole lifecycle works against the same CA enroll does.
    private bool ResolveRecipientCert(out X509Certificate2 recipient, out string error) {
        ScepResult<IReadOnlyList<X509Certificate2>> ca_result;

        recipient = null!;
        error = string.Empty;

        if (_recipient_cert_cache is not null) {
            recipient = _recipient_cert_cache;
            return true;
        }

        ca_result = GetCaCert();
        if (!ca_result.IsOk || ca_result.Value.Count == 0) {
            error = ca_result.IsOk ? "server returned no CA certificate" : ca_result.Error;
            return false;
        }
        if (!SelectRecipient(ca_result.Value, out recipient, out error)) {
            return false;
        }
        _recipient_cert_cache = recipient;
        return true;
    }

    // -------------------------------------------------------------------------
    // GetNewCertificate
    // -------------------------------------------------------------------------

    /// <summary>
    /// High-level enrollment lifecycle: resolves the recipient cert if needed, enrolls, persists the
    /// issued cert+key (optionally encrypted under <paramref name="key_passphrase"/>), and appends a use record.
    /// </summary>
    public async Task<ScepResult<EnrollOutcome>> GetNewCertificateAsync(EnrollRequest request, Storage.CertStore store, Storage.UseRecordLog log, string? key_passphrase = null) {
        ScepResult<IReadOnlyList<X509Certificate2>> ca_result;
        ScepResult<EnrollOutcome> enroll_result;
        EnrollOutcome outcome;
        X509Certificate2 recipient;
        string select_error;

        try {
            Emit(TraceLevel.Info, "GetNewCertificate", "starting enrollment lifecycle");

            if (request.CaCertificate is null) {
                ca_result = await GetCaCertAsync().ConfigureAwait(false);
                if (!ca_result.IsOk) {
                    return ScepResult<EnrollOutcome>.Fail(ca_result.Status, ca_result.Error);
                }
                if (!SelectRecipient(ca_result.Value, out recipient, out select_error)) {
                    return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, select_error);
                }
                request.CaCertificate = recipient;
            }

            enroll_result = await EnrollAsync(request).ConfigureAwait(false);

            if (enroll_result.IsOk) {
                outcome = enroll_result.Value;
                if (outcome.Certificate is not null) {
                    if (string.IsNullOrEmpty(key_passphrase)) {
                        store.Save(Server.Id, outcome.Certificate, request, Crypto);
                    } else {
                        store.Save(Server.Id, outcome.Certificate, request.Key, Crypto,
                            challenge_password: request.ChallengePassword, renewed_from: null, transaction_id: outcome.TransactionId, passphrase: key_passphrase,
                            key_spec_text: request.KeySpecText);
                    }
                }
                log.Append(Server.Id, outcome);
            }

            return enroll_result;
        } catch (Exception ex) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, ex.Message);
        }
    }

    /// <summary>
    /// High-level enrollment lifecycle: resolves the recipient cert if needed, enrolls, persists the
    /// issued cert+key (optionally encrypted under <paramref name="key_passphrase"/>), and appends a use record.
    /// </summary>
    public ScepResult<EnrollOutcome> GetNewCertificate(EnrollRequest request, Storage.CertStore store, Storage.UseRecordLog log, string? key_passphrase = null) {
        ScepResult<IReadOnlyList<X509Certificate2>> ca_result;
        ScepResult<EnrollOutcome> enroll_result;
        EnrollOutcome outcome;
        X509Certificate2 recipient;
        string select_error;

        try {
            Emit(TraceLevel.Info, "GetNewCertificate", "starting enrollment lifecycle");

            if (request.CaCertificate is null) {
                ca_result = GetCaCert();
                if (!ca_result.IsOk) {
                    return ScepResult<EnrollOutcome>.Fail(ca_result.Status, ca_result.Error);
                }
                if (!SelectRecipient(ca_result.Value, out recipient, out select_error)) {
                    return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProtocolError, select_error);
                }
                request.CaCertificate = recipient;
            }

            enroll_result = Enroll(request);

            if (enroll_result.IsOk) {
                outcome = enroll_result.Value;
                if (outcome.Certificate is not null) {
                    if (string.IsNullOrEmpty(key_passphrase)) {
                        store.Save(Server.Id, outcome.Certificate, request, Crypto);
                    } else {
                        store.Save(Server.Id, outcome.Certificate, request.Key, Crypto,
                            challenge_password: request.ChallengePassword, renewed_from: null, transaction_id: outcome.TransactionId, passphrase: key_passphrase,
                            key_spec_text: request.KeySpecText);
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

    // Choose the EnvelopedData recipient from the GetCACert bundle by KeyUsage (SCEP allows separate
    // signing and encryption certs). Emits conformance findings; fails (no send) when the server
    // offers no encryption-capable recipient.
    private bool SelectRecipient(IReadOnlyList<X509Certificate2> certs, out X509Certificate2 recipient, out string error) {
        RecipientSelection selection;

        recipient = null!;
        error = string.Empty;

        selection = RecipientSelector.Select(certs);
        foreach (RecipientFinding finding in selection.Findings) {
            Emit(TraceLevel.Opinion, "RecipientSelection", $"{finding.Code}: {finding.Message}");
        }

        if (!selection.CanEnvelope || selection.EncryptionCertificate is null) {
            error = selection.Findings.Count > 0
                ? selection.Findings[0].Message
                : "GetCACert returned no encryption-capable recipient certificate";
            return false;
        }

        recipient = selection.EncryptionCertificate;
        return true;
    }

    private ScepResult<EnrollOutcome> BuildPkiMessage(EnrollRequest request, out PkiMessage pki_message, out string error) {
        Pkcs10 csr;
        IScepKey signer_key;

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

        signer_key = request.Key;
        if (Algorithms.KindOf(request.Key.AlgorithmOid) == AlgorithmKind.Signature) {
            KeySpec rsa_spec;
            string spec_error;
            IScepKey transient_signer;
            string gen_error;

            // A PQ signature subject key cannot decrypt the SCEP response (RFC 8894 encrypts the
            // CertRep to the requester's signing key). Use a transient RSA transport key; the issued
            // certificate still carries the PQ subject key from the CSR.

            if (!KeySpec.Parse("rsa:2048", out rsa_spec, out spec_error)) {
                error = spec_error;
                return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
            }
            if (!Crypto.GenerateKey(rsa_spec, out transient_signer, out gen_error)) {
                error = gen_error;
                return ScepResult<EnrollOutcome>.Fail(ScepClientResult.ProviderError, gen_error);
            }
            signer_key = transient_signer;
            Emit(TraceLevel.Opinion, "Enroll", "subject key is PQ (signature-only); signing the SCEP exchange with a transient RSA transport key so the CA can envelope the CertRep back. Not a PQ downgrade: this key protects ONLY the response (your issued public certificate — no secret transits), and the certified key stays ML-DSA/SLH-DSA. The confidential request (CSR+challenge) is still enveloped to the CA's RA cert, which can be ML-KEM.");
        }

        pki_message = new PkiMessage {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = signer_key,
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

        return DecodeResponse(raw.Value, pki_message.SignerKey!, subject_key, trans_id, pki_message.SenderNonce, sw.Elapsed);
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

        return DecodeResponse(raw.Value, pki_message.SignerKey!, subject_key, trans_id, pki_message.SenderNonce, sw.Elapsed);
    }

    // Posts an already-encoded PKIOperation and decodes the response. Used by the replay probe to send
    // the same DER twice; trans_id/sender_nonce echo-tracking is irrelevant here, so they stay empty.
    private ScepResult<EnrollOutcome> PostRawPkiOperation(byte[] der, IScepKey recipient_key, IScepKey subject_key) {
        ScepResult<byte[]> raw;
        Stopwatch sw;

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
        return DecodeResponse(raw.Value, recipient_key, subject_key, string.Empty, null, sw.Elapsed);
    }

    private ScepResult<EnrollOutcome> DecodeResponse(byte[] response_bytes, IScepKey recipient_key, IScepKey subject_key, string trans_id, byte[]? sender_nonce, TimeSpan elapsed) {
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
        if (cert != null) {
            CertificateIssued?.Invoke(cert);
        }

        outcome = new EnrollOutcome {
            Status = mapped_status,
            PkiStatus = decoded.PkiStatus,
            FailInfo = decoded.FailInfo,
            Certificate = cert,
            SubjectKey = subject_key,
            TransactionId = trans_id,
            SenderNonce = sender_nonce,
            RecipientNonce = decoded.RecipientNonce,
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
