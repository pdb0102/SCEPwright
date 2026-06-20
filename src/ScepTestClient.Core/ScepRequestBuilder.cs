using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

/// <summary>
/// Fluent composer for a SCEP <see cref="PkiMessage"/>. Generates the subject/transient key from a
/// KeySpec (or accepts one via SubjectKey for same-key renewal); produces an always-valid message or
/// a clear error. See design spec §6.
/// </summary>
public sealed class ScepRequestBuilder {
    private readonly IScepCrypto _crypto;
    private readonly List<string> _dns_names;
    private readonly List<string> _upns;
    private readonly List<string> _ekus;
    private ScepTestClient.CryptoApi.MessageType _message_type;
    private X509Certificate2? _ca_cert;
    private X509Certificate2? _signer_cert;
    private IScepKey? _signer_key;
    private IScepKey? _subject_key;
    private IScepKey? _alt_key;
    private string? _key_spec_text;
    private string? _subject;
    private string? _sid;
    private string? _challenge;
    private string? _issuer_name;
    private string? _serial;
    private string? _poll_subject;
    private string _digest_oid;
    private string _cipher_oid;
    private FaultDirectives? _faults;

    private ScepRequestBuilder(IScepCrypto crypto) {
        _crypto = crypto;
        _dns_names = new List<string>();
        _upns = new List<string>();
        _ekus = new List<string>();
        _message_type = ScepTestClient.CryptoApi.MessageType.PkcsReq;
        _digest_oid = Algorithms.OidFor("SHA-256")!;
        _cipher_oid = Algorithms.OidFor("AES-128-CBC")!;
    }

    public static ScepRequestBuilder For(IScepCrypto crypto) => new ScepRequestBuilder(crypto);

    public ScepRequestBuilder CaCertificate(X509Certificate2 ca_cert) { _ca_cert = ca_cert; return this; }
    public ScepRequestBuilder MessageType(MessageType type) { _message_type = type; return this; }
    public ScepRequestBuilder Subject(string subject) { _subject = subject; return this; }
    public ScepRequestBuilder SanDns(string dns) { _dns_names.Add(dns); return this; }
    public ScepRequestBuilder Upn(string upn) { _upns.Add(upn); return this; }
    public ScepRequestBuilder Eku(string eku) { _ekus.Add(eku); return this; }
    public ScepRequestBuilder Sid(string sid) { _sid = sid; return this; }
    public ScepRequestBuilder Challenge(string challenge) { _challenge = challenge; return this; }
    public ScepRequestBuilder KeySpec(string key_spec_text) { _key_spec_text = key_spec_text; return this; }
    public ScepRequestBuilder SubjectKey(IScepKey key) { _subject_key = key; return this; }
    public ScepRequestBuilder AltKey(IScepKey key) { _alt_key = key; return this; }
    public ScepRequestBuilder SignerCertificate(X509Certificate2 cert) { _signer_cert = cert; return this; }
    public ScepRequestBuilder SignerKey(IScepKey key) { _signer_key = key; return this; }
    public ScepRequestBuilder IssuerAndSerial(string issuer_name, string serial_hex) { _issuer_name = issuer_name; _serial = serial_hex; return this; }
    public ScepRequestBuilder IssuerAndSubject(string issuer_name, string subject_name) { _issuer_name = issuer_name; _poll_subject = subject_name; return this; }
    public ScepRequestBuilder AllowFaults(FaultDirectives faults) { _faults = faults; return this; }

    public FaultDirectives? Faults => _faults;

    public ScepRequestBuilder Digest(string name_or_oid) {
        _digest_oid = Algorithms.OidFor(name_or_oid) ?? name_or_oid;
        return this;
    }

    public ScepRequestBuilder Cipher(string name_or_oid) {
        string? resolved;

        resolved = Algorithms.OidFor(name_or_oid) ?? Algorithms.OidFor(name_or_oid + "-CBC");
        _cipher_oid = resolved ?? name_or_oid;
        return this;
    }

    public bool Build(out PkiMessage message, out IScepKey subject_key, out string error) {
        message = null!;
        subject_key = null!;
        error = string.Empty;

        if (_ca_cert is null) {
            error = "CaCertificate must be set";
            return false;
        }

        if (!ResolveSubjectKey(out subject_key, out error)) {
            return false;
        }

        switch (_message_type) {
            case ScepTestClient.CryptoApi.MessageType.PkcsReq:
            case ScepTestClient.CryptoApi.MessageType.RenewalReq:
                return BuildCsrMessage(subject_key, out message, out error);
            case ScepTestClient.CryptoApi.MessageType.GetCert:
            case ScepTestClient.CryptoApi.MessageType.GetCrl:
                return BuildIssuerSerialMessage(subject_key, out message, out error);
            case ScepTestClient.CryptoApi.MessageType.CertPoll:
                return BuildPollMessage(subject_key, out message, out error);
            default:
                error = $"unsupported message type: {_message_type}";
                return false;
        }
    }

    private bool ResolveSubjectKey(out IScepKey subject_key, out string error) {
        KeySpec spec;
        string spec_error;
        string gen_error;

        subject_key = null!;
        error = string.Empty;

        if (_subject_key is not null) {
            subject_key = _subject_key;
            return true;
        }

        if (string.IsNullOrEmpty(_key_spec_text)) {
            error = "either KeySpec or SubjectKey must be supplied";
            return false;
        }

        if (!CryptoApi.KeySpec.Parse(_key_spec_text!, out spec, out spec_error)) {
            error = spec_error;
            return false;
        }

        if (!_crypto.GenerateKey(spec, out subject_key, out gen_error)) {
            error = gen_error;
            return false;
        }

        return true;
    }

    private bool BuildCsrMessage(IScepKey subject_key, out PkiMessage message, out string error) {
        Pkcs10 csr;

        message = null!;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(_subject)) {
            error = "Subject must be set for an enroll/renewal request";
            return false;
        }

        if (_message_type == ScepTestClient.CryptoApi.MessageType.RenewalReq && (_signer_cert is null || _signer_key is null)) {
            error = "RenewalReq requires SignerCertificate and SignerKey";
            return false;
        }

        csr = new Pkcs10 { Key = subject_key, AltKey = _alt_key, ChallengePassword = _challenge, Sid = _sid };
        csr.SetSubject(_subject!, out _);
        foreach (string dns in _dns_names) { csr.DnsNames.Add(dns); }
        foreach (string upn in _upns) { csr.Upns.Add(upn); }
        foreach (string eku in _ekus) { csr.Ekus.Add(eku); }

        message = new PkiMessage {
            MessageType = _message_type,
            InnerCsr = csr,
            RecipientCaCert = _ca_cert,
            DigestAlgorithmOid = _digest_oid,
            ContentEncryptionAlgorithmOid = _cipher_oid,
            SignerCert = _signer_cert,
            SignerKey = _signer_key ?? subject_key,
            TransactionId = Guid.NewGuid().ToString("N"),
        };
        return true;
    }

    private bool BuildIssuerSerialMessage(IScepKey subject_key, out PkiMessage message, out string error) {
        message = null!;
        error = string.Empty;

        if (string.IsNullOrEmpty(_issuer_name) || string.IsNullOrEmpty(_serial)) {
            error = $"{_message_type} requires IssuerAndSerial";
            return false;
        }

        message = new PkiMessage {
            MessageType = _message_type,
            RecipientCaCert = _ca_cert,
            DigestAlgorithmOid = _digest_oid,
            ContentEncryptionAlgorithmOid = _cipher_oid,
            SignerCert = _signer_cert,
            SignerKey = _signer_key ?? subject_key,
            IssuerName = _issuer_name,
            SerialNumber = _serial,
            TransactionId = Guid.NewGuid().ToString("N"),
        };
        return true;
    }

    private bool BuildPollMessage(IScepKey subject_key, out PkiMessage message, out string error) {
        message = null!;
        error = string.Empty;

        if (string.IsNullOrEmpty(_issuer_name) || string.IsNullOrEmpty(_poll_subject)) {
            error = "CertPoll requires IssuerAndSubject";
            return false;
        }

        message = new PkiMessage {
            MessageType = _message_type,
            RecipientCaCert = _ca_cert,
            DigestAlgorithmOid = _digest_oid,
            ContentEncryptionAlgorithmOid = _cipher_oid,
            SignerCert = _signer_cert,
            SignerKey = _signer_key ?? subject_key,
            IssuerName = _issuer_name,
            SubjectName = _poll_subject,
            TransactionId = Guid.NewGuid().ToString("N"),
        };
        return true;
    }
}
