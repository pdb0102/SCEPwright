**Intune Simulator** — a standalone, embeddable .NET 8 simulator of Microsoft Intune's SCEP certificate-validation service and all the surrounding services its PKI connector talks to: fake AAD/MSAL, MS Graph service discovery, the Intune SCEP actions, and PKI-connector revocation. Test a SCEP server's Intune integration — both the happy path and every failure mode — without provisioning real Intune or Azure AD.

It implements the **entire call chain** the Microsoft "Intune Access" sample (and products built on it) exercises, so you can point every configurable URL at the simulator and drive real enrollments end-to-end — including deterministic error injection at every hop. It's verified against **real MSAL.NET and the real Microsoft sample validator classes** over loopback TLS, for both secret and certificate auth.

## What it emulates

- **AAD / MSAL** — instance discovery, OpenID configuration, JWKS, and a client-credentials **token endpoint** that validates a **client secret** or a **certificate JWT client-assertion** (RS256) and issues simulator-signed tokens.
- **MS Graph service discovery** — `servicePrincipals/appId=…/endpoints`, with the legacy **AAD Graph** (`servicePrincipalsByAppId/…/serviceEndpoints`) fallback.
- **Intune SCEP actions** — `validateRequest`, `successNotification`, `failureNotification`.
- **PKI-connector revocation** — `downloadRevocationRequests` / `uploadRevocationResults`.

## Highlights

- **Deterministic failure-flow engine** — walks every failure mode (timeout, connection reset, 500/503/401, malformed JSON, SCEP error codes) at every hop in the chain. Manual stepping for precise tests, plus an auto mode; soft faults with an `X-Sim-Injected` header, or real socket faults against real Kestrel. Self-documented to `FAILURE-FLOW.md` and `--print-failure-doc`.
- **Behavior control endpoint** (`/control`) — read/set behavior at runtime as JSON: auth password, challenge password, canned SCEP error codes, revocation queue, request log, and the failure flow. `GET /control/requests` exposes everything the simulator received.
- **Challenge-password endpoint** (`/challenge`) — a web page for manual copy-out and a JSON form for automation, plus all the URLs to configure.
- **Info page & startup banner**, **per-request console logging**, **hardened auto-TLS** (or bring your own via `--tls-cert`), and an **ADAL-fallback trigger** (`failTokenScopeContains`).

## Quick start

```bash
dotnet run --project src/IntuneSimulator.Host
```

Defaults: HTTP **8080**, HTTPS **8443**, auth password **`IntunePassw0rd!`**, tenant `contoso.onmicrosoft.com`. The startup banner prints every URL to configure. Run with `--help` for all options. See the [README](README.md) for the full configuration table, TLS-trust guidance, and embedding instructions.

## Hosting

- **Standalone** Kestrel executable (HTTP + HTTPS).
- **IIS** via the included `web.config` (ASP.NET Core Module, in-process); set `--advertised-base-url` for the external URL.
- **In-process** in .NET test suites via `WebApplicationFactory`; or as an external process for .NET Framework 4.8 test suites.

## Requirements

- .NET 8 (the projects target `net8.0`).

## Notes & limitations

- This is a **test double**, not a security product — it issues signed tokens but does not enforce real authorization, and it performs no real PKCS#10/SCEP cryptographic policy validation.
- The self-signed TLS cert must be trusted by the machine running your SCEP server (into the **Local Machine** store if it runs as a Windows service). The README has a TLS-trust troubleshooting section and an `mkcert` alternative.
- Runtime behavior state (canned codes, failure cursor, revocation queue) is in-memory and resets on restart.

---
