# AsicSharp - STRIDE Threat Model

**Version:** 1.2
**Created:** 2026-02-28
**Next Review:** 2029-02-28

## System Overview

### Description

AsicSharp is a .NET library and CLI tool for creating and verifying ASiC-S (Simple) and ASiC-E (Extended) Associated Signature Containers with RFC 3161 timestamps. It proves that data existed at a specific point in time using trusted Timestamp Authorities (TSAs). Compliant with ETSI EN 319 162-1 (ASiC-S), ETSI EN 319 162-2 (ASiC-E), and EU eIDAS.

### Components

| Component | Description | Technology |
|-----------|-------------|------------|
| **AsicSharp** (library) | Core library for ASiC-S/ASiC-E creation/verification | .NET (netstandard2.1, net8.0, net10.0) |
| **AsicSharp.Cli** (`asicts`) | CLI tool wrapping the library | .NET 8.0, System.CommandLine |
| **TsaClient** | HTTP client for RFC 3161 timestamp requests | HttpClient, System.Security.Cryptography.Pkcs |
| **AsicService** | Orchestrator for container creation/verification | ZipArchive, XDocument (ASiCManifest), CMS/CAdES signatures |

### Users / Actors

| Actor | Description |
|-------|-------------|
| **Developer** | Integrates the library into .NET applications via NuGet |
| **CLI User** | Uses the `asicts` command-line tool directly |
| **Timestamp Authority** | External RFC 3161 TSA server providing cryptographic timestamps |

### Data Flow

```
                         ┌──────────────────┐
                         │   CLI User /     │
                         │   Developer App  │
                         └────────┬─────────┘
                                  │
                    File paths, data bytes, config
                                  │
                         ┌────────▼─────────┐
                         │   AsicService     │
                         │                   │
                         │  - Hash data      │
                         │  - Build manifest │ (ASiC-E: ASiCManifest XML)
                         │  - Build ZIP      │
                         │  - Verify tokens  │
                         │  - Parse manifest │ (ASiC-E: XDocument)
                         │  - CMS signing    │
                         └───┬──────────┬────┘
                             │          │
                     ┌───────▼──┐  ┌────▼───────────────┐
                     │ TsaClient│  │  File System        │
                     │          │  │                     │
                     │ HTTP POST│  │ Read input files    │
                     │ to TSA   │  │ Write .asics/.asice │
                     └───┬──────┘  │ Extract data        │
                         │         └─────────────────────┘
              ┌──────────▼───────────┐
              │  Timestamp Authority │
              │  (External Server)   │
              │                      │
              │  e.g. DigiCert,      │
              │  Sectigo, GlobalSign │
              └──────────────────────┘
```

### Trust Boundaries

| Boundary | From | To | Data Crossing |
|----------|------|----|---------------|
| **TB-1** | User/Application | Library | File paths, data, configuration |
| **TB-2** | Library | File System | File reads/writes, ZIP operations |
| **TB-3** | Library | TSA Server | Data hash (outbound), timestamp token (inbound) |

### Data Classification

| Data Type | Classification | Notes |
|-----------|---------------|-------|
| User files (data to timestamp) | Varies (up to confidential) | Stored in ZIP container; only hash sent to TSA |
| Data hash (SHA-256/384/512) | Low sensitivity | One-way; does not reveal original data |
| RFC 3161 timestamp token | Integrity-critical | Cryptographically signed proof of time |
| Signing certificate (optional) | Sensitive | Private key material; caller-managed |
| TSA certificate | Public | Embedded in token response |
| ASiC-S container (.asics) | Same as input data | ZIP containing data + timestamp + optional signature |
| ASiC-E container (.asice) | Same as input data | ZIP containing multiple data files + ASiCManifest + timestamp + optional signature |
| ASiCManifest XML | Integrity-critical | Lists file digests; timestamp covers this manifest |

---

## STRIDE Analysis

### S — Spoofing

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|------------|--------|-------|------------|
| S-1 | Rogue TSA server | Attacker configures a malicious TSA URL to issue fake timestamps | 1 (Very Low) | 3 (High) | 3 | TSA URL is caller-configured, not user-input. Library validates the cryptographic signature on TSA responses. Forged tokens fail verification. |
| S-2 | TSA certificate compromise | A TSA's signing key is compromised, allowing forged timestamps | 1 (Very Low) | 4 (Critical) | 4 | Relies on TSA operational security and CA revocation. Outside library scope. |
| S-3 | Revoked signing certificate accepted | CMS signature verification does not enforce revocation checking | 2 (Low) | 2 (Medium) | 4 | .NET's `SignedCms.CheckSignature(false)` performs chain validation. Revocation checking depends on platform configuration. CMS signing is optional. |

**Countermeasures in place:**
- TSA responses are cryptographically validated using `Rfc3161TimestampToken.VerifySignatureForHash`
- Certificate chain validation via .NET PKI APIs
- Library does not accept TSA URLs from untrusted input (developer-configured)

### T — Tampering

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|------------|--------|-------|------------|
| T-1 | ZIP path traversal on extract | Malicious ASiC-S container contains ZIP entry with `../` in filename; CLI `extract` writes to arbitrary path | 1 (Very Low) | 4 (Critical) | 4 | **Mitigated.** `Extract()` and `Verify()` apply `Path.GetFileName()` to strip directory components from ZIP entry names. Fixed in [#1](https://github.com/stevehansen/AsicSharp/issues/1). |
| T-2 | Data tampering in container | Attacker modifies data inside an ASiC-S container | 2 (Low) | 3 (High) | 6 | Verification detects hash mismatch. Timestamp token binds to original data hash. |
| T-3 | Timestamp replay | Attacker replays a previously captured timestamp token | 1 (Very Low) | 2 (Medium) | 2 | **Mitigated.** `TsaClient` generates a random 8-byte nonce when `UseNonce` is true (default). `ProcessResponse` validates the nonce in the TSA response. Tokens are also bound to a specific data hash. |
| T-4 | TSA response interception (HTTP) | TSA URLs use HTTP; MITM could intercept and modify responses | 1 (Very Low) | 3 (High) | 3 | RFC 3161 TSA responses are cryptographically signed — a modified response fails `ProcessResponse` validation regardless of transport. HTTP is standard for TSAs (security is in the signature, not the transport). |
| T-5 | XXE/XML bomb in ASiCManifest | Malicious ASiC-E container contains crafted ASiCManifest.xml with external entity references or recursive expansion | 1 (Very Low) | 3 (High) | 3 | **Mitigated.** `XDocument.Parse()` in .NET does not process DTDs or resolve external entities by default. XML bomb expansion is bounded by .NET's default XML reader limits. |
| T-6 | ASiCManifest digest mismatch | Attacker modifies a data file in an ASiC-E container without updating the manifest | 2 (Low) | 3 (High) | 6 | **Mitigated.** Verification recomputes each file's digest and compares against the manifest. The timestamp binds to the manifest bytes, so manifest changes are also detected. |

**Countermeasures in place:**
- SHA-256 hash binding between data and timestamp token
- Cryptographic signature verification on timestamp tokens
- `ValidateFileName()` prevents path separators in filenames during creation
- `Path.GetFileName()` sanitizes ZIP entry names during extraction and verification
- Random nonce included in timestamp requests (replay protection)
- `Rfc3161TimestampRequest.ProcessResponse` validates response integrity and nonce
- ASiC-E digest verification: each file's hash verified against ASiCManifest, manifest hash verified against timestamp
- `XDocument.Parse()` used for manifest parsing (safe XML defaults, no DTD processing)

### R — Repudiation

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|------------|--------|-------|------------|
| R-1 | No audit trail for operations | Library does not log who created/verified containers or maintain an audit trail | 2 (Low) | 2 (Medium) | 4 | Structured logging via `ILogger` at Debug/Information levels. Calling application can capture and persist logs. |
| R-2 | Timestamp authority denial | TSA denies issuing a timestamp | 1 (Very Low) | 2 (Medium) | 2 | RFC 3161 tokens contain the TSA's cryptographic signature, providing non-repudiation. Multiple well-known TSAs available. |

**Countermeasures in place:**
- RFC 3161 timestamps provide cryptographic non-repudiation of time
- Optional CMS/CAdES signatures provide signer non-repudiation
- `ILogger` integration for operation tracing

### I — Information Disclosure

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|------------|--------|-------|------------|
| I-1 | Data hash in logs | SHA-256 hash of timestamped data is logged at Information level and returned in results | 2 (Low) | 1 (Low) | 2 | Hash is a one-way function — it does not reveal original data content. Standard practice for timestamping workflows. |
| I-2 | File paths in CLI output | Full file system paths are printed to console | 2 (Low) | 1 (Low) | 2 | CLI output is local to the user's terminal. Expected behavior for a CLI tool. |
| I-3 | Exception messages expose internals | `TimestampAuthorityException` includes HTTP status codes; `CryptographicException` messages forwarded to callers | 2 (Low) | 1 (Low) | 2 | Exception details help developers diagnose issues. Library consumers control whether exceptions reach end users. |
| I-4 | Signing certificate in memory | `X509Certificate2` with private key held in memory (unprotected) | 1 (Very Low) | 3 (High) | 3 | Standard .NET pattern. Callers should use secure certificate storage (Key Vault, DPAPI, etc.). Private key lifetime is caller's responsibility. |

**Countermeasures in place:**
- Only data hash (not raw data) is logged or sent to TSA
- Structured logging allows consumers to control log levels and sinks
- Custom exception hierarchy allows granular error handling

### D — Denial of Service

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|------------|--------|-------|------------|
| D-1 | TSA unavailability | TSA server is down or rate-limits requests | 2 (Low) | 2 (Medium) | 4 | Configurable timeout (default 30s). `HttpRequestException` thrown on failure. Caller can retry or use alternate TSA. |
| D-2 | ZIP bomb in container | Malicious ASiC-S with highly compressed entry causes memory exhaustion during verification | 1 (Very Low) | 3 (High) | 3 | Container bytes are fully loaded into memory via `byte[]` API. .NET `ZipArchive` provides basic protection against unbounded expansion. |
| D-3 | Large file processing | Very large input file(s) cause memory pressure (all data loaded via `ReadAllBytes`). ASiC-E amplifies this with multiple files. | 2 (Low) | 2 (Medium) | 4 | **Mitigated.** Configurable `MaxFileSize` option (default 10 MB) rejects oversized files before processing. Set to `null` to disable. Stream-based `CreateAsync(Stream, ...)` overload also available for ASiC-S. |

**Countermeasures in place:**
- Configurable HTTP timeout (default 30 seconds)
- Configurable per-file size limit (`MaxFileSize`, default 10 MB)
- Stream overload for memory-efficient creation
- Multiple well-known TSA URLs available as fallbacks
- `CancellationToken` support on async operations

### E — Elevation of Privilege

| ID | Threat | Attack Path | Likelihood | Impact | Score | Mitigation |
|----|--------|-------------|------------|--------|-------|------------|
| E-1 | Arbitrary file write via extract | Malicious ZIP entry name with path traversal sequences causes file overwrite outside output directory | 1 (Very Low) | 4 (Critical) | 4 | **Mitigated.** Same fix as T-1 — `Extract()` and `Verify()` sanitize entry names via `Path.GetFileName()`. Fixed in [#1](https://github.com/stevehansen/AsicSharp/issues/1). |
| E-2 | Signing certificate misuse | Compromised signing certificate used to create fraudulent signed containers | 1 (Very Low) | 3 (High) | 3 | Certificate management is the caller's responsibility. Library does not store or manage certificates. |

**Countermeasures in place:**
- Library runs with caller's privileges (no elevation)
- No network listeners or server components
- File system access limited to caller-specified paths
- ZIP entry names sanitized with `Path.GetFileName()` on extraction

---

## Risk Summary

### High Priority Threats (Score >= 8)

None — all previously high-priority threats have been mitigated.

| ID | Threat | Original Score | Current Score | Status |
|----|--------|---------------|---------------|--------|
| **T-1** | ZIP path traversal on extract | 8 | 4 | Mitigated — `Path.GetFileName()` sanitization ([#1](https://github.com/stevehansen/AsicSharp/issues/1)) |
| **E-1** | Arbitrary file write via extract | 8 | 4 | Mitigated — same fix as T-1 |

### Residual Risks

| Risk | Severity | Rationale |
|------|----------|-----------|
| TSA operational security | Medium | Library trusts TSA certificate chain; TSA compromise is outside scope |
| SHA-1 backward compatibility | Low | Supported for legacy TSA tokens; SHA-256 is the default and recommended |
| HTTP transport for TSA | Low | Standard practice — RFC 3161 security relies on cryptographic signatures, not transport |

---

## Security Controls Summary

| Category | Implementation |
|----------|---------------|
| **Cryptography** | SHA-256/384/512 via .NET APIs; RFC 3161 timestamp tokens with nonce replay protection; CMS/CAdES detached signatures |
| **Input Validation** | `ValidateFileName()` on creation (rejects duplicates for ASiC-E); `Path.GetFileName()` on extraction; null/empty checks on all public APIs; file existence checks |
| **XML Processing** | `XDocument.Parse()` for ASiCManifest (safe defaults: no DTD, no external entities); digest verification per `DataObjectReference` |
| **Certificate Validation** | `Rfc3161TimestampToken.VerifySignatureForHash`; `SignedCms.CheckSignature` with chain validation |
| **Error Handling** | Custom exception hierarchy (`AsicTimestampException` → specific subtypes); structured logging |
| **Transport** | HttpClient with configurable timeout; TSA response validation independent of transport |
| **Build Security** | `TreatWarningsAsErrors`; `AnalysisLevel latest-recommended`; nullable enabled |
| **CI/CD** | Automated unit + integration tests; OIDC trusted publishing to NuGet (no API key secrets) |

---

## Review History

| Version | Date | Reviewer | Changes |
|---------|------|----------|---------|
| 1.0 | 2026-02-28 | Initial analysis | Initial STRIDE threat model |
| 1.1 | 2026-02-28 | Post-fix update | T-1/E-1 mitigated (path traversal fix); T-3 mitigated (nonce support implemented) |
| 1.2 | 2026-02-28 | ASiC-E support | Added T-5 (XXE/XML bomb), T-6 (manifest digest mismatch), updated D-3 for multi-file; added XML processing controls |

---

## References

- [ETSI EN 319 162-1](https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/) — ASiC Baseline Profile (ASiC-S)
- [ETSI EN 319 162-2](https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/) — ASiC Extended Profile (ASiC-E)
- [ETSI TS 102 918](https://www.etsi.org/deliver/etsi_ts/102900_102999/102918/) — ASiCManifest XML Schema
- [RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161) — Internet X.509 PKI Time-Stamp Protocol
- [RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652) — Cryptographic Message Syntax (CMS)
- [OWASP STRIDE](https://owasp.org/www-community/Threat_Modeling_Process) — Threat Modeling Methodology
- [EU eIDAS Regulation](https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation) — Electronic Identification and Trust Services
