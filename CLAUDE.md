# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AsicSharp is a .NET library and CLI tool (`asicts`) for creating and verifying **ASiC** containers with **RFC 3161 timestamps** — **ASiC-S** (one file) and **ASiC-E** (many files + manifest). It proves that data existed at a specific point in time using trusted Timestamp Authorities (TSAs) — without requiring a signing certificate. Compliant with ETSI EN 319 162-1/-2, ETSI TS 102 918, and EU eIDAS.

## Build & Test Commands

```bash
dotnet build                                                    # Build all projects
dotnet build --configuration Release                            # Release build
dotnet test --filter "Category!=Integration"                    # Unit tests
dotnet test --filter "Category=Integration"                     # Integration tests (real TSA servers, needs network)
dotnet test --filter "FullyQualifiedName~AsicServiceTests"      # A specific test class
dotnet test --filter "DisplayName~CreateAsync_ShouldProduceValid" # A single test by name
dotnet run --project src/AsicSharp.Cli -- verify file.asics -v  # Run the CLI from source
dotnet pack src/AsicSharp/AsicSharp.csproj -c Release           # Pack the library NuGet
dotnet pack src/AsicSharp.Cli/AsicSharp.Cli.csproj -c Release   # Pack the CLI tool
```

The library sets `GeneratePackageOnBuild=true`, so a plain build already emits its `.nupkg`. There is no separate lint step — style comes from `.editorconfig` plus `TreatWarningsAsErrors`.

## Solution Structure

Three projects in `AsicSharp.sln`:

- **`src/AsicSharp`** — Core library (multi-target: `netstandard2.1`, `net8.0`, `net10.0`). Published as NuGet package `AsicSharp`. Uses PolySharp for netstandard2.1 polyfills.
- **`src/AsicSharp.Cli`** — CLI (`net8.0`), assembly and tool command both named `asicts`, packaged as a dotnet global tool (`AsicSharp.Cli`).
- **`tests/AsicSharp.Tests`** — xUnit (`net8.0`) with NSubstitute and AwesomeAssertions (the free Apache-2.0 fork of FluentAssertions; v8+ of FluentAssertions is commercially licensed — don't reintroduce it). Integration tests carry trait `Category=Integration`.

## Architecture

### Flow

- **Create ASiC-S**: hash the data → `ITsaClient` → token → build ZIP (`mimetype`, data file, `META-INF/timestamp.tst`, `META-INF/README.txt`, optional `META-INF/signature.p7s`).
- **Create ASiC-E**: build `META-INF/ASiCManifest.xml` holding each file's digest → hash *the manifest* → timestamp that. Data files are timestamped transitively through the manifest, so the digests in the manifest are what verification checks per file.
- **Verify**: open the ZIP → detect the format from `mimetype` (falling back to `ASiCManifest.xml` presence) → ASiC-S path in `Verify` or ASiC-E path in `VerifyExtended` → walk the timestamp chain.

### Two services, both behind interfaces

- **`ITsaClient` / `TsaClient`** — RFC 3161 requests over HTTP using `Rfc3161TimestampRequest`/`Rfc3161TimestampToken` from `System.Security.Cryptography.Pkcs`. Designed as a typed `HttpClient` for DI. Walks `TimestampAuthorityUrls` in order, falling through to the next URL on `HttpRequestException` or `TimestampAuthorityException`; throws the last failure only when every URL fails. Optional random nonce for replay protection.
- **`IAsicService` / `AsicService`** — Create / verify / extract / renew for both formats, plus `GetContainerType` as a lightweight format probe that never throws.

Both expose dual constructors: `IOptions<AsicTimestampOptions>` for DI (marked `[ActivatorUtilitiesConstructor]`) and raw `AsicTimestampOptions` for standalone use.

### Verification model

`Verify` does not throw on a bad container — every check becomes a `VerificationStep`, `IsValid` is "all steps passed", and `Error` is the concatenation of failing details. Adding a step therefore adds a new way for a container to be *invalid*; step names and ordering are asserted by tests.

Renewal chains (`RenewAsync`, per ETSI EN 319 162-1 §5.4): every `META-INF/*.tst` is sorted lexicographically, and token *i* is verified against token *i-1*'s raw bytes — token 1 against the data file (ASiC-S) or the manifest (ASiC-E). `TimestampChain` is only populated when 2+ tokens exist (null stays backward compatible). The result's `Timestamp`/`TsaCertificate`/`HashAlgorithm` always come from token 1 — the original proof of existence. The hash algorithm used during verification is read from the token's OID, not from options.

### Key types

- **`AsicTimestampOptions`** (`Configuration/`) — Config section `"AsicTimestamp"`. TSA URL(s), hash algorithm, timeout, nonce and signer-cert policy, `SigningCertificate` (when set, a detached CMS/CAdES `signature.p7s` is added), and `MaxFileSize` (10 MB default, `null` disables) enforced both on create and per-ZIP-entry on read.
- **`WellKnownTsa`** — TSA URL constants (DigiCert default; also Sectigo, GlobalSign, FreeTSA, Apple, Entrust).
- **`AsicContainerType`** — `None` / `Simple` / `Extended`.
- **`AsicCreateResult` / `AsicVerifyResult` / `TimestampResult` / `TimestampChainEntry` / `VerificationStep`** (`Models/`) — Immutable, `required init` properties.
- **`AsicConstants`** and **`AsicCrypto`** (`Services/`) — Internal: ETSI entry names/MIME types/namespace, and the shared hash + hex helpers. Visible to CLI and tests via `InternalsVisibleTo`.
- **`ServiceCollectionExtensions`** (`Extensions/`) — `AddAsicSharp()` with action-based and `IConfigurationSection` overloads.

### Container invariants to preserve

- `mimetype` must be the **first** entry and written with `CompressionLevel.NoCompression`, UTF-8 without BOM (ETSI requirement).
- `META-INF/README.txt` is a human-readable explainer held as const strings in `AsicService`; tests assert its content.
- Renewal appends the new token with `ZipArchiveMode.Update` rather than rebuilding the ZIP, so previously timestamped bytes stay byte-identical.
- Extraction sanitizes entry names through `Path.GetFileName` (Zip Slip defence) and rejects oversized entries.

### Exception Hierarchy

`AsicTimestampException` (base) → `TimestampAuthorityException`, `InvalidAsicContainerException`, `AsicVerificationException`.

## CLI

Commands: `stamp` (multiple file arguments switch it to ASiC-E automatically), `verify` (`-v` prints every step; exit code 1 when invalid), `renew` (rewrites the container in place), `extract`, `info`.

`System.CommandLine` is pinned to `2.0.0-beta4`, whose API (`SetHandler`, `InvocationContext`, `GetValueForOption`) differs from the stable 2.0 shape — don't modernize the call style without also moving the pin.

## Build Configuration

- **Central package management** via `Directory.Packages.props` — all versions live there.
- **`Directory.Build.props`** — `TreatWarningsAsErrors`, `Nullable enable`, `ImplicitUsings enable`, `AnalysisLevel latest-recommended`, `LangVersion latest`, package metadata. Author: Steve Hansen.
- **PolySharp** polyfills `init`, `required`, records, etc. on netstandard2.1. **MinVer** derives versions from git tags; **ThisAssembly.Git** injects git assembly info.
- netstandard2.1 gaps to guard: `Convert.ToHexString` (`#if NET5_0_OR_GREATER`, wrapped by `AsicCrypto.ToHexString`), and the cancellation-token overloads of `File.ReadAllBytesAsync` / `HttpContent.ReadAsByteArrayAsync` (`#if NET8_0_OR_GREATER`).
- Suppressed analyzers: CA1848/CA1873 (LoggerMessage delegates), CA5350 (SHA1 kept for TSA compat), CS1591 (XML docs inherited from interfaces), CA1707 (test underscores).

## Testing Notes

Unit tests substitute `ITsaClient` and feed a **non-DER placeholder** token (`CreateFakeTimestampToken` returns plain UTF-8 bytes), so they only cover container structure and hashing. Anything that exercises token decoding, TSA signature validation, or renewal-chain verification has to be an integration test against a real TSA.

## CI & Publishing

- **CI** (`.github/workflows/ci.yml`): builds on .NET 8 and 10, runs unit tests, then integration tests in a separate job with `continue-on-error: true` since TSAs may be unavailable.
- **Publish** (`.github/workflows/publish.yml`): tag-triggered (`X.Y.Z`), OIDC trusted publishing via `nuget/login@v1` with `vars.NUGET_USER`. No API key secrets.

## Code Style

- 4-space indentation, UTF-8, LF line endings (`.editorconfig`); 2-space for XML/JSON/YAML
- File-scoped namespaces
- Warnings as errors
- **Conventional Commits**: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `ci:`, `chore:`

## Security Documentation

### STRIDE.md Threat Model

This repository includes a STRIDE threat model (`STRIDE.md`) for security analysis.

**When to update STRIDE.md:**
- Adding new authentication/authorization mechanisms
- Changing data storage, encryption, or secrets handling
- Adding new external integrations or API endpoints
- Modifying trust boundaries (new external connections, database access)
- After security incidents or penetration test findings
- When addressing security recommendations from the document
- **When a change mitigates or resolves an existing finding** — move it to Mitigated/Resolved (update the mitigation text, score/status, and risk-summary row)

**Updates are bidirectional and ride in the same PR.** Whether a change *introduces/surfaces* a threat or *mitigates/resolves* one, the matching `STRIDE.md` edit ships in the **same PR** as the code/config change — never as a follow-up. A fix that closes a tracked finding is not done until `STRIDE.md` (and the linked issue's status) reflects it. Treat a security-relevant diff with no STRIDE.md change as incomplete.

**How to update:**
1. Add new threats to the relevant STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
2. Assess likelihood (Very Low → High) and impact (Low → Critical)
3. Document existing mitigations or add recommendations
4. Link GitHub issues for unresolved findings
5. Update the Review History table
6. Update version if using frontmatter

**Tracking critical findings:**
- Critical/High risk findings should have a linked GitHub issue with `security` label
- Review STRIDE.md annually or after major releases
