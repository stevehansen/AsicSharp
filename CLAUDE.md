# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AsicSharp is a .NET library and CLI tool for creating and verifying **ASiC-S** (Associated Signature Containers) with **RFC 3161 timestamps**. It proves that data existed at a specific point in time using trusted Timestamp Authorities (TSAs) — without requiring a signing certificate. Compliant with ETSI EN 319 162-1 and EU eIDAS.

## Build & Test Commands

```bash
dotnet build                                                    # Build all projects
dotnet build --configuration Release                            # Release build
dotnet test --filter "Category!=Integration"                    # Run unit tests (exclude integration)
dotnet test --filter "Category=Integration"                     # Run integration tests (requires network to TSA servers)
dotnet test --filter "FullyQualifiedName~AsicServiceTests"      # Run a specific test class
dotnet test --filter "DisplayName~CreateAsync_ShouldProduceValid" # Run a single test by name
dotnet pack src/AsicSharp/AsicSharp.csproj -c Release           # Pack the library NuGet
dotnet pack src/AsicSharp.Cli/AsicSharp.Cli.csproj -c Release   # Pack the CLI tool
```

## Solution Structure

Three projects in `AsicSharp.sln`:

- **`src/AsicSharp`** — Core library (multi-target: `netstandard2.1`, `net8.0`, `net10.0`). Published as NuGet package. Uses PolySharp for netstandard2.1 polyfills.
- **`src/AsicSharp.Cli`** — CLI tool (`net8.0`). Packaged as a dotnet global tool (`asicts`). Uses `System.CommandLine` for arg parsing.
- **`tests/AsicSharp.Tests`** — xUnit tests (`net8.0`) with NSubstitute for mocking and FluentAssertions. Integration tests (trait `Category=Integration`) hit real TSA servers and need network access.

## Architecture

### Core Library (`AsicSharp`)

Two main services behind interfaces:

- **`ITsaClient` / `TsaClient`** — Sends RFC 3161 timestamp requests to a TSA over HTTP. Uses `Rfc3161TimestampRequest`/`Rfc3161TimestampToken` from `System.Security.Cryptography.Pkcs`. Designed as a typed `HttpClient` for DI.
- **`IAsicService` / `AsicService`** — Orchestrates container creation and verification. Builds ASiC-S ZIP containers (mimetype entry first, data file, `META-INF/timestamp.tst`, optional `META-INF/signature.p7s`). Verification walks through structured steps returning `AsicVerifyResult` with a list of `VerificationStep`.

Both services have dual constructors: `IOptions<AsicTimestampOptions>` for DI (marked with `[ActivatorUtilitiesConstructor]`) and raw `AsicTimestampOptions` for standalone use.

### Key Types

- **`AsicTimestampOptions`** (`Configuration/`) — All config: TSA URL, hash algorithm, signing certificate, timeout, nonce policy. Config section name: `"AsicTimestamp"`.
- **`WellKnownTsa`** — Static constants for common TSA URLs (DigiCert default).
- **`AsicCreateResult` / `AsicVerifyResult` / `TimestampResult`** (`Models/`) — Immutable result objects with `required init` properties.
- **`AsicConstants`** (`Services/`) — Internal constants for ZIP entry names and paths per ETSI spec. Visible to CLI and Tests via `InternalsVisibleTo`.
- **`ServiceCollectionExtensions`** (`Extensions/`) — `AddAsicSharp()` DI registration with overloads for action-based config and `IConfigurationSection` binding.

### Exception Hierarchy

`AsicTimestampException` (base) → `TimestampAuthorityException`, `InvalidAsicContainerException`, `AsicVerificationException`.

## Build Configuration

- **Central package management** via `Directory.Packages.props` — all package versions defined there.
- **`Directory.Build.props`** — Shared properties: `TreatWarningsAsErrors`, `Nullable enable`, `AnalysisLevel latest-recommended`, `LangVersion latest`. Author: Steve Hansen.
- **PolySharp** provides polyfills for `init`, `required`, records, etc. on `netstandard2.1`.
- **MinVer** for automatic versioning from git tags. **ThisAssembly.Git** for assembly info.
- `Convert.ToHexString` is not available on netstandard2.1 — use the `#if NET5_0_OR_GREATER` guarded `ToHexString` helper in `AsicService`.
- Suppressed analyzers: CA1848 (LoggerMessage delegates), CA5350 (SHA1 needed for TSA compat), CS1591 (XML doc inheritance), CA1707 (test underscores).

## CI & Publishing

- **CI** (`.github/workflows/ci.yml`): builds on .NET 8 and 10, runs unit tests, runs integration tests separately (`continue-on-error: true` since TSAs may be unavailable), packs NuGet on main branch.
- **Publish** (`.github/workflows/publish.yml`): Tag-triggered (`X.Y.Z`), uses OIDC trusted publishing via `nuget/login@v1` with `vars.NUGET_USER`. No API key secrets needed.

## Code Style

- 4-space indentation, UTF-8, LF line endings (`.editorconfig`)
- 2-space indent for XML/JSON/YAML files
- File-scoped namespaces
- Warnings as errors
- **Conventional Commits**: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `ci:`, `chore:`
