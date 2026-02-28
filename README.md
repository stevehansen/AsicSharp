# AsicSharp

[![CI](https://github.com/stevehansen/AsicSharp/actions/workflows/ci.yml/badge.svg)](https://github.com/stevehansen/AsicSharp/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/AsicSharp.svg)](https://www.nuget.org/packages/AsicSharp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Create and verify **ASiC-S** and **ASiC-E** (Associated Signature Containers) with **RFC 3161 timestamps** in .NET.

Prove that data existed at a specific point in time using trusted Timestamp Authorities (TSA) like DigiCert — **without needing your own signing certificate**.

## What is this?

ASiC containers are ZIP files (per [ETSI EN 319 162](https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf)) that bundle your files with cryptographic timestamps:

- **ASiC-S** (Simple) — A single file with a timestamp token
- **ASiC-E** (Extended) — Multiple files with an ASiCManifest XML listing each file's digest, timestamped together

This proves that **this exact data existed at this exact time**, signed by a trusted third party. The format is recognized by the EU eIDAS regulation for legal validity.

## Installation

### Library (for your application)

```bash
dotnet add package AsicSharp
```

### CLI Tool (global)

```bash
dotnet tool install -g AsicSharp.Cli
```

## Quick Start

### Library Usage

```csharp
using AsicSharp.Configuration;
using AsicSharp.Services;

// Standalone (no DI)
using var httpClient = new HttpClient();
var options = new AsicTimestampOptions
{
    TimestampAuthorityUrl = WellKnownTsa.DigiCert
};

var tsaClient = new TsaClient(httpClient, options);
var asicService = new AsicService(tsaClient, options);

// Create a timestamped container (single file → ASiC-S)
var data = File.ReadAllBytes("contract.pdf");
var result = await asicService.CreateAsync(data, "contract.pdf");

File.WriteAllBytes("contract.pdf.asics", result.ContainerBytes);
Console.WriteLine($"Timestamped at: {result.Timestamp:O}");

// Create an ASiC-E container (multiple files)
var files = new List<(string FileName, byte[] Data)>
{
    ("contract.pdf", File.ReadAllBytes("contract.pdf")),
    ("annex.pdf", File.ReadAllBytes("annex.pdf"))
};
var extended = await asicService.CreateExtendedAsync(files);
File.WriteAllBytes("bundle.asice", extended.ContainerBytes);

// Verify any container (auto-detects ASiC-S or ASiC-E)
var verification = asicService.VerifyFile("contract.pdf.asics");
Console.WriteLine($"Valid: {verification.IsValid}");
Console.WriteLine($"Timestamp: {verification.Timestamp:O}");
Console.WriteLine($"TSA: {verification.TsaCertificate?.Subject}");

// Renew timestamp for long-term archival (adds archive timestamp per ETSI EN 319 162-1 §5.4)
var renewed = await asicService.RenewFileAsync("contract.pdf.asics");
File.WriteAllBytes("contract.pdf.asics", renewed.ContainerBytes);
Console.WriteLine($"Renewed at: {renewed.Timestamp:O}");
```

### With Dependency Injection

```csharp
// In Startup / Program.cs
builder.Services.AddAsicSharp(options =>
{
    options.TimestampAuthorityUrl = WellKnownTsa.DigiCert;
    options.HashAlgorithm = HashAlgorithmName.SHA256;
});

// Or bind from configuration
builder.Services.AddAsicSharp(
    builder.Configuration.GetSection("AsicTimestamp"));
```

```json
// appsettings.json
{
  "AsicTimestamp": {
    "TimestampAuthorityUrl": "http://timestamp.digicert.com",
    "HashAlgorithm": "SHA256",
    "RequestSignerCertificates": true,
    "Timeout": "00:00:30",
    "MaxFileSize": 10485760
  }
}
```

> **File size limit:** By default, files larger than 10 MB are rejected to prevent accidental memory exhaustion. Set `MaxFileSize` to a higher value or `null` to disable the limit.

```csharp
// In your service
public class MyService
{
    private readonly IAsicService _asicService;

    public MyService(IAsicService asicService)
    {
        _asicService = asicService;
    }

    public async Task TimestampDocument(byte[] data, string fileName)
    {
        var result = await _asicService.CreateAsync(data, fileName);
        // result.ContainerBytes, result.Timestamp, result.DataHash
    }
}
```

### CLI Usage

```bash
# Timestamp a single file (ASiC-S)
asicts stamp contract.pdf
asicts stamp contract.pdf --tsa http://timestamp.digicert.com --algorithm SHA256

# Timestamp multiple files (ASiC-E)
asicts stamp contract.pdf annex.pdf terms.txt

# Verify a container (auto-detects ASiC-S or ASiC-E)
asicts verify contract.pdf.asics
asicts verify bundle.asice --verbose

# Renew timestamp for long-term archival
asicts renew contract.pdf.asics
asicts renew bundle.asice --tsa http://timestamp.sectigo.com

# Extract files from any container
asicts extract contract.pdf.asics --output ./extracted/
asicts extract bundle.asice --output ./extracted/

# List known TSA servers
asicts info
```

## Supported Platforms

| Target | Status |
|--------|--------|
| .NET 10.0 | ✅ |
| .NET 8.0 | ✅ |
| .NET Standard 2.1 | ✅ (.NET Core 3.0+) |

## Well-Known Timestamp Authorities

| TSA | URL | Notes |
|-----|-----|-------|
| DigiCert | `http://timestamp.digicert.com` | Default, widely trusted |
| Sectigo | `http://timestamp.sectigo.com` | Formerly Comodo |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` | |
| FreeTSA | `https://freetsa.org/tsr` | Free & open |
| Apple | `http://timestamp.apple.com/ts01` | |
| Entrust | `http://timestamp.entrust.net/TSS/RFC3161sha2TS` | |

## Container Formats

### ASiC-S (Simple) — Single File

```
document.pdf.asics (ZIP)
├── mimetype                          → "application/vnd.etsi.asic-s+zip"
├── document.pdf                      → Your original file (unchanged)
└── META-INF/
    ├── timestamp.tst                 → RFC 3161 timestamp token (covers the data file)
    ├── timestamp-002.tst             → (After renewal) Archive timestamp covering timestamp.tst
    └── signature.p7s                 → (Optional) CMS/CAdES signature
```

### ASiC-E (Extended) — Multiple Files

```
bundle.asice (ZIP)
├── mimetype                          → "application/vnd.etsi.asic-e+zip"
├── contract.pdf                      → Data file 1
├── annex.pdf                         → Data file 2
└── META-INF/
    ├── ASiCManifest.xml              → Lists all files with their digests
    ├── timestamp.tst                 → RFC 3161 timestamp token (covers the manifest)
    ├── timestamp-002.tst             → (After renewal) Archive timestamp covering timestamp.tst
    └── signature.p7s                 → (Optional) CMS/CAdES signature
```

The timestamp in ASiC-E covers the ASiCManifest XML, which in turn contains cryptographic digests of every data file — so all files are transitively timestamped.

## Timestamp Renewal for Long-Term Archival

Timestamp tokens have a validity period tied to the TSA certificate's lifetime (typically 5-10 years). For long-term archival, renew the timestamp before the original TSA certificate expires. Per ETSI EN 319 162-1 §5.4, each archive timestamp covers the previous token's bytes, creating a chain:

```
timestamp.tst      → Covers data (or manifest)
timestamp-002.tst  → Covers timestamp.tst bytes
timestamp-003.tst  → Covers timestamp-002.tst bytes
```

Verification walks the full chain, ensuring each link is valid. The original timestamp proves when the data existed; renewal timestamps extend the proof indefinitely.

## Optional: Signing with Your Own Certificate

If you need to prove **who** timestamped the data (not just **when**), provide a signing certificate:

```csharp
services.AddAsicSharp(options =>
{
    options.SigningCertificate = new X509Certificate2("cert.pfx", "password");
});
```

This adds a CMS/CAdES detached signature (`META-INF/signature.p7s`) alongside the timestamp.

## Verification Details

The `Verify` method returns detailed step-by-step results:

```csharp
var result = asicService.Verify(containerBytes);

foreach (var step in result.Steps)
{
    Console.WriteLine($"{(step.Passed ? "✓" : "✗")} {step.Name}: {step.Detail}");
}
// ✓ Container structure: Valid ZIP archive
// ✓ MIME type: application/vnd.etsi.asic-s+zip
// ✓ Data file: contract.pdf (125432 bytes)
// ✓ Timestamp token decode: Token decoded, timestamp: 2026-02-28T14:30:00Z
// ✓ Timestamp signature: Valid, signed by: CN=DigiCert Timestamp 2024, O=DigiCert
// ✓ Data hash match: Hash in timestamp matches data file
```

## Standards Compliance

- **ETSI EN 319 162-1** — Associated Signature Containers (ASiC) baseline (ASiC-S)
- **ETSI EN 319 162-2** — Associated Signature Containers extended (ASiC-E)
- **ETSI TS 102 918** — ASiCManifest XML schema
- **RFC 3161** — Internet X.509 PKI Time-Stamp Protocol
- **RFC 5652** — Cryptographic Message Syntax (CMS)
- **EU eIDAS Regulation** — Electronic identification and trust services

## License

MIT — see [LICENSE](LICENSE)
