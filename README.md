# AsicSharp

[![NuGet](https://img.shields.io/nuget/v/AsicSharp.svg)](https://www.nuget.org/packages/AsicSharp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Create and verify **ASiC-S** (Associated Signature Containers) with **RFC 3161 timestamps** in .NET.

Prove that data existed at a specific point in time using trusted Timestamp Authorities (TSA) like DigiCert — **without needing your own signing certificate**.

## What is this?

An ASiC-S container is a ZIP file (per [ETSI EN 319 162](https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf)) that bundles:

- Your original file (any format)
- An RFC 3161 timestamp token from a trusted Timestamp Authority

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

// Create a timestamped container
var data = File.ReadAllBytes("contract.pdf");
var result = await asicService.CreateAsync(data, "contract.pdf");

File.WriteAllBytes("contract.pdf.asics", result.ContainerBytes);
Console.WriteLine($"Timestamped at: {result.Timestamp:O}");

// Verify it later
var verification = asicService.VerifyFile("contract.pdf.asics");
Console.WriteLine($"Valid: {verification.IsValid}");
Console.WriteLine($"Timestamp: {verification.Timestamp:O}");
Console.WriteLine($"TSA: {verification.TsaCertificate?.Subject}");
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
    "Timeout": "00:00:30"
  }
}
```

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
# Timestamp a file
asicts stamp contract.pdf
asicts stamp contract.pdf --tsa http://timestamp.digicert.com --algorithm SHA256

# Verify a container
asicts verify contract.pdf.asics
asicts verify contract.pdf.asics --verbose

# Extract original file
asicts extract contract.pdf.asics --output ./extracted/

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

## ASiC-S Container Format

```
document.pdf.asics (ZIP)
├── mimetype                          → "application/vnd.etsi.asic-s+zip"
├── document.pdf                      → Your original file (unchanged)
└── META-INF/
    ├── timestamp.tst                 → RFC 3161 timestamp token
    └── signature.p7s                 → (Optional) CMS/CAdES signature
```

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

- **ETSI EN 319 162-1** — Associated Signature Containers (ASiC) baseline
- **RFC 3161** — Internet X.509 PKI Time-Stamp Protocol
- **RFC 5652** — Cryptographic Message Syntax (CMS)
- **EU eIDAS Regulation** — Electronic identification and trust services

## License

MIT — see [LICENSE](LICENSE)
