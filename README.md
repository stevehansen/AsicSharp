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

### Large Files: Streaming

The `byte[]` API above holds the payload and the finished container in memory at once. For large
files, three members avoid that entirely — the payload is hashed in chunks and copied straight
into the container:

```csharp
// Create without materialising the payload or the container
await using (var input = File.OpenRead("huge-archive.zip"))
await using (var output = File.Create("huge-archive.zip.asics"))
{
    var result = await asicService.CreateToStreamAsync(input, "huge-archive.zip", output);
    Console.WriteLine($"Wrote {result.BytesWritten:N0} bytes, stamped {result.Timestamp:O}");
}

// Verify in place, without copying the container into a byte[]
await using (var container = File.OpenRead("huge-archive.zip.asics"))
{
    var verification = asicService.Verify(container);
    Console.WriteLine($"Valid: {verification.IsValid}");
}

// Extract straight back out to a stream
await using (var container = File.OpenRead("huge-archive.zip.asics"))
await using (var restored = File.Create("restored.zip"))
{
    var fileName = await asicService.ExtractToStreamAsync(container, restored);
    Console.WriteLine($"Extracted {fileName}");
}
```

Streaming a 64 MB payload allocates roughly 300 KB, against 128 MB+ for the `byte[]` path.

Three things to know:

- **All three require a seekable stream.** `CreateToStreamAsync` reads the payload twice, because
  the TSA must see its hash before the first byte can be written; on the read side, `ZipArchive`
  does not reject a forward-only stream — it silently buffers the whole thing, which would defeat
  the purpose. A non-seekable stream throws `ArgumentException`; the `byte[]` overloads are the
  fallback.
- **`CreateToStreamAsync` cannot add a CAdES signature** and throws `NotSupportedException` if
  `SigningCertificate` is set, since signing needs the whole payload in memory.
- **`CreateAsync(Stream, …)` is *not* one of these.** It buffers the stream into a `byte[]`
  internally; it saves you the read, not the memory. ASiC-E creation and renewal are
  `byte[]`-only.

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
    "UseNonce": true,
    "Timeout": "00:00:30",
    "MaxFileSize": 10485760
  }
}
```

#### Falling back to another TSA

A single TSA is a single point of failure. Set `TimestampAuthorityUrls` and each URL is tried in
order until one answers; the request only fails once every one of them has. The URL that actually
answered comes back on `AsicCreateResult.TimestampAuthorityUrl`, which may not be the first you
listed.

```json
{
  "AsicTimestamp": {
    "TimestampAuthorityUrls": [
      "http://timestamp.digicert.com",
      "http://timestamp.sectigo.com",
      "https://freetsa.org/tsr"
    ],
    "HashAlgorithm": "SHA256"
  }
}
```

When `TimestampAuthorityUrls` is non-empty, the singular `TimestampAuthorityUrl` is ignored.

#### All options

| Option | Default | What it does |
|---|---|---|
| `TimestampAuthorityUrl` | DigiCert | The TSA to use. Ignored when `TimestampAuthorityUrls` is set. |
| `TimestampAuthorityUrls` | *(empty)* | TSAs to try in order, falling through on failure. |
| `HashAlgorithm` | `SHA256` | Hash for timestamping. `SHA384` and `SHA512` also supported. |
| `RequestSignerCertificates` | `true` | Ask the TSA to embed its certificate chain in the token. Keep it on — without it, a token cannot be verified offline. |
| `UseNonce` | `true` | Send a random nonce and validate it in the response, so a captured token cannot be replayed as an answer to a new request. |
| `Timeout` | 30 s | HTTP timeout per TSA request. |
| `MaxFileSize` | 10 MB | Reject any single data file larger than this, on creation and per ZIP entry on read. `null` disables the limit. |
| `SigningCertificate` | `null` | When set, a detached CAdES signature (`META-INF/signature.p7s`) is added, asserting *who* vouches for the data as well as *when* it existed. |

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

Because the proof runs through the manifest, `AsicCreateResult.DataHash` is the *manifest's* hash on
this profile, not any file's. Use `FileNames` and `FileHashes` when you mean a specific file — these
are the very digests written into the manifest, and both are populated for ASiC-S too, so you never
have to branch on the profile:

```csharp
var result = await asicService.CreateExtendedAsync(files);

foreach (var name in result.FileNames!)
    Console.WriteLine($"{name}  {result.FileHashes![name]}");

Console.WriteLine($"Manifest hash (what the token covers): {result.DataHash}");
```

Both are `null` on a result from `RenewAsync`, which adds a timestamp token and touches no data file.

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

**`IsValid` is the conjunction of every step.** One failing `VerificationStep` makes the whole
container invalid, and `Error` is then the `"; "`-joined `Detail` of each failing step (`null` when
valid). `Error` is a diagnostic message, not a stable code — don't parse it. Step names, by
contrast, are contract: tests assert them and `asicts verify -v` prints them verbatim.

**Valid means unaltered, not trusted.** No `X509Chain` is built for the TSA certificate, so a
self-issued TSA still yields `IsValid == true`. The certificate is handed to you on
`TsaCertificate` precisely so that the trust decision stays yours.

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

// The data itself, without a second Extract() call — ASiC-S only, null for ASiC-E
if (result.DataBytes is not null)
    File.WriteAllBytes("recovered.pdf", result.DataBytes);
```

### What a valid ASiC-E container does *not* tell you

An ASiC-E timestamp covers the ASiCManifest, and the manifest lists one hash per data file. A ZIP
entry the manifest never references is therefore covered by no proof of existence at all — yet the
referenced files' proofs are untouched, so the container still verifies.

Those entries are reported rather than ignored:

```csharp
var result = asicService.VerifyFile("bundle.asice");

// IsValid says "nothing listed in the manifest was altered"
Console.WriteLine($"Valid: {result.IsValid}");

// ... which is not the same as "every file here was timestamped"
if (result.UnreferencedFileNames is { Count: > 0 } uncovered)
    Console.WriteLine($"Not covered by the timestamp: {string.Join(", ", uncovered)}");
```

`UnreferencedFileNames` is empty when every entry is referenced and `null` for ASiC-S, which has no
manifest. It deliberately does **not** affect `IsValid`, since third-party containers may
legitimately carry extra entries — if your policy is that every byte must be covered, enforce it on
this list. `ExtractAll` already refuses to hand back uncovered entries, so a verify-then-extract
caller cannot surface unstamped bytes as though they were timestamped.

### Errors

Everything this library throws derives from `AsicTimestampException`, so one `catch` covers all of
it:

```
AsicTimestampException
├── TimestampAuthorityException    — every configured TSA URL failed
├── InvalidAsicContainerException  — the container is unreadable or structurally wrong
└── AsicVerificationException      — a verification operation could not be completed
```

```csharp
try
{
    var result = await asicService.CreateFromFileAsync("contract.pdf");
}
catch (TimestampAuthorityException ex)
{
    // No TSA answered — retry later, or add fallbacks via TimestampAuthorityUrls
    Console.Error.WriteLine($"No timestamp authority available: {ex.Message}");
}
catch (AsicTimestampException ex)
{
    Console.Error.WriteLine($"Timestamping failed: {ex.Message}");
}
```

Note what does **not** throw:

- **`Verify` and `VerifyFile` report, they do not throw.** A corrupt ZIP, a missing entry, an
  undecodable token — all come back as `IsValid == false` with a failed step. The only exceptions
  are `ArgumentException` for empty input and `FileNotFoundException` for a missing file.
- **`GetContainerType` never throws.** Anything unrecognized is `AsicContainerType.None`.
- **Bad arguments still throw `ArgumentException`** from the create, extract and renew paths — an
  empty payload, a file name containing a path separator, or data over `MaxFileSize`.

## Standards Compliance

- **ETSI EN 319 162-1** — Associated Signature Containers (ASiC) baseline (ASiC-S)
- **ETSI EN 319 162-2** — Associated Signature Containers extended (ASiC-E)
- **ETSI TS 102 918** — ASiCManifest XML schema
- **RFC 3161** — Internet X.509 PKI Time-Stamp Protocol
- **RFC 5652** — Cryptographic Message Syntax (CMS)
- **EU eIDAS Regulation** — Electronic identification and trust services

## License

MIT — see [LICENSE](LICENSE)
