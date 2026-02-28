using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using AsicSharp.Configuration;
using AsicSharp.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AsicSharp.Services;

/// <summary>
/// Service for creating and verifying ASiC-S (Associated Signature Containers).
/// </summary>
public interface IAsicService
{
    /// <summary>
    /// Create an ASiC-S container with an RFC 3161 timestamp for the given data.
    /// </summary>
    /// <param name="data">The data to timestamp.</param>
    /// <param name="fileName">The filename to use inside the container.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The result containing the container bytes and metadata.</returns>
    Task<AsicCreateResult> CreateAsync(
        byte[] data,
        string fileName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Create an ASiC-S container from a stream.
    /// </summary>
    Task<AsicCreateResult> CreateAsync(
        Stream data,
        string fileName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Create an ASiC-S container from a file on disk.
    /// </summary>
    Task<AsicCreateResult> CreateFromFileAsync(
        string filePath,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verify an ASiC-S container and return detailed results.
    /// </summary>
    /// <param name="containerBytes">The raw ASiC-S container bytes.</param>
    /// <returns>Verification result with details.</returns>
    AsicVerifyResult Verify(byte[] containerBytes);

    /// <summary>
    /// Verify an ASiC-S container from a file on disk.
    /// </summary>
    AsicVerifyResult VerifyFile(string filePath);

    /// <summary>
    /// Extract the original data from an ASiC-S container without verification.
    /// </summary>
    /// <param name="containerBytes">The raw ASiC-S container bytes.</param>
    /// <returns>Tuple of filename and data bytes.</returns>
    (string FileName, byte[] Data) Extract(byte[] containerBytes);

    /// <summary>
    /// Create an ASiC-E (Extended) container with an RFC 3161 timestamp for multiple files.
    /// The timestamp covers an ASiCManifest XML that references all files.
    /// </summary>
    /// <param name="files">The files to include, each as a (FileName, Data) tuple.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The result containing the container bytes and metadata.</returns>
    Task<AsicCreateResult> CreateExtendedAsync(
        IEnumerable<(string FileName, byte[] Data)> files,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Create an ASiC-E (Extended) container from files on disk.
    /// </summary>
    Task<AsicCreateResult> CreateExtendedFromFilesAsync(
        IEnumerable<string> filePaths,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Extract all data files from an ASiC container (works for both ASiC-S and ASiC-E).
    /// </summary>
    /// <param name="containerBytes">The raw ASiC container bytes.</param>
    /// <returns>List of (FileName, Data) tuples for all data files.</returns>
    IReadOnlyList<(string FileName, byte[] Data)> ExtractAll(byte[] containerBytes);
}

/// <summary>
/// Default implementation of <see cref="IAsicService"/>.
/// Creates ETSI EN 319 162 compliant ASiC-S containers.
/// </summary>
public sealed class AsicService : IAsicService
{
    private readonly ITsaClient _tsaClient;
    private readonly AsicTimestampOptions _options;
    private readonly ILogger<AsicService> _logger;

    [ActivatorUtilitiesConstructor]
    public AsicService(
        ITsaClient tsaClient,
        IOptions<AsicTimestampOptions> options,
        ILogger<AsicService>? logger = null)
    {
        _tsaClient = tsaClient ?? throw new ArgumentNullException(nameof(tsaClient));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<AsicService>.Instance;
    }

    /// <summary>
    /// Create an AsicService without DI, for standalone usage.
    /// </summary>
    public AsicService(ITsaClient tsaClient, AsicTimestampOptions options)
        : this(tsaClient, Options.Create(options), null) { }

    public async Task<AsicCreateResult> CreateAsync(
        byte[] data,
        string fileName,
        CancellationToken cancellationToken = default)
    {
        if (data == null || data.Length == 0)
            throw new ArgumentException("Data cannot be null or empty.", nameof(data));
        if (string.IsNullOrWhiteSpace(fileName))
            throw new ArgumentException("File name cannot be null or empty.", nameof(fileName));

        ValidateFileName(fileName);

        _logger.LogDebug("Creating ASiC-S container for {FileName} ({Size} bytes)", fileName, data.Length);

        // Compute hash
        var hash = ComputeHash(data, _options.HashAlgorithm);
        var hashHex = ToHexString(hash);

        // Get timestamp token from TSA
        var tsResult = await _tsaClient.RequestTimestampAsync(
            hash, _options.HashAlgorithm, cancellationToken);

        // Optionally create a CMS signature if a signing cert is configured
        byte[]? signatureBytes = null;
        if (_options.SigningCertificate != null)
        {
            signatureBytes = CreateCmsSignature(data, _options.SigningCertificate, tsResult.TokenBytes);
        }

        // Build the ASiC-S container
        var containerBytes = BuildContainer(data, fileName, tsResult.TokenBytes, signatureBytes);

        _logger.LogInformation(
            "Created ASiC-S container: {FileName}, {Size} bytes, timestamp {Timestamp:O}",
            fileName, containerBytes.Length, tsResult.Timestamp);

        return new AsicCreateResult
        {
            ContainerBytes = containerBytes,
            Timestamp = tsResult.Timestamp,
            HashAlgorithm = _options.HashAlgorithm.Name!,
            DataHash = hashHex,
            TimestampAuthorityUrl = tsResult.TimestampAuthorityUrl ?? _options.TimestampAuthorityUrl
        };
    }

    public async Task<AsicCreateResult> CreateAsync(
        Stream data,
        string fileName,
        CancellationToken cancellationToken = default)
    {
        using var ms = new MemoryStream();
        await data.CopyToAsync(ms, 81920, cancellationToken);
        return await CreateAsync(ms.ToArray(), fileName, cancellationToken);
    }

    public async Task<AsicCreateResult> CreateFromFileAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found.", filePath);

        var data = File.ReadAllBytes(filePath);
        var fileName = Path.GetFileName(filePath);
        return await CreateAsync(data, fileName, cancellationToken);
    }

    public AsicVerifyResult Verify(byte[] containerBytes)
    {
        if (containerBytes == null || containerBytes.Length == 0)
            throw new ArgumentException("Container bytes cannot be null or empty.", nameof(containerBytes));

        var steps = new List<VerificationStep>();

        try
        {
            // Step 1: Parse the ZIP
            using var zip = OpenZip(containerBytes);
            steps.Add(new VerificationStep { Name = "Container structure", Passed = true, Detail = "Valid ZIP archive" });

            // Step 2: Validate MIME type and detect container type
            var mimeEntry = zip.GetEntry(AsicConstants.MimeTypeEntryName);
            bool isExtended = false;
            if (mimeEntry != null)
            {
                var mimeContent = ReadEntry(mimeEntry).Trim();
                isExtended = mimeContent == AsicConstants.MimeTypeExtended;
                var mimeValid = mimeContent == AsicConstants.MimeType || isExtended;
                steps.Add(new VerificationStep
                {
                    Name = "MIME type",
                    Passed = mimeValid,
                    Detail = mimeValid
                        ? (isExtended ? $"{AsicConstants.MimeTypeExtended} (ASiC-E)" : AsicConstants.MimeType)
                        : $"Unexpected: {mimeContent}"
                });
            }
            else
            {
                steps.Add(new VerificationStep
                {
                    Name = "MIME type",
                    Passed = false,
                    Detail = "Missing mimetype entry"
                });
            }

            // Also detect ASiC-E by manifest presence
            var manifestEntry = zip.GetEntry(AsicConstants.AsicManifestEntryPath);
            if (manifestEntry != null)
                isExtended = true;

            if (isExtended)
                return VerifyExtended(zip, manifestEntry, steps);

            // ASiC-S verification path

            // Step 3: Find the data file
            var dataEntry = FindDataEntry(zip);
            if (dataEntry == null)
            {
                return FailResult("No data file found in container", steps);
            }

            var dataBytes = ReadEntryBytes(dataEntry);
            steps.Add(new VerificationStep
            {
                Name = "Data file",
                Passed = true,
                Detail = $"{dataEntry.FullName} ({dataBytes.Length} bytes)"
            });

            // Step 4: Find and verify timestamp
            var tsEntry = zip.GetEntry(AsicConstants.TimestampEntryPath);
            if (tsEntry == null)
            {
                // Try any .tst file in META-INF
                tsEntry = zip.Entries.FirstOrDefault(e =>
                    e.FullName.StartsWith(AsicConstants.MetaInfDir + "/", StringComparison.OrdinalIgnoreCase) &&
                    e.FullName.EndsWith(".tst", StringComparison.OrdinalIgnoreCase));
            }

            DateTimeOffset? timestamp = null;
            X509Certificate2? tsaCert = null;
            string? hashAlgorithm = null;

            if (tsEntry != null)
            {
                var tsTokenBytes = ReadEntryBytes(tsEntry);
                var tsVerification = VerifyTimestampToken(dataBytes, tsTokenBytes);

                steps.Add(new VerificationStep
                {
                    Name = "Timestamp token decode",
                    Passed = tsVerification.Decoded,
                    Detail = tsVerification.Decoded
                        ? $"Token decoded, timestamp: {tsVerification.Timestamp:O}"
                        : tsVerification.Error
                });

                if (tsVerification.Decoded)
                {
                    steps.Add(new VerificationStep
                    {
                        Name = "Timestamp signature",
                        Passed = tsVerification.SignatureValid,
                        Detail = tsVerification.SignatureValid
                            ? $"Valid, signed by: {tsVerification.TsaCertificate?.Subject}"
                            : tsVerification.Error
                    });

                    steps.Add(new VerificationStep
                    {
                        Name = "Data hash match",
                        Passed = tsVerification.HashMatches,
                        Detail = tsVerification.HashMatches
                            ? "Hash in timestamp matches data file"
                            : "Hash mismatch — data has been modified"
                    });

                    timestamp = tsVerification.Timestamp;
                    tsaCert = tsVerification.TsaCertificate;
                    hashAlgorithm = tsVerification.HashAlgorithm;
                }
            }
            else
            {
                steps.Add(new VerificationStep
                {
                    Name = "Timestamp token",
                    Passed = false,
                    Detail = "No timestamp token found in META-INF/"
                });
            }

            // Step 5: Check for optional CMS/CAdES signature
            X509Certificate2? signingCert = null;
            var sigEntry = zip.GetEntry(AsicConstants.SignatureEntryPath)
                ?? zip.Entries.FirstOrDefault(e =>
                    e.FullName.StartsWith(AsicConstants.MetaInfDir + "/", StringComparison.OrdinalIgnoreCase) &&
                    e.FullName.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase));

            if (sigEntry != null)
            {
                var sigBytes = ReadEntryBytes(sigEntry);
                var sigResult = VerifyCmsSignature(dataBytes, sigBytes);
                steps.Add(new VerificationStep
                {
                    Name = "CMS/CAdES signature",
                    Passed = sigResult.Valid,
                    Detail = sigResult.Valid
                        ? $"Valid, signed by: {sigResult.Certificate?.Subject}"
                        : sigResult.Error
                });
                signingCert = sigResult.Certificate;
            }

            // Compute data hash for the result
            var hash = ComputeHash(dataBytes, _options.HashAlgorithm);
            var hashHex = ToHexString(hash);

            bool allPassed = steps.All(s => s.Passed);

            return new AsicVerifyResult
            {
                IsValid = allPassed,
                Timestamp = timestamp,
                FileName = Path.GetFileName(dataEntry.FullName),
                DataBytes = dataBytes,
                FileNames = [Path.GetFileName(dataEntry.FullName)],
                TsaCertificate = tsaCert,
                SigningCertificate = signingCert,
                HashAlgorithm = hashAlgorithm ?? _options.HashAlgorithm.Name,
                DataHash = hashHex,
                Steps = steps,
                Error = allPassed ? null : string.Join("; ", steps.Where(s => !s.Passed).Select(s => s.Detail))
            };
        }
        catch (InvalidDataException)
        {
            return FailResult("Invalid ZIP archive", steps);
        }
        catch (Exception ex)
        {
            return FailResult($"Verification error: {ex.Message}", steps);
        }
    }

    public AsicVerifyResult VerifyFile(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("Container file not found.", filePath);

        return Verify(File.ReadAllBytes(filePath));
    }

    public (string FileName, byte[] Data) Extract(byte[] containerBytes)
    {
        using var zip = OpenZip(containerBytes);
        var dataEntry = FindDataEntry(zip)
            ?? throw new InvalidAsicContainerException("No data file found in container.");

        // Sanitize entry name to prevent path traversal (Zip Slip)
        var fileName = Path.GetFileName(dataEntry.FullName);
        if (string.IsNullOrEmpty(fileName))
            throw new InvalidAsicContainerException("Data entry has an invalid file name.");

        return (fileName, ReadEntryBytes(dataEntry));
    }

    public async Task<AsicCreateResult> CreateExtendedAsync(
        IEnumerable<(string FileName, byte[] Data)> files,
        CancellationToken cancellationToken = default)
    {
        var fileList = files?.ToList() ?? throw new ArgumentNullException(nameof(files));

        if (fileList.Count == 0)
            throw new ArgumentException("At least one file is required.", nameof(files));

        // Validate all file names
        var fileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (fileName, data) in fileList)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                throw new ArgumentException("File name cannot be null or empty.");
            if (data == null || data.Length == 0)
                throw new ArgumentException($"Data for '{fileName}' cannot be null or empty.");

            ValidateFileName(fileName);

            if (!fileNames.Add(fileName))
                throw new ArgumentException($"Duplicate file name: '{fileName}'.");
        }

        _logger.LogDebug("Creating ASiC-E container for {Count} files", fileList.Count);

        // Compute hash of each file and build manifest
        var manifestBytes = BuildAsicManifest(fileList, _options.HashAlgorithm);

        // Hash the manifest and get timestamp
        var manifestHash = ComputeHash(manifestBytes, _options.HashAlgorithm);
        var manifestHashHex = ToHexString(manifestHash);

        var tsResult = await _tsaClient.RequestTimestampAsync(
            manifestHash, _options.HashAlgorithm, cancellationToken);

        // Optionally create a CMS signature if a signing cert is configured
        byte[]? signatureBytes = null;
        if (_options.SigningCertificate != null)
        {
            signatureBytes = CreateCmsSignature(manifestBytes, _options.SigningCertificate, tsResult.TokenBytes);
        }

        // Build the ASiC-E container
        var containerBytes = BuildExtendedContainer(fileList, manifestBytes, tsResult.TokenBytes, signatureBytes);

        _logger.LogInformation(
            "Created ASiC-E container: {Count} files, {Size} bytes, timestamp {Timestamp:O}",
            fileList.Count, containerBytes.Length, tsResult.Timestamp);

        return new AsicCreateResult
        {
            ContainerBytes = containerBytes,
            Timestamp = tsResult.Timestamp,
            HashAlgorithm = _options.HashAlgorithm.Name!,
            DataHash = manifestHashHex,
            TimestampAuthorityUrl = tsResult.TimestampAuthorityUrl ?? _options.TimestampAuthorityUrl
        };
    }

    public async Task<AsicCreateResult> CreateExtendedFromFilesAsync(
        IEnumerable<string> filePaths,
        CancellationToken cancellationToken = default)
    {
        var pathList = filePaths?.ToList() ?? throw new ArgumentNullException(nameof(filePaths));
        var files = new List<(string FileName, byte[] Data)>(pathList.Count);

        foreach (var filePath in pathList)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found.", filePath);

            files.Add((Path.GetFileName(filePath), File.ReadAllBytes(filePath)));
        }

        return await CreateExtendedAsync(files, cancellationToken);
    }

    public IReadOnlyList<(string FileName, byte[] Data)> ExtractAll(byte[] containerBytes)
    {
        using var zip = OpenZip(containerBytes);
        var dataEntries = FindDataEntries(zip);

        if (dataEntries.Count == 0)
            throw new InvalidAsicContainerException("No data files found in container.");

        var result = new List<(string, byte[])>(dataEntries.Count);
        foreach (var entry in dataEntries)
        {
            // Sanitize entry name to prevent path traversal (Zip Slip)
            var fileName = Path.GetFileName(entry.FullName);
            if (string.IsNullOrEmpty(fileName))
                throw new InvalidAsicContainerException("Data entry has an invalid file name.");

            result.Add((fileName, ReadEntryBytes(entry)));
        }

        return result;
    }

    #region Private methods

    private const string ReadmeContentSimple =
        """
        This is an ASiC-S (Associated Signature Container) compliant with ETSI EN 319 162-1.

        It contains an RFC 3161 timestamp that cryptographically proves the enclosed data
        file existed at a specific point in time. The timestamp is issued by a trusted
        Timestamp Authority (TSA) and is self-verifying — no signing certificate is required.

        Container contents:
          - mimetype           : Container MIME type identifier
          - <datafile>         : The original data file
          - META-INF/timestamp.tst : The RFC 3161 timestamp token
          - META-INF/signature.p7s : CAdES signature (if present)

        To verify this container:
          CLI:           asicts verify <file>.asics
          NuGet package: https://www.nuget.org/packages/AsicSharp

        More information: https://github.com/stevehansen/AsicSharp
        """;

    private const string ReadmeContentExtended =
        """
        This is an ASiC-E (Associated Signature Container - Extended) compliant with ETSI EN 319 162-2.

        It contains multiple data files with an ASiCManifest XML listing each file's digest.
        An RFC 3161 timestamp covers the manifest, which in turn cryptographically proves all
        enclosed files existed at a specific point in time. The timestamp is issued by a trusted
        Timestamp Authority (TSA) and is self-verifying — no signing certificate is required.

        Container contents:
          - mimetype                    : Container MIME type identifier
          - <datafiles>                 : The original data files
          - META-INF/ASiCManifest.xml   : Manifest listing all data files with digests
          - META-INF/timestamp.tst      : The RFC 3161 timestamp token (covers the manifest)
          - META-INF/signature.p7s      : CAdES signature (if present)

        To verify this container:
          CLI:           asicts verify <file>.asice
          NuGet package: https://www.nuget.org/packages/AsicSharp

        More information: https://github.com/stevehansen/AsicSharp
        """;

    private static byte[] BuildContainer(
        byte[] data, string fileName, byte[] timestampToken, byte[]? signatureBytes)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            // 1. mimetype — MUST be first entry, stored uncompressed (ETSI requirement)
            var mimeEntry = zip.CreateEntry(AsicConstants.MimeTypeEntryName, CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), new UTF8Encoding(false)))
            {
                writer.Write(AsicConstants.MimeType);
            }

            // 2. The data file
            var dataEntry = zip.CreateEntry(fileName, CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
            {
                stream.Write(data, 0, data.Length);
            }

            // 3. Timestamp token in META-INF/
            var tsEntry = zip.CreateEntry(AsicConstants.TimestampEntryPath, CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
            {
                stream.Write(timestampToken, 0, timestampToken.Length);
            }

            // 4. README in META-INF/
            var readmeEntry = zip.CreateEntry(AsicConstants.ReadmeEntryPath, CompressionLevel.Optimal);
            using (var writer = new StreamWriter(readmeEntry.Open(), new UTF8Encoding(false)))
            {
                writer.Write(ReadmeContentSimple);
            }

            // 5. Optional CMS signature in META-INF/
            if (signatureBytes != null)
            {
                var sigEntry = zip.CreateEntry(AsicConstants.SignatureEntryPath, CompressionLevel.Optimal);
                using (var stream = sigEntry.Open())
                {
                    stream.Write(signatureBytes, 0, signatureBytes.Length);
                }
            }
        }

        return ms.ToArray();
    }

    private static byte[] CreateCmsSignature(
        byte[] data, X509Certificate2 signingCert, byte[] timestampToken)
    {
        var contentInfo = new ContentInfo(data);
        var signedCms = new SignedCms(contentInfo, detached: true);

        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signingCert)
        {
            DigestAlgorithm = new System.Security.Cryptography.Oid("2.16.840.1.101.3.4.2.1"), // SHA-256
            IncludeOption = X509IncludeOption.WholeChain
        };

        signedCms.ComputeSignature(signer);

        // Embed the timestamp as an unsigned attribute
        signedCms.SignerInfos[0].AddUnsignedAttribute(
            new AsnEncodedData(
                new System.Security.Cryptography.Oid("1.2.840.113549.1.9.16.2.14"),
                timestampToken));

        return signedCms.Encode();
    }

    private sealed record TimestampVerification(
        bool Decoded,
        bool SignatureValid,
        bool HashMatches,
        DateTimeOffset? Timestamp,
        X509Certificate2? TsaCertificate,
        string? HashAlgorithm,
        string? Error);

    private static TimestampVerification VerifyTimestampToken(byte[] data, byte[] tokenBytes)
    {
        if (!Rfc3161TimestampToken.TryDecode(tokenBytes, out var token, out _))
        {
            return new TimestampVerification(false, false, false, null, null, null, "Failed to decode timestamp token");
        }

        // Determine the hash algorithm from the token
        var hashAlgOid = token.TokenInfo.HashAlgorithmId;
        var hashAlgName = OidToHashAlgorithmName(hashAlgOid);

        // Hash the data with the same algorithm
        var hash = ComputeHash(data, hashAlgName);

        // Verify the timestamp signature
        X509Certificate2? tsaCert = null;
        bool signatureValid;
        try
        {
            signatureValid = token.VerifySignatureForHash(hash, hashAlgName, out tsaCert);
        }
        catch (Exception ex)
        {
            return new TimestampVerification(true, false, false, token.TokenInfo.Timestamp, null,
                hashAlgName.Name, $"Signature verification failed: {ex.Message}");
        }

        // Check if hash matches
        var tokenHash = token.TokenInfo.GetMessageHash().ToArray();
        var hashMatches = hash.SequenceEqual(tokenHash);

        return new TimestampVerification(
            Decoded: true,
            SignatureValid: signatureValid,
            HashMatches: hashMatches,
            Timestamp: token.TokenInfo.Timestamp,
            TsaCertificate: tsaCert,
            HashAlgorithm: hashAlgName.Name,
            Error: signatureValid && hashMatches ? null : "Verification failed");
    }

    private sealed record CmsVerification(bool Valid, X509Certificate2? Certificate, string? Error);

    private static CmsVerification VerifyCmsSignature(byte[] data, byte[] signatureBytes)
    {
        try
        {
            var contentInfo = new ContentInfo(data);
            var signedCms = new SignedCms(contentInfo, detached: true);
            signedCms.Decode(signatureBytes);
            signedCms.CheckSignature(verifySignatureOnly: false);

            var cert = signedCms.SignerInfos[0].Certificate;
            return new CmsVerification(true, cert, null);
        }
        catch (Exception ex)
        {
            return new CmsVerification(false, null, $"CMS signature invalid: {ex.Message}");
        }
    }

    private static ZipArchive OpenZip(byte[] bytes)
    {
        return new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
    }

    private static byte[] BuildExtendedContainer(
        List<(string FileName, byte[] Data)> files,
        byte[] manifestBytes, byte[] timestampToken, byte[]? signatureBytes)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            // 1. mimetype — MUST be first entry, stored uncompressed (ETSI requirement)
            var mimeEntry = zip.CreateEntry(AsicConstants.MimeTypeEntryName, CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), new UTF8Encoding(false)))
            {
                writer.Write(AsicConstants.MimeTypeExtended);
            }

            // 2. All data files
            foreach (var (fileName, data) in files)
            {
                var dataEntry = zip.CreateEntry(fileName, CompressionLevel.Optimal);
                using var stream = dataEntry.Open();
                stream.Write(data, 0, data.Length);
            }

            // 3. ASiCManifest.xml in META-INF/
            var manifestEntry = zip.CreateEntry(AsicConstants.AsicManifestEntryPath, CompressionLevel.Optimal);
            using (var stream = manifestEntry.Open())
            {
                stream.Write(manifestBytes, 0, manifestBytes.Length);
            }

            // 4. Timestamp token in META-INF/
            var tsEntry = zip.CreateEntry(AsicConstants.TimestampEntryPath, CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
            {
                stream.Write(timestampToken, 0, timestampToken.Length);
            }

            // 5. README in META-INF/
            var readmeEntry = zip.CreateEntry(AsicConstants.ReadmeEntryPath, CompressionLevel.Optimal);
            using (var writer = new StreamWriter(readmeEntry.Open(), new UTF8Encoding(false)))
            {
                writer.Write(ReadmeContentExtended);
            }

            // 6. Optional CMS signature in META-INF/
            if (signatureBytes != null)
            {
                var sigEntry = zip.CreateEntry(AsicConstants.SignatureEntryPath, CompressionLevel.Optimal);
                using var stream = sigEntry.Open();
                stream.Write(signatureBytes, 0, signatureBytes.Length);
            }
        }

        return ms.ToArray();
    }

    private static readonly XNamespace AsicNs = AsicConstants.AsicManifestNamespace;

    private static byte[] BuildAsicManifest(
        List<(string FileName, byte[] Data)> files, HashAlgorithmName hashAlgorithm)
    {
        var xmlUri = HashAlgorithmToXmlUri(hashAlgorithm);

        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement(AsicNs + "ASiCManifest",
                new XElement(AsicNs + "SigReference",
                    new XAttribute("URI", AsicConstants.TimestampEntryPath),
                    new XAttribute("MimeType", AsicConstants.TimestampMimeType)),
                files.Select(f =>
                {
                    var hash = ComputeHash(f.Data, hashAlgorithm);
                    return new XElement(AsicNs + "DataObjectReference",
                        new XAttribute("URI", f.FileName),
                        new XAttribute("MimeType", GetMimeType(f.FileName)),
                        new XElement(AsicNs + "DigestMethod",
                            new XAttribute("Algorithm", xmlUri)),
                        new XElement(AsicNs + "DigestValue",
                            Convert.ToBase64String(hash)));
                })));

        using var ms = new MemoryStream();
        using (var writer = new StreamWriter(ms, new UTF8Encoding(false), bufferSize: 1024, leaveOpen: true))
        {
            doc.Save(writer);
        }

        return ms.ToArray();
    }

    private AsicVerifyResult VerifyExtended(
        ZipArchive zip, ZipArchiveEntry? manifestEntry, List<VerificationStep> steps)
    {
        // Step 3: Find and parse ASiCManifest
        if (manifestEntry == null)
        {
            return FailResult("ASiC-E container missing ASiCManifest.xml", steps);
        }

        var manifestBytes = ReadEntryBytes(manifestEntry);
        steps.Add(new VerificationStep
        {
            Name = "ASiCManifest",
            Passed = true,
            Detail = $"Found ({manifestBytes.Length} bytes)"
        });

        XDocument manifestDoc;
        try
        {
            manifestDoc = XDocument.Parse(Encoding.UTF8.GetString(manifestBytes));
        }
        catch (Exception ex)
        {
            return FailResult($"Invalid ASiCManifest XML: {ex.Message}", steps);
        }

        // Step 4: Verify each file's digest against the manifest
        var dataRefs = manifestDoc.Root!
            .Elements(AsicNs + "DataObjectReference")
            .ToList();

        var fileNames = new List<string>();

        foreach (var dataRef in dataRefs)
        {
            var uri = dataRef.Attribute("URI")?.Value;
            if (uri == null)
            {
                steps.Add(new VerificationStep
                {
                    Name = "Manifest entry",
                    Passed = false,
                    Detail = "DataObjectReference missing URI attribute"
                });
                continue;
            }

            fileNames.Add(uri);

            var entry = zip.GetEntry(uri);
            if (entry == null)
            {
                steps.Add(new VerificationStep
                {
                    Name = $"Data file: {uri}",
                    Passed = false,
                    Detail = $"File '{uri}' referenced in manifest but not found in container"
                });
                continue;
            }

            var digestMethodEl = dataRef.Element(AsicNs + "DigestMethod");
            var digestValueEl = dataRef.Element(AsicNs + "DigestValue");

            if (digestMethodEl == null || digestValueEl == null)
            {
                steps.Add(new VerificationStep
                {
                    Name = $"Data file: {uri}",
                    Passed = false,
                    Detail = "Missing DigestMethod or DigestValue in manifest"
                });
                continue;
            }

            var algUri = digestMethodEl.Attribute("Algorithm")?.Value;
            var expectedDigest = digestValueEl.Value;
            var hashAlg = XmlUriToHashAlgorithmName(algUri);

            var fileBytes = ReadEntryBytes(entry);
            var actualHash = ComputeHash(fileBytes, hashAlg);
            var actualDigest = Convert.ToBase64String(actualHash);

            var digestMatch = actualDigest == expectedDigest;
            steps.Add(new VerificationStep
            {
                Name = $"Data file: {uri}",
                Passed = digestMatch,
                Detail = digestMatch
                    ? $"Digest verified ({fileBytes.Length} bytes)"
                    : "Digest mismatch — file has been modified"
            });
        }

        // Step 5: Verify timestamp covers the manifest
        var tsEntry = zip.GetEntry(AsicConstants.TimestampEntryPath)
            ?? zip.Entries.FirstOrDefault(e =>
                e.FullName.StartsWith(AsicConstants.MetaInfDir + "/", StringComparison.OrdinalIgnoreCase) &&
                e.FullName.EndsWith(".tst", StringComparison.OrdinalIgnoreCase));

        DateTimeOffset? timestamp = null;
        X509Certificate2? tsaCert = null;
        string? hashAlgorithm = null;

        if (tsEntry != null)
        {
            var tsTokenBytes = ReadEntryBytes(tsEntry);
            var tsVerification = VerifyTimestampToken(manifestBytes, tsTokenBytes);

            steps.Add(new VerificationStep
            {
                Name = "Timestamp token decode",
                Passed = tsVerification.Decoded,
                Detail = tsVerification.Decoded
                    ? $"Token decoded, timestamp: {tsVerification.Timestamp:O}"
                    : tsVerification.Error
            });

            if (tsVerification.Decoded)
            {
                steps.Add(new VerificationStep
                {
                    Name = "Timestamp signature",
                    Passed = tsVerification.SignatureValid,
                    Detail = tsVerification.SignatureValid
                        ? $"Valid, signed by: {tsVerification.TsaCertificate?.Subject}"
                        : tsVerification.Error
                });

                steps.Add(new VerificationStep
                {
                    Name = "Manifest hash match",
                    Passed = tsVerification.HashMatches,
                    Detail = tsVerification.HashMatches
                        ? "Hash in timestamp matches ASiCManifest.xml"
                        : "Hash mismatch — manifest has been modified"
                });

                timestamp = tsVerification.Timestamp;
                tsaCert = tsVerification.TsaCertificate;
                hashAlgorithm = tsVerification.HashAlgorithm;
            }
        }
        else
        {
            steps.Add(new VerificationStep
            {
                Name = "Timestamp token",
                Passed = false,
                Detail = "No timestamp token found in META-INF/"
            });
        }

        // Step 6: Check for optional CMS/CAdES signature (covers manifest)
        X509Certificate2? signingCert = null;
        var sigEntry = zip.GetEntry(AsicConstants.SignatureEntryPath)
            ?? zip.Entries.FirstOrDefault(e =>
                e.FullName.StartsWith(AsicConstants.MetaInfDir + "/", StringComparison.OrdinalIgnoreCase) &&
                e.FullName.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase));

        if (sigEntry != null)
        {
            var sigBytes = ReadEntryBytes(sigEntry);
            var sigResult = VerifyCmsSignature(manifestBytes, sigBytes);
            steps.Add(new VerificationStep
            {
                Name = "CMS/CAdES signature",
                Passed = sigResult.Valid,
                Detail = sigResult.Valid
                    ? $"Valid, signed by: {sigResult.Certificate?.Subject}"
                    : sigResult.Error
            });
            signingCert = sigResult.Certificate;
        }

        var manifestHash = ComputeHash(manifestBytes, _options.HashAlgorithm);
        var manifestHashHex = ToHexString(manifestHash);

        bool allPassed = steps.All(s => s.Passed);

        return new AsicVerifyResult
        {
            IsValid = allPassed,
            Timestamp = timestamp,
            FileName = fileNames.FirstOrDefault(),
            FileNames = fileNames,
            TsaCertificate = tsaCert,
            SigningCertificate = signingCert,
            HashAlgorithm = hashAlgorithm ?? _options.HashAlgorithm.Name,
            DataHash = manifestHashHex,
            Steps = steps,
            Error = allPassed ? null : string.Join("; ", steps.Where(s => !s.Passed).Select(s => s.Detail))
        };
    }

    private static ZipArchiveEntry? FindDataEntry(ZipArchive zip)
    {
        return zip.Entries.FirstOrDefault(e =>
            !string.Equals(e.FullName, AsicConstants.MimeTypeEntryName, StringComparison.OrdinalIgnoreCase) &&
            !e.FullName.StartsWith(AsicConstants.MetaInfDir + "/", StringComparison.OrdinalIgnoreCase) &&
            !e.FullName.StartsWith(AsicConstants.MetaInfDir + "\\", StringComparison.OrdinalIgnoreCase));
    }

    private static List<ZipArchiveEntry> FindDataEntries(ZipArchive zip)
    {
        return zip.Entries.Where(e =>
            !string.Equals(e.FullName, AsicConstants.MimeTypeEntryName, StringComparison.OrdinalIgnoreCase) &&
            !e.FullName.StartsWith(AsicConstants.MetaInfDir + "/", StringComparison.OrdinalIgnoreCase) &&
            !e.FullName.StartsWith(AsicConstants.MetaInfDir + "\\", StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private static string ReadEntry(ZipArchiveEntry entry)
    {
        using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static byte[] ReadEntryBytes(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private static byte[] ComputeHash(byte[] data, HashAlgorithmName algorithmName)
    {
        using var algorithm = CreateHashAlgorithm(algorithmName);
        return algorithm.ComputeHash(data);
    }

    private static HashAlgorithm CreateHashAlgorithm(HashAlgorithmName name)
    {
        if (name == HashAlgorithmName.SHA256) return SHA256.Create();
        if (name == HashAlgorithmName.SHA384) return SHA384.Create();
        if (name == HashAlgorithmName.SHA512) return SHA512.Create();
        if (name == HashAlgorithmName.SHA1) return SHA1.Create();
        throw new ArgumentException($"Unsupported hash algorithm: {name.Name}", nameof(name));
    }

    private static HashAlgorithmName OidToHashAlgorithmName(System.Security.Cryptography.Oid oid)
    {
        return oid.Value switch
        {
            "1.3.14.3.2.26" => HashAlgorithmName.SHA1,
            "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256 // fallback
        };
    }

    private static string ToHexString(byte[] bytes)
    {
#if NET5_0_OR_GREATER
        return Convert.ToHexString(bytes).ToLowerInvariant();
#else
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
            sb.Append(b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        return sb.ToString();
#endif
    }

    private static void ValidateFileName(string fileName)
    {
        if (fileName.Contains('/') || fileName.Contains('\\'))
            throw new ArgumentException("File name cannot contain path separators.", nameof(fileName));

        if (string.Equals(fileName, AsicConstants.MimeTypeEntryName, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("File name cannot be 'mimetype'.", nameof(fileName));

        if (fileName.StartsWith(AsicConstants.MetaInfDir, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("File name cannot start with 'META-INF'.", nameof(fileName));
    }

    private static string HashAlgorithmToXmlUri(HashAlgorithmName name)
    {
        if (name == HashAlgorithmName.SHA256) return "http://www.w3.org/2001/04/xmlenc#sha256";
        if (name == HashAlgorithmName.SHA384) return "http://www.w3.org/2001/04/xmldsig-more#sha384";
        if (name == HashAlgorithmName.SHA512) return "http://www.w3.org/2001/04/xmlenc#sha512";
        if (name == HashAlgorithmName.SHA1) return "http://www.w3.org/2000/09/xmldsig#sha1";
        throw new ArgumentException($"Unsupported hash algorithm: {name.Name}", nameof(name));
    }

    private static HashAlgorithmName XmlUriToHashAlgorithmName(string? uri) => uri switch
    {
        "http://www.w3.org/2001/04/xmlenc#sha256" => HashAlgorithmName.SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => HashAlgorithmName.SHA384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => HashAlgorithmName.SHA512,
        "http://www.w3.org/2000/09/xmldsig#sha1" => HashAlgorithmName.SHA1,
        _ => HashAlgorithmName.SHA256
    };

    private static string GetMimeType(string fileName)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        return ext switch
        {
            ".txt" => "text/plain",
            ".pdf" => "application/pdf",
            ".xml" => "application/xml",
            ".json" => "application/json",
            ".html" or ".htm" => "text/html",
            ".csv" => "text/csv",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".svg" => "image/svg+xml",
            ".zip" => "application/zip",
            ".doc" => "application/msword",
            ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls" => "application/vnd.ms-excel",
            ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            _ => "application/octet-stream"
        };
    }

    private static AsicVerifyResult FailResult(string error, List<VerificationStep> steps)
    {
        return new AsicVerifyResult
        {
            IsValid = false,
            Error = error,
            Steps = steps
        };
    }

    #endregion
}
