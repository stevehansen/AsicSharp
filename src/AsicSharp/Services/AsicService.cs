using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
            TimestampAuthorityUrl = _options.TimestampAuthorityUrl
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

            // Step 2: Validate ASiC-S structure
            var mimeEntry = zip.GetEntry(AsicConstants.MimeTypeEntryName);
            if (mimeEntry != null)
            {
                var mimeContent = ReadEntry(mimeEntry).Trim();
                var mimeValid = mimeContent == AsicConstants.MimeType;
                steps.Add(new VerificationStep
                {
                    Name = "MIME type",
                    Passed = mimeValid,
                    Detail = mimeValid ? AsicConstants.MimeType : $"Unexpected: {mimeContent}"
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

    #region Private methods

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

            // 4. Optional CMS signature in META-INF/
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

    private static ZipArchiveEntry? FindDataEntry(ZipArchive zip)
    {
        return zip.Entries.FirstOrDefault(e =>
            !string.Equals(e.FullName, AsicConstants.MimeTypeEntryName, StringComparison.OrdinalIgnoreCase) &&
            !e.FullName.StartsWith(AsicConstants.MetaInfDir + "/", StringComparison.OrdinalIgnoreCase) &&
            !e.FullName.StartsWith(AsicConstants.MetaInfDir + "\\", StringComparison.OrdinalIgnoreCase));
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
