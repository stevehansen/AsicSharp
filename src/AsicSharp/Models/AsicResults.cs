using System.Security.Cryptography.X509Certificates;

namespace AsicSharp.Models;

/// <summary>
/// Result of creating an ASiC-S container.
/// </summary>
public sealed class AsicCreateResult
{
    /// <summary>The raw bytes of the ASiC-S container (.asics ZIP).</summary>
    public required byte[] ContainerBytes { get; init; }

    /// <summary>The UTC timestamp from the TSA.</summary>
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>The hash algorithm used.</summary>
    public required string HashAlgorithm { get; init; }

    /// <summary>The hex-encoded hash of the original data.</summary>
    public required string DataHash { get; init; }

    /// <summary>The TSA URL that issued the timestamp.</summary>
    public required string TimestampAuthorityUrl { get; init; }
}

/// <summary>
/// Result of verifying an ASiC-S container.
/// </summary>
public sealed class AsicVerifyResult
{
    /// <summary>Whether the timestamp and data integrity are valid.</summary>
    public required bool IsValid { get; init; }

    /// <summary>The UTC timestamp from the TSA, if successfully decoded.</summary>
    public DateTimeOffset? Timestamp { get; init; }

    /// <summary>The name of the data file inside the container (first/only file for ASiC-S).</summary>
    public string? FileName { get; init; }

    /// <summary>The raw data bytes extracted from the container (first/only file for ASiC-S).</summary>
    public byte[]? DataBytes { get; init; }

    /// <summary>All data file names inside the container (populated for both ASiC-S and ASiC-E).</summary>
    public IReadOnlyList<string>? FileNames { get; init; }

    /// <summary>The TSA certificate that signed the timestamp, if available.</summary>
    public X509Certificate2? TsaCertificate { get; init; }

    /// <summary>The signing certificate, if the container includes a CMS/CAdES signature.</summary>
    public X509Certificate2? SigningCertificate { get; init; }

    /// <summary>Hash algorithm used in the timestamp.</summary>
    public string? HashAlgorithm { get; init; }

    /// <summary>Hex-encoded hash of the data file.</summary>
    public string? DataHash { get; init; }

    /// <summary>Error message if verification failed.</summary>
    public string? Error { get; init; }

    /// <summary>Detailed verification steps performed.</summary>
    public IReadOnlyList<VerificationStep> Steps { get; init; } = [];

    /// <summary>
    /// Timestamp chain entries when the container has been renewed (2+ timestamps).
    /// Null for single-timestamp containers (backward compatible).
    /// </summary>
    public IReadOnlyList<TimestampChainEntry>? TimestampChain { get; init; }
}

/// <summary>
/// A single entry in a timestamp renewal chain.
/// </summary>
public sealed class TimestampChainEntry
{
    /// <summary>ZIP entry path (e.g., META-INF/timestamp.tst or META-INF/timestamp-002.tst).</summary>
    public required string EntryName { get; init; }

    /// <summary>UTC timestamp from this token.</summary>
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>TSA certificate that signed this token, if available.</summary>
    public X509Certificate2? TsaCertificate { get; init; }

    /// <summary>Hash algorithm used in this token.</summary>
    public string? HashAlgorithm { get; init; }

    /// <summary>Whether this link in the chain verified successfully.</summary>
    public required bool IsValid { get; init; }

    /// <summary>Position in the chain (1 = original timestamp).</summary>
    public required int Order { get; init; }
}

/// <summary>
/// A single step in the verification process, for audit/diagnostics.
/// </summary>
public sealed class VerificationStep
{
    public required string Name { get; init; }
    public required bool Passed { get; init; }
    public string? Detail { get; init; }
}
