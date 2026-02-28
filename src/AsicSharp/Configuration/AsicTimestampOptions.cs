using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AsicSharp.Configuration;

/// <summary>
/// Configuration for the ASiC timestamp service.
/// </summary>
public class AsicTimestampOptions
{
    /// <summary>
    /// The section name used in configuration binding (e.g., appsettings.json).
    /// </summary>
    public const string SectionName = "AsicTimestamp";

    /// <summary>
    /// The URL of the RFC 3161 Timestamp Authority.
    /// Defaults to DigiCert's free TSA.
    /// When <see cref="TimestampAuthorityUrls"/> is non-empty, this property is ignored.
    /// </summary>
    public string TimestampAuthorityUrl { get; set; } = WellKnownTsa.DigiCert;

    /// <summary>
    /// Optional list of TSA URLs to try in order. If the first TSA is unavailable,
    /// the next one is tried automatically. When empty, <see cref="TimestampAuthorityUrl"/>
    /// is used as a single-item list.
    /// </summary>
    public IList<string> TimestampAuthorityUrls { get; set; } = new List<string>();

    /// <summary>
    /// The hash algorithm to use for timestamping. Defaults to SHA-256.
    /// </summary>
    public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

    /// <summary>
    /// Whether to request the TSA's signer certificate chain in the response.
    /// Recommended for offline verification. Defaults to true.
    /// </summary>
    public bool RequestSignerCertificates { get; set; } = true;

    /// <summary>
    /// Optional nonce policy. When true, a random nonce is included in the request
    /// and validated in the response. Provides replay protection. Defaults to true.
    /// </summary>
    public bool UseNonce { get; set; } = true;

    /// <summary>
    /// HTTP request timeout for TSA requests. Defaults to 30 seconds.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Maximum allowed size (in bytes) for a single data file. Prevents accidental memory
    /// exhaustion. Set to <c>null</c> to disable the limit. Defaults to 10 MB.
    /// </summary>
    public long? MaxFileSize { get; set; } = 10 * 1024 * 1024;

    /// <summary>
    /// Optional signing certificate for creating signed ASiC containers (ASiC with CAdES signature).
    /// When null, only timestamp-based containers are created.
    /// </summary>
    public X509Certificate2? SigningCertificate { get; set; }
}
