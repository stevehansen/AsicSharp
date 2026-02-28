using System.Security.Cryptography.X509Certificates;

namespace AsicSharp.Models;

/// <summary>
/// Result of an RFC 3161 timestamp request.
/// </summary>
public sealed class TimestampResult
{
    /// <summary>The raw DER-encoded timestamp token bytes.</summary>
    public required byte[] TokenBytes { get; init; }

    /// <summary>The UTC timestamp from the TSA.</summary>
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>The TSA's signing certificate, if included in the response.</summary>
    public X509Certificate2? TsaCertificate { get; init; }
}
