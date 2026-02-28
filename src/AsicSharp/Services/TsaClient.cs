using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using AsicSharp.Configuration;
using AsicSharp.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AsicSharp.Services;

/// <summary>
/// Client for requesting RFC 3161 timestamps from a Timestamp Authority.
/// </summary>
public interface ITsaClient
{
    /// <summary>
    /// Request a timestamp for the given data hash.
    /// </summary>
    /// <param name="hash">The hash of the data to timestamp.</param>
    /// <param name="hashAlgorithm">The hash algorithm used (must match the hash bytes).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The timestamp result containing the token and timestamp.</returns>
    Task<TimestampResult> RequestTimestampAsync(
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Request a timestamp for the given data (hashes it internally).
    /// </summary>
    /// <param name="data">The raw data to timestamp.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The timestamp result containing the token and timestamp.</returns>
    Task<TimestampResult> RequestTimestampForDataAsync(
        byte[] data,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Default implementation of <see cref="ITsaClient"/> using HttpClient.
/// Designed for use with typed HttpClient via DI.
/// </summary>
public sealed class TsaClient : ITsaClient
{
    private readonly HttpClient _httpClient;
    private readonly AsicTimestampOptions _options;
    private readonly ILogger<TsaClient> _logger;

    [ActivatorUtilitiesConstructor]
    public TsaClient(
        HttpClient httpClient,
        IOptions<AsicTimestampOptions> options,
        ILogger<TsaClient>? logger = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<TsaClient>.Instance;
    }

    /// <summary>
    /// Create a TsaClient without DI, for standalone usage.
    /// </summary>
    public TsaClient(HttpClient httpClient, AsicTimestampOptions options)
        : this(httpClient, Options.Create(options), null) { }

    public async Task<TimestampResult> RequestTimestampForDataAsync(
        byte[] data,
        CancellationToken cancellationToken = default)
    {
        if (data == null || data.Length == 0)
            throw new ArgumentException("Data cannot be null or empty.", nameof(data));

        var hash = ComputeHash(data, _options.HashAlgorithm);
        return await RequestTimestampAsync(hash, _options.HashAlgorithm, cancellationToken);
    }

    public async Task<TimestampResult> RequestTimestampAsync(
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default)
    {
        if (hash == null || hash.Length == 0)
            throw new ArgumentException("Hash cannot be null or empty.", nameof(hash));

        // Build effective URL list: TimestampAuthorityUrls if non-empty, else single TimestampAuthorityUrl
        var tsaUrls = _options.TimestampAuthorityUrls is { Count: > 0 }
            ? _options.TimestampAuthorityUrls
            : new[] { _options.TimestampAuthorityUrl };

        Exception? lastException = null;

        foreach (var tsaUrl in tsaUrls)
        {
            try
            {
                return await RequestTimestampFromUrlAsync(hash, hashAlgorithm, tsaUrl, cancellationToken);
            }
            catch (HttpRequestException ex)
            {
                _logger.LogWarning("TSA {TsaUrl} failed: {Message}. Trying next TSA...", tsaUrl, ex.Message);
                lastException = ex;
            }
            catch (TimestampAuthorityException ex)
            {
                _logger.LogWarning("TSA {TsaUrl} failed: {Message}. Trying next TSA...", tsaUrl, ex.Message);
                lastException = ex;
            }
        }

        // All URLs failed — throw the last exception
        throw lastException is TimestampAuthorityException
            ? lastException
            : new TimestampAuthorityException(
                $"All TSA URLs failed. Last error: {lastException?.Message}", lastException!);
    }

    private async Task<TimestampResult> RequestTimestampFromUrlAsync(
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        string tsaUrl,
        CancellationToken cancellationToken)
    {
        _logger.LogDebug("Requesting timestamp from {TsaUrl} using {Algorithm}",
            tsaUrl, hashAlgorithm.Name);

        // Build the RFC 3161 timestamp request
        ReadOnlyMemory<byte>? nonce = null;
        if (_options.UseNonce)
        {
            var nonceBytes = new byte[8];
            RandomNumberGenerator.Fill(nonceBytes);
            nonce = nonceBytes;
        }

        var tsRequest = Rfc3161TimestampRequest.CreateFromHash(
            hash,
            hashAlgorithm,
            nonce: nonce,
            requestSignerCertificates: _options.RequestSignerCertificates);

        var requestBytes = tsRequest.Encode();

        // Send to TSA
        using var content = new ByteArrayContent(requestBytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.PostAsync(tsaUrl, content, cancellationToken);
        }
        catch (HttpRequestException ex)
        {
            throw new TimestampAuthorityException(
                $"Failed to connect to TSA at {tsaUrl}: {ex.Message}", ex);
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new TimestampAuthorityException(
                $"TSA at {tsaUrl} returned HTTP {(int)response.StatusCode} ({response.StatusCode})",
                (int)response.StatusCode);
        }

        var responseBytes = await ReadResponseBytesAsync(response, cancellationToken);

        // Parse and validate the response
        Rfc3161TimestampToken token;
        try
        {
            token = tsRequest.ProcessResponse(responseBytes, out _);
        }
        catch (CryptographicException ex)
        {
            throw new TimestampAuthorityException(
                $"TSA at {tsaUrl} returned invalid response: {ex.Message}", ex);
        }

        _logger.LogInformation("Timestamp received: {Timestamp:O} from {TsaUrl}",
            token.TokenInfo.Timestamp, tsaUrl);

        // Extract TSA certificate if present
        X509Certificate2? tsaCert = null;
        try
        {
            token.VerifySignatureForHash(hash, hashAlgorithm, out tsaCert);
        }
        catch
        {
            // Verification is done separately; we just want the cert here
        }

        return new TimestampResult
        {
            TokenBytes = token.AsSignedCms().Encode(),
            Timestamp = token.TokenInfo.Timestamp,
            TsaCertificate = tsaCert,
            TimestampAuthorityUrl = tsaUrl
        };
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

    private static async Task<byte[]> ReadResponseBytesAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
#if NET8_0_OR_GREATER
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
#else
        return await response.Content.ReadAsByteArrayAsync();
#endif
    }
}
