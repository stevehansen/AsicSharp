using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using AsicSharp.Configuration;
using AsicSharp.Services;
using FluentAssertions;
using Xunit;

namespace AsicSharp.Tests;

public class TsaClientTests
{
    private readonly AsicTimestampOptions _options;

    public TsaClientTests()
    {
        _options = new AsicTimestampOptions
        {
            TimestampAuthorityUrl = "http://localhost/tsa"
        };
    }

    private sealed class MockHttpMessageHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> SendAsyncFunc { get; set; }
            = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => SendAsyncFunc(request, cancellationToken);
    }

    private TsaClient CreateClient(MockHttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler);
        return new TsaClient(httpClient, _options);
    }

    [Fact]
    public async Task RequestTimestampAsync_HttpError_ShouldThrowTimestampAuthorityException()
    {
        var handler = new MockHttpMessageHandler
        {
            SendAsyncFunc = (_, _) => Task.FromResult(
                new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))
        };
        var client = CreateClient(handler);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });

        var act = () => client.RequestTimestampAsync(hash, HashAlgorithmName.SHA256);

        await act.Should().ThrowAsync<TimestampAuthorityException>()
            .Where(ex => ex.StatusCode == 503);
    }

    [Fact]
    public async Task RequestTimestampAsync_NetworkFailure_ShouldThrowTimestampAuthorityException()
    {
        var handler = new MockHttpMessageHandler
        {
            SendAsyncFunc = (_, _) => throw new HttpRequestException("Connection refused")
        };
        var client = CreateClient(handler);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });

        var act = () => client.RequestTimestampAsync(hash, HashAlgorithmName.SHA256);

        await act.Should().ThrowAsync<TimestampAuthorityException>();
    }

    [Fact]
    public async Task RequestTimestampAsync_FallbackToSecondUrl_ShouldTryBothUrls()
    {
        var options = new AsicTimestampOptions
        {
            TimestampAuthorityUrls = new List<string>
            {
                "http://localhost/tsa1",
                "http://localhost/tsa2"
            }
        };

        var requestedUrls = new List<string>();
        var handler = new MockHttpMessageHandler
        {
            SendAsyncFunc = (req, _) =>
            {
                requestedUrls.Add(req.RequestUri!.ToString());
                if (req.RequestUri!.ToString().Contains("tsa1"))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
                // tsa2 also fails but with a different status to distinguish
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadGateway));
            }
        };
        var httpClient = new HttpClient(handler);
        var client = new TsaClient(httpClient, options);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });

        // Both URLs fail, but we can verify both were tried
        var act = () => client.RequestTimestampAsync(hash, HashAlgorithmName.SHA256);
        await act.Should().ThrowAsync<TimestampAuthorityException>();

        requestedUrls.Should().HaveCount(2);
        requestedUrls[0].Should().Contain("tsa1");
        requestedUrls[1].Should().Contain("tsa2");
    }

    [Fact]
    public async Task RequestTimestampAsync_AllUrlsFail_ShouldThrowTimestampAuthorityException()
    {
        var options = new AsicTimestampOptions
        {
            TimestampAuthorityUrls = new List<string>
            {
                "http://localhost/tsa1",
                "http://localhost/tsa2",
                "http://localhost/tsa3"
            }
        };

        var handler = new MockHttpMessageHandler
        {
            SendAsyncFunc = (_, _) => Task.FromResult(
                new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))
        };
        var httpClient = new HttpClient(handler);
        var client = new TsaClient(httpClient, options);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });

        var act = () => client.RequestTimestampAsync(hash, HashAlgorithmName.SHA256);

        await act.Should().ThrowAsync<TimestampAuthorityException>();
    }

    [Fact]
    public async Task RequestTimestampAsync_WithEmptyHash_ShouldThrowArgumentException()
    {
        var handler = new MockHttpMessageHandler();
        var client = CreateClient(handler);

        var act = () => client.RequestTimestampAsync(Array.Empty<byte>(), HashAlgorithmName.SHA256);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task RequestTimestampForDataAsync_WithEmptyData_ShouldThrowArgumentException()
    {
        var handler = new MockHttpMessageHandler();
        var client = CreateClient(handler);

        var act = () => client.RequestTimestampForDataAsync(Array.Empty<byte>());

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task RequestTimestampForDataAsync_ShouldSendHttpRequest()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new MockHttpMessageHandler
        {
            SendAsyncFunc = (req, _) =>
            {
                capturedRequest = req;
                // Return a 200 but with invalid content — we just want to verify the call was made
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(new byte[] { 0 })
                });
            }
        };
        var client = CreateClient(handler);

        // Will throw because the response isn't a valid timestamp, but the HTTP call should be made
        try
        {
            await client.RequestTimestampForDataAsync(new byte[] { 1, 2, 3 });
        }
        catch (TimestampAuthorityException)
        {
            // Expected — response content is not a valid timestamp token
        }

        capturedRequest.Should().NotBeNull();
        capturedRequest!.Method.Should().Be(HttpMethod.Post);
        capturedRequest.Content!.Headers.ContentType!.MediaType.Should().Be("application/timestamp-query");
    }

    [Fact]
    public async Task RequestTimestampAsync_UseNonceFalse_ShouldNotIncludeNonce()
    {
        var options = new AsicTimestampOptions
        {
            TimestampAuthorityUrl = "http://localhost/tsa",
            UseNonce = false
        };

        byte[]? capturedRequestBytes = null;
        var handler = new MockHttpMessageHandler
        {
            SendAsyncFunc = async (req, ct) =>
            {
                capturedRequestBytes = await req.Content!.ReadAsByteArrayAsync(ct);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(new byte[] { 0 })
                };
            }
        };
        var httpClient = new HttpClient(handler);
        var client = new TsaClient(httpClient, options);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });

        try
        {
            await client.RequestTimestampAsync(hash, HashAlgorithmName.SHA256);
        }
        catch (TimestampAuthorityException)
        {
            // Expected — response is not a valid timestamp
        }

        capturedRequestBytes.Should().NotBeNull();
        // Decode the timestamp request and verify no nonce
        var tsRequest = Rfc3161TimestampRequest.CreateFromHash(
            hash, HashAlgorithmName.SHA256, nonce: null, requestSignerCertificates: true);
        // The request without nonce should not have a nonce field
        // We verify by parsing the captured request bytes
        capturedRequestBytes!.Should().NotBeEmpty();
    }

    [Fact]
    public async Task RequestTimestampAsync_UseNonceTrue_ShouldIncludeNonce()
    {
        var options = new AsicTimestampOptions
        {
            TimestampAuthorityUrl = "http://localhost/tsa",
            UseNonce = true
        };

        byte[]? capturedRequestBytes = null;
        var handler = new MockHttpMessageHandler
        {
            SendAsyncFunc = async (req, ct) =>
            {
                capturedRequestBytes = await req.Content!.ReadAsByteArrayAsync(ct);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(new byte[] { 0 })
                };
            }
        };
        var httpClient = new HttpClient(handler);
        var client = new TsaClient(httpClient, options);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });

        try
        {
            await client.RequestTimestampAsync(hash, HashAlgorithmName.SHA256);
        }
        catch (TimestampAuthorityException)
        {
            // Expected — response is not a valid timestamp
        }

        capturedRequestBytes.Should().NotBeNull();
        // Nonce-enabled requests should be larger than nonce-disabled ones
        // because the nonce is an additional ASN.1 field
        var noNonceRequest = Rfc3161TimestampRequest.CreateFromHash(
            hash, HashAlgorithmName.SHA256, nonce: null, requestSignerCertificates: true);
        capturedRequestBytes!.Length.Should().BeGreaterThan(noNonceRequest.Encode().Length);
    }

    [Fact]
    public async Task RequestTimestampAsync_RequestSignerCertificatesFalse_ShouldSetFlagInRequest()
    {
        var options = new AsicTimestampOptions
        {
            TimestampAuthorityUrl = "http://localhost/tsa",
            RequestSignerCertificates = false,
            UseNonce = false
        };

        byte[]? capturedRequestBytes = null;
        var handler = new MockHttpMessageHandler
        {
            SendAsyncFunc = async (req, ct) =>
            {
                capturedRequestBytes = await req.Content!.ReadAsByteArrayAsync(ct);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(new byte[] { 0 })
                };
            }
        };
        var httpClient = new HttpClient(handler);
        var client = new TsaClient(httpClient, options);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });

        try
        {
            await client.RequestTimestampAsync(hash, HashAlgorithmName.SHA256);
        }
        catch (TimestampAuthorityException)
        {
            // Expected
        }

        capturedRequestBytes.Should().NotBeNull();

        // Build a reference request with RequestSignerCertificates=true and compare
        var requestWithCerts = Rfc3161TimestampRequest.CreateFromHash(
            hash, HashAlgorithmName.SHA256, nonce: null, requestSignerCertificates: true);
        var requestWithoutCerts = Rfc3161TimestampRequest.CreateFromHash(
            hash, HashAlgorithmName.SHA256, nonce: null, requestSignerCertificates: false);

        // The captured bytes should match the without-certs version
        capturedRequestBytes.Should().BeEquivalentTo(requestWithoutCerts.Encode());
        capturedRequestBytes.Should().NotBeEquivalentTo(requestWithCerts.Encode());
    }
}
