using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using AsicSharp.Configuration;
using AsicSharp.Models;
using AsicSharp.Services;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace AsicSharp.Tests;

/// <summary>
/// Integration tests that hit real TSA servers.
/// These require network access and are skipped in CI by default.
/// Run with: dotnet test --filter "Category=Integration"
/// </summary>
[Trait("Category", "Integration")]
public class IntegrationTests : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly AsicTimestampOptions _options;
    private readonly TsaClient _tsaClient;
    private readonly AsicService _asicService;

    public IntegrationTests()
    {
        _httpClient = new HttpClient();
        _options = new AsicTimestampOptions
        {
            TimestampAuthorityUrl = WellKnownTsa.DigiCert,
            HashAlgorithm = HashAlgorithmName.SHA256,
            RequestSignerCertificates = true
        };
        _tsaClient = new TsaClient(_httpClient, _options);
        _asicService = new AsicService(_tsaClient, _options);
    }

    [Fact]
    public async Task TsaClient_ShouldGetTimestampFromDigiCert()
    {
        var data = Encoding.UTF8.GetBytes("Hello, DigiCert TSA!");
        var hash = SHA256.HashData(data);

        var result = await _tsaClient.RequestTimestampAsync(hash, HashAlgorithmName.SHA256);

        result.Should().NotBeNull();
        result.TokenBytes.Should().NotBeNullOrEmpty();
        result.Timestamp.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
    }

    [Fact]
    public async Task AsicService_RoundTrip_CreateAndVerify()
    {
        var data = Encoding.UTF8.GetBytes("This is a legally important document. Created at " + DateTime.UtcNow);

        // Create
        var createResult = await _asicService.CreateAsync(data, "document.txt");

        createResult.ContainerBytes.Should().NotBeNullOrEmpty();
        createResult.Timestamp.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
        createResult.HashAlgorithm.Should().Be("SHA256");

        // Verify
        var verifyResult = _asicService.Verify(createResult.ContainerBytes);

        verifyResult.IsValid.Should().BeTrue(because: verifyResult.Error ?? "no error");
        verifyResult.Timestamp.Should().Be(createResult.Timestamp);
        verifyResult.FileName.Should().Be("document.txt");
        verifyResult.DataBytes.Should().BeEquivalentTo(data);
        verifyResult.TsaCertificate.Should().NotBeNull();
        verifyResult.TsaCertificate!.Subject.Should().Contain("DigiCert");
    }

    [Fact]
    public async Task AsicService_TamperedData_ShouldFailVerification()
    {
        var data = Encoding.UTF8.GetBytes("Original content");
        var createResult = await _asicService.CreateAsync(data, "original.txt");

        // Tamper: modify the data inside the container
        var tampered = TamperWithDataInContainer(createResult.ContainerBytes);

        var verifyResult = _asicService.Verify(tampered);

        // Either hash mismatch or signature verification should fail
        verifyResult.Steps.Should().Contain(s => !s.Passed);
    }

    [Fact]
    public async Task AsicService_BinaryData_ShouldWork()
    {
        // Create random binary data
        var data = new byte[1024];
        Random.Shared.NextBytes(data);

        var createResult = await _asicService.CreateAsync(data, "random.bin");
        var verifyResult = _asicService.Verify(createResult.ContainerBytes);

        verifyResult.IsValid.Should().BeTrue();
        verifyResult.DataBytes.Should().BeEquivalentTo(data);
    }

    [Fact]
    public async Task AsicService_Extract_ShouldReturnOriginalData()
    {
        var data = Encoding.UTF8.GetBytes("Extract me!");

        var createResult = await _asicService.CreateAsync(data, "extract-test.txt");
        var (fileName, extractedData) = _asicService.Extract(createResult.ContainerBytes);

        fileName.Should().Be("extract-test.txt");
        extractedData.Should().BeEquivalentTo(data);
    }

    private static byte[] TamperWithDataInContainer(byte[] containerBytes)
    {
        using var inputMs = new MemoryStream(containerBytes);
        using var inputZip = new System.IO.Compression.ZipArchive(inputMs, System.IO.Compression.ZipArchiveMode.Read);

        using var outputMs = new MemoryStream();
        using (var outputZip = new System.IO.Compression.ZipArchive(outputMs, System.IO.Compression.ZipArchiveMode.Create))
        {
            foreach (var entry in inputZip.Entries)
            {
                var newEntry = outputZip.CreateEntry(entry.FullName);
                using var inputStream = entry.Open();
                using var outputStream = newEntry.Open();

                if (entry.FullName != "mimetype" &&
                    !entry.FullName.StartsWith("META-INF/", StringComparison.Ordinal))
                {
                    // Tamper with the data file
                    outputStream.Write(Encoding.UTF8.GetBytes("TAMPERED CONTENT"));
                }
                else
                {
                    inputStream.CopyTo(outputStream);
                }
            }
        }

        return outputMs.ToArray();
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}
