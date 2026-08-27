using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using AsicSharp.Configuration;
using AsicSharp.Models;
using AsicSharp.Services;
using AwesomeAssertions;
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
    private static readonly string[] ChainAfterTwoRenewals =
    [
        "META-INF/timestamp.tst",
        "META-INF/timestamp-002.tst",
        "META-INF/timestamp-003.tst"
    ];

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
    public async Task AsicService_RenewTwice_ChainShouldVerifyAndKeepTheOriginalInstant()
    {
        // The only test that exercises real chain-link cryptography: unit tests use a non-DER
        // placeholder token, so token decoding and hash linkage never run there.
        var data = Encoding.UTF8.GetBytes("Long-term archival document. Created at " + DateTime.UtcNow);

        var createResult = await _asicService.CreateAsync(data, "archive.txt");
        var renew1 = await _asicService.RenewAsync(createResult.ContainerBytes);
        var renew2 = await _asicService.RenewAsync(renew1.ContainerBytes);

        var verifyResult = _asicService.Verify(renew2.ContainerBytes);

        verifyResult.IsValid.Should().BeTrue(because: verifyResult.Error ?? "no error");
        verifyResult.Timestamp.Should().Be(
            createResult.Timestamp,
            because: "renewal extends a proof of existence, it never moves the original instant forward");

        verifyResult.TimestampChain.Should().NotBeNull();
        verifyResult.TimestampChain!.Select(e => e.EntryName).Should().Equal(ChainAfterTwoRenewals);
        verifyResult.TimestampChain.Should().OnlyContain(link => link.IsValid);
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

    [Fact]
    public async Task AsicService_AsicE_UnreferencedZipEntry_IsReportedButDoesNotInvalidate()
    {
        var createResult = await _asicService.CreateExtendedAsync(
            [("doc.txt", Encoding.UTF8.GetBytes("Covered by the manifest"))]);

        // Smuggle in a data entry without touching the ASiCManifest.
        byte[] tampered;
        using (var ms = new MemoryStream())
        {
            ms.Write(createResult.ContainerBytes, 0, createResult.ContainerBytes.Length);
            using (var zip = new System.IO.Compression.ZipArchive(
                ms, System.IO.Compression.ZipArchiveMode.Update, leaveOpen: true))
            {
                var entry = zip.CreateEntry("injected.txt");
                using var stream = entry.Open();
                stream.Write(Encoding.UTF8.GetBytes("Never timestamped"));
            }

            tampered = ms.ToArray();
        }

        var result = _asicService.Verify(tampered);

        // The referenced file's proof of existence is untouched, so the verdict stands.
        result.IsValid.Should().BeTrue();
        result.Error.Should().BeNull();

        // The uncovered entry is still reported, both as a property and as a passing step.
        result.UnreferencedFileNames.Should().BeEquivalentTo(["injected.txt"]);
        var step = result.Steps.Single(s => s.Name == "Manifest completeness");
        step.Passed.Should().BeTrue();
        step.Detail.Should().Contain("injected.txt");

        // Extraction hands back only what the manifest covers.
        _asicService.ExtractAll(tampered).Select(e => e.FileName)
            .Should().BeEquivalentTo(["doc.txt"]);
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}
