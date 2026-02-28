using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using AsicSharp.Configuration;
using AsicSharp.Models;
using AsicSharp.Services;
using FluentAssertions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace AsicSharp.Tests;

public class AsicServiceTests
{
    private readonly ITsaClient _mockTsa;
    private readonly AsicTimestampOptions _options;
    private readonly AsicService _service;

    public AsicServiceTests()
    {
        _mockTsa = Substitute.For<ITsaClient>();
        _options = new AsicTimestampOptions();
        _service = new AsicService(_mockTsa, _options);
    }

    [Fact]
    public async Task CreateAsync_ShouldProduceValidAsicSContainer()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Hello, ASiC-S!");
        var hash = SHA256.HashData(data);
        var fakeTokenBytes = CreateFakeTimestampToken();
        var timestamp = DateTimeOffset.UtcNow;

        _mockTsa.RequestTimestampAsync(
            Arg.Any<byte[]>(),
            Arg.Any<HashAlgorithmName>(),
            Arg.Any<CancellationToken>())
            .Returns(new TimestampResult
            {
                TokenBytes = fakeTokenBytes,
                Timestamp = timestamp
            });

        // Act
        var result = await _service.CreateAsync(data, "test.txt");

        // Assert
        result.ContainerBytes.Should().NotBeNullOrEmpty();
        result.Timestamp.Should().Be(timestamp);
        result.HashAlgorithm.Should().Be("SHA256");
        result.DataHash.Should().NotBeNullOrEmpty();
        result.TimestampAuthorityUrl.Should().Be(WellKnownTsa.DigiCert);
    }

    [Fact]
    public async Task CreateAsync_ContainerShouldBeValidZip()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Test data");
        SetupMockTsa();

        // Act
        var result = await _service.CreateAsync(data, "document.txt");

        // Assert — should be a valid ZIP
        using var zip = new ZipArchive(new MemoryStream(result.ContainerBytes), ZipArchiveMode.Read);

        zip.Entries.Should().HaveCountGreaterOrEqualTo(3); // mimetype, data, timestamp

        // mimetype must be first
        zip.Entries[0].FullName.Should().Be("mimetype");

        // Check mimetype content
        using var reader = new StreamReader(zip.Entries[0].Open());
        var mimeContent = reader.ReadToEnd();
        mimeContent.Should().Be("application/vnd.etsi.asic-s+zip");

        // Data file should exist
        zip.GetEntry("document.txt").Should().NotBeNull();

        // Timestamp should exist
        zip.GetEntry("META-INF/timestamp.tst").Should().NotBeNull();
    }

    [Fact]
    public async Task CreateAsync_ShouldPreserveOriginalData()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Important contract content");
        SetupMockTsa();

        // Act
        var result = await _service.CreateAsync(data, "contract.txt");

        // Assert — extract and compare
        var (fileName, extractedData) = _service.Extract(result.ContainerBytes);
        fileName.Should().Be("contract.txt");
        extractedData.Should().BeEquivalentTo(data);
    }

    [Fact]
    public async Task CreateAsync_WithEmptyData_ShouldThrow()
    {
        var act = () => _service.CreateAsync(Array.Empty<byte>(), "empty.txt");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task CreateAsync_WithInvalidFileName_ShouldThrow()
    {
        var data = new byte[] { 1, 2, 3 };
        SetupMockTsa();

        var act = () => _service.CreateAsync(data, "path/to/file.txt");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task CreateAsync_WithMimetypeFileName_ShouldThrow()
    {
        var data = new byte[] { 1, 2, 3 };
        SetupMockTsa();

        var act = () => _service.CreateAsync(data, "mimetype");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public void Extract_WithInvalidZip_ShouldThrow()
    {
        var act = () => _service.Extract(new byte[] { 1, 2, 3 });
        act.Should().Throw<Exception>();
    }

    [Fact]
    public void Verify_WithEmptyBytes_ShouldThrow()
    {
        var act = () => _service.Verify(Array.Empty<byte>());
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Verify_WithInvalidZip_ShouldReturnInvalid()
    {
        var result = _service.Verify(new byte[] { 0x50, 0x4B, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
        result.IsValid.Should().BeFalse();
    }

    private void SetupMockTsa()
    {
        _mockTsa.RequestTimestampAsync(
            Arg.Any<byte[]>(),
            Arg.Any<HashAlgorithmName>(),
            Arg.Any<CancellationToken>())
            .Returns(new TimestampResult
            {
                TokenBytes = CreateFakeTimestampToken(),
                Timestamp = DateTimeOffset.UtcNow
            });
    }

    /// <summary>
    /// Creates a minimal fake token for container structure tests.
    /// Real timestamp verification tests need integration tests with an actual TSA.
    /// </summary>
    private static byte[] CreateFakeTimestampToken()
    {
        // This is a minimal DER-encoded structure, not a real timestamp.
        // Real integration tests should hit an actual TSA.
        return Encoding.UTF8.GetBytes("FAKE_TIMESTAMP_TOKEN_FOR_STRUCTURE_TESTS");
    }
}
