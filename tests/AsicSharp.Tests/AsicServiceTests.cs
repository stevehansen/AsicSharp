using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using AsicSharp;
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

        zip.Entries.Should().HaveCountGreaterOrEqualTo(4); // mimetype, data, timestamp, README.txt

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
    public async Task CreateAsync_ContainerShouldContainReadme()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Test data");
        SetupMockTsa();

        // Act
        var result = await _service.CreateAsync(data, "document.txt");

        // Assert
        using var zip = new ZipArchive(new MemoryStream(result.ContainerBytes), ZipArchiveMode.Read);

        var readmeEntry = zip.GetEntry("META-INF/README.txt");
        readmeEntry.Should().NotBeNull();

        using var reader = new StreamReader(readmeEntry!.Open());
        var content = reader.ReadToEnd();
        content.Should().Contain("ASiC-S");
        content.Should().Contain("ETSI EN 319 162-1");
        content.Should().Contain("RFC 3161");
        content.Should().Contain("asicts verify");
        content.Should().Contain("https://github.com/stevehansen/AsicSharp");
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
    public void Extract_WithPathTraversal_ShouldReturnSanitizedFileName()
    {
        // Arrange — craft a malicious container with path traversal in the entry name
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), Encoding.UTF8))
                writer.Write("application/vnd.etsi.asic-s+zip");

            // Malicious entry with path traversal
            var dataEntry = zip.CreateEntry("../../../evil.txt", CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("malicious content"));

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        var containerBytes = ms.ToArray();

        // Act
        var (fileName, _) = _service.Extract(containerBytes);

        // Assert — path traversal stripped, only the base filename remains
        fileName.Should().Be("evil.txt");
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

    [Fact]
    public async Task CreateAsync_ExceedingMaxFileSize_ShouldThrow()
    {
        var data = new byte[10 * 1024 * 1024 + 1]; // 10 MB + 1 byte
        SetupMockTsa();

        var act = () => _service.CreateAsync(data, "large.bin");
        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*exceeds the maximum allowed size*");
    }

    [Fact]
    public async Task CreateAsync_WithMaxFileSizeDisabled_ShouldNotThrow()
    {
        var options = new AsicTimestampOptions { MaxFileSize = null };
        var service = new AsicService(_mockTsa, options);
        var data = new byte[11 * 1024 * 1024]; // 11 MB
        data[0] = 1; // ensure non-empty

        _mockTsa.RequestTimestampAsync(
            Arg.Any<byte[]>(),
            Arg.Any<HashAlgorithmName>(),
            Arg.Any<CancellationToken>())
            .Returns(new TimestampResult
            {
                TokenBytes = CreateFakeTimestampToken(),
                Timestamp = DateTimeOffset.UtcNow
            });

        var act = () => service.CreateAsync(data, "large.bin");
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task CreateExtendedAsync_ExceedingMaxFileSize_ShouldThrow()
    {
        var files = new List<(string FileName, byte[] Data)>
        {
            ("small.txt", new byte[] { 1, 2, 3 }),
            ("large.bin", new byte[10 * 1024 * 1024 + 1]) // 10 MB + 1 byte
        };
        SetupMockTsa();

        var act = () => _service.CreateExtendedAsync(files);
        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*exceeds the maximum allowed size*");
    }

    [Fact]
    public void Extract_ExceedingMaxFileSize_ShouldThrow()
    {
        // Build a container with a data entry that exceeds MaxFileSize
        var options = new AsicTimestampOptions { MaxFileSize = 5 };
        var service = new AsicService(_mockTsa, options);

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), Encoding.UTF8))
                writer.Write("application/vnd.etsi.asic-s+zip");

            var dataEntry = zip.CreateEntry("test.txt", CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("this content exceeds 5 bytes"));

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        var act = () => service.Extract(ms.ToArray());
        act.Should().Throw<InvalidAsicContainerException>().WithMessage("*exceeds the maximum allowed size*");
    }

    [Fact]
    public void Verify_ExceedingMaxFileSize_ShouldReturnInvalid()
    {
        // Build a container with a data entry that exceeds MaxFileSize
        var options = new AsicTimestampOptions { MaxFileSize = 5 };
        var service = new AsicService(_mockTsa, options);

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), Encoding.UTF8))
                writer.Write("application/vnd.etsi.asic-s+zip");

            var dataEntry = zip.CreateEntry("test.txt", CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("this content exceeds 5 bytes"));

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        // Verify catches the exception and returns a failed result
        var result = service.Verify(ms.ToArray());
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("exceeds the maximum allowed size");
    }

    [Fact]
    public void ExtractAll_ExceedingMaxFileSize_ShouldThrow()
    {
        // Build an ASiC-E-style container with an oversized entry
        var options = new AsicTimestampOptions { MaxFileSize = 5 };
        var service = new AsicService(_mockTsa, options);

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), Encoding.UTF8))
                writer.Write("application/vnd.etsi.asic-s+zip");

            var dataEntry = zip.CreateEntry("large.txt", CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("this content exceeds 5 bytes"));

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        var act = () => service.ExtractAll(ms.ToArray());
        act.Should().Throw<InvalidAsicContainerException>().WithMessage("*exceeds the maximum allowed size*");
    }

    #region Timestamp Renewal Tests

    [Fact]
    public async Task RenewAsync_ShouldAddArchiveTimestampToContainer()
    {
        // Arrange — create a container first
        var data = Encoding.UTF8.GetBytes("Hello, renewal!");
        SetupMockTsa();
        var createResult = await _service.CreateAsync(data, "test.txt");

        // Act
        var renewResult = await _service.RenewAsync(createResult.ContainerBytes);

        // Assert — both timestamp files should exist
        using var zip = new ZipArchive(new MemoryStream(renewResult.ContainerBytes), ZipArchiveMode.Read);
        zip.GetEntry("META-INF/timestamp.tst").Should().NotBeNull();
        zip.GetEntry("META-INF/timestamp-002.tst").Should().NotBeNull();
        renewResult.Timestamp.Should().NotBe(default);
        renewResult.DataHash.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task RenewAsync_ShouldPreserveOriginalContainerContents()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Preserved content");
        SetupMockTsa();
        var createResult = await _service.CreateAsync(data, "document.txt");

        // Act
        var renewResult = await _service.RenewAsync(createResult.ContainerBytes);

        // Assert — data file should be unchanged
        var (fileName, extractedData) = _service.Extract(renewResult.ContainerBytes);
        fileName.Should().Be("document.txt");
        extractedData.Should().BeEquivalentTo(data);
    }

    [Fact]
    public async Task RenewAsync_MultipleRenewals_ShouldIncrementEntryNames()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Multiple renewals");
        SetupMockTsa();
        var createResult = await _service.CreateAsync(data, "test.txt");

        // Act — renew 3 times
        var renew1 = await _service.RenewAsync(createResult.ContainerBytes);
        var renew2 = await _service.RenewAsync(renew1.ContainerBytes);
        var renew3 = await _service.RenewAsync(renew2.ContainerBytes);

        // Assert — all 4 timestamps should exist with correct names
        using var zip = new ZipArchive(new MemoryStream(renew3.ContainerBytes), ZipArchiveMode.Read);
        zip.GetEntry("META-INF/timestamp.tst").Should().NotBeNull();
        zip.GetEntry("META-INF/timestamp-002.tst").Should().NotBeNull();
        zip.GetEntry("META-INF/timestamp-003.tst").Should().NotBeNull();
        zip.GetEntry("META-INF/timestamp-004.tst").Should().NotBeNull();
    }

    [Fact]
    public async Task RenewAsync_WithEmptyBytes_ShouldThrow()
    {
        var act = () => _service.RenewAsync(Array.Empty<byte>());
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task RenewAsync_WithNoTimestamp_ShouldThrow()
    {
        // Build a container without a timestamp
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), Encoding.UTF8))
                writer.Write("application/vnd.etsi.asic-s+zip");

            var dataEntry = zip.CreateEntry("test.txt", CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("no timestamp"));
        }

        var act = () => _service.RenewAsync(ms.ToArray());
        await act.Should().ThrowAsync<InvalidAsicContainerException>();
    }

    [Fact]
    public async Task RenewAsync_Stream_ShouldWork()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Stream renewal");
        SetupMockTsa();
        var createResult = await _service.CreateAsync(data, "test.txt");

        // Act
        using var stream = new MemoryStream(createResult.ContainerBytes);
        var renewResult = await _service.RenewAsync(stream);

        // Assert
        using var zip = new ZipArchive(new MemoryStream(renewResult.ContainerBytes), ZipArchiveMode.Read);
        zip.GetEntry("META-INF/timestamp.tst").Should().NotBeNull();
        zip.GetEntry("META-INF/timestamp-002.tst").Should().NotBeNull();
    }

    [Fact]
    public async Task RenewAsync_PreservesMimetypeFirst()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Mimetype ordering");
        SetupMockTsa();
        var createResult = await _service.CreateAsync(data, "test.txt");

        // Act
        var renewResult = await _service.RenewAsync(createResult.ContainerBytes);

        // Assert — mimetype should still be the first entry
        using var zip = new ZipArchive(new MemoryStream(renewResult.ContainerBytes), ZipArchiveMode.Read);
        zip.Entries[0].FullName.Should().Be("mimetype");
    }

    [Fact]
    public async Task Verify_SingleTimestamp_TimestampChainShouldBeNull()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Single timestamp");
        SetupMockTsa();
        var createResult = await _service.CreateAsync(data, "test.txt");

        // Act
        var result = _service.Verify(createResult.ContainerBytes);

        // Assert — no chain for single-timestamp containers
        result.TimestampChain.Should().BeNull();
    }

    #endregion

    #region ASiC-E (Extended) Tests

    [Fact]
    public async Task CreateExtendedAsync_ShouldProduceValidAsicEContainer()
    {
        // Arrange
        var files = new List<(string FileName, byte[] Data)>
        {
            ("file1.pdf", Encoding.UTF8.GetBytes("PDF content")),
            ("file2.txt", Encoding.UTF8.GetBytes("Text content"))
        };
        SetupMockTsa();

        // Act
        var result = await _service.CreateExtendedAsync(files);

        // Assert
        result.ContainerBytes.Should().NotBeNullOrEmpty();
        result.HashAlgorithm.Should().Be("SHA256");
        result.DataHash.Should().NotBeNullOrEmpty();

        using var zip = new ZipArchive(new MemoryStream(result.ContainerBytes), ZipArchiveMode.Read);

        // mimetype must be first and ASiC-E
        zip.Entries[0].FullName.Should().Be("mimetype");
        using var reader = new StreamReader(zip.Entries[0].Open());
        reader.ReadToEnd().Should().Be("application/vnd.etsi.asic-e+zip");

        // Data files should exist
        zip.GetEntry("file1.pdf").Should().NotBeNull();
        zip.GetEntry("file2.txt").Should().NotBeNull();

        // Manifest and timestamp should exist
        zip.GetEntry("META-INF/ASiCManifest.xml").Should().NotBeNull();
        zip.GetEntry("META-INF/timestamp.tst").Should().NotBeNull();
        zip.GetEntry("META-INF/README.txt").Should().NotBeNull();
    }

    [Fact]
    public async Task CreateExtendedAsync_ContainerShouldContainManifest()
    {
        // Arrange
        var files = new List<(string FileName, byte[] Data)>
        {
            ("file1.pdf", Encoding.UTF8.GetBytes("PDF content")),
            ("file2.txt", Encoding.UTF8.GetBytes("Text content"))
        };
        SetupMockTsa();

        // Act
        var result = await _service.CreateExtendedAsync(files);

        // Assert
        using var zip = new ZipArchive(new MemoryStream(result.ContainerBytes), ZipArchiveMode.Read);
        var manifestEntry = zip.GetEntry("META-INF/ASiCManifest.xml");
        manifestEntry.Should().NotBeNull();

        using var stream = manifestEntry!.Open();
        var doc = XDocument.Load(stream);

        // Verify namespace
        XNamespace ns = "http://uri.etsi.org/02918/v1.2.1#";
        doc.Root!.Name.Should().Be(ns + "ASiCManifest");

        // Verify SigReference
        var sigRef = doc.Root.Element(ns + "SigReference");
        sigRef.Should().NotBeNull();
        sigRef!.Attribute("URI")!.Value.Should().Be("META-INF/timestamp.tst");
        sigRef.Attribute("MimeType")!.Value.Should().Be("application/vnd.etsi.timestamp-token");

        // Verify DataObjectReferences
        var dataRefs = doc.Root.Elements(ns + "DataObjectReference").ToList();
        dataRefs.Should().HaveCount(2);

        dataRefs[0].Attribute("URI")!.Value.Should().Be("file1.pdf");
        dataRefs[0].Attribute("MimeType")!.Value.Should().Be("application/pdf");
        dataRefs[0].Element(ns + "DigestMethod")!.Attribute("Algorithm")!.Value
            .Should().Be("http://www.w3.org/2001/04/xmlenc#sha256");
        dataRefs[0].Element(ns + "DigestValue")!.Value.Should().NotBeNullOrEmpty();

        dataRefs[1].Attribute("URI")!.Value.Should().Be("file2.txt");
        dataRefs[1].Attribute("MimeType")!.Value.Should().Be("text/plain");
    }

    [Fact]
    public async Task CreateExtendedAsync_ShouldPreserveAllData()
    {
        // Arrange
        var file1Data = Encoding.UTF8.GetBytes("First file content");
        var file2Data = Encoding.UTF8.GetBytes("Second file content");
        var files = new List<(string FileName, byte[] Data)>
        {
            ("first.txt", file1Data),
            ("second.txt", file2Data)
        };
        SetupMockTsa();

        // Act
        var result = await _service.CreateExtendedAsync(files);

        // Assert — extract all and compare
        var extracted = _service.ExtractAll(result.ContainerBytes);
        extracted.Should().HaveCount(2);
        extracted[0].FileName.Should().Be("first.txt");
        extracted[0].Data.Should().BeEquivalentTo(file1Data);
        extracted[1].FileName.Should().Be("second.txt");
        extracted[1].Data.Should().BeEquivalentTo(file2Data);
    }

    [Fact]
    public async Task CreateExtendedAsync_WithDuplicateFileNames_ShouldThrow()
    {
        var files = new List<(string FileName, byte[] Data)>
        {
            ("file.txt", new byte[] { 1 }),
            ("file.txt", new byte[] { 2 })
        };
        SetupMockTsa();

        var act = () => _service.CreateExtendedAsync(files);
        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*Duplicate*");
    }

    [Fact]
    public async Task CreateExtendedAsync_WithEmptyFileList_ShouldThrow()
    {
        var files = new List<(string FileName, byte[] Data)>();

        var act = () => _service.CreateExtendedAsync(files);
        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*At least one file*");
    }

    [Fact]
    public async Task CreateExtendedAsync_ManifestDigestsShouldMatchFileContent()
    {
        // Arrange
        var file1Data = Encoding.UTF8.GetBytes("Content 1");
        var file2Data = Encoding.UTF8.GetBytes("Content 2");
        var files = new List<(string FileName, byte[] Data)>
        {
            ("a.txt", file1Data),
            ("b.pdf", file2Data)
        };
        SetupMockTsa();

        // Act
        var result = await _service.CreateExtendedAsync(files);

        // Assert — verify manifest digests match actual file hashes
        using var zip = new ZipArchive(new MemoryStream(result.ContainerBytes), ZipArchiveMode.Read);
        var manifestEntry = zip.GetEntry("META-INF/ASiCManifest.xml")!;
        using var stream = manifestEntry.Open();
        var doc = XDocument.Load(stream);

        XNamespace ns = "http://uri.etsi.org/02918/v1.2.1#";
        var dataRefs = doc.Root!.Elements(ns + "DataObjectReference").ToList();

        var expectedHash1 = Convert.ToBase64String(SHA256.HashData(file1Data));
        var expectedHash2 = Convert.ToBase64String(SHA256.HashData(file2Data));

        dataRefs[0].Element(ns + "DigestValue")!.Value.Should().Be(expectedHash1);
        dataRefs[1].Element(ns + "DigestValue")!.Value.Should().Be(expectedHash2);
    }

    [Fact]
    public async Task Verify_AsicEContainer_ShouldDetectContainerType()
    {
        // Arrange — build a minimal ASiC-E container
        var files = new List<(string FileName, byte[] Data)>
        {
            ("doc.txt", Encoding.UTF8.GetBytes("Hello"))
        };
        SetupMockTsa();

        var createResult = await _service.CreateExtendedAsync(files);

        // Act
        var verifyResult = _service.Verify(createResult.ContainerBytes);

        // Assert — should detect as ASiC-E (MIME type step reflects it)
        var mimeStep = verifyResult.Steps.FirstOrDefault(s => s.Name == "MIME type");
        mimeStep.Should().NotBeNull();
        mimeStep!.Detail.Should().Contain("ASiC-E");
        verifyResult.FileNames.Should().Contain("doc.txt");
    }

    [Fact]
    public void ExtractAll_ShouldReturnAllFiles_ForAsicS()
    {
        // Arrange — build a simple ASiC-S container manually
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), Encoding.UTF8))
                writer.Write("application/vnd.etsi.asic-s+zip");

            var dataEntry = zip.CreateEntry("test.txt", CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("test content"));

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        // Act
        var result = _service.ExtractAll(ms.ToArray());

        // Assert
        result.Should().HaveCount(1);
        result[0].FileName.Should().Be("test.txt");
    }

    [Fact]
    public async Task ExtractAll_ShouldReturnAllFiles_ForAsicE()
    {
        // Arrange
        var file1Data = Encoding.UTF8.GetBytes("File 1");
        var file2Data = Encoding.UTF8.GetBytes("File 2");
        var file3Data = Encoding.UTF8.GetBytes("File 3");
        var files = new List<(string FileName, byte[] Data)>
        {
            ("one.txt", file1Data),
            ("two.pdf", file2Data),
            ("three.json", file3Data)
        };
        SetupMockTsa();

        var createResult = await _service.CreateExtendedAsync(files);

        // Act
        var extracted = _service.ExtractAll(createResult.ContainerBytes);

        // Assert
        extracted.Should().HaveCount(3);
        extracted.Select(e => e.FileName).Should().BeEquivalentTo(["one.txt", "two.pdf", "three.json"]);
        extracted[0].Data.Should().BeEquivalentTo(file1Data);
        extracted[1].Data.Should().BeEquivalentTo(file2Data);
        extracted[2].Data.Should().BeEquivalentTo(file3Data);
    }

    #endregion

    #region Stream and file-based creation

    [Fact]
    public async Task CreateAsync_StreamOverload_ShouldProduceValidContainer()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("Stream data");
        SetupMockTsa();

        // Act
        using var stream = new MemoryStream(data);
        var result = await _service.CreateAsync(stream, "stream-test.txt");

        // Assert
        result.ContainerBytes.Should().NotBeNullOrEmpty();
        var (fileName, extractedData) = _service.Extract(result.ContainerBytes);
        fileName.Should().Be("stream-test.txt");
        extractedData.Should().BeEquivalentTo(data);
    }

    [Fact]
    public async Task CreateAsync_WithNullData_ShouldThrow()
    {
        var act = () => _service.CreateAsync((byte[])null!, "test.txt");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task CreateAsync_WithNullFileName_ShouldThrow()
    {
        var act = () => _service.CreateAsync(new byte[] { 1 }, null!);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task CreateFromFileAsync_HappyPath_ShouldCreateContainer()
    {
        // Arrange
        SetupMockTsa();
        var tempFile = Path.GetTempFileName();
        try
        {
            var data = Encoding.UTF8.GetBytes("File content for testing");
            File.WriteAllBytes(tempFile, data);

            // Act
            var result = await _service.CreateFromFileAsync(tempFile);

            // Assert
            result.ContainerBytes.Should().NotBeNullOrEmpty();
            var (_, extractedData) = _service.Extract(result.ContainerBytes);
            extractedData.Should().BeEquivalentTo(data);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task CreateFromFileAsync_MissingFile_ShouldThrowFileNotFoundException()
    {
        var act = () => _service.CreateFromFileAsync("/nonexistent/path/ghost.txt");
        await act.Should().ThrowAsync<FileNotFoundException>();
    }

    [Fact]
    public async Task CreateExtendedFromFilesAsync_MissingFile_ShouldThrowFileNotFoundException()
    {
        string[] paths = ["/nonexistent/ghost.pdf"];
        var act = () => _service.CreateExtendedFromFilesAsync(paths);
        await act.Should().ThrowAsync<FileNotFoundException>();
    }

    #endregion

    #region VerifyFile and RenewFile

    [Fact]
    public async Task VerifyFile_HappyPath_ShouldReturnResult()
    {
        // Arrange
        SetupMockTsa();
        var data = Encoding.UTF8.GetBytes("Verify file content");
        var createResult = await _service.CreateAsync(data, "doc.txt");
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, createResult.ContainerBytes);

            // Act
            var result = _service.VerifyFile(tempFile);

            // Assert
            result.Steps.Should().NotBeEmpty();
            result.FileName.Should().Be("doc.txt");
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void VerifyFile_MissingFile_ShouldThrowFileNotFoundException()
    {
        var act = () => _service.VerifyFile("/nonexistent/container.asics");
        act.Should().Throw<FileNotFoundException>();
    }

    [Fact]
    public async Task RenewFileAsync_HappyPath_ShouldReturnResult()
    {
        // Arrange
        SetupMockTsa();
        var data = Encoding.UTF8.GetBytes("Renew file content");
        var createResult = await _service.CreateAsync(data, "doc.txt");
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, createResult.ContainerBytes);

            // Act
            var result = await _service.RenewFileAsync(tempFile);

            // Assert
            result.ContainerBytes.Should().NotBeNullOrEmpty();
            result.Timestamp.Should().NotBe(default);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task RenewFileAsync_MissingFile_ShouldThrowFileNotFoundException()
    {
        var act = () => _service.RenewFileAsync("/nonexistent/container.asics");
        await act.Should().ThrowAsync<FileNotFoundException>();
    }

    #endregion

    #region Verification edge cases

    [Fact]
    public void Verify_MissingMimetypeEntry_ShouldReturnFailedMimeStep()
    {
        // Build a ZIP without a mimetype entry
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var dataEntry = zip.CreateEntry("test.txt", CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("some data"));

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        var result = _service.Verify(ms.ToArray());

        var mimeStep = result.Steps.FirstOrDefault(s => s.Name == "MIME type");
        mimeStep.Should().NotBeNull();
        mimeStep!.Passed.Should().BeFalse();
        mimeStep.Detail.Should().Contain("Missing");
    }

    [Fact]
    public void Verify_WrongMimetypeContent_ShouldReturnFailedMimeStep()
    {
        // Build a ZIP with wrong mimetype content
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), Encoding.UTF8))
                writer.Write("application/zip");

            var dataEntry = zip.CreateEntry("test.txt", CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("some data"));

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        var result = _service.Verify(ms.ToArray());

        var mimeStep = result.Steps.FirstOrDefault(s => s.Name == "MIME type");
        mimeStep.Should().NotBeNull();
        mimeStep!.Passed.Should().BeFalse();
        mimeStep.Detail.Should().Contain("Unexpected");
    }

    [Fact]
    public void Verify_NoDataFile_ShouldReturnInvalid()
    {
        // Build a container with mimetype and timestamp but no data file
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), Encoding.UTF8))
                writer.Write("application/vnd.etsi.asic-s+zip");

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        var result = _service.Verify(ms.ToArray());

        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("No data file");
    }

    [Fact]
    public async Task Verify_RenewedContainer_TimestampChainShouldBePopulated()
    {
        // Arrange — create and renew
        var data = Encoding.UTF8.GetBytes("Chain test");
        SetupMockTsa();
        var createResult = await _service.CreateAsync(data, "test.txt");
        var renewResult = await _service.RenewAsync(createResult.ContainerBytes);

        // Act
        var verifyResult = _service.Verify(renewResult.ContainerBytes);

        // Assert
        verifyResult.TimestampChain.Should().NotBeNull();
        verifyResult.TimestampChain.Should().HaveCount(2);
        verifyResult.TimestampChain![0].Order.Should().Be(1);
        verifyResult.TimestampChain[1].Order.Should().Be(2);
    }

    #endregion

    #region ASiC-E verification edge cases

    [Fact]
    public async Task Verify_AsicE_TamperedDataFile_ShouldFailDigestStep()
    {
        // Arrange — create a valid ASiC-E then tamper with a data file
        var files = new List<(string FileName, byte[] Data)>
        {
            ("file1.txt", Encoding.UTF8.GetBytes("Original content"))
        };
        SetupMockTsa();
        var createResult = await _service.CreateExtendedAsync(files);

        var tamperedBytes = TamperDataFileInContainer(createResult.ContainerBytes, "file1.txt", "Tampered content");

        // Act
        var result = _service.Verify(tamperedBytes);

        // Assert
        result.IsValid.Should().BeFalse();
        var digestStep = result.Steps.FirstOrDefault(s => s.Name.Contains("file1.txt"));
        digestStep.Should().NotBeNull();
        digestStep!.Passed.Should().BeFalse();
        digestStep.Detail.Should().Contain("mismatch");
    }

    [Fact]
    public void Verify_AsicE_MissingManifest_ShouldReturnInvalid()
    {
        // Build an ASiC-E container (by mimetype) but without an ASiCManifest.xml
        var noBom = new UTF8Encoding(false);
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), noBom))
                writer.Write("application/vnd.etsi.asic-e+zip");

            var dataEntry = zip.CreateEntry("doc.txt", CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("some data"));

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        var result = _service.Verify(ms.ToArray());

        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("ASiCManifest");
    }

    [Fact]
    public void Verify_AsicE_MalformedManifestXml_ShouldReturnInvalid()
    {
        // Build an ASiC-E container with invalid XML in the manifest
        var noBom = new UTF8Encoding(false);
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), noBom))
                writer.Write("application/vnd.etsi.asic-e+zip");

            var dataEntry = zip.CreateEntry("doc.txt", CompressionLevel.Optimal);
            using (var stream = dataEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("some data"));

            var manifestEntry = zip.CreateEntry("META-INF/ASiCManifest.xml", CompressionLevel.Optimal);
            using (var writer = new StreamWriter(manifestEntry.Open(), noBom))
                writer.Write("<<< not valid XML >>>");

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        var result = _service.Verify(ms.ToArray());

        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("Invalid ASiCManifest XML");
    }

    [Fact]
    public void Verify_AsicE_MissingReferencedFile_ShouldReturnInvalid()
    {
        // Build an ASiC-E container with a manifest that references a non-existent file
        var ns = "http://uri.etsi.org/02918/v1.2.1#";
        var manifestXml = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<ASiCManifest xmlns=""{ns}"">
  <SigReference URI=""META-INF/timestamp.tst"" MimeType=""application/vnd.etsi.timestamp-token"" />
  <DataObjectReference URI=""ghost.pdf"" MimeType=""application/pdf"">
    <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
    <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
  </DataObjectReference>
</ASiCManifest>";
        var noBom = new UTF8Encoding(false);

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using (var writer = new StreamWriter(mimeEntry.Open(), noBom))
                writer.Write("application/vnd.etsi.asic-e+zip");

            var manifestEntry = zip.CreateEntry("META-INF/ASiCManifest.xml", CompressionLevel.Optimal);
            using (var writer = new StreamWriter(manifestEntry.Open(), noBom))
                writer.Write(manifestXml);

            var tsEntry = zip.CreateEntry("META-INF/timestamp.tst", CompressionLevel.Optimal);
            using (var stream = tsEntry.Open())
                stream.Write(Encoding.UTF8.GetBytes("FAKE_TOKEN"));
        }

        var result = _service.Verify(ms.ToArray());

        result.IsValid.Should().BeFalse();
        var ghostStep = result.Steps.FirstOrDefault(s => s.Detail != null && s.Detail.Contains("ghost.pdf"));
        ghostStep.Should().NotBeNull();
        ghostStep!.Passed.Should().BeFalse();
        ghostStep.Detail.Should().Contain("not found in container");
    }

    #endregion

    #region GetContainerType

    [Fact]
    public async Task GetContainerType_AsicSContainer_ShouldReturnSimple()
    {
        var data = Encoding.UTF8.GetBytes("Simple container");
        SetupMockTsa();
        var result = await _service.CreateAsync(data, "test.txt");

        _service.GetContainerType(result.ContainerBytes).Should().Be(AsicContainerType.Simple);
    }

    [Fact]
    public async Task GetContainerType_AsicEContainer_ShouldReturnExtended()
    {
        var files = new List<(string FileName, byte[] Data)>
        {
            ("doc.txt", Encoding.UTF8.GetBytes("Extended container"))
        };
        SetupMockTsa();
        var result = await _service.CreateExtendedAsync(files);

        _service.GetContainerType(result.ContainerBytes).Should().Be(AsicContainerType.Extended);
    }

    [Fact]
    public void GetContainerType_RandomBytes_ShouldReturnNone()
    {
        _service.GetContainerType(new byte[] { 1, 2, 3, 4, 5 }).Should().Be(AsicContainerType.None);
    }

    [Fact]
    public void GetContainerType_EmptyBytes_ShouldReturnNone()
    {
        _service.GetContainerType(Array.Empty<byte>()).Should().Be(AsicContainerType.None);
    }

    [Fact]
    public void GetContainerType_NullBytes_ShouldReturnNone()
    {
        _service.GetContainerType(null!).Should().Be(AsicContainerType.None);
    }

    [Fact]
    public void GetContainerType_ZipWithUnknownMimetype_ShouldReturnNone()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var mimeEntry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
            using var writer = new StreamWriter(mimeEntry.Open(), Encoding.UTF8);
            writer.Write("application/zip");
        }

        _service.GetContainerType(ms.ToArray()).Should().Be(AsicContainerType.None);
    }

    [Fact]
    public void GetContainerType_ZipWithManifestButNoMimetype_ShouldReturnExtended()
    {
        // Fallback detection: ASiCManifest.xml present without proper mimetype
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var manifestEntry = zip.CreateEntry("META-INF/ASiCManifest.xml", CompressionLevel.Optimal);
            using var writer = new StreamWriter(manifestEntry.Open(), Encoding.UTF8);
            writer.Write("<ASiCManifest/>");
        }

        _service.GetContainerType(ms.ToArray()).Should().Be(AsicContainerType.Extended);
    }

    #endregion

    #region ValidateFileName

    [Fact]
    public async Task CreateAsync_WithMetaInfPrefixedFileName_ShouldSucceed()
    {
        // A file literally named "META-INFSummary.pdf" should be allowed
        // since it doesn't contain path separators
        var data = new byte[] { 1, 2, 3 };
        SetupMockTsa();

        var result = await _service.CreateAsync(data, "META-INFSummary.pdf");
        result.ContainerBytes.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task CreateAsync_WithMetaInfExactName_ShouldThrow()
    {
        var data = new byte[] { 1, 2, 3 };
        SetupMockTsa();

        var act = () => _service.CreateAsync(data, "META-INF");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    #endregion

    #region CreateExtendedFromFilesAsync + Extract on ASiC-E

    [Fact]
    public async Task CreateExtendedFromFilesAsync_HappyPath_ShouldCreateContainer()
    {
        SetupMockTsa();
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        try
        {
            var file1 = Path.Combine(tempDir, "a.txt");
            var file2 = Path.Combine(tempDir, "b.pdf");
            File.WriteAllText(file1, "File A content");
            File.WriteAllBytes(file2, new byte[] { 1, 2, 3 });

            // Act
            var result = await _service.CreateExtendedFromFilesAsync(new[] { file1, file2 });

            // Assert
            result.ContainerBytes.Should().NotBeNullOrEmpty();
            var extracted = _service.ExtractAll(result.ContainerBytes);
            extracted.Should().HaveCount(2);
            extracted.Select(e => e.FileName).Should().BeEquivalentTo(["a.txt", "b.pdf"]);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Extract_OnAsicEContainer_ShouldReturnFirstDataFile()
    {
        // Arrange
        var files = new List<(string FileName, byte[] Data)>
        {
            ("first.txt", Encoding.UTF8.GetBytes("First")),
            ("second.txt", Encoding.UTF8.GetBytes("Second"))
        };
        SetupMockTsa();
        var result = await _service.CreateExtendedAsync(files);

        // Act — Extract returns only the first data file for ASiC-E
        var (fileName, data) = _service.Extract(result.ContainerBytes);

        // Assert
        fileName.Should().Be("first.txt");
        data.Should().BeEquivalentTo(Encoding.UTF8.GetBytes("First"));
    }

    [Fact]
    public async Task RenewAsync_OnAsicEContainer_ShouldAddArchiveTimestamp()
    {
        // Arrange
        var files = new List<(string FileName, byte[] Data)>
        {
            ("doc.txt", Encoding.UTF8.GetBytes("Extended renewal"))
        };
        SetupMockTsa();
        var createResult = await _service.CreateExtendedAsync(files);

        // Act
        var renewResult = await _service.RenewAsync(createResult.ContainerBytes);

        // Assert
        using var zip = new ZipArchive(new MemoryStream(renewResult.ContainerBytes), ZipArchiveMode.Read);
        zip.GetEntry("META-INF/timestamp.tst").Should().NotBeNull();
        zip.GetEntry("META-INF/timestamp-002.tst").Should().NotBeNull();
    }

    #endregion

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

    private static byte[] TamperDataFileInContainer(byte[] containerBytes, string fileName, string newContent)
    {
        using var inputMs = new MemoryStream(containerBytes);
        using var inputZip = new ZipArchive(inputMs, ZipArchiveMode.Read);

        using var outputMs = new MemoryStream();
        using (var outputZip = new ZipArchive(outputMs, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in inputZip.Entries)
            {
                var newEntry = outputZip.CreateEntry(entry.FullName,
                    entry.FullName == "mimetype" ? CompressionLevel.NoCompression : CompressionLevel.Optimal);

                using var entryStream = newEntry.Open();
                if (entry.FullName == fileName)
                {
                    // Replace with tampered content
                    entryStream.Write(Encoding.UTF8.GetBytes(newContent));
                }
                else
                {
                    using var originalStream = entry.Open();
                    originalStream.CopyTo(entryStream);
                }
            }
        }

        return outputMs.ToArray();
    }
}
