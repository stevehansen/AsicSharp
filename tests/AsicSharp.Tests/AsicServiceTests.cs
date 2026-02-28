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
