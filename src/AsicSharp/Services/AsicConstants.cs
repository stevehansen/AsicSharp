namespace AsicSharp.Services;

/// <summary>
/// Constants for ASiC container formats per ETSI EN 319 162.
/// </summary>
internal static class AsicConstants
{
    /// <summary>MIME type for ASiC-S containers.</summary>
    public const string MimeType = "application/vnd.etsi.asic-s+zip";

    /// <summary>MIME type for ASiC-E containers.</summary>
    public const string MimeTypeExtended = "application/vnd.etsi.asic-e+zip";

    /// <summary>File extension for ASiC-S containers.</summary>
    public const string Extension = ".asics";

    /// <summary>File extension for ASiC-E containers.</summary>
    public const string ExtensionExtended = ".asice";

    /// <summary>The name of the mimetype entry (must be first in ZIP).</summary>
    public const string MimeTypeEntryName = "mimetype";

    /// <summary>The META-INF directory name.</summary>
    public const string MetaInfDir = "META-INF";

    /// <summary>Default timestamp token filename.</summary>
    public const string TimestampFileName = "timestamp.tst";

    /// <summary>Default CAdES signature filename.</summary>
    public const string SignatureFileName = "signature.p7s";

    /// <summary>Full path for the timestamp token inside the container.</summary>
    public const string TimestampEntryPath = MetaInfDir + "/" + TimestampFileName;

    /// <summary>Full path for the CAdES signature inside the container.</summary>
    public const string SignatureEntryPath = MetaInfDir + "/" + SignatureFileName;

    /// <summary>Full path for the README inside the container.</summary>
    public const string ReadmeEntryPath = MetaInfDir + "/README.txt";

    /// <summary>ASiCManifest filename.</summary>
    public const string AsicManifestFileName = "ASiCManifest.xml";

    /// <summary>Full path for the ASiCManifest inside the container.</summary>
    public const string AsicManifestEntryPath = MetaInfDir + "/" + AsicManifestFileName;

    /// <summary>ETSI TS 102 918 namespace for ASiCManifest.</summary>
    public const string AsicManifestNamespace = "http://uri.etsi.org/02918/v1.2.1#";

    /// <summary>MIME type for timestamp tokens.</summary>
    public const string TimestampMimeType = "application/vnd.etsi.timestamp-token";

    /// <summary>Prefix for archive (renewal) timestamp filenames (e.g., timestamp-002.tst).</summary>
    public const string ArchiveTimestampPrefix = "timestamp-";

    /// <summary>File extension for timestamp tokens.</summary>
    public const string TimestampExtension = ".tst";
}
