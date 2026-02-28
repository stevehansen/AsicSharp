namespace AsicSharp.Services;

/// <summary>
/// Constants for ASiC-S container format per ETSI EN 319 162.
/// </summary>
internal static class AsicConstants
{
    /// <summary>MIME type for ASiC-S containers.</summary>
    public const string MimeType = "application/vnd.etsi.asic-s+zip";

    /// <summary>File extension for ASiC-S containers.</summary>
    public const string Extension = ".asics";

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

    /// <summary>Manifest file (optional, for ASiC-E).</summary>
    public const string ManifestEntryPath = MetaInfDir + "/manifest.xml";
}
