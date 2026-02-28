namespace AsicSharp.Configuration;

/// <summary>
/// Well-known RFC 3161 Timestamp Authority URLs.
/// </summary>
public static class WellKnownTsa
{
    /// <summary>DigiCert Timestamp Authority (free, widely trusted).</summary>
    public const string DigiCert = "http://timestamp.digicert.com";

    /// <summary>Sectigo (formerly Comodo) Timestamp Authority.</summary>
    public const string Sectigo = "http://timestamp.sectigo.com";

    /// <summary>GlobalSign Timestamp Authority.</summary>
    public const string GlobalSign = "http://timestamp.globalsign.com/tsa/r6advanced1";

    /// <summary>FreeTSA.org — free and open timestamp service.</summary>
    public const string FreeTsa = "https://freetsa.org/tsr";

    /// <summary>Apple Timestamp Authority.</summary>
    public const string Apple = "http://timestamp.apple.com/ts01";

    /// <summary>Entrust Timestamp Authority.</summary>
    public const string Entrust = "http://timestamp.entrust.net/TSS/RFC3161sha2TS";
}
