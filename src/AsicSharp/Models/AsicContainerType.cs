namespace AsicSharp.Models;

/// <summary>
/// The type of an ASiC container.
/// </summary>
public enum AsicContainerType
{
    /// <summary>Not a recognized ASiC container.</summary>
    None,

    /// <summary>ASiC-S (Simple) — single data file with a timestamp or signature.</summary>
    Simple,

    /// <summary>ASiC-E (Extended) — multiple data files with an ASiCManifest.</summary>
    Extended
}
