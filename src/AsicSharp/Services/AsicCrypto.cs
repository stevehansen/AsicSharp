using System.Security.Cryptography;
using System.Text;

namespace AsicSharp.Services;

/// <summary>
/// Shared cryptographic helpers used by <see cref="TsaClient"/> and <see cref="AsicService"/>.
/// </summary>
internal static class AsicCrypto
{
    public static byte[] ComputeHash(byte[] data, HashAlgorithmName algorithmName)
    {
        using var algorithm = CreateHashAlgorithm(algorithmName);
        return algorithm.ComputeHash(data);
    }

    public static HashAlgorithm CreateHashAlgorithm(HashAlgorithmName name)
    {
        if (name == HashAlgorithmName.SHA256) return SHA256.Create();
        if (name == HashAlgorithmName.SHA384) return SHA384.Create();
        if (name == HashAlgorithmName.SHA512) return SHA512.Create();
        if (name == HashAlgorithmName.SHA1) return SHA1.Create();
        throw new ArgumentException($"Unsupported hash algorithm: {name.Name}", nameof(name));
    }

    public static string ToHexString(byte[] bytes)
    {
#if NET5_0_OR_GREATER
        return Convert.ToHexString(bytes).ToLowerInvariant();
#else
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
            sb.Append(b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        return sb.ToString();
#endif
    }
}
