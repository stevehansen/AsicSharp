namespace AsicSharp;

/// <summary>
/// Base exception for ASiC timestamp operations.
/// </summary>
public class AsicTimestampException : Exception
{
    public AsicTimestampException(string message) : base(message) { }
    public AsicTimestampException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when the Timestamp Authority returns an error or unexpected response.
/// </summary>
public class TimestampAuthorityException : AsicTimestampException
{
    public int? StatusCode { get; }

    public TimestampAuthorityException(string message, int? statusCode = null)
        : base(message)
    {
        StatusCode = statusCode;
    }

    public TimestampAuthorityException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Thrown when an ASiC container has invalid structure.
/// </summary>
public class InvalidAsicContainerException : AsicTimestampException
{
    public InvalidAsicContainerException(string message) : base(message) { }
}

/// <summary>
/// Thrown when timestamp or signature verification fails.
/// </summary>
public class AsicVerificationException : AsicTimestampException
{
    public AsicVerificationException(string message) : base(message) { }
}
