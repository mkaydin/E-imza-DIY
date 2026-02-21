using System.Security.Cryptography;
using SigningService.Crypto;

namespace SigningService.Raw;

/// <summary>
/// Service for signing raw binary data.
/// Uses SHA-256 for hashing and delegates signing to the ISigner implementation.
/// </summary>
public class RawSigningService
{
    private readonly ISigner _signer;
    private readonly HashAlgorithmName _hashAlgorithm;

    /// <summary>
    /// Initializes a new instance with the specified signer.
    /// </summary>
    /// <param name="signer">The signer implementation to use.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use (default: SHA-256).</param>
    public RawSigningService(ISigner signer, HashAlgorithmName? hashAlgorithm = null)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _hashAlgorithm = hashAlgorithm ?? HashAlgorithmName.SHA256;
    }

    /// <summary>
    /// Signs the specified data by first hashing it, then signing the hash.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <returns>A DigitalSignature containing the signature and metadata.</returns>
    /// <exception cref="ArgumentNullException">Thrown when data is null.</exception>
    public DigitalSignature SignData(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        // Step 1: Hash the data
        byte[] hash = HashData(data);

        // Step 2: Sign the hash
        byte[] signature = _signer.Sign(hash);

        return new DigitalSignature
        {
            Signature = signature,
            Hash = hash,
            HashAlgorithm = _hashAlgorithm.Name,
            Timestamp = DateTimeOffset.UtcNow
        };
    }

    /// <summary>
    /// Verifies a signature against the original data.
    /// </summary>
    /// <param name="data">The original data.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public bool VerifySignature(byte[] data, byte[] signature)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (signature == null)
            throw new ArgumentNullException(nameof(signature));

        // Re-hash the data and verify
        byte[] hash = HashData(data);
        return _signer.Verify(hash, signature);
    }

    /// <summary>
    /// Verifies a DigitalSignature against the original data.
    /// </summary>
    /// <param name="data">The original data.</param>
    /// <param name="digitalSignature">The digital signature to verify.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public bool VerifySignature(byte[] data, DigitalSignature digitalSignature)
    {
        if (digitalSignature == null)
            throw new ArgumentNullException(nameof(digitalSignature));

        // Verify the hash matches first (optional validation)
        byte[] computedHash = HashData(data);
        if (!computedHash.SequenceEqual(digitalSignature.Hash))
            return false;

        return _signer.Verify(digitalSignature.Hash, digitalSignature.Signature);
    }

    /// <summary>
    /// Computes the hash of the specified data using the configured hash algorithm.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The hash value.</returns>
    private byte[] HashData(byte[] data)
    {
        using var hasher = CryptographyHelper.CreateHashAlgorithm(_hashAlgorithm);
        return hasher.ComputeHash(data);
    }

    /// <summary>
    /// Computes the hash of the specified data stream.
    /// </summary>
    /// <param name="stream">The stream containing the data to hash.</param>
    /// <returns>The hash value.</returns>
    public byte[] HashData(Stream stream)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        using var hasher = CryptographyHelper.CreateHashAlgorithm(_hashAlgorithm);
        return hasher.ComputeHash(stream);
    }

    /// <summary>
    /// Computes the hash of a file.
    /// </summary>
    /// <param name="filePath">The path to the file.</param>
    /// <returns>The hash value.</returns>
    public byte[] HashFile(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));
        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found.", filePath);

        using var stream = File.OpenRead(filePath);
        return HashData(stream);
    }
}

/// <summary>
/// Represents a digital signature with metadata.
/// </summary>
public class DigitalSignature
{
    /// <summary>
    /// The signature value.
    /// </summary>
    public byte[] Signature { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The hash of the original data.
    /// </summary>
    public byte[] Hash { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The hash algorithm used (e.g., "SHA256").
    /// </summary>
    public string? HashAlgorithm { get; set; }

    /// <summary>
    /// The timestamp when the signature was created.
    /// </summary>
    public DateTimeOffset Timestamp { get; set; }

    /// <summary>
    /// Converts the signature to a base64-encoded string.
    /// </summary>
    /// <returns>Base64-encoded signature.</returns>
    public string ToBase64()
    {
        return Convert.ToBase64String(Signature);
    }

    /// <summary>
    /// Converts the hash to a hexadecimal string.
    /// </summary>
    /// <returns>Hexadecimal hash string.</returns>
    public string HashToHex()
    {
        return Convert.ToHexString(Hash).ToLower();
    }
}

/// <summary>
/// Helper class for creating hash algorithms.
/// </summary>
internal static class CryptographyHelper
{
    public static HashAlgorithm CreateHashAlgorithm(HashAlgorithmName hashAlgorithmName)
    {
        return hashAlgorithmName.Name switch
        {
            "SHA256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            "SHA1" => SHA1.Create(),
            _ => throw new NotSupportedException($"Hash algorithm '{hashAlgorithmName.Name}' is not supported.")
        };
    }
}
