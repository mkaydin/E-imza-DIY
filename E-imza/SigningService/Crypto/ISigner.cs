namespace SigningService.Crypto;

/// <summary>
/// Unified interface for cryptographic signing operations.
/// This abstraction allows swapping between software-based and hardware-based signers.
/// </summary>
public interface ISigner
{
    /// <summary>
    /// Signs a hash value using the private key.
    /// </summary>
    /// <param name="hash">The hash value to sign.</param>
    /// <returns>The digital signature as a byte array.</returns>
    byte[] Sign(byte[] hash);

    /// <summary>
    /// Verifies a signature against a hash value using the public key.
    /// </summary>
    /// <param name="hash">The original hash value.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    bool Verify(byte[] hash, byte[] signature);

    /// <summary>
    /// Gets the public key for verification purposes.
    /// </summary>
    /// <returns>The public key parameters as a byte array.</returns>
    byte[] GetPublicKey();
}
