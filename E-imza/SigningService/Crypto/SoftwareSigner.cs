using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SigningService.Crypto;

/// <summary>
/// Software-based implementation of the ISigner interface using RSA with SHA-256.
/// This signer generates and stores keys in memory, making it suitable for testing
/// and scenarios where hardware security modules are not required.
/// </summary>
public class SoftwareSigner : ISigner, IDisposable
{
    private readonly RSA _rsa;

    /// <summary>
    /// Initializes a new instance with a new 2048-bit RSA key pair.
    /// </summary>
    public SoftwareSigner()
    {
        _rsa = RSA.Create(2048);
    }

    /// <summary>
    /// Initializes a new instance with an existing RSA key pair.
    /// </summary>
    /// <param name="rsa">The RSA instance with the key pair.</param>
    public SoftwareSigner(RSA rsa)
    {
        _rsa = rsa ?? throw new ArgumentNullException(nameof(rsa));
    }

    /// <summary>
    /// Initializes a new instance with an existing X.509 certificate.
    /// </summary>
    /// <param name="certificate">The certificate containing the public key.</param>
    /// <param name="privateKey">The private key (optional, for signing only).</param>
    public SoftwareSigner(X509Certificate2 certificate, RSA? privateKey = null)
    {
        if (certificate == null)
            throw new ArgumentNullException(nameof(certificate));

        _rsa = privateKey ?? certificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Certificate does not contain an RSA private key.");
    }

    /// <summary>
    /// Signs the specified hash value using RSA with PKCS#1 v1.5 padding and SHA-256.
    /// </summary>
    /// <param name="hash">The hash value to sign.</param>
    /// <returns>The digital signature.</returns>
    /// <exception cref="ArgumentNullException">Thrown when hash is null.</exception>
    /// <exception cref="ArgumentException">Thrown when hash length is invalid.</exception>
    public byte[] Sign(byte[] hash)
    {
        if (hash == null)
            throw new ArgumentNullException(nameof(hash));

        if (hash.Length != 32) // SHA-256 produces 32 bytes
            throw new ArgumentException("Hash must be 32 bytes (SHA-256).", nameof(hash));

        return _rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Verifies a signature against the specified hash value.
    /// </summary>
    /// <param name="hash">The original hash value.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public bool Verify(byte[] hash, byte[] signature)
    {
        if (hash == null)
            throw new ArgumentNullException(nameof(hash));
        if (signature == null)
            throw new ArgumentNullException(nameof(signature));

        return _rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Exports the public key in ASN.1 DER format.
    /// </summary>
    /// <returns>The public key as a byte array.</returns>
    public byte[] GetPublicKey()
    {
        return _rsa.ExportRSAPublicKey();
    }

    /// <summary>
    /// Creates a self-signed X.509 certificate for this signer.
    /// Useful for PDF and XML signing where certificates are required.
    /// </summary>
    /// <param name="subjectName">The subject name for the certificate.</param>
    /// <returns>A self-signed X.509 certificate.</returns>
    public X509Certificate2 CreateSelfSignedCertificate(string subjectName = "CN=SoftwareSigner")
    {
        var request = new CertificateRequest(
            subjectName,
            _rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add extensions for a basic code signing certificate
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: false));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, // Code signing
                critical: false));

        // Create a self-signed certificate valid for 1 year
        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        return certificate;
    }

    /// <summary>
    /// Releases the resources used by the RSA instance.
    /// </summary>
    public void Dispose()
    {
        _rsa?.Dispose();
    }
}
