using System.Security.Cryptography;
using System.Text;
using SigningService.Crypto;
using SigningService.Raw;
using Xunit;

namespace SigningService.Tests.Raw;

public class RawSigningServiceTests : IDisposable
{
    private readonly SoftwareSigner _signer;
    private readonly RawSigningService _service;

    public RawSigningServiceTests()
    {
        _signer = new SoftwareSigner();
        _service = new RawSigningService(_signer);
    }

    public void Dispose()
    {
        _signer.Dispose();
    }

    [Fact]
    public void SignData_ValidData_ReturnsValidSignature()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Hello, World!");

        // Act
        var signature = _service.SignData(data);

        // Assert
        Assert.NotNull(signature);
        Assert.NotNull(signature.Signature);
        Assert.NotEmpty(signature.Signature);
        Assert.NotNull(signature.Hash);
        Assert.Equal(32, signature.Hash.Length); // SHA-256 produces 32 bytes
        Assert.Equal("SHA256", signature.HashAlgorithm);
        Assert.True(signature.Timestamp <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public void SignAndVerify_ValidData_ReturnsTrue()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Test data for signing");

        // Act
        var signature = _service.SignData(data);
        bool isValid = _service.VerifySignature(data, signature.Signature);

        // Assert
        Assert.True(isValid, "Signature verification should succeed for valid data");
    }

    [Fact]
    public void VerifySignature_InvalidData_ReturnsFalse()
    {
        // Arrange
        byte[] originalData = Encoding.UTF8.GetBytes("Original data");
        byte[] modifiedData = Encoding.UTF8.GetBytes("Modified data");

        // Act
        var signature = _service.SignData(originalData);
        bool isValid = _service.VerifySignature(modifiedData, signature.Signature);

        // Assert
        Assert.False(isValid, "Signature verification should fail for modified data");
    }

    [Fact]
    public void VerifySignature_TamperedSignature_ReturnsFalse()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Test data");

        // Act
        var signature = _service.SignData(data);
        var tamperedSignature = (byte[])signature.Signature.Clone();
        tamperedSignature[0] ^= 0xFF; // Flip all bits in the first byte

        bool isValid = _service.VerifySignature(data, tamperedSignature);

        // Assert
        Assert.False(isValid, "Signature verification should fail for tampered signature");
    }

    [Fact]
    public void SignData_EmptyData_ReturnsValidSignature()
    {
        // Arrange
        byte[] data = Array.Empty<byte>();

        // Act
        var signature = _service.SignData(data);

        // Assert
        Assert.NotNull(signature);
        Assert.NotEmpty(signature.Signature);
        Assert.True(_service.VerifySignature(data, signature.Signature));
    }

    [Fact]
    public void SignData_LargeData_ReturnsValidSignature()
    {
        // Arrange
        byte[] data = new byte[10_000_000]; // 10 MB
        new Random().NextBytes(data);

        // Act
        var signature = _service.SignData(data);

        // Assert
        Assert.NotNull(signature);
        Assert.NotEmpty(signature.Signature);
        Assert.True(_service.VerifySignature(data, signature.Signature));
    }

    [Fact]
    public void HashData_ValidStream_ReturnsCorrectHash()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Hash this data");
        using var stream = new MemoryStream(data);

        // Act
        byte[] hash1 = _service.HashData(stream);

        // Arrange (second call with new stream)
        using var stream2 = new MemoryStream(data);
        byte[] hash2 = _service.HashData(stream2);

        // Assert
        Assert.Equal(32, hash1.Length); // SHA-256 produces 32 bytes
        Assert.Equal(hash1, hash2); // Same data should produce same hash
    }

    [Fact]
    public void SignAndVerify_UsingDigitalSignatureObject_ReturnsTrue()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Test with DigitalSignature object");

        // Act
        var signature = _service.SignData(data);
        bool isValid = _service.VerifySignature(data, signature);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void ToBase64_ValidSignature_ReturnsValidBase64String()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Test base64 encoding");
        var signature = _service.SignData(data);

        // Act
        string base64 = signature.ToBase64();

        // Assert
        Assert.NotNull(base64);
        Assert.NotEmpty(base64);
        Assert.Equal(Convert.FromBase64String(base64), signature.Signature);
    }

    [Fact]
    public void HashToHex_ValidSignature_ReturnsValidHexString()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Test hex encoding");
        var signature = _service.SignData(data);

        // Act
        string hex = signature.HashToHex();

        // Assert
        Assert.NotNull(hex);
        Assert.NotEmpty(hex);
        Assert.Equal(64, hex.Length); // 32 bytes = 64 hex characters
        Assert.True(hex.All(c => char.IsDigit(c) || (c >= 'a' && c <= 'f')));
    }

    [Theory]
    [InlineData(null)]
    public void SignData_NullData_ThrowsArgumentNullException(byte[]? data)
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _service.SignData(data!));
    }

    [Fact]
    public void VerifySignature_NullSignature_ThrowsArgumentNullException()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Test");
        byte[]? nullSignature = null;

        // Act & Assert - Explicit cast to disambiguate
        Assert.Throws<ArgumentNullException>(() => _service.VerifySignature(data, (byte[])nullSignature!));
    }

    [Fact]
    public void VerifySignature_ShortSignature_ReturnsFalse()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Test");
        byte[] shortSignature = new byte[] { 1, 2, 3 };

        // Act
        bool isValid = _service.VerifySignature(data, shortSignature);

        // Assert - Short/invalid signature should not be valid
        Assert.False(isValid);
    }

    [Fact]
    public void MultipleSignatures_SameData_CanVerifyBoth()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Same data");

        // Act
        var sig1 = _service.SignData(data);
        var sig2 = _service.SignData(data);

        // Assert
        // Both signatures should verify successfully, even if they are the same
        // (deterministic signing is a valid implementation)
        Assert.True(_service.VerifySignature(data, sig1.Signature));
        Assert.True(_service.VerifySignature(data, sig2.Signature));
    }
}
