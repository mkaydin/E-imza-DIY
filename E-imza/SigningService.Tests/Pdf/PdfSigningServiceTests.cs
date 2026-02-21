using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using iText.Kernel.Pdf;
using SigningService.Crypto;
using SigningService.Pdf;
using Xunit;
using Xunit.Abstractions;

namespace SigningService.Tests.Pdf;

public class PdfSigningServiceTests : IDisposable
{
    private readonly SoftwareSigner _signer;
    private readonly X509Certificate2 _certificate;
    private readonly PdfSigningService _service;
    private readonly ITestOutputHelper _output;
    private readonly string _testOutputDirectory;

    public PdfSigningServiceTests(ITestOutputHelper output)
    {
        _output = output;
        _signer = new SoftwareSigner();
        _certificate = _signer.CreateSelfSignedCertificate("CN=TestPdfSigner");
        _service = new PdfSigningService(_signer, _certificate);

        // Create a temporary directory for test outputs
        _testOutputDirectory = Path.Combine(Path.GetTempPath(), "PdfSigningTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testOutputDirectory);
    }

    public void Dispose()
    {
        _signer.Dispose();

        // Clean up test files
        if (Directory.Exists(_testOutputDirectory))
        {
            try
            {
                Directory.Delete(_testOutputDirectory, true);
            }
            catch
            {
                // Ignore cleanup errors
            }
        }
    }

    private string CreateSamplePdf(string fileName)
    {
        string filePath = Path.Combine(_testOutputDirectory, fileName);

        // Create a simple PDF using iText
        using var writer = new PdfWriter(filePath);
        using var pdf = new PdfDocument(writer);
        var document = new iText.Layout.Document(pdf);
        document.Add(new iText.Layout.Element.Paragraph("Sample PDF for Testing"));
        document.Add(new iText.Layout.Element.Paragraph($"Created at: {DateTimeOffset.UtcNow}"));
        document.Close();

        return filePath;
    }

    [Fact]
    public void SignPdf_ValidInput_CreatesSignedPdf()
    {
        // Arrange
        string inputFile = CreateSamplePdf("input.pdf");
        string outputFile = Path.Combine(_testOutputDirectory, "signed.pdf");

        // Act
        _service.SignPdf(inputFile, outputFile);

        // Assert
        Assert.True(File.Exists(outputFile));
        Assert.True(new FileInfo(outputFile).Length > 0);
    }

    [Fact]
    public void SignAndVerify_ValidPdf_ReturnsValidSignature()
    {
        // Arrange
        string inputFile = CreateSamplePdf("input_verify.pdf");
        string outputFile = Path.Combine(_testOutputDirectory, "signed_verify.pdf");

        // Act
        _service.SignPdf(inputFile, outputFile);
        var result = _service.VerifySignature(outputFile);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(1, result.TotalSignatures);
        Assert.Single(result.Signatures);
    }

    [Fact]
    public void VerifySignature_SignedPdf_ReturnsCorrectInfo()
    {
        // Arrange
        string inputFile = CreateSamplePdf("input_info.pdf");
        string outputFile = Path.Combine(_testOutputDirectory, "signed_info.pdf");

        // Act
        _service.SignPdf(inputFile, outputFile);
        var result = _service.VerifySignature(outputFile);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(1, result.TotalSignatures);
        Assert.Equal("CN=TestPdfSigner", result.Signatures[0].SignedBy);
        Assert.True(result.Signatures[0].IsSignatureValid);
        Assert.False(result.Signatures[0].IsDocumentModified);
    }

    [Fact]
    public void SignPdf_ByteArray_ReturnsSignedPdf()
    {
        // Arrange
        string inputFile = CreateSamplePdf("input_bytes.pdf");
        byte[] inputBytes = File.ReadAllBytes(inputFile);

        // Act
        byte[] signedBytes = _service.SignPdf(inputBytes);

        // Assert
        Assert.NotNull(signedBytes);
        Assert.NotEmpty(signedBytes);
        Assert.True(signedBytes.Length > inputBytes.Length); // Signed PDF should be larger
    }

    [Fact]
    public void SignAndVerify_ByteArray_ReturnsValidSignature()
    {
        // Arrange
        string inputFile = CreateSamplePdf("input_bytes_verify.pdf");
        byte[] inputBytes = File.ReadAllBytes(inputFile);

        // Act
        byte[] signedBytes = _service.SignPdf(inputBytes);
        // Save to temp file for verification
        string tempFile = Path.Combine(_testOutputDirectory, "temp_signed.pdf");
        File.WriteAllBytes(tempFile, signedBytes);
        var result = _service.VerifySignature(tempFile);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(1, result.TotalSignatures);
        Assert.Single(result.Signatures);
    }

    [Fact]
    public void VerifySignature_UnsignedPdf_ReturnsNoSignatures()
    {
        // Arrange
        string unsignedFile = CreateSamplePdf("unsigned.pdf");

        // Act
        var result = _service.VerifySignature(unsignedFile);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(0, result.TotalSignatures);
        Assert.Empty(result.Signatures);
    }

    [Fact]
    public void PdfSignatureVerificationResult_ToString_ReturnsFormattedString()
    {
        // Arrange
        string inputFile = CreateSamplePdf("input_tostring.pdf");
        string outputFile = Path.Combine(_testOutputDirectory, "signed_tostring.pdf");

        _service.SignPdf(inputFile, outputFile);
        var result = _service.VerifySignature(outputFile);

        // Act
        string resultString = result.ToString();

        // Assert
        Assert.NotNull(resultString);
        Assert.Contains("Total signatures: 1", resultString);
        Assert.Contains("All signatures valid:", resultString);
        Assert.Contains("Signature:", resultString);
        _output.WriteLine(resultString);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SignPdf_InvalidInputPath_ThrowsArgumentException(string? inputPath)
    {
        // Arrange
        string outputFile = Path.Combine(_testOutputDirectory, "output.pdf");

        // Act & Assert
        Assert.ThrowsAny<ArgumentException>(() => _service.SignPdf(inputPath!, outputFile));
    }

    [Fact]
    public void SignPdf_NonexistentFile_ThrowsFileNotFoundException()
    {
        // Arrange
        string inputFile = Path.Combine(_testOutputDirectory, "nonexistent.pdf");
        string outputFile = Path.Combine(_testOutputDirectory, "output.pdf");

        // Act & Assert
        Assert.Throws<FileNotFoundException>(() => _service.SignPdf(inputFile, outputFile));
    }

    [Fact]
    public void SignPdf_LargePdf_WorksCorrectly()
    {
        // Arrange
        string inputFile = CreateLargePdf("large_input.pdf");
        string outputFile = Path.Combine(_testOutputDirectory, "large_signed.pdf");

        // Act
        _service.SignPdf(inputFile, outputFile);

        // Assert
        Assert.True(File.Exists(outputFile));
        var result = _service.VerifySignature(outputFile);
        Assert.Equal(1, result.TotalSignatures);
    }

    private string CreateLargePdf(string fileName)
    {
        string filePath = Path.Combine(_testOutputDirectory, fileName);

        using var writer = new PdfWriter(filePath);
        using var pdf = new PdfDocument(writer);
        var document = new iText.Layout.Document(pdf);

        // Add many pages with content
        for (int i = 0; i < 10; i++)
        {
            document.Add(new iText.Layout.Element.Paragraph($"Page {i + 1}"));
            document.Add(new iText.Layout.Element.Paragraph(new string('A', 1000)));
        }

        document.Close();
        return filePath;
    }
}
