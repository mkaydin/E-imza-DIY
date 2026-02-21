using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using SigningService.Crypto;
using SigningService.Pdf;
using SigningService.Raw;
using SigningService.Xml;

namespace SigningService;

/// <summary>
/// Main program demonstrating the usage of the signing services.
/// This example shows how to sign and verify raw data, XML documents, and PDF documents.
/// </summary>
class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║         .NET Digital Signing Service - Examples              ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.WriteLine();

        // Set up dependency injection
        var serviceProvider = ConfigureServices();

        try
        {
            // Example 1: Raw Data Signing
            await Example1_RawDataSigning(serviceProvider);

            Console.WriteLine("\n" + new string('-', 60) + "\n");

            // Example 2: XML Signing
            await Example2_XmlSigning(serviceProvider);

            Console.WriteLine("\n" + new string('-', 60) + "\n");

            // Example 3: PDF Signing
            await Example3_PdfSigning(serviceProvider);

            Console.WriteLine("\n" + new string('-', 60) + "\n");

            // Example 4: Demonstrating hardware signer swap capability
            Example4_HardwareSignerSwapDemo();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error: {ex.Message}");
            Console.ResetColor();
        }

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }

    /// <summary>
    /// Demonstrates raw data signing and verification.
    /// </summary>
    static async Task Example1_RawDataSigning(IServiceProvider serviceProvider)
    {
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║  Example 1: Raw Data Signing                                 ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");

        var signer = serviceProvider.GetRequiredService<ISigner>();
        var rawService = new RawSigningService(signer);

        // Example data to sign
        byte[] data = Encoding.UTF8.GetBytes("Hello, this is important data that needs to be signed!");

        Console.WriteLine($"Original Data: {Encoding.UTF8.GetString(data)}");
        Console.WriteLine($"Data Length: {data.Length} bytes");

        // Sign the data
        var signature = rawService.SignData(data);

        Console.WriteLine($"\n--- Signature Information ---");
        Console.WriteLine($"Hash Algorithm: {signature.HashAlgorithm}");
        Console.WriteLine($"Hash (hex): {signature.HashToHex()}");
        Console.WriteLine($"Signature (base64): {signature.ToBase64().Substring(0, Math.Min(50, signature.ToBase64().Length))}...");
        Console.WriteLine($"Timestamp: {signature.Timestamp:yyyy-MM-dd HH:mm:ss} UTC");

        // Verify the signature
        bool isValid = rawService.VerifySignature(data, signature);
        Console.WriteLine($"\nSignature Valid: {(isValid ? "✓ YES" : "✗ NO")}");

        // Demonstrate tamper detection
        byte[] tamperedData = Encoding.UTF8.GetBytes("Hello, this is tampered data!");
        bool isTamperedValid = rawService.VerifySignature(tamperedData, signature.Signature);
        Console.WriteLine($"Tampered Data Valid: {(isTamperedValid ? "✓ YES" : "✗ NO")}");

        // Hash a file example
        string tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "Sample file content for hashing");
        byte[] fileHash = rawService.HashFile(tempFile);
        Console.WriteLine($"\nFile Hash (SHA-256): {Convert.ToHexString(fileHash).ToLower()}");
        File.Delete(tempFile);
    }

    /// <summary>
    /// Demonstrates XML document signing and verification.
    /// </summary>
    static async Task Example2_XmlSigning(IServiceProvider serviceProvider)
    {
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║  Example 2: XML Document Signing (XMLDSIG)                   ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");

        var signer = serviceProvider.GetRequiredService<ISigner>();
        var certificate = signer is SoftwareSigner ss ? ss.CreateSelfSignedCertificate("CN=XmlSigner") : null!;
        var xmlService = new XmlSigningService(signer, certificate);

        // Sample XML document
        string xmlContent = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<invoice xmlns=""http://example.com/invoice"">
    <header>
        <number>INV-2024-001</number>
        <date>2024-02-20</date>
        <customer>Acme Corporation</customer>
    </header>
    <items>
        <item>
            <description>Software Development Services</description>
            <quantity>100</quantity>
            <unit>hours</unit>
            <price>150.00</price>
        </item>
    </items>
    <total>15000.00</total>
    <currency>USD</currency>
</invoice>";

        Console.WriteLine("--- Original XML Document ---");
        Console.WriteLine(xmlContent);

        // Sign the XML document
        string signedXml = xmlService.SignXmlString(xmlContent);

        Console.WriteLine($"\n--- Signed XML Document (first 500 chars) ---");
        Console.WriteLine(signedXml.Substring(0, Math.Min(500, signedXml.Length)) + "...");

        // Verify the signature
        bool isValid = xmlService.VerifyXmlString(signedXml);
        Console.WriteLine($"\nXML Signature Valid: {(isValid ? "✓ YES" : "✗ NO")}");

        // Demonstrate tamper detection
        string tamperedXml = signedXml.Replace("15000.00", "100.00");
        bool isTamperedValid = xmlService.VerifyXmlString(tamperedXml);
        Console.WriteLine($"Tampered XML Valid: {(isTamperedValid ? "✓ YES" : "✗ NO")}");

        // Save to files for inspection
        string originalFile = "example_invoice.xml";
        string signedFile = "example_invoice_signed.xml";
        await File.WriteAllTextAsync(originalFile, xmlContent);
        await File.WriteAllTextAsync(signedFile, signedXml);
        Console.WriteLine($"\nFiles saved: {originalFile}, {signedFile}");
    }

    /// <summary>
    /// Demonstrates PDF document signing and verification.
    /// </summary>
    static async Task Example3_PdfSigning(IServiceProvider serviceProvider)
    {
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║  Example 3: PDF Document Signing                             ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");

        var signer = serviceProvider.GetRequiredService<ISigner>();
        var certificate = signer is SoftwareSigner ss ? ss.CreateSelfSignedCertificate("CN=PdfSigner") : null!;
        var pdfService = new PdfSigningService(signer, certificate);

        // Create a sample PDF file (using iText7)
        string inputFile = "sample_document.pdf";
        string signedFile = "sample_document_signed.pdf";

        await CreateSamplePdfAsync(inputFile);
        Console.WriteLine($"Created sample PDF: {inputFile}");

        // Sign the PDF
        Console.WriteLine("\nSigning PDF document...");
        pdfService.SignPdf(inputFile, signedFile);

        Console.WriteLine($"Signed PDF saved: {signedFile}");

        // Verify the signature
        Console.WriteLine("\nVerifying signature...");
        var result = pdfService.VerifySignature(signedFile);

        Console.WriteLine($"\n--- Verification Results ---");
        Console.WriteLine(result.ToString());
    }

    /// <summary>
    /// Demonstrates how the ISigner interface can be swapped for a hardware-based implementation.
    /// </summary>
    static void Example4_HardwareSignerSwapDemo()
    {
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║  Example 4: Hardware Signer Swap (Architecture Demo)         ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");

        // Using SoftwareSigner (current implementation)
        ISigner softwareSigner = new SoftwareSigner();
        var rawService = new RawSigningService(softwareSigner);

        byte[] data = Encoding.UTF8.GetBytes("Test data for signer swap demo");
        var signature = rawService.SignData(data);

        Console.WriteLine("--- Using SoftwareSigner ---");
        Console.WriteLine($"Signature created: {signature.ToBase64().Substring(0, 30)}...");
        Console.WriteLine($"Verification: {(rawService.VerifySignature(data, signature) ? "✓ Valid" : "✗ Invalid")}");

        Console.WriteLine("\n--- Future Hardware Signer Integration ---");
        Console.WriteLine("To integrate a hardware signer (HSM, Smart Card):");
        Console.WriteLine("1. Implement ISigner interface:");
        Console.WriteLine("   public class HardwareSigner : ISigner");
        Console.WriteLine("   {");
        Console.WriteLine("       public byte[] Sign(byte[] hash)");
        Console.WriteLine("       {");
        Console.WriteLine("           // Delegate to hardware device");
        Console.WriteLine("           return hsmDevice.Sign(hash);");
        Console.WriteLine("       }");
        Console.WriteLine("       // ... implement Verify and GetPublicKey");
        Console.WriteLine("   }");
        Console.WriteLine();
        Console.WriteLine("2. Update DI configuration:");
        Console.WriteLine("   services.AddTransient<ISigner, HardwareSigner>();");
        Console.WriteLine();
        Console.WriteLine("3. All existing services (RawSigningService, etc.)");
        Console.WriteLine("   will automatically use the hardware signer!");

        // Clean up
        if (softwareSigner is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }

    /// <summary>
    /// Creates a sample PDF document for testing.
    /// </summary>
    static async Task CreateSamplePdfAsync(string filePath)
    {
        using var writer = new iText.Kernel.Pdf.PdfWriter(filePath);
        using var pdf = new iText.Kernel.Pdf.PdfDocument(writer);
        var document = new iText.Layout.Document(pdf);

        // Create a bold font
        var boldFont = iText.Kernel.Font.PdfFontFactory.CreateFont();

        document.Add(new iText.Layout.Element.Paragraph("Sample Document for Digital Signing")
            .SetFontSize(18)
            .SetBold());

        document.Add(new iText.Layout.Element.Paragraph("\n"));

        document.Add(new iText.Layout.Element.Paragraph(
            "This is a sample document created to demonstrate the PDF signing capabilities.")
            .SetTextAlignment(iText.Layout.Properties.TextAlignment.JUSTIFIED));

        document.Add(new iText.Layout.Element.Paragraph("\n"));

        document.Add(new iText.Layout.Element.Paragraph(
            "The document will be signed using the software-based cryptographic implementation,")
            .SetTextAlignment(iText.Layout.Properties.TextAlignment.JUSTIFIED));

        document.Add(new iText.Layout.Element.Paragraph(
            "which can be easily replaced with a hardware-based signer in the future.")
            .SetTextAlignment(iText.Layout.Properties.TextAlignment.JUSTIFIED));

        document.Add(new iText.Layout.Element.Paragraph("\n"));

        document.Add(new iText.Layout.Element.Paragraph($"Generated: {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC")
            .SetFontSize(10)
            .SetFontColor(iText.Kernel.Colors.DeviceGray.GRAY));

        document.Close();
    }

    /// <summary>
    /// Configures dependency injection for the application.
    /// </summary>
    static IServiceProvider ConfigureServices()
    {
        var services = new ServiceCollection();

        // Register the software-based signer
        services.AddTransient<ISigner, SoftwareSigner>();

        // Register signing services
        services.AddTransient<RawSigningService>();
        services.AddTransient<XmlSigningService>();
        services.AddTransient<PdfSigningService>(sp =>
        {
            var signer = sp.GetRequiredService<ISigner>();
            var certificate = signer is SoftwareSigner ss
                ? ss.CreateSelfSignedCertificate("CN=DefaultSigner")
                : throw new InvalidOperationException("Signer must be SoftwareSigner");
            return new PdfSigningService(signer, certificate);
        });

        return services.BuildServiceProvider();
    }
}
