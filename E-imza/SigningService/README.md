# .NET Digital Signing Service

A comprehensive .NET signing service capable of digitally signing raw binary data, XML documents, and PDF documents using software-based cryptographic keys.

## Features

- **Raw Data Signing**: Sign and verify any binary data using SHA-256 hashing and RSA signatures
- **XML Signing (XMLDSIG)**: Create enveloped XML signatures embedded within documents
- **PDF Signing**: Sign PDF documents with signatures recognized by Adobe Reader and other PDF readers
- **Hardware-Agnostic**: Clean separation between signing logic and implementation, ready for future hardware signer integration
- **Dependency Injection**: Full DI support for easy testing and swapping implementations

## Architecture

```
SigningService/
├── Crypto/
│   ├── ISigner.cs           # Unified signing interface
│   └── SoftwareSigner.cs    # Software-based RSA implementation
├── Raw/
│   └── RawSigningService.cs # Raw data signing service
├── Xml/
│   └── XmlSigningService.cs # XML document signing (XMLDSIG)
├── Pdf/
│   └── PdfSigningService.cs # PDF document signing (iText7)
└── Program.cs               # Example usage and demonstrations
```

## Quick Start

### 1. Raw Data Signing

```csharp
using SigningService.Crypto;
using SigningService.Raw;

// Create signer and service
var signer = new SoftwareSigner();
var rawService = new RawSigningService(signer);

// Sign data
byte[] data = Encoding.UTF8.GetBytes("Important data");
var signature = rawService.SignData(data);

// Verify signature
bool isValid = rawService.VerifySignature(data, signature);
Console.WriteLine($"Signature valid: {isValid}");
```

### 2. XML Document Signing

```csharp
using SigningService.Xml;

// Create signer and certificate
var signer = new SoftwareSigner();
var certificate = signer.CreateSelfSignedCertificate("CN=XmlSigner");
var xmlService = new XmlSigningService(signer, certificate);

// Sign XML document
string xmlString = "<root><data>Important content</data></root>";
string signedXml = xmlService.SignXmlString(xmlString);

// Verify signature
bool isValid = xmlService.VerifyXmlString(signedXml);
```

### 3. PDF Document Signing

```csharp
using SigningService.Pdf;

// Create signer and certificate
var signer = new SoftwareSigner();
var certificate = signer.CreateSelfSignedCertificate("CN=PdfSigner");
var pdfService = new PdfSigningService(signer, certificate);

// Sign PDF file
pdfService.SignPdf(
    inputFilePath: "document.pdf",
    outputFilePath: "signed.pdf",
    reason: "Document Approval",
    location: "Headquarters");

// Verify signature
var result = pdfService.VerifySignature("signed.pdf");
Console.WriteLine($"Signature valid: {result.AllSignaturesValid}");
```

## Building and Running

### Build the Project

```bash
cd SigningService
dotnet build
```

### Run Examples

```bash
dotnet run
```

### Run Tests

```bash
cd SigningService.Tests
dotnet test
```

## Dependencies

- **.NET 8.0** or later
- **iText7** (v9.0.0) - PDF manipulation and signing
- **System.Security.Cryptography.Xml** (v8.0.0) - XML digital signatures
- **Microsoft.Extensions.DependencyInjection** (v8.0.0) - DI support

## Integration with Hardware Signers

The `ISigner` interface allows easy swapping of signing implementations:

```csharp
public interface ISigner
{
    byte[] Sign(byte[] hash);
    bool Verify(byte[] hash, byte[] signature);
    byte[] GetPublicKey();
}
```

To integrate a hardware signer (HSM, Smart Card):

1. Implement `ISigner`:
```csharp
public class HardwareSigner : ISigner
{
    private readonly IHsmDevice _device;

    public HardwareSigner(IHsmDevice device)
    {
        _device = device;
    }

    public byte[] Sign(byte[] hash)
    {
        return _device.Sign(hash);
    }

    public bool Verify(byte[] hash, byte[] signature)
    {
        return _device.Verify(hash, signature);
    }

    public byte[] GetPublicKey()
    {
        return _device.ExportPublicKey();
    }
}
```

2. Update DI configuration:
```csharp
services.AddTransient<ISigner, HardwareSigner>();
```

All existing services (`RawSigningService`, `XmlSigningService`, `PdfSigningService`) will automatically use the hardware signer.

## Testing

The project includes comprehensive unit tests:

- **Raw Data Tests**: [RawSigningServiceTests.cs](../SigningService.Tests/Raw/RawSigningServiceTests.cs)
- **XML Tests**: [XmlSigningServiceTests.cs](../SigningService.Tests/Xml/XmlSigningServiceTests.cs)
- **PDF Tests**: [PdfSigningServiceTests.cs](../SigningService.Tests/Pdf/PdfSigningServiceTests.cs)

Run all tests:
```bash
dotnet test
```

## Security Notes

- This implementation uses software-based RSA keys (2048-bit)
- SHA-256 is used for all hashing operations
- Certificates are self-signed for demonstration purposes
- For production use, consider:
  - Using certificates from a trusted CA
  - Integrating with an HSM for enhanced security
  - Implementing proper key management policies
  - Adding timestamp authority support for long-term signature validation

## License

This is a demonstration project for educational and development purposes.
