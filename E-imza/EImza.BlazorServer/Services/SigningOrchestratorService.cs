using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using EImza.BlazorServer.Models;
using SigningService.Crypto;
using SigningService.Raw;
using SigningService.Xml;
using SigningService.Pdf;

namespace EImza.BlazorServer.Services;

public class SigningOrchestratorService
{
    private readonly IServiceProvider _services;
    private readonly FileStorageService _storage;
    private readonly CertificateService _certificateService;
    private readonly ILogger<SigningOrchestratorService> _logger;

    public SigningOrchestratorService(
        IServiceProvider services,
        FileStorageService storage,
        CertificateService certificateService,
        ILogger<SigningOrchestratorService> logger)
    {
        _services = services;
        _storage = storage;
        _certificateService = certificateService;
        _logger = logger;
    }

    public async Task<SigningResult> SignRawTextAsync(SigningRequest request, IProgress<int>? progress = null)
    {
        try
        {
            progress?.Report(10);

            // Get or create signer
            var signer = await GetSignerAsync(request.Certificate);
            progress?.Report(30);

            var rawService = new RawSigningService(signer);
            progress?.Report(50);

            // Sign the data
            var signature = rawService.SignData(request.Content);
            progress?.Report(80);

            // Store signed content
            var signedFileName = string.IsNullOrEmpty(request.FileName)
                ? "signed_text.txt"
                : Path.GetFileNameWithoutExtension(request.FileName) + "_signed.txt";

            var fileId = await _storage.StoreFileAsync(request.Content, signedFileName);
            progress?.Report(100);

            return new SigningResult
            {
                SignedContent = request.Content,
                FileId = fileId,
                OriginalFileName = request.FileName,
                SignedFileName = signedFileName,
                ContentType = ContentType.RawText,
                Timestamp = signature.Timestamp,
                Signature = signature.Signature,
                Hash = signature.Hash,
                HashAlgorithm = signature.HashAlgorithm
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error signing raw text");
            return new SigningResult
            {
                ContentType = ContentType.RawText,
                ErrorMessage = ex.Message
            };
        }
    }

    public async Task<SigningResult> SignXmlAsync(SigningRequest request, IProgress<int>? progress = null)
    {
        try
        {
            progress?.Report(10);

            // Get or create signer and certificate
            var signer = await GetSignerAsync(request.Certificate);
            progress?.Report(30);

            var cert = await GetCertificateAsync(signer, request.Certificate);
            progress?.Report(50);

            var xmlService = new XmlSigningService(signer, cert);

            // Load and sign XML
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(request.ContentAsString);
            progress?.Report(70);

            string signedXml = xmlService.SignDocument(xmlDoc);
            progress?.Report(90);

            // Store signed content
            var signedBytes = System.Text.Encoding.UTF8.GetBytes(signedXml);
            var fileId = await _storage.StoreFileAsync(signedBytes, request.FileNameWithSuffix);
            progress?.Report(100);

            return new SigningResult
            {
                SignedContent = signedBytes,
                FileId = fileId,
                OriginalFileName = request.FileName,
                SignedFileName = request.FileNameWithSuffix,
                ContentType = ContentType.Xml,
                Timestamp = DateTimeOffset.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error signing XML document");
            return new SigningResult
            {
                ContentType = ContentType.Xml,
                ErrorMessage = ex.Message
            };
        }
    }

    public async Task<SigningResult> SignPdfAsync(SigningRequest request, IProgress<int>? progress = null)
    {
        try
        {
            progress?.Report(10);

            // Get or create signer and certificate
            var signer = await GetSignerAsync(request.Certificate);
            progress?.Report(30);

            var cert = await GetCertificateAsync(signer, request.Certificate);
            progress?.Report(50);

            var pdfService = new PdfSigningService(signer, cert);
            progress?.Report(70);

            // Sign PDF
            var signedPdf = pdfService.SignPdf(request.Content);
            progress?.Report(90);

            // Store signed content
            var fileId = await _storage.StoreFileAsync(signedPdf, request.FileNameWithSuffix);
            progress?.Report(100);

            return new SigningResult
            {
                SignedContent = signedPdf,
                FileId = fileId,
                OriginalFileName = request.FileName,
                SignedFileName = request.FileNameWithSuffix,
                ContentType = ContentType.Pdf,
                Timestamp = DateTimeOffset.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error signing PDF document");
            return new SigningResult
            {
                ContentType = ContentType.Pdf,
                ErrorMessage = ex.Message
            };
        }
    }

    public async Task<VerificationResult> VerifyAsync(VerificationRequest request, DocumentType documentType)
    {
        try
        {
            return documentType switch
            {
                DocumentType.Xml => await VerifyXmlAsync(request),
                DocumentType.Pdf => await VerifyPdfAsync(request),
                _ => new VerificationResult
                {
                    IsValid = false,
                    DocumentType = documentType,
                    ErrorMessage = "Unsupported document type for verification"
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying document");
            return new VerificationResult
            {
                IsValid = false,
                DocumentType = documentType,
                ErrorMessage = ex.Message
            };
        }
    }

    private async Task<VerificationResult> VerifyXmlAsync(VerificationRequest request)
    {
        var signer = _services.GetRequiredService<ISigner>();
        var xmlService = new XmlSigningService(signer);

        var xmlDoc = new XmlDocument();
        xmlDoc.PreserveWhitespace = true;
        xmlDoc.LoadXml(System.Text.Encoding.UTF8.GetString(request.Content));

        var isValid = xmlService.VerifySignature(xmlDoc);

        return new VerificationResult
        {
            IsValid = isValid,
            DocumentType = DocumentType.Xml,
            Signatures = new List<Models.SignatureInfo>
            {
                new()
                {
                    Signer = "Unknown",
                    SigningTime = DateTime.UtcNow,
                    HashAlgorithm = "SHA256",
                    IsSignatureValid = isValid,
                    IsDocumentModified = !isValid
                }
            }
        };
    }

    private async Task<VerificationResult> VerifyPdfAsync(VerificationRequest request)
    {
        var signer = _services.GetRequiredService<ISigner>();
        var cert = signer is SoftwareSigner ss
            ? ss.CreateSelfSignedCertificate("CN=Verifier")
            : throw new InvalidOperationException("Signer must be SoftwareSigner");

        var pdfService = new PdfSigningService(signer, cert);

        // Write to temp file for verification
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempFile, request.Content);
            var result = pdfService.VerifySignature(tempFile);

            var signatures = result.Signatures.Select(s => new Models.SignatureInfo
            {
                Signer = s.SignedBy,
                SigningTime = s.SigningDate,
                HashAlgorithm = "SHA256",
                IsSignatureValid = s.IsSignatureValid,
                IsDocumentModified = s.IsDocumentModified
            }).ToList();

            return new VerificationResult
            {
                IsValid = result.AllSignaturesValid,
                DocumentType = DocumentType.Pdf,
                Signatures = signatures
            };
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    public async Task<DocumentType> DetectDocumentTypeAsync(VerificationRequest request)
    {
        if (request.Content.Length == 0)
            return DocumentType.Unknown;

        // Check for PDF (%PDF)
        if (request.Content.Length > 4 &&
            request.Content[0] == 0x25 && request.Content[1] == 0x50 &&
            request.Content[2] == 0x44 && request.Content[3] == 0x46)
        {
            return DocumentType.Pdf;
        }

        // Check for XML (starts with <)
        var contentStart = System.Text.Encoding.UTF8.GetString(request.Content.Take(Math.Min(100, request.Content.Length)).ToArray());
        if (contentStart.TrimStart().StartsWith("<"))
        {
            return DocumentType.Xml;
        }

        return DocumentType.Unknown;
    }

    private async Task<ISigner> GetSignerAsync(CertificateInfo? certificate)
    {
        if (certificate == null || certificate.IsAutoGenerated)
        {
            return new SoftwareSigner();
        }

        // For uploaded certificates, we'd need to create a signer from the certificate
        // For now, we'll use the SoftwareSigner as a placeholder
        // TODO: Implement certificate-based signer initialization
        return new SoftwareSigner();
    }

    private async Task<X509Certificate2> GetCertificateAsync(ISigner signer, CertificateInfo? certificate)
    {
        if (certificate == null || certificate.IsAutoGenerated)
        {
            if (signer is SoftwareSigner ss)
            {
                return ss.CreateSelfSignedCertificate("CN=EImzaAutoGenerated");
            }
            throw new InvalidOperationException("Cannot generate certificate for non-SoftwareSigner");
        }

        return _certificateService.GetCertificateForSigning(certificate);
    }
}
