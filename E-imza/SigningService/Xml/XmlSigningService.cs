using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SigningService.Crypto;

namespace SigningService.Xml;

/// <summary>
/// Service for signing XML documents using XMLDSIG (XML Digital Signature).
/// Creates enveloped signatures embedded within the XML document.
/// </summary>
public class XmlSigningService
{
    private readonly ISigner _signer;
    private readonly X509Certificate2? _certificate;

    /// <summary>
    /// Initializes a new instance with the specified signer.
    /// </summary>
    /// <param name="signer">The signer implementation to use.</param>
    /// <param name="certificate">Optional certificate to embed in the signature.</param>
    public XmlSigningService(ISigner signer, X509Certificate2? certificate = null)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _certificate = certificate;
    }

    /// <summary>
    /// Signs an XML document using enveloped signature format.
    /// </summary>
    /// <param name="xmlDocument">The XML document to sign.</param>
    /// <returns>The signed XML document as a string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when xmlDocument is null.</exception>
    public string SignDocument(XmlDocument xmlDocument)
    {
        if (xmlDocument == null)
            throw new ArgumentNullException(nameof(xmlDocument));

        // Create a SignedXml object with our custom RSA wrapper
        var signingRsa = new SigningRsa(_signer);
        var signedXml = new SignedXml(xmlDocument);

        // Set the signing key
        signedXml.SigningKey = signingRsa;

        // Get the root element to sign
        if (xmlDocument.DocumentElement == null)
            throw new InvalidOperationException("XML document has no root element.");

        // Create a reference to the entire document
        var reference = new Reference
        {
            Uri = ""
        };

        // Add an enveloped signature transform
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigC14NTransform());

        // Add the reference to the SignedXml
        signedXml.AddReference(reference);

        // Add KeyInfo if certificate is available
        if (_certificate != null)
        {
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(_certificate));
            signedXml.KeyInfo = keyInfo;
        }

        // Compute the signature
        signedXml.ComputeSignature();

        // Get the XML representation of the signature
        XmlElement signatureElement = signedXml.GetXml();

        // Append the signature to the document
        xmlDocument.DocumentElement.AppendChild(signatureElement);

        return xmlDocument.OuterXml;
    }

    /// <summary>
    /// Signs an XML document from a file path.
    /// </summary>
    /// <param name="inputFilePath">The path to the input XML file.</param>
    /// <param name="outputFilePath">The path to save the signed XML file.</param>
    public void SignDocument(string inputFilePath, string outputFilePath)
    {
        if (string.IsNullOrEmpty(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        if (string.IsNullOrEmpty(outputFilePath))
            throw new ArgumentException("Output file path cannot be null or empty.", nameof(outputFilePath));

        var xmlDoc = new XmlDocument();
        xmlDoc.PreserveWhitespace = true;
        xmlDoc.Load(inputFilePath);

        string signedXml = SignDocument(xmlDoc);

        File.WriteAllText(outputFilePath, signedXml);
    }

    /// <summary>
    /// Signs an XML document from a string.
    /// </summary>
    /// <param name="xmlString">The XML string to sign.</param>
    /// <returns>The signed XML string.</returns>
    public string SignXmlString(string xmlString)
    {
        if (string.IsNullOrEmpty(xmlString))
            throw new ArgumentException("XML string cannot be null or empty.", nameof(xmlString));

        var xmlDoc = new XmlDocument
        {
            PreserveWhitespace = true
        };
        xmlDoc.LoadXml(xmlString);

        return SignDocument(xmlDoc);
    }

    /// <summary>
    /// Verifies the signature of an XML document.
    /// </summary>
    /// <param name="xmlDocument">The signed XML document.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public bool VerifySignature(XmlDocument xmlDocument)
    {
        if (xmlDocument == null)
            throw new ArgumentNullException(nameof(xmlDocument));

        // Find the Signature element
        var signatureNode = xmlDocument.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")
            .Cast<XmlNode>()
            .FirstOrDefault();

        if (signatureNode == null)
            return false;

        // Create a SignedXml object for verification
        var signedXml = new SignedXml(xmlDocument);
        signedXml.LoadXml((XmlElement)signatureNode);

        // Verify using the embedded key info or public key
        bool isValid;
        if (signedXml.KeyInfo != null && _certificate != null)
        {
            isValid = signedXml.CheckSignature(_certificate, true);
        }
        else
        {
            isValid = signedXml.CheckSignature();
        }

        return isValid;
    }

    /// <summary>
    /// Verifies the signature of an XML document from a file.
    /// </summary>
    /// <param name="filePath">The path to the signed XML file.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public bool VerifySignature(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));
        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found.", filePath);

        var xmlDoc = new XmlDocument
        {
            PreserveWhitespace = true
        };
        xmlDoc.Load(filePath);

        return VerifySignature(xmlDoc);
    }

    /// <summary>
    /// Verifies the signature of an XML document from a string.
    /// </summary>
    /// <param name="xmlString">The signed XML string.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public bool VerifyXmlString(string xmlString)
    {
        if (string.IsNullOrEmpty(xmlString))
            throw new ArgumentException("XML string cannot be null or empty.", nameof(xmlString));

        var xmlDoc = new XmlDocument
        {
            PreserveWhitespace = true
        };
        xmlDoc.LoadXml(xmlString);

        return VerifySignature(xmlDoc);
    }
}

/// <summary>
/// Custom RSA implementation that delegates to our ISigner interface.
/// This allows us to use our pluggable signing architecture with SignedXml.
/// </summary>
internal class SigningRsa : RSA
{
    private readonly ISigner _signer;

    public SigningRsa(ISigner signer)
    {
        _signer = signer;
    }

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        return _signer.Sign(hash);
    }

    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        return _signer.Verify(hash, signature);
    }

    [Obsolete]
    public override byte[] DecryptValue(byte[] rgb) => throw new NotSupportedException();

    [Obsolete]
    public override byte[] EncryptValue(byte[] rgb) => throw new NotSupportedException();

    public override RSAParameters ExportParameters(bool includePrivateParameters) => throw new NotSupportedException();
    public override void ImportParameters(RSAParameters parameters) => throw new NotSupportedException();
}
