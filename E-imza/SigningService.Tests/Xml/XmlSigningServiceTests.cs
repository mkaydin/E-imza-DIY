using System.Security.Cryptography;
using System.Xml;
using SigningService.Crypto;
using SigningService.Xml;
using Xunit;

namespace SigningService.Tests.Xml;

public class XmlSigningServiceTests : IDisposable
{
    private readonly SoftwareSigner _signer;
    private readonly XmlSigningService _service;

    public XmlSigningServiceTests()
    {
        _signer = new SoftwareSigner();
        var certificate = _signer.CreateSelfSignedCertificate("CN=TestSigner");
        _service = new XmlSigningService(_signer, certificate);
    }

    public void Dispose()
    {
        _signer.Dispose();
    }

    [Fact]
    public void SignDocument_ValidXml_ReturnsSignedXml()
    {
        // Arrange
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml("<root><data>Important data</data></root>");

        // Act
        string signedXml = _service.SignDocument(xmlDoc);

        // Assert
        Assert.NotNull(signedXml);
        Assert.Contains("<Signature", signedXml);
        Assert.Contains("xmlns=\"http://www.w3.org/2000/09/xmldsig#\"", signedXml);
    }

    [Fact]
    public void SignAndVerify_ValidXml_ReturnsTrue()
    {
        // Arrange
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml("<root><data>Important data</data></root>");

        // Act
        string signedXml = _service.SignDocument(xmlDoc);

        var signedDoc = new XmlDocument();
        signedDoc.PreserveWhitespace = true;
        signedDoc.LoadXml(signedXml);

        bool isValid = _service.VerifySignature(signedDoc);

        // Assert
        Assert.True(isValid, "XML signature verification should succeed");
    }

    [Fact]
    public void VerifySignature_TamperedContent_ReturnsFalse()
    {
        // Arrange
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml("<root><data>Original data</data></root>");

        // Act
        string signedXml = _service.SignDocument(xmlDoc);

        // Tamper with the content
        string tamperedXml = signedXml.Replace("Original data", "Modified data");

        var tamperedDoc = new XmlDocument();
        tamperedDoc.PreserveWhitespace = true;
        tamperedDoc.LoadXml(tamperedXml);

        bool isValid = _service.VerifySignature(tamperedDoc);

        // Assert
        Assert.False(isValid, "Signature verification should fail for tampered content");
    }

    [Fact]
    public void SignXmlString_ValidXmlString_ReturnsSignedXml()
    {
        // Arrange
        string xmlString = "<root><item>Test item</item></root>";

        // Act
        string signedXml = _service.SignXmlString(xmlString);

        // Assert
        Assert.NotNull(signedXml);
        Assert.Contains("<Signature", signedXml);
    }

    [Fact]
    public void SignXmlString_VerifyWithVerifyXmlString_ReturnsTrue()
    {
        // Arrange
        string xmlString = "<document><content>Sensitive content</content></document>";

        // Act
        string signedXml = _service.SignXmlString(xmlString);
        bool isValid = _service.VerifyXmlString(signedXml);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void SignDocument_ComplexXml_PreservesStructure()
    {
        // Arrange
        string complexXml = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<invoice>
    <header>
        <number>INV-001</number>
        <date>2024-01-15</date>
    </header>
    <items>
        <item>
            <description>Widget</description>
            <quantity>10</quantity>
            <price>19.99</price>
        </item>
    </items>
    <total>199.90</total>
</invoice>";

        // Act
        string signedXml = _service.SignXmlString(complexXml);

        // Assert
        Assert.NotNull(signedXml);
        Assert.Contains("<number>INV-001</number>", signedXml);
        Assert.Contains("<total>199.90</total>", signedXml);
        Assert.Contains("<Signature", signedXml);

        bool isValid = _service.VerifyXmlString(signedXml);
        Assert.True(isValid);
    }

    [Fact]
    public void SignDocument_WithNamespace_WorksCorrectly()
    {
        // Arrange
        string xmlWithNamespace = @"<?xml version=""1.0""?>
<root xmlns=""http://example.com/ns"">
    <element>Value</element>
</root>";

        // Act
        string signedXml = _service.SignXmlString(xmlWithNamespace);

        // Assert
        Assert.NotNull(signedXml);
        Assert.Contains("xmlns=\"http://example.com/ns\"", signedXml);

        bool isValid = _service.VerifyXmlString(signedXml);
        Assert.True(isValid);
    }

    [Fact]
    public void SignDocument_SigningTwice_CreatesTwoSignatures()
    {
        // Arrange
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml("<root><data>Document to sign twice</data></root>");

        // Act
        _service.SignDocument(xmlDoc);
        string signedTwice = _service.SignDocument(xmlDoc);

        // Assert
        var doc = new XmlDocument();
        doc.PreserveWhitespace = true;
        doc.LoadXml(signedTwice);

        var signatures = doc.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
        Assert.Equal(2, signatures.Count);
    }

    [Fact]
    public void VerifyDocument_NoSignature_ReturnsFalse()
    {
        // Arrange
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml("<root><data>Unsigned document</data></root>");

        // Act
        bool isValid = _service.VerifySignature(xmlDoc);

        // Assert
        Assert.False(isValid, "Unsigned document should return false");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SignXmlString_NullOrEmptyXml_ThrowsArgumentException(string? xmlString)
    {
        // Act & Assert
        Assert.ThrowsAny<ArgumentException>(() => _service.SignXmlString(xmlString!));
    }

    [Fact]
    public void VerifySignature_RemovedSignatureElement_ReturnsFalse()
    {
        // Arrange
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml("<root><data>Test</data></root>");
        string signedXml = _service.SignDocument(xmlDoc);

        var tamperedDoc = new XmlDocument();
        tamperedDoc.PreserveWhitespace = true;
        tamperedDoc.LoadXml(signedXml);

        // Remove the signature element
        var signatureNode = tamperedDoc.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")
            .Cast<XmlNode>()
            .FirstOrDefault();
        if (signatureNode != null && signatureNode.ParentNode != null)
        {
            signatureNode.ParentNode.RemoveChild(signatureNode);
        }

        // Act
        bool isValid = _service.VerifySignature(tamperedDoc);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void SignAndVerify_SpecialCharacters_WorksCorrectly()
    {
        // Arrange
        string xmlWithSpecialChars = "<root><data>Test with &lt;special&gt; characters &amp; symbols</data></root>";

        // Act
        string signedXml = _service.SignXmlString(xmlWithSpecialChars);
        bool isValid = _service.VerifyXmlString(signedXml);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void SignDocument_WithAttributes_PreservesAttributes()
    {
        // Arrange
        string xmlWithAttrs = @"<root id=""main"" version=""1.0"">
    <data status=""active"">Content</data>
</root>";

        // Act
        string signedXml = _service.SignXmlString(xmlWithAttrs);

        // Assert
        Assert.Contains("id=\"main\"", signedXml);
        Assert.Contains("version=\"1.0\"", signedXml);
        Assert.Contains("status=\"active\"", signedXml);

        bool isValid = _service.VerifyXmlString(signedXml);
        Assert.True(isValid);
    }
}
