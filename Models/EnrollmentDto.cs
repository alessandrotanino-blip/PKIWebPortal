namespace PkiPortal.Models;

public class CertificateSubmissionRequest
{
    public string? CaId { get; set; }
    public string TemplateName { get; set; } = string.Empty;
    public string CsrPem { get; set; } = string.Empty;
    public string? PrivateKeyPem { get; set; } // Chiave privata opzionale (per generazione PFX post-approvazione)
    public string? SanAttribute { get; set; } // Opzionale: formato AD CS "san:dns=host1&dns=host2"
    public string? RequesterComments { get; set; }
}

public class CertificateSubmissionResponse
{
    public bool Success { get; set; }
    public string Disposition { get; set; } = string.Empty; // "Issued", "UnderSubmission", "Denied", "Failed"
    public int RequestId { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
    public string? CertificatePem { get; set; }
    public string? CertificateChainPem { get; set; }
    public string? CaCertificatePem { get; set; }
    public string? P7bBase64 { get; set; }
    public string? PrivateKeyPem { get; set; }
    public string? RequesterUser { get; set; }
    public string? SubjectCommonName { get; set; }
    public string? TemplateDisplayName { get; set; }
    public bool HasPrivateKey => !string.IsNullOrEmpty(PrivateKeyPem);
    public string? RawOutput { get; set; }
}

public class CertificateStatusQueryRequest
{
    public string? CaId { get; set; }
    public int RequestId { get; set; }
}

public class CsrParseRequest
{
    public string CsrPem { get; set; } = string.Empty;
}

public class CsrParseResponse
{
    public bool Success { get; set; }
    public string? Subject { get; set; }
    public string? CommonName { get; set; }
    public List<string> SubjectAlternativeNames { get; set; } = new();
    public string? KeyAlgorithm { get; set; }
    public int KeySize { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Template pubblicato sulla CA, scoperto tramite certutil -CATemplates.
/// </summary>
public class PublishedTemplate
{
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Validità (in giorni) letta direttamente dalla definizione AD CS del
    /// template (proprietà KeyUsagePeriod, via certutil -template).
    /// Non è un valore scelto dall'amministratore del portale.
    /// Null se la CA non espone la proprietà o la lettura non è andata a buon fine.
    /// </summary>
    public int? ValidityDays { get; set; }
}

public class TemplateDiscoveryRequest
{
    public string? CaId { get; set; }
    public string? ConfigString { get; set; }
    public string? AuthMode { get; set; }
    public string? CredentialTarget { get; set; }
    public bool UseSimulator { get; set; }
}

public class TemplateDiscoveryResponse
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public string? RawOutput { get; set; }
    public List<PublishedTemplate> Templates { get; set; } = new();
}
