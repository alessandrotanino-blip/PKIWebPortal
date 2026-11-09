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
    public string? ErrorCode { get; set; }
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

/// <summary>
/// SECURITY (2.3.1): risposta di revoca certificato AD CS (revoca ACME RFC 8555 Sez. 7.6).
/// </summary>
public class CertificateRevocationResponse
{
    public bool Success { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
    public string? RawOutput { get; set; }
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

/// <summary>
/// Richiesta di rilevamento dei nomi CA ospitati su un server AD CS.
/// Il nome della CA (e quindi la ConfigString "server\Nome-CA") può essere
/// dedotto automaticamente una volta identificato il dominio e il server:
/// 1) interrogazione del partizionamento AD Configuration (attributo caDnsName
///    degli oggetti CA), con credenziali esplicite in modalità CredentialManager;
/// 2) fallback sulla pagina CAPL del server CA (http/https://server/CertSrv/CertSrv.dll).
/// </summary>
public class CaDiscoveryRequest
{
    /// <summary>Foresta o dominio AD da interrogare (opzionale ma consigliato).</summary>
    public string? ForestOrDomain { get; set; }

    /// <summary>Hostname/DNS del server CA (es. "vdpki.vd.ld"). Obbligatorio.</summary>
    public string? CaServer { get; set; }

    /// <summary>"LocalIdentity" o "CredentialManager" (come in TemplateDiscoveryRequest).</summary>
    public string? AuthMode { get; set; }

    /// <summary>Target della credenziale in Windows Credential Manager (default: CaServer).</summary>
    public string? CredentialTarget { get; set; }
}

public class CaDiscoveryResponse
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }

    /// <summary>Nomi CA rilevati (es. "Foresta1-IssuingCA"), deduplicati e ordinati.</summary>
    public List<string> CaNames { get; set; } = new();

    /// <summary>Fonte del rilevamento: "ad", "capl" o "ad+capl". Null se nessun nome trovato.</summary>
    public string? Source { get; set; }

    /// <summary>
    /// Avvertenza non bloccante (es. CAPL letta con validazione TLS
    /// disattivata perché il certificato della CA non è fidato dal processo).
    /// </summary>
    public string? Warning { get; set; }
}
