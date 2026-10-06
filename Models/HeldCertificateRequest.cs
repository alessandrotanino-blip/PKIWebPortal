namespace PkiPortal.Models;

/// <summary>
/// Rappresenta una richiesta certificato trattenuta dal portale (post-submission hold).
/// Quando un template ha RequiresApproval=true e la CA emette il certificato,
/// il portale lo trattiene qui fino ad approvazione manuale dell'admin.
/// </summary>
public class HeldCertificateRequest
{
    public string HoldId { get; set; } = string.Empty;
    public DateTime SubmittedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ReviewedAt { get; set; }

    // Dati della richiesta originale
    public string CaId { get; set; } = string.Empty;
    public string TemplateName { get; set; } = string.Empty;
    public string TemplateDisplayName { get; set; } = string.Empty;
    public string? RequesterComments { get; set; }
    public string? RequesterUser { get; set; }
    public string? SubjectCommonName { get; set; }
    public string? SanAttribute { get; set; }

    // Dati del certificato emesso dalla CA (trattenuto)
    public int CaRequestId { get; set; }
    public string? CertificatePem { get; set; }
    public string? CertificateChainPem { get; set; }
    public string? CaCertificatePem { get; set; }
    public string? P7bBase64 { get; set; }
    public string? PrivateKeyPem { get; set; } // Chiave privata in formato PEM (per download PFX)

    // Stato nel portale
    public HoldStatus Status { get; set; } = HoldStatus.PendingApproval;
    public string? ReviewedBy { get; set; }
    public string? RejectionReason { get; set; }
}

public enum HoldStatus
{
    PendingApproval,
    Approved,
    Rejected,
    Issued,
    UnderSubmission
}
