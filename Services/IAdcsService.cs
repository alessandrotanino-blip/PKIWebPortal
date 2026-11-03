using PkiPortal.Models;

namespace PkiPortal.Services;

public interface IAdcsService
{
    Task<List<CaConfig>> GetAvailableCAsAsync();
    Task<CaConfig?> GetCaConfigAsync(string? caId);
    Task<CertificateSubmissionResponse> SubmitCertificateRequestAsync(CertificateSubmissionRequest request);
    Task<CertificateSubmissionResponse> RetrievePendingCertificateAsync(string? caId, int requestId);

    /// <summary>
    /// SECURITY (2.3.1): revoca di un certificato già emesso presso la CA
    /// (revoca ACME RFC 8555 Sez. 7.6). serialNumber in esadecimale senza
    /// prefisso.
    /// </summary>
    Task<CertificateRevocationResponse> RevokeCertificateAsync(string? caId, string serialNumber, string reason);
    Task<List<PublishedTemplate>> GetPublishedTemplatesAsync(string caId);
    Task<TemplateDiscoveryResponse> DiscoverTemplatesAsync(TemplateDiscoveryRequest request);
}
