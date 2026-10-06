using PkiPortal.Models;

namespace PkiPortal.Services;

public interface IAdcsService
{
    Task<List<CaConfig>> GetAvailableCAsAsync();
    Task<CaConfig?> GetCaConfigAsync(string? caId);
    Task<CertificateSubmissionResponse> SubmitCertificateRequestAsync(CertificateSubmissionRequest request);
    Task<CertificateSubmissionResponse> RetrievePendingCertificateAsync(string? caId, int requestId);
    Task<List<PublishedTemplate>> GetPublishedTemplatesAsync(string caId);
    Task<TemplateDiscoveryResponse> DiscoverTemplatesAsync(TemplateDiscoveryRequest request);
}
