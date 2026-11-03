using PkiPortal.Models;

namespace PkiPortal.Services;

public interface IAcmeValidationService
{
    Task<(bool Success, string? ErrorDetail)> ValidateHttp01Async(string identifier, string token, string expectedKeyAuth, AcmeConfig config);
}
