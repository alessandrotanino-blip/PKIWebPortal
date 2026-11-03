using PkiPortal.Models;

namespace PkiPortal.Services;

public interface IAcmeCryptoService
{
    string Base64UrlEncode(byte[] data);
    string Base64UrlEncode(string text);
    byte[] Base64UrlDecode(string input);
    string Base64UrlDecodeToString(string input);

    string ComputeJwkThumbprint(AcmeJwk jwk);
    bool ValidateJwkStrength(AcmeJwk jwk, out string? errorMessage);
    AcmeJwsHeader? ParseProtectedHeader(string protectedHeaderB64);
    bool VerifyJwsSignature(string protectedHeaderB64, string payloadB64, string signatureB64, AcmeJwk jwk, out string? errorMessage);
    string ConvertDerCsrToPem(byte[] derCsr);
}
