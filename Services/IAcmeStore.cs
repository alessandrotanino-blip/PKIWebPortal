using PkiPortal.Models;

namespace PkiPortal.Services;

public interface IAcmeStore
{
    string CreateNonce();
    bool ValidateAndConsumeNonce(string nonce);

    Task<AcmeAccount?> GetAccountByIdAsync(string accountId);
    Task<AcmeAccount?> GetAccountByThumbprintAsync(string thumbprint);
    Task<AcmeAccount> SaveAccountAsync(AcmeAccount account);

    Task<AcmeOrder?> GetOrderByIdAsync(string orderId);
    Task<List<AcmeOrder>> GetOrdersByAccountIdAsync(string accountId);
    Task<AcmeOrder> SaveOrderAsync(AcmeOrder order);

    Task<AcmeAuthorization?> GetAuthorizationByIdAsync(string authId);
    Task<AcmeAuthorization> SaveAuthorizationAsync(AcmeAuthorization auth);

    Task<AcmeChallenge?> GetChallengeAsync(string authId, string type);
    Task<AcmeChallenge> SaveChallengeAsync(AcmeChallenge challenge);

    /// <summary>
    /// SECURITY (2.3.1): restituisce l'ordine il cui certificato emesso ha il
    /// thumbprint specificato (per la revoca ACME, RFC 8555 Sez. 7.6).
    /// </summary>
    Task<AcmeOrder?> FindOrderByCertificateThumbprintAsync(string thumbprint);

    /// <summary>
    /// Esporta tutti i dati ACME (account, ordini, autorizzazioni, challenge) in JSON per migrazione/backup (v2.7.0).
    /// </summary>
    Task<string> ExportDataJsonAsync();

    /// <summary>
    /// Importa i dati ACME da JSON (migrazione/backup) e li persiste su disco (v2.7.0).
    /// </summary>
    Task<int> ImportDataJsonAsync(string json, bool merge);
}
