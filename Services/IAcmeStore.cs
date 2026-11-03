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
}
