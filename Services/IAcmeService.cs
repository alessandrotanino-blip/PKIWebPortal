using PkiPortal.Models;

namespace PkiPortal.Services;

public interface IAcmeService
{
    AcmeDirectory GetDirectory(string baseUrl);
    string CreateNonce();

    Task<(IResult Result, string NewNonce)> HandleNewAccountAsync(AcmeJwsRequest jws, string baseUrl);
    Task<(IResult Result, string NewNonce)> HandleGetAccountAsync(string accountId, AcmeJwsRequest? jws, string baseUrl);
    Task<(IResult Result, string NewNonce)> HandleGetOrdersAsync(string accountId, AcmeJwsRequest? jws, string baseUrl);
    Task<(IResult Result, string NewNonce)> HandleNewOrderAsync(AcmeJwsRequest jws, string baseUrl);
    Task<(IResult Result, string NewNonce)> HandleGetOrderAsync(string orderId, AcmeJwsRequest? jws, string baseUrl);
    Task<(IResult Result, string NewNonce)> HandleGetAuthorizationAsync(string authId, AcmeJwsRequest? jws, string baseUrl);
    Task<(IResult Result, string NewNonce)> HandleChallengeAsync(string authId, string type, AcmeJwsRequest jws, string baseUrl);
    Task<(IResult Result, string NewNonce)> HandleFinalizeOrderAsync(string orderId, AcmeJwsRequest jws, string baseUrl);
    Task<(IResult Result, string NewNonce)> HandleGetCertificateAsync(string orderId, AcmeJwsRequest? jws, string baseUrl);
    Task<(IResult Result, string NewNonce)> HandleRevokeCertAsync(AcmeJwsRequest jws, string baseUrl);
    Task<(IResult Result, string NewNonce)> HandleKeyChangeAsync(AcmeJwsRequest jws, string baseUrl);
}
