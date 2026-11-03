using System.Text.Json;
using Microsoft.Extensions.Options;
using PkiPortal.Models;

namespace PkiPortal.Services;

public class AcmeService : IAcmeService
{
    private readonly IAcmeStore _store;
    private readonly IAcmeCryptoService _crypto;
    private readonly IAcmeValidationService _validator;
    private readonly IAdcsService _adcsService;
    private readonly IOptionsMonitor<PortalConfig> _portalConfigMonitor;
    private readonly IOptionsMonitor<AcmeConfig> _acmeConfigMonitor;
    private readonly ILogger<AcmeService> _logger;

    public AcmeService(
        IAcmeStore store,
        IAcmeCryptoService crypto,
        IAcmeValidationService validator,
        IAdcsService adcsService,
        IOptionsMonitor<PortalConfig> portalConfigMonitor,
        IOptionsMonitor<AcmeConfig> acmeConfigMonitor,
        ILogger<AcmeService> logger)
    {
        _store = store;
        _crypto = crypto;
        _validator = validator;
        _adcsService = adcsService;
        _portalConfigMonitor = portalConfigMonitor;
        _acmeConfigMonitor = acmeConfigMonitor;
        _logger = logger;
    }

    private AcmeConfig Config
    {
        get
        {
            var cfg = _acmeConfigMonitor.CurrentValue;
            if (cfg != null && !string.IsNullOrEmpty(cfg.DefaultTemplateName)) return cfg;
            return _portalConfigMonitor.CurrentValue.Acme ?? new AcmeConfig();
        }
    }

    private PortalConfig PortalConfig => _portalConfigMonitor.CurrentValue;

    public string CreateNonce() => _store.CreateNonce();

    public AcmeDirectory GetDirectory(string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        return new AcmeDirectory
        {
            NewNonce = $"{baseUrl}/acme/new-nonce",
            NewAccount = $"{baseUrl}/acme/new-account",
            NewOrder = $"{baseUrl}/acme/new-order",
            RevokeCert = $"{baseUrl}/acme/revoke-cert",
            KeyChange = $"{baseUrl}/acme/key-change",
            Meta = new AcmeDirectoryMeta
            {
                TermsOfService = $"{baseUrl}{Config.TermsOfServiceUrl}",
                Website = baseUrl,
                ExternalAccountRequired = false
            }
        };
    }

    public async Task<(IResult Result, string NewNonce)> HandleNewAccountAsync(AcmeJwsRequest jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        var (authOk, errorResult, header, account, _) = await VerifyJwsAsync(jws, requireJwk: true);
        if (!authOk) return (errorResult!, newNonce);

        if (header!.Jwk == null)
        {
            return (Problem(AcmeErrorTypes.Malformed, "Per new-account è obbligatorio specificare la chiave pubblica 'jwk' nell'header JWS."), newNonce);
        }

        string thumbprint;
        try
        {
            thumbprint = _crypto.ComputeJwkThumbprint(header.Jwk);
        }
        catch (Exception ex)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Chiave JWK non valida: {ex.Message}"), newNonce);
        }

        AcmeNewAccountRequest req;
        try
        {
            string payloadJson = _crypto.Base64UrlDecodeToString(jws.Payload);
            if (string.IsNullOrWhiteSpace(payloadJson))
            {
                req = new AcmeNewAccountRequest();
            }
            else
            {
                req = JsonSerializer.Deserialize<AcmeNewAccountRequest>(payloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                    ?? new AcmeNewAccountRequest();
            }
        }
        catch (Exception ex)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Payload JSON non valido: {ex.Message}"), newNonce);
        }

        // Verifica se l'account esiste già
        var existing = await _store.GetAccountByThumbprintAsync(thumbprint);
        if (existing != null)
        {
            string loc = $"{baseUrl}/acme/account/{existing.Id}";
            var res = Results.Ok(existing);
            return (new CustomLocationResult(res, loc), newNonce);
        }

        if (req.OnlyReturnExisting == true)
        {
            return (Problem(AcmeErrorTypes.AccountDoesNotExist, "Nessun account esistente trovato per la chiave specificata.", 404), newNonce);
        }

        if (Config.RequireTermsOfServiceAgreed && req.TermsOfServiceAgreed != true)
        {
            return (Problem(AcmeErrorTypes.Unauthorized, "È necessario accettare i termini di servizio ('termsOfServiceAgreed: true') per registrarsi.", 403), newNonce);
        }

        string accountId = $"acc-{Guid.NewGuid():N}";
        var newAccount = new AcmeAccount
        {
            Id = accountId,
            Status = "valid",
            Contact = req.Contact ?? new(),
            TermsOfServiceAgreed = req.TermsOfServiceAgreed == true,
            Orders = $"{baseUrl}/acme/account/{accountId}/orders",
            CreatedAt = DateTime.UtcNow,
            Jwk = header.Jwk,
            Thumbprint = thumbprint
        };

        await _store.SaveAccountAsync(newAccount);
        _logger.LogInformation("Nuovo account ACME creato con successo: ID {AccountId}, Thumbprint {Thumbprint}", accountId, thumbprint);

        string locationUrl = $"{baseUrl}/acme/account/{accountId}";
        var createdResult = Results.Created(locationUrl, newAccount);
        return (new CustomLocationResult(createdResult, locationUrl), newNonce);
    }

    public async Task<(IResult Result, string NewNonce)> HandleGetAccountAsync(string accountId, AcmeJwsRequest? jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        if (jws != null && !string.IsNullOrEmpty(jws.Protected))
        {
            var (authOk, errorResult, _, _, _) = await VerifyJwsAsync(jws, requireJwk: false);
            if (!authOk) return (errorResult!, newNonce);
        }

        var account = await _store.GetAccountByIdAsync(accountId);
        if (account == null)
        {
            return (Problem(AcmeErrorTypes.AccountDoesNotExist, $"Account con ID '{accountId}' non trovato.", 404), newNonce);
        }

        account.Orders = $"{baseUrl}/acme/account/{accountId}/orders";
        return (Results.Ok(account), newNonce);
    }

    public async Task<(IResult Result, string NewNonce)> HandleGetOrdersAsync(string accountId, AcmeJwsRequest? jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        if (jws != null && !string.IsNullOrEmpty(jws.Protected))
        {
            var (authOk, errorResult, _, _, _) = await VerifyJwsAsync(jws, requireJwk: false);
            if (!authOk) return (errorResult!, newNonce);
        }

        var account = await _store.GetAccountByIdAsync(accountId);
        if (account == null)
        {
            return (Problem(AcmeErrorTypes.AccountDoesNotExist, $"Account '{accountId}' non trovato.", 404), newNonce);
        }

        var orders = await _store.GetOrdersByAccountIdAsync(accountId);
        var orderUrls = orders.Select(o => $"{baseUrl}/acme/order/{o.Id}").ToList();

        return (Results.Ok(new { orders = orderUrls }), newNonce);
    }

    public async Task<(IResult Result, string NewNonce)> HandleNewOrderAsync(AcmeJwsRequest jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        var (authOk, errorResult, header, account, payloadJson) = await VerifyJwsAsync(jws, requireJwk: false);
        if (!authOk) return (errorResult!, newNonce);

        AcmeNewOrderRequest req;
        try
        {
            req = JsonSerializer.Deserialize<AcmeNewOrderRequest>(payloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? new AcmeNewOrderRequest();
        }
        catch (Exception ex)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Payload new-order JSON non valido: {ex.Message}"), newNonce);
        }

        if (req.Identifiers == null || req.Identifiers.Count == 0)
        {
            return (Problem(AcmeErrorTypes.Malformed, "È necessario specificare almeno un identifier DNS per il certificato."), newNonce);
        }

        foreach (var ident in req.Identifiers)
        {
            if (!string.Equals(ident.Type, "dns", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(ident.Value))
            {
                return (Problem(AcmeErrorTypes.RejectedIdentifier, $"Identificatore non supportato: '{ident.Type}' : '{ident.Value}'. Solo DNS supportati."), newNonce);
            }
        }

        string orderId = $"ord-{Guid.NewGuid():N}";
        var authUrls = new List<string>();

        // Creazione autorizzazioni e challenge per ciascun identifier
        foreach (var ident in req.Identifiers)
        {
            string authId = $"auth-{Guid.NewGuid():N}";
            string authUrl = $"{baseUrl}/acme/authz/{authId}";
            authUrls.Add(authUrl);

            string tokenHttp = GenerateToken();
            string tokenDns = GenerateToken();

            var challHttp = new AcmeChallenge
            {
                Id = $"chall-http-{Guid.NewGuid():N}",
                AuthId = authId,
                OrderId = orderId,
                Type = "http-01",
                Url = $"{baseUrl}/acme/chall/{authId}/http-01",
                Token = tokenHttp,
                Status = "pending"
            };

            var challDns = new AcmeChallenge
            {
                Id = $"chall-dns-{Guid.NewGuid():N}",
                AuthId = authId,
                OrderId = orderId,
                Type = "dns-01",
                Url = $"{baseUrl}/acme/chall/{authId}/dns-01",
                Token = tokenDns,
                Status = "pending"
            };

            await _store.SaveChallengeAsync(challHttp);
            await _store.SaveChallengeAsync(challDns);

            var auth = new AcmeAuthorization
            {
                Id = authId,
                OrderId = orderId,
                Status = "pending",
                Expires = DateTime.UtcNow.AddDays(7).ToString("o"),
                Identifier = ident,
                Challenges = new List<AcmeChallenge> { challHttp, challDns }
            };

            await _store.SaveAuthorizationAsync(auth);
        }

        string caId = !string.IsNullOrEmpty(Config.DefaultCaId) ? Config.DefaultCaId : PortalConfig.DefaultCaId;
        string tpl = !string.IsNullOrEmpty(Config.DefaultTemplateName) ? Config.DefaultTemplateName : "WebServer";

        var order = new AcmeOrder
        {
            Id = orderId,
            AccountId = account!.Id,
            Status = "pending",
            Expires = DateTime.UtcNow.AddDays(7).ToString("o"),
            Identifiers = req.Identifiers,
            Authorizations = authUrls,
            Finalize = $"{baseUrl}/acme/order/{orderId}/finalize",
            CreatedAt = DateTime.UtcNow,
            CaId = caId,
            TemplateName = tpl
        };

        await _store.SaveOrderAsync(order);
        _logger.LogInformation("Nuovo ordine ACME creato: ID {OrderId} per conto di {AccountId} (Domini: {Domains})",
            orderId, account.Id, string.Join(", ", req.Identifiers.Select(i => i.Value)));

        string location = $"{baseUrl}/acme/order/{orderId}";
        var created = Results.Created(location, order);
        return (new CustomLocationResult(created, location), newNonce);
    }

    public async Task<(IResult Result, string NewNonce)> HandleGetOrderAsync(string orderId, AcmeJwsRequest? jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        if (jws != null && !string.IsNullOrEmpty(jws.Protected))
        {
            var (authOk, errorResult, _, _, _) = await VerifyJwsAsync(jws, requireJwk: false);
            if (!authOk) return (errorResult!, newNonce);
        }

        var order = await _store.GetOrderByIdAsync(orderId);
        if (order == null)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Ordine con ID '{orderId}' non trovato.", 404), newNonce);
        }

        // Se l'ordine è in processing (es. approvazione AD CS trattenuta), verifichiamo se è stato approvato
        if (order.Status == "processing" && order.CaRequestId > 0)
        {
            try
            {
                var checkRes = await _adcsService.RetrievePendingCertificateAsync(order.CaId, order.CaRequestId);
                if (checkRes.Success && checkRes.Disposition == "Issued" && !string.IsNullOrEmpty(checkRes.CertificatePem))
                {
                    order.Status = "valid";
                    order.CertificatePem = checkRes.CertificatePem;
                    order.CertificateChainPem = checkRes.CertificateChainPem;
                    order.CaCertificatePem = checkRes.CaCertificatePem;
                    order.Certificate = $"{baseUrl}/acme/cert/{order.Id}";
                    await _store.SaveOrderAsync(order);
                    _logger.LogInformation("Ordine ACME {OrderId} completato post-approvazione (#ID {ReqId}).", order.Id, order.CaRequestId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Verifica stato pending AD CS per ordine {OrderId} non riuscita.", order.Id);
            }
        }

        order.Finalize = $"{baseUrl}/acme/order/{orderId}/finalize";
        if (order.Status == "valid" && !string.IsNullOrEmpty(order.CertificatePem))
        {
            order.Certificate = $"{baseUrl}/acme/cert/{orderId}";
        }

        return (Results.Ok(order), newNonce);
    }

    public async Task<(IResult Result, string NewNonce)> HandleGetAuthorizationAsync(string authId, AcmeJwsRequest? jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        if (jws != null && !string.IsNullOrEmpty(jws.Protected))
        {
            var (authOk, errorResult, _, _, _) = await VerifyJwsAsync(jws, requireJwk: false);
            if (!authOk) return (errorResult!, newNonce);
        }

        var auth = await _store.GetAuthorizationByIdAsync(authId);
        if (auth == null)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Autorizzazione '{authId}' non trovata.", 404), newNonce);
        }

        return (Results.Ok(auth), newNonce);
    }

    public async Task<(IResult Result, string NewNonce)> HandleChallengeAsync(string authId, string type, AcmeJwsRequest jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        var (authOk, errorResult, _, account, _) = await VerifyJwsAsync(jws, requireJwk: false);
        if (!authOk) return (errorResult!, newNonce);

        var challenge = await _store.GetChallengeAsync(authId, type);
        if (challenge == null)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Challenge '{type}' per autorizzazione '{authId}' non trovata.", 404), newNonce);
        }

        var auth = await _store.GetAuthorizationByIdAsync(authId);
        if (auth == null)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Autorizzazione '{authId}' non trovata.", 404), newNonce);
        }

        // Se già valida, restituisce lo stato
        if (challenge.Status == "valid")
        {
            return (Results.Ok(challenge), newNonce);
        }

        challenge.Status = "processing";
        await _store.SaveChallengeAsync(challenge);

        string expectedKeyAuth = $"{challenge.Token}.{account!.Thumbprint}";

        if (string.Equals(type, "http-01", StringComparison.OrdinalIgnoreCase))
        {
            var (valid, errorDetail) = await _validator.ValidateHttp01Async(auth.Identifier.Value, challenge.Token, expectedKeyAuth, Config);
            if (valid)
            {
                challenge.Status = "valid";
                challenge.Validated = DateTime.UtcNow.ToString("o");
                challenge.Error = null;
                auth.Status = "valid";
            }
            else
            {
                challenge.Status = "invalid";
                challenge.Error = new AcmeProblem
                {
                    Type = AcmeErrorTypes.IncorrectResponse,
                    Detail = errorDetail ?? "Validazione HTTP-01 fallita.",
                    Status = 400
                };
                auth.Status = "invalid";
            }
        }
        else if (string.Equals(type, "dns-01", StringComparison.OrdinalIgnoreCase))
        {
            // Validazione DNS-01: se in AutoApprove la approviamo direttamente, altrimenti informiamo
            if (string.Equals(Config.ValidationMode, "AutoApprove", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Config.ValidationMode, "None", StringComparison.OrdinalIgnoreCase))
            {
                challenge.Status = "valid";
                challenge.Validated = DateTime.UtcNow.ToString("o");
                auth.Status = "valid";
            }
            else
            {
                challenge.Status = "invalid";
                challenge.Error = new AcmeProblem
                {
                    Type = AcmeErrorTypes.Malformed,
                    Detail = "Validazione automatica DNS-01 richiede configurazione provider DNS AD o ValidationMode 'AutoApprove'.",
                    Status = 400
                };
                auth.Status = "invalid";
            }
        }

        await _store.SaveChallengeAsync(challenge);
        await _store.SaveAuthorizationAsync(auth);

        // Aggiorna lo stato dell'ordine associato
        var order = await _store.GetOrderByIdAsync(challenge.OrderId);
        if (order != null)
        {
            bool allValid = true;
            bool anyInvalid = false;

            foreach (var authUrl in order.Authorizations)
            {
                string aId = authUrl.Split('/').Last();
                var a = await _store.GetAuthorizationByIdAsync(aId);
                if (a == null || a.Status != "valid")
                {
                    allValid = false;
                }
                if (a != null && a.Status == "invalid")
                {
                    anyInvalid = true;
                }
            }

            if (allValid)
            {
                order.Status = "ready";
                _logger.LogInformation("Ordine ACME {OrderId} in stato 'ready' (tutte le challenge validate con successo).", order.Id);
            }
            else if (anyInvalid)
            {
                order.Status = "invalid";
                _logger.LogWarning("Ordine ACME {OrderId} in stato 'invalid' per fallimento challenge.", order.Id);
            }

            await _store.SaveOrderAsync(order);
        }

        return (Results.Ok(challenge), newNonce);
    }

    public async Task<(IResult Result, string NewNonce)> HandleFinalizeOrderAsync(string orderId, AcmeJwsRequest jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        var (authOk, errorResult, _, account, payloadJson) = await VerifyJwsAsync(jws, requireJwk: false);
        if (!authOk) return (errorResult!, newNonce);

        var order = await _store.GetOrderByIdAsync(orderId);
        if (order == null)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Ordine '{orderId}' non trovato.", 404), newNonce);
        }

        if (order.Status != "ready")
        {
            return (Problem(AcmeErrorTypes.OrderNotReady, $"L'ordine non è nello stato 'ready' (stato attuale: '{order.Status}').", 403), newNonce);
        }

        AcmeFinalizeRequest finalizeReq;
        try
        {
            finalizeReq = JsonSerializer.Deserialize<AcmeFinalizeRequest>(payloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? new AcmeFinalizeRequest();
        }
        catch (Exception ex)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Payload finalize JSON non valido: {ex.Message}"), newNonce);
        }

        if (string.IsNullOrWhiteSpace(finalizeReq.Csr))
        {
            return (Problem(AcmeErrorTypes.Malformed, "Il campo 'csr' in formato Base64Url DER è obbligatorio."), newNonce);
        }

        string csrPem;
        try
        {
            byte[] derBytes = _crypto.Base64UrlDecode(finalizeReq.Csr);
            csrPem = _crypto.ConvertDerCsrToPem(derBytes);
        }
        catch (Exception ex)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Decodifica CSR non riuscita: {ex.Message}"), newNonce);
        }

        string caId = !string.IsNullOrEmpty(order.CaId) ? order.CaId : (Config.DefaultCaId ?? PortalConfig.DefaultCaId);
        string templateName = !string.IsNullOrEmpty(order.TemplateName) ? order.TemplateName : Config.DefaultTemplateName;

        _logger.LogInformation("Sottomissione CSR ad AD CS per ordine ACME {OrderId} (CA: {CaId}, Template: {Template})",
            order.Id, caId, templateName);

        var submission = new CertificateSubmissionRequest
        {
            CaId = caId,
            TemplateName = templateName,
            CsrPem = csrPem,
            RequesterComments = $"ACME order {order.Id} (Account: {account!.Id})"
        };

        try
        {
            var adcsResponse = await _adcsService.SubmitCertificateRequestAsync(submission);

            if (adcsResponse.Success && string.Equals(adcsResponse.Disposition, "Issued", StringComparison.OrdinalIgnoreCase))
            {
                order.Status = "valid";
                order.CaRequestId = adcsResponse.RequestId;
                order.CertificatePem = adcsResponse.CertificatePem;
                order.CertificateChainPem = adcsResponse.CertificateChainPem;
                order.CaCertificatePem = adcsResponse.CaCertificatePem;
                order.Certificate = $"{baseUrl}/acme/cert/{order.Id}";

                await _store.SaveOrderAsync(order);
                _logger.LogInformation("Certificato ACME emesso con successo per ordine {OrderId} (#ID AD CS: {ReqId}).",
                    order.Id, adcsResponse.RequestId);

                return (Results.Ok(order), newNonce);
            }
            else if (string.Equals(adcsResponse.Disposition, "UnderSubmission", StringComparison.OrdinalIgnoreCase))
            {
                order.Status = "processing";
                order.CaRequestId = adcsResponse.RequestId;

                await _store.SaveOrderAsync(order);
                _logger.LogInformation("Ordine ACME {OrderId} trattenuto in attesa di approvazione (#ID AD CS: {ReqId}).",
                    order.Id, adcsResponse.RequestId);

                return (Results.Ok(order), newNonce);
            }
            else
            {
                order.Status = "invalid";
                await _store.SaveOrderAsync(order);

                string detail = !string.IsNullOrEmpty(adcsResponse.StatusMessage)
                    ? adcsResponse.StatusMessage
                    : "Emissione rifiutata o fallita sulla CA AD CS.";
                _logger.LogWarning("Emissione AD CS fallita per ordine ACME {OrderId}: {Detail}", order.Id, detail);

                return (Problem(AcmeErrorTypes.ServerInternal, $"Emissione AD CS fallita: {detail}", 500), newNonce);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Errore imprevisto durante l'invio del CSR ad AD CS.");
            order.Status = "invalid";
            await _store.SaveOrderAsync(order);
            return (Problem(AcmeErrorTypes.ServerInternal, $"Errore interno durante l'emissione: {ex.Message}", 500), newNonce);
        }
    }

    public async Task<(IResult Result, string NewNonce)> HandleGetCertificateAsync(string orderId, AcmeJwsRequest? jws, string baseUrl)
    {
        string newNonce = CreateNonce();

        if (jws != null && !string.IsNullOrEmpty(jws.Protected))
        {
            var (authOk, errorResult, _, _, _) = await VerifyJwsAsync(jws, requireJwk: false);
            if (!authOk) return (errorResult!, newNonce);
        }

        var order = await _store.GetOrderByIdAsync(orderId);
        if (order == null || order.Status != "valid" || string.IsNullOrEmpty(order.CertificatePem))
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Certificato per ordine '{orderId}' non trovato o non ancora emesso.", 404), newNonce);
        }

        // Assembla la catena secondo RFC 8555 Sez. 7.4.2 (application/pem-certificate-chain):
        // Foglia (End-Entity) seguito da intermedi e Root CA.
        string chain = order.CertificatePem.Trim();
        string caChain = (order.CertificateChainPem ?? order.CaCertificatePem ?? string.Empty).Trim();
        if (!string.IsNullOrEmpty(caChain))
        {
            chain = $"{chain}\n{caChain}";
        }

        return (Results.Content(chain, "application/pem-certificate-chain"), newNonce);
    }

    public Task<(IResult Result, string NewNonce)> HandleRevokeCertAsync(AcmeJwsRequest jws, string baseUrl)
    {
        string newNonce = CreateNonce();
        // RFC 8555 Sez. 7.6
        _logger.LogInformation("Ricevuta richiesta revoca certificato ACME.");
        return Task.FromResult<(IResult, string)>((Results.Ok(), newNonce));
    }

    public Task<(IResult Result, string NewNonce)> HandleKeyChangeAsync(AcmeJwsRequest jws, string baseUrl)
    {
        string newNonce = CreateNonce();
        // RFC 8555 Sez. 7.5
        _logger.LogInformation("Ricevuta richiesta cambio chiave account ACME.");
        return Task.FromResult<(IResult, string)>((Results.Ok(), newNonce));
    }

    private async Task<(bool Success, IResult? ErrorResult, AcmeJwsHeader? Header, AcmeAccount? Account, string PayloadJson)> VerifyJwsAsync(
        AcmeJwsRequest jws,
        bool requireJwk)
    {
        if (string.IsNullOrWhiteSpace(jws.Protected) || string.IsNullOrWhiteSpace(jws.Signature))
        {
            return (false, Problem(AcmeErrorTypes.Malformed, "Header protetto o firma JWS mancanti."), null, null, string.Empty);
        }

        var header = _crypto.ParseProtectedHeader(jws.Protected);
        if (header == null)
        {
            return (false, Problem(AcmeErrorTypes.Malformed, "Header protetto JWS non interpretabile."), null, null, string.Empty);
        }

        // Verifica Nonce anti-replay
        if (string.IsNullOrWhiteSpace(header.Nonce) || !_store.ValidateAndConsumeNonce(header.Nonce))
        {
            return (false, Problem(AcmeErrorTypes.BadNonce, "Nonce anti-replay non valido, scaduto o già utilizzato."), header, null, string.Empty);
        }

        AcmeJwk? keyToVerify = header.Jwk;
        AcmeAccount? account = null;

        if (requireJwk)
        {
            if (header.Jwk == null)
            {
                return (false, Problem(AcmeErrorTypes.Malformed, "La richiesta richiede l'incorporamento del membro 'jwk' nell'header protetto."), header, null, string.Empty);
            }
        }
        else
        {
            if (!string.IsNullOrEmpty(header.Kid))
            {
                // kid = "https://pki.azienda.lan/acme/account/acc-12345"
                string accountId = header.Kid.Split('/').Last();
                account = await _store.GetAccountByIdAsync(accountId);
                if (account == null)
                {
                    return (false, Problem(AcmeErrorTypes.AccountDoesNotExist, $"Account identificato da kid '{header.Kid}' non trovato.", 404), header, null, string.Empty);
                }
                keyToVerify = account.Jwk;
            }
            else if (header.Jwk != null)
            {
                keyToVerify = header.Jwk;
            }
            else
            {
                return (false, Problem(AcmeErrorTypes.Malformed, "L'header JWS deve specificare 'kid' o 'jwk'."), header, null, string.Empty);
            }
        }

        if (keyToVerify == null)
        {
            return (false, Problem(AcmeErrorTypes.Malformed, "Chiave pubblica per la verifica della firma non disponibile."), header, null, string.Empty);
        }

        string payloadStr = jws.Payload ?? string.Empty;
        if (!_crypto.VerifyJwsSignature(jws.Protected, payloadStr, jws.Signature, keyToVerify, out string? verifyErr))
        {
            return (false, Problem(AcmeErrorTypes.Malformed, $"Verifica firma JWS fallita: {verifyErr}"), header, null, string.Empty);
        }

        string payloadJson = string.Empty;
        if (!string.IsNullOrEmpty(jws.Payload))
        {
            try
            {
                payloadJson = _crypto.Base64UrlDecodeToString(jws.Payload);
            }
            catch (Exception ex)
            {
                return (false, Problem(AcmeErrorTypes.Malformed, $"Decodifica payload JWS fallita: {ex.Message}"), header, null, string.Empty);
            }
        }

        return (true, null, header, account, payloadJson);
    }

    private static string GenerateToken()
    {
        byte[] bytes = new byte[24];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string NormalizeBaseUrl(string url)
    {
        return url.TrimEnd('/');
    }

    private static IResult Problem(string type, string detail, int statusCode = 400)
    {
        var problem = new AcmeProblem
        {
            Type = type,
            Detail = detail,
            Status = statusCode
        };
        return Results.Json(problem, contentType: "application/problem+json", statusCode: statusCode);
    }

    /// <summary>
    /// Helper personalizzato per restituire header Location corretto e status code HTTP.
    /// </summary>
    private class CustomLocationResult : IResult
    {
        private readonly IResult _innerResult;
        private readonly string _location;

        public CustomLocationResult(IResult innerResult, string location)
        {
            _innerResult = innerResult;
            _location = location;
        }

        public async Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.Headers.Location = _location;
            await _innerResult.ExecuteAsync(httpContext);
        }
    }
}
