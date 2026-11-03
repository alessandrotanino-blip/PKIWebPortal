using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Options;
using PkiPortal.Models;

namespace PkiPortal.Services;

public class AcmeService : IAcmeService
{
    // SECURITY (2.3.1): limite massimo di identifier per singolo ordine
    // (mitiga DoS: ogni identifier genera autorizzazione + 2 challenge +
    // verifiche e persistenze).
    private const int MaxIdentifiersPerOrder = 10;

    private readonly IAcmeStore _store;
    private readonly IAcmeCryptoService _crypto;
    private readonly IAcmeValidationService _validator;
    private readonly IAdcsService _adcsService;
    private readonly ICsrParserService _csrParser;
    private readonly IOptionsMonitor<PortalConfig> _portalConfigMonitor;
    private readonly IOptionsMonitor<AcmeConfig> _acmeConfigMonitor;
    private readonly ILogger<AcmeService> _logger;

    // Lock per ordine: serializza le transizioni di stato (finalize,
    // aggiornamento challenge, check processing) sullo stesso ordine.
    // (SemaphoreSlim e non lock: il corpo contiene chiamate async/await.)
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _orderLocks = new();
    // Lock per la creazione account (anti race check-then-insert su thumbprint).
    private readonly SemaphoreSlim _newAccountLock = new(1, 1);

    public AcmeService(
        IAcmeStore store,
        IAcmeCryptoService crypto,
        IAcmeValidationService validator,
        IAdcsService adcsService,
        ICsrParserService csrParser,
        IOptionsMonitor<PortalConfig> portalConfigMonitor,
        IOptionsMonitor<AcmeConfig> acmeConfigMonitor,
        ILogger<AcmeService> logger)
    {
        _store = store;
        _crypto = crypto;
        _validator = validator;
        _adcsService = adcsService;
        _csrParser = csrParser;
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

    private SemaphoreSlim OrderLock(string orderId) => _orderLocks.GetOrAdd(orderId, _ => new SemaphoreSlim(1, 1));

    public string CreateNonce() => _store.CreateNonce();

    public AcmeDirectory GetDirectory(string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string? tos = Config.TermsOfServiceUrl;
        string tosUrl = tos != null && tos.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? tos : $"{baseUrl}{tos}";
        return new AcmeDirectory
        {
            NewNonce = $"{baseUrl}/acme/new-nonce",
            NewAccount = $"{baseUrl}/acme/new-account",
            NewOrder = $"{baseUrl}/acme/new-order",
            RevokeCert = $"{baseUrl}/acme/revoke-cert",
            KeyChange = $"{baseUrl}/acme/key-change",
            Meta = new AcmeDirectoryMeta
            {
                TermsOfService = tosUrl,
                Website = baseUrl,
                ExternalAccountRequired = false
            }
        };
    }

    public async Task<(IResult Result, string NewNonce)> HandleNewAccountAsync(AcmeJwsRequest jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        var (authOk, errorResult, header, _, _) = await VerifyJwsAsync(jws, requireJwk: true);
        if (!authOk) return (errorResult!, newNonce);

        if (header!.Jwk == null)
        {
            return (Problem(AcmeErrorTypes.Malformed, "Per new-account è obbligatorio specificare la chiave pubblica 'jwk' nell'header JWS."), newNonce);
        }

        // SECURITY (2.3.1): forza minima della chiave account (RFC 8555 Sez. 6.2).
        if (!_crypto.ValidateJwkStrength(header.Jwk, out var strengthErr))
        {
            return (Problem(AcmeErrorTypes.Malformed, strengthErr ?? "Chiave account non accettata."), newNonce);
        }

        string thumbprint;
        try
        {
            thumbprint = _crypto.ComputeJwkThumbprint(header.Jwk);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "JWK non valido in new-account.");
            return (Problem(AcmeErrorTypes.Malformed, "Chiave JWK non valida."), newNonce);
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
        catch (Exception)
        {
            return (Problem(AcmeErrorTypes.Malformed, "Payload JSON non valido."), newNonce);
        }

        // SECURITY: lock attorno a check-then-insert per evitare la creazione
        // di due account con la stessa chiave in richieste concorrenti.
        await _newAccountLock.WaitAsync();
        try
        {
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
        finally
        {
            _newAccountLock.Release();
        }
    }

    public async Task<(IResult Result, string NewNonce)> HandleGetAccountAsync(string accountId, AcmeJwsRequest? jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        // SECURITY (2.3.1, H1): lettura autenticata con ownership — l'account
        // identificato dal JWS (kid o jwk) deve coincidere con quello richiesto.
        if (jws == null || string.IsNullOrEmpty(jws.Protected))
        {
            return (Problem(AcmeErrorTypes.Unauthorized, "Lettura account non autenticata non consentita: usare un POST-as-GET firmato.", 401), newNonce);
        }

        var (authOk, errorResult, _, account, _) = await VerifyJwsAsync(jws, requireJwk: false);
        if (!authOk) return (errorResult!, newNonce);

        var target = await _store.GetAccountByIdAsync(accountId);
        if (target == null)
        {
            return (Problem(AcmeErrorTypes.AccountDoesNotExist, $"Account con ID '{accountId}' non trovato.", 404), newNonce);
        }

        if (!string.Equals(account!.Id, target.Id, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Tentativo di lettura account altrui ({Requested}) dall'account {Actual}.", accountId, account.Id);
            return (Problem(AcmeErrorTypes.Unauthorized, "L'account autenticato non corrisponde a quello richiesto.", 403), newNonce);
        }

        target.Orders = $"{baseUrl}/acme/account/{target.Id}/orders";
        return (Results.Ok(target), newNonce);
    }

    public async Task<(IResult Result, string NewNonce)> HandleGetOrdersAsync(string accountId, AcmeJwsRequest? jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        // SECURITY (2.3.1, H1): lettura autenticata con ownership.
        if (jws == null || string.IsNullOrEmpty(jws.Protected))
        {
            return (Problem(AcmeErrorTypes.Unauthorized, "Lettura ordini non autenticata non consentita: usare un POST-as-GET firmato.", 401), newNonce);
        }

        var (authOk, errorResult, _, account, _) = await VerifyJwsAsync(jws, requireJwk: false);
        if (!authOk) return (errorResult!, newNonce);

        var target = await _store.GetAccountByIdAsync(accountId);
        if (target == null)
        {
            return (Problem(AcmeErrorTypes.AccountDoesNotExist, $"Account '{accountId}' non trovato.", 404), newNonce);
        }

        if (!string.Equals(account!.Id, target.Id, StringComparison.OrdinalIgnoreCase))
        {
            return (Problem(AcmeErrorTypes.Unauthorized, "L'account autenticato non corrisponde a quello richiesto.", 403), newNonce);
        }

        var orders = await _store.GetOrdersByAccountIdAsync(target.Id);
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
        catch (Exception)
        {
            return (Problem(AcmeErrorTypes.Malformed, "Payload new-order JSON non valido."), newNonce);
        }

        if (req.Identifiers == null || req.Identifiers.Count == 0)
        {
            return (Problem(AcmeErrorTypes.Malformed, "È necessario specificare almeno un identifier DNS per il certificato."), newNonce);
        }

        // SECURITY (2.3.1): limite di identifier per ordine (anti DoS).
        if (req.Identifiers.Count > MaxIdentifiersPerOrder)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Numero massimo di identifier per ordine: {MaxIdentifiersPerOrder}."), newNonce);
        }

        // Duplicati (case-insensitive) → scarto silenzioso.
        var unique = new List<AcmeIdentifier>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var ident in req.Identifiers)
        {
            if (ident != null && !string.IsNullOrWhiteSpace(ident.Value) && seen.Add(ident.Value.Trim()))
            {
                ident.Value = ident.Value.Trim();
                unique.Add(ident);
            }
        }
        req.Identifiers = unique;

        foreach (var ident in req.Identifiers)
        {
            // SECURITY (2.3.1): rifiuto wildcard (RFC 8555 Sez. 8.1.4: http-01
            // MUST rifiutare wildcard; il server non supporta dns-01 reale).
            if (ident.Value.TrimStart().StartsWith("*", StringComparison.Ordinal))
            {
                return (Problem(AcmeErrorTypes.RejectedIdentifier, $"Identificatore wildcard '{ident.Value}' non supportato da questo server."), newNonce);
            }

            if (!string.Equals(ident.Type, "dns", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(ident.Value))
            {
                return (Problem(AcmeErrorTypes.RejectedIdentifier, $"Identificatore non supportato: '{ident.Type}' : '{ident.Value}'. Solo DNS supportati."), newNonce);
            }

            // SECURITY (2.3.1, C3): allowlist domini — se configurata, ogni
            // identifier deve coincidere con una voce o essere suo subdominio.
            if (!IsDomainAllowed(ident.Value))
            {
                _logger.LogWarning("Ordine ACME rifiutato: identifier '{Domain}' non presente in AllowedDomains (account {AccountId}).", ident.Value, account!.Id);
                return (Problem(AcmeErrorTypes.RejectedIdentifier, $"Il dominio '{ident.Value}' non è emittibile da questo server ACME."), newNonce);
            }
        }

        // SECURITY (2.3.1, C3): con validazione disattivata (AutoApprove/None)
        // l'allowlist è obbligatoria — senza di essa qualsiasi nome (anche
        // interno) diventerebbe emittibile senza proof di ownership.
        if ((string.Equals(Config.ValidationMode, "AutoApprove", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(Config.ValidationMode, "None", StringComparison.OrdinalIgnoreCase)) &&
            (Config.AllowedDomains == null || Config.AllowedDomains.Count == 0))
        {
            _logger.LogError("Ordine ACME rifiutato: ValidationMode '{Mode}' senza AllowedDomains configurata (configurazione pericolosa).", Config.ValidationMode);
            return (Problem(AcmeErrorTypes.RejectedIdentifier, "Il server opera in modalità AutoApprove/None e richiede l'allowlist AllowedDomains per emettere certificati."), newNonce);
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

        // SECURITY (2.3.1, H1): lettura autenticata con ownership.
        if (jws == null || string.IsNullOrEmpty(jws.Protected))
        {
            return (Problem(AcmeErrorTypes.Unauthorized, "Lettura ordine non autenticata non consentita: usare un POST-as-GET firmato.", 401), newNonce);
        }

        var (authOk, errorResult, _, account, _) = await VerifyJwsAsync(jws, requireJwk: false);
        if (!authOk) return (errorResult!, newNonce);

        var order = await _store.GetOrderByIdAsync(orderId);
        if (order == null)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Ordine con ID '{orderId}' non trovato.", 404), newNonce);
        }

        if (!string.Equals(order.AccountId, account!.Id, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Tentativo di lettura ordine altrui ({OrderId}) dall'account {Actual}.", orderId, account.Id);
            return (Problem(AcmeErrorTypes.Unauthorized, "L'account autenticato non ha richiesto questo ordine.", 403), newNonce);
        }

        await OrderLock(orderId).WaitAsync();
        try
        {
            // SECURITY (2.3.1, M1): applicazione dell'expiry dell'ordine.
            if (IsExpired(order.Expires) &&
                order.Status is "pending" or "ready" or "processing")
            {
                order.Status = "expired";
                await _store.SaveOrderAsync(order);
                _logger.LogInformation("Ordine ACME {OrderId} scaduto (expiry applicato).", order.Id);
            }

            // Se l'ordine è in processing (es. approvazione AD CS trattenuta),
            // verifichiamo se è stato approvato.
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
                        order.CertificateThumbprint = ComputeCertificateThumbprint(checkRes.CertificatePem);
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

            // Resilienza: ordine "valid" senza certificato in memoria
            // (es. upgrade da versioni precedenti) → riprova il recupero da AD CS.
            if (order.Status == "valid" && string.IsNullOrEmpty(order.CertificatePem) && order.CaRequestId > 0)
            {
                try
                {
                    var checkRes = await _adcsService.RetrievePendingCertificateAsync(order.CaId, order.CaRequestId);
                    if (checkRes.Success && !string.IsNullOrEmpty(checkRes.CertificatePem))
                    {
                        order.CertificatePem = checkRes.CertificatePem;
                        order.CertificateChainPem = checkRes.CertificateChainPem;
                        order.CaCertificatePem = checkRes.CaCertificatePem;
                        order.CertificateThumbprint = ComputeCertificateThumbprint(checkRes.CertificatePem);
                        await _store.SaveOrderAsync(order);
                        _logger.LogInformation("Ordine ACME {OrderId}: certificato recuperato dalla CA (#ID {ReqId}).", order.Id, order.CaRequestId);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Recupero certificato AD CS per ordine {OrderId} non riuscito.", order.Id);
                }
            }
        }
        finally
        {
            OrderLock(orderId).Release();
        }

        order.Finalize = $"{baseUrl}/acme/order/{orderId}/finalize";
        if (order.Status == "valid" && !string.IsNullOrEmpty(order.CertificatePem))
        {
            order.Certificate = $"{baseUrl}/acme/cert/{order.Id}";
        }

        return (Results.Ok(order), newNonce);
    }

    public async Task<(IResult Result, string NewNonce)> HandleGetAuthorizationAsync(string authId, AcmeJwsRequest? jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        // SECURITY (2.3.1, H1): lettura autenticata con ownership.
        if (jws == null || string.IsNullOrEmpty(jws.Protected))
        {
            return (Problem(AcmeErrorTypes.Unauthorized, "Lettura autorizzazione non autenticata non consentita: usare un POST-as-GET firmato.", 401), newNonce);
        }

        var (authOk, errorResult, _, account, _) = await VerifyJwsAsync(jws, requireJwk: false);
        if (!authOk) return (errorResult!, newNonce);

        var auth = await _store.GetAuthorizationByIdAsync(authId);
        if (auth == null)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Autorizzazione '{authId}' non trovata.", 404), newNonce);
        }

        var order = await _store.GetOrderByIdAsync(auth.OrderId);
        if (order == null || !string.Equals(order.AccountId, account!.Id, StringComparison.OrdinalIgnoreCase))
        {
            return (Problem(AcmeErrorTypes.Unauthorized, "L'account autenticato non ha richiesto questa autorizzazione.", 403), newNonce);
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

        // SECURITY (2.3.1, H1): solo l'account proprietario dell'ordine può
        // triggerare la validazione di una challenge.
        var ownerOrder = await _store.GetOrderByIdAsync(challenge.OrderId);
        if (ownerOrder == null || !string.Equals(ownerOrder.AccountId, account!.Id, StringComparison.OrdinalIgnoreCase))
        {
            return (Problem(AcmeErrorTypes.Unauthorized, "L'account autenticato non ha richiesto questa challenge.", 403), newNonce);
        }

        // Se già valida, restituisce lo stato
        if (challenge.Status == "valid")
        {
            return (Results.Ok(challenge), newNonce);
        }

        // SECURITY (2.3.1, M1): expiry dell'autorizzazione.
        if (IsExpired(auth.Expires))
        {
            challenge.Status = "invalid";
            challenge.Error = new AcmeProblem
            {
                Type = AcmeErrorTypes.OrderNotReady,
                Detail = "L'autorizzazione è scaduta: creare un nuovo ordine.",
                Status = 403
            };
            auth.Status = "expired";
            await _store.SaveChallengeAsync(challenge);
            await _store.SaveAuthorizationAsync(auth);
            await MarkOrderExpiredIfNeeded(challenge.OrderId);
            return (Results.Ok(challenge), newNonce);
        }

        // SECURITY (2.3.1, C3): ri-verifica dell'allowlist al momento della
        // validazione (la configurazione può essere cambiata dopo la creazione
        // dell'ordine).
        if (!IsDomainAllowed(auth.Identifier.Value))
        {
            challenge.Status = "invalid";
            challenge.Error = new AcmeProblem
            {
                Type = AcmeErrorTypes.RejectedIdentifier,
                Detail = "Il dominio non è più emittibile da questo server ACME.",
                Status = 400
            };
            auth.Status = "invalid";
            await _store.SaveChallengeAsync(challenge);
            await _store.SaveAuthorizationAsync(auth);
            await UpdateOrderStatusAfterChallengeAsync(challenge.OrderId);
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
            // Validazione DNS-01: se in AutoApprove la approviamo (solo con
            // AllowedDomains configurata — gate applicato in new-order),
            // altrimenti informiamo del mancato supporto.
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
        await UpdateOrderStatusAfterChallengeAsync(challenge.OrderId);

        return (Results.Ok(challenge), newNonce);
    }

    public async Task<(IResult Result, string NewNonce)> HandleFinalizeOrderAsync(string orderId, AcmeJwsRequest jws, string baseUrl)
    {
        baseUrl = NormalizeBaseUrl(baseUrl);
        string newNonce = CreateNonce();

        var (authOk, errorResult, _, account, payloadJson) = await VerifyJwsAsync(jws, requireJwk: false);
        if (!authOk) return (errorResult!, newNonce);

        // SECURITY (2.3.1, M8): lock per ordine attorno alla transizione di
        // stato — impedisce a due finalize concorrenti di doppia-sottomettere
        // lo stesso ordine a AD CS.
        await OrderLock(orderId).WaitAsync();
        try
        {
            var order = await _store.GetOrderByIdAsync(orderId);
            if (order == null)
            {
                return (Problem(AcmeErrorTypes.Malformed, $"Ordine '{orderId}' non trovato.", 404), newNonce);
            }

            if (!string.Equals(order.AccountId, account!.Id, StringComparison.OrdinalIgnoreCase))
            {
                return (Problem(AcmeErrorTypes.Unauthorized, "L'account autenticato non ha richiesto questo ordine.", 403), newNonce);
            }

            // SECURITY (2.3.1, M1): expiry — un ordine "ready" scaduto non può
            // più essere finalizzato.
            if (IsExpired(order.Expires) && order.Status != "valid")
            {
                order.Status = "expired";
                await _store.SaveOrderAsync(order);
                return (Problem(AcmeErrorTypes.OrderNotReady, "L'ordine è scaduto: crearne uno nuovo.", 403), newNonce);
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
            catch (Exception)
            {
                return (Problem(AcmeErrorTypes.Malformed, "Payload finalize JSON non valido."), newNonce);
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
            catch (Exception)
            {
                return (Problem(AcmeErrorTypes.Malformed, "Decodifica CSR non riuscita: contenuto non valido."), newNonce);
            }

            // SECURITY (2.3.1, C1 — CRITICO): il CSR deve essere vincolato agli
            // identifier autorizzati nell'ordine. Senza questo controllo un
            // cliente valido potrebbe farsi emettere un certificato con
            // SAN/CN arbitrari (anche nomi interni) non coperti da alcuna
            // autorizzazione ACME (RFC 8555 Sez. 7.4).
            string? csrBindingError = ValidateCsrAgainstOrder(csrPem, order);
            if (csrBindingError != null)
            {
                _logger.LogWarning("Finalize ordine ACME {OrderId} rifiutato: {Reason}", order.Id, csrBindingError);
                return (Problem(AcmeErrorTypes.Malformed, csrBindingError, 400), newNonce);
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
                RequesterComments = $"ACME order {order.Id} (Account: {account.Id})"
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
                    order.CertificateThumbprint = ComputeCertificateThumbprint(adcsResponse.CertificatePem);
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

                    _logger.LogWarning("Emissione AD CS fallita per ordine ACME {OrderId}: {Detail}", order.Id, adcsResponse.StatusMessage);

                    // SECURITY: non esporre lo StatusMessage AD CS al client
                    // (potrebbe contenere dettagli interni).
                    return (Problem(AcmeErrorTypes.ServerInternal, "Emissione rifiutata o fallita sulla CA AD CS. I dettagli sono nel log del server.", 500), newNonce);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Errore imprevisto durante l'invio del CSR ad AD CS (ordine {OrderId}).", order.Id);
                order.Status = "invalid";
                await _store.SaveOrderAsync(order);
                return (Problem(AcmeErrorTypes.ServerInternal, "Errore interno durante l'emissione.", 500), newNonce);
            }
        }
        finally
        {
            OrderLock(orderId).Release();
        }
    }

    public async Task<(IResult Result, string NewNonce)> HandleGetCertificateAsync(string orderId, AcmeJwsRequest? jws, string baseUrl)
    {
        string newNonce = CreateNonce();

        // Compatibilità client (certbot usa GET semplice per il download):
        // il GET resta consentito, ma se è presente un JWS DEVE autenticare
        // l'account proprietario dell'ordine (SECURITY 2.3.1, H1).
        if (jws != null && !string.IsNullOrEmpty(jws.Protected))
        {
            var (authOk, errorResult, _, account, _) = await VerifyJwsAsync(jws, requireJwk: false);
            if (!authOk) return (errorResult!, newNonce);

            var orderCheck = await _store.GetOrderByIdAsync(orderId);
            if (orderCheck != null && !string.Equals(orderCheck.AccountId, account!.Id, StringComparison.OrdinalIgnoreCase))
            {
                return (Problem(AcmeErrorTypes.Unauthorized, "L'account autenticato non ha richiesto questo ordine.", 403), newNonce);
            }
        }

        var order = await _store.GetOrderByIdAsync(orderId);
        if (order == null || order.Status != "valid" || string.IsNullOrEmpty(order.CertificatePem))
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Certificato per ordine '{orderId}' non trovato o non ancora emesso.", 404), newNonce);
        }

        // SECURITY: certificato revocato → non più scaricabile.
        if (order.Status == "revoked" || order.RevokedAt != null)
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Il certificato dell'ordine '{orderId}' è stato revocato.", 404), newNonce);
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

    /// <summary>
    /// SECURITY (2.3.1, H3): implementazione reale della revoca ACME
    /// (RFC 8555 Sez. 7.6): verifica JWS, identifica il certificato emesso,
    /// verifica l'ownership e chiede la revoca a AD CS.
    /// </summary>
    public async Task<(IResult Result, string NewNonce)> HandleRevokeCertAsync(AcmeJwsRequest jws, string baseUrl)
    {
        string newNonce = CreateNonce();

        var (authOk, errorResult, _, account, payloadJson) = await VerifyJwsAsync(jws, requireJwk: false);
        if (!authOk) return (errorResult!, newNonce);

        AcmeRevokeRequest req;
        try
        {
            req = JsonSerializer.Deserialize<AcmeRevokeRequest>(payloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? new AcmeRevokeRequest();
        }
        catch (Exception)
        {
            return (Problem(AcmeErrorTypes.Malformed, "Payload revoca JSON non valido."), newNonce);
        }

        if (string.IsNullOrWhiteSpace(req.Certificate))
        {
            return (Problem(AcmeErrorTypes.Malformed, "Il campo 'certificate' (DER Base64Url) è obbligatorio per la revoca."), newNonce);
        }

        byte[] der;
        try
        {
            der = _crypto.Base64UrlDecode(req.Certificate);
        }
        catch (Exception)
        {
            return (Problem(AcmeErrorTypes.Malformed, "Il campo 'certificate' non è un DER Base64Url valido."), newNonce);
        }

        string thumbprint;
        string serial;
        using (var cert = new X509Certificate2(der))
        {
            byte[] hash = SHA256.HashData(cert.RawData);
            thumbprint = Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            serial = cert.GetSerialNumberString();
        }

        var order = await _store.FindOrderByCertificateThumbprintAsync(thumbprint);
        if (order == null)
        {
            _logger.LogWarning("Revoca ACME: certificato (thumbprint {Thumbprint}) non emesso da questo server.", thumbprint);
            return (Problem(AcmeErrorTypes.Malformed, "Certificato non emesso da questo server ACME.", 404), newNonce);
        }

        if (!string.Equals(order.AccountId, account!.Id, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Revoca ACME rifiutata: l'account {Actual} non è proprietario dell'ordine {OrderId}.", account.Id, order.Id);
            return (Problem(AcmeErrorTypes.Unauthorized, "Solo l'account che ha richiesto il certificato può revocarlo.", 403), newNonce);
        }

        // RFC 8555 Sez. 7.6: se già revocato, la risposta MUST essere 200.
        if (order.Status == "revoked" || order.RevokedAt != null)
        {
            return (Results.Ok(), newNonce);
        }

        if (order.Status != "valid")
        {
            // Nessun certificato valido emesso: nessun'azione da compiere.
            return (Results.Ok(), newNonce);
        }

        _logger.LogInformation("Revoca ACME richiesta per l'ordine {OrderId} (serial {Serial}) dall'account {AccountId} {StatusDetail}.",
            order.Id, serial, account.Id, req.StatusDetail ?? string.Empty);

        var rev = await _adcsService.RevokeCertificateAsync(order.CaId, serial, "Revoca ACME richiesta dall'account");
        if (!rev.Success)
        {
            _logger.LogError("Revoca AD CS fallita per ordine {OrderId} (serial {Serial}): {Msg}", order.Id, serial, rev.StatusMessage);
            return (Problem(AcmeErrorTypes.ServerInternal, "La revoca presso la CA non è andata a buon fine: il certificato resta valido. Riprovare o contattare l'amministratore.", 500), newNonce);
        }

        order.Status = "revoked";
        order.RevokedAt = DateTime.UtcNow;
        await _store.SaveOrderAsync(order);
        _logger.LogInformation("Certificato ACME revocato: ordine {OrderId}, serial {Serial}, account {AccountId}.", order.Id, serial, account.Id);

        return (Results.Ok(), newNonce);
    }

    /// <summary>
    /// SECURITY (2.3.1, H3): implementazione reale del key-change (RFC 8555
    /// Sez. 7.5): JWS esterno con la chiave corrente, JWS interno con la nuova
    /// chiave; l'account viene aggiornato solo se entrambe le firme sono valide.
    /// </summary>
    public async Task<(IResult Result, string NewNonce)> HandleKeyChangeAsync(AcmeJwsRequest jws, string baseUrl)
    {
        string newNonce = CreateNonce();

        var (authOk, errorResult, _, account, payloadJson) = await VerifyJwsAsync(jws, requireJwk: false);
        if (!authOk) return (errorResult!, newNonce);

        AcmeKeyChangeRequest req;
        try
        {
            req = JsonSerializer.Deserialize<AcmeKeyChangeRequest>(payloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? new AcmeKeyChangeRequest();
        }
        catch (Exception)
        {
            return (Problem(AcmeErrorTypes.Malformed, "Payload key-change JSON non valido."), newNonce);
        }

        if (string.IsNullOrWhiteSpace(req.Outer))
        {
            return (Problem(AcmeErrorTypes.Malformed, "Il campo 'outer' (JWS interno Base64Url) è obbligatorio per il key-change."), newNonce);
        }

        AcmeJwsRequest inner;
        try
        {
            inner = JsonSerializer.Deserialize<AcmeJwsRequest>(_crypto.Base64UrlDecodeToString(req.Outer), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? new AcmeJwsRequest();
        }
        catch (Exception)
        {
            return (Problem(AcmeErrorTypes.Malformed, "Il JWS interno non è interpretabile."), newNonce);
        }

        var innerHeader = _crypto.ParseProtectedHeader(inner.Protected);
        if (innerHeader == null || innerHeader.Jwk == null)
        {
            return (Problem(AcmeErrorTypes.Malformed, "L'header protetto del JWS interno deve contenere la nuova chiave 'jwk'."), newNonce);
        }

        if (!_crypto.ValidateJwkStrength(innerHeader.Jwk, out var strengthErr))
        {
            return (Problem(AcmeErrorTypes.Malformed, strengthErr ?? "Nuova chiave non accettata."), newNonce);
        }

        string newThumbprint;
        try
        {
            newThumbprint = _crypto.ComputeJwkThumbprint(innerHeader.Jwk);
        }
        catch (Exception)
        {
            return (Problem(AcmeErrorTypes.Malformed, "La nuova chiave JWK non è valida."), newNonce);
        }

        if (string.Equals(newThumbprint, account!.Thumbprint, StringComparison.Ordinal))
        {
            return (Problem(AcmeErrorTypes.Malformed, "La nuova chiave è identica a quella corrente: key-change non necessario."), newNonce);
        }

        // Verifica la firma del JWS interno (payload vuoto) con la nuova chiave.
        if (!_crypto.VerifyJwsSignature(inner.Protected, string.Empty, inner.Signature, innerHeader.Jwk, out var innerErr))
        {
            return (Problem(AcmeErrorTypes.Malformed, $"Firma del JWS interno non valida: {innerErr}"), newNonce);
        }

        account.Jwk = innerHeader.Jwk;
        account.Thumbprint = newThumbprint;
        await _store.SaveAccountAsync(account);
        _logger.LogInformation("Key-change ACME eseguito per l'account {AccountId} (nuovo thumbprint {Thumbprint}).", account.Id, newThumbprint);

        return (Results.Ok(), newNonce);
    }

    // ===== Helper =====

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
                // SECURITY (2.3.1): il JWS con 'jwk' deve identificare un
                // account esistente (lookup per thumbprint): altrimenti un
                // JWS firmato con una chiave effimera qualsiasi passerebbe
                // l'autenticazione senza alcun account associato.
                string tp;
                try
                {
                    tp = _crypto.ComputeJwkThumbprint(header.Jwk);
                }
                catch (Exception)
                {
                    return (false, Problem(AcmeErrorTypes.Malformed, "JWK non valido nell'header protetto."), header, null, string.Empty);
                }
                account = await _store.GetAccountByThumbprintAsync(tp);
                if (account == null)
                {
                    return (false, Problem(AcmeErrorTypes.AccountDoesNotExist, "Nessun account associato alla chiave specificata.", 404), header, null, string.Empty);
                }
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
            catch (Exception)
            {
                return (false, Problem(AcmeErrorTypes.Malformed, "Decodifica payload JWS fallita."), header, null, string.Empty);
            }
        }

        return (true, null, header, account, payloadJson);
    }

    /// <summary>
    /// SECURITY (2.3.1, C1): verifica che tutti i nomi richiesti dal CSR
    /// (Common Name + SAN DNS) siano un sottoinsieme degli identifier
    /// autorizzati nell'ordine. SAN IP/Email/URI e nomi non coperti vengono
    /// rifiutati. Ritorna null se OK, altrimenti il messaggio d'errore.
    /// </summary>
    private string? ValidateCsrAgainstOrder(string csrPem, AcmeOrder order)
    {
        try
        {
            var certReq = CertificateRequest.LoadSigningRequestPem(
                csrPem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

            var allowed = new HashSet<string>(
                order.Identifiers.Select(i => i.Value.Trim().TrimEnd('.').ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);

            var requested = new List<string>();

            // Common Name (se presente).
            string? cn = ExtractCommonName(certReq.SubjectName);
            if (!string.IsNullOrWhiteSpace(cn)) requested.Add(cn);

            // Tutte le SAN: in .NET 8 gli Enumerate* per email/URI non sono
            // disponibili su X509SubjectAlternativeNameExtension, quindi i
            // GeneralNames vengono analizzati direttamente dal DER.
            foreach (var ext in certReq.CertificateExtensions)
            {
                if (ext.Oid?.Value != "2.5.29.17") continue;

                foreach (var (tag, value) in ParseDerSequenceItems(ext.RawData))
                {
                    // Numerazione GeneralNames (RFC 5280 §4.2.1.6):
                    //   [0] otherName, [1] rfc822Name (email), [2] dNSName,
                    //   [3] x400Address, [4] directoryName, [5] ediPartyName,
                    //   [6] uniformResourceIdentifier, [7] iPAddress,
                    //   [8] registeredID
                    int which = tag & 0x1F;
                    switch (which)
                    {
                        case 2: // [2] dNSName
                            requested.Add(DecodeDerString(value));
                            break;
                        case 1: // [1] rfc822Name (email)
                            return $"SAN email '{DecodeDerString(value)}' non consentita: il server ACME emette solo certificati DNS per gli identifier autorizzati.";
                        case 7: // [7] iPAddress
                            return $"SAN IP '{FormatDerIp(value)}' non consentita: il server ACME emette solo certificati DNS per gli identifier autorizzati.";
                        case 6: // [6] uniformResourceIdentifier (IA5String)
                            return $"SAN URI '{DecodeDerString(value)}' non consentita: il server ACME emette solo certificati DNS per gli identifier autorizzati.";
                        default:
                            // [0] otherName, [3] x400Address, [4] directoryName,
                            // [5] ediPartyName, [8] registeredID: non aggiungono
                            // identità DNS usata dall'autenticazione TLS → ignorati.
                            break;
                    }
                }
            }

            if (requested.Count == 0)
            {
                return "Il CSR non contiene Common Name né Subject Alternative Name DNS: impossibile associarlo agli identifier autorizzati.";
            }

            foreach (var name in requested)
            {
                var norm = name.Trim().TrimEnd('.').ToLowerInvariant();
                if (allowed.Count > 0 && !allowed.Contains(norm))
                {
                    return $"Il nome '{name}' richiesto nel CSR non corrisponde agli identifier autorizzati nell'ordine ({string.Join(", ", order.Identifiers.Select(i => i.Value))}).";
                }
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Errore durante la validazione CSR per ordine {OrderId}.", order.Id);
            return "Il CSR non è nel formato PKCS#10 atteso: impossibile verificarne i nomi richiesti.";
        }
    }

    private static string? ExtractCommonName(System.Security.Cryptography.X509Certificates.X500DistinguishedName dn)
    {
        foreach (var part in dn.Name.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed.Substring(3).Trim();
            }
        }
        return null;
    }

    // ===== Parser DER minimale per GeneralNames (SAN) =====
    // Necessario perché in .NET 8 X509SubjectAlternativeNameExtension non espone
    // EnumerateEmailAddresses/EnumerateUniformResourceIdentifiers (aggiunte in
    // .NET 9): si analizza direttamente il contenuto DER dell'estensione.

    /// <summary>Itera gli elementi (tag, value) della SEQUENCE DER più
    /// esterna (GeneralNames). Input: contenuto dell'estensione (OctetString
    /// che contiene la SEQUENCE).</summary>
    private static IEnumerable<(int Tag, byte[] Value)> ParseDerSequenceItems(byte[] data)
    {
        if (data == null || data.Length < 4 || data[0] != 0x30) yield break;

        int pos = 1;
        pos = ReadDerLength(data, pos, out int outerLen);
        if (pos + outerLen > data.Length) yield break;
        int end = pos + outerLen;

        while (pos < end)
        {
            int tag = data[pos];
            pos += 1;
            pos = ReadDerLength(data, pos, out int len);
            if (pos + len > data.Length) yield break;
            var value = data.Skip(pos).Take(len).ToArray();
            pos += len;
            yield return (tag, value);
        }
    }

    private static int ReadDerLength(byte[] data, int pos, out int len)
    {
        if (pos >= data.Length) { len = 0; return pos; }
        int first = data[pos++];
        if ((first & 0x80) == 0)
        {
            len = first;
            return pos;
        }
        int numBytes = first & 0x7F;
        len = 0;
        for (int i = 0; i < numBytes && pos < data.Length; i++)
        {
            len = (len << 8) | data[pos++];
        }
        return pos;
    }

    /// <summary>Decodifica un valore DER "stringa" (IA5/UTF8) sanificandolo
    /// (max 253 caratteri, senza caratteri di controllo).</summary>
    private static string DecodeDerString(byte[] value)
    {
        string s = System.Text.Encoding.UTF8.GetString(value);
        return new string(s.Take(253).Where(c => !char.IsControl(c)).ToArray());
    }

    private static string FormatDerIp(byte[] value)
    {
        try
        {
            if (value.Length == 4)
                return new System.Net.IPAddress(value).ToString();
            if (value.Length == 16)
                return new System.Net.IPAddress(value).ToString();
            return BitConverter.ToString(value);
        }
        catch
        {
            return BitConverter.ToString(value);
        }
    }



    /// <summary>SECURITY (2.3.1): base64url(sha256(raw)) della foglia PEM,
    /// usato per il matching nelle richieste di revoca.</summary>
    private static string? ComputeCertificateThumbprint(string? leafPem)
    {
        if (string.IsNullOrWhiteSpace(leafPem)) return null;
        try
        {
            var leaf = leafPem.Split("-----END CERTIFICATE-----")[0]
                .Replace("-----BEGIN CERTIFICATE-----", "")
                .Replace("\r", "").Replace("\n", "").Replace(" ", "");
            byte[] raw = Convert.FromBase64String(leaf);
            byte[] hash = SHA256.HashData(raw);
            return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
        catch
        {
            return null;
        }
    }

    /// <summary>SECURITY (2.3.1): true se l'expires (ISO 8601 "o") è passato.</summary>
    private static bool IsExpired(string? expires)
    {
        if (string.IsNullOrWhiteSpace(expires)) return false;
        if (!DateTime.TryParse(expires, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dt)) return false;
        return DateTime.UtcNow >= dt;
    }

    /// <summary>SECURITY (2.3.1, C3): verifica l'allowlist AllowedDomains
    /// (coincidenza esatta o subdominio). Allowlist vuota = nessuna restrizione
    /// (solo per le modalità con validazione reale).</summary>
    private bool IsDomainAllowed(string value)
    {
        var allowed = (Config.AllowedDomains ?? new List<string>())
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Trim().TrimEnd('.').ToLowerInvariant())
            .ToList();
        if (allowed.Count == 0) return true;

        var v = value.Trim().TrimEnd('.').ToLowerInvariant();
        foreach (var a in allowed)
        {
            if (v == a || v.EndsWith("." + a, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private async Task UpdateOrderStatusAfterChallengeAsync(string orderId)
    {
        var order = await _store.GetOrderByIdAsync(orderId);
        if (order == null) return;

        await OrderLock(orderId).WaitAsync();
        try
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
        finally
        {
            OrderLock(orderId).Release();
        }
    }

    private async Task MarkOrderExpiredIfNeeded(string orderId)
    {
        var order = await _store.GetOrderByIdAsync(orderId);
        if (order == null) return;

        await OrderLock(orderId).WaitAsync();
        try
        {
            if (order.Status is "pending" or "ready" or "processing" or "invalid")
            {
                order.Status = "expired";
                await _store.SaveOrderAsync(order);
            }
        }
        finally
        {
            OrderLock(orderId).Release();
        }
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
