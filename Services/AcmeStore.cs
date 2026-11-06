using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using PkiPortal.Models;

namespace PkiPortal.Services;

public class AcmeStore : IAcmeStore
{
    private readonly ILogger<AcmeStore> _logger;
    private readonly string _persistencePath;
    private readonly SemaphoreSlim _saveLock = new(1, 1);

    // Nonces anti-replay: mappa nonce -> UtcNow di creazione
    private readonly ConcurrentDictionary<string, DateTime> _nonces = new();
    private static readonly TimeSpan NonceTtl = TimeSpan.FromMinutes(15);

    // SECURITY (2.3.1): tetto duro al numero di nonces in memoria. new-nonce è
    // anonimo (300 req/min per IP): senza un limite, un attacco multi-IP
    // farebbe crescere la mappa all'infinito (DoS di memoria).
    private const int NonceHardCap = 200_000;
    private long _nonceCreatedCount;

    // Store in memoria
    private readonly ConcurrentDictionary<string, AcmeAccount> _accounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _accountsByThumbprint = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AcmeOrder> _orders = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, AcmeAuthorization> _authorizations = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, AcmeChallenge> _challenges = new(StringComparer.OrdinalIgnoreCase);

    public AcmeStore(ILogger<AcmeStore> logger)
    {
        _logger = logger;
        var appDataDir = Path.Combine(AppContext.BaseDirectory, "App_Data");
        try
        {
            Directory.CreateDirectory(appDataDir);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Impossibile verificare/creare cartella App_Data per AcmeStore.");
        }

        _persistencePath = Path.Combine(appDataDir, "acme-store.json");
        LoadFromDisk();
    }

    public string CreateNonce()
    {
        if (Interlocked.Increment(ref _nonceCreatedCount) % 100 == 0)
        {
            PruneExpiredNonces();
        }

        // Security: se il tetto è raggiunto (attacco multi-IP), si rimuovono
        // prima gli scaduti e, se necessario, i nonces più vecchi, invece di
        // crescere all'infinito.
        if (_nonces.Count >= NonceHardCap)
        {
            PruneExpiredNonces();
            if (_nonces.Count >= NonceHardCap)
            {
                foreach (var kvp in _nonces.ToArray())
                {
                    if (_nonces.Count < NonceHardCap - 1000) break;
                    _nonces.TryRemove(kvp.Key, out _);
                }
            }
        }

        byte[] bytes = new byte[24];
        RandomNumberGenerator.Fill(bytes);
        string nonce = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        _nonces[nonce] = DateTime.UtcNow;
        return nonce;
    }

    public bool ValidateAndConsumeNonce(string nonce)
    {
        if (string.IsNullOrWhiteSpace(nonce)) return false;
        PruneExpiredNonces();

        if (_nonces.TryRemove(nonce, out var createdAt))
        {
            return (DateTime.UtcNow - createdAt) <= NonceTtl;
        }
        return false;
    }

    private void PruneExpiredNonces()
    {
        var cutoff = DateTime.UtcNow - NonceTtl;
        foreach (var kvp in _nonces)
        {
            if (kvp.Value < cutoff)
            {
                _nonces.TryRemove(kvp.Key, out _);
            }
        }
    }

    public Task<AcmeAccount?> GetAccountByIdAsync(string accountId)
    {
        if (string.IsNullOrWhiteSpace(accountId)) return Task.FromResult<AcmeAccount?>(null);
        _accounts.TryGetValue(accountId, out var account);
        return Task.FromResult(account);
    }

    public Task<AcmeAccount?> GetAccountByThumbprintAsync(string thumbprint)
    {
        if (string.IsNullOrWhiteSpace(thumbprint)) return Task.FromResult<AcmeAccount?>(null);
        if (_accountsByThumbprint.TryGetValue(thumbprint, out var accountId))
        {
            return GetAccountByIdAsync(accountId);
        }
        return Task.FromResult<AcmeAccount?>(null);
    }

    public async Task<AcmeAccount> SaveAccountAsync(AcmeAccount account)
    {
        _accounts[account.Id] = account;
        if (!string.IsNullOrEmpty(account.Thumbprint))
        {
            _accountsByThumbprint[account.Thumbprint] = account.Id;
        }
        await SaveToDiskAsync();
        return account;
    }

    public Task<AcmeOrder?> GetOrderByIdAsync(string orderId)
    {
        if (string.IsNullOrWhiteSpace(orderId)) return Task.FromResult<AcmeOrder?>(null);
        _orders.TryGetValue(orderId, out var order);
        return Task.FromResult(order);
    }

    public Task<List<AcmeOrder>> GetOrdersByAccountIdAsync(string accountId)
    {
        var list = _orders.Values
            .Where(o => string.Equals(o.AccountId, accountId, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(o => o.CreatedAt)
            .ToList();
        return Task.FromResult(list);
    }

    public async Task<AcmeOrder> SaveOrderAsync(AcmeOrder order)
    {
        _orders[order.Id] = order;
        await SaveToDiskAsync();
        return order;
    }

    public Task<AcmeAuthorization?> GetAuthorizationByIdAsync(string authId)
    {
        if (string.IsNullOrWhiteSpace(authId)) return Task.FromResult<AcmeAuthorization?>(null);
        _authorizations.TryGetValue(authId, out var auth);
        return Task.FromResult(auth);
    }

    public async Task<AcmeAuthorization> SaveAuthorizationAsync(AcmeAuthorization auth)
    {
        _authorizations[auth.Id] = auth;
        await SaveToDiskAsync();
        return auth;
    }

    public Task<AcmeChallenge?> GetChallengeAsync(string authId, string type)
    {
        string key = $"{authId}_{type}";
        _challenges.TryGetValue(key, out var challenge);
        return Task.FromResult(challenge);
    }

    public async Task<AcmeChallenge> SaveChallengeAsync(AcmeChallenge challenge)
    {
        string key = $"{challenge.AuthId}_{challenge.Type}";
        _challenges[key] = challenge;
        await SaveToDiskAsync();
        return challenge;
    }

    public Task<AcmeOrder?> FindOrderByCertificateThumbprintAsync(string thumbprint)
    {
        if (string.IsNullOrWhiteSpace(thumbprint)) return Task.FromResult<AcmeOrder?>(null);
        AcmeOrder? found = null;
        foreach (var order in _orders.Values)
        {
            if (string.Equals(order.CertificateThumbprint, thumbprint, StringComparison.Ordinal))
            {
                found = order;
                break;
            }
        }
        return Task.FromResult(found);
    }

    // ===== Persistenza =====
    //
    // SECURITY (2.3.1): i modelli API (AcmeAccount, AcmeOrder, ecc.) usano
    // [JsonIgnore] sui campi sensibili (Jwk, Thumbprint, AccountId, CaId,
    // CertificatePem, …) per proteggerli dalle risposte JSON. Il file di
    // persistenza DEVE però contenere quei campi, altrimenti dopo un recycle
    // IIS gli account perderebbero la chiave pubblica (lockout di tutti i
    // client ACME) e gli ordini il legame con l'account. Si usano quindi DTO
    // di persistenza dedicati, mappati esplicitamente.

    private class AcmeAccountRecord
    {
        public string Id { get; set; } = string.Empty;
        public string Status { get; set; } = "valid";
        public List<string> Contact { get; set; } = new();
        public bool TermsOfServiceAgreed { get; set; }
        public DateTime CreatedAt { get; set; }
        public AcmeJwk? Jwk { get; set; }
        public string Thumbprint { get; set; } = string.Empty;
    }

    private class AcmeOrderRecord
    {
        public string Id { get; set; } = string.Empty;
        public string AccountId { get; set; } = string.Empty;
        public string Status { get; set; } = "pending";
        public string Expires { get; set; } = string.Empty;
        public List<AcmeIdentifier> Identifiers { get; set; } = new();
        public List<string> Authorizations { get; set; } = new();
        public DateTime CreatedAt { get; set; }
        public string? CaId { get; set; }
        public string? TemplateName { get; set; }
        public int CaRequestId { get; set; }
        public string? CertificateThumbprint { get; set; }
        public string? CertificatePem { get; set; }
        public string? CertificateChainPem { get; set; }
        public string? CaCertificatePem { get; set; }
        public DateTime? RevokedAt { get; set; }
        public string? ClientIp { get; set; }
    }

    private class AcmeAuthorizationRecord
    {
        public string Id { get; set; } = string.Empty;
        public string OrderId { get; set; } = string.Empty;
        public string Status { get; set; } = "pending";
        public string Expires { get; set; } = string.Empty;
        public AcmeIdentifier Identifier { get; set; } = new();
        public bool Wildcard { get; set; }
    }

    private class AcmeChallengeRecord
    {
        public string Id { get; set; } = string.Empty;
        public string AuthId { get; set; } = string.Empty;
        public string OrderId { get; set; } = string.Empty;
        public string Type { get; set; } = "http-01";
        public string Token { get; set; } = string.Empty;
        public string Status { get; set; } = "pending";
        public string? Validated { get; set; }
        public AcmeProblem? Error { get; set; }
    }

    private class AcmeStoreData
    {
        public List<AcmeAccountRecord> Accounts { get; set; } = new();
        public List<AcmeOrderRecord> Orders { get; set; } = new();
        public List<AcmeAuthorizationRecord> Authorizations { get; set; } = new();
        public List<AcmeChallengeRecord> Challenges { get; set; } = new();
    }

    private void LoadFromDisk()
    {
        if (!File.Exists(_persistencePath)) return;

        try
        {
            var json = File.ReadAllText(_persistencePath);
            var data = JsonSerializer.Deserialize<AcmeStoreData>(json);
            if (data == null) return;

            foreach (var acc in data.Accounts)
            {
                var account = new AcmeAccount
                {
                    Id = acc.Id,
                    Status = acc.Status,
                    Contact = acc.Contact ?? new(),
                    TermsOfServiceAgreed = acc.TermsOfServiceAgreed,
                    CreatedAt = acc.CreatedAt,
                    Jwk = acc.Jwk,
                    Thumbprint = acc.Thumbprint ?? string.Empty
                };
                _accounts[account.Id] = account;
                if (!string.IsNullOrEmpty(account.Thumbprint))
                {
                    _accountsByThumbprint[account.Thumbprint] = account.Id;
                }
            }

            foreach (var ord in data.Orders)
            {
                _orders[ord.Id] = new AcmeOrder
                {
                    Id = ord.Id,
                    AccountId = ord.AccountId,
                    Status = ord.Status,
                    Expires = ord.Expires,
                    Identifiers = ord.Identifiers ?? new(),
                    Authorizations = ord.Authorizations ?? new(),
                    CreatedAt = ord.CreatedAt,
                    CaId = ord.CaId,
                    TemplateName = ord.TemplateName,
                    CaRequestId = ord.CaRequestId,
                    CertificateThumbprint = ord.CertificateThumbprint,
                    CertificatePem = ord.CertificatePem,
                    CertificateChainPem = ord.CertificateChainPem,
                    CaCertificatePem = ord.CaCertificatePem,
                    RevokedAt = ord.RevokedAt,
                    ClientIp = ord.ClientIp
                };
            }

            foreach (var authRec in data.Authorizations)
            {
                _authorizations[authRec.Id] = new AcmeAuthorization
                {
                    Id = authRec.Id,
                    OrderId = authRec.OrderId,
                    Status = authRec.Status,
                    Expires = authRec.Expires,
                    Identifier = authRec.Identifier ?? new(),
                    Wildcard = authRec.Wildcard,
                    Challenges = new List<AcmeChallenge>()
                };
            }

            // I challenge vengono ricollegati alle authorizzazioni.
            foreach (var challRec in data.Challenges)
            {
                var challenge = new AcmeChallenge
                {
                    Id = challRec.Id,
                    AuthId = challRec.AuthId,
                    OrderId = challRec.OrderId,
                    Type = challRec.Type,
                    Token = challRec.Token,
                    Status = challRec.Status,
                    Validated = challRec.Validated,
                    Error = challRec.Error
                };
                _challenges[$"{challenge.AuthId}_{challenge.Type}"] = challenge;
                if (_authorizations.TryGetValue(challenge.AuthId, out var auth))
                {
                    auth.Challenges.Add(challenge);
                }
            }

            _logger.LogInformation("AcmeStore inizializzato con successo: {Accounts} account, {Orders} ordini, {Authz} autorizzazioni.",
                _accounts.Count, _orders.Count, _authorizations.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Errore durante il caricamento del file di persistenza ACME ({Path}).", _persistencePath);
        }
    }

    private async Task SaveToDiskAsync()
    {
        await _saveLock.WaitAsync();
        try
        {
            var data = new AcmeStoreData
            {
                Accounts = _accounts.Values.Select(a => new AcmeAccountRecord
                {
                    Id = a.Id,
                    Status = a.Status,
                    Contact = a.Contact,
                    TermsOfServiceAgreed = a.TermsOfServiceAgreed,
                    CreatedAt = a.CreatedAt,
                    Jwk = a.Jwk,
                    Thumbprint = a.Thumbprint
                }).ToList(),
                Orders = _orders.Values.Select(o => new AcmeOrderRecord
                {
                    Id = o.Id,
                    AccountId = o.AccountId,
                    Status = o.Status,
                    Expires = o.Expires,
                    Identifiers = o.Identifiers,
                    Authorizations = o.Authorizations,
                    CreatedAt = o.CreatedAt,
                    CaId = o.CaId,
                    TemplateName = o.TemplateName,
                    CaRequestId = o.CaRequestId,
                    CertificateThumbprint = o.CertificateThumbprint,
                    CertificatePem = o.CertificatePem,
                    CertificateChainPem = o.CertificateChainPem,
                    CaCertificatePem = o.CaCertificatePem,
                    RevokedAt = o.RevokedAt,
                    ClientIp = o.ClientIp
                }).ToList(),
                Authorizations = _authorizations.Values.Select(x => new AcmeAuthorizationRecord
                {
                    Id = x.Id,
                    OrderId = x.OrderId,
                    Status = x.Status,
                    Expires = x.Expires,
                    Identifier = x.Identifier,
                    Wildcard = x.Wildcard
                }).ToList(),
                Challenges = _challenges.Values.Select(c => new AcmeChallengeRecord
                {
                    Id = c.Id,
                    AuthId = c.AuthId,
                    OrderId = c.OrderId,
                    Type = c.Type,
                    Token = c.Token,
                    Status = c.Status,
                    Validated = c.Validated,
                    Error = c.Error
                }).ToList()
            };

            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
            var tmp = _persistencePath + ".tmp";
            await File.WriteAllTextAsync(tmp, json);
            File.Move(tmp, _persistencePath, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Errore durante il salvataggio dei dati ACME su {Path}.", _persistencePath);
        }
        finally
        {
            _saveLock.Release();
        }
    }
}
