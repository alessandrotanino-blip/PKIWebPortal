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

    // Store in memoria
    private readonly ConcurrentDictionary<string, AcmeAccount> _accounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _accountsByThumbprint = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AcmeOrder> _orders = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, AcmeAuthorization> _authorizations = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, AcmeChallenge> _challenges = new(StringComparer.OrdinalIgnoreCase);

    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

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
        PruneExpiredNonces();
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
        // Pulizia periodica per evitare accumulo di memoria
        if (_nonces.Count > 1000)
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

    private void LoadFromDisk()
    {
        if (!File.Exists(_persistencePath)) return;

        try
        {
            var json = File.ReadAllText(_persistencePath);
            var data = JsonSerializer.Deserialize<AcmeStoreData>(json, _jsonOptions);
            if (data == null) return;

            foreach (var acc in data.Accounts)
            {
                _accounts[acc.Id] = acc;
                if (!string.IsNullOrEmpty(acc.Thumbprint))
                {
                    _accountsByThumbprint[acc.Thumbprint] = acc.Id;
                }
            }

            foreach (var ord in data.Orders)
            {
                _orders[ord.Id] = ord;
            }

            foreach (var auth in data.Authorizations)
            {
                _authorizations[auth.Id] = auth;
            }

            foreach (var chall in data.Challenges)
            {
                _challenges[$"{chall.AuthId}_{chall.Type}"] = chall;
            }

            _logger.LogInformation("AcmeStore inizializzato con successo: {Accounts} account, {Orders} ordini.",
                _accounts.Count, _orders.Count);
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
                Accounts = _accounts.Values.ToList(),
                Orders = _orders.Values.ToList(),
                Authorizations = _authorizations.Values.ToList(),
                Challenges = _challenges.Values.ToList()
            };

            var json = JsonSerializer.Serialize(data, _jsonOptions);
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

    private class AcmeStoreData
    {
        public List<AcmeAccount> Accounts { get; set; } = new();
        public List<AcmeOrder> Orders { get; set; } = new();
        public List<AcmeAuthorization> Authorizations { get; set; } = new();
        public List<AcmeChallenge> Challenges { get; set; } = new();
    }
}
