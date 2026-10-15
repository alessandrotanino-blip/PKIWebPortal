using System.Security.Cryptography;
using System.Text;

namespace PkiPortal.Services;

/// <summary>
/// SECURITY (2.1.0): token anti-CSRF legati all'identità autenticata.
/// Sostituisce il precedente valore statico pubblico ("pki-admin"): ogni token è
/// un payload <c>utente|scadenza</c> firmato con HMAC-SHA256 da un segreto
/// server-side persistito in App_Data (blindata via ACL dallo script di
/// installazione). La validazione verifica firma, corrispondenza utente e
/// scadenza, quindi un token rubato da un'altra sessione (o di un altro utente)
/// non è utilizzabile.
/// Formato: Base64(payload) + "." + Base64(HMAC-SHA256(payload))
/// </summary>
public class CsrfTokenService
{
    /// <summary>Vita utile di un token, in minuti.</summary>
    public const int TokenLifetimeMinutes = 30;

    private readonly byte[] _secret;
    private readonly ILogger<CsrfTokenService> _logger;

    public CsrfTokenService(ILogger<CsrfTokenService> logger)
    {
        _logger = logger;

        var appDataDir = Path.Combine(AppContext.BaseDirectory, "App_Data");
        try
        {
            Directory.CreateDirectory(appDataDir);
        }
        catch
        {
            // La creazione del percorso è best-effort: se fallisce si usa un
            // segreto volatile (token validi solo nel ciclo di vita del processo).
        }

        var secretPath = Path.Combine(appDataDir, "csrf-secret.bin");
        try
        {
            if (File.Exists(secretPath))
            {
                var existing = File.ReadAllBytes(secretPath);
                if (existing.Length == 32)
                {
                    _secret = existing;
                    return;
                }
                _logger.LogWarning("Segreto CSRF esistente in {Path} con lunghezza non prevista ({Len} byte): rigenerato.", secretPath, existing.Length);
            }
            _secret = RandomNumberGenerator.GetBytes(32);
            File.WriteAllBytes(secretPath, _secret);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Impossibile caricare/creare il segreto CSRF in {Path}: uso segreto volatile (i token verranno invalidati al riavvio del processo).", secretPath);
            _secret = RandomNumberGenerator.GetBytes(32);
        }
    }

    /// <summary>Emette un token valido per l'identità <paramref name="userName"/>.</summary>
    public string IssueTokenForUser(string userName)
    {
        long expiresAt = DateTimeOffset.UtcNow.AddMinutes(TokenLifetimeMinutes).ToUnixTimeSeconds();
        string payload = $"{userName}|{expiresAt}";
        string signature = ComputeHmac(payload);
        return $"{Convert.ToBase64String(Encoding.UTF8.GetBytes(payload))}.{signature}";
    }

    /// <summary>
    /// Valida un token: firma HMAC corretta, emesso per l'utente indicato, non scaduto.
    /// </summary>
    public bool ValidateToken(string? token, string userName)
    {
        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(userName))
        {
            return false;
        }

        var parts = token.Split('.');
        if (parts.Length != 2)
        {
            return false;
        }

        try
        {
            string payload = Encoding.UTF8.GetString(Convert.FromBase64String(parts[0]));

            // Confronto della firma in tempo costante (anti timing attack).
            string expected = ComputeHmac(payload);
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(expected),
                    Encoding.UTF8.GetBytes(parts[1])))
            {
                return false;
            }

            var segments = payload.Split('|');
            if (segments.Length != 2)
            {
                return false;
            }

            // Il token è utilizzabile solo dall'identità per cui è stato emesso.
            if (!string.Equals(segments[0], userName, StringComparison.Ordinal))
            {
                return false;
            }

            return long.TryParse(segments[1], out long exp) &&
                   exp >= DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private string ComputeHmac(string payload)
    {
        using var hmac = new HMACSHA256(_secret);
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload)));
    }
}
