using System.Net.Http;
using PkiPortal.Models;

namespace PkiPortal.Services;

public class AcmeValidationService : IAcmeValidationService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AcmeValidationService> _logger;

    public AcmeValidationService(IHttpClientFactory httpClientFactory, ILogger<AcmeValidationService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<(bool Success, string? ErrorDetail)> ValidateHttp01Async(
        string identifier,
        string token,
        string expectedKeyAuth,
        AcmeConfig config)
    {
        // 1. Modalità AutoApprove: verifica bypassata (utile per lab interni, DMZ o test)
        if (string.Equals(config.ValidationMode, "AutoApprove", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(config.ValidationMode, "None", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("ACME ValidationMode '{Mode}': challenge HTTP-01 approvata automaticamente per {Identifier}.",
                config.ValidationMode, identifier);
            return (true, null);
        }

        // 2. Costruzione URL standard RFC 8555 Sez. 8.3
        int port = config.HttpPort > 0 ? config.HttpPort : 80;
        string portSegment = port == 80 ? "" : $":{port}";
        string challengeUrl = $"http://{identifier}{portSegment}/.well-known/acme-challenge/{token}";

        _logger.LogInformation("Avvio validazione HTTP-01 su {Url} (atteso key authorization: {KeyAuth})", challengeUrl, expectedKeyAuth);

        try
        {
            var client = _httpClientFactory.CreateClient("AcmeChallengeClient");
            client.Timeout = TimeSpan.FromSeconds(Math.Max(5, config.ChallengeTimeoutSeconds));

            // User-Agent standard ACME
            client.DefaultRequestHeaders.UserAgent.Clear();
            client.DefaultRequestHeaders.UserAgent.ParseAdd("PkiPortal-AcmeValidator/2.3.0 (+https://github.com/PkiPortal)");

            var response = await client.GetAsync(challengeUrl);

            if (!response.IsSuccessStatusCode)
            {
                string msg = $"Server target ha risposto con codice HTTP {(int)response.StatusCode} ({response.ReasonPhrase}) durante la verifica di {challengeUrl}.";
                _logger.LogWarning("{Msg}", msg);

                if (string.Equals(config.ValidationMode, "Http01WithAutoFallback", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("Http01WithAutoFallback: fallback ad approvazione automatica per {Identifier}.", identifier);
                    return (true, null);
                }

                return (false, msg);
            }

            string body = (await response.Content.ReadAsStringAsync()).Trim();

            // Confronto con l'autorizzazione di chiave RFC 8555: "<token>.<account_thumbprint>"
            if (string.Equals(body, expectedKeyAuth.Trim(), StringComparison.Ordinal))
            {
                _logger.LogInformation("Validazione HTTP-01 completata con successo per {Identifier}.", identifier);
                return (true, null);
            }
            else
            {
                string msg = $"Il contenuto restituito da {challengeUrl} non corrisponde. Ricevuto: '{body}', Atteso: '{expectedKeyAuth}'.";
                _logger.LogWarning("{Msg}", msg);

                if (string.Equals(config.ValidationMode, "Http01WithAutoFallback", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("Http01WithAutoFallback: fallback ad approvazione automatica per {Identifier}.", identifier);
                    return (true, null);
                }

                return (false, msg);
            }
        }
        catch (Exception ex)
        {
            string msg = $"Errore di connessione a {challengeUrl}: {ex.Message}";
            _logger.LogWarning(ex, "{Msg}", msg);

            if (string.Equals(config.ValidationMode, "Http01WithAutoFallback", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Http01WithAutoFallback: fallback ad approvazione automatica per {Identifier} in seguito all'errore: {Error}", identifier, ex.Message);
                return (true, null);
            }

            return (false, msg);
        }
    }
}
