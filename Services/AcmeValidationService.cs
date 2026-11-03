using System.Net;
using System.Net.Sockets;
using System.Net.Http;
using PkiPortal.Models;

namespace PkiPortal.Services;

public class AcmeValidationService : IAcmeValidationService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AcmeValidationService> _logger;

    // SECURITY (2.3.1): limite di lettura del body della challenge.
    // La key authorization attende è ~100 byte: 4 KB abbondano e impediscono
    // a un server di challenge controllato dall'attaccante di far leggere,
    // loggare ed echiare megabyte di contenuto (DoS / info disclosure).
    private const int MaxChallengeBodyBytes = 4096;

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
        // 1. Modalità AutoApprove: verifica bypassata (gate Applicato in
        //    AcmeService: richiede AllowedDomains non vuoto, altrimenti gli
        //    ordini vengono rifiutati a monte).
        if (string.Equals(config.ValidationMode, "AutoApprove", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(config.ValidationMode, "None", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("ACME ValidationMode '{Mode}': challenge HTTP-01 approvata automaticamente per {Identifier} (consentito da AllowedDomains).",
                config.ValidationMode, identifier);
            return (true, null);
        }

        // 2. SECURITY (2.3.1, anti-SSRF): l'identifier è input di un client
        //    anonimo. Deve essere un hostname DNS valido che risolva ESCLUSIVAMENTE
        //    su indirizzi pubblici: si impedisce così di puntare la validazione
        //    verso loopback, rete interna, metadata endpoint cloud (169.254.169.254)
        //    o IP literal privati, e di leggere i loro contenuti.
        string? ssrfError = ValidateIdentifierIsPublicDns(identifier, out IPAddress[] publicAddresses);
        if (ssrfError != null)
        {
            _logger.LogWarning("Validazione HTTP-01 rifiutata per identifier non pubblico '{Identifier}': {Reason}", identifier, ssrfError);
            return (false, "Dominio non accettato per la validazione HTTP-01 (identificatore non valido o non risolvibile su indirizzi pubblici).");
        }

        int port = config.HttpPort > 0 ? config.HttpPort : 80;
        string portSegment = port == 80 ? "" : $":{port}";
        string challengeUrl = $"http://{identifier}{portSegment}/.well-known/acme-challenge/{token}";

        _logger.LogInformation("Avvio validazione HTTP-01 su {Url} (atteso key authorization: {KeyAuth})", challengeUrl, expectedKeyAuth);

        try
        {
            var client = _httpClientFactory.CreateClient("AcmeChallengeClient");

            // SECURITY: User-Agent standard ACME (il client è condiviso dal
            // factory: non mutiamo la Timeout condivisa, usiamo un CTS per call).
            client.DefaultRequestHeaders.UserAgent.Clear();
            client.DefaultRequestHeaders.UserAgent.ParseAdd("PkiPortal-AcmeValidator/2.3.1 (+https://github.com/PkiPortal)");

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Max(5, config.ChallengeTimeoutSeconds)));
            HttpResponseMessage response;
            try
            {
                response = await client.GetAsync(challengeUrl, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Timeout dopo {Seconds}s nella validazione HTTP-01 di {Url}.", config.ChallengeTimeoutSeconds, challengeUrl);
                return (false, "Validazione HTTP-01 fallita: timeout di connessione al server target.");
            }

            using (response)
            {
                if (!response.IsSuccessStatusCode)
                {
                    string msg = $"Server target ha risposto con codice HTTP {(int)response.StatusCode} durante la verifica di {challengeUrl}.";
                    _logger.LogWarning("{Msg}", msg);

                    if (string.Equals(config.ValidationMode, "Http01WithAutoFallback", StringComparison.OrdinalIgnoreCase))
                    {
                        // SECURITY: il fallback approva SENZA proof di ownership:
                        // va segnalato come evento di sicurezza, non come warning.
                        _logger.LogError("Http01WithAutoFallback: approvazione AUTOMATICA senza validazione riuscita per {Identifier} (HTTP {Status}). Il certificato verrà emesso senza proof di dominio.", identifier, (int)response.StatusCode);
                        return (true, null);
                    }

                    // SECURITY: dettaglio generico verso il client (niente echo
                    // di contenuto o dettagli di rete).
                    return (false, "Validazione HTTP-01 fallita: il server target non ha risposto correttamente.");
                }

                // Lettura del body con limite di dimensione (anti DoS).
                string body;
                using (var stream = await response.Content.ReadAsStreamAsync(cts.Token))
                using (var limited = new LimitedStream(stream, MaxChallengeBodyBytes))
                using (var reader = new System.IO.StreamReader(limited, System.Text.Encoding.UTF8))
                {
                    body = (await reader.ReadToEndAsync()).Trim();
                }

                // Confronto con l'autorizzazione di chiave RFC 8555: "<token>.<account_thumbprint>"
                if (string.Equals(body, expectedKeyAuth.Trim(), StringComparison.Ordinal))
                {
                    _logger.LogInformation("Validazione HTTP-01 completata con successo per {Identifier}.", identifier);
                    return (true, null);
                }
                else
                {
                    // SECURITY: il contenuto ricevuto è controllato dall'attaccante
                    // (se possiede il web server del dominio): lo si logga TRONCATO
                    // e sanificato, e si restituisce un dettaglio generico.
                    string bodyForLog = string.Join(" ", body.Take(512).Where(c => !char.IsControl(c)));
                    _logger.LogWarning("Contenuto challenge per {Url} non conforme (ricevuto: '{Body}', atteso: '{Expected}').", challengeUrl, bodyForLog, expectedKeyAuth);

                    if (string.Equals(config.ValidationMode, "Http01WithAutoFallback", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogError("Http01WithAutoFallback: approvazione AUTOMATICA senza validazione riuscita per {Identifier} (contenuto non conforme). Il certificato verrà emesso senza proof di dominio.", identifier);
                        return (true, null);
                    }

                    return (false, "Validazione HTTP-01 fallita: il contenuto restituito dal server target non corrisponde alla key authorization attesa.");
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Timeout durante la lettura della risposta HTTP-01 di {Url}.", challengeUrl);
            return (false, "Validazione HTTP-01 fallita: timeout di lettura del server target.");
        }
        catch (Exception ex)
        {
            // SECURITY: ex.Message può contenere dettagli di rete interni
            // (indirizzi, errori socket): si logga ma non si espone al client.
            _logger.LogWarning(ex, "Errore di connessione durante la validazione HTTP-01 di {Url}.", challengeUrl);

            if (string.Equals(config.ValidationMode, "Http01WithAutoFallback", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogError("Http01WithAutoFallback: approvazione AUTOMATICA per {Identifier} in seguito ad errore di connessione ({Error}). Il certificato verrà emesso senza proof di dominio.", identifier, ex.GetType().Name);
                return (true, null);
            }

            return (false, "Validazione HTTP-01 fallita: impossibile contattare il server target.");
        }
    }

    /// <summary>
    /// SECURITY (2.3.1, anti-SSRF): verifica che l'identifier sia un hostname
    /// DNS valido che risolva solo su indirizzi pubblici. Ritorna null se OK,
    /// altrimenti il motivo del rifiuto (uso solo a scopo di log).
    /// </summary>
    private static string? ValidateIdentifierIsPublicDns(string identifier, out IPAddress[] publicAddresses)
    {
        publicAddresses = Array.Empty<IPAddress>();
        identifier = identifier?.Trim().TrimEnd('.') ?? string.Empty;

        if (string.IsNullOrWhiteSpace(identifier))
            return "identifier vuoto.";

        // IP literal: ammessi solo se pubblici (nessuna risoluzione, nessun
        // vhost: il client non controlla più nulla).
        if (IPAddress.TryParse(identifier, out var literal))
        {
            if (!IsPublicIp(literal))
                return "IP literal non pubblico.";
            publicAddresses = new[] { literal };
            return null;
        }

        // Forma hostname: label di alfanumerici/linee/battensign, separati da '.',
        // senza spazi, senza '@' o '/' (impedisce URL malfatti o credenziali).
        if (identifier.Length > 253 ||
            identifier.IndexOfAny(new[] { ' ', '@', '/', '\\', ':', '#', '?' }) >= 0 ||
            !System.Text.RegularExpressions.Regex.IsMatch(identifier, @"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$"))
        {
            return "hostname non valido.";
        }

        IPAddress[] addresses;
        try
        {
            addresses = Dns.GetHostAddresses(identifier);
        }
        catch (Exception ex)
        {
            return $"risoluzione DNS non riuscita ({ex.GetType().Name}).";
        }

        if (addresses.Length == 0)
            return "nessuna risoluzione DNS.";

        // Blocca se QUALSIASI indirizzo risolto è non pubblico: impedisce a un
        // dominio sotto controllo dell'attaccante di puntare ad A record interni
        // (DNS rebinding / record misti pubblico+privato).
        foreach (var addr in addresses)
        {
            if (!IsPublicIp(addr))
                return "l'hostname risolve anche su indirizzi non pubblici.";
        }

        publicAddresses = addresses;
        return null;
    }

    /// <summary>True solo per indirizzi IPv4/IPv6 "pubblici" (non loopback,
    /// privati, link-local, multicast, reserved o metadata).</summary>
    private static bool IsPublicIp(IPAddress ip)
    {
        // Mappature IPv4-in-IPv6 (::ffff:a.b.c.d) → ispeziona l'embedded IPv4.
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6)
            {
                byte[] v4 = ip.GetAddressBytes().Skip(12).Take(4).ToArray();
                return IsPublicIp(new IPAddress(v4));
            }

            Span<byte> b = ip.GetAddressBytes();
            if (b[0] == 0 && b[1] == 0)
            {
                // :: (non assegnato), ::1 (loopback), ::ffff:0:0/96
                bool allZero = true;
                for (int i = 0; i < 10; i++) if (b[i] != 0) { allZero = false; break; }
                if (allZero) return false;
                if (b[9] == 1) return false; // ::1
                if (b[8] == 0xff) return false; // IPv4-mapped
            }
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return false; // fe80::/10 link-local
            if (b[0] == 0xfc || b[0] == 0xfd) return false;          // fc00::/7 ULA
            if (b[0] == 0xff) return false;                          // ff00::/8 multicast
            if (b[0] == 0x64 && b[1] == 0xff && b[2] == 0x9b) return false; // 64:ff9b::/96 NAT64
            // Il restante spazio IPv6 pubblico è accettato.
            return true;
        }

        byte[] o = ip.GetAddressBytes();
        // 0.0.0.0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16,
        // 100.64/10 (CGNAT), 224/4 (multicast), 240/4 (reserved).
        if (o[0] == 0) return false;
        if (o[0] == 10) return false;
        if (o[0] == 127) return false;
        if (o[0] == 169 && o[1] == 254) return false;
        if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return false;
        if (o[0] == 192 && o[1] == 168) return false;
        if (o[0] == 100 && (o[1] & 0xc0) == 64) return false;
        if (o[0] >= 224) return false;
        return true;
    }

    /// <summary>Stream che tronca la lettura a un numero massimo di byte
    /// (la chiave authorization attesa è ~100 byte).</summary>
    private sealed class LimitedStream : System.IO.Stream
    {
        private readonly System.IO.Stream _inner;
        private readonly long _max;
        private long _position;

        public LimitedStream(System.IO.Stream inner, long max)
        {
            _inner = inner;
            _max = max;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            long remaining = _max - _position;
            if (remaining <= 0) return 0;
            if (count > remaining) count = (int)remaining;
            int read = _inner.Read(buffer, offset, count);
            _position += read;
            return read;
        }
        public override long Seek(long offset, System.IO.SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
