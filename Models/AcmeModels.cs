using System.Text.Json.Serialization;

namespace PkiPortal.Models;

/// <summary>
/// Configurazione del server ACME (RFC 8555) integrato nel portale PKI.
/// </summary>
public class AcmeConfig
{
    /// <summary>
    /// Abilita o disabilita il server ACME integrato. Default: true.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// URL base assoluto del portale (es. "https://pki.azienda.lan").
    /// Se vuoto o null, viene dedotto automaticamente dallo schema e dall'host della richiesta HTTP.
    /// </summary>
    public string? BaseUrl { get; set; }

    /// <summary>
    /// Identificativo della CA AD CS da utilizzare per l'emissione dei certificati ACME.
    /// Se null, viene utilizzata la CA predefinita definita in PortalConfig.DefaultCaId.
    /// </summary>
    public string? DefaultCaId { get; set; }

    /// <summary>
    /// Nome del template AD CS predefinito per le richieste ACME (es. "WebServer" o "WebServer5y").
    /// </summary>
    public string DefaultTemplateName { get; set; } = "WebServer";

    /// <summary>
    /// Elenco opzionale dei template AD CS abilitati per l'emissione ACME.
    /// Se vuoto, è consentito solo DefaultTemplateName.
    /// </summary>
    public List<string> AllowedTemplates { get; set; } = new();

    /// <summary>
    /// SECURITY (2.3.1): allowlist dei domini emittibili via ACME. Ogni identifier
    /// deve coincidere esattamente con una voce o essere un suo subdominio
    /// (es. voce "vd.ld" ammette "app01.vd.ld"). Se vuoto (e ValidationMode
    /// diversa da AutoApprove/None) non ci sono restrizioni.
    /// In modalità AutoApprove/None l'allowlist è OBBLIGATORIA: senza di essa
    /// il server rifiuta ogni ordine (previene l'emissione di certificati per
    /// nomi arbitrari senza proof di ownership).
    /// </summary>
    public List<string> AllowedDomains { get; set; } = new();

    /// <summary>
    /// Modalità di validazione delle challenge di dominio:
    /// - "Http01" (default): verifica reale via HTTP GET su port 80 (RFC 8555 Sez. 8.3).
    /// - "AutoApprove": approvazione immediata senza richiesta HTTP (ideale per lab, reti chiuse o test).
    /// - "Http01WithAutoFallback": tenta HTTP-01; se irraggiungibile approva comunque (utile in migrazione).
    /// </summary>
    public string ValidationMode { get; set; } = "Http01";

    /// <summary>
    /// Porta HTTP su cui contattare il server richiedente per la challenge http-01 (default: 80).
    /// </summary>
    public int HttpPort { get; set; } = 80;

    /// <summary>
    /// Se true, consente la validazione HTTP-01 anche verso indirizzi IP privati
    /// della intranet aziendale (RFC 1918: 10/8, 172.16/12, 192.168/16; CGNAT 100.64/10; ULA fc00::/7).
    /// Per protezione anti-SSRF, loopback (127.0.0.1, ::1) e Cloud metadata (169.254.169.254, fe80::/10)
    /// rimangono SEMPRE bloccati. In modalità IP privati l'allowlist AllowedDomains è obbligatoria.
    /// Default: false.
    /// </summary>
    public bool AllowPrivateIpValidation { get; set; } = false;

    /// <summary>
    /// Timeout in secondi per la validazione della challenge http-01 (default: 15s).
    /// </summary>
    public int ChallengeTimeoutSeconds { get; set; } = 15;

    /// <summary>
    /// Richiede l'accettazione esplicita dei termini di servizio alla creazione dell'account.
    /// </summary>
    public bool RequireTermsOfServiceAgreed { get; set; } = true;

    /// <summary>
    /// Percorso o URL dei termini di servizio.
    /// </summary>
    public string TermsOfServiceUrl { get; set; } = "/acme/terms";
}

/// <summary>
/// Directory ACME secondo RFC 8555 Sez. 7.1.1.
/// </summary>
public class AcmeDirectory
{
    [JsonPropertyName("newNonce")]
    public string NewNonce { get; set; } = string.Empty;

    [JsonPropertyName("newAccount")]
    public string NewAccount { get; set; } = string.Empty;

    [JsonPropertyName("newOrder")]
    public string NewOrder { get; set; } = string.Empty;

    [JsonPropertyName("revokeCert")]
    public string RevokeCert { get; set; } = string.Empty;

    [JsonPropertyName("keyChange")]
    public string KeyChange { get; set; } = string.Empty;

    [JsonPropertyName("meta")]
    public AcmeDirectoryMeta? Meta { get; set; }
}

public class AcmeDirectoryMeta
{
    [JsonPropertyName("termsOfService")]
    public string? TermsOfService { get; set; }

    [JsonPropertyName("website")]
    public string? Website { get; set; }

    [JsonPropertyName("caaIdentities")]
    public List<string>? CaaIdentities { get; set; }

    [JsonPropertyName("externalAccountRequired")]
    public bool ExternalAccountRequired { get; set; } = false;
}

/// <summary>
/// Dettaglio errore ACME RFC 7807 / RFC 8555 Sez. 6.7.
/// </summary>
public class AcmeProblem
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = AcmeErrorTypes.ServerInternal;

    [JsonPropertyName("detail")]
    public string Detail { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public int Status { get; set; } = 400;

    [JsonPropertyName("instance")]
    public string? Instance { get; set; }
}

/// <summary>
/// Codici errore standard ACME RFC 8555 Sez. 6.7.
/// </summary>
public static class AcmeErrorTypes
{
    public const string BadNonce = "urn:ietf:params:acme:error:badNonce";
    public const string Malformed = "urn:ietf:params:acme:error:malformed";
    public const string AccountDoesNotExist = "urn:ietf:params:acme:error:accountDoesNotExist";
    public const string Unauthorized = "urn:ietf:params:acme:error:unauthorized";
    public const string OrderNotReady = "urn:ietf:params:acme:error:orderNotReady";
    public const string InvalidContact = "urn:ietf:params:acme:error:invalidContact";
    public const string ServerInternal = "urn:ietf:params:acme:error:serverInternal";
    public const string Connection = "urn:ietf:params:acme:error:connection";
    public const string IncorrectResponse = "urn:ietf:params:acme:error:incorrectResponse";
    public const string RejectedIdentifier = "urn:ietf:params:acme:error:rejectedIdentifier";
}

/// <summary>
/// JWS Flattened Serialization (RFC 7515 Sez. 7.2.2 / RFC 8555 Sez. 6.2).
/// </summary>
public class AcmeJwsRequest
{
    [JsonPropertyName("protected")]
    public string Protected { get; set; } = string.Empty;

    [JsonPropertyName("payload")]
    public string Payload { get; set; } = string.Empty;

    [JsonPropertyName("signature")]
    public string Signature { get; set; } = string.Empty;
}

/// <summary>
/// Header protetto JWS decodificato.
/// </summary>
public class AcmeJwsHeader
{
    [JsonPropertyName("alg")]
    public string Alg { get; set; } = string.Empty;

    [JsonPropertyName("jwk")]
    public AcmeJwk? Jwk { get; set; }

    [JsonPropertyName("kid")]
    public string? Kid { get; set; }

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;
}

/// <summary>
/// Chiave pubblica JWK (RFC 7517 / RFC 7638).
/// </summary>
public class AcmeJwk
{
    [JsonPropertyName("kty")]
    public string Kty { get; set; } = string.Empty; // "RSA" o "EC"

    // Parametri RSA
    [JsonPropertyName("n")]
    public string? N { get; set; }

    [JsonPropertyName("e")]
    public string? E { get; set; }

    // Parametri EC
    [JsonPropertyName("crv")]
    public string? Crv { get; set; } // "P-256", "P-384", "P-521"

    [JsonPropertyName("x")]
    public string? X { get; set; }

    [JsonPropertyName("y")]
    public string? Y { get; set; }
}

/// <summary>
/// Payload di registrazione account (RFC 8555 Sez. 7.3).
/// </summary>
public class AcmeNewAccountRequest
{
    [JsonPropertyName("contact")]
    public List<string>? Contact { get; set; }

    [JsonPropertyName("termsOfServiceAgreed")]
    public bool? TermsOfServiceAgreed { get; set; }

    [JsonPropertyName("onlyReturnExisting")]
    public bool? OnlyReturnExisting { get; set; }
}

/// <summary>
/// Account ACME (RFC 8555 Sez. 7.1.2).
/// </summary>
public class AcmeAccount
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "valid"; // "valid", "deactivated", "revoked"

    [JsonPropertyName("contact")]
    public List<string> Contact { get; set; } = new();

    [JsonPropertyName("termsOfServiceAgreed")]
    public bool TermsOfServiceAgreed { get; set; }

    [JsonPropertyName("orders")]
    public string Orders { get; set; } = string.Empty;

    [JsonPropertyName("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [JsonIgnore]
    public AcmeJwk? Jwk { get; set; }

    [JsonIgnore]
    public string Thumbprint { get; set; } = string.Empty;
}

/// <summary>
/// Identificatore ACME (RFC 8555 Sez. 9.7.7).
/// </summary>
public class AcmeIdentifier
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "dns";

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;
}

/// <summary>
/// Payload creazione nuovo ordine (RFC 8555 Sez. 7.4).
/// </summary>
public class AcmeNewOrderRequest
{
    [JsonPropertyName("identifiers")]
    public List<AcmeIdentifier> Identifiers { get; set; } = new();

    [JsonPropertyName("notBefore")]
    public string? NotBefore { get; set; }

    [JsonPropertyName("notAfter")]
    public string? NotAfter { get; set; }
}

/// <summary>
/// Ordine ACME (RFC 8555 Sez. 7.1.3).
/// </summary>
public class AcmeOrder
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonIgnore]
    public string AccountId { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "pending"; // "pending", "ready", "processing", "valid", "invalid"

    [JsonPropertyName("expires")]
    public string Expires { get; set; } = string.Empty;

    [JsonPropertyName("identifiers")]
    public List<AcmeIdentifier> Identifiers { get; set; } = new();

    [JsonPropertyName("authorizations")]
    public List<string> Authorizations { get; set; } = new();

    [JsonPropertyName("finalize")]
    public string Finalize { get; set; } = string.Empty;

    [JsonPropertyName("certificate")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Certificate { get; set; }

    [JsonIgnore]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [JsonIgnore]
    public string? CaId { get; set; }

    [JsonIgnore]
    public string? TemplateName { get; set; }

    [JsonIgnore]
    public int CaRequestId { get; set; }

    [JsonIgnore]
    public string? CertificatePem { get; set; }

    [JsonIgnore]
    public string? CertificateChainPem { get; set; }

    [JsonIgnore]
    public string? CaCertificatePem { get; set; }

    /// <summary>
    /// SECURITY (2.3.1): thumbprint SHA-256 (base64url) della foglia emessa,
    /// usato per rintracciare il certificato nelle richieste di revoca ACME
    /// (RFC 8555 Sez. 7.6). Non esposto nelle risposte API.
    /// </summary>
    [JsonIgnore]
    public string? CertificateThumbprint { get; set; }

    /// <summary>
    /// SECURITY (2.3.1): istante UTC in cui il certificato è stato revocato.
    /// </summary>
    [JsonIgnore]
    public DateTime? RevokedAt { get; set; }
}

/// <summary>
/// Oggetto Autorizzazione ACME (RFC 8555 Sez. 7.1.4).
/// </summary>
public class AcmeAuthorization
{
    [JsonPropertyName("id")]
    [JsonIgnore]
    public string Id { get; set; } = string.Empty;

    [JsonIgnore]
    public string OrderId { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "pending"; // "pending", "valid", "invalid", "deactivated", "expired", "revoked"

    [JsonPropertyName("expires")]
    public string Expires { get; set; } = string.Empty;

    [JsonPropertyName("identifier")]
    public AcmeIdentifier Identifier { get; set; } = new();

    [JsonPropertyName("challenges")]
    public List<AcmeChallenge> Challenges { get; set; } = new();

    [JsonPropertyName("wildcard")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Wildcard { get; set; } = false;
}

/// <summary>
/// Challenge ACME (RFC 8555 Sez. 7.1.5 / 8).
/// </summary>
public class AcmeChallenge
{
    [JsonPropertyName("id")]
    [JsonIgnore]
    public string Id { get; set; } = string.Empty;

    [JsonIgnore]
    public string AuthId { get; set; } = string.Empty;

    [JsonIgnore]
    public string OrderId { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = "http-01"; // "http-01" o "dns-01"

    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "pending"; // "pending", "processing", "valid", "invalid"

    [JsonPropertyName("token")]
    public string Token { get; set; } = string.Empty;

    [JsonPropertyName("validated")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Validated { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AcmeProblem? Error { get; set; }
}

/// <summary>
/// Payload di finalizzazione ordine con CSR (RFC 8555 Sez. 7.4).
/// </summary>
public class AcmeFinalizeRequest
{
    [JsonPropertyName("csr")]
    public string Csr { get; set; } = string.Empty;
}

/// <summary>
/// Payload di revoca certificato (RFC 8555 Sez. 7.6).
/// </summary>
public class AcmeRevokeRequest
{
    /// <summary>Certificato in formato DER, codificato Base64Url.</summary>
    [JsonPropertyName("certificate")]
    public string Certificate { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("statusDetail")]
    public string? StatusDetail { get; set; }
}

/// <summary>
/// Payload di key-change account (RFC 8555 Sez. 7.5): contiene un JWS interno
/// firmato con la nuova chiave.
/// </summary>
public class AcmeKeyChangeRequest
{
    [JsonPropertyName("outer")]
    public string Outer { get; set; } = string.Empty;
}
