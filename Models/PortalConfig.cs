namespace PkiPortal.Models;

using System.Text.Json.Serialization;

public class PortalConfig
{
    public string PortalMode { get; set; } = "Standalone"; // "Standalone" o "Hub"
    public string PortalTitle { get; set; } = "Enterprise PKI Web Enrollment Portal";
    public string DefaultCaId { get; set; } = "default-ca";
    [JsonPropertyName("cas")]
    public List<CaConfig> CAs { get; set; } = new();
}

public class CaConfig
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ForestOrDomain { get; set; } = string.Empty;
    public string ConfigString { get; set; } = string.Empty; // es. "subca01.foresta1.local\\Foresta1-IssuingCA"
    public bool IsDefault { get; set; } = false;
    public bool UseSimulator { get; set; } = false; // Utile per demo/test o ambienti offline
    public string? Description { get; set; }

    /// <summary>
    /// Modalità di autenticazione verso la CA:
    /// "LocalIdentity": usa l'identità dell'Application Pool / utente corrente (ideale per istanze locali affiancate a certsrv).
    /// "CredentialManager": usa le credenziali archiviate in Windows Credential Manager (ideale per Hub in DMZ verso foreste non trustate).
    /// </summary>
    public string AuthMode { get; set; } = "LocalIdentity";

    /// <summary>
    /// Nome del Target memorizzato in Windows Credential Manager (es. "subca01.foresta1.lan" o "PKI:ca-foresta1").
    /// Se non specificato, viene dedotto automaticamente dall'hostname presente in ConfigString.
    /// Nessuna password viene mai salvata nei file di configurazione!
    /// </summary>
    public string? CredentialTarget { get; set; }

    public List<TemplateConfig> Templates { get; set; } = new();
}

public class TemplateConfig
{
    public string Name { get; set; } = string.Empty; // Nome di sistema del template in AD CS (es. "WebServer")
    public string DisplayName { get; set; } = string.Empty; // Nome mostrato all'utente
    public string Description { get; set; } = string.Empty;
    public bool RequiresApproval { get; set; } = false;

    /// <summary>
    /// Se true (default), consente l'archiviazione cifrata della chiave privata sul server
    /// durante l'emissione da wizard, permettendo al richiedente o agli amministratori
    /// di recuperare il pacchetto PFX anche successivamente.
    /// Se false, la chiave privata non viene trasmessa al server per i template senza approvazione,
    /// e il recupero successivo offrirà solo il certificato (.crt).
    /// </summary>
    public bool StorePrivateKeyForRetrieval { get; set; } = true;

    /// <summary>
    /// Validità (in giorni) del certificato emesso con questo template.
    /// NON è un parametro modificabile manualmente dall'amministratore: viene
    /// letta automaticamente dalla definizione AD CS del template (proprietà
    /// KeyUsagePeriod) quando il template viene scoperto dalla CA. Per le CA in
    /// modalità simulatore il valore è puramente informativo.
    /// </summary>
    public int ValidityDays { get; set; } = 365;
    public List<string> AllowedKeyTypes { get; set; } = new() { "RSA-2048", "RSA-4096", "ECDSA-P256" };
    public List<string> KeyUsages { get; set; } = new() { "DigitalSignature", "KeyEncipherment" };
    public List<string> ExtendedKeyUsages { get; set; } = new() { "ServerAuthentication" };

    /// <summary>
    /// Gruppi AD/Windows autorizzati a emettere certificati con questo template
    /// (es. "VD\\Web-Operators", "LD\\App-Team"). Se la lista è vuota il template
    /// è accessibile a tutti gli utenti autenticati. Gli amministratori del portale
    /// (AdminConfig) bypassano sempre il vincolo e possono usare tutti i template.
    /// </summary>
    public List<string> AllowedGroups { get; set; } = new();
}
