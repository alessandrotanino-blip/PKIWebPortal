using PkiPortal.Models;

namespace PkiPortal.Services;

public class MigrationExportPackage
{
    public int FormatVersion { get; set; } = 1;
    public DateTime ExportedAtUtc { get; set; } = DateTime.UtcNow;
    public string ExportedBy { get; set; } = string.Empty;
    public string PortalVersion { get; set; } = "2.7.0";
    public List<HeldCertificateRequest> HeldRequests { get; set; } = new();
    public string? AcmeDataJson { get; set; }
    public string? PortalConfigJson { get; set; }
}

public class MigrationImportResult
{
    public bool Success { get; set; }
    public string? Message { get; set; }
    public int TotalRequestsImported { get; set; }
    public int PrivateKeysImported { get; set; }
    public int AcmeAccountsImported { get; set; }
    public DateTime? ExportedAtUtc { get; set; }
    public string? ExportedBy { get; set; }
    public string? SourcePortalVersion { get; set; }
}

public interface IMigrationService
{
    /// <summary>
    /// Crea un pacchetto binario cifrato (.pkibak) contenente le richieste trattenute (con le private key decifrate in RAM),
    /// i dati ACME e la configurazione, protetto con AES-256-GCM e PBKDF2 (600.000 iterazioni).
    /// </summary>
    Task<byte[]> CreateExportPackageAsync(string passphrase, string exportedBy);

    /// <summary>
    /// Decifra un pacchetto di migrazione/backup con la passphrase fornita, verifica l'integrità
    /// e ricifra a riposo tutti i dati usando i provider crittografici del server/account correnti.
    /// </summary>
    Task<MigrationImportResult> ImportPackageAsync(Stream packageStream, string passphrase, string importedBy, bool merge = true);
}
