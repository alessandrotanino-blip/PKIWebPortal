using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using PkiPortal.Models;

namespace PkiPortal.Services;

public class MigrationService : IMigrationService
{
    private readonly IHeldRequestStore _heldRequestStore;
    private readonly IAcmeStore _acmeStore;
    private readonly IOptionsMonitor<PortalConfig>? _portalConfigMonitor;
    private readonly ILogger<MigrationService> _logger;

    private static readonly byte[] MagicBytes = "PKIB"u8.ToArray(); // PKI Backup
    private const byte EnvelopeVersion = 1;
    private const byte KdfPbkdf2Sha256 = 1;
    private const int DefaultIterations = 600_000;
    private const int MinIterations = 10_000;
    private const int MaxIterations = 2_000_000;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int HeaderSize = 4 + 1 + 1 + 4 + SaltSize + NonceSize + TagSize; // 54 bytes
    private const int MinPassphraseLength = 12;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = null,
        Converters = { new JsonStringEnumConverter() }
    };

    public MigrationService(
        IHeldRequestStore heldRequestStore,
        IAcmeStore acmeStore,
        IOptionsMonitor<PortalConfig>? portalConfigMonitor,
        ILogger<MigrationService> logger)
    {
        _heldRequestStore = heldRequestStore;
        _acmeStore = acmeStore;
        _portalConfigMonitor = portalConfigMonitor;
        _logger = logger;
    }

    public async Task<byte[]> CreateExportPackageAsync(string passphrase, string exportedBy)
    {
        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < MinPassphraseLength)
        {
            throw new ArgumentException($"La passphrase di cifratura deve contenere almeno {MinPassphraseLength} caratteri.", nameof(passphrase));
        }

        // 1. Recupera tutte le richieste certificato (in RAM le private key sono già decifrate in chiaro)
        var heldRequests = await _heldRequestStore.GetAllRequestsAsync();

        // 2. Recupera i dati ACME
        string? acmeJson = null;
        try
        {
            acmeJson = await _acmeStore.ExportDataJsonAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Impossibile esportare i dati dello store ACME per il pacchetto di migrazione.");
        }

        // 3. Snapshot configurazione portale
        string? portalConfigJson = null;
        if (_portalConfigMonitor?.CurrentValue != null)
        {
            try
            {
                portalConfigJson = JsonSerializer.Serialize(_portalConfigMonitor.CurrentValue, new JsonSerializerOptions { WriteIndented = true });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Impossibile includere lo snapshot di configurazione portale.");
            }
        }

        var package = new MigrationExportPackage
        {
            FormatVersion = 1,
            ExportedAtUtc = DateTime.UtcNow,
            ExportedBy = string.IsNullOrWhiteSpace(exportedBy) ? "Admin" : exportedBy,
            PortalVersion = "2.7.0",
            HeldRequests = heldRequests,
            AcmeDataJson = acmeJson,
            PortalConfigJson = portalConfigJson
        };

        // 4. Serializza e comprime con GZip in memoria
        var rawJsonBytes = JsonSerializer.SerializeToUtf8Bytes(package, JsonOptions);
        byte[] compressedBytes;
        using (var ms = new MemoryStream())
        {
            using (var gzip = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            {
                gzip.Write(rawJsonBytes, 0, rawJsonBytes.Length);
            }
            compressedBytes = ms.ToArray();
        }

        // 5. Cifra con AES-256-GCM + PBKDF2-HMAC-SHA256
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, DefaultIterations, HashAlgorithmName.SHA256, 32);

        var ciphertext = new byte[compressedBytes.Length];
        var tag = new byte[TagSize];

        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Encrypt(nonce, compressedBytes, ciphertext, tag);
        }

        // 6. Assembla envelope binario:
        // [0..3: Magic "PKIB"][4: Ver=1][5: KDF=1][6..9: Iterations 600K][10..25: Salt 16B][26..37: Nonce 12B][38..53: Tag 16B][54..end: Ciphertext]
        var packageBytes = new byte[HeaderSize + ciphertext.Length];
        Buffer.BlockCopy(MagicBytes, 0, packageBytes, 0, 4);
        packageBytes[4] = EnvelopeVersion;
        packageBytes[5] = KdfPbkdf2Sha256;
        BinaryPrimitives.WriteInt32BigEndian(packageBytes.AsSpan(6, 4), DefaultIterations);
        Buffer.BlockCopy(salt, 0, packageBytes, 10, SaltSize);
        Buffer.BlockCopy(nonce, 0, packageBytes, 26, NonceSize);
        Buffer.BlockCopy(tag, 0, packageBytes, 38, TagSize);
        Buffer.BlockCopy(ciphertext, 0, packageBytes, HeaderSize, ciphertext.Length);

        // Bonifica della chiave simmetrica dalla memoria
        CryptographicOperations.ZeroMemory(key);

        int keyCount = heldRequests.Count(r => !string.IsNullOrEmpty(r.PrivateKeyPem));
        _logger.LogInformation("Creato pacchetto di migrazione/backup crittografato: {Requests} richieste ({Keys} chiavi), esportato da {User}. Dimensione finale: {Size} bytes.",
            heldRequests.Count, keyCount, package.ExportedBy, packageBytes.Length);

        return packageBytes;
    }

    public async Task<MigrationImportResult> ImportPackageAsync(Stream packageStream, string passphrase, string importedBy, bool merge = true)
    {
        if (string.IsNullOrWhiteSpace(passphrase))
        {
            return new MigrationImportResult { Success = false, Message = "La passphrase di cifratura è obbligatoria." };
        }

        byte[] packageBytes;
        using (var ms = new MemoryStream())
        {
            await packageStream.CopyToAsync(ms);
            packageBytes = ms.ToArray();
        }

        if (packageBytes.Length < HeaderSize)
        {
            return new MigrationImportResult { Success = false, Message = "File di backup non valido o intestazione danneggiata." };
        }

        // Verifica Magic Bytes
        if (packageBytes[0] != MagicBytes[0] || packageBytes[1] != MagicBytes[1] ||
            packageBytes[2] != MagicBytes[2] || packageBytes[3] != MagicBytes[3])
        {
            return new MigrationImportResult { Success = false, Message = "Formato file non riconosciuto: firma magica PKIB mancante." };
        }

        byte version = packageBytes[4];
        if (version != EnvelopeVersion)
        {
            return new MigrationImportResult { Success = false, Message = $"Versione formato pacchetto non supportata: {version}." };
        }

        byte kdfType = packageBytes[5];
        if (kdfType != KdfPbkdf2Sha256)
        {
            return new MigrationImportResult { Success = false, Message = $"Algoritmo KDF non supportato: {kdfType}." };
        }

        int iterations = BinaryPrimitives.ReadInt32BigEndian(packageBytes.AsSpan(6, 4));
        if (iterations < MinIterations || iterations > MaxIterations)
        {
            return new MigrationImportResult { Success = false, Message = $"Numero di iterazioni KDF ({iterations}) fuori dai limiti di sicurezza consentiti." };
        }

        var salt = new byte[SaltSize];
        Buffer.BlockCopy(packageBytes, 10, salt, 0, SaltSize);

        var nonce = new byte[NonceSize];
        Buffer.BlockCopy(packageBytes, 26, nonce, 0, NonceSize);

        var tag = new byte[TagSize];
        Buffer.BlockCopy(packageBytes, 38, tag, 0, TagSize);

        int cipherLen = packageBytes.Length - HeaderSize;
        var ciphertext = new byte[cipherLen];
        Buffer.BlockCopy(packageBytes, HeaderSize, ciphertext, 0, cipherLen);

        // Derivazione chiave e decifratura
        var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA256, 32);
        var compressedBytes = new byte[cipherLen];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, compressedBytes);
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(key);
            _logger.LogWarning("Tentativo di importazione backup fallito: passphrase errata o file manomesso.");
            return new MigrationImportResult
            {
                Success = false,
                Message = "Passphrase errata o file di backup manomesso/corrotto."
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        // Decompressione GZip
        byte[] rawJsonBytes;
        try
        {
            using var ms = new MemoryStream(compressedBytes);
            using var gzip = new GZipStream(ms, CompressionMode.Decompress);
            using var outMs = new MemoryStream();
            await gzip.CopyToAsync(outMs);
            rawJsonBytes = outMs.ToArray();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Errore durante la decompressione del pacchetto di migrazione.");
            return new MigrationImportResult { Success = false, Message = "Impossibile decomprimere il contenuto del pacchetto." };
        }

        // Deserializzazione payload
        MigrationExportPackage? package;
        try
        {
            package = JsonSerializer.Deserialize<MigrationExportPackage>(rawJsonBytes, JsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Errore durante il parsing del JSON del pacchetto di migrazione.");
            return new MigrationImportResult { Success = false, Message = "Contenuto JSON del pacchetto non valido." };
        }

        if (package == null)
        {
            return new MigrationImportResult { Success = false, Message = "Il pacchetto di migrazione è vuoto." };
        }

        // 1. Ripristino e re-cifratura delle richieste e chiavi private in HeldRequestStore
        int totalRequests = 0;
        int privateKeys = 0;
        if (package.HeldRequests != null && package.HeldRequests.Count > 0)
        {
            var res = await _heldRequestStore.ImportRequestsAsync(package.HeldRequests, merge);
            totalRequests = res.totalImported;
            privateKeys = res.privateKeysImported;
        }

        // 2. Ripristino ACME se presente
        int acmeAccounts = 0;
        if (!string.IsNullOrWhiteSpace(package.AcmeDataJson))
        {
            try
            {
                acmeAccounts = await _acmeStore.ImportDataJsonAsync(package.AcmeDataJson, merge);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Errore non bloccante durante il ripristino dei dati ACME.");
            }
        }

        _logger.LogInformation("Importazione e re-cifratura pacchetto completata con successo da {User}: {Total} richieste ({Keys} chiavi), {Acme} account ACME. Export originario: {OrigDate} da {OrigUser} (v{OrigVer}).",
            importedBy, totalRequests, privateKeys, acmeAccounts, package.ExportedAtUtc, package.ExportedBy, package.PortalVersion);

        return new MigrationImportResult
        {
            Success = true,
            TotalRequestsImported = totalRequests,
            PrivateKeysImported = privateKeys,
            AcmeAccountsImported = acmeAccounts,
            ExportedAtUtc = package.ExportedAtUtc,
            ExportedBy = package.ExportedBy,
            SourcePortalVersion = package.PortalVersion,
            Message = $"Ripristino completato con successo: {totalRequests} richieste ({privateKeys} chiavi private ricifrate) e {acmeAccounts} account ACME."
        };
    }
}
