using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PkiPortal.Models;

namespace PkiPortal.Services;

/// <summary>
/// Store in-memory per le richieste certificato trattenute dal portale.
/// Persiste su file JSON per sopravvivere ai riavvii dell'applicazione.
/// </summary>
public class HeldRequestStore : IHeldRequestStore
{
    private readonly ConcurrentDictionary<string, HeldCertificateRequest> _store = new();
    private readonly string _persistencePath;
    private readonly ILogger<HeldRequestStore> _logger;
    private readonly SemaphoreSlim _saveLock = new(1, 1);
    private readonly object _stateLock = new();

    // Prefissi di formato cifratura a riposo:
    // PKEY1:   = DPAPI machine-scope + entropia crittografica locale
    // AESGCM1: = AES-256-GCM con chiave crittografica di installazione (App_Data/store-key.bin)
    private const string DpapiPrefix = "PKEY1:";
    private const string AesGcmPrefix = "AESGCM1:";

    private readonly byte[]? _dpapiEntropy;
    private readonly bool _dpapiAvailable;
    private readonly byte[]? _aesKey;

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = null,
        Converters = { new JsonStringEnumConverter() }
    };

    public HeldRequestStore(ILogger<HeldRequestStore> logger)
    {
        _logger = logger;

        var appDataDir = Path.Combine(AppContext.BaseDirectory, "App_Data");
        try
        {
            Directory.CreateDirectory(appDataDir);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Impossibile creare la cartella App_Data: {Path}", appDataDir);
        }

        _persistencePath = Path.Combine(appDataDir, "held-requests.json");
        var entropyPath = Path.Combine(appDataDir, "store-entropy.bin");
        var keyPath = Path.Combine(appDataDir, "store-key.bin");

        // Migrazione automatica da vecchia directory radice se presente
        MigrateLegacyFile(Path.Combine(AppContext.BaseDirectory, "store-entropy.bin"), entropyPath);
        MigrateLegacyFile(Path.Combine(AppContext.BaseDirectory, "store-key.bin"), keyPath);
        MigrateLegacyFile(Path.Combine(AppContext.BaseDirectory, "held-requests.json"), _persistencePath);

        // Controllo aggiuntivo su Directory.GetCurrentDirectory() se diverso da BaseDirectory
        if (!string.Equals(Directory.GetCurrentDirectory(), AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase))
        {
            MigrateLegacyFile(Path.Combine(Directory.GetCurrentDirectory(), "store-entropy.bin"), entropyPath);
            MigrateLegacyFile(Path.Combine(Directory.GetCurrentDirectory(), "store-key.bin"), keyPath);
            MigrateLegacyFile(Path.Combine(Directory.GetCurrentDirectory(), "held-requests.json"), _persistencePath);
        }

        // Inizializzazione chiave AES-256-GCM (sempre disponibile come fallback o difesa in profondità)
        try
        {
            _aesKey = LoadOrCreateKey(keyPath, 32);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Impossibile inizializzare la chiave AES-256-GCM in {Path}.", keyPath);
        }

        // Inizializzazione e self-test DPAPI su Windows
        if (OperatingSystem.IsWindows())
        {
            try
            {
                _dpapiEntropy = LoadOrCreateKey(entropyPath, 32);
                if (VerifyDpapi(_dpapiEntropy, _logger))
                {
                    _dpapiAvailable = true;
                    _logger.LogInformation("Cifratura DPAPI (machine-scope) inizializzata e verificata con successo per le private key a riposo.");
                }
                else
                {
                    _logger.LogWarning("Self-test DPAPI fallito: le private key a riposo verranno protette tramite AES-256-GCM.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Impossibile inizializzare DPAPI: fallback su cifratura AES-256-GCM.");
            }
        }
        else
        {
            _logger.LogInformation("Piattaforma non-Windows: protezione delle private key a riposo gestita tramite AES-256-GCM.");
        }

        if (!_dpapiAvailable && _aesKey == null)
        {
            _logger.LogCritical("NESSUN PROVIDER CRITTOGRAFICO DISPONIBILE! Le private key non potranno essere persistite.");
        }

        LoadFromDisk();
    }

    private void MigrateLegacyFile(string source, string destination)
    {
        if (File.Exists(source) && !File.Exists(destination))
        {
            try
            {
                File.Move(source, destination);
                _logger.LogInformation("Migrato {Source} in cartella sicura {Destination}", source, destination);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Impossibile spostare {Source} in {Destination}, fallback a copia.", source, destination);
                try { File.Copy(source, destination, true); } catch { }
            }
        }
    }

    private static byte[] LoadOrCreateKey(string path, int byteCount)
    {
        if (File.Exists(path))
        {
            var existing = File.ReadAllBytes(path);
            if (existing.Length == byteCount)
            {
                return existing;
            }
        }

        var fresh = RandomNumberGenerator.GetBytes(byteCount);
        File.WriteAllBytes(path, fresh);
        return fresh;
    }

    private static bool VerifyDpapi(byte[] entropy, ILogger logger)
    {
        try
        {
            var probe = "DPAPI-SELFTEST-" + Guid.NewGuid();
            var enc = DpapiInterop.Protect(probe, entropy);
            var dec = DpapiInterop.Unprotect(enc, entropy);
            return string.Equals(probe, dec, StringComparison.Ordinal);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Verifica funzionale DPAPI non riuscita.");
            return false;
        }
    }

    /// <summary>
    /// Cifra la private key per la persistenza a riposo.
    /// Ordine di priorità: DPAPI machine-scope + entropia locale, fallback AES-256-GCM.
    /// Non scrive MAI una private key in chiaro su disco.
    /// </summary>
    private string EncryptAtRest(string pem)
    {
        if (string.IsNullOrEmpty(pem))
        {
            return pem;
        }

        if (_dpapiAvailable && _dpapiEntropy != null)
        {
            try
            {
                return DpapiPrefix + DpapiInterop.Protect(pem, _dpapiEntropy);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Cifratura DPAPI fallita; fallback su AES-256-GCM.");
            }
        }

        if (_aesKey != null)
        {
            return AesGcmPrefix + AesGcmHelper.Protect(pem, _aesKey);
        }

        throw new CryptographicException("Nessun provider crittografico at-rest disponibile. Rifiutata la scrittura della private key in chiaro su disco.");
    }

    /// <summary>
    /// Decifra una private key letta dal disco.
    /// Supporta i prefissi PKEY1: (DPAPI), AESGCM1: (AES-256-GCM) e formati legacy in chiaro.
    /// </summary>
    private string? DecryptFromRest(string? stored)
    {
        if (string.IsNullOrEmpty(stored))
        {
            return stored;
        }

        if (stored.StartsWith(DpapiPrefix, StringComparison.Ordinal))
        {
            if (!_dpapiAvailable || _dpapiEntropy == null)
            {
                _logger.LogError("Record cifrato con DPAPI presente ma DPAPI non inizializzato o non disponibile.");
                return null;
            }
            return DpapiInterop.Unprotect(stored[DpapiPrefix.Length..], _dpapiEntropy);
        }

        if (stored.StartsWith(AesGcmPrefix, StringComparison.Ordinal))
        {
            if (_aesKey == null)
            {
                _logger.LogError("Record cifrato con AES-256-GCM presente ma chiave di installazione non disponibile.");
                return null;
            }
            return AesGcmHelper.Unprotect(stored[AesGcmPrefix.Length..], _aesKey);
        }

        // Record legacy in chiaro: restituito per uso immediato ma segnalato per migrazione
        return stored;
    }

    /// <summary>
    /// Cifratura DPAPI via P/Invoke su crypt32.dll (machine-scope: CRYPTPROTECT_LOCAL_MACHINE).
    /// Con CharSet Unicode e deallocazione LocalFree conformi alle specifiche Win32.
    /// </summary>
    private static class DpapiInterop
    {
        private const uint CRYPTPROTECT_LOCAL_MACHINE = 0x4;
        private const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPTOIDATA_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
            public uint dwReserved;
        }

        [DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CryptProtectData", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptProtectData(
            ref CRYPTOIDATA_BLOB pDataIn, string? szDataDescr, ref CRYPTOIDATA_BLOB pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref CRYPTOIDATA_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CryptUnprotectData", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptUnprotectData(
            ref CRYPTOIDATA_BLOB pDataIn, IntPtr pszDataDescr, ref CRYPTOIDATA_BLOB pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref CRYPTOIDATA_BLOB pDataOut);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        public static string Protect(string plainText, byte[] entropy)
        {
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            return Convert.ToBase64String(Transform(plainBytes, entropy, protect: true));
        }

        public static string Unprotect(string base64Cipher, byte[] entropy)
        {
            var cipherBytes = Convert.FromBase64String(base64Cipher);
            return Encoding.UTF8.GetString(Transform(cipherBytes, entropy, protect: false));
        }

        private static byte[] Transform(byte[] input, byte[] entropy, bool protect)
        {
            IntPtr inPtr = Marshal.AllocHGlobal(input.Length);
            IntPtr entPtr = Marshal.AllocHGlobal(entropy.Length);
            try
            {
                Marshal.Copy(input, 0, inPtr, input.Length);
                Marshal.Copy(entropy, 0, entPtr, entropy.Length);

                var inBlob = new CRYPTOIDATA_BLOB { cbData = (uint)input.Length, pbData = inPtr, dwReserved = 0 };
                var entBlob = new CRYPTOIDATA_BLOB { cbData = (uint)entropy.Length, pbData = entPtr, dwReserved = 0 };
                var outBlob = new CRYPTOIDATA_BLOB();
                var flags = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN;

                bool ok = protect
                    ? CryptProtectData(ref inBlob, "PkiPortal.PrivateKey", ref entBlob, IntPtr.Zero, IntPtr.Zero, flags, ref outBlob)
                    : CryptUnprotectData(ref inBlob, IntPtr.Zero, ref entBlob, IntPtr.Zero, IntPtr.Zero, flags, ref outBlob);

                if (!ok)
                {
                    throw new CryptographicException($"DPAPI {(protect ? "Protect" : "Unprotect")} fallito (Win32 error {Marshal.GetLastWin32Error()}).");
                }

                var output = new byte[outBlob.cbData];
                Marshal.Copy(outBlob.pbData, output, 0, output.Length);
                LocalFree(outBlob.pbData);
                return output;
            }
            finally
            {
                Marshal.FreeHGlobal(inPtr);
                Marshal.FreeHGlobal(entPtr);
            }
        }
    }

    /// <summary>
    /// Helper crittografico per cifratura autenticata AES-256-GCM.
    /// Formato payload Base64: [Nonce 12B][Tag 16B][Ciphertext].
    /// </summary>
    private static class AesGcmHelper
    {
        private const int NonceSize = 12; // 96-bit nonce standard NIST
        private const int TagSize = 16;   // 128-bit authentication tag

        public static string Protect(string plainText, byte[] key)
        {
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var tag = new byte[TagSize];
            var cipher = new byte[plainBytes.Length];

            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plainBytes, cipher, tag);

            var combined = new byte[NonceSize + TagSize + cipher.Length];
            Buffer.BlockCopy(nonce, 0, combined, 0, NonceSize);
            Buffer.BlockCopy(tag, 0, combined, NonceSize, TagSize);
            Buffer.BlockCopy(cipher, 0, combined, NonceSize + TagSize, cipher.Length);

            return Convert.ToBase64String(combined);
        }

        public static string Unprotect(string base64Cipher, byte[] key)
        {
            var combined = Convert.FromBase64String(base64Cipher);
            if (combined.Length < NonceSize + TagSize)
            {
                throw new CryptographicException("Ciphertext AES-GCM corrotto o dimensione insufficiente.");
            }

            var nonce = new byte[NonceSize];
            var tag = new byte[TagSize];
            int cipherSize = combined.Length - NonceSize - TagSize;
            var cipher = new byte[cipherSize];
            var plainBytes = new byte[cipherSize];

            Buffer.BlockCopy(combined, 0, nonce, 0, NonceSize);
            Buffer.BlockCopy(combined, NonceSize, tag, 0, TagSize);
            Buffer.BlockCopy(combined, NonceSize + TagSize, cipher, 0, cipherSize);

            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, cipher, tag, plainBytes);

            return Encoding.UTF8.GetString(plainBytes);
        }
    }

    public Task<HeldCertificateRequest> HoldRequestAsync(HeldCertificateRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.HoldId))
        {
            request.HoldId = $"HOLD-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid():N}"[..24];
        }

        request.Status = HoldStatus.PendingApproval;
        request.SubmittedAt = DateTime.UtcNow;

        _store[request.HoldId] = request;
        _logger.LogInformation(
            "Richiesta certificato trattenuta: HoldId={HoldId}, Template={Template}, CA RequestId={CaRequestId}, Richiedente={Requester}",
            request.HoldId, request.TemplateName, request.CaRequestId, request.RequesterUser);

        _ = SaveToDiskAsync(); // Fire-and-forget, errori gestiti internamente
        return Task.FromResult(request);
    }

    public Task<HeldCertificateRequest?> GetByHoldIdAsync(string holdId)
    {
        _store.TryGetValue(holdId, out var request);
        return Task.FromResult(request);
    }

    public Task<HeldCertificateRequest?> GetByCaRequestIdAsync(string? caId, int caRequestId)
    {
        var match = _store.Values
            .Where(r => r.CaRequestId == caRequestId &&
                        (string.IsNullOrWhiteSpace(caId) || string.Equals(r.CaId, caId, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(r => r.SubmittedAt)
            .FirstOrDefault();
        return Task.FromResult(match);
    }

    public Task<HeldCertificateRequest> SaveRequestAsync(HeldCertificateRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.HoldId))
        {
            request.HoldId = $"REQ-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid():N}"[..24];
        }

        if (request.SubmittedAt == default)
        {
            request.SubmittedAt = DateTime.UtcNow;
        }

        _store[request.HoldId] = request;
        _logger.LogInformation(
            "Richiesta registrata nello store: HoldId={HoldId}, Stato={Status}, Template={Template}, CA RequestId={CaRequestId}, Richiedente={Requester}",
            request.HoldId, request.Status, request.TemplateName, request.CaRequestId, request.RequesterUser);

        _ = SaveToDiskAsync();
        return Task.FromResult(request);
    }

    public Task<HeldCertificateRequest?> UpdateRequestAsync(HeldCertificateRequest request)
    {
        _store[request.HoldId] = request;
        _logger.LogInformation(
            "Richiesta aggiornata nello store: HoldId={HoldId}, Stato={Status}, CA RequestId={CaRequestId}",
            request.HoldId, request.Status, request.CaRequestId);

        _ = SaveToDiskAsync();
        return Task.FromResult<HeldCertificateRequest?>(request);
    }

    public Task<List<HeldCertificateRequest>> GetRequestsByUserAsync(string userName)
    {
        var userRequests = _store.Values
            .Where(r => !string.IsNullOrEmpty(r.RequesterUser) &&
                        r.RequesterUser.Equals(userName, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(r => r.SubmittedAt)
            .ToList();
        return Task.FromResult(userRequests);
    }

    public Task<List<HeldCertificateRequest>> GetPendingRequestsAsync()
    {
        var pending = _store.Values
            .Where(r => r.Status == HoldStatus.PendingApproval)
            .OrderByDescending(r => r.SubmittedAt)
            .ToList();
        return Task.FromResult(pending);
    }

    public Task<List<HeldCertificateRequest>> GetAllRequestsAsync(HoldStatus? statusFilter = null)
    {
        var query = _store.Values.AsEnumerable();
        if (statusFilter.HasValue)
        {
            if (statusFilter.Value == HoldStatus.Approved)
            {
                query = query.Where(r => r.Status == HoldStatus.Approved || r.Status == HoldStatus.Issued);
            }
            else
            {
                query = query.Where(r => r.Status == statusFilter.Value);
            }
        }
        var result = query.OrderByDescending(r => r.SubmittedAt).ToList();
        return Task.FromResult(result);
    }

    public async Task<HeldCertificateRequest?> ApproveRequestAsync(string holdId, string approvedBy)
    {
        HeldCertificateRequest? request;
        lock (_stateLock)
        {
            if (!_store.TryGetValue(holdId, out request))
            {
                return null;
            }

            if (request.Status != HoldStatus.PendingApproval)
            {
                _logger.LogWarning("Tentativo di approvare una richiesta non in stato PendingApproval: HoldId={HoldId}, Stato={Status}", holdId, request.Status);
                return null;
            }

            request.Status = HoldStatus.Approved;
            request.ReviewedAt = DateTime.UtcNow;
            request.ReviewedBy = approvedBy;
        }

        _logger.LogInformation("Richiesta certificato APPROVATA: HoldId={HoldId}, Approvata da={ApprovedBy}", holdId, approvedBy);
        await SaveToDiskAsync(); // persistenza attendibile della transizione di stato
        return request;
    }

    public async Task<HeldCertificateRequest?> RejectRequestAsync(string holdId, string rejectedBy, string? reason)
    {
        HeldCertificateRequest? request;
        lock (_stateLock)
        {
            if (!_store.TryGetValue(holdId, out request))
            {
                return null;
            }

            if (request.Status != HoldStatus.PendingApproval)
            {
                _logger.LogWarning("Tentativo di rifiutare una richiesta non in stato PendingApproval: HoldId={HoldId}, Stato={Status}", holdId, request.Status);
                return null;
            }

            request.Status = HoldStatus.Rejected;
            request.ReviewedAt = DateTime.UtcNow;
            request.ReviewedBy = rejectedBy;
            request.RejectionReason = reason;
        }

        _logger.LogInformation("Richiesta certificato RIFIUTATA: HoldId={HoldId}, Rifiutata da={RejectedBy}, Motivo={Reason}", holdId, rejectedBy, reason);
        await SaveToDiskAsync(); // persistenza attendibile della transizione di stato
        return request;
    }

    #region Persistenza su disco

    private void LoadFromDisk()
    {
        var path = _persistencePath;
        if (!File.Exists(path))
        {
            var fallback = Path.Combine(Directory.GetCurrentDirectory(), "held-requests.json");
            if (File.Exists(fallback)) path = fallback;
        }

        if (!File.Exists(path))
        {
            _logger.LogInformation("Nessun file di persistenza richieste trattenute trovato in {Path}.", _persistencePath);
            return;
        }

        try
        {
            var json = File.ReadAllText(path);
            var items = JsonSerializer.Deserialize<List<HeldCertificateRequest>>(json, _jsonOptions);
            if (items != null)
            {
                bool legacyUnencryptedFound = false;
                foreach (var item in items)
                {
                    if (!string.IsNullOrEmpty(item.PrivateKeyPem))
                    {
                        bool wasEncrypted = item.PrivateKeyPem.StartsWith(DpapiPrefix, StringComparison.Ordinal) ||
                                           item.PrivateKeyPem.StartsWith(AesGcmPrefix, StringComparison.Ordinal);
                        try
                        {
                            item.PrivateKeyPem = DecryptFromRest(item.PrivateKeyPem);
                            if (!wasEncrypted)
                            {
                                legacyUnencryptedFound = true;
                            }
                        }
                        catch (Exception ex)
                        {
                            // Il fallimento di decifrazione non deve far perdere l'intera
                            // richiesta: la richiesta resta disponibile, senza la chiave.
                            _logger.LogError(ex, "Impossibile decifrare la private key della richiesta {HoldId}: la richiesta resta disponibile senza chiave.", item.HoldId);
                            item.PrivateKeyPem = null;
                        }
                    }
                    _store[item.HoldId] = item;
                }
                _logger.LogInformation("Caricate {Count} richieste trattenute dal file di persistenza ({Path}).", items.Count, path);

                if (legacyUnencryptedFound)
                {
                    _logger.LogWarning("Rilevati record legacy con private key in chiaro in {Path}: migrazione immediata a cifratura a riposo...", path);
                    _ = SaveToDiskAsync();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Errore durante il caricamento delle richieste trattenute da {Path}: lo store parte VUOTO. Il file corrotto viene archiviato come backup.", _persistencePath);
            try
            {
                var backup = $"{path}.corrupt-{DateTime.UtcNow:yyyyMMddHHmmss}";
                File.Move(path, backup, overwrite: true);
                _logger.LogWarning("File corrotto archiviato in {Backup}.", backup);
            }
            catch (Exception backupEx)
            {
                _logger.LogError(backupEx, "Impossibile archiviare il file corrotto {Path}.", path);
            }
        }
    }

    private async Task SaveToDiskAsync()
    {
        await _saveLock.WaitAsync();
        try
        {
            // Le private key vengono cifrate solo nella copia persistita a disco:
            // in memoria restano utilizzabili per il download PFX.
            var items = _store.Values.Select(CloneForPersistence).ToList();
            var json = JsonSerializer.Serialize(items, _jsonOptions);

            // Scrittura atomica: temp + rename, in modo che un crash a metà
            // non possa corrompere il file di persistenza.
            var tmp = _persistencePath + ".tmp";
            await File.WriteAllTextAsync(tmp, json);
            File.Move(tmp, _persistencePath, overwrite: true);

            // Se esistono copie legacy in chiaro nella root applicativa, bonifichiamole
            CleanupLegacyRootFile(Path.Combine(AppContext.BaseDirectory, "held-requests.json"));
            if (!string.Equals(Directory.GetCurrentDirectory(), AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase))
            {
                CleanupLegacyRootFile(Path.Combine(Directory.GetCurrentDirectory(), "held-requests.json"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Errore durante il salvataggio delle richieste trattenute su {Path}.", _persistencePath);
        }
        finally
        {
            _saveLock.Release();
        }
    }

    private void CleanupLegacyRootFile(string legacyPath)
    {
        try
        {
            if (File.Exists(legacyPath) && !string.Equals(Path.GetFullPath(legacyPath), Path.GetFullPath(_persistencePath), StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(legacyPath);
                _logger.LogInformation("Rimosso file legacy obsoleto: {Path}", legacyPath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Impossibile eliminare file legacy {Path}", legacyPath);
        }
    }

    private HeldCertificateRequest CloneForPersistence(HeldCertificateRequest r)
    {
        if (string.IsNullOrEmpty(r.PrivateKeyPem))
        {
            return r;
        }

        return new HeldCertificateRequest
        {
            HoldId = r.HoldId,
            SubmittedAt = r.SubmittedAt,
            ReviewedAt = r.ReviewedAt,
            CaId = r.CaId,
            TemplateName = r.TemplateName,
            TemplateDisplayName = r.TemplateDisplayName,
            RequesterComments = r.RequesterComments,
            RequesterUser = r.RequesterUser,
            SubjectCommonName = r.SubjectCommonName,
            SanAttribute = r.SanAttribute,
            CaRequestId = r.CaRequestId,
            CertificatePem = r.CertificatePem,
            CertificateChainPem = r.CertificateChainPem,
            CaCertificatePem = r.CaCertificatePem,
            P7bBase64 = r.P7bBase64,
            PrivateKeyPem = EncryptAtRest(r.PrivateKeyPem),
            Status = r.Status,
            ReviewedBy = r.ReviewedBy,
            RejectionReason = r.RejectionReason
        };
    }

    #endregion
}
