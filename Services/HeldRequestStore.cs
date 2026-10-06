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

    // Entropia DPAPI persistente (32 byte casuali, generati una sola volta): vincola
    // la cifratura at-rest delle private key a questa specifica installazione.
    private const string DpapiPrefix = "PKEY1:";
    private readonly byte[]? _dpapiEntropy;
    private readonly bool _dpapiAvailable;

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

        // Migrazione automatica da vecchia directory radice se presente
        var legacyPersistencePath = Path.Combine(AppContext.BaseDirectory, "held-requests.json");
        var legacyEntropyPath = Path.Combine(AppContext.BaseDirectory, "store-entropy.bin");

        if (File.Exists(legacyEntropyPath) && !File.Exists(entropyPath))
        {
            try
            {
                File.Move(legacyEntropyPath, entropyPath);
                _logger.LogInformation("Migrato store-entropy.bin in {Destination}", entropyPath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Impossibile spostare store-entropy.bin in App_Data/, fallback a copia.");
                try { File.Copy(legacyEntropyPath, entropyPath, true); } catch { }
            }
        }

        if (File.Exists(legacyPersistencePath) && !File.Exists(_persistencePath))
        {
            try
            {
                File.Move(legacyPersistencePath, _persistencePath);
                _logger.LogInformation("Migrato held-requests.json in {Destination}", _persistencePath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Impossibile spostare held-requests.json in App_Data/, fallback a copia.");
                try { File.Copy(legacyPersistencePath, _persistencePath, true); } catch { }
            }
        }

        if (OperatingSystem.IsWindows())
        {
            try
            {
                _dpapiEntropy = LoadOrCreateEntropy(entropyPath);
                _dpapiAvailable = true;
                _logger.LogInformation("Cifratura DPAPI (machine-scope) abilitata per le private key a riposo.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Impossibile inizializzare DPAPI: le private key verranno persistite in chiaro. Verificare il sistema.");
            }
        }
        else
        {
            _logger.LogWarning("DPAPI non disponibile su questa piattaforma: le private key nel file di persistenza non saranno cifrate (solo sviluppo).");
        }

        LoadFromDisk();
    }

    private static byte[] LoadOrCreateEntropy(string path)
    {
        if (File.Exists(path))
        {
            var existing = File.ReadAllBytes(path);
            if (existing.Length == 32)
            {
                return existing;
            }
        }

        var fresh = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, fresh);
        return fresh;
    }

    /// <summary>Cifra la private key per la persistenza (DPAPI machine-scope + entropia locale).</summary>
    private string EncryptAtRest(string pem)
    {
        if (string.IsNullOrEmpty(pem) || !_dpapiAvailable || _dpapiEntropy == null)
        {
            return pem;
        }

        return DpapiPrefix + DpapiInterop.Protect(pem, _dpapiEntropy);
    }

    /// <summary>Decifra una private key letta dal disco. I record legacy in chiaro restano invariati.</summary>
    private string? DecryptFromRest(string? stored)
    {
        if (string.IsNullOrEmpty(stored) || !stored.StartsWith(DpapiPrefix, StringComparison.Ordinal))
        {
            return stored;
        }

        if (_dpapiEntropy == null)
        {
            _logger.LogError("Record cifrato presente ma DPAPI non inizializzato: la private key della richiesta non è recuperabile.");
            return null;
        }

        return DpapiInterop.Unprotect(stored[DpapiPrefix.Length..], _dpapiEntropy);
    }

    /// <summary>
    /// Cifratura DPAPI via P/Invoke su crypt32.dll (machine-scope: CRYPTPROTECT_LOCAL_MACHINE).
    /// Nessun pacchetto NuGet aggiuntivo richiesto. Solo Windows.
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

        // NOTA: pOptionalEntropy è un puntatore a CRYPTOIDATA_BLOB (non un buffer raw).
        [DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CryptProtectData")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptProtectData(
            ref CRYPTOIDATA_BLOB pDataIn, string? szDataDescr, ref CRYPTOIDATA_BLOB pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref CRYPTOIDATA_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CryptUnprotectData")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptUnprotectData(
            ref CRYPTOIDATA_BLOB pDataIn, out string? pszDataDescr, ref CRYPTOIDATA_BLOB pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref CRYPTOIDATA_BLOB pDataOut);

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
                    : CryptUnprotectData(ref inBlob, out _, ref entBlob, IntPtr.Zero, IntPtr.Zero, flags, ref outBlob);

                if (!ok)
                {
                    throw new CryptographicException($"DPAPI {(protect ? "Protect" : "Unprotect")} fallito (Win32 error {Marshal.GetLastWin32Error()}).");
                }

                var output = new byte[outBlob.cbData];
                Marshal.Copy(outBlob.pbData, output, 0, output.Length);
                Marshal.FreeHGlobal(outBlob.pbData);
                return output;
            }
            finally
            {
                Marshal.FreeHGlobal(inPtr);
                Marshal.FreeHGlobal(entPtr);
            }
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
                foreach (var item in items)
                {
                    try
                    {
                        item.PrivateKeyPem = DecryptFromRest(item.PrivateKeyPem);
                    }
                    catch (Exception ex)
                    {
                        // Il fallimento di decifrazione non deve far perdere l'intera
                        // richiesta: la richiesta resta disponibile, senza la chiave.
                        _logger.LogError(ex, "Impossibile decifrare la private key della richiesta {HoldId}: la richiesta resta disponibile senza chiave.", item.HoldId);
                        item.PrivateKeyPem = null;
                    }
                    _store[item.HoldId] = item;
                }
                _logger.LogInformation("Caricate {Count} richieste trattenute dal file di persistenza ({Path}).", items.Count, path);
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
