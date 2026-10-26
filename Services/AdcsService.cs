using System.ComponentModel;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Microsoft.Win32.SafeHandles;
using PkiPortal.Models;

namespace PkiPortal.Services;

public class AdcsService : IAdcsService
{
    private readonly IOptionsMonitor<PortalConfig> _portalConfigMonitor;
    private readonly ILogger<AdcsService> _logger;
    private readonly IHeldRequestStore _heldRequestStore;

    // Costanti Microsoft CertRequest COM
    // NB: con CR_IN_BASE64, Submit() richiede la CSR in forma Base64 del DER
    // PKCS#10 (NON testo PEM armato): con PEM si ottiene 0x8007000D ERROR_INVALID_DATA.
    private const int CR_IN_BASE64 = 0x1;
    private const int CR_DISP_INCOMPLETE = 0;
    private const int CR_DISP_ERROR = 1;
    private const int CR_DISP_DENIED = 2;
    private const int CR_DISP_ISSUED = 3;
    private const int CR_DISP_ISSUED_OUT_OF_BAND = 4;
    private const int CR_DISP_UNDER_SUBMISSION = 5;

    private const int CR_OUT_BASE64 = 0x1;
    private const int CR_OUT_CHAIN = 0x100;

    // SECURITY: policy di validazione input. TemplateName e SanAttribute devono
    // rispettare queste forme strette per non iniettare parametri in certreq.exe/
    // certutil.exe né attributi COM non autorizzati (vulnerabilità H2).
    private static readonly Regex TemplateNameRegex =
        new(@"^[A-Za-z0-9_-]{1,64}\z", RegexOptions.Compiled);
    private static readonly Regex SanAttributeRegex =
        new(@"^san:(?:dns=(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|ip=(?:\d{1,3}\.){3}\d{1,3}|email=[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+|userPrincipalName=[A-Za-z0-9._@-]+)(?:&(?:dns=(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|ip=(?:\d{1,3}\.){3}\d{1,3}|email=[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+|userPrincipalName=[A-Za-z0-9._@-]+))*\z", RegexOptions.Compiled);
    // SECURITY (M6, affinata): la ConfigString deve avere la forma host\NomeCA.
    // Il nome CA (dopo la prima barra rovesciata) può contenere spazi e altri
    // caratteri tipici dei nomi AD CS (es. "vdpki.vd.ld\CloudLD Sub CA"), ma
    // NON virgolette doppie, barre rovesciate aggiuntive né caratteri di
    // controllo: sono gli unici in grado di uscire dal token "quotato" con cui
    // la stringa viene passata a certutil.exe/certreq.exe (CreateProcess, non
    // cmd.exe) e iniettare parametri aggiuntivi.
    private static readonly Regex CaConfigStringRegex =
        new(@"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\\[^""\\\x00-\x1F\x7F]{1,128}\z", RegexOptions.Compiled);

    // Simulatore per CA Demo / Test
    private static readonly Lazy<X509Certificate2> MockRootCa = new(() =>
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Enterprise Mock Root CA, O=Enterprise PKI, C=IT", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
    });

    // Client HTTP per il download dei certificati CA dai URL AIA (completamento
    // catena quando AD CS non li include nella risposta P7B).
    private static readonly HttpClient AiaHttpClient = new() { Timeout = TimeSpan.FromSeconds(10) };

    public AdcsService(IOptionsMonitor<PortalConfig> portalConfigMonitor, ILogger<AdcsService> logger, IHeldRequestStore heldRequestStore)
    {
        _portalConfigMonitor = portalConfigMonitor;
        _logger = logger;
        _heldRequestStore = heldRequestStore;

        _logger.LogInformation(
            "=== PkiPortal v{Version} in avvio (build {BuildTime}) — catena certificati: parser PKCS#7 + completamento AIA attivi ===",
            typeof(AdcsService).Assembly.GetName().Version, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));

        // SECURITY (fail-fast): in Production il simulatore non deve mai emettere
        // certificati: un portale "di produzione" con UseSimulator=true rilascerebbe
        // certificati non validi firmati da una root mock.
        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Production")
        {
            var simulatorCas = (portalConfigMonitor.CurrentValue.CAs ?? new List<CaConfig>())
                .Where(c => c.UseSimulator)
                .Select(c => c.Id)
                .ToList();
            if (simulatorCas.Count > 0)
            {
                throw new InvalidOperationException(
                    "Avvio bloccato (sicurezza): UseSimulator=true per le CA [" + string.Join(", ", simulatorCas) +
                    "] in ASPNETCORE_ENVIRONMENT=Production. Il simulatore non può emettere certificati in produzione: impostare UseSimulator=false in appsettings.json.");
            }
        }
    }

    private PortalConfig Config => _portalConfigMonitor.CurrentValue;

    /// <summary>Tronca e rimuove caratteri di controllo prima di loggare input di terzi (anti log-forging CRLF).</summary>
    private static string SanitizeForLog(string? value) =>
        string.IsNullOrEmpty(value) ? string.Empty :
        new string(value.Take(128).Where(c => !char.IsControl(c)).ToArray());

    public Task<List<CaConfig>> GetAvailableCAsAsync()
    {
        return Task.FromResult(Config.CAs ?? new List<CaConfig>());
    }

    public Task<CaConfig?> GetCaConfigAsync(string? caId)
    {
        if (string.IsNullOrWhiteSpace(caId))
        {
            caId = Config.DefaultCaId;
        }

        var ca = Config.CAs?.FirstOrDefault(c => c.Id.Equals(caId, StringComparison.OrdinalIgnoreCase))
                 ?? Config.CAs?.FirstOrDefault(c => c.IsDefault)
                 ?? Config.CAs?.FirstOrDefault();

        return Task.FromResult(ca);
    }

    public async Task<CertificateSubmissionResponse> SubmitCertificateRequestAsync(CertificateSubmissionRequest request)
    {
        return await SubmitCertificateRequestInternalAsync(request, requesterUser: null);
    }

    /// <summary>
    /// Versione interna che accetta anche il nome dell'utente richiedente (per tracciamento hold).
    /// </summary>
    internal async Task<CertificateSubmissionResponse> SubmitCertificateRequestInternalAsync(CertificateSubmissionRequest request, string? requesterUser)
    {
        var ca = await GetCaConfigAsync(request.CaId);
        if (ca == null)
        {
            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "Failed",
                StatusMessage = "Nessuna configurazione CA valida trovata."
            };
        }

        if (string.IsNullOrWhiteSpace(request.CsrPem))
        {
            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "Failed",
                StatusMessage = "La richiesta CSR Base64 è vuota."
            };
        }

        // SECURITY (H1): una CA non configurata non può essere usata. Il fallback
        // silenzioso alla CA default resta valido solo quando il client non
        // specificava alcuna CA.
        if (!string.IsNullOrWhiteSpace(request.CaId) &&
            !ca.Id.Equals(request.CaId, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Rifiutata sottomissione: CA '{CaId}' non configurata nel portale.", SanitizeForLog(request.CaId));
            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "Failed",
                StatusMessage = "La CA specificata non è configurata nel portale. Verificare l'identificativo CA."
            };
        }

        // SECURITY (H2): validazione stretta di TemplateName e SanAttribute prima di
        // passarli a certreq.exe/certutil/COM: impedisce l'iniezione di parametri.
        if (string.IsNullOrWhiteSpace(request.TemplateName) || !TemplateNameRegex.IsMatch(request.TemplateName))
        {
            _logger.LogWarning("Rifiutata sottomissione: TemplateName non conforme alla policy: '{TemplateName}'.", SanitizeForLog(request.TemplateName));
            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "Failed",
                StatusMessage = "Nome template non valido. Verificare la selezione del template."
            };
        }

        if (!string.IsNullOrWhiteSpace(request.SanAttribute) &&
            (request.SanAttribute.Length > 512 || !SanAttributeRegex.IsMatch(request.SanAttribute)))
        {
            _logger.LogWarning("Rifiutata sottomissione: SanAttribute non conforme al formato atteso: '{San}'.", SanitizeForLog(request.SanAttribute));
            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "Failed",
                StatusMessage = "Formato SAN non valido. Formato atteso: san:dns=nome1&dns=nome2"
            };
        }

        // SECURITY (H1): il template deve essere esplicitamente esposto dal portale
        // per la CA selezionata; qualsiasi altro template è rifiutato.
        var template = ca.Templates.FirstOrDefault(t => t.Name.Equals(request.TemplateName, StringComparison.OrdinalIgnoreCase));
        if (template == null)
        {
            _logger.LogWarning("Rifiutata sottomissione: template '{Template}' non autorizzato per la CA '{CaId}'.", request.TemplateName, ca.Id);
            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "Failed",
                StatusMessage = "Il template richiesto non è disponibile nel portale per questa CA."
            };
        }

        // Verifica se il template richiede approvazione portale
        bool portalApprovalRequired = template?.RequiresApproval ?? false;

        CertificateSubmissionResponse caResponse;

        // Se la CA è configurata per usare il simulatore o se non siamo su Windows
        if (ca.UseSimulator || !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            _logger.LogInformation("Utilizzo del motore di simulazione per la CA {CaId}", ca.Id);
            caResponse = SimulateIssuance(request, ca);
        }
        else
        {
            // Costruzione degli attributi ADCS: "CertificateTemplate:TemplateName\nsan:dns=..."
            var attribsBuilder = new StringBuilder();
            attribsBuilder.Append($"CertificateTemplate:{request.TemplateName}");
            if (!string.IsNullOrWhiteSpace(request.SanAttribute))
            {
                attribsBuilder.AppendLine();
                attribsBuilder.Append(request.SanAttribute);
            }
            string attributes = attribsBuilder.ToString();

            // Eseguiamo la sottomissione all'interno del contesto di sicurezza corretto
            // (Locale oppure con credenziali lette in sicurezza da Windows Credential Manager)
            caResponse = await ExecuteInSecurityContextAsync(ca, async () =>
            {
                // 1. Tentativo con COM Interop nativo (CCertRequest) con timeout
                try
                {
                    _logger.LogInformation("Tentativo di sottomissione via COM CCertRequest verso {ConfigString}", ca.ConfigString);
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        // Esegui COM su un thread separato con timeout di 30 secondi
                        // per evitare blocchi indefiniti se la CA non risponde
                        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                        var comTask = Task.Run(() => OperatingSystem.IsWindows() ? SubmitViaCom(ca.ConfigString, request.CsrPem, attributes) : null, cts.Token);
                        
                        try
                        {
                            var comResponse = await comTask.WaitAsync(cts.Token);
                            if (comResponse != null)
                            {
                                return comResponse;
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            _logger.LogWarning("Timeout di 30 secondi raggiunto per la sottomissione COM verso {ConfigString}. Fallback su certreq.exe.", ca.ConfigString);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Sottomissione via COM fallita o non disponibile. Fallback su certreq.exe CLI.");
                }

                // 2. Fallback su certreq.exe
                try
                {
                    _logger.LogInformation("Tentativo di sottomissione via certreq.exe verso {ConfigString}", ca.ConfigString);
                    return await SubmitViaCertreqAsync(ca.ConfigString, request.CsrPem, request.TemplateName, request.SanAttribute);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Errore durante la sottomissione con certreq.exe");
                    return new CertificateSubmissionResponse
                    {
                        Success = false,
                        Disposition = "Failed",
                        StatusMessage = "Errore durante la comunicazione con la CA ADCS. I dettagli sono disponibili nel log del server."
                    };
                }
            });
        }

        // ======== POST-SUBMISSION REGISTRATION & HOLD ========
        // Se il template ha RequiresApproval=true e la CA ha emesso il certificato automaticamente,
        // il portale trattiene il certificato e NON lo restituisce all'utente finché non approvato.
        if (portalApprovalRequired && caResponse.Success && caResponse.Disposition == "Issued")
        {
            _logger.LogInformation(
                "Il template '{Template}' richiede approvazione portale. La CA ha emesso il certificato (ReqId={RequestId}), ma viene trattenuto in attesa di approvazione admin.",
                request.TemplateName, caResponse.RequestId);

            // Salva il certificato nello store trattenuto (PendingApproval)
            var heldRequest = new HeldCertificateRequest
            {
                CaId = ca.Id,
                TemplateName = request.TemplateName,
                TemplateDisplayName = template?.DisplayName ?? request.TemplateName,
                RequesterComments = request.RequesterComments,
                RequesterUser = requesterUser,
                SanAttribute = request.SanAttribute,
                CaRequestId = caResponse.RequestId,
                CertificatePem = caResponse.CertificatePem,
                CertificateChainPem = caResponse.CertificateChainPem,
                CaCertificatePem = caResponse.CaCertificatePem,
                P7bBase64 = caResponse.P7bBase64,
                PrivateKeyPem = request.PrivateKeyPem,
                Status = HoldStatus.PendingApproval,
                SubjectCommonName = ExtractCn(caResponse.CertificatePem, request.CsrPem)
            };

            await _heldRequestStore.HoldRequestAsync(heldRequest);

            // Restituisci all'utente uno stato "Pending" con riferimento all'HoldId
            return new CertificateSubmissionResponse
            {
                Success = true,
                Disposition = "UnderSubmission",
                RequestId = caResponse.RequestId,
                StatusMessage = $"La richiesta per il template '{template?.DisplayName ?? request.TemplateName}' è stata sottomessa con successo alla CA ed è ora in attesa di approvazione da parte di un amministratore del portale (Hold ID: {heldRequest.HoldId})."
            };
        }
        else if (caResponse.Success && caResponse.Disposition == "Issued")
        {
            // Certificato emesso direttamente (nessuna approvazione richiesta):
            // Registra nel portale con stato 'Issued' per tracciare la proprietà e consentire il recupero sicuro!
            var issuedRecord = new HeldCertificateRequest
            {
                CaId = ca.Id,
                TemplateName = request.TemplateName,
                TemplateDisplayName = template?.DisplayName ?? request.TemplateName,
                RequesterComments = request.RequesterComments,
                RequesterUser = requesterUser,
                SanAttribute = request.SanAttribute,
                CaRequestId = caResponse.RequestId,
                CertificatePem = caResponse.CertificatePem,
                CertificateChainPem = caResponse.CertificateChainPem,
                CaCertificatePem = caResponse.CaCertificatePem,
                P7bBase64 = caResponse.P7bBase64,
                PrivateKeyPem = request.PrivateKeyPem,
                Status = HoldStatus.Issued,
                SubjectCommonName = ExtractCn(caResponse.CertificatePem, request.CsrPem)
            };

            await _heldRequestStore.SaveRequestAsync(issuedRecord);
        }
        else if (caResponse.Success && caResponse.Disposition == "UnderSubmission")
        {
            // Richiesta in sospeso sulla CA:
            // Registra nel portale con stato 'UnderSubmission' per tracciare chi l'ha sottomessa!
            var pendingRecord = new HeldCertificateRequest
            {
                CaId = ca.Id,
                TemplateName = request.TemplateName,
                TemplateDisplayName = template?.DisplayName ?? request.TemplateName,
                RequesterComments = request.RequesterComments,
                RequesterUser = requesterUser,
                SanAttribute = request.SanAttribute,
                CaRequestId = caResponse.RequestId,
                PrivateKeyPem = request.PrivateKeyPem,
                Status = HoldStatus.UnderSubmission,
                SubjectCommonName = ExtractCn(null, request.CsrPem)
            };

            await _heldRequestStore.SaveRequestAsync(pendingRecord);
        }

        return caResponse;
    }


    public async Task<CertificateSubmissionResponse> RetrievePendingCertificateAsync(string? caId, int requestId)
    {
        var ca = await GetCaConfigAsync(caId);
        if (ca == null)
        {
            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "Failed",
                StatusMessage = "Configurazione CA non trovata."
            };
        }

        // Verifica se la richiesta è presente nello store del portale
        var heldRequest = await _heldRequestStore.GetByCaRequestIdAsync(ca.Id, requestId);
        if (heldRequest != null)
        {
            switch (heldRequest.Status)
            {
                case HoldStatus.PendingApproval:
                    return new CertificateSubmissionResponse
                    {
                        Success = true,
                        Disposition = "UnderSubmission",
                        RequestId = requestId,
                        StatusMessage = $"La richiesta per il template '{heldRequest.TemplateDisplayName}' è stata sottomessa alla CA (ID #{requestId}) ma è attualmente in attesa di approvazione da parte di un amministratore del portale (Hold ID: {heldRequest.HoldId})."
                    };

                case HoldStatus.Approved:
                case HoldStatus.Issued:
                    {
                        // Self-healing: se la catena salvata è assente o incompleta
                        // (record registrati con versioni precedenti), la si
                        // ricostruisce dai dati originali (P7B + foglia) con dedup,
                        // completamento locale/AIA e filtro foglia.
                        string? chainToReturn = heldRequest.CertificateChainPem;
                        if (!string.IsNullOrWhiteSpace(heldRequest.P7bBase64) &&
                            !string.IsNullOrWhiteSpace(heldRequest.CertificatePem))
                        {
                            try
                            {
                                var rebuilt = ExtractChainPem(heldRequest.P7bBase64, heldRequest.CaCertificatePem, heldRequest.CertificatePem);
                                if (!string.IsNullOrWhiteSpace(rebuilt) &&
                                    !string.Equals(rebuilt, chainToReturn, StringComparison.Ordinal))
                                {
                                    chainToReturn = rebuilt;
                                    heldRequest.CertificateChainPem = rebuilt;
                                    await _heldRequestStore.UpdateRequestAsync(heldRequest);
                                }
                            }
                            catch { }
                        }

                        return new CertificateSubmissionResponse
                        {
                            Success = true,
                            Disposition = "Issued",
                            RequestId = requestId,
                            StatusMessage = $"Certificato emesso/approvato con successo. Pronto per il download.",
                            CertificatePem = heldRequest.CertificatePem,
                            CertificateChainPem = chainToReturn,
                            CaCertificatePem = heldRequest.CaCertificatePem,
                            P7bBase64 = heldRequest.P7bBase64,
                            PrivateKeyPem = heldRequest.PrivateKeyPem,
                            RequesterUser = heldRequest.RequesterUser,
                            SubjectCommonName = heldRequest.SubjectCommonName,
                            TemplateDisplayName = heldRequest.TemplateDisplayName
                        };
                    }

                case HoldStatus.Rejected:
                    return new CertificateSubmissionResponse
                    {
                        Success = false,
                        Disposition = "Denied",
                        RequestId = requestId,
                        StatusMessage = $"La richiesta è stata rifiutata dall'amministratore {heldRequest.ReviewedBy}." +
                                       (string.IsNullOrWhiteSpace(heldRequest.RejectionReason) ? "" : $" Motivo: {heldRequest.RejectionReason}"),
                        RequesterUser = heldRequest.RequesterUser,
                        SubjectCommonName = heldRequest.SubjectCommonName,
                        TemplateDisplayName = heldRequest.TemplateDisplayName
                    };

                case HoldStatus.UnderSubmission:
                    // Richiesta in sospeso sulla CA, proseguiamo sotto per verificare se la CA l'ha emessa!
                    break;
            }
        }

        if (ca.UseSimulator || !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            if (heldRequest != null && (heldRequest.Status == HoldStatus.Issued || heldRequest.Status == HoldStatus.Approved))
            {
                return new CertificateSubmissionResponse
                {
                    Success = true,
                    Disposition = "Issued",
                    RequestId = requestId,
                    StatusMessage = $"[SIMULATORE] Certificato emesso. Pronto per il download.",
                    CertificatePem = heldRequest.CertificatePem,
                    CertificateChainPem = heldRequest.CertificateChainPem,
                    CaCertificatePem = heldRequest.CaCertificatePem,
                    P7bBase64 = heldRequest.P7bBase64,
                    PrivateKeyPem = heldRequest.PrivateKeyPem,
                    RequesterUser = heldRequest.RequesterUser,
                    SubjectCommonName = heldRequest.SubjectCommonName,
                    TemplateDisplayName = heldRequest.TemplateDisplayName
                };
            }

            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "UnderSubmission",
                RequestId = requestId,
                StatusMessage = $"La richiesta #{requestId} è ancora in attesa di approvazione o non è stata trovata nel simulatore.",
                RequesterUser = heldRequest?.RequesterUser,
                SubjectCommonName = heldRequest?.SubjectCommonName,
                TemplateDisplayName = heldRequest?.TemplateDisplayName
            };
        }

        // Interrogazione CA reale tramite contesto di sicurezza (COM o certreq.exe)
        var caResult = await ExecuteInSecurityContextAsync(ca, async () =>
        {
            // 1. Prova prima via COM CCertRequest (in-process, supporta impersonazione di rete)
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                    var comTask = Task.Run(() => OperatingSystem.IsWindows() ? RetrieveViaCom(ca.ConfigString, requestId) : null, cts.Token);
                    var comResponse = await comTask.WaitAsync(cts.Token);
                    if (comResponse != null)
                    {
                        return comResponse;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Recupero via COM fallito per RequestId #{RequestId}. Fallback su certreq.exe.", requestId);
            }

            // 2. Fallback su certreq.exe CLI
            return await RetrieveViaCertreqAsync(ca.ConfigString, requestId);
        });

        // Se la CA ha emesso il certificato, aggiorna o registra nello store locale
        if (caResult.Success && caResult.Disposition == "Issued")
        {
            if (heldRequest != null)
            {
                heldRequest.Status = HoldStatus.Issued;
                heldRequest.CertificatePem = caResult.CertificatePem;
                heldRequest.CertificateChainPem = caResult.CertificateChainPem;
                heldRequest.CaCertificatePem = caResult.CaCertificatePem;
                heldRequest.P7bBase64 = caResult.P7bBase64;
                await _heldRequestStore.UpdateRequestAsync(heldRequest);
            }
            else
            {
                var newRecord = new HeldCertificateRequest
                {
                    CaId = ca.Id,
                    CaRequestId = requestId,
                    Status = HoldStatus.Issued,
                    CertificatePem = caResult.CertificatePem,
                    CertificateChainPem = caResult.CertificateChainPem,
                    CaCertificatePem = caResult.CaCertificatePem,
                    P7bBase64 = caResult.P7bBase64,
                    SubjectCommonName = ExtractCn(caResult.CertificatePem, null)
                };
                await _heldRequestStore.SaveRequestAsync(newRecord);
            }
        }

        if (heldRequest != null)
        {
            caResult.PrivateKeyPem = heldRequest.PrivateKeyPem;
            caResult.RequesterUser = heldRequest.RequesterUser;
            caResult.SubjectCommonName = heldRequest.SubjectCommonName;
            caResult.TemplateDisplayName = heldRequest.TemplateDisplayName;
        }

        return caResult;
    }

    #region Gestione Contesto di Sicurezza & Windows Credential Manager

    /// <summary>
    /// Esegue un'azione delegata applicando l'autenticazione remota appropriata:
    /// - Se AuthMode == "CredentialManager": cerca il target nel Credential Manager di Windows,
    ///   effettua un LogonUser (NewCredentials) ed impersona il contesto di rete verso la foresta remota.
    /// - Se AuthMode == "LocalIdentity" (default): esegue direttamente con l'identità dell'App Pool locale.
    /// </summary>
    private async Task<CertificateSubmissionResponse> ExecuteInSecurityContextAsync(CaConfig ca, Func<Task<CertificateSubmissionResponse>> action)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ||
            !string.Equals(ca.AuthMode, "CredentialManager", StringComparison.OrdinalIgnoreCase))
        {
            // Modalità Locale / Integrated Identity
            return await action();
        }

        // Determina il target da cercare nel Credential Manager
        string target = ca.CredentialTarget ?? ExtractHostFromConfigString(ca.ConfigString);
        _logger.LogInformation("Autenticazione via Credential Manager per la CA '{CaId}' con Target: '{Target}'", ca.Id, target);

        CredentialInfo? cred = ReadCredentialFromManager(target);
        if (cred == null)
        {
            _logger.LogWarning("Nessuna credenziale trovata in Windows Credential Manager per il target '{Target}'. Tentativo di esecuzione con identità locale.", target);
            return await action();
        }

        _logger.LogInformation("Credenziale trovata per Target '{Target}': Utente='{User}' (Dominio='{Domain}')", target, cred.Username, cred.Domain);

        // Effettua l'impersonazione di rete per accedere alla foresta non trustata
        SafeAccessTokenHandle? tokenHandle = null;
        try
        {
            const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
            const int LOGON32_PROVIDER_WINNT50 = 3;

            bool logonOk = LogonUser(
                cred.Username,
                cred.Domain,
                cred.Password,
                LOGON32_LOGON_NEW_CREDENTIALS,
                LOGON32_PROVIDER_WINNT50,
                out tokenHandle);

            if (!logonOk || tokenHandle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                _logger.LogError("LogonUser fallito per {Domain}\\{User} (Win32 Error: {Error})", cred.Domain, cred.Username, error);
                throw new Win32Exception(error, "Impossibile autenticarsi con le credenziali del Credential Manager.");
            }

            // Esegue l'azione sotto il token di rete impersonato
            return await WindowsIdentity.RunImpersonated(tokenHandle, async () =>
            {
                _logger.LogInformation("Esecuzione richiesta CA in contesto impersonato per la foresta '{Domain}'", cred.Domain);
                return await action();
            });
        }
        finally
        {
            tokenHandle?.Dispose();
        }
    }

    private static string ExtractHostFromConfigString(string configString)
    {
        if (string.IsNullOrWhiteSpace(configString)) return string.Empty;
        var parts = configString.Split('\\', '/');
        return parts[0].Trim();
    }

    private class CredentialInfo
    {
        public string Username { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private CredentialInfo? ReadCredentialFromManager(string targetName)
    {
        try
        {
            if (CredReadW(targetName, CRED_TYPE_GENERIC, 0, out IntPtr credPtr) ||
                CredReadW(targetName, CRED_TYPE_DOMAIN_PASSWORD, 0, out credPtr))
            {
                try
                {
                    var cred = Marshal.PtrToStructure<CREDENTIAL>(credPtr);
                    string fullUserName = Marshal.PtrToStringUni(cred.UserName) ?? string.Empty;
                    string password = Marshal.PtrToStringUni(cred.CredentialBlob, (int)cred.CredentialBlobSize / 2);

                    string domain = string.Empty;
                    string user = fullUserName;

                    if (fullUserName.Contains('\\'))
                    {
                        var parts = fullUserName.Split('\\');
                        domain = parts[0];
                        user = parts[1];
                    }
                    else if (fullUserName.Contains('@'))
                    {
                        var parts = fullUserName.Split('@');
                        user = parts[0];
                        domain = parts[1];
                    }

                    return new CredentialInfo
                    {
                        Username = user,
                        Domain = domain,
                        Password = password
                    };
                }
                finally
                {
                    CredFree(credPtr);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Errore durante la lettura dal Windows Credential Manager per il target '{Target}'", targetName.Replace("\r", string.Empty).Replace("\n", string.Empty));
        }

        return null;
    }

    #region Win32 P/Invoke per Credential Manager e LogonUser
    private const int CRED_TYPE_GENERIC = 1;
    private const int CRED_TYPE_DOMAIN_PASSWORD = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredReadW(string target, uint type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = false)]
    private static extern void CredFree(IntPtr buffer);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out SafeAccessTokenHandle phToken);
    #endregion

    #endregion

    #region Implementazione COM CCertRequest
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private CertificateSubmissionResponse? SubmitViaCom(string caConfigString, string csrPem, string attributes)
    {
        var certRequestType = Type.GetTypeFromProgID("CertificateAuthority.Request");
        if (certRequestType == null)
        {
            _logger.LogInformation("ProgID 'CertificateAuthority.Request' non registrato su questo sistema.");
            return null;
        }

        dynamic certRequest = Activator.CreateInstance(certRequestType)!;
        try
        {
            // CCertRequest::Submit con CR_IN_BASE64 attende la CSR come Base64
            // del DER PKCS#10: si converte dal PEM armato (rimozione armatura e
            // whitespace = Base64 del DER).
            string csrBase64 = PemToBase64Der(csrPem);
            int disposition = certRequest.Submit(CR_IN_BASE64, csrBase64, attributes, caConfigString);
            int reqId = certRequest.GetRequestId();
            string dispMessage = certRequest.GetDispositionMessage();

            _logger.LogInformation("Risultato COM Submit: disposition={Disposition}, RequestId={RequestId}, Message={Message}", disposition, reqId, dispMessage);

            switch (disposition)
            {
                case CR_DISP_ISSUED:
                case CR_DISP_ISSUED_OUT_OF_BAND:
                    string certBase64 = certRequest.GetCertificate(CR_OUT_BASE64);
                    string? chainBase64 = null;
                    try
                    {
                        chainBase64 = certRequest.GetCertificate(CR_OUT_BASE64 | CR_OUT_CHAIN);
                    }
                    catch { }

                    string? caCertBase64 = null;
                    try
                    {
                        caCertBase64 = certRequest.GetCACertificate(0, caConfigString, CR_OUT_BASE64);
                    }
                    catch { }

                    string? normalizedCertPem = NormalizeCertificate(certBase64);
                    string? normalizedChainPem = ExtractChainPem(chainBase64, caCertBase64, normalizedCertPem);
                    string? normalizedCaCertPem = NormalizeCertificate(caCertBase64);
                    _logger.LogInformation("Catena COM Submit (Req #{ReqId}): {Desc}", reqId, DescribeChain(chainBase64, normalizedChainPem));

                    return new CertificateSubmissionResponse
                    {
                        Success = true,
                        Disposition = "Issued",
                        RequestId = reqId,
                        StatusMessage = "Certificato emesso con successo da AD CS.",
                        CertificatePem = normalizedCertPem,
                        CertificateChainPem = normalizedChainPem,
                        CaCertificatePem = normalizedCaCertPem,
                        // Base64 del contenuto standard del file .p7b (PKCS#7 con catena completa)
                        P7bBase64 = BuildP7bBase64Field(chainBase64)
                    };

                case CR_DISP_UNDER_SUBMISSION:
                    return new CertificateSubmissionResponse
                    {
                        Success = true,
                        Disposition = "UnderSubmission",
                        RequestId = reqId,
                        StatusMessage = $"Richiesta sottomessa con successo. La richiesta è in attesa di approvazione manuale (Pending) con Request ID #{reqId}."
                    };

                case CR_DISP_DENIED:
                    return new CertificateSubmissionResponse
                    {
                        Success = false,
                        Disposition = "Denied",
                        RequestId = reqId,
                        StatusMessage = $"Richiesta rifiutata dalla CA ADCS: {dispMessage}"
                    };

                default:
                    return new CertificateSubmissionResponse
                    {
                        Success = false,
                        Disposition = "Failed",
                        RequestId = reqId,
                        StatusMessage = $"Errore durante la sottomissione: {dispMessage} (Code: {disposition})"
                    };
            }
        }
        finally
        {
            if (certRequest != null)
            {
                Marshal.ReleaseComObject(certRequest);
            }
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private CertificateSubmissionResponse? RetrieveViaCom(string caConfigString, int requestId)
    {
        var certRequestType = Type.GetTypeFromProgID("CertificateAuthority.Request");
        if (certRequestType == null)
        {
            _logger.LogInformation("ProgID 'CertificateAuthority.Request' non registrato su questo sistema.");
            return null;
        }

        dynamic certRequest = Activator.CreateInstance(certRequestType)!;
        try
        {
            int disposition = certRequest.RetrievePending(requestId, caConfigString);
            string dispMessage = certRequest.GetDispositionMessage();
            _logger.LogInformation("Risultato COM RetrievePending per Request #{RequestId}: disposition={Disposition}, Message={Message}", requestId, disposition, dispMessage);

            switch (disposition)
            {
                case CR_DISP_ISSUED:
                case CR_DISP_ISSUED_OUT_OF_BAND:
                    string certBase64 = certRequest.GetCertificate(CR_OUT_BASE64);
                    string? chainBase64 = null;
                    try
                    {
                        chainBase64 = certRequest.GetCertificate(CR_OUT_BASE64 | CR_OUT_CHAIN);
                    }
                    catch { }

                    string? caCertBase64 = null;
                    try
                    {
                        caCertBase64 = certRequest.GetCACertificate(0, caConfigString, CR_OUT_BASE64);
                    }
                    catch { }

                    string? normalizedCertPem = NormalizeCertificate(certBase64);
                    string? normalizedChainPem = ExtractChainPem(chainBase64, caCertBase64, normalizedCertPem);
                    string? normalizedCaCertPem = NormalizeCertificate(caCertBase64);
                    _logger.LogInformation("Catena COM Retrieve (Req #{ReqId}): {Desc}", requestId, DescribeChain(chainBase64, normalizedChainPem));

                    return new CertificateSubmissionResponse
                    {
                        Success = true,
                        Disposition = "Issued",
                        RequestId = requestId,
                        StatusMessage = $"Certificato approvato ed emesso con successo da AD CS (Request #{requestId}).",
                        CertificatePem = normalizedCertPem,
                        CertificateChainPem = normalizedChainPem,
                        CaCertificatePem = normalizedCaCertPem,
                        // Base64 del contenuto standard del file .p7b (PKCS#7 con catena completa)
                        P7bBase64 = BuildP7bBase64Field(chainBase64)
                    };

                case CR_DISP_UNDER_SUBMISSION:
                    return new CertificateSubmissionResponse
                    {
                        Success = true,
                        Disposition = "UnderSubmission",
                        RequestId = requestId,
                        StatusMessage = $"La richiesta #{requestId} è ancora in attesa di approvazione da parte dell'amministratore CA ADCS."
                    };

                case CR_DISP_DENIED:
                    return new CertificateSubmissionResponse
                    {
                        Success = false,
                        Disposition = "Denied",
                        RequestId = requestId,
                        StatusMessage = $"La richiesta #{requestId} è stata rifiutata dalla CA ADCS: {dispMessage}"
                    };

                default:
                    return new CertificateSubmissionResponse
                    {
                        Success = false,
                        Disposition = "Failed",
                        RequestId = requestId,
                        StatusMessage = $"Stato richiesta #{requestId}: {dispMessage} (Codice: {disposition})"
                    };
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Eccezione COM RetrievePending per RequestId #{RequestId}", requestId);
            return null;
        }
        finally
        {
            if (certRequest != null)
            {
                Marshal.ReleaseComObject(certRequest);
            }
        }
    }
    #endregion

    #region Implementazione CLI certreq.exe
    private static string GetSecureTempFilePath(string prefix, string extension)
    {
        var tempDir = Path.Combine(AppContext.BaseDirectory, "App_Data", "Temp");
        try
        {
            Directory.CreateDirectory(tempDir);
        }
        catch { }
        return Path.Combine(tempDir, $"{prefix}_{Guid.NewGuid():N}{extension}");
    }

    private async Task<CertificateSubmissionResponse> SubmitViaCertreqAsync(string caConfigString, string csrPem, string templateName, string? sanAttribute)
    {
        string tempReqPath = GetSecureTempFilePath("pki_req", ".req");
        string tempCerPath = GetSecureTempFilePath("pki_out", ".cer");
        string tempChainPath = GetSecureTempFilePath("pki_chain", ".p7b");

        try
        {
            await File.WriteAllTextAsync(tempReqPath, csrPem);

            var attribArg = $"CertificateTemplate:{templateName}";
            if (!string.IsNullOrWhiteSpace(sanAttribute))
            {
                attribArg += $"\n{sanAttribute}";
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = "certreq.exe",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            startInfo.ArgumentList.Add("-submit");
            startInfo.ArgumentList.Add("-config");
            startInfo.ArgumentList.Add(caConfigString);
            startInfo.ArgumentList.Add("-attrib");
            startInfo.ArgumentList.Add(attribArg);
            startInfo.ArgumentList.Add(tempReqPath);
            startInfo.ArgumentList.Add(tempCerPath);
            startInfo.ArgumentList.Add(tempChainPath);

            using var process = new Process { StartInfo = startInfo };
            var outputBuilder = new StringBuilder();
            process.OutputDataReceived += (s, e) => { if (e.Data != null) outputBuilder.AppendLine(e.Data); };
            process.ErrorDataReceived += (s, e) => { if (e.Data != null) outputBuilder.AppendLine(e.Data); };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            
            // Timeout di 60 secondi per evitare blocchi se la CA è irraggiungibile
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Timeout di 60 secondi raggiunto per certreq.exe. Terminazione del processo.");
                try { process.Kill(entireProcessTree: true); } catch { }
                return new CertificateSubmissionResponse
                {
                    Success = false,
                    Disposition = "Failed",
                    StatusMessage = "Timeout: la CA non ha risposto entro 60 secondi. Verificare la connettività di rete e la raggiungibilità della CA."
                };
            }

            string fullOutput = outputBuilder.ToString();
            _logger.LogInformation("Output certreq.exe (exit {ExitCode}): {Output}", process.ExitCode, fullOutput);

            // Analisi dell'output di certreq
            // In caso di emissione: il file .cer viene creato
            if (File.Exists(tempCerPath) && new FileInfo(tempCerPath).Length > 0)
            {
                byte[] certBytes = await File.ReadAllBytesAsync(tempCerPath);
                var (issuedPem, cerChainPem) = ParseCertreqOutputBytes(certBytes);
                _logger.LogInformation("File .cer certreq: {Len} byte, inizio: {Head}, foglia: {Leaf}", certBytes.Length, DescribeBytesHead(certBytes), issuedPem != null ? "riconosciuta" : "NON RICONOSCIUTA");

                string? p7bBase64 = null;
                if (File.Exists(tempChainPath) && new FileInfo(tempChainPath).Length > 0)
                {
                    try
                    {
                        byte[] chainBytes = await File.ReadAllBytesAsync(tempChainPath);
                        // Normalizza il contenuto del file .p7b (certreq lo scrive
                        // come testo Base64 di un PKCS#7): il client riceve sempre
                        // Base64 del contenuto standard del file .p7b.
                        string? p7bContent = BuildP7bFileContent(chainBytes);
                        p7bBase64 = p7bContent != null
                            ? Convert.ToBase64String(Encoding.ASCII.GetBytes(p7bContent))
                            : Convert.ToBase64String(chainBytes);
                    }
                    catch { }
                }

                // La catena viene SEMPRE costruita con ExtractChainPem (deduplica
                // la foglia, completa la root via store locale/AIA, filtro finale):
                // l'estrazione "nava" da .p7b/.cer non viene mai restituita così com'è.
                string? chainPem = null;
                if (!string.IsNullOrWhiteSpace(p7bBase64))
                {
                    try { chainPem = ExtractChainPem(p7bBase64, null, issuedPem); } catch { }
                }
                if (string.IsNullOrWhiteSpace(chainPem) && !string.IsNullOrWhiteSpace(cerChainPem))
                {
                    try { chainPem = ExtractChainPem(cerChainPem, null, issuedPem); } catch { }
                }
                if (string.IsNullOrWhiteSpace(chainPem) && !string.IsNullOrWhiteSpace(cerChainPem))
                {
                    chainPem = cerChainPem; // estremo residuo: catena del .cer così com'è
                }

                int reqId = ExtractRequestId(fullOutput);
                _logger.LogInformation("Catena certreq Submit (Req #{ReqId}): {Desc}", reqId, DescribeChain(p7bBase64, chainPem));

                return new CertificateSubmissionResponse
                {
                    Success = true,
                    Disposition = "Issued",
                    RequestId = reqId,
                    StatusMessage = "Certificato emesso con successo da AD CS.",
                    CertificatePem = issuedPem,
                    CertificateChainPem = chainPem,
                    P7bBase64 = p7bBase64
                };
            }

            // Verifica se la richiesta è Pending (in attesa di approvazione)
            if (fullOutput.Contains("Pending", StringComparison.OrdinalIgnoreCase) ||
                fullOutput.Contains("Taken Under Submission", StringComparison.OrdinalIgnoreCase) ||
                fullOutput.Contains("Incomplete", StringComparison.OrdinalIgnoreCase))
            {
                int reqId = ExtractRequestId(fullOutput);
                return new CertificateSubmissionResponse
                {
                    Success = true,
                    Disposition = "UnderSubmission",
                    RequestId = reqId,
                    StatusMessage = $"Richiesta presa in carico (Pending). Identificativo richiesta: #{reqId}.",
                };
            }

            // In caso di errore o rifiuto
            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = fullOutput.Contains("Denied", StringComparison.OrdinalIgnoreCase) ? "Denied" : "Failed",
                StatusMessage = $"Richiesta fallita: {fullOutput.Trim()}",
                RawOutput = fullOutput
            };
        }
        finally
        {
            if (File.Exists(tempReqPath)) try { File.Delete(tempReqPath); } catch { }
            if (File.Exists(tempCerPath)) try { File.Delete(tempCerPath); } catch { }
            if (File.Exists(tempChainPath)) try { File.Delete(tempChainPath); } catch { }
        }
    }

    private async Task<CertificateSubmissionResponse> RetrieveViaCertreqAsync(string caConfigString, int requestId)
    {
        string tempCerPath = GetSecureTempFilePath("pki_ret", ".cer");
        string tempChainPath = GetSecureTempFilePath("pki_chain", ".p7b");
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "certreq.exe",
                Arguments = $"-retrieve -config \"{caConfigString}\" -q -f {requestId} \"{tempCerPath}\" \"{tempChainPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = startInfo };
            var outputBuilder = new StringBuilder();
            process.OutputDataReceived += (s, e) => { if (e.Data != null) outputBuilder.AppendLine(e.Data); };
            process.ErrorDataReceived += (s, e) => { if (e.Data != null) outputBuilder.AppendLine(e.Data); };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Timeout di 60 secondi raggiunto per certreq.exe -retrieve #{RequestId}. Terminazione.", requestId);
                try { process.Kill(entireProcessTree: true); } catch { }
                return new CertificateSubmissionResponse
                {
                    Success = false,
                    Disposition = "Failed",
                    RequestId = requestId,
                    StatusMessage = "Timeout durante l'interrogazione della CA ADCS tramite certreq.exe."
                };
            }

            string fullOutput = outputBuilder.ToString();

            if (File.Exists(tempCerPath) && new FileInfo(tempCerPath).Length > 0)
            {
                byte[] certBytes = await File.ReadAllBytesAsync(tempCerPath);
                var (issuedPem, cerChainPem) = ParseCertreqOutputBytes(certBytes);
                _logger.LogInformation("File .cer certreq: {Len} byte, inizio: {Head}, foglia: {Leaf}", certBytes.Length, DescribeBytesHead(certBytes), issuedPem != null ? "riconosciuta" : "NON RICONOSCIUTA");

                string? p7bBase64 = null;
                if (File.Exists(tempChainPath) && new FileInfo(tempChainPath).Length > 0)
                {
                    try
                    {
                        byte[] chainBytes = await File.ReadAllBytesAsync(tempChainPath);
                        // Normalizza il contenuto del file .p7b (certreq lo scrive
                        // come testo Base64 di un PKCS#7): il client riceve sempre
                        // Base64 del contenuto standard del file .p7b.
                        string? p7bContent = BuildP7bFileContent(chainBytes);
                        p7bBase64 = p7bContent != null
                            ? Convert.ToBase64String(Encoding.ASCII.GetBytes(p7bContent))
                            : Convert.ToBase64String(chainBytes);
                    }
                    catch { }
                }

                // La catena viene SEMPRE costruita con ExtractChainPem (deduplica
                // la foglia, completa la root via store locale/AIA, filtro finale):
                // l'estrazione "nava" da .p7b/.cer non viene mai restituita così com'è.
                string? chainPem = null;
                if (!string.IsNullOrWhiteSpace(p7bBase64))
                {
                    try { chainPem = ExtractChainPem(p7bBase64, null, issuedPem); } catch { }
                }
                if (string.IsNullOrWhiteSpace(chainPem) && !string.IsNullOrWhiteSpace(cerChainPem))
                {
                    try { chainPem = ExtractChainPem(cerChainPem, null, issuedPem); } catch { }
                }
                if (string.IsNullOrWhiteSpace(chainPem) && !string.IsNullOrWhiteSpace(cerChainPem))
                {
                    chainPem = cerChainPem; // estremo residuo: catena del .cer così com'è
                }

                _logger.LogInformation("Catena certreq Retrieve (Req #{ReqId}): {Desc}", requestId, DescribeChain(p7bBase64, chainPem));

                return new CertificateSubmissionResponse
                {
                    Success = true,
                    Disposition = "Issued",
                    RequestId = requestId,
                    StatusMessage = $"Certificato approvato ed estratto con successo (Request #{requestId}).",
                    CertificatePem = issuedPem,
                    CertificateChainPem = chainPem,
                    P7bBase64 = p7bBase64
                };
            }

            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "UnderSubmission",
                RequestId = requestId,
                StatusMessage = $"La richiesta #{requestId} è ancora in attesa di approvazione o non è stata trovata. Output: {fullOutput.Trim()}"
            };
        }
        finally
        {
            if (File.Exists(tempCerPath)) try { File.Delete(tempCerPath); } catch { }
            if (File.Exists(tempChainPath)) try { File.Delete(tempChainPath); } catch { }
        }
    }

    private static int ExtractRequestId(string output)
    {
        var match = System.Text.RegularExpressions.Regex.Match(output, @"Request Id:\s*(\d+)|RequestId:\s*(\d+)|Id richiesta:\s*(\d+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (match.Success)
        {
            var val = match.Groups[1].Value;
            if (string.IsNullOrEmpty(val)) val = match.Groups[2].Value;
            if (string.IsNullOrEmpty(val)) val = match.Groups[3].Value;
            if (int.TryParse(val, out int id)) return id;
        }
        return 0;
    }
    #endregion

    #region Scoperta Template Pubblicati dalla CA
    public async Task<TemplateDiscoveryResponse> DiscoverTemplatesAsync(TemplateDiscoveryRequest request)
    {
        if (request.UseSimulator || !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            _logger.LogInformation("Modalità simulatore: restituisco template di esempio.");
            return new TemplateDiscoveryResponse
            {
                Success = true,
                Templates = GetMockTemplates(),
                RawOutput = "Modalità simulatore attiva"
            };
        }

        string configString = request.ConfigString?.Trim() ?? string.Empty;
        string authMode = request.AuthMode ?? "LocalIdentity";
        string? credentialTarget = request.CredentialTarget;
        string? forestOrDomain = null;

        if (!string.IsNullOrWhiteSpace(request.CaId))
        {
            var ca = await GetCaConfigAsync(request.CaId);
            if (ca != null)
            {
                // Il dominio della foresta (per la lettura della validità in AD)
                // viene letto dalla configurazione anche quando la UI invia
                // direttamente la ConfigString.
                forestOrDomain = ca.ForestOrDomain;
                if (string.IsNullOrWhiteSpace(configString))
                {
                    configString = ca.ConfigString;
                    authMode = ca.AuthMode;
                    credentialTarget = ca.CredentialTarget;
                    if (ca.UseSimulator)
                    {
                        return new TemplateDiscoveryResponse
                        {
                            Success = true,
                            Templates = GetMockTemplates(),
                            RawOutput = "Modalità simulatore attiva"
                        };
                    }
                }
            }
        }

        if (string.IsNullOrWhiteSpace(configString))
        {
            _logger.LogWarning("Nessuna ConfigString fornita per la scoperta dei template.");
            return new TemplateDiscoveryResponse
            {
                Success = false,
                ErrorMessage = "Config String della CA non specificata (es. server\\Nome-CA)."
            };
        }

        // SECURITY (M6): la ConfigString deve avere la forma host\NomeCA; un carattere
        // non atteso (es. ") permetterebbe di iniettare parametri in certutil.exe
        // (es. -urlcache per scrittura file) o di collegare il server a host arbitrari.
        if (!CaConfigStringRegex.IsMatch(configString))
        {
            _logger.LogWarning("Scoperta template rifiutata: ConfigString non conforme al formato host\\NomeCA.");
            return new TemplateDiscoveryResponse
            {
                Success = false,
                ErrorMessage = "Config String non valida: il formato atteso è 'server\\Nome-CA'."
            };
        }

        var caConfig = new CaConfig
        {
            Id = request.CaId ?? "temp",
            ConfigString = configString,
            AuthMode = authMode,
            CredentialTarget = credentialTarget
        };

        try
        {
            var (templates, rawOutput, exitCode) = await ExecuteInSecurityContextForTemplatesAsync(caConfig, async credential =>
            {
                // 1. Scoperta dei NOMI dei template pubblicati: prima via COM CCertRequest
                //    (veloce, nativo), poi fallback su certutil.exe -CATemplates.
                List<PublishedTemplate> discovered;
                string raw;
                int exit;

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    try
                    {
                        var comTemplates = QueryCaTemplatesViaCom(configString);
                        if (comTemplates != null && comTemplates.Count > 0)
                        {
                            _logger.LogInformation("Template scoperti con successo via COM CCertRequest: {Count} template", comTemplates.Count);
                            (discovered, raw, exit) = (comTemplates, "Recuperati via COM CCertRequest", 0);
                        }
                        else
                        {
                            (discovered, raw, exit) = await QueryCaTemplatesViaCertutilAsync(configString);
                        }
                    }
                    catch (Exception comEx)
                    {
                        _logger.LogDebug(comEx, "Scoperta template via COM non riuscita, passaggio a certutil.exe");
                        (discovered, raw, exit) = await QueryCaTemplatesViaCertutilAsync(configString);
                    }
                }
                else
                {
                    (discovered, raw, exit) = await QueryCaTemplatesViaCertutilAsync(configString);
                }

                // 2. Lettura della VALIDITÀ direttamente dalla DEFINIZIONE del template
                //    AD CS (attributo pKIDefaultLifetime in AD, fallback certutil):
                //    la validità è definita dal template, non dall'admin del portale.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && discovered.Count > 0)
                {
                    await EnrichTemplatesWithValidityAsync(forestOrDomain, configString, discovered, credential);
                }

                return (discovered, raw, exit);
            });

            bool success = exitCode == 0 || templates.Count > 0;
            string? errorMessage = null;

            if (!success)
            {
                errorMessage = $"certutil ha restituito codice di uscita {exitCode}. Output: {rawOutput.Trim()}";
            }
            else if (templates.Count == 0)
            {
                errorMessage = $"Nessun template pubblicato trovato sulla CA '{configString}'. Output: {rawOutput.Trim()}";
            }

            return new TemplateDiscoveryResponse
            {
                Success = success && templates.Count > 0,
                ErrorMessage = errorMessage,
                RawOutput = rawOutput,
                Templates = templates
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Errore durante la scoperta dei template per ConfigString '{ConfigString}'", configString.Replace("\r", string.Empty).Replace("\n", string.Empty));
            return new TemplateDiscoveryResponse
            {
                Success = false,
                ErrorMessage = $"Eccezione durante la scoperta template: {ex.Message}"
            };
        }
    }

    public async Task<List<PublishedTemplate>> GetPublishedTemplatesAsync(string caId)
    {
        var response = await DiscoverTemplatesAsync(new TemplateDiscoveryRequest { CaId = caId });
        return response.Templates;
    }

    private static List<PublishedTemplate> GetMockTemplates() => new()
    {
        // ValidityDays = validità "definita dal template" (in modalità simulatore
        // le definizioni mock sono l'equivalente delle definizioni AD CS reali).
        new() { Name = "WebServer", DisplayName = "Web Server", ValidityDays = 365 },
        new() { Name = "Machine", DisplayName = "Computer", ValidityDays = 1825 },
        new() { Name = "User", DisplayName = "User", ValidityDays = 730 },
        new() { Name = "SubCA", DisplayName = "Subordinate Certification Authority", ValidityDays = 1825 },
        new() { Name = "CodeSigning", DisplayName = "Code Signing", ValidityDays = 365 },
        new() { Name = "EFS", DisplayName = "Basic EFS", ValidityDays = 730 },
        new() { Name = "EFSRecovery", DisplayName = "EFS Recovery Agent", ValidityDays = 730 },
        new() { Name = "SmartcardLogon", DisplayName = "Smartcard Logon", ValidityDays = 730 },
        new() { Name = "IPSECIntermediateOnline", DisplayName = "IPSec (Offline request)", ValidityDays = 1825 },
        new() { Name = "EnrollmentAgent", DisplayName = "Enrollment Agent", ValidityDays = 365 },
    };

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static List<PublishedTemplate>? QueryCaTemplatesViaCom(string caConfigString)
    {
        var certRequestType = Type.GetTypeFromProgID("CertificateAuthority.Request");
        if (certRequestType == null) return null;

        dynamic? certRequest = null;
        try
        {
            certRequest = Activator.CreateInstance(certRequestType);
            if (certRequest == null) return null;

            const int CR_PROP_TEMPLATES = 29;
            const int PROPTYPE_STRING = 4;

            // In ADCS CCertRequest::GetCAProperty(0, caConfigString, CR_PROP_TEMPLATES, 0, PROPTYPE_STRING, 0)
            string? raw = null;
            try
            {
                raw = certRequest.GetCAProperty(0, caConfigString, CR_PROP_TEMPLATES, 0, PROPTYPE_STRING, 0);
            }
            catch
            {
                try
                {
                    raw = certRequest.GetCAProperty(0, caConfigString, CR_PROP_TEMPLATES, 0, 4, 1 /* CR_OUT_BASE64 */);
                }
                catch { }
            }

            if (!string.IsNullOrWhiteSpace(raw))
            {
                var list = new List<PublishedTemplate>();
                foreach (var item in raw.Split(new[] { '\n', '\r', '\0' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = item.Trim();
                    if (!string.IsNullOrWhiteSpace(trimmed))
                    {
                        var colonIdx = trimmed.IndexOf(':');
                        if (colonIdx > 0)
                        {
                            var name = trimmed.Substring(0, colonIdx).Trim();
                            var disp = trimmed.Substring(colonIdx + 1).Trim();
                            list.Add(new PublishedTemplate { Name = name, DisplayName = disp });
                        }
                        else
                        {
                            list.Add(new PublishedTemplate { Name = trimmed, DisplayName = trimmed });
                        }
                    }
                }
                if (list.Count > 0) return list;
            }
        }
        catch { }
        finally
        {
            if (certRequest != null)
            {
                try { Marshal.ReleaseComObject(certRequest); } catch { }
            }
        }
        return null;
    }

    /// <summary>
    /// Esegue l'azione in sicurezza; quando opera in modalità CredentialManager
    /// trasmette all'azione anche le credenziali esplicate (parametro <c>credential</c>
    /// dell'azione) così che le operazioni in-process (es. LDAP) possano usare
    /// l'identità corretta: COM e processi figli ereditano l'impersonazione, ma
    /// new NetworkCredential() NO.
    /// </summary>
    private async Task<(List<PublishedTemplate> Templates, string RawOutput, int ExitCode)> ExecuteInSecurityContextForTemplatesAsync(
        CaConfig ca, Func<CredentialInfo?, Task<(List<PublishedTemplate> Templates, string RawOutput, int ExitCode)>> action)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ||
            !string.Equals(ca.AuthMode, "CredentialManager", StringComparison.OrdinalIgnoreCase))
        {
            return await action(null);
        }

        string target = ca.CredentialTarget ?? ExtractHostFromConfigString(ca.ConfigString);
        CredentialInfo? cred = ReadCredentialFromManager(target);
        if (cred == null)
        {
            _logger.LogWarning("Nessuna credenziale trovata per il target '{Target}'. Tentativo con identità locale.", target.Replace("\r", string.Empty).Replace("\n", string.Empty));
            return await action(null);
        }

        SafeAccessTokenHandle? tokenHandle = null;
        try
        {
            const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
            const int LOGON32_PROVIDER_WINNT50 = 3;

            bool logonOk = LogonUser(cred.Username, cred.Domain, cred.Password,
                LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, out tokenHandle);

            if (!logonOk || tokenHandle.IsInvalid)
            {
                _logger.LogWarning("LogonUser fallito per la scoperta template. Uso identità locale.");
                return await action(null);
            }

            return await WindowsIdentity.RunImpersonated(tokenHandle, async () => await action(cred));
        }
        finally
        {
            tokenHandle?.Dispose();
        }
    }

    private async Task<(List<PublishedTemplate> Templates, string RawOutput, int ExitCode)> QueryCaTemplatesViaCertutilAsync(string configString)
    {
        var results = new List<PublishedTemplate>();

        // NOTA: in certutil le opzioni come -config DEVONO precedere il comando -CATemplates,
        // altrimenti certutil interpreta "-config" come il nome del template da cercare!
        var startInfo = new ProcessStartInfo
        {
            FileName = "certutil.exe",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-config");
        startInfo.ArgumentList.Add(configString);
        startInfo.ArgumentList.Add("-CATemplates");

        using var process = new Process { StartInfo = startInfo };
        var stdoutBuilder = new StringBuilder();
        var stderrBuilder = new StringBuilder();
        process.OutputDataReceived += (s, e) => { if (e.Data != null) stdoutBuilder.AppendLine(e.Data); };
        process.ErrorDataReceived += (s, e) => { if (e.Data != null) stderrBuilder.AppendLine(e.Data); };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            return (results, "Timeout: certutil non ha risposto entro 30 secondi.", -1);
        }

        string stdout = stdoutBuilder.ToString();
        string stderr = stderrBuilder.ToString();
        string combinedOutput = stdout + (string.IsNullOrWhiteSpace(stderr) ? "" : "\n[STDERR]\n" + stderr);

        _logger.LogInformation("Output certutil -CATemplates (exit {ExitCode}):\nSTDOUT: {Stdout}\nSTDERR: {Stderr}", 
            process.ExitCode, stdout, stderr);

        // Parsing dell'output di certutil -CATemplates
        // Formato tipico: "NomeTemplate: Display Name -- Flags..."
        // Ogni riga contenente ":" è potenzialmente un template
        foreach (var line in stdout.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed)) continue;
            
            // Ignora righe di sistema certutil
            if (trimmed.StartsWith("CertUtil", StringComparison.OrdinalIgnoreCase)) continue;
            if (trimmed.StartsWith("Entry", StringComparison.OrdinalIgnoreCase)) continue;
            if (trimmed.StartsWith("Cert", StringComparison.OrdinalIgnoreCase) && trimmed.Contains("command")) continue;
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) continue;
            if (!trimmed.Contains(':')) continue;

            var colonIdx = trimmed.IndexOf(':');
            var name = trimmed.Substring(0, colonIdx).Trim();
            var rest = trimmed.Substring(colonIdx + 1).Trim();

            // Ignora righe dove il "nome" contiene spazi (probabile messaggio, non un template name)
            // I nomi template ADCS non contengono spazi
            if (name.Contains(' ')) continue;

            // Rimuovi eventuale " -- Flags/Description" dalla display name
            var dashIdx = rest.IndexOf(" -- ");
            var displayName = dashIdx >= 0 ? rest.Substring(0, dashIdx).Trim() : rest.Trim();

            if (!string.IsNullOrWhiteSpace(name) && name.Length < 100)
            {
                results.Add(new PublishedTemplate
                {
                    Name = name,
                    DisplayName = !string.IsNullOrWhiteSpace(displayName) ? displayName : name
                });
            }
        }

        _logger.LogInformation("Trovati {Count} template pubblicati sulla CA '{Config}'", results.Count, configString.Replace("\r", string.Empty).Replace("\n", string.Empty));
        return (results, combinedOutput, process.ExitCode);
    }

    /// <summary>
    /// Per ogni template scoperto, legge la DEFINIZIONE del template AD CS e
    /// imposta ValidityDays dal suo periodo di validità.
    /// Fonte primaria: l'oggetto del template in Active Directory
    /// (CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration),
    /// attributo pKIExpirationPeriod — la definizione canonica del template,
    /// indipendente dalla localizzazione. Fallback: certutil -template (KeyUsagePeriod).
    /// La validità è quindi presa direttamente dalla definizione del template,
    /// non è un valore inserito manualmente dall'amministratore.
    /// </summary>
    private async Task EnrichTemplatesWithValidityAsync(string? forestOrDomain, string configString, List<PublishedTemplate> templates, CredentialInfo? credential)
    {
        // Tetto di sicurezza: non interrogare la CA/AD per decine di template
        const int MaxTemplatesToQuery = 50;

        // SECURITY (H2): solo i nomi conformi alla policy stretta sono usati nelle
        // query (anti iniezione LDAP/certutil: i nomi ammessi non contengono
        // caratteri speciali del filtro LDAP né spazi).
        var toQuery = templates
            .Where(t => TemplateNameRegex.IsMatch(t.Name))
            .Take(MaxTemplatesToQuery)
            .ToList();
        if (toQuery.Count == 0) return;

        // 1. Fonte primaria: definizione del template in AD (pKIDefaultLifetime)
        string? domain = DetermineAdDomain(forestOrDomain, configString);
        bool adAvailable = false;
        if (domain != null)
        {
            NetworkCredential? ldapCred = credential == null
                ? null
                : new NetworkCredential(string.IsNullOrWhiteSpace(credential.Domain)
                    ? credential.Username
                    : $"{credential.Domain}\\{credential.Username}", credential.Password);
            var (map, adSucceeded) = await GetTemplateValidityFromAdAsync(domain, toQuery.Select(t => t.Name).ToList(), ldapCred);
            adAvailable = adSucceeded;
            foreach (var t in toQuery)
            {
                if (map.TryGetValue(t.Name, out int days))
                {
                    t.ValidityDays = days;
                    _logger.LogInformation("Template '{Template}': validità di {Days} giorni letta dalla definizione AD del template (pKIDefaultLifetime).", t.Name, days);
                }
            }
        }
        else
        {
            _logger.LogWarning("Impossibile determinare il dominio AD per la CA '{Config}': validità non disponibile.", configString.Replace("\r", string.Empty).Replace("\n", string.Empty));
        }

        // 2. Fallback: certutil -template SOLO se AD è raggiungibile ma la
        //    validità di un template non è presente in AD (caso raro). Se AD non
        //    è raggiungibile il fallback sarebbe lento e inutile: si salta.
        if (adAvailable)
        {
            foreach (var t in toQuery.Where(t => t.ValidityDays == null))
            {
                try
                {
                    var days = await GetTemplateValidityDaysAsync(configString, t.Name);
                    if (days.HasValue)
                    {
                        t.ValidityDays = days.Value;
                        _logger.LogInformation("Template '{Template}': validità di {Days} giorni letta via certutil (KeyUsagePeriod).", t.Name, days.Value);
                    }
                    else
                    {
                        _logger.LogWarning("Impossibile leggere la validità del template '{Template}' dalla CA '{Config}' (nessuna fonte disponibile).", t.Name.Replace("\r", string.Empty).Replace("\n", string.Empty), configString.Replace("\r", string.Empty).Replace("\n", string.Empty));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Errore nel fallback certutil per il template '{Template}' (Config '{Config}').", t.Name.Replace("\r", string.Empty).Replace("\n", string.Empty), configString.Replace("\r", string.Empty).Replace("\n", string.Empty));
                }
            }
        }
    }

    /// <summary>
    /// Determina il dominio AD (DNS o NetBIOS) in cui cercare la definizione
    /// dei template: prima dal ForestOrDomain della configurazione CA, poi
    /// dedotto dall'FQDN del server CA (rimuovendo il label host).
    /// </summary>
    private static string? DetermineAdDomain(string? forestOrDomain, string configString)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(forestOrDomain)) candidates.Add(forestOrDomain.Trim());

        string host = ExtractHostFromConfigString(configString);
        var hostLabels = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (hostLabels.Length >= 2)
        {
            candidates.Add(string.Join('.', hostLabels.Skip(1)));
        }

        foreach (var cand in candidates)
        {
            // Nome dominio accettabile: 1-63 caratteri alfanumerici/-. (DNS o NetBIOS)
            if (cand.Length is >= 1 and <= 63 &&
                Regex.IsMatch(cand, @"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$"))
            {
                return cand;
            }
        }
        return null;
    }

    /// <summary>
    /// Interroga AD per la definizione dei template AD CS e restituisce la mappa
    /// NomeTemplate → giorni di validità, dall'attributo pKIExpirationPeriod
    /// (intervallo FILETIME negativo in little-endian, unità da 100 ns).
    /// </summary>
    private async Task<(Dictionary<string, int> Map, bool Succeeded)> GetTemplateValidityFromAdAsync(string domain, List<string> templateNames, NetworkCredential? explicitCred)
    {
        var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (templateNames.Count == 0) return (result, false);

        // I nomi dei template sono già validati da TemplateNameRegex
        // ([A-Za-z0-9_-]{1,64}): nessun metacarattere LDAP presente.
        // Filtro LDAP: objectClass=pKICertificateTemplate, nome nel CN.
        // Se ci sono più template, li cerchiamo con un OR (|).
        string nameFilter = templateNames.Count == 1
            ? $"(cn={templateNames[0]})"
            : "(|" + string.Join(string.Empty, templateNames.Select(n => $"(cn={n})")) + ")";
        string filter = $"(&(objectClass=pKICertificateTemplate){nameFilter})";

        // Base DN: i template AD CS risiedono nel naming context Configuration:
        // CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...
        var domainLabels = domain.Split('.');
        string dcPath = domainLabels.Length >= 2
            ? string.Join(",", domainLabels.Select(l => $"DC={l}"))
            : $"DC={domain}";
        string baseDn = $"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{dcPath}";

        // SECURITY (2.1.0): la query LDAP parte da LDAPS (porta 636, cifrato) in
        // modo che le credenziali esplicite (modalità Hub/CredentialManager) non
        // transitino MAI in chiaro sulla rete. Il fallback su LDAP non cifrato
        // (389) è consentito SOLO quando non sono presenti credenziali esplicite
        // (identità del processo: nessuna password in transito). In tal caso il
        // fallback è una best-effort opzionale per le validità dei template.
        DirectoryResponse SendLdapQuery(int port, bool useSsl)
        {
            using var conn = new LdapConnection(new LdapDirectoryIdentifier(domain, port, useSsl, false));
            conn.Timeout = TimeSpan.FromSeconds(15);
            // In modalità Hub (CredentialManager) usa le credenziali della
            // foresta remota; altrimenti l'identità del processo (App Pool).
            conn.Credential = explicitCred ?? new NetworkCredential();

            var req = new SearchRequest(baseDn, filter, SearchScope.OneLevel,
                new[] { "cn", "pKIExpirationPeriod" });
            req.SizeLimit = 100;
            return conn.SendRequest(req, TimeSpan.FromSeconds(15));
        }

        try
        {
            // LdapConnection è bloccante: esegui sul thread pool.
            DirectoryResponse? rep = null;
            LdapException? sslError = null;

            try
            {
                rep = await Task.Run(() => SendLdapQuery(636, useSsl: true)).ConfigureAwait(false);
            }
            catch (LdapException ex)
            {
                sslError = ex;
            }

            if (rep == null)
            {
                if (explicitCred == null)
                {
                    // Fallback accettabile: identità del processo, nessuna
                    // password esposta anche su LDAP non cifrato.
                    _logger.LogWarning(
                        "Connessione LDAPS (636) al dominio '{Domain}' non riuscita ({Error}): fallback su LDAP (389) con identità di processo (nessuna password in transito).",
                        domain?.Replace("\r", string.Empty).Replace("\n", string.Empty), sslError?.Message?.Replace("\r", string.Empty).Replace("\n", string.Empty));
                    try
                    {
                        rep = await Task.Run(() => SendLdapQuery(389, useSsl: false)).ConfigureAwait(false);
                    }
                    catch (LdapException ex)
                    {
                        _logger.LogWarning("Query LDAP verso il dominio '{Domain}' (fallback 389) non riuscita: {Error}", domain?.Replace("\r", string.Empty).Replace("\n", string.Empty), ex.Message.Replace("\r", string.Empty).Replace("\n", string.Empty));
                        return (result, false);
                    }
                }
                else
                {
                    // CREDENZIALI ESPLICITE: nessun fallback in chiaro (la
                    // password non deve mai transitare su LDAP non cifrato).
                    _logger.LogWarning(
                        "Connessione LDAPS (636) al dominio '{Domain}' non riuscita ({Error}) e fallback LDAP non cifrato negato per la presenza di credenziali esplicite: validità template non disponibili.",
                        domain?.Replace("\r", string.Empty).Replace("\n", string.Empty), sslError?.Message?.Replace("\r", string.Empty).Replace("\n", string.Empty));
                    return (result, false);
                }
            }

            var searchResp = rep as SearchResponse;
            if (searchResp == null)
            {
                _logger.LogWarning("Risposta LDAP inattesa durante la lettura delle definizioni dei template.");
                return (result, false);
            }

            if (searchResp.ResultCode != ResultCode.Success)
            {
                _logger.LogWarning("Query LDAP non riuscita (ResultCode {ResultCode}: {Error}) durante la lettura delle definizioni dei template dal dominio '{Domain}'.",
                    searchResp.ResultCode, searchResp.ErrorMessage?.Replace("\r", string.Empty).Replace("\n", string.Empty), domain?.Replace("\r", string.Empty).Replace("\n", string.Empty));
                return (result, false);
            }

            foreach (var obj in searchResp.Entries)
            {
                try
                {
                    var entry = (SearchResultEntry)obj;

                    var nameAttr = entry.Attributes["cn"];
                    if (nameAttr == null) continue;
                    Array nameVals = nameAttr.GetValues(typeof(string));
                    if (nameVals.Length == 0) continue;
                    string name = (string)nameVals.GetValue(0)!;

                    var lifetimeAttr = entry.Attributes["pKIExpirationPeriod"];
                    if (lifetimeAttr == null) continue;
                    Array lifetimeVals = lifetimeAttr.GetValues(typeof(byte[]));
                    if (lifetimeVals.Length == 0) continue;
                    var raw = (byte[])lifetimeVals.GetValue(0)!;
                    if (raw.Length != 8) continue;

                    // pKIExpirationPeriod è un intervallo FILETIME negativo in
                    // little-endian (unità da 100 ns). Il valore negativo indica
                    // una durata relativa. Lo convertiamo in giorni positivi.
                    long intervalTicks = BitConverter.ToInt64(raw, 0);
                    long positiveTicks = Math.Abs(intervalTicks);

                    // Guardia di sanity: se il valore è troppo piccolo per essere
                    // in 100 ns (1 giorno = 8.64e11), lo si considera già in giorni.
                    int days = positiveTicks >= 8_640_000_000_000L
                        ? (int)Math.Round(positiveTicks / (double)TimeSpan.TicksPerDay)
                        : (int)positiveTicks;
                    if (days > 0 && days < 36_500)
                    {
                        result[name] = days;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Errore nel parsing dell'entry template da AD.");
                }
            }

            _logger.LogInformation("Lette {Count} definizioni template da AD ({Domain}).", result.Count, domain?.Replace("\r", string.Empty).Replace("\n", string.Empty));
            return (result, true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Query LDAP verso il dominio '{Domain}' per le definizioni dei template non riuscita.", domain?.Replace("\r", string.Empty).Replace("\n", string.Empty));
            return (result, false);
        }
    }

    /// <summary>
    /// Interroga la CA con certutil -config ... -template &lt;Nome&gt; e restituisce
    /// la validità (giorni) definita nel template (KeyUsagePeriod).
    /// </summary>
    private async Task<int?> GetTemplateValidityDaysAsync(string configString, string templateName)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "certutil.exe",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-config");
        startInfo.ArgumentList.Add(configString);
        startInfo.ArgumentList.Add("-template");
        startInfo.ArgumentList.Add(templateName);

        using var process = new Process { StartInfo = startInfo };
        var stdoutBuilder = new StringBuilder();
        var stderrBuilder = new StringBuilder();
        process.OutputDataReceived += (s, e) => { if (e.Data != null) stdoutBuilder.AppendLine(e.Data); };
        process.ErrorDataReceived += (s, e) => { if (e.Data != null) stderrBuilder.AppendLine(e.Data); };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        // Timeout di 30 secondi: se la CA non risponde si termina il processo
        // e si restituisce null (la validità resta ignota per quel template).
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            _logger.LogWarning("Timeout di 30 secondi: certutil -template {Template} non ha risposto.", templateName);
            return null;
        }

        string stdout = stdoutBuilder.ToString();
        _logger.LogDebug("Output certutil -template {Template} (exit {ExitCode}): {Output}", templateName, process.ExitCode, stdout);

        return ParseTemplateValidityDays(stdout);
    }

    /// <summary>
    /// Estrapola il periodo di validità in giorni dall'output di certutil -template.
    /// Gestisce il formato standard "KeyUsagePeriod: N days" e le varianti
    /// localizzate (es. "Periodo di validità: N giorni").
    /// </summary>
    private static int? ParseTemplateValidityDays(string output)
    {
        if (string.IsNullOrWhiteSpace(output)) return null;

        // Ordine di preferenza: etichetta canonica, poi varianti localizzate,
        // poi qualsiasi riga "Etichetta: N days/giorni".
        string[] patterns =
        {
            "KeyUsagePeriod\\s*:\\s*(\\d+)",
            "(?:Periodo\\s+di\\s+validit\\w*|ValidityPeriod|Validity\\s*Period)\\s*:\\s*(\\d+)",
            "^\\s*[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ ]{2,30}\\s*:\\s*(\\d+)\\s*(?:days?|giorni)\\s*$"
        };

        foreach (var pattern in patterns)
        {
            var match = Regex.Match(output, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            if (match.Success && int.TryParse(match.Groups[1].Value, out int days) && days > 0)
            {
                return days;
            }
        }

        return null;
    }
    #endregion

    #region Simulatore Certificati (per Demo e Ambienti Test)
    private CertificateSubmissionResponse SimulateIssuance(CertificateSubmissionRequest request, CaConfig ca)
    {
        try
        {
            var template = ca.Templates.FirstOrDefault(t => t.Name.Equals(request.TemplateName, StringComparison.OrdinalIgnoreCase))
                           ?? new TemplateConfig { Name = request.TemplateName, DisplayName = request.TemplateName, ValidityDays = 365 };

            var cleanPem = request.CsrPem.Trim();
            if (!cleanPem.Contains("-----BEGIN"))
            {
                cleanPem = $"-----BEGIN CERTIFICATE REQUEST-----\r\n{cleanPem}\r\n-----END CERTIFICATE REQUEST-----";
            }

            var certReq = CertificateRequest.LoadSigningRequestPem(
                cleanPem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

            var rootCa = MockRootCa.Value;
            byte[] serial = new byte[16];
            RandomNumberGenerator.Fill(serial);

            var issuedCert = certReq.Create(
                rootCa.SubjectName,
                X509SignatureGenerator.CreateForRSA(rootCa.GetRSAPrivateKey()!, RSASignaturePadding.Pkcs1),
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddDays(template.ValidityDays),
                serial);

            string certPem = PemEncoding.WriteString("CERTIFICATE", issuedCert.RawData);
            string rootPem = PemEncoding.WriteString("CERTIFICATE", rootCa.RawData);
            int randomReqId = Random.Shared.Next(1000, 9999);

            // P7B (PKCS#7) con certificato emesso + Root CA simulata, nella stessa
            // semantica dei percorsi reali: Base64 del contenuto standard del file
            // .p7b (testo Base64 del PKCS#7 DER, colonne da 64).
            byte[] pkcs7 = BuildPkcs7DataBag(issuedCert.RawData, rootCa.RawData);
            string? p7bFileContent = BuildP7bFileContent(pkcs7);
            string? p7bBase64 = p7bFileContent != null
                ? Convert.ToBase64String(Encoding.ASCII.GetBytes(p7bFileContent))
                : null;

            return new CertificateSubmissionResponse
            {
                Success = true,
                Disposition = "Issued",
                RequestId = randomReqId,
                StatusMessage = $"[SIMULATORE ADCS] Certificato emesso con successo per la CA '{ca.DisplayName}' con template '{template.DisplayName}'.",
                CertificatePem = certPem,
                CertificateChainPem = $"{certPem}\r\n{rootPem}",
                CaCertificatePem = rootPem,
                P7bBase64 = p7bBase64
            };
        }
        catch (Exception ex)
        {
            return new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "Failed",
                StatusMessage = $"Errore simulazione: {ex.Message}"
            };
        }
    }

    private static string? ExtractCn(string? certPem, string? csrPem)
    {
        if (!string.IsNullOrWhiteSpace(certPem))
        {
            try
            {
                var clean = certPem.Replace("-----BEGIN CERTIFICATE-----", "")
                                   .Replace("-----END CERTIFICATE-----", "")
                                   .Trim();
                using var cert = new X509Certificate2(Convert.FromBase64String(clean));
                var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                if (!string.IsNullOrWhiteSpace(cn)) return cn;
            }
            catch { }
        }

        if (!string.IsNullOrWhiteSpace(csrPem))
        {
            try
            {
                string clean = csrPem.Trim();
                if (!clean.Contains("-----BEGIN"))
                {
                    clean = $"-----BEGIN CERTIFICATE REQUEST-----\r\n{clean}\r\n-----END CERTIFICATE REQUEST-----";
                }
                var certReq = CertificateRequest.LoadSigningRequestPem(
                    clean, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
                var match = System.Text.RegularExpressions.Regex.Match(certReq.SubjectName.Name, @"CN=([^,]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (match.Success) return match.Groups[1].Value.Trim();
            }
            catch { }
        }
        return null;
    }
    #endregion

    private static string? NormalizeCertificate(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return null;
        try
        {
            string text = input.Trim();
            if (text.Contains("-----BEGIN CERTIFICATE-----"))
            {
                using var cert = X509Certificate2.CreateFromPem(text);
                return cert.ExportCertificatePem();
            }

            var pureB64 = new string(text.Where(c => !char.IsWhiteSpace(c) && c != '\r' && c != '\n').ToArray());
            byte[] rawBytes = Convert.FromBase64String(pureB64);
            using var x509 = new X509Certificate2(rawBytes);
            return x509.ExportCertificatePem();
        }
        catch
        {
            try
            {
                var pureB64 = new string(input.Where(c => !char.IsWhiteSpace(c) && c != '\r' && c != '\n' && c != '-').ToArray());
                byte[] rawBytes = Convert.FromBase64String(pureB64);
                return PemEncoding.WriteString("CERTIFICATE", rawBytes);
            }
            catch
            {
                return input;
            }
        }
    }

    /// <summary>
    /// Rimuove whitespace e armature PEM da una stringa Base64.
    /// </summary>
    private static string StripBase64(string input) =>
        new string(input.Where(c => !char.IsWhiteSpace(c) && c != '-').ToArray());

    /// <summary>
    /// Verifica se una stringa ha l'aspetto di testo Base64 "nudo" (senza armatura
    /// PEM), come i file .cer/.p7b scritti da certreq.exe.
    /// </summary>
    private static bool LooksLikeBase64Text(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Contains("-----")) return false;
        var s = new string(text.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (s.Length < 16 || s.Length % 4 is not (0 or 2 or 3)) return false;
        return s.All(c => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=');
    }

    /// <summary>
    /// Importa in <paramref name="coll"/> i certificati X.509 DER contenuti in
    /// <paramref name="der"/>. X509Certificate2Collection.Import gestisce
    /// certificati singoli/concatenati ma NON il PKCS#7: in quel caso (file
    /// .p7b) si estraggono i certificati incorporati camminando l'ASN.1.
    /// </summary>
    private static void ImportDerOrPkcs7(byte[] der, X509Certificate2Collection coll)
    {
        // 1. Testo con armatura PEM: ImportFromPem gestisce TUTTI i blocchi.
        //    (Import(byte[]) su Windows decodifica solo il PRIMO blocco: parziale!)
        try
        {
            string asText = Encoding.UTF8.GetString(der);
            if (asText.Contains("-----BEGIN CERTIFICATE"))
            {
                var c = new X509Certificate2Collection();
                c.ImportFromPem(asText);
                if (c.Count > 0)
                {
                    foreach (var cert in c) coll.Add(cert);
                    return;
                }
            }
            else if (asText.Contains("-----BEGIN PKCS7") || asText.Contains("-----BEGIN spc"))
            {
                // PKCS#7 con armatura (es. "-----BEGIN PKCS7-----"): rimuove le
                // righe di armatura, decodifica il Base64 e riparla il DER.
                string b64 = string.Join("", asText
                    .Replace("\r", "")
                    .Split('\n')
                    .Select(l => l.Trim())
                    .Where(l => l.Length > 0 && !l.StartsWith("-----")));
                byte[] pkcs7Der = Convert.FromBase64String(b64);
                if (TryExtractCertificatesFromPkcs7(pkcs7Der, coll) && coll.Count > 0) return;
            }
        }
        catch { }

        // 2. DER (certificato singolo/concatenati)
        try
        {
            var c = new X509Certificate2Collection();
            c.Import(der);
            if (c.Count > 0)
            {
                foreach (var cert in c) coll.Add(cert);
                return;
            }
        }
        catch { }

        // 3. PKCS#7 (.p7b)
        TryExtractCertificatesFromPkcs7(der, coll);
    }

    // OID PKCS#7: 1.2.840.113549.1.7.1 (data) e 1.2.840.113549.1.7.2 (signedData)
    private static readonly byte[] Pkcs7OidData = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
    private static readonly byte[] Pkcs7OidSignedData = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };

    /// <summary>
    /// Legge un TLV DER alla posizione <paramref name="off"/> (aggiornandolo a
    /// fine header) e ne restituisce tag, lunghezza header e lunghezza contenuto.
    /// </summary>
    private static (int Tag, int HeaderLen, int Len) ReadDerTlv(byte[] d, ref int off)
    {
        int tag = d[off];
        int firstLen = d[off + 1];
        int headerLen = 2;
        int len = firstLen & 0x7F;
        if ((firstLen & 0x80) != 0)
        {
            int n = firstLen & 0x7F;
            len = 0;
            for (int i = 0; i < n; i++) len = (len << 8) | d[off + 2 + i];
            headerLen += n;
        }
        off += headerLen;
        return (tag, headerLen, len);
    }

    /// <summary>
    /// Estrae i certificati X.509 incorporati in una struttura PKCS#7 (P7B)
    /// mediante parsing ASN.1 deterministico del ContentInfo:
    /// - contentType pkcs7-data: contenuto [0] EXPLICIT con SEQUENCE OF
    ///   Certificate (bag classico) oppure OCTET STRING che lo contiene;
    /// - contentType signedData: campo certificates [0] IMPLICIT del
    ///   SignedData (bambini diretti del SEQUENCE, tag 0xA0).
    /// I certificati sono i figli DIRETTI del contenitore: non si fa mai
    /// "scavalcamento" di offset, evitando falsi positivi del parser X.509.
    /// </summary>
    private static bool TryExtractCertificatesFromPkcs7(byte[] p7b, X509Certificate2Collection coll)
    {
        if (p7b == null || p7b.Length < 16 || p7b[0] != 0x30) return false;

        try
        {
            int off = 0;
            var (t0, _, l0) = ReadDerTlv(p7b, ref off);
            if (t0 != 0x30 || off + l0 != p7b.Length) return false;

            // ContentInfo ::= SEQUENCE { contentType OID, content [0] }
            var (tOid, _, lOid) = ReadDerTlv(p7b, ref off);
            if (tOid != 0x06) return false;
            bool isData = lOid == Pkcs7OidData.Length && p7b.AsSpan(off, lOid).SequenceEqual(Pkcs7OidData);
            bool isSignedData = lOid == Pkcs7OidSignedData.Length && p7b.AsSpan(off, lOid).SequenceEqual(Pkcs7OidSignedData);
            off += lOid;

            var (tContent, _, lContent) = ReadDerTlv(p7b, ref off);
            if (tContent != 0xA0) return false;
            int contentStart = off;
            off += lContent;

            (int start, int end)? container = null;

            if (isData)
            {
                int p = contentStart;
                var (t1, h1, l1) = ReadDerTlv(p7b, ref p);
                if (t1 == 0x30)
                {
                    // SEQUENCE OF Certificate (bag di certificati, formato .p7b classico)
                    container = (p, p + l1);
                }
                else if (t1 == 0x04)
                {
                    // RFC 2315: OCTET STRING che contiene la SEQUENCE
                    int q = p;
                    var (t2, h2, l2) = ReadDerTlv(p7b, ref q);
                    if (t2 == 0x30) container = (q, q + l2);
                }
            }
            else if (isSignedData)
            {
                // SignedData ::= SEQUENCE { version, digestAlgorithms,
                //   contentInfo, [0] IMPLICIT certificates?, [1] IMPLICIT cryptoSigners? }
                int p = contentStart;
                var (tSd, _, lSd) = ReadDerTlv(p7b, ref p);
                if (tSd == 0x30)
                {
                    int sdEnd = p + lSd;
                    while (p + 2 <= sdEnd)
                    {
                        var (tc, hc, lc) = ReadDerTlv(p7b, ref p);
                        int nextChild = p + lc;
                        // Solo il campo certificates usa [0] a questo livello di SignedData
                        if (tc != 0xA0) { p = nextChild; continue; }
                        // Verifica: contenuto vuoto oppure SEQUENCE di certificati
                        if (lc == 0) { p = nextChild; break; }
                        int probe = p;
                        var (tp, hp, lp) = ReadDerTlv(p7b, ref probe);
                        if (tp == 0x30)
                        {
                            container = (p, p + lc);
                            break;
                        }
                        p = nextChild;
                    }
                }
            }

            if (container == null) return false;

            // Raccolta: figli DIRETTI del contenitore, in ordine.
            // Accetta sia X509Certificate diretti (0x30) sia certificati avvolti
            // in OCTET STRING (0x04): il formato bag classico dei .p7b di AD CS.
            int c = container.Value.start;
            int cEnd = container.Value.end;
            while (c + 2 <= cEnd)
            {
                int childStart = c;
                var (tc, hc, lc) = ReadDerTlv(p7b, ref c);
                int childContentStart = c; // dopo l'header del figlio
                int childEnd = childContentStart + lc;
                if (childEnd > cEnd) break;

                bool ok = true;
                try
                {
                    if (tc == 0x30)
                    {
                        coll.Add(new X509Certificate2(p7b.AsSpan(childStart, childEnd - childStart).ToArray()));
                    }
                    else if (tc == 0x04 && lc >= 4)
                    {
                        // OCTET STRING contenente un singolo certificato
                        int innerStart = childContentStart;
                        var (t3, h3, l3) = ReadDerTlv(p7b, ref innerStart);
                        if (t3 == 0x30 && innerStart + l3 == childEnd)
                        {
                            coll.Add(new X509Certificate2(p7b.AsSpan(childContentStart, innerStart + l3 - childContentStart).ToArray()));
                        }
                        else
                        {
                            ok = false;
                        }
                    }
                    else
                    {
                        ok = false;
                    }
                }
                catch { ok = false; }

                if (!ok) break;
                c = childEnd;
            }
        }
        catch { }

        return coll.Count > 0;
    }

    /// <summary>
    /// Scarica il certificato dell'EMITTENTE di <paramref name="cert"/> dal URL
    /// caIssuers dell'estensione AIA (Authority Information Access). Gestisce
    /// risposte DER, PEM o PKCS#7. Restituisce null se l'AIA è assente, il
    /// download fallisce o il certificato non è riconoscibile.
    /// </summary>
    // OID 1.3.6.1.5.5.7.1.1 (caIssuers) in forma DER (senza tag/lunghezza)
    private static readonly byte[] AiaOidCaIssuers = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
    // OID 1.3.6.1.5.5.7.30.2 (ocspNoCheck) in forma DER: su molte CA (es. CloudLD)
    // l'URL dell'ocspNoCheck punta proprio al certificato dell'emittente, usato
    // come fallback quando l'estensione AIA non contiene caIssuers.
    private static readonly byte[] AiaOidOcspNoCheck = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02 };

    /// <summary>
    /// Estrae i URL utili a recuperare l'emittente dall'estensione AIA
    /// (1.3.6.1.5.5.7.1.1) mediante parsing ASN.1 diretto (RFC 5280):
    /// AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
    /// AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation
    ///   GeneralName [6] }. Per robustezza accetta anche una struttura con
    /// wrapper interno (SEQUENCE { SEQUENCE OF ... }) usata da alcune CA.
    /// Prima i URL caIssuers, poi gli URL ocspNoCheck (fallback CloudLD,
    /// il cui URL punta al certificato dell'emittente).
    /// </summary>
    private static List<string> ExtractAiaIssuerUrls(X509Certificate2 cert)
    {
        var result = new List<string>();
        var fallback = new List<string>();
        foreach (X509Extension ext in cert.Extensions)
        {
            if (ext.Oid?.Value != "1.3.6.1.5.5.7.1.1") continue;
            byte[] d = ext.RawData;
            if (d.Length < 10 || d[0] != 0x30) continue;
            int off = 0;
            try
            {
                var (t0, _, l0) = ReadDerTlv(d, ref off);
                if (t0 != 0x30) continue;
                int outerEnd = off + l0;
                if (off + 4 > outerEnd) continue;

                // Il primo figlio può essere direttamente un AccessDescription
                // (contenuto che inizia con OID 0x06) oppure un wrapper
                // (contenuto che inizia con SEQUENCE 0x30): si adatta.
                var (tFirst, hFirst, lFirst) = ReadDerTlv(d, ref off);
                int adSeqStart, adSeqEnd;
                if (tFirst == 0x30 && d[off] == 0x30)
                {
                    adSeqStart = off;          // scende nel wrapper
                    adSeqEnd = off + lFirst;
                }
                else
                {
                    adSeqStart = off - hFirst; // SEQUENCE OF direttamente
                    adSeqEnd = outerEnd;
                }

                int a = adSeqStart;
                while (a + 4 < adSeqEnd)
                {
                    int descStart = a;
                    var (t2, h2, l2) = ReadDerTlv(d, ref a); // AccessDescription
                    if (t2 != 0x30) { a = descStart + h2 + l2; continue; }
                    int descEnd = a + l2;
                    var (tOid, _, lo) = ReadDerTlv(d, ref a);
                    int oidContentStart = a;
                    a += lo;
                    bool isCaIssuers = tOid == 0x06 && lo == AiaOidCaIssuers.Length &&
                        d.AsSpan(oidContentStart, lo).SequenceEqual(AiaOidCaIssuers);
                    bool isOcspNoCheck = tOid == 0x06 && lo == AiaOidOcspNoCheck.Length &&
                        d.AsSpan(oidContentStart, lo).SequenceEqual(AiaOidOcspNoCheck);
                    if (!isCaIssuers && !isOcspNoCheck) { a = descEnd; continue; }
                    if (a + 2 > descEnd) { a = descEnd; continue; }
                    var (tLoc, _, lLoc) = ReadDerTlv(d, ref a);
                    if (tLoc == 0x86 && lLoc > 0 && a + lLoc <= descEnd)
                    {
                        string url = Encoding.UTF8.GetString(d, a, lLoc);
                        if (isCaIssuers) result.Add(url); else fallback.Add(url);
                    }
                    a = descEnd;
                }
            }
            catch { }
        }
        foreach (var u in fallback.Where(x => !result.Contains(x))) result.Add(u);
        return result;
    }

    /// <summary>
    /// Scarica l'emittente di <paramref name="cert"/> dai URL dell'estensione AIA
    /// (caIssuers, con fallback ocspNoCheck). Accetta SOLO un certificato il cui
    /// Subject coincide esattamente con l'Issuer atteso. Restituisce null se il
    /// download fallisce o nessun certificato corrisponde all'issuer.
    /// </summary>
    private static X509Certificate2? TryFetchIssuerViaAia(X509Certificate2 cert)
    {
        try
        {
            var urls = ExtractAiaIssuerUrls(cert);
            if (urls.Count == 0) return null;
            string expected = cert.IssuerName.Name;

            foreach (string url in urls)
            {
                try
                {
                    using var resp = AiaHttpClient.GetAsync(url).GetAwaiter().GetResult();
                    if (!resp.IsSuccessStatusCode) continue;
                    byte[] data = resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
                    if (data.Length == 0) continue;

                    var coll = new X509Certificate2Collection();
                    if (!TryImportCertificates(data, coll)) continue;

                    foreach (var c in coll)
                    {
                        if (c.SubjectName.Name.Equals(expected, StringComparison.OrdinalIgnoreCase))
                        {
                            return c;
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
        return null;
    }

    /// <summary>
    /// Converte un blocco PEM armato (CSR PKCS#10 o certificato) nella forma
    /// Base64 del contenuto DER: rimuove le righe di armatura (-----BEGIN/END
    /// ...-----) e gli whitespace. È la codifica attesa da CCertRequest::Submit
    /// quando è impostato CR_IN_BASE64.
    /// </summary>
    private static string PemToBase64Der(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem)) return string.Empty;
        string noArmor = Regex.Replace(pem, @"-{5}(?:BEGIN|END)[A-Z0-9 ]+-{5}", "");
        return new string(noArmor.Where(c => !char.IsWhiteSpace(c)).ToArray());
    }

    /// <summary>
    /// Inizio leggibile di un file binario/testo per i log diagnostici
    /// (16 byte, caratteri non stampabili sostituiti da ".").
    /// </summary>
    private static string DescribeBytesHead(byte[] b)
    {
        if (b == null || b.Length == 0) return "(vuoto)";
        int n = Math.Min(16, b.Length);
        var sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.Append(b[i] >= 32 && b[i] < 127 ? (char)b[i] : '.');
        return "\"" + sb + "\"";
    }

    /// <summary>
    /// Descrizione compatta di input/catena per i log diagnostici: formato del
    /// dato grezzo (con l'inizio, per riconoscere DER/PEM/doppio Base64) e
    /// soggetti dei certificati estratti nella catena.
    /// </summary>
    private static string DescribeChain(string? rawChain, string? chainPem)
    {
        string rawInfo;
        if (string.IsNullOrWhiteSpace(rawChain))
        {
            rawInfo = "input: ASSENTE";
        }
        else
        {
            string head = SanitizeForLog(rawChain.Trim().Substring(0, Math.Min(16, rawChain.Trim().Length)));
            rawInfo = rawChain.Contains("-----BEGIN")
                ? $"input: testo armato [{head}...] {rawChain.Length} char"
                : $"input: base64 [{head}...] {rawChain.Length} char";
        }

        string pemInfo;
        if (string.IsNullOrWhiteSpace(chainPem))
        {
            pemInfo = "catena: NESSUNA";
        }
        else
        {
            var subjects = new List<string>();
            foreach (var part in chainPem.Split("-----END CERTIFICATE-----"))
            {
                if (!part.Contains("-----BEGIN CERTIFICATE-----")) continue;
                try
                {
                    using var c = X509Certificate2.CreateFromPem(part.Trim() + "\n-----END CERTIFICATE-----");
                    subjects.Add(c.SubjectName.Name);
                }
                catch
                {
                    subjects.Add("(non leggibile)");
                }
            }
            pemInfo = subjects.Count == 0 ? "catena: NESSUNA" : "catena: " + string.Join(" | ", subjects);
        }

        return $"{rawInfo} -> {pemInfo}";
    }

    /// <summary>
    /// Importa in <paramref name="coll"/> tutti i certificati X.509 contenuti in
    /// <paramref name="bytes"/> in qualsiasi formato comune:
    /// - DER (certificato singolo o PKCS#7/P7B);
    /// - PEM (uno o più certificati con armatura);
    /// - testo Base64 "nudo" (file .cer/.p7b di certreq.exe), anche con
    ///   doppi incapsulamenti (es. Base64 di un file .p7b che è già Base64).
    /// Restituisce true se è stato importato almeno un certificato.
    /// </summary>
    private static bool TryImportCertificates(byte[] bytes, X509Certificate2Collection coll)
    {
        if (bytes == null || bytes.Length == 0) return false;

        // 1. DER diretto (certificato singolo/concatenati o PKCS#7/P7B)
        ImportDerOrPkcs7(bytes, coll);
        if (coll.Count > 0) return true;

        string text = Encoding.UTF8.GetString(bytes);
        bool armored = text.Contains("-----BEGIN");
        if (!armored && !LooksLikeBase64Text(text)) return false;

        // 2. Testo con armatura PEM (uno o più certificati)
        if (armored)
        {
            try
            {
                var c = new X509Certificate2Collection();
                c.ImportFromPem(text);
                if (c.Count > 0)
                {
                    foreach (var cert in c) coll.Add(cert);
                    return true;
                }
            }
            catch { }
        }

        // 3. Testo Base64 "nudo": prova lo scorporo fino a un livello di
        //    incapsulamento (caso file certreq già Base64-ato una seconda volta)
        for (int depth = 0; depth <= 1; depth++)
        {
            string candidate = text;
            for (int d = 0; d < depth; d++)
            {
                string pure = StripBase64(candidate);
                if (!LooksLikeBase64Text(pure)) break;
                try { candidate = Encoding.UTF8.GetString(Convert.FromBase64String(pure)); }
                catch { break; }
            }

            if (candidate.Contains("-----BEGIN"))
            {
                try
                {
                    var c = new X509Certificate2Collection();
                    c.ImportFromPem(candidate);
                    if (c.Count > 0)
                    {
                        foreach (var cert in c) coll.Add(cert);
                        return true;
                    }
                }
                catch { }
            }
            else if (LooksLikeBase64Text(candidate) && candidate.Trim().Length < 1_000_000)
            {
                try
                {
                    byte[] der = Convert.FromBase64String(StripBase64(candidate));
                    var c = new X509Certificate2Collection();
                    ImportDerOrPkcs7(der, c);
                    if (c.Count > 0)
                    {
                        foreach (var cert in c) coll.Add(cert);
                        return true;
                    }
                }
                catch { }
            }
        }

        return false;
    }

    /// <summary>
    /// Costruisce un PKCS#7 "data" (bag di certificati) in DER nel formato
    /// classico dei file .p7b di AD CS:
    /// ContentInfo ::= SEQUENCE { contentType OID pkcs7-data,
    ///   content [0] EXPLICIT { SEQUENCE { OCTET STRING, ... } } }.
    /// </summary>
    private static byte[] BuildPkcs7DataBag(params byte[][] certDer)
    {
        static byte[] DerLen(int l) => l < 128
            ? new[] { (byte)l }
            : l < 256
                ? new[] { (byte)0x81, (byte)l }
                : new[] { (byte)0x82, (byte)(l >> 8), (byte)l };

        static byte[] DerTlv(int tag, byte[] content)
        {
            byte[] len = DerLen(content.Length);
            byte[] outp = new byte[1 + len.Length + content.Length];
            outp[0] = (byte)tag;
            len.CopyTo(outp, 1);
            content.CopyTo(outp, 1 + len.Length);
            return outp;
        }

        var bag = new List<byte>(2048);
        foreach (byte[] der in certDer)
        {
            byte[] oct = DerTlv(0x04, der);
            bag.AddRange(oct);
        }
        byte[] innerSeq = DerTlv(0x30, bag.ToArray());
        byte[] explicitTag = DerTlv(0xA0, innerSeq);
        byte[] oidData = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
        return DerTlv(0x30, oidData.Concat(explicitTag).ToArray());
    }

    /// <summary>
    /// Normalizza i byte di una catena AD CS (DER PKCS#7, testo Base64 di un
    /// .p7b, o PEM) nel contenuto standard di un file .p7b: testo Base64 di un
    /// PKCS#7 DER, a colonne da 64 caratteri. Restituisce null se l'input non
    /// è interpretabile come struttura PKCS#7.
    /// </summary>
    private static string? BuildP7bFileContent(byte[]? inputBytes)
    {
        if (inputBytes == null || inputBytes.Length == 0) return null;

        byte[]? pkcs7Der = null;

        if (inputBytes[0] == 0x30 && inputBytes.Length > 8)
        {
            // Sembrerebbe già un DER PKCS#7 (o un singolo certificato): lo valida
            // importandolo (con estrazione PKCS#7 se necessario)
            try
            {
                var coll = new X509Certificate2Collection();
                ImportDerOrPkcs7(inputBytes, coll);
                if (coll.Count > 0) pkcs7Der = inputBytes;
            }
            catch { }
        }

        if (pkcs7Der == null)
        {
            // Potrebbe essere il file .p7b (testo Base64 del PKCS#7) o PEM
            string text = Encoding.UTF8.GetString(inputBytes);
            if (LooksLikeBase64Text(text))
            {
                try
                {
                    byte[] decoded = Convert.FromBase64String(StripBase64(text));
                    var coll = new X509Certificate2Collection();
                    ImportDerOrPkcs7(decoded, coll);
                    if (coll.Count > 0) pkcs7Der = decoded;
                }
                catch { }
            }
        }

        if (pkcs7Der == null) return null;

        string b64 = Convert.ToBase64String(pkcs7Der);
        var sb = new StringBuilder(b64.Length + (b64.Length / 64) * 2);
        for (int i = 0; i < b64.Length; i += 64)
        {
            if (sb.Length > 0)
            {
                sb.Append('\r');
                sb.Append('\n');
            }
            sb.Append(b64, i, Math.Min(64, b64.Length - i));
        }
        return sb.ToString();
    }

    /// <summary>
    /// Calcola il campo P7bBase64 (Base64 del contenuto standard del file .p7b)
    /// a partire da una stringa Base64 di un PKCS#7 DER (formato COM CR_OUT_BASE64).
    /// Restituisce l'input invariato se la normalizzazione non è possibile, così
    /// il client può comunque gestirlo con il fallback robusto.
    /// </summary>
    private static string? BuildP7bBase64Field(string? pkcs7Base64)
    {
        if (string.IsNullOrWhiteSpace(pkcs7Base64)) return pkcs7Base64;
        try
        {
            byte[] der = Convert.FromBase64String(StripBase64(pkcs7Base64));
            string? content = BuildP7bFileContent(der);
            return content != null ? Convert.ToBase64String(Encoding.ASCII.GetBytes(content)) : pkcs7Base64;
        }
        catch
        {
            return pkcs7Base64;
        }
    }

    private static (string? LeafPem, string? ChainPem) ParseCertreqOutputBytes(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0) return (null, null);

        var coll = new X509Certificate2Collection();
        if (TryImportCertificates(bytes, coll) && coll.Count > 0)
        {
            string leafPem = coll[0].ExportCertificatePem();
            var chainList = new List<string>();
            for (int i = 1; i < coll.Count; i++)
            {
                chainList.Add(coll[i].ExportCertificatePem());
            }

            string? chainPem = chainList.Count > 0 ? string.Join("\r\n", chainList) : null;
            return (leafPem, chainPem);
        }

        // Fallback: certificato singolo (testo PEM, Base64 nudo di DER, o doppio
        // incapsulamento Base64 — es. Base64 di testo PEM/Base64). Il risultato
        // è accettato SOLO se il certificato deriva effettivamente (probe).
        try
        {
            string text = Encoding.UTF8.GetString(bytes).Trim();
            if (text.Contains("-----BEGIN CERTIFICATE-----"))
            {
                return (text, null);
            }
            if (LooksLikeBase64Text(text))
            {
                byte[] decoded = Convert.FromBase64String(StripBase64(text));

                // Caso 1: DER di certificato
                string? probePem = ProbeCertPem(decoded);
                if (probePem != null) return (probePem, null);

                // Caso 2: doppio incapsulamento (il decodificato è ancora testo)
                string asText = Encoding.UTF8.GetString(decoded).Trim();
                if (asText.Contains("-----BEGIN CERTIFICATE-----"))
                {
                    return (asText, null);
                }
                if (LooksLikeBase64Text(asText))
                {
                    byte[] decoded2 = Convert.FromBase64String(StripBase64(asText));
                    probePem = ProbeCertPem(decoded2);
                    if (probePem != null) return (probePem, null);
                }
            }
        }
        catch { }

        return (null, null);
    }

    /// <summary>
    /// Se <paramref name="der"/> è il DER di un certificato valido (probe con
    /// subject/issuer non vuoti), ne restituisce la forma PEM; altrimenti null.
    /// Evita di produrre "certificati" fittizi da byte arbitrari inizianti con 0x30.
    /// </summary>
    private static string? ProbeCertPem(byte[] der)
    {
        if (der == null || der.Length < 64 || der[0] != 0x30) return null;
        try
        {
            using var c = new X509Certificate2(der);
            if (string.IsNullOrWhiteSpace(c.SubjectName.Name) ||
                string.IsNullOrWhiteSpace(c.IssuerName.Name) ||
                string.IsNullOrWhiteSpace(c.SerialNumber))
            {
                return null;
            }
            return c.ExportCertificatePem();
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractChainPem(string? chainBase64, string? caCertBase64, string? issuedCertPem)
    {
        var chainCerts = new List<string>();
        var seenSerials = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        X509Certificate2? issuedCert = null;
        if (!string.IsNullOrEmpty(issuedCertPem))
        {
            try
            {
                issuedCert = X509Certificate2.CreateFromPem(issuedCertPem);
                seenSerials.Add(issuedCert.SerialNumber.TrimStart('0').ToUpperInvariant());
            }
            catch { }
        }

        // 1. Estrazione dalla risposta PKCS#7 / P7B di AD CS.
        //    TryImportCertificates gestisce DER, PEM, PKCS#7 armato
        //    ("-----BEGIN PKCS7-----"), testo Base64 "nudo" (file .p7b di
        //    certreq) e doppi incapsulamenti Base64.
        if (!string.IsNullOrWhiteSpace(chainBase64))
        {
            try
            {
                string raw = chainBase64.Trim();
                byte[] p7bBytes = raw.Contains("-----BEGIN")
                    ? Encoding.UTF8.GetBytes(raw)
                    : Convert.FromBase64String(StripBase64(raw));
                var coll = new X509Certificate2Collection();
                TryImportCertificates(p7bBytes, coll);

                foreach (var cert in coll)
                {
                    var cleanSerial = cert.SerialNumber.TrimStart('0').ToUpperInvariant();
                    if (!string.IsNullOrEmpty(cleanSerial) && !seenSerials.Contains(cleanSerial))
                    {
                        seenSerials.Add(cleanSerial);
                        chainCerts.Add(cert.ExportCertificatePem());
                    }
                    cert.Dispose();
                }
            }
            catch { }
        }

        // 2. Aggiunta diretta del certificato CA se fornito separatamente
        if (!string.IsNullOrWhiteSpace(caCertBase64))
        {
            var caPem = NormalizeCertificate(caCertBase64);
            if (!string.IsNullOrEmpty(caPem))
            {
                try
                {
                    using var caCert = X509Certificate2.CreateFromPem(caPem);
                    var cleanSerial = caCert.SerialNumber.TrimStart('0').ToUpperInvariant();
                    if (!seenSerials.Contains(cleanSerial))
                    {
                        seenSerials.Add(cleanSerial);
                        chainCerts.Add(caCert.ExportCertificatePem());
                    }
                }
                catch { }
            }
        }

        // 3. Fallback di sistema: risoluzione catena tramite X509Chain locale
        //    (store di sistema / AIA gestita dal runtime). Anche se Build()
        //    "fallisce" (es. root non in trust locale), gli elementi risolti
        //    restano utili per la catena di emissione.
        if (chainCerts.Count == 0 && issuedCert != null)
        {
            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
                chain.Build(issuedCert);
                for (int i = 1; i < chain.ChainElements.Count; i++)
                {
                    var elemCert = chain.ChainElements[i].Certificate;
                    var cleanSerial = elemCert.SerialNumber.TrimStart('0').ToUpperInvariant();
                    if (!seenSerials.Contains(cleanSerial))
                    {
                        seenSerials.Add(cleanSerial);
                        chainCerts.Add(elemCert.ExportCertificatePem());
                    }
                }
            }
            catch { }
        }

        // 4. Completamento catena: finché l'ultimo certificato estratto NON è
        //    auto-firmato (es. il P7B conteneva solo foglia + Sub-CA, o solo la
        //    foglia), risolve l'emittente mancante (max 3 hop) con:
        //    a) X509Chain locale (store di sistema / AIA gestita dal runtime);
        //    b) download esplicito dal URL caIssuers dell'estensione AIA.
        if (chainCerts.Count > 0)
        {
            int hops = 0;
            while (hops < 3)
            {
                using var last = X509Certificate2.CreateFromPem(chainCerts[^1]);
                if (last.IssuerName.Name.Equals(last.SubjectName.Name, StringComparison.OrdinalIgnoreCase))
                {
                    break; // catena completa fino alla root auto-firmata
                }

                X509Certificate2? issuer = null;
                try
                {
                    using var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
                    chain.Build(last);
                    if (chain.ChainElements.Count >= 2)
                    {
                        issuer = chain.ChainElements[1].Certificate;
                    }
                }
                catch { }

                if (issuer == null)
                {
                    issuer = TryFetchIssuerViaAia(last);
                }

                if (issuer == null) break;

                string issuerSerial = issuer.SerialNumber.TrimStart('0').ToUpperInvariant();
                if (issuerSerial.Length == 0 || seenSerials.Contains(issuerSerial))
                {
                    issuer.Dispose();
                    break; // nessun progresso: si evita il loop infinito
                }

                seenSerials.Add(issuerSerial);
                chainCerts.Add(issuer.ExportCertificatePem());
                issuer.Dispose();
                hops++;
            }
        }

        // 5. Rete di sicurezza: rimuove il certificato emesso dalla catena
        //    (duplica la deduplicazione del passo 1, proteggendo i casi in cui
        //    issuedCert non era riconoscibile o il P7B conteneva la foglia in
        //    posizione diversa).
        if (issuedCert != null)
        {
            string issuedSerial = issuedCert.SerialNumber.TrimStart('0').ToUpperInvariant();
            if (issuedSerial.Length > 0)
            {
                var filtered = new List<string>();
                foreach (var pem in chainCerts)
                {
                    try
                    {
                        using var c = X509Certificate2.CreateFromPem(pem);
                        string s = c.SerialNumber.TrimStart('0').ToUpperInvariant();
                        if (s == issuedSerial) continue;
                    }
                    catch { }
                    filtered.Add(pem);
                }
                chainCerts.Clear();
                chainCerts.AddRange(filtered);
            }
        }

        issuedCert?.Dispose();
        return chainCerts.Count > 0 ? string.Join("\r\n", chainCerts) : null;
    }
}
