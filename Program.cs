using Microsoft.AspNetCore.Mvc;
using PkiPortal.Models;
using PkiPortal.Services;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Configurazione servizi
builder.Services.Configure<PortalConfig>(builder.Configuration.GetSection("PortalConfig"));
builder.Services.AddSingleton<ICsrParserService, CsrParserService>();
builder.Services.AddSingleton<IAdcsService, AdcsService>();
builder.Services.AddSingleton<IHeldRequestStore, HeldRequestStore>();

// Supporto file statici e routing
builder.Services.AddEndpointsApiExplorer();

// Configurazione autenticazione (Windows Authentication / Negotiate supportata nativamente da IIS e Kestrel)
builder.Services.AddAuthentication(Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate();
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// Endpoint API
var api = app.MapGroup("/api");

// 1. Recupero configurazione portale, CA disponibili e template
api.MapGet("/config", async (HttpContext ctx, IAdcsService adcsService, IConfiguration config) =>
{
    // SECURITY: prima era anonimo e divulgava FQDN CA, foreste e nomi template.
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
    {
        return Results.Challenge();
    }

    var portalConfig = config.GetSection("PortalConfig").Get<PortalConfig>() ?? new PortalConfig();
    var cas = await adcsService.GetAvailableCAsAsync();

    // IsAllowed: indica se l'identità corrente può emettere con quel template
    // (template senza gruppi = accessibile a tutti; admin del portale = sempre true).
    return Results.Ok(new
    {
        portalConfig.PortalTitle,
        portalConfig.PortalMode,
        portalConfig.DefaultCaId,
        cas = cas.Select(c => new
        {
            c.Id,
            c.DisplayName,
            c.ForestOrDomain,
            c.Description,
            c.IsDefault,
            Templates = c.Templates.Select(t => new
            {
                t.Name,
                t.DisplayName,
                t.Description,
                t.RequiresApproval,
                t.ValidityDays,
                t.AllowedKeyTypes,
                t.KeyUsages,
                t.ExtendedKeyUsages,
                t.AllowedGroups,
                IsAllowed = t.AllowedGroups.Count == 0 || IsServerAdmin(ctx) || IsInAnyWindowsGroup(ctx, t.AllowedGroups)
            })
        })
    });
});

// 2. Parsing e validazione CSR PKCS#10
api.MapPost("/certificates/parse-csr", ([FromBody] CsrParseRequest request, ICsrParserService parser, HttpContext ctx) =>
{
    // SECURITY: prima era anonimo (DoS unauthenticated + parsing di input di terzi).
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
    {
        return Results.Challenge();
    }

    var result = parser.ParseCsr(request.CsrPem);
    return Results.Ok(result);
});

// Info utente autenticato e ruoli
api.MapGet("/me", (HttpContext ctx) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
    {
        return Results.Challenge();
    }

    string? userName = ctx.User.Identity.Name;
    if (string.IsNullOrWhiteSpace(userName))
    {
        userName = ctx.User.FindFirst(ClaimTypes.Name)?.Value
                ?? ctx.User.FindFirst(ClaimTypes.Upn)?.Value
                ?? ctx.User.FindFirst("name")?.Value
                ?? "Utente";
    }

    bool isAdmin = IsServerAdmin(ctx);
    return Results.Ok(new { isAuthenticated = true, userName, isAdmin });
});

// 3. Sottomissione richiesta certificato alla CA ADCS
api.MapPost("/certificates/request", async ([FromBody] CertificateSubmissionRequest request, IAdcsService adcsService, HttpContext ctx) =>
{
    // Verifica autenticazione utente
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
    {
        return Results.Challenge();
    }

    if (string.IsNullOrWhiteSpace(request.TemplateName))
    {
        return Results.BadRequest(new CertificateSubmissionResponse
        {
            Success = false,
            Disposition = "Failed",
            StatusMessage = "È necessario specificare un template di certificato."
        });
    }

    if (string.IsNullOrWhiteSpace(request.CsrPem))
    {
        return Results.BadRequest(new CertificateSubmissionResponse
        {
            Success = false,
            Disposition = "Failed",
            StatusMessage = "La richiesta CSR Base64 è obbligatoria."
        });
    }

    // SECURITY (gruppi AD per template): se il template ha gruppi autorizzati,
    // solo gli utenti appartenenti ad almeno uno di essi possono emettere.
    // Gli amministratori del portale (AdminConfig) hanno accesso a tutti i template.
    var caForGroupCheck = await adcsService.GetCaConfigAsync(request.CaId);
    var tplForGroupCheck = caForGroupCheck?.Templates
        ?.FirstOrDefault(t => t.Name.Equals(request.TemplateName, StringComparison.OrdinalIgnoreCase));
    if (tplForGroupCheck != null &&
        tplForGroupCheck.AllowedGroups.Count > 0 &&
        !IsServerAdmin(ctx) &&
        !IsInAnyWindowsGroup(ctx, tplForGroupCheck.AllowedGroups))
    {
        app.Logger.LogWarning(
            "Accesso negato al template: utente '{User}' non appartiene ai gruppi autorizzati [{Groups}] per il template '{Template}'.",
            ctx.User.Identity.Name, string.Join("; ", tplForGroupCheck.AllowedGroups), request.TemplateName);
        return Results.Json(new CertificateSubmissionResponse
        {
            Success = false,
            Disposition = "Denied",
            StatusMessage = $"Non sei autorizzato a emettere certificati con il template \"{request.TemplateName}\": è richiesta l'appartenenza a uno dei gruppi AD configurati per questo template."
        }, statusCode: StatusCodes.Status403Forbidden);
    }

    // Passa il nome dell'utente autenticato richiedente per tracciamento della proprietà
    string requesterUser = ctx.User.Identity.Name ?? "Utente";
    if (adcsService is AdcsService concreteService)
    {
        var response = await concreteService.SubmitCertificateRequestInternalAsync(request, requesterUser);
        return Results.Ok(response);
    }

    var fallbackResponse = await adcsService.SubmitCertificateRequestAsync(request);
    return Results.Ok(fallbackResponse);
});

// 4. Verifica e recupero certificati in stato Pending o già emessi (con controllo di proprietà)
api.MapGet("/certificates/status/{caId}/{requestId:int}", async (string caId, int requestId, IAdcsService adcsService, IHeldRequestStore holdStore, HttpContext ctx) =>
{
    // Verifica autenticazione obbligatoria per recupero
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
    {
        return Results.Challenge();
    }

    string currentUser = ctx.User.Identity.Name ?? string.Empty;
    bool isAdmin = IsServerAdmin(ctx);

    // Controllo proprietà: il recupero è consentito esclusivamente a chi ha effettuato la richiesta o a un amministratore
    var record = await holdStore.GetByCaRequestIdAsync(caId, requestId);
    if (!isAdmin)
    {
        bool isOwner = record != null &&
                       !string.IsNullOrEmpty(record.RequesterUser) &&
                       record.RequesterUser.Equals(currentUser, StringComparison.OrdinalIgnoreCase);

        if (!isOwner)
        {
            return Results.Json(new CertificateSubmissionResponse
            {
                Success = false,
                Disposition = "Forbidden",
                RequestId = requestId,
                ErrorCode = "NotOwner",
                RequesterUser = currentUser,
                StatusMessage = $"Accesso negato: La richiesta #{requestId} non risulta associata al tuo account ({currentUser}). Solo il richiedente originale o un amministratore possono recuperare il certificato."
            }, statusCode: StatusCodes.Status403Forbidden);
        }
    }

    var response = await adcsService.RetrievePendingCertificateAsync(caId, requestId);
    if (record != null)
    {
        response.RequesterUser ??= record.RequesterUser;
        response.SubjectCommonName ??= record.SubjectCommonName;
        response.TemplateDisplayName ??= record.TemplateDisplayName;
        response.PrivateKeyPem ??= record.PrivateKeyPem;
    }
    return Results.Ok(response);
});

// 5. Lista delle proprie richieste certificato per l'utente collegato
api.MapGet("/certificates/my-requests", async (HttpContext ctx, IHeldRequestStore holdStore) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
    {
        return Results.Challenge();
    }

    string currentUser = ctx.User.Identity.Name ?? string.Empty;
    bool isAdmin = IsServerAdmin(ctx);

    List<HeldCertificateRequest> requests;
    if (isAdmin)
    {
        requests = await holdStore.GetAllRequestsAsync();
    }
    else
    {
        requests = await holdStore.GetRequestsByUserAsync(currentUser);
    }

    return Results.Ok(requests.Select(r => new
    {
        r.HoldId,
        r.CaId,
        r.CaRequestId,
        r.TemplateName,
        r.TemplateDisplayName,
        r.SubjectCommonName,
        r.RequesterUser,
        r.SubmittedAt,
        Status = r.Status.ToString(),
        HasCertificate = !string.IsNullOrEmpty(r.CertificatePem),
        HasPrivateKey = !string.IsNullOrEmpty(r.PrivateKeyPem)
    }));
});

// ===== Protezione anti-CSRF per gli endpoint mutanti admin =====
// Un form HTML cross-site non può impostare header custom: gli endpoint che
// modificano lo stato richiedono un header noto e, quando presente, l'Origin
// deve corrispondere al portale. Questo neutralizza il CSRF anche con
// autenticazione Windows integrata (Kerberos/NTLM), dove le credenziali
// vengono completate automaticamente dal browser della vittima.
const string CsrfHeaderName = "X-Pki-Portal-Admin";
const string CsrfHeaderValue = "pki-admin";

bool HasValidCsrf(HttpContext ctx)
{
    if (!ctx.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase) &&
        !ctx.Request.Method.Equals("PUT", StringComparison.OrdinalIgnoreCase) &&
        !ctx.Request.Method.Equals("DELETE", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    if (!ctx.Request.Headers.TryGetValue(CsrfHeaderName, out var token) ||
        !string.Equals(token.ToString(), CsrfHeaderValue, StringComparison.Ordinal))
    {
        return false;
    }

    if (ctx.Request.Headers.TryGetValue("Origin", out var origin))
    {
        try
        {
            var o = new Uri(origin.ToString());
            bool hostOk = string.Equals(o.Host, ctx.Request.Host.Host, StringComparison.OrdinalIgnoreCase);
            bool portOk = o.IsDefaultPort || string.Equals(o.Port.ToString(), ctx.Request.Host.Port?.ToString(), StringComparison.Ordinal);
            if (!hostOk || !portOk)
            {
                return false;
            }
        }
        catch
        {
            return false; // Origin presente ma non interpretabile: rifiuta
        }
    }

    return true;
}

IResult CsrfDenied() => Results.Json(
    new { message = "Richiesta rifiutata: header anti-CSRF mancante o Origin non valida." },
    statusCode: StatusCodes.Status403Forbidden);

// ===== Area Admin - Solo amministratori del server =====
var admin = app.MapGroup("/api/admin");

// Verifica se l'utente del contesto appartiene ad almeno uno dei gruppi indicati.
// "BUILTIN\Administrators"/"Administrators" vengono risolti come ruolo locale.
// I gruppi non risolvibili (SID assente, trust non raggiungibile) sono ignorati (fail-closed).
bool IsInAnyWindowsGroup(HttpContext ctx, IEnumerable<string> groups)
{
    if (!OperatingSystem.IsWindows())
        return false;

    WindowsPrincipal? principal = ctx.User.Identity is WindowsIdentity winIdentity
        ? new WindowsPrincipal(winIdentity)
        : ctx.User as WindowsPrincipal;

    if (principal == null)
        return false;

    foreach (var group in groups)
    {
        try
        {
            if (group.Equals("BUILTIN\\Administrators", StringComparison.OrdinalIgnoreCase) ||
                group.Equals("Administrators", StringComparison.OrdinalIgnoreCase))
            {
                if (principal.IsInRole(WindowsBuiltInRole.Administrator)) return true;
            }
            else if (principal.IsInRole(group))
            {
                return true;
            }
        }
        catch { /* Ignora errori di risoluzione SID o trust di dominio per gruppi non raggiungibili */ }
    }

    return false;
}

// Funzione di verifica autorizzazione admin
bool IsServerAdmin(HttpContext ctx)
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return false;

    var adminCfg = ctx.RequestServices.GetRequiredService<IConfiguration>()
        .GetSection("AdminConfig").Get<AdminConfig>() ?? new AdminConfig();

    var userName = ctx.User.Identity.Name ?? string.Empty;
    if (!string.IsNullOrEmpty(userName) && adminCfg.AllowedUsers.Any(u => u.Equals(userName, StringComparison.OrdinalIgnoreCase)))
        return true;

    return IsInAnyWindowsGroup(ctx, adminCfg.AllowedGroups);
}

// GET /api/admin/check - Verifica se l'utente è admin
admin.MapGet("/check", (HttpContext ctx) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
    {
        return Results.Challenge();
    }

    bool isAdmin = IsServerAdmin(ctx);
    string userName = ctx.User.Identity.Name ?? "Anonimo";
    return Results.Ok(new { isAdmin, userName });
});

// GET /api/admin/config - Legge l'intera configurazione del portale
admin.MapGet("/config", (HttpContext ctx, IConfiguration config) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    var portalConfig = config.GetSection("PortalConfig").Get<PortalConfig>() ?? new PortalConfig();
    return Results.Ok(portalConfig);
});

// GET /api/admin/templates/{caId} - Scopri template pubblicati dalla CA tramite ID
admin.MapGet("/templates/{caId}", async (string caId, HttpContext ctx, IAdcsService adcsService) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    var templates = await adcsService.GetPublishedTemplatesAsync(caId);
    return Results.Ok(templates);
});

// POST /api/admin/templates/discover - Scopri template con parametri diretti dal form (anche prima del salvataggio)
admin.MapPost("/templates/discover", async ([FromBody] TemplateDiscoveryRequest request, HttpContext ctx, IAdcsService adcsService) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    if (!HasValidCsrf(ctx))
        return CsrfDenied();

    var templates = await adcsService.DiscoverTemplatesAsync(request);
    return Results.Ok(templates);
});

// Lock di sincronizzazione per evitare corruzioni da scritture concorrenti su appsettings.json
var configSaveLock = new SemaphoreSlim(1, 1);

// PUT /api/admin/config - Salva l'intera configurazione del portale
admin.MapPut("/config", async (HttpContext ctx, PortalConfig newConfig) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    if (!HasValidCsrf(ctx))
        return CsrfDenied();

    await configSaveLock.WaitAsync();
    try
    {
        var targetPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.Combine(app.Environment.ContentRootPath, "appsettings.json"),
            Path.Combine(AppContext.BaseDirectory, "appsettings.json")
        };

        var options = new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = null };

        foreach (var filePath in targetPaths)
        {
            if (!File.Exists(filePath)) continue;

            string json = await File.ReadAllTextAsync(filePath);
            using var doc = JsonDocument.Parse(json);

            var root = new Dictionary<string, object>();
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Name == "PortalConfig")
                    continue;
                root[prop.Name] = JsonSerializer.Deserialize<object>(prop.Value.GetRawText())!;
            }
            root["PortalConfig"] = newConfig;

            string updatedJson = JsonSerializer.Serialize(root, options);
            await File.WriteAllTextAsync(filePath, updatedJson);
        }

        // Forza il reload immediato della configurazione in memoria
        (app.Configuration as IConfigurationRoot)?.Reload();

        return Results.Ok(new { success = true, message = "Configurazione salvata con successo. Le modifiche sono attive immediatamente." });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Errore durante il salvataggio: {ex.Message}");
    }
    finally
    {
        configSaveLock.Release();
    }
});

// ===== Gestione Richieste Trattenute (Hold) =====

// GET /api/admin/held-requests - Lista richieste trattenute (default: solo PendingApproval)
admin.MapGet("/held-requests", async (HttpContext ctx, IHeldRequestStore holdStore, string? status) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    HoldStatus? statusFilter = status?.ToLowerInvariant() switch
    {
        "pending" => HoldStatus.PendingApproval,
        "approved" => HoldStatus.Approved,
        "rejected" => HoldStatus.Rejected,
        "all" => null,
        _ => HoldStatus.PendingApproval // default: solo pending
    };

    var requests = await holdStore.GetAllRequestsAsync(statusFilter);
    return Results.Ok(new
    {
        count = requests.Count,
        statusFilter = statusFilter?.ToString() ?? "All",
        requests = requests.Select(r => new
        {
            r.HoldId,
            r.SubmittedAt,
            r.CaId,
            r.TemplateName,
            r.TemplateDisplayName,
            r.RequesterUser,
            r.SubjectCommonName,
            r.SanAttribute,
            r.CaRequestId,
            Status = r.Status.ToString(),
            r.ReviewedAt,
            r.ReviewedBy,
            r.RejectionReason,
            r.RequesterComments
        })
    });
});

// GET /api/admin/held-requests/{holdId} - Dettaglio richiesta trattenuta (con certificato se approvata)
admin.MapGet("/held-requests/{holdId}", async (string holdId, HttpContext ctx, IHeldRequestStore holdStore) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    var request = await holdStore.GetByHoldIdAsync(holdId);
    if (request == null)
        return Results.NotFound(new { message = $"Richiesta con Hold ID '{holdId}' non trovata." });

    return Results.Ok(request);
});

// POST /api/admin/held-requests/{holdId}/approve - Approva una richiesta trattenuta
admin.MapPost("/held-requests/{holdId}/approve", async (string holdId, HttpContext ctx, IHeldRequestStore holdStore) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    if (!HasValidCsrf(ctx))
        return CsrfDenied();

    string approvedBy = ctx.User.Identity.Name ?? "Admin";
    var approved = await holdStore.ApproveRequestAsync(holdId, approvedBy);

    if (approved == null)
        return Results.NotFound(new { message = $"Richiesta con Hold ID '{holdId}' non trovata o non in stato PendingApproval." });

    return Results.Ok(new
    {
        success = true,
        message = $"Richiesta '{holdId}' approvata da {approvedBy}. Il certificato è ora disponibile per il download.",
        holdId = approved.HoldId,
        caRequestId = approved.CaRequestId,
        templateName = approved.TemplateDisplayName,
        subject = approved.SubjectCommonName,
        approvedBy = approved.ReviewedBy,
        approvedAt = approved.ReviewedAt
    });
});

// POST /api/admin/held-requests/{holdId}/reject - Rifiuta una richiesta trattenuta
admin.MapPost("/held-requests/{holdId}/reject", async (string holdId, HttpContext ctx, IHeldRequestStore holdStore, [FromBody] RejectHeldRequestBody? body) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    if (!HasValidCsrf(ctx))
        return CsrfDenied();

    string rejectedBy = ctx.User.Identity.Name ?? "Admin";
    string? reason = body?.Reason;

    var rejected = await holdStore.RejectRequestAsync(holdId, rejectedBy, reason);

    if (rejected == null)
        return Results.NotFound(new { message = $"Richiesta con Hold ID '{holdId}' non trovata o non in stato PendingApproval." });

    return Results.Ok(new
    {
        success = true,
        message = $"Richiesta '{holdId}' rifiutata da {rejectedBy}.",
        holdId = rejected.HoldId,
        reason = rejected.RejectionReason,
        rejectedBy = rejected.ReviewedBy,
        rejectedAt = rejected.ReviewedAt
    });
});

// GET /api/certificates/held/{holdId} - Endpoint utente per recuperare un certificato approvato (con controllo di proprietà)
api.MapGet("/certificates/held/{holdId}", async (string holdId, IHeldRequestStore holdStore, HttpContext ctx) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
    {
        return Results.Challenge();
    }

    string currentUser = ctx.User.Identity.Name ?? string.Empty;
    bool isAdmin = IsServerAdmin(ctx);

    var request = await holdStore.GetByHoldIdAsync(holdId);
    if (request == null)
    {
        return Results.NotFound(new CertificateSubmissionResponse
        {
            Success = false,
            Disposition = "Failed",
            StatusMessage = $"Richiesta con Hold ID '{holdId}' non trovata."
        });
    }

    // Controllo di proprietà
    if (!isAdmin && (string.IsNullOrEmpty(request.RequesterUser) ||
        !request.RequesterUser.Equals(currentUser, StringComparison.OrdinalIgnoreCase)))
    {
        return Results.Json(new CertificateSubmissionResponse
        {
            Success = false,
            Disposition = "Forbidden",
            RequestId = request.CaRequestId,
            ErrorCode = "NotOwner",
            RequesterUser = currentUser,
            StatusMessage = request.CaRequestId > 0
                ? $"Accesso negato: La richiesta #{request.CaRequestId} non risulta associata al tuo account ({currentUser}). Solo il richiedente originale o un amministratore possono recuperare il certificato."
                : $"Accesso negato: La richiesta non risulta associata al tuo account ({currentUser}). Solo il richiedente originale o un amministratore possono recuperare il certificato."
        }, statusCode: StatusCodes.Status403Forbidden);
    }

    return request.Status switch
    {
        HoldStatus.PendingApproval => Results.Ok(new CertificateSubmissionResponse
        {
            Success = true,
            Disposition = "UnderSubmission",
            RequestId = request.CaRequestId,
            StatusMessage = $"La richiesta è ancora in attesa di approvazione da parte di un amministratore (Hold ID: {holdId})."
        }),
        HoldStatus.Approved => Results.Ok(new CertificateSubmissionResponse
        {
            Success = true,
            Disposition = "Issued",
            RequestId = request.CaRequestId,
            StatusMessage = $"Certificato approvato da {request.ReviewedBy} il {request.ReviewedAt:dd/MM/yyyy HH:mm}. Pronto per il download.",
            CertificatePem = request.CertificatePem,
            CertificateChainPem = request.CertificateChainPem,
            CaCertificatePem = request.CaCertificatePem,
            P7bBase64 = request.P7bBase64,
            PrivateKeyPem = request.PrivateKeyPem,
            RequesterUser = request.RequesterUser,
            SubjectCommonName = request.SubjectCommonName,
            TemplateDisplayName = request.TemplateDisplayName
        }),
        HoldStatus.Rejected => Results.Ok(new CertificateSubmissionResponse
        {
            Success = false,
            Disposition = "Denied",
            RequestId = request.CaRequestId,
            StatusMessage = $"La richiesta è stata rifiutata da {request.ReviewedBy} il {request.ReviewedAt:dd/MM/yyyy HH:mm}." +
                           (string.IsNullOrWhiteSpace(request.RejectionReason) ? "" : $" Motivo: {request.RejectionReason}")
        }),
        _ => Results.Problem("Stato richiesta non riconosciuto.")
    };
});

app.Run();

// DTO per il body della reject
public record RejectHeldRequestBody(string? Reason);
