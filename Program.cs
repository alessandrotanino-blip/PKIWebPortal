using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using PkiPortal.Models;
using PkiPortal.Services;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// ROBUSTNESS (2.3.1): la pipeline di logging di default su Windows include il
// provider EventLog (source ".NET Runtime"). Se l'account che esegue l'app
// (app pool limitato, sandbox, container) non ha accesso in scrittura alla
// source, OGNI log Warning/Error lancia AggregateException e fa crollare la
// richiesta in corso — incluse le risposte di rifiuto di sicurezza
// (400/401/403). Provider reso deterministico: solo console, sempre
// disponibile (catturabile via stdoutout.log in IIS out-of-process).
// Se si desidera il logging nell'Event Log, aggiungere esplicitamente
// builder.Logging.AddEventLog(source, logName) con un account abilitato.
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Configurazione servizi
builder.Services.Configure<PortalConfig>(builder.Configuration.GetSection("PortalConfig"));
builder.Services.Configure<AcmeConfig>(builder.Configuration.GetSection("AcmeConfig"));
builder.Services.AddHttpClient();
builder.Services.AddSingleton<ICsrParserService, CsrParserService>();
builder.Services.AddSingleton<IAdcsService, AdcsService>();
builder.Services.AddSingleton<IHeldRequestStore, HeldRequestStore>();
builder.Services.AddSingleton<IAcmeCryptoService, AcmeCryptoService>();
builder.Services.AddSingleton<IAcmeStore, AcmeStore>();
builder.Services.AddSingleton<IAcmeValidationService, AcmeValidationService>();
builder.Services.AddSingleton<IAcmeService, AcmeService>();
builder.Services.AddSingleton<CsrfTokenService>();

// Supporto file statici e routing
builder.Services.AddEndpointsApiExplorer();

// SECURITY (2.1.0): rate limiting per identità per mitigare abuso/DoS sugli
// endpoint che avviano processi esterni (certreq/certutil) o parsing CPU-bound.
// Partizione per utente autenticato, fallback sull'indirizzo IP remoto.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, _) =>
    {
        var response = context.HttpContext.Response;
        response.StatusCode = StatusCodes.Status429TooManyRequests;
        await response.WriteAsJsonAsync(new { message = "Troppe richieste: attendi un minuto e riprova." });
    };

    // Partizione per utente autenticato, fallback sull'indirizzo IP remoto.
    string GetUserKey(HttpContext ctx)
    {
        if (ctx.User?.Identity is { IsAuthenticated: true } identity && !string.IsNullOrWhiteSpace(identity.Name))
        {
            return identity.Name;
        }
        return ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    // Sottomissioni certificati: avviano processi esterni (30-60s) verso la CA.
    options.AddPolicy("portal-submit", ctx =>
        System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(GetUserKey(ctx), _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
        {
            PermitLimit = 5,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));

    // Parsing CSR: CPU-bound.
    options.AddPolicy("portal-parse", ctx =>
        System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(GetUserKey(ctx), _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
        {
            PermitLimit = 20,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));

    // Default portale (tutti gli altri endpoint API).
    // Default portale (tutti gli altri endpoint API).
    options.AddPolicy("acme-policy", ctx =>
        System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(GetUserKey(ctx), _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
        {
            PermitLimit = 300,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.AddPolicy("portal-default", ctx =>
        System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(GetUserKey(ctx), _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
        {
            PermitLimit = 120,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
});

// Configurazione autenticazione (Windows Authentication / Negotiate supportata nativamente da IIS e Kestrel)
builder.Services.AddAuthentication(Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate();
builder.Services.AddAuthorization();

var app = builder.Build();

// Inizializzazione immediata dello store richieste trattenute e verifica crittografica all'avvio
_ = app.Services.GetRequiredService<IHeldRequestStore>();
_ = app.Services.GetRequiredService<IAcmeStore>();

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// SECURITY (2.3.1): guardia ACME — applica la flag "Enabled" (ignorata
// finora: disattivare ACME dal GUI non aveva effetto) e impone TLS sul
// percorso /acme (RFC 8555 Sez. 15.1.1: l'ACME MUST transitare su HTTPS;
// i JWS contengono nonces e le chiavi pubbliche degli account).
// L'HTTP in chiaro resta consentito solo verso localhost (sviluppo/test).
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/acme"))
    {
        var acmeCfg = ctx.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig>>().CurrentValue;
        if (acmeCfg is { Enabled: false })
        {
            ctx.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            ctx.Response.ContentType = "application/problem+json";
            await ctx.Response.WriteAsync(
                "{\"type\":\"urn:ietf:params:acme:error:serverInternal\",\"detail\":\"Il server ACME è disabilitato.\",\"status\":503}");
            return;
        }

        if (ctx.Request.Scheme == "http")
        {
            bool isLocalhost = ctx.Request.Host.Host is "localhost" or "127.0.0.1" or "[::1]";
            if (!isLocalhost)
            {
                ctx.Response.StatusCode = StatusCodes.Status301MovedPermanently;
                ctx.Response.Headers.Location = $"https://{ctx.Request.Host}{ctx.Request.Path}{ctx.Request.QueryString}";
                return;
            }
        }
    }
    await next();
});

// SECURITY (2.1.0): rate limiter DOPO l'autenticazione, così la partizione
// può usare l'identità dell'utente.
app.UseRateLimiter();

// Endpoint API (limite default: 120 req/min per utente; i singoli endpoint
// mutanti/CPU-bound hanno politiche più strette)
var api = app.MapGroup("/api").RequireRateLimiting("portal-default");

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
                t.StorePrivateKeyForRetrieval,
                t.ValidityDays,
                // SECURITY (2.1.0): i nomi dei gruppi AD (AllowedGroups) NON
                // vengono più esposti a ogni utente autenticato: l'API restituisce
                // solo IsAllowed (se l'identità corrente può emettere con il
                // template), evitando di consegnare la mappa dei gruppi di
                // emissione a chiunque abbia un account di dominio.
                t.AllowedKeyTypes,
                t.KeyUsages,
                t.ExtendedKeyUsages,
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
})
.RequireRateLimiting("portal-parse");

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
    var response = await adcsService.SubmitCertificateRequestAsync(request, requesterUser);
    return Results.Ok(response);
})
.RequireRateLimiting("portal-submit");

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

// 5. Lista delle proprie richieste certificato per l'utente collegato (con filtri opzionali)
api.MapGet("/certificates/my-requests", async (
    HttpContext ctx,
    IHeldRequestStore holdStore,
    string? requester,
    string? template,
    string? status,
    string? search) =>
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

    static string ResolveRequester(HeldCertificateRequest r)
    {
        if (!string.IsNullOrWhiteSpace(r.RequesterUser))
            return r.RequesterUser;
        if (r.RequesterComments?.StartsWith("ACME order", StringComparison.OrdinalIgnoreCase) == true)
            return "ACME";
        return string.Empty;
    }

    var query = requests.AsEnumerable();

    if (!string.IsNullOrWhiteSpace(status) && !status.Equals("all", StringComparison.OrdinalIgnoreCase))
    {
        query = query.Where(r => r.Status.ToString().Equals(status, StringComparison.OrdinalIgnoreCase));
    }

    if (!string.IsNullOrWhiteSpace(requester))
    {
        if (requester.Equals("__acme__", StringComparison.OrdinalIgnoreCase) || requester.Equals("acme", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(r => ResolveRequester(r).StartsWith("ACME", StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            query = query.Where(r => ResolveRequester(r).Contains(requester, StringComparison.OrdinalIgnoreCase));
        }
    }

    if (!string.IsNullOrWhiteSpace(template))
    {
        query = query.Where(r =>
            (!string.IsNullOrEmpty(r.TemplateName) && r.TemplateName.Contains(template, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrEmpty(r.TemplateDisplayName) && r.TemplateDisplayName.Contains(template, StringComparison.OrdinalIgnoreCase)));
    }

    if (!string.IsNullOrWhiteSpace(search))
    {
        query = query.Where(r =>
            (!string.IsNullOrEmpty(r.SubjectCommonName) && r.SubjectCommonName.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
            ResolveRequester(r).Contains(search, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrEmpty(r.TemplateName) && r.TemplateName.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrEmpty(r.TemplateDisplayName) && r.TemplateDisplayName.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrEmpty(r.CaId) && r.CaId.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
            r.CaRequestId.ToString().Contains(search) ||
            (!string.IsNullOrEmpty(r.HoldId) && r.HoldId.Contains(search, StringComparison.OrdinalIgnoreCase)));
    }

    return Results.Ok(query.Select(r => new
    {
        r.HoldId,
        r.CaId,
        r.CaRequestId,
        r.TemplateName,
        r.TemplateDisplayName,
        r.SubjectCommonName,
        RequesterUser = ResolveRequester(r),
        r.RequesterComments,
        r.SubmittedAt,
        Status = r.Status.ToString(),
        HasCertificate = !string.IsNullOrEmpty(r.CertificatePem),
        HasPrivateKey = !string.IsNullOrEmpty(r.PrivateKeyPem)
    }));
});

// ===== Protezione anti-CSRF per gli endpoint mutanti admin =====
// Un form HTML cross-site non può impostare header custom né leggere il token
// di origine diversa: gli endpoint che modificano lo stato richiedono
// (1) l'header X-Pki-Portal-Admin con un token ANTI-CSRF emesso da
// GET /api/admin/csrf, legato all'identità autenticata (HMAC + scadenza), e
// (2) quando presente, un Origin coerente con il portale. Questo neutralizza
// il CSRF anche con autenticazione Windows integrata (Kerberos/NTLM), dove le
// credenziali vengono completate automaticamente dal browser della vittima.
// SECURITY (2.1.0): il precedente valore statico pubblico "pki-admin" è stato
// sostituito da token per sessione (CsrfTokenService).
const string CsrfHeaderName = "X-Pki-Portal-Admin";

var csrfTokenService = app.Services.GetRequiredService<CsrfTokenService>();

bool HasValidCsrf(HttpContext ctx)
{
    if (!ctx.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase) &&
        !ctx.Request.Method.Equals("PUT", StringComparison.OrdinalIgnoreCase) &&
        !ctx.Request.Method.Equals("DELETE", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    if (!ctx.Request.Headers.TryGetValue(CsrfHeaderName, out var token))
    {
        return false;
    }

    string? csrfUser = ctx.User.Identity?.Name;
    if (string.IsNullOrEmpty(csrfUser) ||
        !csrfTokenService.ValidateToken(token.ToString(), csrfUser))
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
var admin = app.MapGroup("/api/admin").RequireRateLimiting("portal-default");

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

// GET /api/admin/csrf - Emette il token anti-CSRF legato all'identità corrente.
// Il client (admin.html) lo invia nell'header X-Pki-Portal-Admin su ogni
// richiesta mutante. SECURITY (2.1.0): sostituisce il token statico pubblico.
admin.MapGet("/csrf", (HttpContext ctx, CsrfTokenService csrf) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    string csrfUser = ctx.User.Identity.Name ?? "Anonimo";
    return Results.Ok(new
    {
        token = csrf.IssueTokenForUser(csrfUser),
        expiresInSeconds = CsrfTokenService.TokenLifetimeMinutes * 60
    });
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
        // SECURITY (2.1.0): i dettagli dell'eccezione restano solo nel log del
        // server: la risposta non espone più ex.Message (informazioni interne,
        // percorsi, dettagli di sistema).
        app.Logger.LogError(ex, "Errore durante il salvataggio della configurazione del portale.");
        return Results.Problem("Errore durante il salvataggio della configurazione. I dettagli sono nel log del server.");
    }
    finally
    {
        configSaveLock.Release();
    }
});

// ===== Configurazione ACME =====

// GET /api/admin/acme-config - Legge la configurazione ACME corrente
admin.MapGet("/acme-config", (HttpContext ctx, IConfiguration config) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    var acmeCfg = config.GetSection("AcmeConfig").Get<AcmeConfig>() ?? new AcmeConfig();
    return Results.Ok(acmeCfg);
});

// PUT /api/admin/acme-config - Salva la configurazione ACME in appsettings.json
admin.MapPut("/acme-config", async (HttpContext ctx, AcmeConfig newAcmeCfg) =>
{
    if (ctx.User.Identity == null || !ctx.User.Identity.IsAuthenticated)
        return Results.Challenge();

    if (!IsServerAdmin(ctx))
        return Results.Forbid();

    if (!HasValidCsrf(ctx))
        return CsrfDenied();

    // Validazione input
    // SECURITY (2.3.1): BaseUrl deve essere un URL http/https (esclude
    // javascript:, file:, ftp:, …).
    if (!string.IsNullOrEmpty(newAcmeCfg.BaseUrl))
    {
        if (!Uri.TryCreate(newAcmeCfg.BaseUrl, UriKind.Absolute, out var baseUrlUri) ||
            (!baseUrlUri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
             !baseUrlUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            return Results.BadRequest(new { message = "BaseUrl deve essere un URL assoluto con schema http o https." });
        }
    }

    var validModes = new[] { "Http01", "AutoApprove", "Http01WithAutoFallback" };
    if (!validModes.Contains(newAcmeCfg.ValidationMode, StringComparer.OrdinalIgnoreCase))
        return Results.BadRequest(new { message = $"ValidationMode non valido. Valori accettati: {string.Join(", ", validModes)}." });

    // SECURITY (2.3.1, C3): in modalità AutoApprove la validazione del dominio
    // è assente per definizione: l'allowlist AllowedDomains diventa
    // obbligatoria, altrimenti il server diventerebbe un "oracle" di
    // certificati per qualsiasi nome (anche interno).
    if (string.Equals(newAcmeCfg.ValidationMode, "AutoApprove", StringComparison.OrdinalIgnoreCase) &&
        (newAcmeCfg.AllowedDomains == null || !newAcmeCfg.AllowedDomains.Any(d => !string.IsNullOrWhiteSpace(d))))
    {
        return Results.BadRequest(new { message = "Con ValidationMode 'AutoApprove' è obbligatorio impostare almeno un dominio in AllowedDomains." });
    }

    // SECURITY (2.3.2): con AllowPrivateIpValidation abilitato l'allowlist è
    // obbligatoria per impedire che client ACME usino la validazione su IP privati per SSRF.
    if (newAcmeCfg.AllowPrivateIpValidation &&
        (newAcmeCfg.AllowedDomains == null || !newAcmeCfg.AllowedDomains.Any(d => !string.IsNullOrWhiteSpace(d))))
    {
        return Results.BadRequest(new { message = "Con 'AllowPrivateIpValidation' abilitato è obbligatorio impostare almeno un dominio in AllowedDomains." });
    }

    if (newAcmeCfg.HttpPort is < 1 or > 65535)
        return Results.BadRequest(new { message = "HttpPort deve essere compreso tra 1 e 65535." });

    if (newAcmeCfg.ChallengeTimeoutSeconds is < 5 or > 120)
        return Results.BadRequest(new { message = "ChallengeTimeoutSeconds deve essere compreso tra 5 e 120." });

    // SECURITY (2.3.1): template e domini — forme strette anti-iniezione
    // (i template finiscono in parametri di certreq/certutil).
    var templateShape = new System.Text.RegularExpressions.Regex(@"^[A-Za-z0-9_-]{1,64}$");
    foreach (var t in (newAcmeCfg.AllowedTemplates ?? new List<string>()))
    {
        if (!templateShape.IsMatch(t ?? string.Empty))
            return Results.BadRequest(new { message = $"Nome template non valido: '{t}'." });
    }
    if (!string.IsNullOrWhiteSpace(newAcmeCfg.DefaultTemplateName) &&
        !templateShape.IsMatch(newAcmeCfg.DefaultTemplateName))
        return Results.BadRequest(new { message = $"DefaultTemplateName non valido: '{newAcmeCfg.DefaultTemplateName}'." });

    var domainShape = new System.Text.RegularExpressions.Regex(@"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$");
    foreach (var d in (newAcmeCfg.AllowedDomains ?? new List<string>()))
    {
        if (!domainShape.IsMatch((d ?? string.Empty).Trim()))
            return Results.BadRequest(new { message = $"Dominio non valido in AllowedDomains: '{d}'." });
    }

    // SECURITY (2.3.1): ToS URL — relativo (deve iniziare con '/') o
    // assoluto http/https: viene concatenato/inserito nella directory ACME.
    if (!string.IsNullOrWhiteSpace(newAcmeCfg.TermsOfServiceUrl))
    {
        var tos = newAcmeCfg.TermsOfServiceUrl.Trim();
        bool tosOk = tos.StartsWith('/') ||
            (tos.StartsWith("http", StringComparison.OrdinalIgnoreCase) &&
             Uri.TryCreate(tos, UriKind.Absolute, out var tosUri) &&
             (tosUri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
              tosUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)));
        if (!tosOk)
            return Results.BadRequest(new { message = "TermsOfServiceUrl deve essere un percorso relativo (inizia con '/') o un URL http/https." });
    }

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
                if (prop.Name == "AcmeConfig")
                    continue;
                root[prop.Name] = JsonSerializer.Deserialize<object>(prop.Value.GetRawText())!;
            }
            root["AcmeConfig"] = newAcmeCfg;

            // Scrittura diretta su appsettings.json (su cui l'AppPool ha Modify).
            string updatedJson = JsonSerializer.Serialize(root, options);
            await File.WriteAllTextAsync(filePath, updatedJson);
        }

        (app.Configuration as IConfigurationRoot)?.Reload();

        return Results.Ok(new { success = true, message = "Configurazione ACME salvata con successo. Le modifiche sono attive immediatamente." });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Errore durante il salvataggio della configurazione ACME.");
        return Results.Problem("Errore durante il salvataggio della configurazione ACME. I dettagli sono nel log del server.");
    }
    finally
    {
        configSaveLock.Release();
    }
});

// ===== Gestione Richieste Trattenute (Hold) =====

// GET /api/admin/held-requests - Lista richieste trattenute (default: solo PendingApproval, con filtri)
admin.MapGet("/held-requests", async (
    HttpContext ctx,
    IHeldRequestStore holdStore,
    string? status,
    string? requester,
    string? template,
    string? search) =>
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
        "issued" => HoldStatus.Issued,
        "undersubmission" => HoldStatus.UnderSubmission,
        "all" => null,
        _ => HoldStatus.PendingApproval // default: solo pending
    };

    var requests = await holdStore.GetAllRequestsAsync(statusFilter);

    static string ResolveRequester(HeldCertificateRequest r)
    {
        if (!string.IsNullOrWhiteSpace(r.RequesterUser))
            return r.RequesterUser;
        if (r.RequesterComments?.StartsWith("ACME order", StringComparison.OrdinalIgnoreCase) == true)
            return "ACME";
        return string.Empty;
    }

    var query = requests.AsEnumerable();

    if (!string.IsNullOrWhiteSpace(requester))
    {
        if (requester.Equals("__acme__", StringComparison.OrdinalIgnoreCase) || requester.Equals("acme", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(r => ResolveRequester(r).StartsWith("ACME", StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            query = query.Where(r => ResolveRequester(r).Contains(requester, StringComparison.OrdinalIgnoreCase));
        }
    }

    if (!string.IsNullOrWhiteSpace(template))
    {
        query = query.Where(r =>
            (!string.IsNullOrEmpty(r.TemplateName) && r.TemplateName.Contains(template, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrEmpty(r.TemplateDisplayName) && r.TemplateDisplayName.Contains(template, StringComparison.OrdinalIgnoreCase)));
    }

    if (!string.IsNullOrWhiteSpace(search))
    {
        query = query.Where(r =>
            (!string.IsNullOrEmpty(r.SubjectCommonName) && r.SubjectCommonName.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
            ResolveRequester(r).Contains(search, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrEmpty(r.TemplateName) && r.TemplateName.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrEmpty(r.TemplateDisplayName) && r.TemplateDisplayName.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrEmpty(r.CaId) && r.CaId.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
            r.CaRequestId.ToString().Contains(search) ||
            (!string.IsNullOrEmpty(r.HoldId) && r.HoldId.Contains(search, StringComparison.OrdinalIgnoreCase)));
    }

    var filteredList = query.ToList();

    return Results.Ok(new
    {
        count = filteredList.Count,
        statusFilter = statusFilter?.ToString() ?? "All",
        requests = filteredList.Select(r => new
        {
            r.HoldId,
            r.SubmittedAt,
            r.CaId,
            r.TemplateName,
            r.TemplateDisplayName,
            RequesterUser = ResolveRequester(r),
            r.SubjectCommonName,
            r.SanAttribute,
            r.CaRequestId,
            Status = r.Status.ToString(),
            r.ReviewedAt,
            r.ReviewedBy,
            r.RejectionReason,
            r.RequesterComments,
            HasCertificate = !string.IsNullOrEmpty(r.CertificatePem),
            HasPrivateKey = !string.IsNullOrEmpty(r.PrivateKeyPem)
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

// ===== ACME Server (RFC 8555) Integrato =====
// Consente il rinnovo automatico tramite client ACME (win-acme, certbot, acme.sh, ecc.).
// Gli endpoint ACME sono esposti in modalità anonima poiché autenticati crittograficamente con JWS (RFC 7515).

string GetAcmeBaseUrl(HttpContext ctx, AcmeConfig config)
{
    if (!string.IsNullOrWhiteSpace(config.BaseUrl))
        return config.BaseUrl.TrimEnd('/');
    return $"{ctx.Request.Scheme}://{ctx.Request.Host}".TrimEnd('/');
}

async Task<AcmeJwsRequest?> ReadAcmeJwsAsync(HttpContext ctx)
{
    try
    {
        // SECURITY (2.3.1): limite di dimensione del body JWS (RFC 8555
        // Sez. 6.2: 32 KiB) — impedisce a payload maliziosi di grande
        // dimensione di consumare memoria/CPU nel parsing.
        if (ctx.Request.ContentLength is long cl and > (32 * 1024))
        {
            return null;
        }
        return await ctx.Request.ReadFromJsonAsync<AcmeJwsRequest>();
    }
    catch
    {
        return null;
    }
}

void ApplyAcmeResponseHeaders(HttpContext ctx, string? newNonce, string baseUrl)
{
    if (!string.IsNullOrEmpty(newNonce))
    {
        ctx.Response.Headers["Replay-Nonce"] = newNonce;
    }
    ctx.Response.Headers["Cache-Control"] = "no-store";
    ctx.Response.Headers.Append("Link", $"<{baseUrl}/acme/directory>;rel=\"index\"");
}

string? GetClientIp(HttpContext ctx)
{
    if (ctx.Request.Headers.TryGetValue("X-Forwarded-For", out var forwarded) && !string.IsNullOrWhiteSpace(forwarded))
    {
        var first = forwarded.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(first))
            return first;
    }
    var ip = ctx.Connection.RemoteIpAddress;
    if (ip != null)
    {
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        return ip.ToString();
    }
    return null;
}

var acme = app.MapGroup("/acme")
    .AllowAnonymous()
    .RequireRateLimiting("acme-policy");

// 1. Directory RFC 8555 Sez. 7.1.1
acme.MapGet("/directory", (HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    var dir = acmeSvc.GetDirectory(baseUrl);
    return Results.Ok(dir);
});

// 2. New-Nonce RFC 8555 Sez. 7.2
acme.MapMethods("/new-nonce", new[] { "GET", "HEAD" }, (HttpContext ctx, IAcmeService acmeSvc) =>
{
    string nonce = acmeSvc.CreateNonce();
    ctx.Response.Headers["Replay-Nonce"] = nonce;
    ctx.Response.Headers["Cache-Control"] = "no-store";
    return Results.NoContent();
});

// 3. New-Account RFC 8555 Sez. 7.3
acme.MapPost("/new-account", async (HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    var jws = await ReadAcmeJwsAsync(ctx);
    if (jws == null)
    {
        string nonce = acmeSvc.CreateNonce();
        ApplyAcmeResponseHeaders(ctx, nonce, baseUrl);
        return Results.Json(new AcmeProblem { Type = AcmeErrorTypes.Malformed, Detail = "Richiesta JWS non valida.", Status = 400 },
            contentType: "application/problem+json", statusCode: 400);
    }

    var (result, newNonce) = await acmeSvc.HandleNewAccountAsync(jws, baseUrl);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 4. Account Management & POST-as-GET RFC 8555 Sez. 7.3.1
acme.MapMethods("/account/{id}", new[] { "GET", "POST" }, async (string id, HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    AcmeJwsRequest? jws = ctx.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
        ? await ReadAcmeJwsAsync(ctx)
        : null;

    var (result, newNonce) = await acmeSvc.HandleGetAccountAsync(id, jws, baseUrl);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 5. Account Orders List RFC 8555 Sez. 7.1.2.1
acme.MapMethods("/account/{id}/orders", new[] { "GET", "POST" }, async (string id, HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    AcmeJwsRequest? jws = ctx.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
        ? await ReadAcmeJwsAsync(ctx)
        : null;

    var (result, newNonce) = await acmeSvc.HandleGetOrdersAsync(id, jws, baseUrl);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 6. New-Order RFC 8555 Sez. 7.4
acme.MapPost("/new-order", async (HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    var jws = await ReadAcmeJwsAsync(ctx);
    if (jws == null)
    {
        string nonce = acmeSvc.CreateNonce();
        ApplyAcmeResponseHeaders(ctx, nonce, baseUrl);
        return Results.Json(new AcmeProblem { Type = AcmeErrorTypes.Malformed, Detail = "Richiesta JWS non valida.", Status = 400 },
            contentType: "application/problem+json", statusCode: 400);
    }

    string? clientIp = GetClientIp(ctx);
    var (result, newNonce) = await acmeSvc.HandleNewOrderAsync(jws, baseUrl, clientIp);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 7. Order Status RFC 8555 Sez. 7.4
acme.MapMethods("/order/{id}", new[] { "GET", "POST" }, async (string id, HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    AcmeJwsRequest? jws = ctx.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
        ? await ReadAcmeJwsAsync(ctx)
        : null;

    var (result, newNonce) = await acmeSvc.HandleGetOrderAsync(id, jws, baseUrl);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 8. Order Finalize RFC 8555 Sez. 7.4
acme.MapPost("/order/{id}/finalize", async (string id, HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    var jws = await ReadAcmeJwsAsync(ctx);
    if (jws == null)
    {
        string nonce = acmeSvc.CreateNonce();
        ApplyAcmeResponseHeaders(ctx, nonce, baseUrl);
        return Results.Json(new AcmeProblem { Type = AcmeErrorTypes.Malformed, Detail = "Richiesta JWS non valida.", Status = 400 },
            contentType: "application/problem+json", statusCode: 400);
    }

    string? clientIp = GetClientIp(ctx);
    var (result, newNonce) = await acmeSvc.HandleFinalizeOrderAsync(id, jws, baseUrl, clientIp);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 9. Authorization RFC 8555 Sez. 7.5
acme.MapMethods("/authz/{id}", new[] { "GET", "POST" }, async (string id, HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    AcmeJwsRequest? jws = ctx.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
        ? await ReadAcmeJwsAsync(ctx)
        : null;

    var (result, newNonce) = await acmeSvc.HandleGetAuthorizationAsync(id, jws, baseUrl);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 10. Challenge RFC 8555 Sez. 7.5.1
acme.MapMethods("/chall/{authId}/{type}", new[] { "GET", "POST" }, async (string authId, string type, HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    var jws = await ReadAcmeJwsAsync(ctx);
    if (jws == null && ctx.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase))
    {
        string nonce = acmeSvc.CreateNonce();
        ApplyAcmeResponseHeaders(ctx, nonce, baseUrl);
        return Results.Json(new AcmeProblem { Type = AcmeErrorTypes.Malformed, Detail = "Richiesta JWS non valida.", Status = 400 },
            contentType: "application/problem+json", statusCode: 400);
    }

    if (jws == null)
    {
        var authResult = await acmeSvc.HandleGetAuthorizationAsync(authId, null, baseUrl);
        ApplyAcmeResponseHeaders(ctx, authResult.NewNonce, baseUrl);
        return authResult.Result;
    }

    var (result, newNonce) = await acmeSvc.HandleChallengeAsync(authId, type, jws, baseUrl);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 11. Certificate Download RFC 8555 Sez. 7.4.2
acme.MapMethods("/cert/{id}", new[] { "GET", "POST" }, async (string id, HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    AcmeJwsRequest? jws = ctx.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
        ? await ReadAcmeJwsAsync(ctx)
        : null;

    var (result, newNonce) = await acmeSvc.HandleGetCertificateAsync(id, jws, baseUrl);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 12. Revoke Cert RFC 8555 Sez. 7.6
acme.MapPost("/revoke-cert", async (HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    var jws = await ReadAcmeJwsAsync(ctx);
    if (jws == null)
    {
        string nonce = acmeSvc.CreateNonce();
        ApplyAcmeResponseHeaders(ctx, nonce, baseUrl);
        return Results.Json(new AcmeProblem { Type = AcmeErrorTypes.Malformed, Detail = "Richiesta JWS non valida.", Status = 400 },
            contentType: "application/problem+json", statusCode: 400);
    }

    var (result, newNonce) = await acmeSvc.HandleRevokeCertAsync(jws, baseUrl);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 13. Key Change RFC 8555 Sez. 7.5
acme.MapPost("/key-change", async (HttpContext ctx, IAcmeService acmeSvc, Microsoft.Extensions.Options.IOptionsMonitor<AcmeConfig> cfgMonitor) =>
{
    string baseUrl = GetAcmeBaseUrl(ctx, cfgMonitor.CurrentValue);
    var jws = await ReadAcmeJwsAsync(ctx);
    if (jws == null)
    {
        string nonce = acmeSvc.CreateNonce();
        ApplyAcmeResponseHeaders(ctx, nonce, baseUrl);
        return Results.Json(new AcmeProblem { Type = AcmeErrorTypes.Malformed, Detail = "Richiesta JWS non valida.", Status = 400 },
            contentType: "application/problem+json", statusCode: 400);
    }

    var (result, newNonce) = await acmeSvc.HandleKeyChangeAsync(jws, baseUrl);
    ApplyAcmeResponseHeaders(ctx, newNonce, baseUrl);
    return result;
});

// 14. Termini di servizio
acme.MapGet("/terms", () => Results.Text("Enterprise PKI Portal - ACME Automated Certificate Enrollment Terms of Service.\nAutomated issuance governed by Enterprise Active Directory Certificate Services policies.", "text/plain"));

// Supporto locale /.well-known/acme-challenge/{token} per test
app.MapGet("/.well-known/acme-challenge/{token}", (string token) =>
{
    return Results.NotFound();
}).AllowAnonymous();

app.Run();

// DTO per il body della reject
public record RejectHeldRequestBody(string? Reason);
