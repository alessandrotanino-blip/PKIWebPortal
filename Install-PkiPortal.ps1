<#
.SYNOPSIS
    Script di installazione del Portale PKI Web Enrollment su IIS Windows Server.
    Installa il sito a fianco del Microsoft Web Enrollment (certsrv) senza modificarlo.

.DESCRIPTION
    Questo script esegue le seguenti operazioni:
    1. Verifica ed installa i prerequisiti IIS necessari (senza toccare certsrv).
    2. Scarica e installa il .NET 8 Hosting Bundle se non presente.
    3. Pubblica l'applicazione ASP.NET Core nella cartella di destinazione.
    4. Crea un nuovo Application Pool dedicato con l'identità specificata.
    5. Crea un nuovo sito IIS separato (su porta e hostname configurabili).
    6. Crea una regola firewall per la porta configurata.
    7. Configura i log e le cartelle necessarie.

.PARAMETER SiteName
    Nome del sito IIS da creare (default: "PkiWebEnrollment")

.PARAMETER SitePort
    Porta HTTP su cui il sito sarà in ascolto (default: 8443)

.PARAMETER SiteHostHeader
    Host header opzionale per il sito (es. "pki.azienda.lan"). Se vuoto, risponde su qualsiasi hostname.

.PARAMETER InstallPath
    Percorso fisico sul server dove pubblicare l'applicazione (default: "C:\inetpub\PkiWebEnrollment")

.PARAMETER AppPoolIdentity
    Identità dell'Application Pool. Valori: "ApplicationPoolIdentity", "NetworkService", "LocalSystem",
    oppure un account di dominio nel formato "DOMAIN\ServiceAccount" (con -AppPoolPassword),
    oppure un account gMSA (Group Managed Service Account) nel formato "DOMAIN\Account$" o con il parametro -IsGMSA.

.PARAMETER AppPoolPassword
    Password dell'account di dominio (NON necessaria per account gMSA).

.PARAMETER IsGMSA
    Specifica che l'identità dell'AppPool è un account gMSA (Group Managed Service Account).
    I gMSA non hanno password: lo script configurerà IIS con password vuota, verificherà che il nome
    termini con '$' (aggiungendolo automaticamente se omesso) e assegnerà il diritto SeBatchLogonRight.

.PARAMETER UseHttps
    Se specificato, configura il binding HTTPS sulla porta indicata (richiede -CertThumbprint).

.PARAMETER CertThumbprint
    Thumbprint del certificato SSL/TLS da associare al binding HTTPS.
    Il certificato deve essere già installato nello store Personal del computer locale.

.PARAMETER SourcePath
    Percorso del progetto sorgente ASP.NET Core (default: directory corrente).

.PARAMETER NuGetSource
    Una o più sorgenti NuGet (URL o cartella locale con i .nupkg) da usare per il restore durante la
    pubblicazione. Utile su server isolati da Internet: sostituisce le sorgenti configurate (nuget.org incluso).

.PARAMETER SkipDotnetPublish
    Se specificato, salta la fase di compilazione e deploy (usa file già pubblicati in InstallPath).

.PARAMETER SkipFirewall
    Se specificato, non crea la regola firewall.

.PARAMETER OverwriteConfig
    Se specificato, sovrascrive appsettings.json e web.config nella cartella di installazione
    anche se già esistenti. Senza questo parametro, i file di configurazione esistenti vengono
    preservati durante gli aggiornamenti (vengono copiati solo alla prima installazione).

.EXAMPLE
    # Installazione base con porta HTTP 8443
    .\Install-PkiPortal.ps1

.EXAMPLE
    # Installazione con gMSA (Group Managed Service Account - nessuna password richiesta)
    .\Install-PkiPortal.ps1 -SitePort 8443 -AppPoolIdentity "VD\T0_PKI_WEB" -IsGMSA

.EXAMPLE
    # Installazione HTTPS con certificato SSL e account utente standard
    .\Install-PkiPortal.ps1 -SitePort 443 -SiteHostHeader "pki.azienda.lan" -UseHttps `
        -CertThumbprint "A1B2C3D4E5..." -AppPoolIdentity "FORESTA1\svc-pki-portal" -AppPoolPassword (Read-Host -AsSecureString)

.EXAMPLE
    # Installazione su porta custom senza modifiche firewall
    .\Install-PkiPortal.ps1 -SiteName "PKI-Enrollment-F1" -SitePort 9443 -SkipFirewall

.NOTES
    Autore:  Enterprise PKI Team
    Versione: 1.0
    Richiede: Windows Server 2016+ con ruolo IIS, privilegi di amministratore locale.
    IMPORTANTE: Questo script NON modifica in alcun modo il sito "Default Web Site" né certsrv.
#>

[CmdletBinding()]
param(
    [string]$SiteName          = "PkiWebEnrollment",
    [int]$SitePort             = 8443,
    [string]$SiteHostHeader    = "",
    [string]$InstallPath       = "C:\inetpub\PkiWebEnrollment",
    [string]$AppPoolIdentity   = "ApplicationPoolIdentity",
    [SecureString]$AppPoolPassword,
    [switch]$IsGMSA,
    [switch]$UseHttps,
    [string]$CertThumbprint    = "",
    [string]$SourcePath        = $PSScriptRoot,
    [string[]]$NuGetSource     = @(),
    [switch]$SkipDotnetPublish,
    [switch]$SkipFirewall,
    [Alias("OverwriteAppSettings")]
    [switch]$OverwriteConfig
)

# ============================================================================
# FUNZIONI DI SUPPORTO
# ============================================================================

function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor $Color
    Write-Host "  $Message" -ForegroundColor White
    Write-Host "===============================================================" -ForegroundColor $Color
}

function Write-Info {
    param([string]$Message)
    Write-Host "  [INFO] $Message" -ForegroundColor Gray
}

function Write-OK {
    param([string]$Message)
    Write-Host "  [OK]   $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

function Test-IsAdmin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Grant-BatchLogonRight {
    param([string]$Account)
    try {
        $tempCfg = [System.IO.Path]::GetTempFileName()
        $tempDb  = [System.IO.Path]::GetTempFileName()
        Remove-Item $tempDb -Force -ErrorAction SilentlyContinue

        secedit /export /cfg $tempCfg /areas USER_RIGHTS | Out-Null
        if (Test-Path $tempCfg) {
            $content = Get-Content $tempCfg -Raw -Encoding Unicode
            $sid = $null
            try {
                $sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch { }

            $accountTarget = if ($sid) { "*$sid" } else { $Account }

            if ($content -match "SeBatchLogonRight\s*=\s*([^\r\n]*)") {
                $currentRights = $matches[1]
                if ($currentRights -notmatch [regex]::Escape($accountTarget) -and ($sid -and $currentRights -notmatch [regex]::Escape($sid))) {
                    $newRights = "$currentRights,$accountTarget"
                    $content = $content -replace "SeBatchLogonRight\s*=.*", "SeBatchLogonRight = $newRights"
                    [System.IO.File]::WriteAllText($tempCfg, $content, [System.Text.Encoding]::Unicode)
                    secedit /configure /db $tempDb /cfg $tempCfg /areas USER_RIGHTS | Out-Null
                    Write-OK "Diritto 'Accesso come processo batch' (SeBatchLogonRight) assegnato a '$Account'."
                } else {
                    Write-OK "Diritto 'Accesso come processo batch' (SeBatchLogonRight) già presente per '$Account'."
                }
            } else {
                $content = $content -replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSeBatchLogonRight = $accountTarget"
                [System.IO.File]::WriteAllText($tempCfg, $content, [System.Text.Encoding]::Unicode)
                secedit /configure /db $tempDb /cfg $tempCfg /areas USER_RIGHTS | Out-Null
                Write-OK "Diritto 'Accesso come processo batch' (SeBatchLogonRight) assegnato a '$Account'."
            }
        }
    } catch {
        Write-Warn "Verifica SeBatchLogonRight: $($_.Exception.Message)"
        Write-Info "Se l'Application Pool non dovesse avviarsi (errore WAS 5021), verificare nei Criteri Locali (secpol.msc)"
        Write-Info "che l'account '$Account' abbia il diritto 'Accesso come processo batch'."
    } finally {
        Remove-Item $tempCfg, $tempDb -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# STEP 0: Verifica privilegi di amministratore
# ============================================================================

if (-not (Test-IsAdmin)) {
    Write-Fail "Questo script deve essere eseguito come Amministratore."
    Write-Fail "Fare clic destro su PowerShell -> 'Esegui come amministratore', quindi rieseguire lo script."
    exit 1
}

$ErrorActionPreference = "Stop"
# In PowerShell 7.3+, native commands (dotnet.exe, appcmd.exe, ecc.) writing anything
# to stderr would otherwise be treated as a terminating error when $ErrorActionPreference
# = "Stop", even on success. Disattivato per lasciare che sia il controllo su
# $LASTEXITCODE (già presente nello script) a decidere se un comando è fallito.
# No-op su Windows PowerShell 5.1, dove questa variabile non esiste.
$PSNativeCommandUseErrorActionPreference = $false

# Rilevamento account gMSA (Group Managed Service Account)
# Un account è considerato gMSA se:
# 1. È specificato il parametro -IsGMSA, oppure
# 2. Il nome termina con '$' (standard Active Directory per service account), oppure
# 3. È un account di dominio specificato senza password
$isAccountGMSA = $false
if ($AppPoolIdentity -notin @("ApplicationPoolIdentity", "NetworkService", "LocalSystem")) {
    if ($IsGMSA -or $AppPoolIdentity.EndsWith('$') -or ($AppPoolIdentity -like "*\*" -and -not $AppPoolPassword)) {
        $isAccountGMSA = $true
        # Nei sistemi Windows / Active Directory i gMSA terminano sempre con '$'
        if (-not $AppPoolIdentity.EndsWith('$')) {
            $AppPoolIdentity = "${AppPoolIdentity}$"
        }
    }
}

# Codifica della console: forza UTF-8 così accenti e output di dotnet.exe non risultano corrotti.
# (Il file è salvato in UTF-8 con BOM, indispensabile per Windows PowerShell 5.1.)
# Il valore originale viene ripristinato al termine dello script (blocco finally in fondo).
$prevConsoleEncoding = $null
try {
    $prevConsoleEncoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding          = [System.Text.UTF8Encoding]::new($false)
}
catch { }

try {

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  INSTALLAZIONE PORTALE PKI WEB ENROLLMENT (AD CS Modern)         " -ForegroundColor White
Write-Host "  Installazione a fianco di Microsoft certsrv (non intrusiva)     " -ForegroundColor Gray
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Info "Nome Sito IIS:        $SiteName"
Write-Info "Porta:                $SitePort"
Write-Info "Host Header:          $(if ($SiteHostHeader) { $SiteHostHeader } else { '(tutti)' })"
Write-Info "Percorso Installazione: $InstallPath"
Write-Info "App Pool Identity:    $AppPoolIdentity $(if ($isAccountGMSA) { '(gMSA - Group Managed Service Account)' })"
Write-Info "Protocollo:           $(if ($UseHttps) { 'HTTPS' } else { 'HTTP' })"
Write-Info "Sorgente Progetto:    $SourcePath"
Write-Host ""

# ============================================================================
# STEP 1: Verifica e Installazione Feature IIS Necessarie
# ============================================================================

Write-Step "STEP 1: Verifica prerequisiti IIS (senza modificare certsrv)"

# Elenco delle feature IIS necessarie per ASP.NET Core hosting.
# NON includiamo Web-Cert-Auth o Web-Windows-Auth per non interferire con certsrv.
# Includiamo solo i moduli di base necessari per l'hosting di un sito ASP.NET Core.
$requiredFeatures = @(
    @{ Name = "Web-Server";             Desc = "Ruolo Web Server (IIS)" },
    @{ Name = "Web-Common-Http";        Desc = "Funzionalità HTTP comuni" },
    @{ Name = "Web-Default-Doc";        Desc = "Documenti predefiniti" },
    @{ Name = "Web-Static-Content";     Desc = "Contenuto statico" },
    @{ Name = "Web-Http-Errors";        Desc = "Errori HTTP personalizzati" },
    @{ Name = "Web-Http-Logging";       Desc = "Logging HTTP" },
    @{ Name = "Web-Request-Monitor";    Desc = "Monitor richieste" },
    @{ Name = "Web-Filtering";          Desc = "Filtro richieste" },
    @{ Name = "Web-Stat-Compression";   Desc = "Compressione statica" },
    @{ Name = "Web-Dyn-Compression";    Desc = "Compressione dinamica" },
    @{ Name = "Web-Mgmt-Console";       Desc = "Console di gestione IIS" }
)

$installedFeatures = 0
$alreadyInstalled = 0

foreach ($feature in $requiredFeatures) {
    $state = Get-WindowsFeature -Name $feature.Name -ErrorAction SilentlyContinue
    if ($null -eq $state) {
        Write-Warn "$($feature.Desc) ($($feature.Name)) - Feature non trovata su questo sistema (possibile edizione senza Server Manager)"
        continue
    }

    if ($state.Installed) {
        Write-OK "$($feature.Desc) - già installata"
        $alreadyInstalled++
    }
    else {
        Write-Info "Installazione in corso: $($feature.Desc) ($($feature.Name))..."
        try {
            Install-WindowsFeature -Name $feature.Name -IncludeManagementTools -ErrorAction Stop | Out-Null
            Write-OK "$($feature.Desc) - installata con successo"
            $installedFeatures++
        }
        catch {
            Write-Warn "Impossibile installare $($feature.Name): $($_.Exception.Message)"
        }
    }
}

Write-Info "Feature già presenti: $alreadyInstalled, Nuove installate: $installedFeatures"

# Importa modulo WebAdministration (necessario per gestione siti IIS via PowerShell)
Import-Module WebAdministration -ErrorAction SilentlyContinue
if (-not (Get-Module WebAdministration -ErrorAction SilentlyContinue)) {
    Write-Warn "Il modulo PowerShell 'WebAdministration' non è disponibile. Tentativo con IISAdministration..."
    Import-Module IISAdministration -ErrorAction SilentlyContinue
}

# ============================================================================
# STEP 2: Verifica e Installazione .NET 8 ASP.NET Core Hosting Bundle
# ============================================================================

Write-Step "STEP 2: Verifica .NET 8 ASP.NET Core Hosting Bundle"

$aspnetModuleInstalled = $false

# Verifica se il modulo ASP.NET Core è registrato in IIS
$aspnetModule = Get-WebGlobalModule -Name "AspNetCoreModuleV2" -ErrorAction SilentlyContinue
if ($aspnetModule) {
    Write-OK "ASP.NET Core Module V2 è già registrato in IIS."
    $aspnetModuleInstalled = $true
}

# Verifica anche la presenza del runtime .NET 8 x64
$dotnetRuntimes = & "C:\Program Files\dotnet\dotnet.exe" --list-runtimes 2>&1 | Select-String "Microsoft.AspNetCore.App 8\."
if ($dotnetRuntimes) {
    Write-OK "Runtime ASP.NET Core 8.x trovato: $($dotnetRuntimes -join ', ')"
}
else {
    Write-Warn "Runtime ASP.NET Core 8.x non trovato."
}

if (-not $aspnetModuleInstalled) {
    Write-Info "Il modulo ASP.NET Core non è registrato in IIS."
    Write-Info "È necessario installare il '.NET 8 Hosting Bundle' da:"
    Write-Host ""
    Write-Host "  https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
    Write-Host ""
    Write-Info "Scaricando l'installer automaticamente..."

    $hostingBundleUrl = "https://download.visualstudio.microsoft.com/download/pr/hosting-bundle-8.0-latest-win-x64.exe"
    $hostingBundlePath = Join-Path $env:TEMP "dotnet-hosting-8.0-win.exe"

    try {
        # Tentativo di download (potrebbe non funzionare in ambienti airgapped)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/8.0.0/dotnet-hosting-8.0.0-win.exe" `
            -OutFile $hostingBundlePath -UseBasicParsing -ErrorAction Stop

        Write-Info "Download completato. Avvio installazione silenziosa..."
        $process = Start-Process -FilePath $hostingBundlePath -ArgumentList "/install", "/quiet", "/norestart" `
            -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -eq 0) {
            Write-OK "Hosting Bundle .NET 8 installato con successo."
            Write-Warn "Potrebbe essere necessario riavviare IIS dopo l'installazione (iisreset)."
        }
        else {
            Write-Warn "L'installer è terminato con codice: $($process.ExitCode)"
        }
    }
    catch {
        Write-Warn "Download automatico fallito: $($_.Exception.Message)"
        Write-Host ""
        Write-Host "  AZIONE RICHIESTA: Scaricare manualmente il .NET 8 Hosting Bundle da:" -ForegroundColor Red
        Write-Host "  https://dotnet.microsoft.com/download/dotnet/8.0 -> Hosting Bundle (Windows)" -ForegroundColor Yellow
        Write-Host "  Installarlo ed eseguire nuovamente questo script." -ForegroundColor Red
        Write-Host ""

        $continueChoice = Read-Host "Continuare comunque? (S/N)"
        if ($continueChoice -ne "S") {
            Write-Fail "Installazione interrotta."
            exit 1
        }
    }
}

# ============================================================================
# STEP 3: Verifica che certsrv non venga toccato
# ============================================================================

Write-Step "STEP 3: Verifica integrità sito certsrv (Microsoft Web Enrollment)"

$defaultWebSite = Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
if ($defaultWebSite) {
    Write-OK "Sito 'Default Web Site' trovato (stato: $($defaultWebSite.State))"

    $certsrvApp = Get-WebApplication -Site "Default Web Site" -Name "CertSrv" -ErrorAction SilentlyContinue
    if ($certsrvApp) {
        Write-OK "Applicazione certsrv trovata sotto Default Web Site: $($certsrvApp.PhysicalPath)"
        Write-Info "certsrv NON verrà modificato. Il portale PKI verrà installato come sito IIS SEPARATO."
    }
    else {
        Write-Info "Applicazione certsrv non trovata sotto Default Web Site (potrebbe essere già rimossa o non installata)."
    }
}
else {
    Write-Info "'Default Web Site' non trovato. Procedendo con la creazione del nuovo sito."
}

# Verifica che il nome del sito non esista già
$existingSite = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
if ($existingSite) {
    Write-Warn "Il sito '$SiteName' esiste già in IIS."
    $overwrite = Read-Host "  Sovrascrivere la configurazione del sito esistente? (S/N)"
    if ($overwrite -ne "S") {
        Write-Fail "Installazione interrotta dall'utente."
        exit 1
    }
    Write-Info "Rimozione del sito IIS esistente '$SiteName'..."
    Remove-Website -Name $SiteName -ErrorAction SilentlyContinue
}

# Verifica che la porta non sia in uso da un altro sito (eccetto Default Web Site su 80/443)
$portInUse = Get-WebBinding | Where-Object {
    $_.bindingInformation -match ":${SitePort}:" -and
    (Get-Website | Where-Object { $_.Name -ne $SiteName -and $_.Bindings.Collection.bindingInformation -contains $_.bindingInformation })
}
if ($portInUse) {
    Write-Warn "La porta $SitePort potrebbe essere già in uso da un altro sito IIS."
    Write-Warn "Valutare una porta diversa con il parametro -SitePort."
}

# ============================================================================
# STEP 3b: Arresto App Pool e Sito IIS (se già esistenti - aggiornamento)
# ============================================================================

$appPoolName = "${SiteName}_Pool"
$appcmd = "$env:SystemRoot\system32\inetsrv\appcmd.exe"

# 1. Se la cartella di installazione esiste, posiziona app_offline.htm per liberare i lock di ASP.NET Core
$appOfflineFile = Join-Path $InstallPath "app_offline.htm"
if (Test-Path $InstallPath) {
    try {
        Set-Content -Path $appOfflineFile -Value "<html><body><h3>Aggiornamento Portale PKI in corso...</h3></body></html>" -Force -ErrorAction SilentlyContinue
    } catch { }
}

$existingSite = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
$existingAppPool = Get-WebAppPoolState -Name $appPoolName -ErrorAction SilentlyContinue

if ($existingSite -or $existingAppPool -or (Test-Path $InstallPath)) {
    Write-Step "STEP 3b: Arresto sito e App Pool esistenti per aggiornamento"

    # Arresta il sito
    if ($existingSite -and $existingSite.State -eq 'Started') {
        try {
            Stop-Website -Name $SiteName -ErrorAction Stop
            Write-OK "Sito '$SiteName' arrestato."
        }
        catch {
            Write-Warn "Impossibile arrestare il sito '$SiteName' via PowerShell. Tentativo con appcmd..."
            if (Test-Path $appcmd) { & $appcmd stop site /site.name:"$SiteName" 2>$null }
        }
    }
    elseif ($existingSite) {
        Write-Info "Sito '$SiteName' già in stato '$($existingSite.State)'."
    }

    # Arresta l'App Pool
    try {
        if (Test-Path $appcmd) {
            & $appcmd stop apppool /apppool.name:"$appPoolName" 2>$null
        }
        Stop-WebAppPool -Name $appPoolName -ErrorAction SilentlyContinue
    } catch { }

    # Attendi che il worker process termini graziosamente
    $timeout = 10
    $elapsed = 0
    while ($elapsed -lt $timeout) {
        $state = (Get-WebAppPoolState -Name $appPoolName -ErrorAction SilentlyContinue).Value
        if ($state -ne 'Started' -and $state -ne 'Stopping') { break }
        Start-Sleep -Seconds 1
        $elapsed++
    }

    # Verifica se ci sono ancora processi w3wp.exe attivi per questo AppPool o che bloccano PkiPortal.dll
    try {
        $w3wpProcesses = Get-CimInstance Win32_Process -Filter "Name = 'w3wp.exe'" -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -like "*$appPoolName*"
        }
        foreach ($proc in $w3wpProcesses) {
            Write-Warn "Worker process w3wp.exe (PID $($proc.ProcessId)) ancora attivo. Terminazione forzata..."
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        }
    } catch { }

    Write-OK "Sito e Application Pool pronti per l'aggiornamento dei file."
}
else {
    Write-Info "Nessun sito/pool '$SiteName' esistente da arrestare (prima installazione)."
}

# ============================================================================
# STEP 4: Compilazione e Pubblicazione dell'applicazione
# ============================================================================

Write-Step "STEP 4: Compilazione e pubblicazione applicazione ASP.NET Core"

if ($SkipDotnetPublish) {
    Write-Info "Fase di pubblicazione saltata (-SkipDotnetPublish specificato)."
    Write-Info "I file applicativi devono già essere presenti in: $InstallPath"
}
else {
    # Individua il dotnet CLI (x64)
    $dotnetExe = "C:\Program Files\dotnet\dotnet.exe"
    if (-not (Test-Path $dotnetExe)) {
        $dotnetExe = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
    }
    if (-not $dotnetExe -or -not (Test-Path $dotnetExe)) {
        Write-Fail "Impossibile trovare dotnet.exe. Installare .NET 8 SDK o Hosting Bundle."
        exit 1
    }
    Write-Info "CLI .NET trovato: $dotnetExe"

    # Verifica che il progetto esista nel percorso sorgente
    $csprojPath = Join-Path $SourcePath "PkiPortal.csproj"
    if (-not (Test-Path $csprojPath)) {
        Write-Fail "File di progetto non trovato: $csprojPath"
        Write-Fail "Specificare il percorso corretto con il parametro -SourcePath."
        exit 1
    }
    Write-OK "File di progetto trovato: $csprojPath"

    # Creazione cartella di destinazione
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        Write-OK "Cartella di installazione creata: $InstallPath"
    }

    # Backup preventivo dei file di configurazione esistenti in destinazione:
    # La pubblicazione (dotnet publish) copia automaticamente i file dal sorgente sovrascrivendo
    # la destinazione. Se non è specificato -OverwriteConfig (-OverwriteAppSettings), preserviamo
    # il file appsettings.json e web.config esistenti salvandone una copia temporanea.
    $destSettings = Join-Path $InstallPath "appsettings.json"
    $destWebConfig = Join-Path $InstallPath "web.config"
    $backupSettingsPath = $null
    $backupWebConfigPath = $null

    if (-not $OverwriteConfig) {
        if (Test-Path $destSettings) {
            $backupSettingsPath = Join-Path ([System.IO.Path]::GetTempPath()) "pki_backup_appsettings_$([Guid]::NewGuid().ToString('N')).json"
            Copy-Item -Path $destSettings -Destination $backupSettingsPath -Force
            Write-Info "Backup di sicurezza di appsettings.json esistente: $backupSettingsPath"
        }
        if (Test-Path $destWebConfig) {
            $backupWebConfigPath = Join-Path ([System.IO.Path]::GetTempPath()) "pki_backup_webconfig_$([Guid]::NewGuid().ToString('N')).xml"
            Copy-Item -Path $destWebConfig -Destination $backupWebConfigPath -Force
            Write-Info "Backup di sicurezza di web.config esistente: $backupWebConfigPath"
        }
    }

    # Pubblicazione
    Write-Info 'Pubblicazione in corso (Release - non self-contained)...'
    $publishArgs = @(
        "publish"
        $csprojPath
        "--configuration", "Release"
        "--output", $InstallPath
        "--no-self-contained"
        "--runtime", "win-x64"
        "--nologo"
        # Non scaricare i targeting pack dei framework non referenziati (es. Microsoft.WindowsDesktop.App.Ref)
        "-p:DisableTransitiveFrameworkReferenceDownloads=true"
    )
    foreach ($src in $NuGetSource) {
        $publishArgs += @("--source", $src)
    }

    # Variabili d'ambiente valide solo per questa invocazione: niente banner "Welcome to .NET",
    # niente telemetria, niente creazione del certificato HTTPS di sviluppo su un server.
    $dotnetEnv = @{
        DOTNET_NOLOGO                      = "1"
        DOTNET_CLI_TELEMETRY_OPTOUT        = "1"
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE  = "1"
        DOTNET_GENERATE_ASPNET_CERTIFICATE = "false"
    }
    $prevEnv = @{}
    foreach ($name in $dotnetEnv.Keys) {
        $prevEnv[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        [Environment]::SetEnvironmentVariable($name, $dotnetEnv[$name], "Process")
    }

    # Esecuzione della pubblicazione
    # NOTA: In Windows PowerShell 5.1, reindirizzare '2>&1' quando $ErrorActionPreference = 'Stop'
    # trasforma qualsiasi riga scritta su stderr (anche semplici warning di compilazione) in una
    # eccezione terminante 'NativeCommandError'.
    # Eseguiamo il comando impostando temporaneamente $ErrorActionPreference = 'Continue'
    # e controllando direttamente $LASTEXITCODE. Ogni riga viene convertita in stringa
    # (le righe di stderr sono ErrorRecord) per poterle stampare in modo uniforme.
    $prevEA = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $publishOutput = & $dotnetExe @publishArgs 2>&1 | ForEach-Object { "$_" }
        $publishExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevEA
        foreach ($name in $prevEnv.Keys) {
            [Environment]::SetEnvironmentVariable($name, $prevEnv[$name], "Process")
        }
    }

    if ($publishExitCode -ne 0) {
        Write-Fail "Errore durante la pubblicazione (codice di uscita: $publishExitCode):"
        $publishOutput | Where-Object { $_ -and $_.Trim() } | ForEach-Object {
            Write-Host "    $_" -ForegroundColor Red
        }

        # Errori di restore NuGet (pacchetti non risolvibili / sorgente non raggiungibile)
        if (($publishOutput -join "`n") -match 'NU1100|NU1101|NU1102|NU1301') {
            Write-Host ""
            Write-Warn "Il restore NuGet non riesce a ottenere i pacchetti richiesti (targeting pack / apphost .NET)."
            Write-Info "Causa probabile: l'SDK installato è più recente del framework di destinazione del progetto"
            Write-Info "e deve scaricare i pack da NuGet, ma nessuna sorgente NuGet è raggiungibile o configurata."
            Write-Info "Soluzioni possibili:"
            Write-Info "  1. Verificare le sorgenti con 'dotnet nuget list source' e abilitare nuget.org se manca."
            Write-Info "  2. Server isolato da Internet: compilare (dotnet publish) su un PC con accesso a NuGet,"
            Write-Info "     copiare l'output in $InstallPath e rieseguire lo script con -SkipDotnetPublish."
            Write-Info "  3. Server isolato: copiare in una cartella i .nupkg indicati nell'errore (stessa versione)"
            Write-Info "     e rieseguire con -NuGetSource <cartella>. Servono: Microsoft.NETCore.App.Ref,"
            Write-Info "     Microsoft.AspNetCore.App.Ref, Microsoft.NETCore.App.Host.win-x64."
            Write-Info "  4. In alternativa, impostare <TargetFramework>net10.0</TargetFramework> nel .csproj"
            Write-Info "     (i pack .NET 10 sono inclusi nell'SDK 10) e installare l'Hosting Bundle .NET 10."
        }
        exit 1
    }

    Write-OK "Applicazione pubblicata con successo in: $InstallPath"

    # Gestione appsettings.json: se esisteva prima del publish e non è stato richiesto -OverwriteConfig,
    # ripristiniamo il file precedente. Altrimenti lasciamo quello generato/copiato dal publish.
    $customSettings = Join-Path $SourcePath "appsettings.json"
    if ($backupSettingsPath -and (Test-Path $backupSettingsPath)) {
        Copy-Item -Path $backupSettingsPath -Destination $destSettings -Force
        Remove-Item -Path $backupSettingsPath -Force -ErrorAction SilentlyContinue
        Write-OK "File appsettings.json di produzione ESISTENTE PRESERVATO (non sovrascritto). Usare -OverwriteConfig per sovrascriverlo."
    }
    elseif ($OverwriteConfig -and (Test-Path $customSettings)) {
        Copy-Item -Path $customSettings -Destination $destSettings -Force
        Write-OK "File di configurazione appsettings.json sovrascritto dal sorgente (-OverwriteConfig specificato)."
    }
    elseif (-not (Test-Path $destSettings) -and (Test-Path $customSettings)) {
        Copy-Item -Path $customSettings -Destination $destSettings -Force
        Write-OK "File di configurazione appsettings.json copiato (prima installazione)."
    }

    # Gestione web.config: stessa logica di preservazione
    $customWebConfig = Join-Path $SourcePath "web.config"
    if ($backupWebConfigPath -and (Test-Path $backupWebConfigPath)) {
        Copy-Item -Path $backupWebConfigPath -Destination $destWebConfig -Force
        Remove-Item -Path $backupWebConfigPath -Force -ErrorAction SilentlyContinue
        Write-OK "File web.config ESISTENTE PRESERVATO (non sovrascritto). Usare -OverwriteConfig per sovrascriverlo."
    }
    elseif ($OverwriteConfig -and (Test-Path $customWebConfig)) {
        Copy-Item -Path $customWebConfig -Destination $destWebConfig -Force
        Write-OK "File web.config sovrascritto dal sorgente (-OverwriteConfig specificato)."
    }
    elseif (-not (Test-Path $destWebConfig) -and (Test-Path $customWebConfig)) {
        Copy-Item -Path $customWebConfig -Destination $destWebConfig -Force
        Write-OK "File web.config copiato (prima installazione)."
    }
    # Rimuovi app_offline.htm per consentire l'avvio della nuova versione
    $appOfflineFile = Join-Path $InstallPath "app_offline.htm"
    if (Test-Path $appOfflineFile) {
        Remove-Item -Path $appOfflineFile -Force -ErrorAction SilentlyContinue
    }
}

# Creazione cartella log per stdout
$logPath = Join-Path $InstallPath "logs"
if (-not (Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    Write-OK "Cartella log creata: $logPath"
}

# Creazione cartella protetta App_Data per custodia sicura di chiavi, held-requests ed entropia
$appDataPath = Join-Path $InstallPath "App_Data"
if (-not (Test-Path $appDataPath)) {
    New-Item -ItemType Directory -Path $appDataPath -Force | Out-Null
    Write-OK "Cartella sicura App_Data creata: $appDataPath"
}
$appDataTempPath = Join-Path $appDataPath "Temp"
if (-not (Test-Path $appDataTempPath)) {
    New-Item -ItemType Directory -Path $appDataTempPath -Force | Out-Null
    Write-OK "Cartella temporanea sicura creata: $appDataTempPath"
}

# Migrazione file sensibili legacy da root di installazione verso App_Data
$legacyHeld = Join-Path $InstallPath "held-requests.json"
$targetHeld = Join-Path $appDataPath "held-requests.json"
if ((Test-Path $legacyHeld) -and -not (Test-Path $targetHeld)) {
    Move-Item -Path $legacyHeld -Destination $targetHeld -Force
    Write-Info "Spostato held-requests.json legacy nella cartella protetta App_Data"
}

$legacyEntropy = Join-Path $InstallPath "store-entropy.bin"
$targetEntropy = Join-Path $appDataPath "store-entropy.bin"
if ((Test-Path $legacyEntropy) -and -not (Test-Path $targetEntropy)) {
    Move-Item -Path $legacyEntropy -Destination $targetEntropy -Force
    Write-Info "Spostato store-entropy.bin legacy nella cartella protetta App_Data"
}

# ============================================================================
# STEP 5: Creazione Application Pool dedicato
# ============================================================================

Write-Step "STEP 5: Creazione Application Pool IIS dedicato"

$appPoolName = "${SiteName}_Pool"
$appcmd = "$env:SystemRoot\system32\inetsrv\appcmd.exe"

$existingPool = & $appcmd list apppool /name:"$appPoolName"
if (-not $existingPool) {
    Write-Info "Creazione Application Pool: $appPoolName"
    & $appcmd add apppool /name:"$appPoolName" | Out-Null
    Write-OK "Application Pool '$appPoolName' creato."
}
else {
    Write-OK "Application Pool '$appPoolName' gia' esistente."
}

# Configurazione pool
& $appcmd set apppool /apppool.name:"$appPoolName" /managedRuntimeVersion:"" /enable32BitAppOnWin64:false /startMode:AlwaysRunning /processModel.idleTimeout:00:00:00 | Out-Null

# Configurazione identita
if ($AppPoolIdentity -eq "ApplicationPoolIdentity") {
    & $appcmd set apppool /apppool.name:"$appPoolName" /processModel.identityType:ApplicationPoolIdentity | Out-Null
    Write-OK "Identita pool: ApplicationPoolIdentity (predefinita)"
}
elseif ($AppPoolIdentity -eq "NetworkService") {
    & $appcmd set apppool /apppool.name:"$appPoolName" /processModel.identityType:NetworkService | Out-Null
    Write-OK "Identita pool: NetworkService"
}
elseif ($AppPoolIdentity -eq "LocalSystem") {
    & $appcmd set apppool /apppool.name:"$appPoolName" /processModel.identityType:LocalSystem | Out-Null
    Write-OK "Identita pool: LocalSystem"
}
elseif ($isAccountGMSA) {
    Write-Info "Configurazione identita pool come gMSA: $AppPoolIdentity (senza password)"
    & $appcmd set config /section:applicationPools "/[name='$appPoolName'].processModel.identityType:SpecificUser" "/[name='$appPoolName'].processModel.userName:$AppPoolIdentity" "/[name='$appPoolName'].processModel.password:" /commit:apphost | Out-Null

    # Assegnazione / verifica del diritto 'Accesso come processo batch' (SeBatchLogonRight) necessario a WAS/IIS
    Grant-BatchLogonRight -Account $AppPoolIdentity

    # Verifica autorizzazione gMSA sul server locale se il modulo ActiveDirectory è presente
    if (Get-Command Test-ADServiceAccount -ErrorAction SilentlyContinue) {
        $samName = if ($AppPoolIdentity -match '^[^\\]+\\(.+)$') { $matches[1] } else { $AppPoolIdentity }
        try {
            $testRes = Test-ADServiceAccount -Identity $samName -ErrorAction SilentlyContinue
            if ($testRes -eq $true) {
                Write-OK "Verifica gMSA: questo server è autorizzato a utilizzare l'account '$AppPoolIdentity'."
            } elseif ($testRes -eq $false) {
                Write-Warn "Verifica gMSA: 'Test-ADServiceAccount -Identity $samName' ha restituito False."
                Write-Info "Se l'Application Pool non dovesse avviarsi, verificare in Active Directory che questo server sia"
                Write-Info "membro del gruppo autorizzato (PrincipalsAllowedToRetrieveManagedPassword) e lanciare:"
                Write-Info "Install-ADServiceAccount -Identity $samName"
            }
        } catch { }
    }

    Write-OK "Identità pool: $AppPoolIdentity (gMSA)"
}
else {
    # Account utente di dominio standard con password
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name "processModel.identityType" -Value "SpecificUser"
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name "processModel.userName"     -Value $AppPoolIdentity

    if ($AppPoolPassword) {
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AppPoolPassword)
        )
        Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name "processModel.password" -Value $plainPassword
        $plainPassword = $null
    }
    Write-OK "Identità pool: $AppPoolIdentity (account utente di dominio)"
}

Write-Info "Pool configurato: startMode=AlwaysRunning, idleTimeout=0, 64-bit, No Managed Runtime."

# ============================================================================
# STEP 6: Creazione Sito IIS
# ============================================================================

Write-Step "STEP 6: Creazione Sito IIS '$SiteName' (porta $SitePort)"

$protocol = if ($UseHttps) { "https" } else { "http" }
$bindingInfo = "*:${SitePort}:${SiteHostHeader}"

Write-Info "Binding: $protocol su $bindingInfo"

if ($UseHttps) {
    if ([string]::IsNullOrWhiteSpace($CertThumbprint)) {
        Write-Warn "Binding HTTPS richiesto ma nessun -CertThumbprint specificato."
        Write-Info "Ricerca di un certificato valido nello store locale..."

        # Tentativo di trovare un certificato con il nome server
        $serverCerts = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey } |
            Sort-Object NotAfter -Descending

        if ($serverCerts.Count -gt 0) {
            $CertThumbprint = $serverCerts[0].Thumbprint
            Write-Info "Trovato certificato: $($serverCerts[0].Subject) (Thumbprint: $CertThumbprint)"
            $useCert = Read-Host "  Utilizzare questo certificato? (S/N)"
            if ($useCert -ne "S") {
                Write-Fail "Specificare un thumbprint con -CertThumbprint oppure usare -UseHttps:$false"
                exit 1
            }
        }
        else {
            Write-Fail "Nessun certificato SSL trovato nello store LocalMachine\My."
            Write-Fail "Installare un certificato SSL e specificare il thumbprint con -CertThumbprint."
            exit 1
        }
    }

    # Creazione sito con binding HTTPS
    New-Website -Name $SiteName `
        -PhysicalPath $InstallPath `
        -ApplicationPool $appPoolName `
        -Port $SitePort `
        -HostHeader $SiteHostHeader `
        -Ssl `
        -Force | Out-Null

    # Associazione del certificato SSL al binding
    $binding = Get-WebBinding -Name $SiteName -Protocol "https"
    if ($binding) {
        $binding.AddSslCertificate($CertThumbprint, "My")
        Write-OK "Certificato SSL associato al binding HTTPS (Thumbprint: $CertThumbprint)"
    }
}
else {
    # SECURITY: HTTP in chiaro + Windows Authentication = NTLM negoziabile in
    # chiaro sulla rete (capture degli hash, NTLM relay). Richiede la conferma
    # esplicita dell'operatore; in produzione usare -UseHttps -CertThumbprint.
    Write-Host "" -ForegroundColor Red
    Write-Host "  [ATTENZIONE] Stai per installare il portale su HTTP IN CHIARO con Windows Authentication." -ForegroundColor Red
    Write-Host "  NTLM viaggia in chiaro sulla rete: rischio capture degli hash e NTLM relay." -ForegroundColor Red
    Write-Host "  In produzione usare: -UseHttps -CertThumbprint <thumbprint> (e abilitare EPAL/EAAL)." -ForegroundColor Red
    $httpConfirm = Read-Host "  Continuare comunque con HTTP in chiaro? (s/N)"
    if ($httpConfirm -ne 's' -and $httpConfirm -ne 'S') {
        Write-Fail "Installazione interrotta: HTTP in chiaro non confermato. Ripetere con -UseHttps -CertThumbprint <thumbprint>."
        exit 1
    }

    # Creazione sito con binding HTTP
    New-Website -Name $SiteName `
        -PhysicalPath $InstallPath `
        -ApplicationPool $appPoolName `
        -Port $SitePort `
        -HostHeader $SiteHostHeader `
        -Force | Out-Null
}

# Configurazione autenticazione a livello di sito IIS (evitando sezioni bloccate in web.config)
try {
    & $appCmd set config "$SiteName" -section:system.webServer/security/authentication/anonymousAuthentication /enabled:"True" /commit:apphost | Out-Null
    & $appCmd set config "$SiteName" -section:system.webServer/security/authentication/windowsAuthentication /enabled:"True" /commit:apphost | Out-Null
    Write-OK "Autenticazione Anonymous e Windows abilitate sul sito IIS '$SiteName'."
}
catch {
    Write-Warn "Configurazione autenticazione IIS: $($_.Exception.Message)"
}

Write-OK "Sito IIS '$SiteName' creato con successo."
Write-Info "  Physical Path:     $InstallPath"
Write-Info "  Application Pool:  $appPoolName"
Write-Info "  Binding:           ${protocol}://*:${SitePort}${SiteHostHeader}"

# ============================================================================
# STEP 7: Permessi sul File System
# ============================================================================

Write-Step "STEP 7: Configurazione permessi file system"

# L'identità dell'app pool necessita di Read/Execute sulla cartella applicativa
# e di Write sulla cartella logs
$identityAccount = switch ($AppPoolIdentity) {
    "ApplicationPoolIdentity" { "IIS APPPOOL\$appPoolName" }
    "NetworkService"          { "NT AUTHORITY\NETWORK SERVICE" }
    "LocalSystem"             { "NT AUTHORITY\SYSTEM" }
    default                   { $AppPoolIdentity }
}

try {
    # 1. Permessi di lettura/esecuzione sulla cartella radice dell'app
    $acl = Get-Acl $InstallPath
    $readRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identityAccount,
        "ReadAndExecute",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($readRule)
    Set-Acl $InstallPath $acl
    Write-OK "Permessi ReadAndExecute concessi a '$identityAccount' su $InstallPath"

    # 2. Configurazione di MASSIMA SICUREZZA per App_Data (chiavi private, entropia DPAPI, richieste trattenute)
    # Disabilita l'ereditarieta' e rimuove regole ereditate (nessun accesso per Users, Authenticated Users, Everyone o IIS_IUSRS)
    $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ruleAppPool = New-Object System.Security.AccessControl.FileSystemAccessRule($identityAccount, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")

    $appDataSec = New-Object System.Security.AccessControl.DirectorySecurity
    $appDataSec.SetAccessRuleProtection($true, $false)
    $appDataSec.AddAccessRule($ruleSystem)
    $appDataSec.AddAccessRule($ruleAdmins)
    $appDataSec.AddAccessRule($ruleAppPool)
    Set-Acl -Path $appDataPath -AclObject $appDataSec
    Write-OK "Cartella protetta App_Data blindata (accesso esclusivo a SYSTEM, Administrators e '$identityAccount')."

    # 3. Permessi dedicati e protetti sulla cartella logs
    $logSec = New-Object System.Security.AccessControl.DirectorySecurity
    $logSec.SetAccessRuleProtection($true, $false)
    $logSec.AddAccessRule($ruleSystem)
    $logSec.AddAccessRule($ruleAdmins)
    $logSec.AddAccessRule($ruleAppPool)
    Set-Acl -Path $logPath -AclObject $logSec
    Write-OK "Cartella logs protetta: accesso ristretto a SYSTEM, Administrators e '$identityAccount'."

    # 4. Permessi di scrittura su appsettings.json (necessario per il salvataggio dalla pagina admin)
    $appSettingsPath = Join-Path $InstallPath "appsettings.json"
    if (Test-Path $appSettingsPath) {
        $aclSettings = Get-Acl $appSettingsPath
        $settingsRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identityAccount,
            "Modify",
            "None",
            "None",
            "Allow"
        )
        $aclSettings.AddAccessRule($settingsRule)
        Set-Acl $appSettingsPath $aclSettings
        Write-OK "Permessi Modify concessi a '$identityAccount' su $appSettingsPath"
    }
    else {
        Write-Warn "File $appSettingsPath non trovato, i permessi di scrittura andranno configurati manualmente."
    }
}
catch {
    Write-Warn "Errore durante la configurazione dei permessi: $($_.Exception.Message)"
    Write-Warn "Verificare manualmente che '$identityAccount' abbia accesso a $InstallPath e $appDataPath"
}

# ============================================================================
# STEP 8: Regola Firewall
# ============================================================================

if (-not $SkipFirewall) {
    Write-Step "STEP 8: Configurazione regola Windows Firewall"

    $fwRuleName = "PKI Web Enrollment Portal (Porta $SitePort)"

    $existingRule = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        Write-OK "Regola firewall '$fwRuleName' già presente."
    }
    else {
        try {
            New-NetFirewallRule -DisplayName $fwRuleName `
                -Direction Inbound `
                -Protocol TCP `
                -LocalPort $SitePort `
                -Action Allow `
                -Profile Domain,Private `
                -Description "Consente il traffico in ingresso al Portale PKI Web Enrollment (ASP.NET Core)" `
                -ErrorAction Stop | Out-Null

            Write-OK "Regola firewall creata: '$fwRuleName' (TCP $SitePort, profili Domain+Private)"
        }
        catch {
            Write-Warn "Impossibile creare la regola firewall: $($_.Exception.Message)"
            Write-Warn "Creare manualmente una regola per la porta TCP $SitePort."
        }
    }
}
else {
    Write-Info "Creazione regola firewall saltata (-SkipFirewall specificato)."
}

# ============================================================================
# STEP 9: Avvio del sito e verifica
# ============================================================================

Write-Step "STEP 9: Avvio sito e verifica"

try {
    # Avvio del pool e del sito
    Start-WebAppPool -Name $appPoolName -ErrorAction SilentlyContinue
    Start-Website -Name $SiteName -ErrorAction SilentlyContinue
    Write-OK "Sito '$SiteName' e Application Pool '$appPoolName' avviati."
}
catch {
    Write-Warn "Errore durante l'avvio: $($_.Exception.Message)"
}

# Tentativo di verifica HTTP
Start-Sleep -Seconds 2
$testUrl = "${protocol}://localhost:${SitePort}/api/config"
Write-Info "Verifica connettività: $testUrl"

try {
    $response = Invoke-RestMethod -Uri $testUrl -TimeoutSec 10 -ErrorAction Stop
    Write-OK "Il portale risponde correttamente!"
    Write-OK "  Titolo:   $($response.portalTitle)"
    Write-OK "  Modalità: $($response.portalMode)"
    Write-OK "  CA configurate: $($response.cas.Count)"
}
catch {
    Write-Warn "Il portale non risponde ancora su $testUrl"
    Write-Warn "Verificare i log in: $logPath"
    Write-Warn "Potrebbe essere necessario eseguire 'iisreset' o verificare il modulo ASP.NET Core."
}

# Verifica integrità certsrv
$defaultWs = Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
if ($defaultWs -and $defaultWs.State -eq "Started") {
    Write-OK "Sito 'Default Web Site' (certsrv) è ancora attivo e funzionante."
}

# ============================================================================
# RIEPILOGO FINALE
# ============================================================================

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "  INSTALLAZIONE COMPLETATA                                        " -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Portale PKI:     ${protocol}://localhost:${SitePort}" -ForegroundColor Cyan
if ($SiteHostHeader) {
    Write-Host "  URL Hostname:    ${protocol}://${SiteHostHeader}:${SitePort}" -ForegroundColor Cyan
}
Write-Host "  Sito IIS:        $SiteName" -ForegroundColor White
Write-Host "  App Pool:        $appPoolName" -ForegroundColor White
Write-Host "  Percorso Fisico: $InstallPath" -ForegroundColor White
Write-Host "  Log:             $logPath" -ForegroundColor White
Write-Host "  certsrv:         Non modificato [OK]" -ForegroundColor Green
Write-Host ""
Write-Host "  PROSSIMI PASSI:" -ForegroundColor Yellow
Write-Host "    1. Modificare $InstallPath\appsettings.json con le vere Sub-CA e i template" -ForegroundColor White
Write-Host "    2. Impostare UseSimulator = false per le CA reali" -ForegroundColor White
Write-Host "    3. Verificare che l'identità del pool ($identityAccount) abbia" -ForegroundColor White
Write-Host "       permessi 'Request Certificates' sui template ADCS" -ForegroundColor White
if (-not $UseHttps) {
    Write-Host '    4. Configurare un binding HTTPS con un certificato SSL valido' -ForegroundColor White
    Write-Host '       (rieseguire con -UseHttps -CertThumbprint "THUMBPRINT")' -ForegroundColor White
}
Write-Host ""

}
finally {
    if ($null -ne $prevConsoleEncoding) {
        try { [Console]::OutputEncoding = $prevConsoleEncoding } catch { }
    }
}



