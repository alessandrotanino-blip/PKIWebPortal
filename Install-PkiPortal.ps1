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
# RILEVAMENTO LINGUA / LOCALIZATION (i18n)
# ============================================================================
# Se la lingua dell'OS non è l'italiano ("it"), tutti i messaggi dello script
# sono mostrati in lingua inglese.
$script:IsItalian = $false
try {
    $uiCulture = [System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName
    $installedCulture = [System.Globalization.CultureInfo]::InstalledUICulture.TwoLetterISOLanguageName
    if ($uiCulture -eq "it" -or $installedCulture -eq "it") {
        $script:IsItalian = $true
    }
} catch {
    $script:IsItalian = $false
}

function Msg {
    param(
        [Parameter(Mandatory=$true, Position=0)][string]$It,
        [Parameter(Mandatory=$true, Position=1)][string]$En
    )
    if ($script:IsItalian) { $It } else { $En }
}

# ============================================================================
# FUNZIONI DI SUPPORTO / LOGGING
# ============================================================================

function Write-Step {
    param(
        [Parameter(Position=0)][string]$Message,
        [Parameter(Position=1)][string]$EnMessage = "",
        [Parameter(Position=2)][string]$Color = "Cyan"
    )
    $msg = if ($EnMessage -and -not $script:IsItalian) { $EnMessage } else { $Message }
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor $Color
    Write-Host "  $msg" -ForegroundColor White
    Write-Host "===============================================================" -ForegroundColor $Color
}

function Write-Info {
    param(
        [Parameter(Position=0)][string]$Message,
        [Parameter(Position=1)][string]$EnMessage = ""
    )
    $msg = if ($EnMessage -and -not $script:IsItalian) { $EnMessage } else { $Message }
    Write-Host "  [INFO] $msg" -ForegroundColor Gray
}

function Write-OK {
    param(
        [Parameter(Position=0)][string]$Message,
        [Parameter(Position=1)][string]$EnMessage = ""
    )
    $msg = if ($EnMessage -and -not $script:IsItalian) { $EnMessage } else { $Message }
    Write-Host "  [OK]   $msg" -ForegroundColor Green
}

function Write-Warn {
    param(
        [Parameter(Position=0)][string]$Message,
        [Parameter(Position=1)][string]$EnMessage = ""
    )
    $msg = if ($EnMessage -and -not $script:IsItalian) { $EnMessage } else { $Message }
    Write-Host "  [WARN] $msg" -ForegroundColor Yellow
}

function Write-Fail {
    param(
        [Parameter(Position=0)][string]$Message,
        [Parameter(Position=1)][string]$EnMessage = ""
    )
    $msg = if ($EnMessage -and -not $script:IsItalian) { $EnMessage } else { $Message }
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
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
                    Write-OK "Diritto 'Accesso come processo batch' (SeBatchLogonRight) assegnato a '$Account'." "'Log on as a batch job' right (SeBatchLogonRight) granted to '$Account'."
                } else {
                    Write-OK "Diritto 'Accesso come processo batch' (SeBatchLogonRight) già presente per '$Account'." "'Log on as a batch job' right (SeBatchLogonRight) already granted to '$Account'."
                }
            } else {
                $content = $content -replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSeBatchLogonRight = $accountTarget"
                [System.IO.File]::WriteAllText($tempCfg, $content, [System.Text.Encoding]::Unicode)
                secedit /configure /db $tempDb /cfg $tempCfg /areas USER_RIGHTS | Out-Null
                Write-OK "Diritto 'Accesso come processo batch' (SeBatchLogonRight) assegnato a '$Account'." "'Log on as a batch job' right (SeBatchLogonRight) granted to '$Account'."
            }
        }
    } catch {
        Write-Warn "Verifica SeBatchLogonRight: $($_.Exception.Message)" "SeBatchLogonRight check: $($_.Exception.Message)"
        Write-Info "Se l'Application Pool non dovesse avviarsi (errore WAS 5021), verificare nei Criteri Locali (secpol.msc)" "If Application Pool fails to start (WAS 5021 error), check Local Security Policy (secpol.msc)"
        Write-Info "che l'account '$Account' abbia il diritto 'Accesso come processo batch'." "that account '$Account' is granted 'Log on as a batch job' right."
    } finally {
        Remove-Item $tempCfg, $tempDb -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# STEP 0: Verifica privilegi di amministratore
# ============================================================================

if (-not (Test-IsAdmin)) {
    Write-Fail "Questo script deve essere eseguito come Amministratore." "This script must be run as Administrator."
    Write-Fail "Fare clic destro su PowerShell -> 'Esegui come amministratore', quindi rieseguire lo script." "Right-click PowerShell -> 'Run as administrator', then rerun the script."
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
if ($script:IsItalian) {
    Write-Host "  INSTALLAZIONE PORTALE PKI WEB ENROLLMENT (AD CS Modern) v2.0.11 " -ForegroundColor White
    Write-Host "  Installazione a fianco di Microsoft certsrv (non intrusiva)     " -ForegroundColor Gray
} else {
    Write-Host "  PKI WEB ENROLLMENT PORTAL INSTALLATION (AD CS Modern) v2.0.11   " -ForegroundColor White
    Write-Host "  Side-by-side with Microsoft certsrv (non-intrusive)             " -ForegroundColor Gray
}
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Info "Nome Sito IIS:          $SiteName" "IIS Site Name:         $SiteName"
Write-Info "Porta:                  $SitePort" "Port:                  $SitePort"
Write-Info "Host Header:            $(if ($SiteHostHeader) { $SiteHostHeader } else { (Msg '(tutti)' '(all)') })" "Host Header:            $(if ($SiteHostHeader) { $SiteHostHeader } else { (Msg '(tutti)' '(all)') })"
Write-Info "Percorso Installazione: $InstallPath" "Install Path:          $InstallPath"
Write-Info "App Pool Identity:      $AppPoolIdentity $(if ($isAccountGMSA) { (Msg '(gMSA - Group Managed Service Account)' '(gMSA - Group Managed Service Account)') })" "App Pool Identity:      $AppPoolIdentity $(if ($isAccountGMSA) { (Msg '(gMSA - Group Managed Service Account)' '(gMSA - Group Managed Service Account)') })"
Write-Info "Protocollo:             $(if ($UseHttps) { 'HTTPS' } else { 'HTTP' })" "Protocol:              $(if ($UseHttps) { 'HTTPS' } else { 'HTTP' })"
Write-Info "Sorgente Progetto:      $SourcePath" "Project Source:        $SourcePath"
Write-Host ""

# ============================================================================
# STEP 1: Verifica e Installazione Feature IIS Necessarie
# ============================================================================

Write-Step "STEP 1: Verifica prerequisiti IIS (senza modificare certsrv)" "STEP 1: Verifying IIS prerequisites (without modifying certsrv)"

# Elenco delle feature IIS necessarie per ASP.NET Core hosting.
# NON includiamo Web-Cert-Auth o Web-Windows-Auth per non interferire con certsrv.
# Includiamo solo i moduli di base necessari per l'hosting di un sito ASP.NET Core.
$requiredFeatures = @(
    @{ Name = "Web-Server";             Desc = "Ruolo Web Server (IIS)";       DescEn = "Web Server Role (IIS)" },
    @{ Name = "Web-Common-Http";        Desc = "Funzionalità HTTP comuni";     DescEn = "Common HTTP Features" },
    @{ Name = "Web-Default-Doc";        Desc = "Documenti predefiniti";         DescEn = "Default Document" },
    @{ Name = "Web-Static-Content";     Desc = "Contenuto statico";            DescEn = "Static Content" },
    @{ Name = "Web-Http-Errors";        Desc = "Errori HTTP personalizzati";   DescEn = "Custom HTTP Errors" },
    @{ Name = "Web-Http-Logging";       Desc = "Logging HTTP";                 DescEn = "HTTP Logging" },
    @{ Name = "Web-Request-Monitor";    Desc = "Monitor richieste";            DescEn = "Request Monitor" },
    @{ Name = "Web-Filtering";          Desc = "Filtro richieste";             DescEn = "Request Filtering" },
    @{ Name = "Web-Stat-Compression";   Desc = "Compressione statica";         DescEn = "Static Content Compression" },
    @{ Name = "Web-Dyn-Compression";    Desc = "Compressione dinamica";        DescEn = "Dynamic Content Compression" },
    @{ Name = "Web-Mgmt-Console";       Desc = "Console di gestione IIS";      DescEn = "IIS Management Console" }
)

$installedFeatures = 0
$alreadyInstalled = 0

foreach ($feature in $requiredFeatures) {
    $fDesc = if ($script:IsItalian) { $feature.Desc } else { $feature.DescEn }
    $state = Get-WindowsFeature -Name $feature.Name -ErrorAction SilentlyContinue
    if ($null -eq $state) {
        Write-Warn "$fDesc ($($feature.Name)) - Feature non trovata su questo sistema (possibile edizione senza Server Manager)" "$fDesc ($($feature.Name)) - Feature not found on this system (possible non-Server Manager edition)"
        continue
    }

    if ($state.Installed) {
        Write-OK "$fDesc - già installata" "$fDesc - already installed"
        $alreadyInstalled++
    }
    else {
        Write-Info "Installazione in corso: $fDesc ($($feature.Name))..." "Installing: $fDesc ($($feature.Name))..."
        try {
            Install-WindowsFeature -Name $feature.Name -IncludeManagementTools -ErrorAction Stop | Out-Null
            Write-OK "$fDesc - installata con successo" "$fDesc - installed successfully"
            $installedFeatures++
        }
        catch {
            Write-Warn "Impossibile installare $($feature.Name): $($_.Exception.Message)" "Unable to install $($feature.Name): $($_.Exception.Message)"
        }
    }
}

Write-Info "Feature già presenti: $alreadyInstalled, Nuove installate: $installedFeatures" "Features already present: $alreadyInstalled, Newly installed: $installedFeatures"

# Importa modulo WebAdministration (necessario per gestione siti IIS via PowerShell)
Import-Module WebAdministration -ErrorAction SilentlyContinue
if (-not (Get-Module WebAdministration -ErrorAction SilentlyContinue)) {
    Write-Warn "Il modulo PowerShell 'WebAdministration' non è disponibile. Tentativo con IISAdministration..." "PowerShell module 'WebAdministration' is not available. Trying IISAdministration..."
    Import-Module IISAdministration -ErrorAction SilentlyContinue
}

# ============================================================================
# STEP 2: Verifica e Installazione .NET 8 ASP.NET Core Hosting Bundle
# ============================================================================

Write-Step "STEP 2: Verifica .NET 8 ASP.NET Core Hosting Bundle" "STEP 2: Verifying .NET 8 ASP.NET Core Hosting Bundle"

$aspnetModuleInstalled = $false

# Verifica se il modulo ASP.NET Core è registrato in IIS
$aspnetModule = Get-WebGlobalModule -Name "AspNetCoreModuleV2" -ErrorAction SilentlyContinue
if ($aspnetModule) {
    Write-OK "ASP.NET Core Module V2 è già registrato in IIS." "ASP.NET Core Module V2 is already registered in IIS."
    $aspnetModuleInstalled = $true
}

# Verifica anche la presenza del runtime .NET 8 x64
$dotnetRuntimes = & "C:\Program Files\dotnet\dotnet.exe" --list-runtimes 2>&1 | Select-String "Microsoft.AspNetCore.App 8\."
if ($dotnetRuntimes) {
    Write-OK "Runtime ASP.NET Core 8.x trovato: $($dotnetRuntimes -join ', ')" "ASP.NET Core 8.x runtime found: $($dotnetRuntimes -join ', ')"
}
else {
    Write-Warn "Runtime ASP.NET Core 8.x non trovato." "ASP.NET Core 8.x runtime not found."
}

if (-not $aspnetModuleInstalled) {
    Write-Info "Il modulo ASP.NET Core non è registrato in IIS." "ASP.NET Core Module is not registered in IIS."
    Write-Info "È necessario installare il '.NET 8 Hosting Bundle' da:" "The '.NET 8 Hosting Bundle' must be installed from:"
    Write-Host ""
    Write-Host "  https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
    Write-Host ""
    Write-Info "Scaricando l'installer automaticamente..." "Downloading installer automatically..."

    $hostingBundleUrl = "https://download.visualstudio.microsoft.com/download/pr/hosting-bundle-8.0-latest-win-x64.exe"
    $hostingBundlePath = Join-Path $env:TEMP "dotnet-hosting-8.0-win.exe"

    try {
        # Tentativo di download (potrebbe non funzionare in ambienti airgapped)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/8.0.0/dotnet-hosting-8.0.0-win.exe" `
            -OutFile $hostingBundlePath -UseBasicParsing -ErrorAction Stop

        Write-Info "Download completato. Avvio installazione silenziosa..." "Download complete. Starting silent installation..."
        $process = Start-Process -FilePath $hostingBundlePath -ArgumentList "/install", "/quiet", "/norestart" `
            -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -eq 0) {
            Write-OK "Hosting Bundle .NET 8 installato con successo." ".NET 8 Hosting Bundle installed successfully."
            Write-Warn "Potrebbe essere necessario riavviare IIS dopo l'installazione (iisreset)." "An IIS restart (iisreset) may be required after installation."
        }
        else {
            Write-Warn "L'installer è terminato con codice: $($process.ExitCode)" "Installer exited with code: $($process.ExitCode)"
        }
    }
    catch {
        Write-Warn "Download automatico fallito: $($_.Exception.Message)" "Automatic download failed: $($_.Exception.Message)"
        Write-Host ""
        if ($script:IsItalian) {
            Write-Host "  AZIONE RICHIESTA: Scaricare manualmente il .NET 8 Hosting Bundle da:" -ForegroundColor Red
            Write-Host "  https://dotnet.microsoft.com/download/dotnet/8.0 -> Hosting Bundle (Windows)" -ForegroundColor Yellow
            Write-Host "  Installarlo ed eseguire nuovamente questo script." -ForegroundColor Red
        } else {
            Write-Host "  ACTION REQUIRED: Manually download .NET 8 Hosting Bundle from:" -ForegroundColor Red
            Write-Host "  https://dotnet.microsoft.com/download/dotnet/8.0 -> Hosting Bundle (Windows)" -ForegroundColor Yellow
            Write-Host "  Install it and rerun this script." -ForegroundColor Red
        }
        Write-Host ""

        $continueChoice = Read-Host (Msg "Continuare comunque? (S/N)" "Continue anyway? (Y/N)")
        if ($continueChoice -notmatch '^[sSyY]$') {
            Write-Fail "Installazione interrotta." "Installation aborted."
            exit 1
        }
    }
}

# ============================================================================
# STEP 3: Verifica che certsrv non venga toccato
# ============================================================================

Write-Step "STEP 3: Verifica integrità sito certsrv (Microsoft Web Enrollment)" "STEP 3: Verifying certsrv site integrity (Microsoft Web Enrollment)"

$defaultWebSite = Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
if ($defaultWebSite) {
    Write-OK "Sito 'Default Web Site' trovato (stato: $($defaultWebSite.State))" "'Default Web Site' found (state: $($defaultWebSite.State))"

    $certsrvApp = Get-WebApplication -Site "Default Web Site" -Name "CertSrv" -ErrorAction SilentlyContinue
    if ($certsrvApp) {
        Write-OK "Applicazione certsrv trovata sotto Default Web Site: $($certsrvApp.PhysicalPath)" "certsrv application found under Default Web Site: $($certsrvApp.PhysicalPath)"
        Write-Info "certsrv NON verrà modificato. Il portale PKI verrà installato come sito IIS SEPARATO." "certsrv will NOT be modified. PKI Portal will be installed as a SEPARATE IIS site."
    }
    else {
        Write-Info "Applicazione certsrv non trovata sotto Default Web Site (potrebbe essere già rimossa o non installata)." "certsrv application not found under Default Web Site (may already be removed or not installed)."
    }
}
else {
    Write-Info "'Default Web Site' non trovato. Procedendo con la creazione del nuovo sito." "'Default Web Site' not found. Proceeding with new site creation."
}

# Verifica che il nome del sito non esista già
$existingSite = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
if ($existingSite) {
    Write-Warn "Il sito '$SiteName' esiste già in IIS." "Site '$SiteName' already exists in IIS."
    $overwrite = Read-Host (Msg "  Sovrascrivere la configurazione del sito esistente? (S/N)" "  Overwrite existing site configuration? (Y/N)")
    if ($overwrite -notmatch '^[sSyY]$') {
        Write-Fail "Installazione interrotta dall'utente." "Installation aborted by user."
        exit 1
    }
    Write-Info "Rimozione del sito IIS esistente '$SiteName'..." "Removing existing IIS site '$SiteName'..."
    Remove-Website -Name $SiteName -ErrorAction SilentlyContinue
}

# Verifica che la porta non sia in uso da un altro sito (eccetto Default Web Site su 80/443)
$portInUse = Get-WebBinding | Where-Object {
    $_.bindingInformation -match ":${SitePort}:" -and
    (Get-Website | Where-Object { $_.Name -ne $SiteName -and $_.Bindings.Collection.bindingInformation -contains $_.bindingInformation })
}
if ($portInUse) {
    Write-Warn "La porta $SitePort potrebbe essere già in uso da un altro sito IIS." "Port $SitePort may already be in use by another IIS site."
    Write-Warn "Valutare una porta diversa con il parametro -SitePort." "Consider using a different port with the -SitePort parameter."
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
        $offlineMsg = Msg "Aggiornamento Portale PKI in corso..." "PKI Portal update in progress..."
        Set-Content -Path $appOfflineFile -Value "<html><body><h3>$offlineMsg</h3></body></html>" -Force -ErrorAction SilentlyContinue
    } catch { }
}

$existingSite = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
$appPoolExists = Test-Path "IIS:\AppPools\$appPoolName"
$existingAppPool = if ($appPoolExists) { Get-WebAppPoolState -Name $appPoolName -ErrorAction SilentlyContinue } else { $null }

if ($existingSite -or $existingAppPool -or (Test-Path $InstallPath)) {
    Write-Step "STEP 3b: Arresto sito e App Pool esistenti per aggiornamento" "STEP 3b: Stopping existing site and App Pool for update"

    # Arresta il sito
    if ($existingSite -and $existingSite.State -eq 'Started') {
        try {
            Stop-Website -Name $SiteName -ErrorAction Stop
            Write-OK "Sito '$SiteName' arrestato." "Site '$SiteName' stopped."
        }
        catch {
            Write-Warn "Impossibile arrestare il sito '$SiteName' via PowerShell. Tentativo con appcmd..." "Unable to stop site '$SiteName' via PowerShell. Trying appcmd..."
            if (Test-Path $appcmd) { & $appcmd stop site /site.name:"$SiteName" 2>$null }
        }
    }
    elseif ($existingSite) {
        Write-Info "Sito '$SiteName' già in stato '$($existingSite.State)'." "Site '$SiteName' already in '$($existingSite.State)' state."
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
        if (-not (Test-Path "IIS:\AppPools\$appPoolName")) { break }
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
            Write-Warn "Worker process w3wp.exe (PID $($proc.ProcessId)) ancora attivo. Terminazione forzata..." "Worker process w3wp.exe (PID $($proc.ProcessId)) still active. Forcing termination..."
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        }
    } catch { }

    Write-OK "Sito e Application Pool pronti per l'aggiornamento dei file." "Site and Application Pool ready for file updates."
}
else {
    Write-Info "Nessun sito/pool '$SiteName' esistente da arrestare (prima installazione)." "No existing site/pool '$SiteName' to stop (initial installation)."
}

# ============================================================================
# STEP 4: Compilazione e Pubblicazione dell'applicazione
# ============================================================================

Write-Step "STEP 4: Compilazione e pubblicazione applicazione ASP.NET Core" "STEP 4: Building and publishing ASP.NET Core application"

if ($SkipDotnetPublish) {
    Write-Info "Fase di pubblicazione saltata (-SkipDotnetPublish specificato)." "Publish stage skipped (-SkipDotnetPublish specified)."
    Write-Info "I file applicativi devono già essere presenti in: $InstallPath" "Application files must already be present in: $InstallPath"
}
else {
    # Individua il dotnet CLI (x64)
    $dotnetExe = "C:\Program Files\dotnet\dotnet.exe"
    if (-not (Test-Path $dotnetExe)) {
        $dotnetExe = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
    }
    if (-not $dotnetExe -or -not (Test-Path $dotnetExe)) {
        Write-Fail "Impossibile trovare dotnet.exe. Installare .NET 8 SDK o Hosting Bundle." "Unable to find dotnet.exe. Install .NET 8 SDK or Hosting Bundle."
        exit 1
    }
    Write-Info "CLI .NET trovato: $dotnetExe" ".NET CLI found: $dotnetExe"

    # Verifica che il progetto esista nel percorso sorgente
    $csprojPath = Join-Path $SourcePath "PkiPortal.csproj"
    if (-not (Test-Path $csprojPath)) {
        Write-Fail "File di progetto non trovato: $csprojPath" "Project file not found: $csprojPath"
        Write-Fail "Specificare il percorso corretto con il parametro -SourcePath." "Specify the correct path using -SourcePath parameter."
        exit 1
    }
    Write-OK "File di progetto trovato: $csprojPath" "Project file found: $csprojPath"

    # Creazione cartella di destinazione
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        Write-OK "Cartella di installazione creata: $InstallPath" "Installation directory created: $InstallPath"
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
            Write-Info "Backup di sicurezza di appsettings.json esistente: $backupSettingsPath" "Safety backup of existing appsettings.json: $backupSettingsPath"
        }
        if (Test-Path $destWebConfig) {
            $backupWebConfigPath = Join-Path ([System.IO.Path]::GetTempPath()) "pki_backup_webconfig_$([Guid]::NewGuid().ToString('N')).xml"
            Copy-Item -Path $destWebConfig -Destination $backupWebConfigPath -Force
            Write-Info "Backup di sicurezza di web.config esistente: $backupWebConfigPath" "Safety backup of existing web.config: $backupWebConfigPath"
        }
    }

    # Pubblicazione
    Write-Info 'Pubblicazione in corso (Release - non self-contained)...' 'Publishing in progress (Release - non-self-contained)...'
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
        Write-Fail "Errore durante la pubblicazione (codice di uscita: $publishExitCode):" "Publish error (exit code: $publishExitCode):"
        $publishOutput | Where-Object { $_ -and $_.Trim() } | ForEach-Object {
            Write-Host "    $_" -ForegroundColor Red
        }

        # Errori di restore NuGet (pacchetti non risolvibili / sorgente non raggiungibile)
        if (($publishOutput -join "`n") -match 'NU1100|NU1101|NU1102|NU1301') {
            Write-Host ""
            Write-Warn "Il restore NuGet non riesce a ottenere i pacchetti richiesti (targeting pack / apphost .NET)." "NuGet restore cannot acquire required packages (targeting pack / apphost .NET)."
            Write-Info "Causa probabile: l'SDK installato è più recente del framework di destinazione del progetto" "Probable cause: installed SDK is newer than project target framework"
            Write-Info "e deve scaricare i pack da NuGet, ma nessuna sorgente NuGet è raggiungibile o configurata." "and requires downloading packs from NuGet, but no NuGet source is reachable."
            if ($script:IsItalian) {
                Write-Info "Soluzioni possibili:"
                Write-Info "  1. Verificare le sorgenti con 'dotnet nuget list source' e abilitare nuget.org se manca."
                Write-Info "  2. Server isolato da Internet: compilare (dotnet publish) su un PC con accesso a NuGet,"
                Write-Info "     copiare l'output in $InstallPath e rieseguire lo script con -SkipDotnetPublish."
                Write-Info "  3. Server isolato: copiare in una cartella i .nupkg indicati nell'errore (stessa versione)"
                Write-Info "     e rieseguire con -NuGetSource <cartella>. Servono: Microsoft.NETCore.App.Ref,"
                Write-Info "     Microsoft.AspNetCore.App.Ref, Microsoft.NETCore.App.Host.win-x64."
                Write-Info "  4. In alternativa, impostare <TargetFramework>net10.0</TargetFramework> nel .csproj"
                Write-Info "     (i pack .NET 10 sono inclusi nell'SDK 10) e installare l'Hosting Bundle .NET 10."
            } else {
                Write-Info "Possible solutions:"
                Write-Info "  1. Check sources via 'dotnet nuget list source' and enable nuget.org if missing."
                Write-Info "  2. Air-gapped server: build (dotnet publish) on a machine with internet access,"
                Write-Info "     copy output to $InstallPath and rerun with -SkipDotnetPublish."
                Write-Info "  3. Air-gapped server: place required .nupkg packages in a folder"
                Write-Info "     and rerun with -NuGetSource <folder>."
                Write-Info "  4. Alternatively update target framework or install matching Hosting Bundle."
            }
        }
        exit 1
    }

    Write-OK "Applicazione pubblicata con successo in: $InstallPath" "Application published successfully to: $InstallPath"

    # Gestione appsettings.json
    $customSettings = Join-Path $SourcePath "appsettings.json"
    if ($backupSettingsPath -and (Test-Path $backupSettingsPath)) {
        Copy-Item -Path $backupSettingsPath -Destination $destSettings -Force
        Remove-Item -Path $backupSettingsPath -Force -ErrorAction SilentlyContinue
        Write-OK "File appsettings.json di produzione ESISTENTE PRESERVATO (non sovrascritto). Usare -OverwriteConfig per sovrascriverlo." "Existing production appsettings.json PRESERVED (not overwritten). Use -OverwriteConfig to overwrite."
    }
    elseif ($OverwriteConfig -and (Test-Path $customSettings)) {
        Copy-Item -Path $customSettings -Destination $destSettings -Force
        Write-OK "File di configurazione appsettings.json sovrascritto dal sorgente (-OverwriteConfig specificato)." "Configuration file appsettings.json overwritten from source (-OverwriteConfig specified)."
    }
    elseif (-not (Test-Path $destSettings) -and (Test-Path $customSettings)) {
        Copy-Item -Path $customSettings -Destination $destSettings -Force
        Write-OK "File di configurazione appsettings.json copiato (prima installazione)." "Configuration file appsettings.json copied (initial installation)."
    }

    # Gestione web.config
    $customWebConfig = Join-Path $SourcePath "web.config"
    if ($backupWebConfigPath -and (Test-Path $backupWebConfigPath)) {
        Copy-Item -Path $backupWebConfigPath -Destination $destWebConfig -Force
        Remove-Item -Path $backupWebConfigPath -Force -ErrorAction SilentlyContinue
        Write-OK "File web.config ESISTENTE PRESERVATO (non sovrascritto). Usare -OverwriteConfig per sovrascriverlo." "Existing web.config PRESERVED (not overwritten). Use -OverwriteConfig to overwrite."
    }
    elseif ($OverwriteConfig -and (Test-Path $customWebConfig)) {
        Copy-Item -Path $customWebConfig -Destination $destWebConfig -Force
        Write-OK "File web.config sovrascritto dal sorgente (-OverwriteConfig specificato)." "File web.config overwritten from source (-OverwriteConfig specified)."
    }
    elseif (-not (Test-Path $destWebConfig) -and (Test-Path $customWebConfig)) {
        Copy-Item -Path $customWebConfig -Destination $destWebConfig -Force
        Write-OK "File web.config copiato (prima installazione)." "File web.config copied (initial installation)."
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
    Write-OK "Cartella log creata: $logPath" "Log folder created: $logPath"
}

# Creazione cartella protetta App_Data per custodia sicura di chiavi, held-requests ed entropia
$appDataPath = Join-Path $InstallPath "App_Data"
if (-not (Test-Path $appDataPath)) {
    New-Item -ItemType Directory -Path $appDataPath -Force | Out-Null
    Write-OK "Cartella sicura App_Data creata: $appDataPath" "Secure App_Data folder created: $appDataPath"
}
$appDataTempPath = Join-Path $appDataPath "Temp"
if (-not (Test-Path $appDataTempPath)) {
    New-Item -ItemType Directory -Path $appDataTempPath -Force | Out-Null
    Write-OK "Cartella temporanea sicura creata: $appDataTempPath" "Secure temporary folder created: $appDataTempPath"
}

# Migrazione file sensibili legacy da root di installazione verso App_Data
$legacyHeld = Join-Path $InstallPath "held-requests.json"
$targetHeld = Join-Path $appDataPath "held-requests.json"
if ((Test-Path $legacyHeld) -and -not (Test-Path $targetHeld)) {
    Move-Item -Path $legacyHeld -Destination $targetHeld -Force
    Write-Info "Spostato held-requests.json legacy nella cartella protetta App_Data" "Moved legacy held-requests.json into secure App_Data folder"
}

$legacyEntropy = Join-Path $InstallPath "store-entropy.bin"
$targetEntropy = Join-Path $appDataPath "store-entropy.bin"
if ((Test-Path $legacyEntropy) -and -not (Test-Path $targetEntropy)) {
    Move-Item -Path $legacyEntropy -Destination $targetEntropy -Force
    Write-Info "Spostato store-entropy.bin legacy nella cartella protetta App_Data" "Moved legacy store-entropy.bin into secure App_Data folder"
}

# ============================================================================
# STEP 5: Creazione Application Pool dedicato
# ============================================================================

Write-Step "STEP 5: Creazione Application Pool IIS dedicato" "STEP 5: Creating dedicated IIS Application Pool"

$appPoolName = "${SiteName}_Pool"
$appcmd = "$env:SystemRoot\system32\inetsrv\appcmd.exe"

$existingPool = & $appcmd list apppool /name:"$appPoolName"
if (-not $existingPool) {
    Write-Info "Creazione Application Pool: $appPoolName" "Creating Application Pool: $appPoolName"
    & $appcmd add apppool /name:"$appPoolName" | Out-Null
    Write-OK "Application Pool '$appPoolName' creato." "Application Pool '$appPoolName' created."
}
else {
    Write-OK "Application Pool '$appPoolName' gia' esistente." "Application Pool '$appPoolName' already exists."
}

# Configurazione pool
& $appcmd set apppool /apppool.name:"$appPoolName" /managedRuntimeVersion:"" /enable32BitAppOnWin64:false /startMode:AlwaysRunning /processModel.idleTimeout:00:00:00 | Out-Null

# Configurazione identita
if ($AppPoolIdentity -eq "ApplicationPoolIdentity") {
    & $appcmd set apppool /apppool.name:"$appPoolName" /processModel.identityType:ApplicationPoolIdentity | Out-Null
    Write-OK "Identita pool: ApplicationPoolIdentity (predefinita)" "Pool identity: ApplicationPoolIdentity (default)"
}
elseif ($AppPoolIdentity -eq "NetworkService") {
    & $appcmd set apppool /apppool.name:"$appPoolName" /processModel.identityType:NetworkService | Out-Null
    Write-OK "Identita pool: NetworkService" "Pool identity: NetworkService"
}
elseif ($AppPoolIdentity -eq "LocalSystem") {
    & $appcmd set apppool /apppool.name:"$appPoolName" /processModel.identityType:LocalSystem | Out-Null
    Write-OK "Identita pool: LocalSystem" "Pool identity: LocalSystem"
}
elseif ($isAccountGMSA) {
    Write-Info "Configurazione identita pool come gMSA: $AppPoolIdentity (senza password)" "Configuring pool identity as gMSA: $AppPoolIdentity (without password)"
    & $appcmd set config /section:applicationPools "/[name='$appPoolName'].processModel.identityType:SpecificUser" "/[name='$appPoolName'].processModel.userName:$AppPoolIdentity" "/[name='$appPoolName'].processModel.password:" /commit:apphost | Out-Null

    # Assegnazione / verifica del diritto 'Accesso come processo batch' (SeBatchLogonRight) necessario a WAS/IIS
    Grant-BatchLogonRight -Account $AppPoolIdentity

    # Verifica autorizzazione gMSA sul server locale se il modulo ActiveDirectory è presente
    if (Get-Command Test-ADServiceAccount -ErrorAction SilentlyContinue) {
        $samName = if ($AppPoolIdentity -match '^[^\\]+\\(.+)$') { $matches[1] } else { $AppPoolIdentity }
        try {
            $testRes = Test-ADServiceAccount -Identity $samName -ErrorAction SilentlyContinue
            if ($testRes -eq $true) {
                Write-OK "Verifica gMSA: questo server è autorizzato a utilizzare l'account '$AppPoolIdentity'." "gMSA check: this server is authorized to use account '$AppPoolIdentity'."
            } elseif ($testRes -eq $false) {
                Write-Warn "Verifica gMSA: 'Test-ADServiceAccount -Identity $samName' ha restituito False." "gMSA check: 'Test-ADServiceAccount -Identity $samName' returned False."
                Write-Info "Se l'Application Pool non dovesse avviarsi, verificare in Active Directory che questo server sia" "If Application Pool fails to start, verify in Active Directory that this server is"
                Write-Info "membro del gruppo autorizzato (PrincipalsAllowedToRetrieveManagedPassword) e lanciare:" "member of authorized group (PrincipalsAllowedToRetrieveManagedPassword) and run:"
                Write-Info "Install-ADServiceAccount -Identity $samName" "Install-ADServiceAccount -Identity $samName"
            }
        } catch { }
    }

    Write-OK "Identità pool: $AppPoolIdentity (gMSA)" "Pool identity: $AppPoolIdentity (gMSA)"
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
    Write-OK "Identità pool: $AppPoolIdentity (account utente di dominio)" "Pool identity: $AppPoolIdentity (domain user account)"
}

Write-Info "Pool configurato: startMode=AlwaysRunning, idleTimeout=0, 64-bit, No Managed Runtime." "Pool configured: startMode=AlwaysRunning, idleTimeout=0, 64-bit, No Managed Runtime."

# ============================================================================
# STEP 6: Creazione Sito IIS
# ============================================================================

Write-Step "STEP 6: Creazione Sito IIS '$SiteName' (porta $SitePort)" "STEP 6: Creating IIS Site '$SiteName' (port $SitePort)"

$protocol = if ($UseHttps) { "https" } else { "http" }
$bindingInfo = "*:${SitePort}:${SiteHostHeader}"

Write-Info "Binding: $protocol su $bindingInfo" "Binding: $protocol on $bindingInfo"

if ($UseHttps) {
    if ([string]::IsNullOrWhiteSpace($CertThumbprint)) {
        Write-Warn "Binding HTTPS richiesto ma nessun -CertThumbprint specificato." "HTTPS binding requested but no -CertThumbprint specified."
        Write-Info "Ricerca di un certificato valido nello store locale..." "Searching for a valid certificate in local machine store..."

        # Tentativo di trovare un certificato con il nome server
        $serverCerts = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey } |
            Sort-Object NotAfter -Descending

        if ($serverCerts.Count -gt 0) {
            $CertThumbprint = $serverCerts[0].Thumbprint
            Write-Info "Trovato certificato: $($serverCerts[0].Subject) (Thumbprint: $CertThumbprint)" "Found certificate: $($serverCerts[0].Subject) (Thumbprint: $CertThumbprint)"
            $useCert = Read-Host (Msg "  Utilizzare questo certificato? (S/N)" "  Use this certificate? (Y/N)")
            if ($useCert -notmatch '^[sSyY]$') {
                Write-Fail "Specificare un thumbprint con -CertThumbprint oppure usare -UseHttps:`$false" "Specify a thumbprint with -CertThumbprint or use -UseHttps:`$false"
                exit 1
            }
        }
        else {
            Write-Fail "Nessun certificato SSL trovato nello store LocalMachine\My." "No SSL certificates found in LocalMachine\My store."
            Write-Fail "Installare un certificato SSL e specificare il thumbprint con -CertThumbprint." "Install an SSL certificate and specify its thumbprint using -CertThumbprint."
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
        Write-OK "Certificato SSL associato al binding HTTPS (Thumbprint: $CertThumbprint)" "SSL certificate bound to HTTPS binding (Thumbprint: $CertThumbprint)"
    }
}
else {
    # SECURITY: HTTP in chiaro + Windows Authentication
    Write-Host "" -ForegroundColor Red
    if ($script:IsItalian) {
        Write-Host "  [ATTENZIONE] Stai per installare il portale su HTTP IN CHIARO con Windows Authentication." -ForegroundColor Red
        Write-Host "  NTLM viaggia in chiaro sulla rete: rischio capture degli hash e NTLM relay." -ForegroundColor Red
        Write-Host "  In produzione usare: -UseHttps -CertThumbprint <thumbprint> (e abilitare EPAL/EAAL)." -ForegroundColor Red
    } else {
        Write-Host "  [WARNING] You are installing the portal over UNENCRYPTED HTTP with Windows Authentication." -ForegroundColor Red
        Write-Host "  NTLM travels in cleartext across the network: risk of hash capture and NTLM relay." -ForegroundColor Red
        Write-Host "  In production use: -UseHttps -CertThumbprint <thumbprint> (and enable EPAL/EAAL)." -ForegroundColor Red
    }
    $httpConfirm = Read-Host (Msg "  Continuare comunque con HTTP in chiaro? (s/N)" "  Continue anyway with unencrypted HTTP? (y/N)")
    if ($httpConfirm -ne 's' -and $httpConfirm -ne 'S' -and $httpConfirm -ne 'y' -and $httpConfirm -ne 'Y') {
        Write-Fail "Installazione interrotta: HTTP in chiaro non confermato. Ripetere con -UseHttps -CertThumbprint <thumbprint>." "Installation aborted: unencrypted HTTP not confirmed. Rerun with -UseHttps -CertThumbprint <thumbprint>."
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

# Configurazione autenticazione a livello di sito IIS
try {
    & $appCmd set config "$SiteName" -section:system.webServer/security/authentication/anonymousAuthentication /enabled:"True" /commit:apphost | Out-Null
    & $appCmd set config "$SiteName" -section:system.webServer/security/authentication/windowsAuthentication /enabled:"True" /commit:apphost | Out-Null
    Write-OK "Autenticazione Anonymous e Windows abilitate sul sito IIS '$SiteName'." "Anonymous and Windows authentication enabled on IIS site '$SiteName'."
}
catch {
    Write-Warn "Configurazione autenticazione IIS: $($_.Exception.Message)" "IIS authentication configuration: $($_.Exception.Message)"
}

Write-OK "Sito IIS '$SiteName' creato con successo." "IIS site '$SiteName' created successfully."
Write-Info "  Physical Path:     $InstallPath" "  Physical Path:     $InstallPath"
Write-Info "  Application Pool:  $appPoolName" "  Application Pool:  $appPoolName"
Write-Info "  Binding:           ${protocol}://*:${SitePort}${SiteHostHeader}" "  Binding:           ${protocol}://*:${SitePort}${SiteHostHeader}"

# ============================================================================
# STEP 7: Permessi sul File System
# ============================================================================

Write-Step "STEP 7: Configurazione permessi file system" "STEP 7: Configuring file system permissions"

# L'identità dell'app pool necessita di FullControl sulla cartella applicativa
# e di accesso esclusivo (senza ereditarietà) su App_Data e logs
$identityAccount = switch ($AppPoolIdentity) {
    "ApplicationPoolIdentity" { "IIS APPPOOL\$appPoolName" }
    "NetworkService"          { "NT AUTHORITY\NETWORK SERVICE" }
    "LocalSystem"             { "NT AUTHORITY\SYSTEM" }
    default                   { $AppPoolIdentity }
}

try {
    # 1. Permessi FullControl sulla cartella radice dell'app per l'identità del pool
    $acl = Get-Acl $InstallPath
    $fullControlRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identityAccount,
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($fullControlRule)
    Set-Acl $InstallPath $acl
    Write-OK "Permessi FullControl concessi a '$identityAccount' su $InstallPath" "FullControl permissions granted to '$identityAccount' on $InstallPath"

    # 2. Configurazione di MASSIMA SICUREZZA per App_Data
    $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ruleAppPool = New-Object System.Security.AccessControl.FileSystemAccessRule($identityAccount, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")

    $appDataSec = New-Object System.Security.AccessControl.DirectorySecurity
    $appDataSec.SetAccessRuleProtection($true, $false)
    $appDataSec.AddAccessRule($ruleSystem)
    $appDataSec.AddAccessRule($ruleAdmins)
    $appDataSec.AddAccessRule($ruleAppPool)
    Set-Acl -Path $appDataPath -AclObject $appDataSec
    Write-OK "Cartella protetta App_Data blindata (accesso esclusivo a SYSTEM, Administrators e '$identityAccount')." "Protected App_Data folder secured (exclusive access to SYSTEM, Administrators, and '$identityAccount')."

    # 3. Permessi dedicati e protetti sulla cartella logs
    $logSec = New-Object System.Security.AccessControl.DirectorySecurity
    $logSec.SetAccessRuleProtection($true, $false)
    $logSec.AddAccessRule($ruleSystem)
    $logSec.AddAccessRule($ruleAdmins)
    $logSec.AddAccessRule($ruleAppPool)
    Set-Acl -Path $logPath -AclObject $logSec
    Write-OK "Cartella logs protetta: accesso ristretto a SYSTEM, Administrators e '$identityAccount'." "Protected logs folder secured: restricted to SYSTEM, Administrators, and '$identityAccount'."

    # 4. Se appsettings.json non esiste ma esiste appsettings.example.json, rinomina il file esempio
    $appSettingsPath = Join-Path $InstallPath "appsettings.json"
    $appSettingsExamplePath = Join-Path $InstallPath "appsettings.example.json"
    if (-not (Test-Path $appSettingsPath) -and (Test-Path $appSettingsExamplePath)) {
        Rename-Item -Path $appSettingsExamplePath -NewName "appsettings.json" -Force
        Write-OK "File appsettings.example.json rinominato in appsettings.json (prima installazione)." "File appsettings.example.json renamed to appsettings.json (initial installation)."
    }
    elseif (Test-Path $appSettingsPath) {
        Write-Info "File appsettings.json già presente, appsettings.example.json non rinominato." "File appsettings.json already present, appsettings.example.json not renamed."
    }
}
catch {
    Write-Warn "Errore durante la configurazione dei permessi: $($_.Exception.Message)" "Error configuring permissions: $($_.Exception.Message)"
    Write-Warn "Verificare manualmente che '$identityAccount' abbia accesso a $InstallPath e $appDataPath" "Manually verify '$identityAccount' has access to $InstallPath and $appDataPath"
}

# ============================================================================
# STEP 8: Regola Firewall
# ============================================================================

if (-not $SkipFirewall) {
    Write-Step "STEP 8: Configurazione regola Windows Firewall" "STEP 8: Configuring Windows Firewall rule"

    $fwRuleName = "PKI Web Enrollment Portal (Porta $SitePort)"

    $existingRule = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        Write-OK "Regola firewall '$fwRuleName' già presente." "Firewall rule '$fwRuleName' already exists."
    }
    else {
        try {
            $fwDesc = Msg "Consente il traffico in ingresso al Portale PKI Web Enrollment (ASP.NET Core)" "Allows inbound traffic to PKI Web Enrollment Portal (ASP.NET Core)"
            New-NetFirewallRule -DisplayName $fwRuleName `
                -Direction Inbound `
                -Protocol TCP `
                -LocalPort $SitePort `
                -Action Allow `
                -Profile Domain,Private `
                -Description $fwDesc `
                -ErrorAction Stop | Out-Null

            Write-OK "Regola firewall creata: '$fwRuleName' (TCP $SitePort, profili Domain+Private)" "Firewall rule created: '$fwRuleName' (TCP $SitePort, Domain+Private profiles)"
        }
        catch {
            Write-Warn "Impossibile creare la regola firewall: $($_.Exception.Message)" "Unable to create firewall rule: $($_.Exception.Message)"
            Write-Warn "Creare manualmente una regola per la porta TCP $SitePort." "Manually create a rule for TCP port $SitePort."
        }
    }
}
else {
    Write-Info "Creazione regola firewall saltata (-SkipFirewall specificato)." "Firewall rule creation skipped (-SkipFirewall specified)."
}

# ============================================================================
# STEP 9: Avvio del sito e verifica
# ============================================================================

Write-Step "STEP 9: Avvio sito e verifica" "STEP 9: Starting site and verification"

try {
    # Avvio del pool e del sito
    Start-WebAppPool -Name $appPoolName -ErrorAction SilentlyContinue
    Start-Website -Name $SiteName -ErrorAction SilentlyContinue
    Write-OK "Sito '$SiteName' e Application Pool '$appPoolName' avviati." "Site '$SiteName' and Application Pool '$appPoolName' started."
}
catch {
    Write-Warn "Errore durante l'avvio: $($_.Exception.Message)" "Startup error: $($_.Exception.Message)"
}

# Tentativo di verifica HTTP
Start-Sleep -Seconds 2
$testUrl = "${protocol}://localhost:${SitePort}/api/config"
Write-Info "Verifica connettività: $testUrl" "Verifying connectivity: $testUrl"

try {
    $response = Invoke-RestMethod -Uri $testUrl -TimeoutSec 10 -ErrorAction Stop
    Write-OK "Il portale risponde correttamente!" "Portal responded successfully!"
    Write-OK "  Titolo:   $($response.portalTitle)" "  Title:   $($response.portalTitle)"
    Write-OK "  Modalità: $($response.portalMode)" "  Mode:    $($response.portalMode)"
    Write-OK "  CA configurate: $($response.cas.Count)" "  Configured CAs: $($response.cas.Count)"
}
catch {
    Write-Warn "Il portale non risponde ancora su $testUrl" "Portal is not yet responding on $testUrl"
    Write-Warn "Verificare i log in: $logPath" "Check logs in: $logPath"
    Write-Warn "Potrebbe essere necessario eseguire 'iisreset' o verificare il modulo ASP.NET Core." "An 'iisreset' may be required, or verify ASP.NET Core module."
}

# Verifica integrità certsrv
$defaultWs = Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
if ($defaultWs -and $defaultWs.State -eq "Started") {
    Write-OK "Sito 'Default Web Site' (certsrv) è ancora attivo e funzionante." "Site 'Default Web Site' (certsrv) is still active and operational."
}

# ============================================================================
# RIEPILOGO FINALE
# ============================================================================

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Green
if ($script:IsItalian) {
    Write-Host "  INSTALLAZIONE COMPLETATA (v2.0.11)                              " -ForegroundColor White
} else {
    Write-Host "  INSTALLATION COMPLETED (v2.0.11)                                " -ForegroundColor White
}
Write-Host "==================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  $(Msg 'Portale PKI:' 'PKI Portal:')     ${protocol}://localhost:${SitePort}" -ForegroundColor Cyan
if ($SiteHostHeader) {
    Write-Host "  $(Msg 'URL Hostname:' 'Hostname URL:')    ${protocol}://${SiteHostHeader}:${SitePort}" -ForegroundColor Cyan
}
Write-Host "  $(Msg 'Sito IIS:' 'IIS Site:')        $SiteName" -ForegroundColor White
Write-Host "  $(Msg 'App Pool:' 'App Pool:')        $appPoolName" -ForegroundColor White
Write-Host "  $(Msg 'Percorso Fisico:' 'Physical Path:') $InstallPath" -ForegroundColor White
Write-Host "  $(Msg 'Log:' 'Logs:')             $logPath" -ForegroundColor White
Write-Host "  certsrv:         $(Msg 'Non modificato [OK]' 'Unmodified [OK]')" -ForegroundColor Green
Write-Host ""
if ($script:IsItalian) {
    Write-Host "  PROSSIMI PASSI:" -ForegroundColor Yellow
    Write-Host "    1. Modificare $InstallPath\appsettings.json con le vere Sub-CA e i template" -ForegroundColor White
    Write-Host "    2. Impostare UseSimulator = false per le CA reali" -ForegroundColor White
    Write-Host "    3. Verificare che l'identità del pool ($identityAccount) abbia" -ForegroundColor White
    Write-Host "       permessi 'Request Certificates' sui template ADCS" -ForegroundColor White
    if (-not $UseHttps) {
        Write-Host '    4. Configurare un binding HTTPS con un certificato SSL valido' -ForegroundColor White
        Write-Host '       (rieseguire con -UseHttps -CertThumbprint "THUMBPRINT")' -ForegroundColor White
    }
} else {
    Write-Host "  NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "    1. Configure $InstallPath\appsettings.json with real Sub-CAs and templates" -ForegroundColor White
    Write-Host "    2. Set UseSimulator = false for real CAs" -ForegroundColor White
    Write-Host "    3. Verify pool identity ($identityAccount) has" -ForegroundColor White
    Write-Host "       'Request Certificates' permissions on AD CS templates" -ForegroundColor White
    if (-not $UseHttps) {
        Write-Host '    4. Configure an HTTPS binding with a valid SSL certificate' -ForegroundColor White
        Write-Host '       (rerun with -UseHttps -CertThumbprint "THUMBPRINT")' -ForegroundColor White
    }
}
Write-Host ""

}
finally {
    if ($null -ne $prevConsoleEncoding) {
        try { [Console]::OutputEncoding = $prevConsoleEncoding } catch { }
    }
}



