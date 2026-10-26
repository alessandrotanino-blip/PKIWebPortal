<#
.SYNOPSIS
    Installation script for the PKI Web Enrollment Portal on IIS Windows Server.
    Installs the site alongside Microsoft Web Enrollment (certsrv) without modifying it.

.DESCRIPTION
    This script performs the following operations:
    1. Checks and installs the required IIS prerequisites (without touching certsrv).
    2. Downloads and installs the .NET 8 Hosting Bundle if not present.
    3. Publishes the ASP.NET Core application to the destination folder.
    4. Creates a new dedicated Application Pool with the specified identity.
    5. Creates a new, separate IIS site (with configurable port and hostname).
    6. Creates a firewall rule for the configured port.
    7. Configures the required logs and folders.

.PARAMETER SiteName
    Name of the IIS site to create (default: "PkiWebEnrollment")

.PARAMETER SitePort
    HTTP port the site will listen on (default: 8443)

.PARAMETER SiteHostHeader
    Optional host header for the site (e.g. "pki.azienda.lan"). If empty, the site responds on any hostname.

.PARAMETER InstallPath
    Physical path on the server where the application is published (default: "C:\inetpub\PkiWebEnrollment")

.PARAMETER AppPoolIdentity
    Application Pool identity. Values: "ApplicationPoolIdentity", "NetworkService", "LocalSystem",
    or a domain account in the form "DOMAIN\ServiceAccount" (with -AppPoolPassword),
    or a gMSA (Group Managed Service Account) in the form "DOMAIN\Account$" or with the -IsGMSA parameter.

.PARAMETER AppPoolPassword
    Password of the domain account (NOT required for gMSA accounts).

.PARAMETER IsGMSA
    Specifies that the AppPool identity is a gMSA (Group Managed Service Account).
    gMSAs have no password: the script will configure IIS with an empty password, verify that the name
    ends with '$' (adding it automatically if omitted) and grant the SeBatchLogonRight right.

.PARAMETER UseHttps
    If specified, configures the HTTPS binding on the given port (requires -CertThumbprint).
    ALWAYS RECOMMENDED in production: with Windows Authentication (NTLM/Negotiate) and private key
    traffic, cleartext HTTP exposes NTLM hashes and sensitive payloads on the network.

.PARAMETER AllowInsecureHttp
    If specified, allows the installation to complete over cleartext HTTP (without -UseHttps).
    SINCE 2.1.0 INSTALLATION OVER CLEARTEXT HTTP IS BLOCKED BY DEFAULT: the script stops with an error
    unless either -UseHttps OR this explicit override switch is passed.
    Use only for isolated test environments: in production use -UseHttps.

.PARAMETER CertThumbprint
    Thumbprint of the SSL/TLS certificate to bind to the HTTPS binding.
    The certificate must already be installed in the local computer Personal store.

.PARAMETER SourcePath
    Path of the ASP.NET Core source project (default: current directory).

.PARAMETER NuGetSource
    One or more NuGet sources (URL or local folder with .nupkg files) to use for the restore during
    publishing. Useful on servers isolated from the Internet: replaces the configured sources (nuget.org included).

.PARAMETER SkipDotnetPublish
    If specified, skips the build and deploy phase (uses files already published in InstallPath).

.PARAMETER SkipFirewall
    If specified, does not create the firewall rule.

.PARAMETER OverwriteConfig
    If specified, overwrites appsettings.json and web.config in the installation folder
    even if they already exist. Without this parameter, existing configuration files are
    preserved during updates (they are copied only on first installation).

.EXAMPLE
    # Basic installation over HTTPS on port 8443 (recommended)
    .\Install-PkiPortal.ps1 -SitePort 8443 -UseHttps -CertThumbprint "A1B2C3D4E5..."

.EXAMPLE
    # Isolated test environment only: cleartext HTTP must be explicitly allowed
    .\Install-PkiPortal.ps1 -SitePort 8443 -AllowInsecureHttp

.EXAMPLE
    # Installation with gMSA (Group Managed Service Account - no password required)
    .\Install-PkiPortal.ps1 -SitePort 8443 -UseHttps -CertThumbprint "A1B2C3D4E5..." `
        -AppPoolIdentity "VD\T0_PKI_WEB" -IsGMSA

.EXAMPLE
    # HTTPS installation with SSL certificate and standard user account
    .\Install-PkiPortal.ps1 -SitePort 443 -SiteHostHeader "pki.azienda.lan" -UseHttps `
        -CertThumbprint "A1B2C3D4E5..." -AppPoolIdentity "FORESTA1\svc-pki-portal" -AppPoolPassword (Read-Host -AsSecureString)

.EXAMPLE
    # Installation on a custom port without firewall changes
    .\Install-PkiPortal.ps1 -SiteName "PKI-Enrollment-F1" -SitePort 9443 -UseHttps `
        -CertThumbprint "A1B2C3D4E5..." -SkipFirewall

.NOTES
    Author:  Enterprise PKI Team
    Version: 2.2.0
    Requires: Windows Server 2016+ with the IIS role, local administrator privileges.
    IMPORTANT: This script does NOT modify the "Default Web Site" site or certsrv in any way.
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
    [Alias("AllowHttp")]
    [switch]$AllowInsecureHttp,
    [string]$CertThumbprint    = "",
    [string]$SourcePath        = $PSScriptRoot,
    [string[]]$NuGetSource     = @(),
    [switch]$SkipDotnetPublish,
    [switch]$SkipFirewall,
    [Alias("OverwriteAppSettings")]
    [switch]$OverwriteConfig
)

# ============================================================================
# LANGUAGE DETECTION / LOCALIZATION (i18n)
# ============================================================================
# If the OS language is not Italian ("it"), all script messages
# are shown in English.
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
# HELPER FUNCTIONS / LOGGING
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
# STEP 0: Check administrator privileges
# ============================================================================

if (-not (Test-IsAdmin)) {
    Write-Fail "Questo script deve essere eseguito come Amministratore." "This script must be run as Administrator."
    Write-Fail "Fare clic destro su PowerShell -> 'Esegui come amministratore', quindi rieseguire lo script." "Right-click PowerShell -> 'Run as administrator', then rerun the script."
    exit 1
}

$ErrorActionPreference = "Stop"
# In PowerShell 7.3+, native commands (dotnet.exe, appcmd.exe, etc.) writing anything
# to stderr would otherwise be treated as a terminating error when $ErrorActionPreference
# = "Stop", even on success. Disabled so that the check on
# $LASTEXITCODE (already present in the script) decides whether a command failed.
# No-op on Windows PowerShell 5.1, where this variable does not exist.
$PSNativeCommandUseErrorActionPreference = $false

# gMSA (Group Managed Service Account) detection
# An account is considered a gMSA if:
# 1. The -IsGMSA parameter is specified, or
# 2. The name ends with '$' (Active Directory standard for service accounts), or
# 3. It is a domain account specified without a password
$isAccountGMSA = $false
if ($AppPoolIdentity -notin @("ApplicationPoolIdentity", "NetworkService", "LocalSystem")) {
    if ($IsGMSA -or $AppPoolIdentity.EndsWith('$') -or ($AppPoolIdentity -like "*\*" -and -not $AppPoolPassword)) {
        $isAccountGMSA = $true
        # On Windows / Active Directory systems, gMSAs always end with '$'
        if (-not $AppPoolIdentity.EndsWith('$')) {
            $AppPoolIdentity = "${AppPoolIdentity}$"
        }
    }
}

# Console encoding: force UTF-8 so accented characters and dotnet.exe output are not corrupted.
# (The file is saved as UTF-8 with BOM, which is essential for Windows PowerShell 5.1.)
# The original value is restored when the script ends (finally block at the bottom).
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
    Write-Host "  INSTALLAZIONE PORTALE PKI WEB ENROLLMENT (AD CS Modern) v2.2.0 " -ForegroundColor White
    Write-Host "  Installazione a fianco di Microsoft certsrv (non intrusiva)     " -ForegroundColor Gray
} else {
    Write-Host "  PKI WEB ENROLLMENT PORTAL INSTALLATION (AD CS Modern) v2.2.0   " -ForegroundColor White
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
# STEP 1: Check and install required IIS features
# ============================================================================

Write-Step "STEP 1: Verifica prerequisiti IIS (senza modificare certsrv)" "STEP 1: Verifying IIS prerequisites (without modifying certsrv)"

# List of IIS features required for ASP.NET Core hosting.
# Web-Windows-Auth is required for the portal's Windows authentication (STEP 6). Installing
# the feature only installs the module: it is enabled exclusively at the level of the
# portal site, so certsrv and Default Web Site are not modified.
# We do NOT include Web-Cert-Auth so as not to interfere with certsrv.
$requiredFeatures = @(
    @{ Name = "Web-Server";             Desc = "Ruolo Web Server (IIS)";       DescEn = "Web Server Role (IIS)" },
    @{ Name = "Web-Common-Http";        Desc = "Funzionalità HTTP comuni";     DescEn = "Common HTTP Features" },
    @{ Name = "Web-Default-Doc";        Desc = "Documenti predefiniti";         DescEn = "Default Document" },
    @{ Name = "Web-Static-Content";     Desc = "Contenuto statico";            DescEn = "Static Content" },
    @{ Name = "Web-Http-Errors";        Desc = "Errori HTTP personalizzati";   DescEn = "Custom HTTP Errors" },
    @{ Name = "Web-Http-Logging";       Desc = "Logging HTTP";                 DescEn = "HTTP Logging" },
    @{ Name = "Web-Request-Monitor";    Desc = "Monitor richieste";            DescEn = "Request Monitor" },
    @{ Name = "Web-Filtering";          Desc = "Filtro richieste";             DescEn = "Request Filtering" },
    @{ Name = "Web-Windows-Auth";       Desc = "Autenticazione Windows";       DescEn = "Windows Authentication" },
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

# Import the WebAdministration module (required to manage IIS sites via PowerShell)
Import-Module WebAdministration -ErrorAction SilentlyContinue
if (-not (Get-Module WebAdministration -ErrorAction SilentlyContinue)) {
    Write-Warn "Il modulo PowerShell 'WebAdministration' non è disponibile. Tentativo con IISAdministration..." "PowerShell module 'WebAdministration' is not available. Trying IISAdministration..."
    Import-Module IISAdministration -ErrorAction SilentlyContinue
}

# ============================================================================
# STEP 2: Check and install the .NET 8 ASP.NET Core Hosting Bundle
# ============================================================================

Write-Step "STEP 2: Verifica .NET 8 ASP.NET Core Hosting Bundle" "STEP 2: Verifying .NET 8 ASP.NET Core Hosting Bundle"

$aspnetModuleInstalled = $false

# Check whether the ASP.NET Core module is registered in IIS
$aspnetModule = Get-WebGlobalModule -Name "AspNetCoreModuleV2" -ErrorAction SilentlyContinue
if ($aspnetModule) {
    Write-OK "ASP.NET Core Module V2 è già registrato in IIS." "ASP.NET Core Module V2 is already registered in IIS."
    $aspnetModuleInstalled = $true
}

# Also check for the .NET 8 x64 runtime
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
        # Download attempt (may not work in air-gapped environments)
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
# STEP 3: Verify that certsrv is not touched
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

# Check that the site name does not already exist
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

# Check that the port is not in use by another site (except Default Web Site on 80/443)
$portInUse = Get-WebBinding | Where-Object {
    $_.bindingInformation -match ":${SitePort}:" -and
    (Get-Website | Where-Object { $_.Name -ne $SiteName -and $_.Bindings.Collection.bindingInformation -contains $_.bindingInformation })
}
if ($portInUse) {
    Write-Warn "La porta $SitePort potrebbe essere già in uso da un altro sito IIS." "Port $SitePort may already be in use by another IIS site."
    Write-Warn "Valutare una porta diversa con il parametro -SitePort." "Consider using a different port with the -SitePort parameter."
}

# ============================================================================
# STEP 3b: Stop App Pool and IIS Site (if already existing - update)
# ============================================================================

$appPoolName = "${SiteName}_Pool"
$appcmd = "$env:SystemRoot\system32\inetsrv\appcmd.exe"

# 1. If the installation folder exists, place app_offline.htm to release ASP.NET Core locks
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

    # Stop the site
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

    # Stop the App Pool
    try {
        if (Test-Path $appcmd) {
            & $appcmd stop apppool /apppool.name:"$appPoolName" 2>$null
        }
        Stop-WebAppPool -Name $appPoolName -ErrorAction SilentlyContinue
    } catch { }

    # Wait for the worker process to terminate gracefully
    $timeout = 10
    $elapsed = 0
    while ($elapsed -lt $timeout) {
        if (-not (Test-Path "IIS:\AppPools\$appPoolName")) { break }
        $state = (Get-WebAppPoolState -Name $appPoolName -ErrorAction SilentlyContinue).Value
        if ($state -ne 'Started' -and $state -ne 'Stopping') { break }
        Start-Sleep -Seconds 1
        $elapsed++
    }

    # Check whether any w3wp.exe processes are still active for this AppPool or locking PkiPortal.dll
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
# STEP 4: Build and publish the application
# ============================================================================

Write-Step "STEP 4: Compilazione e pubblicazione applicazione ASP.NET Core" "STEP 4: Building and publishing ASP.NET Core application"

if ($SkipDotnetPublish) {
    Write-Info "Fase di pubblicazione saltata (-SkipDotnetPublish specificato)." "Publish stage skipped (-SkipDotnetPublish specified)."
    Write-Info "I file applicativi devono già essere presenti in: $InstallPath" "Application files must already be present in: $InstallPath"
}
else {
    # Locate the dotnet CLI (x64)
    $dotnetExe = "C:\Program Files\dotnet\dotnet.exe"
    if (-not (Test-Path $dotnetExe)) {
        $dotnetExe = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
    }
    if (-not $dotnetExe -or -not (Test-Path $dotnetExe)) {
        Write-Fail "Impossibile trovare dotnet.exe. Installare .NET 8 SDK o Hosting Bundle." "Unable to find dotnet.exe. Install .NET 8 SDK or Hosting Bundle."
        exit 1
    }
    Write-Info "CLI .NET trovato: $dotnetExe" ".NET CLI found: $dotnetExe"

    # Check that the project exists in the source path
    $csprojPath = Join-Path $SourcePath "PkiPortal.csproj"
    if (-not (Test-Path $csprojPath)) {
        Write-Fail "File di progetto non trovato: $csprojPath" "Project file not found: $csprojPath"
        Write-Fail "Specificare il percorso corretto con il parametro -SourcePath." "Specify the correct path using -SourcePath parameter."
        exit 1
    }
    Write-OK "File di progetto trovato: $csprojPath" "Project file found: $csprojPath"

    # Create the destination folder
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        Write-OK "Cartella di installazione creata: $InstallPath" "Installation directory created: $InstallPath"
    }

    # Preventive backup of existing configuration files in the destination:
    # Publishing (dotnet publish) automatically copies files from the source, overwriting
    # the destination. If -OverwriteConfig (-OverwriteAppSettings) is not specified, we preserve
    # the existing appsettings.json and web.config files by saving a temporary copy.
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

    # Publishing
    Write-Info 'Pubblicazione in corso (Release - non self-contained)...' 'Publishing in progress (Release - non-self-contained)...'
    $publishArgs = @(
        "publish"
        $csprojPath
        "--configuration", "Release"
        "--output", $InstallPath
        "--no-self-contained"
        "--runtime", "win-x64"
        "--nologo"
        # Do not download targeting packs for unreferenced frameworks (e.g. Microsoft.WindowsDesktop.App.Ref)
        "-p:DisableTransitiveFrameworkReferenceDownloads=true"
    )
    foreach ($src in $NuGetSource) {
        $publishArgs += @("--source", $src)
    }

    # Environment variables valid only for this invocation: no "Welcome to .NET" banner,
    # no telemetry, no creation of the development HTTPS certificate on a server.
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

    # Run the publish
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

        # NuGet restore errors (unresolvable packages / unreachable source)
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

    # appsettings.json handling
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

    # web.config handling
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
    # Remove app_offline.htm to allow the new version to start
    $appOfflineFile = Join-Path $InstallPath "app_offline.htm"
    if (Test-Path $appOfflineFile) {
        Remove-Item -Path $appOfflineFile -Force -ErrorAction SilentlyContinue
    }
}

# Create the log folder for stdout
$logPath = Join-Path $InstallPath "logs"
if (-not (Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    Write-OK "Cartella log creata: $logPath" "Log folder created: $logPath"
}

# Create the protected App_Data folder for secure storage of keys, held requests and entropy
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

# Migrate legacy sensitive files from the installation root to App_Data
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

$legacyKey = Join-Path $InstallPath "store-key.bin"
$targetKey = Join-Path $appDataPath "store-key.bin"
if ((Test-Path $legacyKey) -and -not (Test-Path $targetKey)) {
    Move-Item -Path $legacyKey -Destination $targetKey -Force
    Write-Info "Spostato store-key.bin legacy nella cartella protetta App_Data" "Moved legacy store-key.bin into secure App_Data folder"
}

# ============================================================================
# STEP 5: Create the dedicated Application Pool
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

# Pool configuration
& $appcmd set apppool /apppool.name:"$appPoolName" /managedRuntimeVersion:"" /enable32BitAppOnWin64:false /startMode:AlwaysRunning /processModel.idleTimeout:00:00:00 | Out-Null

# Identity configuration
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

    # Grant / verify the 'Log on as a batch job' right (SeBatchLogonRight) required by WAS/IIS
    Grant-BatchLogonRight -Account $AppPoolIdentity

    # Verify gMSA authorization on the local server if the ActiveDirectory module is present
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
    # Standard domain user account with password
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
# STEP 6: Create the IIS Site
# ============================================================================

Write-Step "STEP 6: Creazione Sito IIS '$SiteName' (porta $SitePort)" "STEP 6: Creating IIS Site '$SiteName' (port $SitePort)"

$protocol = if ($UseHttps) { "https" } else { "http" }
$bindingInfo = "*:${SitePort}:${SiteHostHeader}"

Write-Info "Binding: $protocol su $bindingInfo" "Binding: $protocol on $bindingInfo"

if ($UseHttps) {
    if ([string]::IsNullOrWhiteSpace($CertThumbprint)) {
        Write-Warn "Binding HTTPS richiesto ma nessun -CertThumbprint specificato." "HTTPS binding requested but no -CertThumbprint specified."
        Write-Info "Ricerca di un certificato valido nello store locale..." "Searching for a valid certificate in local machine store..."

        # Attempt to find a certificate matching the server name
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

    # Create the site with HTTPS binding
    New-Website -Name $SiteName `
        -PhysicalPath $InstallPath `
        -ApplicationPool $appPoolName `
        -Port $SitePort `
        -HostHeader $SiteHostHeader `
        -Ssl `
        -Force | Out-Null

    # Bind the SSL certificate to the binding
    $binding = Get-WebBinding -Name $SiteName -Protocol "https"
    if ($binding) {
        $binding.AddSslCertificate($CertThumbprint, "My")
        Write-OK "Certificato SSL associato al binding HTTPS (Thumbprint: $CertThumbprint)" "SSL certificate bound to HTTPS binding (Thumbprint: $CertThumbprint)"
    }
}
else {
    # SECURITY (2.1.0): cleartext HTTP + Windows Authentication is BLOCKED by default.
    # NTLM travels in cleartext across the network (hash capture / relay) and the portal flows
    # transmit sensitive payloads (CSRs and, in templates with approval, private keys).
    # The previous interactive confirmation is not sufficient: the explicit
    # -AllowInsecureHttp switch is now required, documented and traceable in procedures.
    Write-Host "" -ForegroundColor Red
    if ($script:IsItalian) {
        Write-Host "  [BLOCCATO] Installazione su HTTP IN CHIARO con Windows Authentication." -ForegroundColor Red
        Write-Host "  NTLM viaggia in chiaro sulla rete: rischio capture degli hash, NTLM relay" -ForegroundColor Red
        Write-Host "  e esposizione dei carichi sensibili del portale (CSR/private key)." -ForegroundColor Red
        Write-Host "  In produzione e in test in rete usare SEMPRE: -UseHttps -CertThumbprint <thumbprint>." -ForegroundColor Red
    } else {
        Write-Host "  [BLOCKED] Installation over UNENCRYPTED HTTP with Windows Authentication." -ForegroundColor Red
        Write-Host "  NTLM travels in cleartext across the network: risk of hash capture, NTLM relay" -ForegroundColor Red
        Write-Host "  and exposure of sensitive portal payloads (CSR/private keys)." -ForegroundColor Red
        Write-Host "  In production and in networked test ALWAYS use: -UseHttps -CertThumbprint <thumbprint>." -ForegroundColor Red
    }

    if (-not $AllowInsecureHttp) {
        Write-Fail (Msg "Installazione interrotta: HTTP in chiaro bloccato by default. Ripetere con -UseHttps -CertThumbprint <thumbprint>." "Installation aborted: unencrypted HTTP is blocked by default. Rerun with -UseHttps -CertThumbprint <thumbprint>.")
        Write-Info (Msg "Per override in ambienti di test isolati: aggiungere -AllowInsecureHttp." "To override in isolated test environments: add -AllowInsecureHttp.")
        exit 1
    }

    if ($script:IsItalian) {
        Write-Warn "Override -AllowInsecureHttp rilevato: proseguo con HTTP in chiaro (NON adatto a produzione)."
    } else {
        Write-Warn "-AllowInsecureHttp override detected: continuing over unencrypted HTTP (NOT suitable for production)."
    }

    # Create the site with HTTP binding
    New-Website -Name $SiteName `
        -PhysicalPath $InstallPath `
        -ApplicationPool $appPoolName `
        -Port $SitePort `
        -HostHeader $SiteHostHeader `
        -Force | Out-Null
}

# Authentication configuration at IIS site level
# SECURITY (2.1.0):
#  - anonymousAuthentication disabled: every request (including static files)
#    goes through the NTLM/Kerberos challenge; the administration UI is no longer
#    reachable anonymously.
#  - windowsAuthentication enabled (default Negotiate/NTLM providers).
#  - Extended Protection (channel binding, tokenChecking=Allow) on HTTPS only:
#    protects against NTLM relay and stays compatible with clients that do not support it.
# The configuration is written to applicationHost.config with a <location> on the portal
# site only: Default Web Site / certsrv are not touched.
try {
    $authBase    = "system.webServer/security/authentication"
    $apphostPath = "MACHINE/WEBROOT/APPHOST"

    $feat = Get-WindowsFeature -Name "Web-Windows-Auth" -ErrorAction SilentlyContinue
    if ($feat -and -not $feat.Installed) {
        throw (Msg "La feature IIS 'Web-Windows-Auth' non è installata (vedi STEP 1)." "The IIS feature 'Web-Windows-Auth' is not installed (see STEP 1).")
    }

    Set-WebConfigurationProperty -PSPath $apphostPath -Location $SiteName `
        -Filter "$authBase/anonymousAuthentication" -Name "enabled" -Value $false -ErrorAction Stop
    Set-WebConfigurationProperty -PSPath $apphostPath -Location $SiteName `
        -Filter "$authBase/windowsAuthentication" -Name "enabled" -Value $true -ErrorAction Stop

    if ($UseHttps) {
        Set-WebConfigurationProperty -PSPath $apphostPath -Location $SiteName `
            -Filter "$authBase/windowsAuthentication/extendedProtection" -Name "tokenChecking" -Value "Allow" -ErrorAction Stop
    }

    # Verify the state actually applied
    $winOn  = Get-WebConfigurationProperty -PSPath $apphostPath -Location $SiteName -Filter "$authBase/windowsAuthentication" -Name "enabled"
    $anonOn = Get-WebConfigurationProperty -PSPath $apphostPath -Location $SiteName -Filter "$authBase/anonymousAuthentication" -Name "enabled"
    if ($winOn  -is [psobject] -and $winOn.PSObject.Properties['Value'])  { $winOn  = $winOn.Value }
    if ($anonOn -is [psobject] -and $anonOn.PSObject.Properties['Value']) { $anonOn = $anonOn.Value }
    if (-not $winOn -or $anonOn) {
        throw (Msg "Stato autenticazione inatteso dopo la configurazione (Windows=$winOn, Anonymous=$anonOn)." "Unexpected authentication state after configuration (Windows=$winOn, Anonymous=$anonOn).")
    }

    Write-OK "Autenticazione Windows abilitata; Anonymous disabilitata sul sito IIS '$SiteName'." "Windows authentication enabled; Anonymous disabled on IIS site '$SiteName'."
    if ($UseHttps) {
        Write-OK "Extended Protection (tokenChecking=Allow) abilitata." "Extended Protection (tokenChecking=Allow) enabled."
    }
}
catch {
    # Fail-closed: a PKI portal must not keep running without authentication.
    Write-Fail "Configurazione autenticazione IIS fallita: $($_.Exception.Message)" "IIS authentication configuration failed: $($_.Exception.Message)"
    Stop-Website -Name $SiteName -ErrorAction SilentlyContinue
    Write-Fail "Sito '$SiteName' fermato. Correggere l'errore e rieseguire lo script." "Site '$SiteName' stopped. Fix the error and rerun the script."
    exit 1
}

Write-OK "Sito IIS '$SiteName' creato con successo." "IIS site '$SiteName' created successfully."
Write-Info "  Physical Path:     $InstallPath" "  Physical Path:     $InstallPath"
Write-Info "  Application Pool:  $appPoolName" "  Application Pool:  $appPoolName"
Write-Info "  Binding:           ${protocol}://*:${SitePort}${SiteHostHeader}" "  Binding:           ${protocol}://*:${SitePort}${SiteHostHeader}"

# ============================================================================
# STEP 7: File system permissions
# ============================================================================

Write-Step "STEP 7: Configurazione permessi file system" "STEP 7: Configuring file system permissions"

# SECURITY (2.1.0) - Principle of least privilege:
# the app pool identity receives ONLY:
#  - ReadAndExecute on the application folder (binaries/config readable, NOT modifiable:
#    prevents DLL swapping by the pool identity);
#  - Modify on appsettings.json (required for saving the configuration at runtime);
#  - Modify on App_Data and logs (locked-down folders, no inheritance).
$identityAccount = switch ($AppPoolIdentity) {
    "ApplicationPoolIdentity" { "IIS APPPOOL\$appPoolName" }
    "NetworkService"          { "NT AUTHORITY\NETWORK SERVICE" }
    "LocalSystem"             { "NT AUTHORITY\SYSTEM" }
    default                   { $AppPoolIdentity }
}

try {
    # 1. ReadAndExecute on the app root folder for the pool identity
    #    (it used to be FullControl: any code running as the pool identity could
    #    replace DLLs and binaries. Now writing is only allowed on the explicit
    #    files/folders listed below.)
    $acl = Get-Acl $InstallPath
    $rxRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identityAccount,
        "ReadAndExecute",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($rxRule)
    Set-Acl $InstallPath $acl
    Write-OK "Permessi ReadAndExecute concessi a '$identityAccount' su $InstallPath (minimo privilegio)" "ReadAndExecute permissions granted to '$identityAccount' on $InstallPath (least privilege)"

    # 2. MAXIMUM SECURITY configuration for App_Data
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

    # 3. Dedicated, protected permissions on the logs folder
    $logSec = New-Object System.Security.AccessControl.DirectorySecurity
    $logSec.SetAccessRuleProtection($true, $false)
    $logSec.AddAccessRule($ruleSystem)
    $logSec.AddAccessRule($ruleAdmins)
    $logSec.AddAccessRule($ruleAppPool)
    Set-Acl -Path $logPath -AclObject $logSec
    Write-OK "Cartella logs protetta: accesso ristretto a SYSTEM, Administrators e '$identityAccount'." "Protected logs folder secured: restricted to SYSTEM, Administrators, and '$identityAccount'."

    # 4. If appsettings.json does not exist but appsettings.example.json does, rename the example file
    $appSettingsPath = Join-Path $InstallPath "appsettings.json"
    $appSettingsExamplePath = Join-Path $InstallPath "appsettings.example.json"
    if (-not (Test-Path $appSettingsPath) -and (Test-Path $appSettingsExamplePath)) {
        Rename-Item -Path $appSettingsExamplePath -NewName "appsettings.json" -Force
        Write-OK "File appsettings.example.json rinominato in appsettings.json (prima installazione)." "File appsettings.example.json renamed to appsettings.json (initial installation)."
    }
    elseif (Test-Path $appSettingsPath) {
        Write-Info "File appsettings.json già presente, appsettings.example.json non rinominato." "File appsettings.json already present, appsettings.example.json not renamed."
    }

    # 5. Modify (write) on appsettings.json: the portal saves its configuration at runtime
    #    (PUT /api/admin/config endpoint). After the rename in step 4 the file is always present.
    if (Test-Path $appSettingsPath) {
        $fileAcl = Get-Acl $appSettingsPath
        $writeRule = New-Object System.Security.AccessControl.FileSystemAccessRule($identityAccount, "Modify", "None", "None", "Allow")
        $fileAcl.AddAccessRule($writeRule)
        Set-Acl $appSettingsPath $fileAcl
        Write-OK "Permessi Modify concessi a '$identityAccount' su appsettings.json (salvataggio runtime config)" "Modify permissions granted to '$identityAccount' on appsettings.json (runtime config save)"
    }
}
catch {
    Write-Warn "Errore durante la configurazione dei permessi: $($_.Exception.Message)" "Error configuring permissions: $($_.Exception.Message)"
    Write-Warn "Verificare manualmente che '$identityAccount' abbia accesso a $InstallPath e $appDataPath" "Manually verify '$identityAccount' has access to $InstallPath and $appDataPath"
}

# ============================================================================
# STEP 8: Firewall rule
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
# STEP 9: Start the site and verify
# ============================================================================

Write-Step "STEP 9: Avvio sito e verifica" "STEP 9: Starting site and verification"

try {
    # Start the pool and the site
    Start-WebAppPool -Name $appPoolName -ErrorAction SilentlyContinue
    Start-Website -Name $SiteName -ErrorAction SilentlyContinue
    Write-OK "Sito '$SiteName' e Application Pool '$appPoolName' avviati." "Site '$SiteName' and Application Pool '$appPoolName' started."
}
catch {
    Write-Warn "Errore durante l'avvio: $($_.Exception.Message)" "Startup error: $($_.Exception.Message)"
}

# HTTP verification attempt
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

# Verify certsrv integrity
$defaultWs = Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
if ($defaultWs -and $defaultWs.State -eq "Started") {
    Write-OK "Sito 'Default Web Site' (certsrv) è ancora attivo e funzionante." "Site 'Default Web Site' (certsrv) is still active and operational."
}

# ============================================================================
# FINAL SUMMARY
# ============================================================================

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Green
if ($script:IsItalian) {
    Write-Host "  INSTALLAZIONE COMPLETATA (v2.2.0)                              " -ForegroundColor White
} else {
    Write-Host "  INSTALLATION COMPLETED (v2.2.0)                                " -ForegroundColor White
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



