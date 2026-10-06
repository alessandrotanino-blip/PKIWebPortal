<#
.SYNOPSIS
    Disinstalla il Portale PKI Web Enrollment da IIS senza toccare certsrv.

.PARAMETER SiteName
    Nome del sito IIS da rimuovere (default: "PkiWebEnrollment")

.PARAMETER RemoveFiles
    Se specificato, elimina anche i file applicativi dalla cartella di installazione.

.PARAMETER InstallPath
    Percorso fisico del sito da rimuovere (default: "C:\inetpub\PkiWebEnrollment")

.EXAMPLE
    .\Uninstall-PkiPortal.ps1
    .\Uninstall-PkiPortal.ps1 -SiteName "PKI-Enrollment-F1" -RemoveFiles
#>

[CmdletBinding()]
param(
    [string]$SiteName    = "PkiWebEnrollment",
    [string]$InstallPath = "C:\inetpub\PkiWebEnrollment",
    [switch]$RemoveFiles
)

$ErrorActionPreference = "Stop"
Import-Module WebAdministration -ErrorAction SilentlyContinue

$appPoolName = "${SiteName}_Pool"

Write-Host ""
Write-Host "===  DISINSTALLAZIONE PORTALE PKI WEB ENROLLMENT  ===" -ForegroundColor Yellow
Write-Host ""

# 1. Arresto e rimozione del sito IIS
$site = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
if ($site) {
    Stop-Website -Name $SiteName -ErrorAction SilentlyContinue
    Remove-Website -Name $SiteName
    Write-Host "  [OK] Sito IIS '$SiteName' rimosso." -ForegroundColor Green
} else {
    Write-Host "  [INFO] Sito '$SiteName' non trovato in IIS." -ForegroundColor Gray
}

# 2. Arresto e rimozione dell'Application Pool
$pool = Get-Item "IIS:\AppPools\$appPoolName" -ErrorAction SilentlyContinue
if ($pool) {
    Stop-WebAppPool -Name $appPoolName -ErrorAction SilentlyContinue
    Remove-WebAppPool -Name $appPoolName
    Write-Host "  [OK] Application Pool '$appPoolName' rimosso." -ForegroundColor Green
} else {
    Write-Host "  [INFO] Application Pool '$appPoolName' non trovato." -ForegroundColor Gray
}

# 3. Rimozione regola firewall
$fwRules = Get-NetFirewallRule -DisplayName "PKI Web Enrollment Portal*" -ErrorAction SilentlyContinue
foreach ($rule in $fwRules) {
    Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
    Write-Host "  [OK] Regola firewall '$($rule.DisplayName)' rimossa." -ForegroundColor Green
}

# 4. Rimozione file applicativi (opzionale)
if ($RemoveFiles -and (Test-Path $InstallPath)) {
    Remove-Item -Path $InstallPath -Recurse -Force
    Write-Host "  [OK] Cartella '$InstallPath' eliminata." -ForegroundColor Green
} elseif (Test-Path $InstallPath) {
    Write-Host "  [INFO] Cartella '$InstallPath' conservata. Usare -RemoveFiles per eliminarla." -ForegroundColor Gray
}

# 5. Verifica integrità certsrv
$defaultWs = Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
if ($defaultWs) {
    Write-Host "  [OK] Sito 'Default Web Site' (certsrv) invariato (stato: $($defaultWs.State))." -ForegroundColor Green
}

Write-Host ""
Write-Host "  Disinstallazione completata. certsrv NON è stato toccato." -ForegroundColor Green
Write-Host ""
