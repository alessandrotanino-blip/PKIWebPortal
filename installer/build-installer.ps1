# build-installer.ps1 - Compila l'installer PkiPortal con Inno Setup 6 (ISCC)
# Uso:  .\build-installer.ps1
#
# Cerca ISCC.exe nei percorsi standard (winget per-user, MSI per-machine, PATH).
# Compila PkiPortal.iss e produce ..\build\PkiPortal-Setup-<versione>.exe

[CmdletBinding()]
param(
    # Percorso esplicito di ISCC.exe (opzionale)
    [string]$IsccPath,
    # Salta il dotnet publish preventivo
    [switch]$SkipPublish
)

$ErrorActionPreference = 'Stop'
$iss   = Join-Path $PSScriptRoot 'PkiPortal.iss'
$root  = Split-Path $PSScriptRoot -Parent
$build = Join-Path $root 'build'
$publish = Join-Path $root 'publish'

function Find-Iscc {
    $candidates = @(
        $IsccPath,
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
        'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
        'C:\Program Files\Inno Setup 6\ISCC.exe'
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    $inPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }
    return $null
}

$iscc = Find-Iscc
if (-not $iscc) {
    Write-Error "ISCC.exe non trovato. Installare Inno Setup 6, ad esempio:`n  winget install JRSoftware.InnoSetup`noppure passare -IsccPath 'C:\...\ISCC.exe'."
    return
}

Write-Host "ISCC: $iscc" -ForegroundColor Cyan
Write-Host "ISS : $iss"  -ForegroundColor Cyan

if (-not (Test-Path $iss)) {
    Write-Error "File di progetto non trovato: $iss"
    return
}

# Rigenera il bundle di pubblicazione se non esplicitamente saltato
if (-not $SkipPublish) {
    Write-Host "Rigenerazione pacchetto: dotnet publish -c Release -o `"$publish`"..." -ForegroundColor Cyan
    $proj = Join-Path $root 'PkiPortal.csproj'
    & dotnet publish $proj -c Release -o $publish
    if ($LASTEXITCODE -ne 0) {
        Write-Error "dotnet publish fallito (exit $LASTEXITCODE)."
        return
    }
} elseif (-not (Test-Path (Join-Path $publish 'PkiPortal.dll'))) {
    Write-Warning "PkiPortal.dll non trovato in ${publish} - il bundle embeddato sarà incompleto."
    Write-Warning "Rigenerare con: dotnet publish -c Release -o publish"
}

# Assicura che file di configurazione locali non vengano inclusi nell'installer
$localConfigs = @('appsettings.json', 'appsettings.Development.json')
foreach ($cfg in $localConfigs) {
    $cfgPath = Join-Path $publish $cfg
    if (Test-Path $cfgPath) {
        Write-Host "Rimozione di $cfg da publish per escluderlo dall'installer..." -ForegroundColor Yellow
        Remove-Item $cfgPath -Force
    }
}

& $iscc $iss
if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilazione fallita (exit $LASTEXITCODE)."
    return
}

Get-ChildItem $build -Filter 'PkiPortal-Setup-*.exe' |
    Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,2)}}, LastWriteTime |
    Format-Table -AutoSize
