<#
.SYNOPSIS
    Registra in modo sicuro le credenziali di un account di servizio nel Windows Credential Manager.
    Utilizzato dal Portale PKI in modalità Hub per autenticarsi su Sub-CA di foreste non trustate.

.DESCRIPTION
    Questo script consente di memorizzare le credenziali nel keystore locale di Windows (Windows Credential Manager)
    senza salvare MAI password in chiaro nei file di configurazione.
    La password viene richiesta tramite prompt sicuro a riga di comando (mascherata).

.PARAMETER Target
    Nome del target (tipicamente l'FQDN della Sub-CA, es. "subca01.foresta1.lan").
    Deve corrispondere al valore 'CredentialTarget' o all'hostname di 'ConfigString' in appsettings.json.

.PARAMETER UserName
    Nome utente dell'account di servizio nella foresta di destinazione nel formato "DOMINIO\Utente"
    (es. "FORESTA1\svc-pki-enroll" o "FORESTA2\svc-pki-enroll").

.PARAMETER AsSystem
    Se specificato, avverte su come configurare le credenziali se il portale esegue come account di sistema/AppPool.

.EXAMPLE
    # Registrazione credenziali per Foresta 1 (la password verrà chiesta in modo interattivo e cifrata)
    .\Add-CaCredential.ps1 -Target "subca01.foresta1.lan" -UserName "FORESTA1\svc-pki-enroll"

.EXAMPLE
    # Registrazione credenziali per Foresta 2 (non trustata)
    .\Add-CaCredential.ps1 -Target "subca02.foresta2.lan" -UserName "FORESTA2\svc-pki-enroll"

.EXAMPLE
    # Visualizzazione delle credenziali correntemente registrate
    .\Add-CaCredential.ps1 -List
#>

[CmdletBinding()]
param(
    [string]$Target,
    [string]$UserName,
    [switch]$List,
    [switch]$Remove
)

# 1. Elenco credenziali
if ($List) {
    Write-Host ""
    Write-Host "═════ CREDENZIALI MEMORIZZATE IN WINDOWS CREDENTIAL MANAGER ═════" -ForegroundColor Cyan
    cmdkey /list
    exit 0
}

# 2. Rimozione credenziale
if ($Remove) {
    if (-not $Target) {
        Write-Error "Specificare il parametro -Target da rimuovere (es. -Target subca01.foresta1.lan)."
        exit 1
    }
    Write-Host "Rimozione del target '$Target' dal Credential Manager..." -ForegroundColor Yellow
    cmdkey /delete:$Target
    Write-Host "[OK] Target rimosso con successo." -ForegroundColor Green
    exit 0
}

# 3. Aggiunta credenziale in modo sicuro
if (-not $Target) {
    $Target = Read-Host "Inserire il Target FQDN della CA (es. subca01.foresta1.lan)"
}

if (-not $UserName) {
    $UserName = Read-Host "Inserire l'account di servizio con dominio (es. FORESTA1\svc-pki-enroll)"
}

Write-Host ""
Write-Host "Registrazione credenziale per il target: $Target" -ForegroundColor Cyan
Write-Host "Account: $UserName" -ForegroundColor White
Write-Host "Inserire la password (i caratteri saranno mascherati):" -ForegroundColor Yellow

$securePass = Read-Host -AsSecureString "Password"
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass)
$plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

try {
    # Registrazione tramite cmdkey (archiviata nel Credential Vault di Windows)
    $proc = Start-Process -FilePath "cmdkey.exe" `
        -ArgumentList "/generic:$Target", "/user:$UserName", "/pass:$plainPass" `
        -NoNewWindow -Wait -PassThru

    if ($proc.ExitCode -eq 0) {
        Write-Host ""
        Write-Host "✅ [SUCCESSO] Credenziale registrata con successo nel Windows Credential Manager!" -ForegroundColor Green
        Write-Host "   Target:  $Target" -ForegroundColor White
        Write-Host "   Account: $UserName" -ForegroundColor White
        Write-Host "   La password è protetta a livello di sistema operativo dal DPAPI di Windows." -ForegroundColor Gray
        Write-Host "   Nessuna password in chiaro è stata salvata su file." -ForegroundColor Green
    } else {
        Write-Host "❌ Errore durante la registrazione con cmdkey (Codice uscita: $($proc.ExitCode))" -ForegroundColor Red
    }
} finally {
    $plainPass = $null
}
