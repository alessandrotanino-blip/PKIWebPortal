<#
.SYNOPSIS
    Script di collaudo e test end-to-end per il server ACME (RFC 8555) integrato nel Portale PKI.

.DESCRIPTION
    Esegue in modo completamente automatico l'intero ciclo di vita di un certificato ACME:
      1. Recupero ACME Directory (GET /acme/directory)
      2. Acquisizione Nonce anti-replay (GET /acme/new-nonce)
      3. Generazione coppia di chiavi account RSA-2048 in memoria
      4. Registrazione nuovo account con firma JWS (POST /acme/new-account)
      5. Creazione nuovo ordine di certificato (POST /acme/new-order)
      6. Query autorizzazione e challenge di dominio (POST-as-GET /acme/authz/{id})
      7. Trigger validazione challenge (POST /acme/chall/{authId}/http-01)
      8. Generazione CSR PKCS#10 in memoria (RSA-2048)
      9. Finalizzazione ordine e invio CSR ad AD CS (POST /acme/order/{id}/finalize)
     10. Download catena certificato (GET /acme/cert/{id})
     11. Ispezione crittografica del certificato X.509 scaricato

.PARAMETER PortalUrl
    URL base del portale PKI (default: "http://localhost:5000" o "https://localhost:5001").

.PARAMETER DomainName
    Nome di dominio / FQDN da richiedere nel certificato (default: "testserver.corp.local").

.PARAMETER ContactEmail
    Email di contatto per l'account ACME (default: "admin@corp.local").

.EXAMPLE
    .\Test-AcmeProtocol.ps1 -PortalUrl "http://localhost:5000" -DomainName "app01.vd.ld"
#>

[CmdletBinding()]
param(
    [string]$PortalUrl = "http://localhost:5000",
    [string]$DomainName = "testserver.corp.local",
    [string]$ContactEmail = "admin@corp.local"
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$msg) {
    Write-Host "`n[STEP] $msg" -ForegroundColor Cyan
}

function Write-Success([string]$msg) {
    Write-Host "  [OK] $msg" -ForegroundColor Green
}

function Write-Err([string]$msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
}

function Base64UrlEncode([byte[]]$bytes) {
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Base64UrlDecode([string]$str) {
    $padded = $str.Trim().Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        2 { $padded += "==" }
        3 { $padded += "=" }
    }
    return [Convert]::FromBase64String($padded)
}

function Get-HeaderValue($headers, [string]$name) {
    if (-not $headers) { return $null }
    $val = $headers[$name]
    if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
        foreach ($item in $val) { return [string]$item }
    }
    return [string]$val
}

function Sign-Jws {
    param(
        [System.Security.Cryptography.RSA]$Rsa,
        [hashtable]$Header,
        [hashtable]$Payload = $null,
        [switch]$PostAsGet
    )

    $headerJson = $Header | ConvertTo-Json -Compress
    $headerB64 = Base64UrlEncode ([System.Text.Encoding]::UTF8.GetBytes($headerJson))

    $payloadB64 = ""
    if (-not $PostAsGet -and $null -ne $Payload) {
        $payloadJson = $Payload | ConvertTo-Json -Compress
        $payloadB64 = Base64UrlEncode ([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
    }

    $toSign = [System.Text.Encoding]::ASCII.GetBytes("${headerB64}.${payloadB64}")
    $sigBytes = $Rsa.SignData($toSign, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $sigB64 = Base64UrlEncode $sigBytes

    return @{
        "protected" = $headerB64
        "payload"   = $payloadB64
        "signature" = $sigB64
    }
}

try {
    $PortalUrl = $PortalUrl.TrimEnd('/')
    Write-Host "==================================================================" -ForegroundColor Magenta
    Write-Host "  TEST AUTOMATICO SERVER ACME (RFC 8555) - PKI PORTAL             " -ForegroundColor White
    Write-Host "  Target: $PortalUrl | Dominio: $DomainName                       " -ForegroundColor White
    Write-Host "==================================================================" -ForegroundColor Magenta

    # 1. ACME Directory
    Write-Step "1. Recupero ACME Directory (/acme/directory)..."
    $dirUrl = "$PortalUrl/acme/directory"
    $dir = Invoke-RestMethod -Uri $dirUrl -Method Get
    Write-Success "Directory ottenuta con successo!"
    Write-Host "    NewNonce:   $($dir.newNonce)" -ForegroundColor DarkGray
    Write-Host "    NewAccount: $($dir.newAccount)" -ForegroundColor DarkGray
    Write-Host "    NewOrder:   $($dir.newOrder)" -ForegroundColor DarkGray

    # 2. Ottenimento Replay-Nonce
    Write-Step "2. Richiesta Replay-Nonce iniziale (/acme/new-nonce)..."
    $nonceResponse = Invoke-WebRequest -Uri $dir.newNonce -Method Get
    $nonce = Get-HeaderValue $nonceResponse.Headers "Replay-Nonce"
    if (-not $nonce) {
        throw "Header 'Replay-Nonce' mancante nella risposta di new-nonce!"
    }
    Write-Success "Nonce acquisito: $nonce"

    # 3. Generazione chiave Account RSA
    Write-Step "3. Generazione chiave privata RSA-2048 per l'account ACME..."
    $accountRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $rsaParams = $accountRsa.ExportParameters($false)
    $jwkN = Base64UrlEncode $rsaParams.Modulus
    $jwkE = Base64UrlEncode $rsaParams.Exponent

    $jwk = @{
        kty = "RSA"
        n   = $jwkN
        e   = $jwkE
    }

    # Calcolo JWK Thumbprint RFC 7638
    $canonicalJwk = "{`"e`":`"$jwkE`",`"kty`":`"RSA`",`"n`":`"$jwkN`"}"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $thumbprintBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonicalJwk))
    $accountThumbprint = Base64UrlEncode $thumbprintBytes
    Write-Success "Chiave generata. JWK Thumbprint (RFC 7638): $accountThumbprint"

    # 4. Registrazione nuovo account (/acme/new-account)
    Write-Step "4. Registrazione account (/acme/new-account)..."
    $accountHeader = @{
        alg   = "RS256"
        jwk   = $jwk
        nonce = $nonce
        url   = $dir.newAccount
    }
    $accountPayload = @{
        contact              = @("mailto:$ContactEmail")
        termsOfServiceAgreed = $true
    }
    $jwsAccount = Sign-Jws -Rsa $accountRsa -Header $accountHeader -Payload $accountPayload
    $jwsAccountJson = $jwsAccount | ConvertTo-Json -Compress

    $regResponse = Invoke-WebRequest -Uri $dir.newAccount -Method Post -Body $jwsAccountJson -ContentType "application/jose+json"
    $accountUrl = Get-HeaderValue $regResponse.Headers "Location"
    $nonce = Get-HeaderValue $regResponse.Headers "Replay-Nonce"
    Write-Success "Account registrato con successo! (Status: $($regResponse.StatusCode))"
    Write-Host "    Account URL (kid): $accountUrl" -ForegroundColor Green
    Write-Host "    Nuovo Nonce:       $nonce" -ForegroundColor DarkGray

    # 5. Creazione nuovo ordine (/acme/new-order)
    Write-Step "5. Invio nuovo ordine per il dominio '$DomainName' (/acme/new-order)..."
    $orderHeader = @{
        alg   = "RS256"
        kid   = $accountUrl
        nonce = $nonce
        url   = $dir.newOrder
    }
    $orderPayload = @{
        identifiers = @(
            @{ type = "dns"; value = $DomainName }
        )
    }
    $jwsOrder = Sign-Jws -Rsa $accountRsa -Header $orderHeader -Payload $orderPayload
    $jwsOrderJson = $jwsOrder | ConvertTo-Json -Compress

    $orderResponse = Invoke-WebRequest -Uri $dir.newOrder -Method Post -Body $jwsOrderJson -ContentType "application/jose+json"
    $orderLocation = Get-HeaderValue $orderResponse.Headers "Location"
    $nonce = Get-HeaderValue $orderResponse.Headers "Replay-Nonce"
    $orderData = $orderResponse.Content | ConvertFrom-Json
    Write-Success "Ordine creato con successo! (Status: $($orderData.status))"
    Write-Host "    Order URL:    $orderLocation" -ForegroundColor Green
    Write-Host "    Finalize URL: $($orderData.finalize)" -ForegroundColor DarkGray
    Write-Host "    Authorizations: $($orderData.authorizations -join ', ')" -ForegroundColor DarkGray

    $authUrl = $orderData.authorizations[0]

    # 6. Query Autorizzazione
    Write-Step "6. Recupero dettagli autorizzazione ($authUrl)..."
    $authHeader = @{
        alg   = "RS256"
        kid   = $accountUrl
        nonce = $nonce
        url   = $authUrl
    }
    # POST-as-GET
    $jwsAuth = Sign-Jws -Rsa $accountRsa -Header $authHeader -PostAsGet
    $jwsAuthJson = $jwsAuth | ConvertTo-Json -Compress

    $authResponse = Invoke-WebRequest -Uri $authUrl -Method Post -Body $jwsAuthJson -ContentType "application/jose+json"
    $nonce = Get-HeaderValue $authResponse.Headers "Replay-Nonce"
    $authData = $authResponse.Content | ConvertFrom-Json
    Write-Success "Autorizzazione recuperata. Identificatore: $($authData.identifier.value)"

    $httpChall = $authData.challenges | Where-Object { $_.type -eq "http-01" }
    Write-Host "    Challenge HTTP-01 URL: $($httpChall.url)" -ForegroundColor DarkGray
    Write-Host "    Token:                 $($httpChall.token)" -ForegroundColor DarkGray

    # Calcolo Key Authorization: "<token>.<account_thumbprint>"
    $keyAuth = "$($httpChall.token).$accountThumbprint"
    Write-Host "    Key Authorization:     $keyAuth" -ForegroundColor Yellow

    # 7. Validazione Challenge
    Write-Step "7. Trigger validazione challenge HTTP-01..."
    $challHeader = @{
        alg   = "RS256"
        kid   = $accountUrl
        nonce = $nonce
        url   = $httpChall.url
    }
    $jwsChall = Sign-Jws -Rsa $accountRsa -Header $challHeader -Payload @{}
    $jwsChallJson = $jwsChall | ConvertTo-Json -Compress

    $challResponse = Invoke-WebRequest -Uri $httpChall.url -Method Post -Body $jwsChallJson -ContentType "application/jose+json"
    $nonce = Get-HeaderValue $challResponse.Headers "Replay-Nonce"
    $challData = $challResponse.Content | ConvertFrom-Json
    Write-Success "Challenge inviata! Stato attuale: $($challData.status)"

    # Controllo stato ordine
    Write-Step "8. Verifica stato ordine pre-finalizzazione..."
    $chkHeader = @{
        alg   = "RS256"
        kid   = $accountUrl
        nonce = $nonce
        url   = $orderLocation
    }
    $jwsChk = Sign-Jws -Rsa $accountRsa -Header $chkHeader -PostAsGet
    $chkResponse = Invoke-WebRequest -Uri $orderLocation -Method Post -Body ($jwsChk | ConvertTo-Json -Compress) -ContentType "application/jose+json"
    $nonce = Get-HeaderValue $chkResponse.Headers "Replay-Nonce"
    $chkData = $chkResponse.Content | ConvertFrom-Json
    Write-Success "Stato ordine: $($chkData.status)"

    # 8. Generazione CSR in memoria
    Write-Step "9. Generazione CSR PKCS#10 per '$DomainName'..."
    $certRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $dn = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=$DomainName")
    $certReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $dn,
        $certRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    # Aggiunta SAN
    $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $sanBuilder.AddDnsName($DomainName)
    $certReq.CertificateExtensions.Add($sanBuilder.Build())

    $derCsr = $certReq.CreateSigningRequest()
    $csrB64Url = Base64UrlEncode $derCsr
    Write-Success "CSR generato con successo! Dimensione DER: $($derCsr.Length) bytes."

    # 9. Finalizzazione ordine (/finalize)
    Write-Step "10. Invio finalize ad AD CS ($($orderData.finalize))..."
    $finalizeHeader = @{
        alg   = "RS256"
        kid   = $accountUrl
        nonce = $nonce
        url   = $orderData.finalize
    }
    $finalizePayload = @{
        csr = $csrB64Url
    }
    $jwsFinalize = Sign-Jws -Rsa $accountRsa -Header $finalizeHeader -Payload $finalizePayload
    $jwsFinalizeJson = $jwsFinalize | ConvertTo-Json -Compress

    $finalizeResponse = Invoke-WebRequest -Uri $orderData.finalize -Method Post -Body $jwsFinalizeJson -ContentType "application/jose+json"
    $nonce = Get-HeaderValue $finalizeResponse.Headers "Replay-Nonce"
    $finalizedOrder = $finalizeResponse.Content | ConvertFrom-Json
    Write-Success "Finalize completata! Stato ordine: $($finalizedOrder.status)"
    Write-Host "    Certificate URL: $($finalizedOrder.certificate)" -ForegroundColor Green

    # 10. Download del certificato
    Write-Step "11. Download del certificato firmato (/acme/cert/{id})..."
    $certUrl = $finalizedOrder.certificate
    if (-not $certUrl) {
        throw "URL certificato assente nell'ordine finalizzato!"
    }

    $certResponse = Invoke-WebRequest -Uri $certUrl -Method Get
    $certPem = if ($certResponse.Content -is [byte[]]) {
        [System.Text.Encoding]::UTF8.GetString($certResponse.Content)
    } else {
        [string]$certResponse.Content
    }
    Write-Success "Catena di certificati scaricata con successo!"
    Write-Host "--------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host $certPem.Substring(0, [Math]::Min(300, $certPem.Length)) -ForegroundColor Gray
    Write-Host "..." -ForegroundColor Gray
    Write-Host "--------------------------------------------------" -ForegroundColor DarkCyan

    # 11. Parsing e verifica certificato X.509
    Write-Step "12. Ispezione certificato X.509 emesso..."
    $certBytes = [System.Text.Encoding]::UTF8.GetBytes($certPem)
    $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($certPem)
    Write-Success "Certificato X.509 valido!"
    Write-Host "    Subject:        $($x509.Subject)" -ForegroundColor White
    Write-Host "    Issuer:         $($x509.Issuer)" -ForegroundColor White
    Write-Host "    Valido dal:     $($x509.NotBefore)" -ForegroundColor White
    Write-Host "    Scadenza:       $($x509.NotAfter)" -ForegroundColor White
    Write-Host "    Thumbprint:     $($x509.Thumbprint)" -ForegroundColor White
    Write-Host "    Algoritmo:      $($x509.SignatureAlgorithm.FriendlyName)" -ForegroundColor White

    Write-Host "`n==================================================================" -ForegroundColor Green
    Write-Host "  TEST ACME SUPERATO CON SUCCESSO AL 100%!                      " -ForegroundColor Green
    Write-Host "==================================================================" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Err "ERRORE DURANTE IL TEST ACME: $($_.Exception.Message)"
    if ($_.ErrorDetails) {
        Write-Host "  Risposta server (ErrorDetails): $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
    if ($_.Exception.Response) {
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $body = $reader.ReadToEnd()
            Write-Host "  Risposta server: $body" -ForegroundColor Red
        } catch {}
    }
    exit 1
}
