<#
.SYNOPSIS
    Test di sicurezza (regression) per il server ACME RFC 8555 di PKI Portal.

.DESCRIPTION
    Verifica i controlli di sicurezza introdotti in 2.3.1:
      1.  Lettura ordine/account anonima → 401 (ownership H1)
      2.  JWS con chiave non registrata → 404 accountDoesNotExist
      3.  Ordine wildcard → rejectedIdentifier
      4.  Ordine su dominio fuori allowlist → rejectedIdentifier
      5.  Finalize con CSR contenente SAN non autorizzate → 400 (binding CSR C1)
      6.  Finalize con CSR contenente SAN IP → 400
      7.  Replay nonce → badNonce
      8.  Body JWS > 32 KiB → 400
      9.  IDOR: account A legge ordine di account B → 403

.PARAMETER PortalUrl
    URL base del portale (default http://localhost:5280).

.PARAMETER DomainName
    Dominio nell'allowlist di sviluppo (default testserver.corp.local).

.EXAMPLE
    .\Test-AcmeSecurity.ps1 -PortalUrl "http://localhost:5280"
#>
[CmdletBinding()]
param(
    [string]$PortalUrl = "http://localhost:5280",
    [string]$DomainName = "testserver.corp.local"
)

$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0
$script:client = [System.Net.Http.HttpClient]::new()
$script:client.Timeout = [TimeSpan]::FromSeconds(90)

function B64Url([byte[]]$bytes) { [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }

function Send-Json([string]$method, [string]$url, $bodyObj) {
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($method), $url)
    if ($null -ne $bodyObj) {
        $json = if ($bodyObj -is [string]) { $bodyObj } else { ConvertTo-Json $bodyObj -Compress }
        $req.Content = [System.Net.Http.StringContent]::new($json, [System.Text.Encoding]::UTF8, 'application/json')
    }
    $resp = $script:client.SendAsync($req).GetAwaiter().GetResult()
    $txt = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $headers = @{}
    foreach ($h in $resp.Headers) { $headers[$h.Key.ToLowerInvariant()] = @($h.Value) }
    foreach ($h in $resp.Content.Headers) { $headers[$h.Key.ToLowerInvariant()] = @($h.Value) }
    $location = $resp.Headers.Location?.ToString()
    $status = [int]$resp.StatusCode
    $resp.Dispose()
    $jsonOut = $null
    try { if ($txt) { $jsonOut = $txt | ConvertFrom-Json } } catch { }
    return [PSCustomObject]@{ Status = $status; Body = $txt; Json = $jsonOut; Location = $location; Headers = $headers }
}

function New-AccountKey {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $p = $rsa.ExportParameters($false)
    $jwk = [PSCustomObject]@{ kty = 'RSA'; n = (B64Url $p.Modulus); e = (B64Url $p.Exponent) }
    return [PSCustomObject]@{ Rsa = $rsa; Jwk = $jwk; Kid = $null }
}

function Sign-Jws([string]$url, $keyObj, $payloadObj, [string]$nonce, [string]$kid) {
    $hdr = [ordered]@{ alg = 'RS256'; nonce = $nonce; url = $url }
    if ($kid) { $hdr.kid = $kid } else { $hdr.jwk = $keyObj.Jwk }
    $prot = B64Url([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $hdr -Compress)))
    $pay  = if ($null -eq $payloadObj) { '' } else { B64Url([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $payloadObj -Compress))) }
    $sig  = B64Url($keyObj.Rsa.SignData([Text.Encoding]::ASCII.GetBytes("$prot.$pay"), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1))
    return [PSCustomObject]@{ protected = $prot; payload = $pay; signature = $sig }
}

function New-Nonce([string]$url) {
    $r = Send-Json 'GET' "$url/acme/new-nonce" $null
    return $r.Headers['replay-nonce'][0]
}

function New-OrderWith([string]$url, $keyObj, [string]$domain) {
    $nonce = New-Nonce $url
    $ident = [PSCustomObject]@{ type = 'dns'; value = $domain }
    $payload = [PSCustomObject]@{ identifiers = @($ident) }
    $jws = Sign-Jws "$url/acme/new-order" $keyObj $payload $nonce $keyObj.Kid
    return Send-Json 'POST' "$url/acme/new-order" $jws
}

function Trigger-Http01([string]$url, $keyObj, [string]$challUrl) {
    # RFC 8555: il trigger di validazione e' un POST con oggetto vuoto
    # verso l'URL della challenge.
    $nonce = New-Nonce $url
    $jws = Sign-Jws $challUrl $keyObj (@{}) $nonce $keyObj.Kid
    return Send-Json 'POST' $challUrl $jws
}

function Get-Order([string]$url, $keyObj, [string]$orderId) {
    $nonce = New-Nonce $url
    $jws = Sign-Jws "$url/acme/order/$orderId" $keyObj $null $nonce $keyObj.Kid
    return Send-Json 'POST' "$url/acme/order/$orderId" $jws
}

function Build-Csr([System.Security.Cryptography.RSA]$rsa, [string]$cn, [string[]]$sanDns, [System.Net.IPAddress[]]$sanIp) {
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$cn", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if ($sanDns.Count -gt 0 -or $sanIp.Count -gt 0) {
        $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        foreach ($d in $sanDns) { $san.AddDnsName($d) }
        foreach ($ip in $sanIp) { $san.AddIpAddress($ip) }
        $req.CertificateExtensions.Add($san.Build())
    }
    return $req.CreateSigningRequest()
}

function Finalize-Order([string]$url, $keyObj, [string]$orderId, [byte[]]$csrDer) {
    $nonce = New-Nonce $url
    $payload = [PSCustomObject]@{ csr = (B64Url $csrDer) }
    $jws = Sign-Jws "$url/acme/order/$orderId/finalize" $keyObj $payload $nonce $keyObj.Kid
    return Send-Json 'POST' "$url/acme/order/$orderId/finalize" $jws
}

function Register-Account([string]$url, $keyObj, [string]$email) {
    $nonce = New-Nonce $url
    $payload = [PSCustomObject]@{ contact = @("mailto:$email"); termsOfServiceAgreed = $true }
    $jws = Sign-Jws "$url/acme/new-account" $keyObj $payload $nonce $null
    $r = Send-Json 'POST' "$url/acme/new-account" $jws
    if ($r.Status -ne 201) { throw "Impossibile registrare l'account: $($r.Status) $($r.Body)" }
    $keyObj.Kid = $r.Location
    return $keyObj
}

function Check([string]$name, [bool]$cond, [string]$detail = '') {
    if ($cond) { $script:pass++; Write-Host "  [PASS] $name" -ForegroundColor Green }
    else        { $script:fail++; Write-Host "  [FAIL] $name $detail" -ForegroundColor Red }
}

Write-Host "`n=== TEST SICUREZZA ACME — target: $PortalUrl ===" -ForegroundColor Cyan

# ---------- 1. Lettura anonima -> 401 ----------
Write-Host "`n[1] GET anonimo /acme/order|account deve restituire 401"
$r = Send-Json 'GET' "$PortalUrl/acme/order/ord-11111111222222223333333344444444" $null
Check "401 su ordine (anonimo)" ($r.Status -eq 401) "got $($r.Status)"
$r = Send-Json 'GET' "$PortalUrl/acme/account/acc-11111111222222223333333344444444" $null
Check "401 su account (anonimo)" ($r.Status -eq 401) "got $($r.Status)"

# ---------- 2. JWS con chiave non registrata -> 404 ----------
Write-Host "`n[2] new-order con chiave mai registrata deve dare 404 accountDoesNotExist"
$rogue = New-AccountKey
$r = New-OrderWith $PortalUrl $rogue $DomainName
Check "404 accountDoesNotExist" ($r.Status -eq 404 -and $r.Json.type -like '*accountDoesNotExist*') "got $($r.Status) $($r.Body)"

# ---------- 3/4. Wildcard e fuori allowlist -> rejectedIdentifier ----------
$acc = Register-Account $PortalUrl (New-AccountKey) 'sec@test.local'

Write-Host "`n[3] Ordine wildcard *.corp.local deve essere rifiutato"
$r = New-OrderWith $PortalUrl $acc '*.corp.local'
Check "400 rejectedIdentifier wildcard" ($r.Status -eq 400 -and $r.Json.type -like '*rejectedIdentifier*') "got $($r.Status) $($r.Body)"

Write-Host "`n[4] Ordine su dominio esterno (evil.com) deve essere rifiutato (allowlist)"
$r = New-OrderWith $PortalUrl $acc 'evil.com'
Check "400 rejectedIdentifier fuori allowlist" ($r.Status -eq 400 -and $r.Json.type -like '*rejectedIdentifier*') "got $($r.Status) $($r.Body)"

# ---------- 5/6. Binding CSR (C1) ----------
Write-Host "`n[5] Finalize con CSR non conforme agli identifier deve fallire (binding CSR)"
$r = New-OrderWith $PortalUrl $acc $DomainName
if ($r.Status -ne 201) {
    Check "ordine valido creato" $false "got $($r.Status) $($r.Body)"
} else {
    $authUrl = $r.Json.authorizations[0]
    $nonce = New-Nonce $PortalUrl
    $jwsAuth = Sign-Jws $authUrl $acc $null $nonce $acc.Kid
    $authData = (Send-Json 'POST' $authUrl $jwsAuth).Json
    $challUrl = ($authData.challenges | Where-Object { $_.type -eq 'http-01' }).url
    $ch = Trigger-Http01 $PortalUrl $acc $challUrl
    $order = Get-Order $PortalUrl $acc $r.Json.id
    Check "ordine in stato ready" ($order.Json.status -eq 'ready') "got $($order.Json.status) (chall: $($ch.Json.status))"

    $rsaCsr = [System.Security.Cryptography.RSA]::Create(2048)
    $badCsr = Build-Csr $rsaCsr $DomainName @('dc01.evil.com') @()
    $f = Finalize-Order $PortalUrl $acc $r.Json.id $badCsr
    Check "400 CSR con SAN esterne" ($f.Status -eq 400 -and $f.Json.detail -like '*identifier autorizzati*') "got $($f.Status) $($f.Body)"

    $badCsr2 = Build-Csr $rsaCsr $DomainName @() @([System.Net.IPAddress]::Parse('10.0.0.5'))
    $f2 = Finalize-Order $PortalUrl $acc $r.Json.id $badCsr2
    Check "400 CSR con SAN IP" ($f2.Status -eq 400 -and $f2.Json.detail -like '*SAN IP*') "got $($f2.Status) $($f2.Body)"
}

# ---------- 7. Replay nonce -> badNonce ----------
Write-Host "`n[7] Reutilizzo di un nonce deve dare badNonce"
$acc2 = New-AccountKey
$nonce = New-Nonce $PortalUrl
$payload = [PSCustomObject]@{ contact = @('mailto:replay@test.local'); termsOfServiceAgreed = $true }
$jwsA = Sign-Jws "$PortalUrl/acme/new-account" $acc2 $payload $nonce $null
$rA = Send-Json 'POST' "$PortalUrl/acme/new-account" $jwsA
Check "primo uso nonce: account creato" ($rA.Status -eq 201) "got $($rA.Status) $($rA.Body)"
$jwsB = Sign-Jws "$PortalUrl/acme/new-account" $acc2 $payload $nonce $null
$rB = Send-Json 'POST' "$PortalUrl/acme/new-account" $jwsB
Check "400 badNonce sul replay" ($rB.Status -eq 400 -and $rB.Json.type -like '*badNonce*') "got $($rB.Status) $($rB.Body)"

# ---------- 8. Body JWS > 32 KiB -> 400 ----------
Write-Host "`n[8] Body JWS > 32 KiB deve essere rifiutato"
$bigSig = 'A' * (40 * 1024)
$bigBody = '{"protected":"x","payload":"","signature":"' + $bigSig + '"}'
$r = Send-Json 'POST' "$PortalUrl/acme/new-order" $bigBody
Check "400 su body oversize" ($r.Status -eq 400) "got $($r.Status)"

# ---------- 9. IDOR: account A legge ordine di account B ----------
Write-Host "`n[9] IDOR: account A su ordine di account B deve dare 403"
$accB = Register-Account $PortalUrl (New-AccountKey) 'b@test.local'
$rB = New-OrderWith $PortalUrl $accB $DomainName
if ($rB.Status -ne 201) {
    Check "ordine B creato" $false "got $($rB.Status) $($rB.Body)"
} else {
    $nonce = New-Nonce $PortalUrl
    $jwsRead = Sign-Jws "$PortalUrl/acme/order/$($rB.Json.id)" $acc $null $nonce $acc.Kid
    $rRead = Send-Json 'POST' "$PortalUrl/acme/order/$($rB.Json.id)" $jwsRead
    Check "403 su ordine altrui" ($rRead.Status -eq 403) "got $($rRead.Status) $($rRead.Body)"
}

Write-Host "`n=== RIESULTATO: $script:pass OK, $script:fail FAIL ===" -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 }
