# Changelog

[🇮🇹 Italiano](CHANGELOG.md) | [🇬🇧 English](CHANGELOG.en.md)

Tutte le modifiche rilevanti apportate a questo progetto saranno documentate in questo file.

Il formato è basato su [Keep a Changelog](https://keepachangelog.com/it/1.0.0/) e questo progetto aderisce al [Semantic Versioning](https://semver.org/lang/it/).

## [2.5.0] - 2026-11-07

### Novità & Funzionalità

- **Rilevamento Automatico del Nome CA nella Configurazione (eliminati i campi ridondanti)**:
  - La scheda CA del pannello di amministrazione non richiede più di digitare manualmente la **Config String**: i campi **Server CA** e **Nome CA** la costruiscono automaticamente in forma `server\Nome-CA`.
  - Nuovo pulsante **🔍 Rileva CA**: identifica i nomi delle CA ospitati sul server specificato e li propone in una **tendina** da cui selezionare il Nome CA (selezione automatica se ne viene rilevata una sola).
  - **Credential Target** non è più un campo libero: viene dedotto automaticamente dal Server CA (corrisponde sempre al target della credenziale nel Windows Credential Manager, come già faceva il fallback lato server).
  - Nuovo endpoint `POST /api/admin/ca/discover` (solo admin, con token anti-CSRF) che interroga:
    1. il partizionamento **Configuration** della foresta AD (attributo standard `dNSHostName` e classe `pKIEnrollmentService`, oltre a `caDnsName`/SPN `Certsrv/<host>`), con confronto tollerante FQDN/hostname e, in modalità **CredentialManager**, la credenziale del target (LDAPS obbligatorio, nessun fallback in chiaro). Il base DN del partizionamento è risolto dinamicamente via **rootDSE** (`configurationNamingContext`) invece che costruito dal nome del dominio: il campo Foresta / Dominio accetta anche il DNS del server CA o un nome NetBIOS, e nelle foreste multi-domain il DN del partizionamento usa il dominio radice. I **referral LDAP** restituiti dal DC vengono seguiti automaticamente (fino a 2 hop) e gli errori indicano il dominio interrogato e, in caso di referral, come correggere il campo Foresta / Dominio;
    2. in fallback, la **pagina CAPL** del server CA (`https://<server>/CertSrv/CertSrv.dll`, poi `http://`), estraendo i link `Machine$<NomeCA>` (con gestione dei nomi con spazi, percent-encoded). Il campo Server CA accetta anche `host:porta` per CAPL su porta non standard. I messaggi d'errore riportano **tutte** le fonti provate (https e http, non solo l'ultimo tentativo) e, se il certificato TLS del server CA non è fidato dal processo del portale, la lettura CAPL viene ripetuta con validazione TLS disattivata (solo per questa scoperta in sola lettura) segnalandolo con un **avviso** non bloccante.
  - La Config String esistente viene scomposta automaticamente in Server CA + Nome CA al caricamento (nessuna migrazione: i file `appsettings.json` pregressi restano validi e vengono risalvati nella stessa forma).
  - Traduzioni complete (IT, EN, FR, DE, ES, PT, ZH) in `i18n.js`.

## [2.4.0] - 2026-11-06

### Novità & Funzionalità

- **Identificazione Richiedente Certificati ACME & Indirizzo IP Client**:
  - Negli elenchi dei certificati e delle richieste (sia nel portale principale che nel pannello di amministrazione), i certificati emessi tramite protocollo ACME (RFC 8555) sono ora chiaramente identificabili nel campo *Richiedente*.
  - Registrazione automatica dell'indirizzo IP del client richiedente ACME (ACME (<ip>), es. ACME (192.168.1.50)) rilevato durante la creazione o finalizzazione dell'ordine, con supporto trasparente per proxy/reverse-proxy (X-Forwarded-For) e mapping IPv6-to-IPv4.
  - Se l'indirizzo IP non è disponibile, viene riportato ACME.
  - Badge grafico distintivo ad alta visibilità (⚡ ACME (...)) sia nella tabella del portale che nelle schede di amministrazione.
  - Retrocompatibilità automatica: tutte le richieste ACME pregresse archiviate nello store persistente (held-requests.json) vengono automaticamente riconosciute ed etichettate come ACME.

- **Filtraggio Avanzato Richieste Certificato (Portale & Admin)**:
  - Nuova barra dei filtri integrata nell'elenco certificati del portale (index.html) e nel tab richieste del pannello admin (dmin.html).
  - **Filtro Richiedente**: menu a tendina auto-popolato dinamicamente con tutti i richiedenti presenti nello storico, inclusa l'opzione rapida ⚡ Solo ACME (tutti) per isolare istantaneamente tutte le emissioni ACME.
  - **Filtro Template**: menu a tendina auto-popolato con tutti i Certificate Template presenti.
  - **Filtro Stato**: selezione per visualizzare solo emessi/approvati, in attesa o rifiutati.
  - **Ricerca Testuale Libera**: input di ricerca live full-text istantaneo che filtra in tempo reale su Common Name (CN), Request ID, Richiedente (inclusi IP ACME), Template e CA.
  - **Contatore e Pulsante Reset**: contatore dinamico delle richieste visibili (Mostrate X su Y richieste) e pulsante ✕ Azzera per ripristinare i filtri con un solo clic.

- **Filtri API RESTful**:
  - Gli endpoint GET /api/certificates/my-requests e GET /api/admin/held-requests supportano ora parametri di query opzionali (?requester=...&template=...&status=...&search=...) consentendo il filtraggio nativo anche via script e automazioni PowerShell/CLI.

### Correzioni & Robustezza

- **Conformità Content Security Policy (CSP) per `admin.html`**:
  - Separata l'intera logica JavaScript del pannello di amministrazione in un file esterno dedicato `wwwroot/js/admin.js`.
  - Risolto il blocco da parte del browser (pannello vuoto) causato dalla direttiva CSP `script-src 'self'` definita in `web.config`.
- **Salvataggio Configurazione ACME in Ambienti IIS Least-Privilege**:
  - Risolta l'eccezione `System.UnauthorizedAccessException` su `appsettings.json.acmetmp` durante il salvataggio delle impostazioni ACME.
  - La scrittura viene ora eseguita direttamente su `appsettings.json` (su cui l'AppPool IIS possiede il diritto di `Modify`), senza tentare di creare file temporanei nella cartella radice protetta in sola `ReadAndExecute`.
## [2.3.2] - 2026-11-04

### Novità & Funzionalità ACME Intranet

- **Supporto IP Privati RFC 1918 per Validazione HTTP-01 (`AllowPrivateIpValidation`)**:
  - Aggiunta l'opzione di configurazione `AcmeConfig.AllowPrivateIpValidation` (default: `false`).
  - Quando abilitata, consente al server ACME di validare challenge HTTP-01 verso server aziendali interni attestati su indirizzi IP privati (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`; CGNAT `100.64.0.0/10`; IPv6 ULA `fc00::/7`).
  - Questa modalità offre un livello di sicurezza notevolmente superiore rispetto ad `AutoApprove` puro, garantendo la *Proof of Possession* / controllo effettivo del server web richiedente anche in ambiente intranet Active Directory.
  - **Difesa Anti-SSRF rigorosa e permanente**: loopback (`127.0.0.0/8`, `::1`), link-local e cloud metadata service (`169.254.0.0/16`, `169.254.169.254`, `fe80::/10`), multicast (`224.0.0.0/4`, `ff00::/8`) e indirizzi non instradabili (`0.0.0.0/8`) restano **sempre categoricamente bloccati**.
  - **Vincolo di sicurezza obbligatorio**: quando `AllowPrivateIpValidation` è attivo, la compilazione dell'allowlist `AllowedDomains` è **obbligatoria** (validata a monte in creazione ordine ACME e nelle API di amministrazione), impedendo a client ACME di usare il portale per effettuare richieste HTTP arbitrarie verso host interni non autorizzati.

### Miglioramenti Admin GUI & i18n

- **Pannello di Amministrazione (`/admin`)**:
  - Aggiunto toggle interattivo **Consenti IP Privati (Intranet RFC 1918)** con testo esplicativo nel tab **🤖 Server ACME**.
  - Traduzioni multilingua complete (IT, EN, FR, DE, ES, PT, ZH) in `i18n.js`.

## [2.3.1] - 2026-11-03

### Sicurezza & Hardening (Security Review Server ACME)

- **Binding CSR↔Ordine (critica)**: `finalize` verifica ora che CN e tutte le SAN DNS del CSR siano contenuto degli identifier dell'ordine ACME; SAN IP, email e URI sono rifiutate. Non è più possibile ottenere un certificato per domini diversi da quelli ordinati/validati (il CSR viene analizzato a livello DER, compatibile con .NET 8).
- **Mitigazione SSRF via http-01 (critica)**: l'identifier della challenge deve essere un hostname DNS pubblico (rifiutati IP letterali, hostname >253, caratteri speciali). Se anche solo uno degli indirizzi risolti è privato/riservato (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, fc00::/7, ecc.) la validazione viene rifiutata. La risposta HTTP del host non viene più ritrasmessa al client: i dettagli restano solo nei log server.
- **Allowlist domini (critica)**: nuovo `AcmeConfig.AllowedDomains` (match esatto o sottodominio). Se non vuota, `new-order` per domini fuori lista → 400 `rejectedIdentifier`. Nelle modalità `AutoApprove`/`Http01WithAutoFallback` la lista è obbligatoria: senza, nessun ordine è accettato. I domini wildcard (`*.`) sono sempre rifiutati.
- **Ownership degli account (alta)**: letture `/acme/account/{id}`, `/acme/order/{id}`, `/acme/authz/{id}` ora richiedono JWS valido: senza firma → 401; con JWS di account diverso → 403 (fix IDOR). JWS con chiave non registrata → 404 `accountDoesNotExist` (autenticazione con chiavi effimere più possibile).
- **Revoca certificati effettiva (alta)**: `revoke-cert` esegue la revoca reale su AD CS (`certutil -revoke` sotto impersonazione dell'account CA); se la revoca fallisce viene restituito 500 (nessun falso successo). I certificati revocati non sono più scaricabili (404).
- **Key change reale (alta)**: `key-change` valida il JWS esterno (chiave vecchia) e quello interno (chiave nuova), verifica la forza della nuova chiave e aggiorna JWK/thumbprint dell'account.
- **Persistenza completa dello stato ACME (alta)**: lo store persiste JWK, thumbprint, associazione ordine↔account, CA, template, request ID, catena certificati e timestamp di revoca: dopo un recycle di IIS gli account mantengono le chiavi e i certificati restano scaricabili.
- **Hardening JWS**: allow-list di algoritmi (niente `none`/sconosciuti), RSA ≥ 2048 bit con esponente valido, curve EC solo P-256/P-384/P-521 (con verifica che alg e curva coincidano), body JWS ≤ 32 KiB, nonce a uso singolo (replay → `badNonce`) con hard cap ed eviction (anti crescita di memoria).
- **Espiry e limiti**: ordini/autorizzazioni scadono (`pending` → `expired`), max 10 identifier per ordine, body challenge ≤ 4 KiB, timeout http-01 gestito per singola richiesta (niente più mutazione del timeout del client condiviso).
- **Enable flag e TLS**: con `AcmeConfig.Enabled = false` gli endpoint `/acme/*` rispondono 503; le richieste HTTP non-localhost vengono redirette a HTTPS (301).
- **Admin API e GUI**: `PUT /api/admin/acme-config` valida Base URL (http/https assoluto), `AllowedTemplates`/`DefaultTemplateName` (regex), `AllowedDomains` (hostname per voce), `TermsOfServiceUrl` e impone `AllowedDomains` non vuota in `AutoApprove`. Scrittura di `appsettings.json` resa atomica (file temporaneo + move). Nuovo campo CSV `AllowedDomains` nel pannello admin.
- **Robustness del logging**: pipeline di logging resa esplicita (solo console) — il provider Windows EventLog di default, in assenza di permesso di scrittura, non fa più crollare le richieste in corso (inclusi i codici di rifiuto di sicurezza).
- **Test di sicurezza automatizzati**: aggiunto `Test-AcmeSecurity.ps1` con 9 scenari di regression (401 anonimi, 404 chiave non registrata, wildcard, allowlist, binding CSR, SAN IP, replay nonce, JWS oversize, IDOR 403).
- **TODO (esterno)**: aggiornare `Microsoft.AspNetCore.Authentication.Negotiate` 8.0.31 → **8.0.32** per CVE-2026-70179 (GHSA-vrrp-6v32-2p8g, elevation of privilege in Negotiate/LDAP). Bloccato in questo ambiente da TLS MITM su nuget.org; è un cambio di una riga in `PkiPortal.csproj` (segnalato con commento TODO).

### Miglioramenti UX

- **Configurazione ACME dal Pannello Admin**:
  - Aggiunto tab **🤖 Server ACME** nel pannello di amministrazione (`/admin`), che permette di leggere e modificare l'intera sezione `AcmeConfig` direttamente dall'interfaccia web, eliminando la necessità di editare manualmente `appsettings.json`.
  - Nuovi campi configurabili via GUI: Abilitato, Base URL, CA Predefinita, Template AD CS, Template Consentiti, Modalità Validazione, Porta HTTP Challenge, Timeout Challenge, Accettazione ToS, URL ToS.
  - Pulsante **🧪 Testa Directory** per verifica live della raggiungibilità dell'endpoint `GET /acme/directory` direttamente dal pannello.
  - Aggiornamento dinamico del link alla directory ACME al cambio del campo Base URL.
  - Lazy load: la configurazione ACME viene caricata solo al primo accesso al tab.
  - Nuovi endpoint API admin protetti (Windows Auth + CSRF): `GET /api/admin/acme-config` e `PUT /api/admin/acme-config`.
  - Fix layout: il campo **Modalità Validazione** ora usa layout verticale con `select` a larghezza piena per evitare il troncamento del testo delle opzioni.

---## [2.3.0] - 2026-11-03

### Funzionalità & Architettura
- **Server ACME RFC 8555 Nativo Integrato**:
  - Implementazione completa del protocollo ACME (RFC 8555) direttamente dentro il runtime ASP.NET Core del portale, eliminando la necessità di proxy o bridge esterni (es. ACME-Server-ADCS, Smallstep, Keyfactor o EJBCA).
  - Piena compatibilità con client ACME standard: **win-acme** (Windows/IIS), **Certbot** (Linux), **Traefik**, **Caddy**, **acme.sh**.
  - Endpoint ACME implementati: `/acme/directory`, `/acme/new-nonce`, `/acme/new-account`, `/acme/account/{id}`, `/acme/account/{id}/orders`, `/acme/new-order`, `/acme/order/{id}`, `/acme/authz/{id}`, `/acme/chall/{authId}/{type}`, `/acme/order/{id}/finalize`, `/acme/cert/{id}`, `/acme/revoke-cert`, `/acme/key-change`, `/acme/terms`.
- **Motore Crittografico ACME (RFC 7515 & RFC 7638)**:
  - Validazione e parsing JWS per firme asimmetriche sia RSA (RS256, RS384, RS512, PS256, PS384, PS512) che ECDSA (ES256, ES384, ES512).
  - Calcolo JWK Thumbprint secondo RFC 7638 per identificazione account e verifica challenge.
- **Validazione Challenge di Dominio (RFC 8555 Sez. 8)**:
  - Supporto challenge `http-01` con verifica automatica porta 80 via `HttpClientFactory`.
  - Modalità `AutoApprove` configurabile per ambienti isolati, air-gapped o lab di collaudo interni.
  - Modalità `Http01WithAutoFallback` per reti aziendali con segmentazione firewall interna.
- **Emissione Diretta su AD CS**:
  - Integrazione nativa del workflow di finalizzazione ACME con `IAdcsService`, mapping con i template AD CS configurati e restituzione della catena X.509 completa (`application/pem-certificate-chain`).
- **Store ACME Thread-Safe con Persistenza Atomica**:
  - Gestione account, ordini, autorizzazioni, challenge e nonce anti-replay con persistenza atomica su `App_Data/acme-store.json`.
- **Script di Collaudo Automatizzato**:
  - Aggiunto `Test-AcmeProtocol.ps1` per test end-to-end completo (generazione chiavi, registrazione, ordine, challenge, CSR, emissione AD CS e verifica certificato X.509).
- **Hardening IIS e Dual-Auth**:
  - Aggiornato `Install-PkiPortal.ps1` per abilitare l'accesso anonimo esclusivamente su `/acme` e `/.well-known`, preservando Windows Authentication (Negotiate) su `/` e `/api/*`.

---
## [2.2.1] - 2026-10-26

### Sicurezza & Hardening
- **Risoluzione avvisi CodeQL**:
  - Mitigazione delle segnalazioni relative a Cross-Site Scripting (XSS), log forging e command injection.
  - Hardening della manipolazione del DOM client-side, sanitizzazione sicura dei messaggi di log e validazione rigorosa dei parametri dei comandi AD CS.

### Incluso
- Tutte le modifiche e funzionalità della v2.2.0, incluso il supporto completo alle lingue Cinese e Portoghese.

---
## [2.2.0] - 2026-10-26

### Funzionalità & Internazionalizzazione

**Supporto nuove lingue: Portoghese (pt) e Cinese (zh)**
- **Estensione i18n (wwwroot/js/i18n.js)**:
  - Aggiunto supporto completo a 7 lingue (**Italiano, Inglese, Francese, Tedesco, Spagnolo, Portoghese, Cinese**) con commutazione dinamica istantanea e persistenza della preferenza utente.
  - Integrate nuove icone SVG ad alta risoluzione per le bandiere del Portogallo (pt) e della Cina (zh).
  - Localizzate tutte le 244 chiavi e stringhe per ciascuna lingua, coprendo wizard crittografico, upload CSR, storico e download certificati/chiavi, amministrazione multi-CA, filtri richieste e messaggi di notifica/errore.
- **Interfaccia Utente (wwwroot/index.html, wwwroot/admin.html)**:
  - Inserite le opzioni Portoghese (Português) e Cinese (中文) nel selettore a discesa .lang-dropdown.
  - Cache-busting e badge versione aggiornati a 2.2.0.
- **Script di installazione e documentazione (Install-PkiPortal.ps1, README.md, README.it.md, DOCUMENTATION.dokuwiki)**:
  - Allineata la versione del portale a 2.2.0 nello script di installazione PowerShell e nella documentazione di progetto.

---
## [2.1.1] - 2026-10-22

### Funzionalità & Correzioni

**Recupero PFX differito configurabile per template (StorePrivateKeyForRetrieval)**
- **Risolto problema recupero PFX per emissione immediata**: nella release 2.1.0 la rimozione dell'invio della chiave privata nei flussi a emissione immediata impediva il successivo recupero del pacchetto .pfx (veniva offerto solo il certificato .crt).
- **Nuovo parametro StorePrivateKeyForRetrieval nei template**:
  - **Attivo di default (	rue)**: durante l'emissione da wizard, la chiave privata generata localmente nel browser viene trasmessa via HTTPS al portale e archiviata cifrata a riposo (DPAPI machine-scope / AES-256-GCM in App_Data/held-requests.json). In questo modo il richiedente originale o gli amministratori autorizzati possono riscaricare o ricostruire in qualsiasi momento il pacchetto .pfx completo (con certificato, chiave privata e catena di certificazione CA).
  - Se configurato su alse, la chiave privata non viene trasmessa al server per i template senza approvazione (modalità zero-knowledge), e il recupero differito consentirà di scaricare unicamente il certificato .crt e la catena .p7b.
- **Supporto nel pannello amministrativo (/admin.html)**: aggiunto toggle "Archivia Chiave per Ritiro PFX" con note esplicative e supporto multilingua (IT, EN, FR, DE, ES) sia per template aggiunti manualmente sia scoperti dalla CA.
- **Esposizione API**: il parametro viene restituito dall'endpoint GET /api/config per guidare il comportamento del client durante l'emissione.

---
## [2.1.0] - 2026-10-15

### Sicurezza (hardening su tutte le aree del portale)

**Installazione e configurazione IIS (`Install-PkiPortal.ps1`, `web.config`)**
- **HTTP in chiaro bloccato by default**: l'installazione senza `-UseHttps` si arresta ora con errore. Per proseguire serve lo switch esplicito `-AllowInsecureHttp` (riservato ad ambienti di test isolati). Con Windows Authentication l'HTTP in chiaro espone gli hash NTLM (capture/relay) e i carichi sensibili del portale (CSR e, nei flussi con approvazione, private key).
- **Extended Protection per NTLM (EPAL)**: `windowsAuthentication` configurato con `extendedProtection:outbound` per proteggere le credenziali da NTLM relay verso altri servizi della LAN.
- **Autenticazione anonima disabilitata** sul sito IIS: ogni richiesta (inclusi i file statici) attraversa il challenge NTLM/Kerberos; il pannello di amministrazione non è più raggiungibile in modo anonimo.
- **Minimo privilegio sul file system**: l'identità dell'App Pool riceve `ReadAndExecute` sulla cartella applicativa (niente più `FullControl` sui binari: impedisce il DLL swap) e `Modify` solo su `appsettings.json` (salvataggio config a runtime), `App_Data` e `logs` (già blindate con ACL esclusive).
- **Header di sicurezza in `web.config`**: `Strict-Transport-Security` (HSTS) e `Content-Security-Policy` restrittiva (solo same-origin, nessun script inline: il preloader del tema e l'handler del pulsante "Annulla Modifiche" sono stati spostati in file esterni, `js/theme-init.js`).

**Esposizione della chiave privata ridotta (`wwwroot/js/app.js`, `wwwroot/js/crypto-helper.js`)**
- Nei flussi a **emissione immediata** la chiave privata **non viene più inviata al server**: `privateKeyPem` viene trasmesso solo per i template con `RequiresApproval` (flusso hold/ritiro differito del PFX, in cui il server deve custodirla cifrata per il ritiro). Nota: per i template con approvazione manuale a livello CA assicurarsi che `RequiresApproval: true` sia impostato nella configurazione del portale.
- **PFX con AES-256-CBC** al posto di 3DES (algoritmo deprecato, vulnerabilità SWEET32).
- **Password del PFX obbligatoria** anche nel flusso "Ritiro Certificati" (prima era opzionale: un PFX con password vuota esponeva la chiave privata).
- **Guard CSPRNG**: se `window.crypto.getRandomValues` non è disponibile (contesto non sicuro o browser obsoleto) il modulo rifiuta di generare chiavi invece di procedere con entropia non garantita.
- Aggiornato il commento d'intestazione di `crypto-helper.js` per documentare accuratamente il ciclo di vita della chiave.

**Anti-CSRF per sessione (`Services/CsrfTokenService.cs`, `Program.cs`, `admin.html`)**
- Il token statico pubblico `"pki-admin"` è stato sostituito da un **token legato all'identità**: payload `utente|scadenza` (30 minuti) firmato con HMAC-SHA256 da un segreto server-side persistito in `App_Data/csrf-secret.bin`. Nuovo endpoint `GET /api/admin/csrf` (solo admin). Il pannello amministrativo ottiene il token all'avvio e lo allega a tutte le richieste mutanti (`X-Pki-Portal-Admin`), con rinnovo automatico prima della scadenza.

**Rate limiting (`Program.cs`)**
- Limitazione delle richieste **per identità** (fallback IP di origine) per mitigare abuso/DoS: 5 req/min per le sottomissioni certificati (`/api/certificates/request`, che avvia processi certreq/certutil), 20 req/min per il parsing CSR, 120 req/min di default su API portale e admin. Rifiuto con HTTP 429.

**LDAP cifrato (`Services/AdcsService.cs`)**
- La lettura della validità dei template da AD parte ora da **LDAPS (porta 636)**: in modalità Hub/CredentialManager la password dell'account di servizio non transita più in chiaro sulla rete. Il fallback su LDAP non cifrato (389) è consentito **solo** quando non sono presenti credenziali esplicite (identità del processo, nessuna password in transito).

**Registrazione credenziali CA (`Add-CaCredential.ps1`)**
- La password non viene più passata come argomento a `cmdkey` (prima `/pass:$plainPass`, visibile nella command line del processo e potenzialmente nei log del shell): con `/pass:` vuoto `cmdkey` chiede la password a prompt interattivo, senza esporla in variabili, command line o log.

**Information disclosure (`Program.cs`)**
- `GET /api/config` non espone più `AllowedGroups` (nomi dei gruppi AD) a ogni utente autenticato: viene restituita solo la flag `IsAllowed` per template.
- Gli errori di `PUT /api/admin/config` non restituiscono più `ex.Message` (i dettagli restano solo nel log del server).

### Vari
- Rimossa dal checkout l'artefatto di sviluppo `.tmp-dpapi-test/`.
- Bump versione a `2.1.0` su `.csproj`, script di installazione, badge navbar e cache-busting dei file statici.

---

## [2.0.12] - 2026-10-14

### Sicurezza & Architettura Crittografica
- **Cifratura Obbligatoria a Riposo delle Chiavi Private (`HeldRequestStore.cs`)**:
  - Eliminata qualsiasi persistenza in chiaro della chiave privata: tutte le chiavi archiviate per la generazione o il ritiro differito del file PFX sono ora rigorosamente cifrate a riposo.
  - Implementata cifratura DPAPI (machine-scope `CRYPTPROTECT_LOCAL_MACHINE` con entropia casuale a 256 bit in `App_Data/store-entropy.bin`) con prefisso `PKEY1:`.
  - Corretti i P/Invoke Win32 su `crypt32.dll` (`CryptProtectData`, `CryptUnprotectData`) con `CharSet = CharSet.Unicode` e rilascio corretto della memoria non gestita tramite `LocalFree` (`kernel32.dll`), prevenendo corruzioni heap o errori di marshaling ANSI.
  - Aggiunto provider crittografico autenticato di fallback / cross-platform basato su **AES-256-GCM** (prefisso `AESGCM1:`) e chiave crittografica a 256 bit in `App_Data/store-key.bin`.
  - Self-test crittografico DPAPI all'avvio: il portale valida l'operatività di DPAPI prima di abilitarlo, commutando automaticamente su AES-256-GCM in caso di anomalie.
  - Rifiuto di salvataggio in chiaro: se nessun modulo crittografico è disponibile, la scrittura su disco della chiave fallisce in modo sicuro con eccezione senza divulgare dati sensibili.
  - **Migrazione automatica trasparente**: all'avvio, eventuali record legacy non cifrati presenti sul disco vengono automaticamente letti, cifrati e riscritti nello store protetto `App_Data/held-requests.json`, bonificando ed eliminando contestualmente copie legacy non protette nella root dell'applicazione.

### Documentazione & Trasparenza
- **Aggiornamento Documentazione (`README.md`, `README.it.md`, `DOCUMENTATION.dokuwiki`)**:
  - Rettificata la descrizione della gestione della chiave privata: chiarito in modo trasparente che, nel wizard con richiesta di pacchetto PFX o approvazione differita, la chiave privata transita su HTTPS protetto ed è custodita a riposo cifrata sul server esclusivamente per consentire al richiedente autorizzato la generazione o il ritiro del pacchetto `.pfx`.
  - Specificato che l'approccio *Zero-Knowledge* (nessun passaggio o tocco sul server della chiave privata) si applica all'invio di CSR generati esternamente (scheda CSR / automazioni REST).
  - Aggiornata la documentazione tecnica DokuWiki (sezioni 1.1, albero file, 8.5 e 12.2) con i dettagli architetturali di DPAPI, AES-256-GCM e le relative garanzie di sicurezza.
- **Interfaccia Utente & Traduzioni i18n (`index.html`, `i18n.js`)**:
  - Aggiornato il sottotitolo dello Step 4 del wizard in tutte le 5 lingue (it, en, fr, de, es) per rispecchiare con precisione la generazione in memoria e la custodia cifrata a riposo sul server.
- **Script di Installazione & Versioning (`Install-PkiPortal.ps1`, `PkiPortal.csproj`)**:
  - Aggiunta la migrazione verso `App_Data` del file chiave `store-key.bin`.
  - Bump versione a `2.0.12` su `.csproj`, script di installazione, navbar e cache-busting dei file statici.

---

## [2.0.11] - 2026-10-12

### Aggiunto & Migliorato
- **Internazionalizzazione Script di Installazione (`Install-PkiPortal.ps1`)**:
  - Rilevamento automatico della lingua del sistema operativo (`CurrentUICulture` / `InstalledUICulture`).
  - Se la lingua del sistema non è l'italiano (`it`), tutti i messaggi, le intestazioni dei passaggi, i warning di sicurezza, i prompt interattivi (`Read-Host`) e il riepilogo finale vengono visualizzati automaticamente in **lingua inglese**.
  - Accettazione unificata degli input utente per le conferme interattive (`S/N` per italiano, `Y/N` per inglese).
- **Versioning**: bump a `2.0.11` su progetto .NET (`PkiPortal.csproj`), badge UI navbar (`index.html`, `admin.html`) e cache-busting delle risorse.

---

## [2.0.10] - 2026-10-12

### Corretto & Migliorato
- **Script di Installazione IIS (`Install-PkiPortal.ps1`)**:
  - Risolto l'errore `Cannot find path 'IIS:\AppPools\...' because it does not exist` al primo avvio su installazioni pulite, proteggendo la verifica dello stato con `Test-Path`.
  - Assegnazione automatica dei permessi NTFS di **FullControl** all'identità dell'Application Pool (inclusi account gMSA) sull'intera cartella di installazione (`$InstallPath`).
  - Auto-inizializzazione del file di configurazione: se `appsettings.json` non è presente (nuova installazione), lo script rinomina in automatico `appsettings.example.json` in `appsettings.json`.
- **Generazione Crittografica Locale nel Browser (`crypto-helper.js`)**:
  - Implementato un meccanismo di auto-recovery e timeout (15s): se i Web Worker non rispondono (es. restrizioni policy o IE ESC su Windows Server), il modulo commuta automaticamente in generazione single-thread (`workers: 0`), sbloccando la generazione della coppia di chiavi e del CSR.
  - Aggiornati i messaggi di avanzamento e le traduzioni i18n in 5 lingue (it, en, fr, de, es).
- **Documentazione (`README.md`, `README.it.md`, `DOCUMENTATION.dokuwiki`)**:
  - Inserite sezioni di **Risoluzione dei Problemi (Troubleshooting)** dedicate al vincolo del **W3C Secure Context (HTTPS)** per le API Web Crypto / Web Worker, ai permessi IIS e alle nuove installazioni.

---

## [2.0.9] - 2026-10-11

### Corretto
- **Fix Errore JavaScript `escapeHtml is not defined` nella Pagina Admin**:
  - Definita la funzione hoisted `escapeHtml()` all'inizio dello script in `admin.html`, prevenendo il `ReferenceError` che bloccava il caricamento della configurazione e delle schede CA/template.
- **Internazionalizzazione (i18n) Pannello Amministrazione & Messaggi di Sistema**:
  - Localizzate le finestre di conferma approvazione (`admin_confirm_approve_req`), inserimento motivo rifiuto (`admin_prompt_reject_req`) e rimozione CA (`confirm_remove_ca`) per tutte le 5 lingue supportate (it, en, fr, de, es).
  - Internazionalizzato il badge utente (`admin_user_label`, es. *"User: ..."* in inglese) con aggiornamento reattivo al cambio di lingua.
  - Tradotti i messaggi di sicurezza 403 Forbidden nel recupero certificati per richieste non associate al proprio account (`access_denied_security_not_owner`).
  - Tradotti i messaggi toast e lo stato di visualizzazione certificato emesso.
- **Accessibilità & Contrasto Tema Chiaro**:
  - Risolto il problema di contrasto nel badge utente (`#portal-user-badge`), ora perfettamente visibile e conforme sia in tema chiaro che in tema scuro.
- **Documentazione**:
  - Inserita galleria screenshot esplicativa (`Screens/`) e allineata la documentazione in italiano e inglese.
- **Versioning**: bump a `2.0.9` (`PkiPortal.csproj`, badge UI in `index.html` e `admin.html`, cache-busting script e fogli di stile `?v=2.0.9`).

---

## [2.0.7] - 2026-10-11

### Aggiunto
- **Informazioni Autore nel Footer**:
  - Inserita l'indicazione dell'autore con relativo link `mailto:` (*Alessandro Tanino*, `mailto:alessandro.tanino@hotmail.com`) nel footer di tutte le pagine (`index.html` e `admin.html`).
  - Aggiunte etichette localizzate nel modulo di internazionalizzazione `i18n.js` per tutte le lingue supportate (it, en, fr, de, es).
  - Regole CSS dedicate nel footer per hover e contrasto sia in tema chiaro che in tema scuro.
- **Versioning**: bump a `2.0.7` (`PkiPortal.csproj`, badge UI in `index.html` e `admin.html`, cache-busting script `?v=2.0.7`).

---

## [2.0.6] - 2026-10-07

### Corretto
- **Sottomissione COM `CCertRequest::Submit` sempre in errore `0x8007000D ERROR_INVALID_DATA`**:
  - Con il flag `CR_IN_BASE64` il metodo `Submit()` richiede la CSR in forma **Base64 del DER PKCS#10**; il codice passava il **testo PEM armato** (`-----BEGIN CERTIFICATE REQUEST-----…`), che COM non riesce a decodificare: ogni sottomissione finiva col fallback su `certreq.exe`.
  - Nuova utility `PemToBase64Der` (rimozione armatura + whitespace) applicata alla CSR prima di `Submit`; rimossa la costante fittizia `CR_IN_FORMATANY` (valore 0x0).
  - Verificato che la conversione produce Base64 valido che decodifica al DER identico al contenuto del PEM (test su certificato reale).
  - Al prossimo avvio, se la via COM funzionerà, il log mostrerà `Risultato COM Submit: disposition=…` senza il warning `Sottomissione via COM fallita`.
- **Versioning**: bump a `2.0.6` (`PkiPortal.csproj`, badge UI, cache-busting script `?v=`).

---

## [2.0.5] - 2026-10-06

### Corretto
- **PFX senza catena: bug client-side nel parsing dei blocchi PEM** (il bug finale):
  - Il regex di `pemChainToCertificates` (`crypto-helper.js`) usava `[A-Z0-9- ]+` tra `BEGIN` e `CERTIFICATE`, che **non matcha i blocchi standard `-----BEGIN CERTIFICATE-----`** (richiede un prefisso di tipo come in `X509 CERTIFICATE`). Il client riceveva la catena dal server ma la scartava silenziosamente: il PFX conteneva sempre solo foglia + chiave. Corretto in `[A-Z0-9- ]*` (tipo opzionale).
- **Catena con foglia e senza Root nei percorsi certreq** (rilevato dai log v2.0.4, Req #270):
  - L'estrazione "nava" `ParseCertreqOutputBytes` dal file `.p7b` **scoraggiava (short-circuit)** `ExtractChainPem`: senza deduplica foglia, senza completamento Root e senza filtro finale. Ora la catena viene **sempre** costruita con `ExtractChainPem` (dedup foglia, completamento store locale/AIA `ocspNoCheck`, filtro finale); l'estrazione nava resta solo come estremo residuo se `ExtractChainPem` non produce nulla.
- **Self-healing al ritiro**: per le richieste già registrate nello store (es. emesse con versioni precedenti), al download l'endpoint di stato **ricostruisce la catena** dai dati originali salvati (P7B + foglia) e aggiorna il record, così anche i PFX ritirati in seguito alla fix contengono la catena completa.
- **Versioning**: bump a `2.0.5` (`PkiPortal.csproj`, badge UI, cache-busting script `?v=`).

---

## [2.0.4] - 2026-10-06

### Corretto & Migliorato
- **Catena ancora incompleta sul server (PFX con foglia + Sub CA ma senza Root)**:
  - **Fallback AIA `ocspNoCheck`**: sui certificati CloudLD l'estensione AIA non contiene `caIssuers`, ma l'URL dell'entry `ocspNoCheck` punta esattamente al certificato dell'emittente. Il server ora usa quel URL (dopo `caIssuers`, se presente) per scaricare l'emittente mancante, **accettando solo il certificato il cui Subject coincide con l'Issuer atteso**.
  - **Parser AIA corretto (RFC 5280)**: parsing ASN.1 dell'estensione AIA adattato alla struttura reale `SEQUENCE OF AccessDescription` (accetta anche la variante con wrapper interno).
  - Verificato sul caso reale: dal certificato `CN=test6.vd.ld` il server scarica `CN=CloudLD Sub CA` da `http://cloudcrl.liguriadigitale.it/CertEnroll/CloudLD%20Sub%20CA.crt` e, per la Sub CA, `CN=Liguria Digitale Root CA` da `http://crl.liguriadigitale.it/CertEnroll/Liguria%20Digitale%20Root%20CA.crt`. Con P7B "solo foglia" (il comportamento del CA CloudLD) la catena finale è `CloudLD Sub CA + Liguria Digitale Root CA`, senza la foglia.
- **Foglia erroneamente inclusa nella catena** (rilevato dal log `Catena certreq Submit` v2.0.3):
  - **Rete di sicurezza finale** in `ExtractChainPem`: dopo tutti i passi di estrazione/completamento, il certificato emesso (per serial) viene rimosso dalla catena.
- **Robustezza parsing del file `.cer` di certreq**:
  - Gestionato il **doppio incapsulamento Base64** (Base64 di Base64/PEM) nel fallback, con validazione "probe" del certificato (subject/issuer/serial non vuoti) per non produrre certificati fittizi da byte arbitrari.
  - **Nuovo log diagnostico**: `File .cer certreq: N byte, inizio: "...", foglia: riconosciuta|NON RICONOSCIUTA` per ogni sottomissione/ritiro.
- **Versioning**: bump a `2.0.4` (`PkiPortal.csproj`, badge UI, cache-busting script `?v=`).

---

## [2.0.3] - 2026-10-06

### Corretto & Migliorato
- **PFX senza catena quando la CA non include i certificati CA nella risposta (es. CloudLD Sub CA)**:
  - **Completamento catena garantito**: se la risposta P7B di AD CS non contiene la catena (opzione CA "Include CA certificates in the chain" disattivata), il server completa ora la catena con:
    - `X509Chain` locale (store di sistema / AIA gestita dal runtime), usando gli elementi risolti anche quando la validazione "fallisce" (es. root non in trust locale);
    - **download esplicito dell'emittente dal URL `caIssuers` dell'estensione AIA** (parsing ASN.1 diretto, max 3 hop), quando presente nel certificato.
  - Verificato sul caso reale CloudLD: con certificato `CN=test6.vd.ld` (emesso da `CN=CloudLD Sub CA`), la catena `CloudLD Sub CA` + `Liguria Digitale Root CA` viene ricostruita e inserita nel PFX.
- **Robustezza parser PKCS#7**: gestito anche il PKCS#7 con armatura (`-----BEGIN PKCS7-----`) nei percorsi di estrazione e normalizzazione.
- **Diagnostica a console**: al via è loggata la versione dell'assembly; per ogni emissione/ritiro viene loggata la riga `Catena ...: input: <formato> -> catena: <soggetti>` che mostra esattamente cosa la CA ha restituito e quali certificati sono stati estratti/completati.
- **Versioning**: bump a `2.0.3` (`PkiPortal.csproj`, badge UI, cache-busting script `?v=`).

---

## [2.0.2] - 2026-10-06

### Corretto
- **Catena Completa nell'Esportazione PFX (.pfx) e P7B (.p7b)**:
  - **PKCS#7 (P7B) non decodificabile**: `X509Certificate2Collection.Import()` non decodifica il PKCS#7 (solo certificati DER singoli/concatenati). Aggiunto un parser ASN.1 deterministico (`TryExtractCertificatesFromPkcs7`) che estrae i certificati dai contenuti `pkcs7-data` (bag con certificati diretti, bag classico AD CS con certificati avvolti in OCTET STRING, variante OCTET STRING RFC 2315) e da `signedData` (campo `certificates [0] IMPLICIT`) dei file `.p7b` di AD CS / `certreq.exe`.
  - **Simulatore**: `SimulateIssuance` genera ora anche un vero P7B (PKCS#7 data bag con certificato emesso + Root CA simulata) nel campo `P7bBase64`, con la stessa semantica dei percorsi reali.
  - **Doppio incapsulamento Base64 del file `.p7b` di `certreq.exe`** (il file è già testo Base64 del PKCS#7): la catena veniva persa in `SubmitViaCertreqAsync` e `RetrieveViaCertreqAsync`. Ora `TryImportCertificates` gestisce DER, PEM multi-blocco, testo Base64 "nudo" e doppi incapsulamenti.
  - **`RetrieveViaCertreqAsync` non estraeva la catena** dal file `.p7b` dedicato (solo dal `.cer` con la sola foglia): ora `CertificateChainPem` è completo anche nel flusso di ritiro.
  - **Completamento catena**: se il P7B non contiene la Root (ultimo certificato non auto-firmato), i livelli superiori mancanti vengono risolti tramite `X509Chain` locale (store di sistema / AIA) e aggiunti alla catena.
  - **P7B client in formato errato**: il pulsante "Scarica Catena (.p7b)" scaricava testo PEM con estensione `.p7b` (PKCS#7 non valido) ignorando il `p7bBase64` del server. Ora scarica il vero PKCS#7 normalizzato (`p7bBase64ToFileText`), con fallback sulla catena PEM come `.crt`; aggiunto il pulsante "Scarica Catena Completa (.p7b)" anche nel flusso di ritiro richieste.
  - **Semantica uniforme di `P7bBase64`**: tutti i percorsi (COM `CR_OUT_CHAIN` e CLI `certreq.exe`) restituiscono il Base64 del contenuto standard del file `.p7b` (PKCS#7 DER in testo Base64, colonne 64), comprensivo di foglia + Sub-CA + Root; il client è retro-compatibile con il formato legacy dei vecchi build (Base64 diretto del DER).
  - `ImportDerOrPkcs7` preferisce `ImportFromPem` per i testi con armatura: su Windows `Import(byte[])` decodifica solo il **primo** blocco PEM (import parziale silenzioso).
- **Versioning**: bump a `2.0.2` (`PkiPortal.csproj`, badge UI, cache-busting script `?v=`).

---

## [2.0.1] - 2026-10-06

### Modificato & Migliorato
- **Inclusione Completa della Catena di Emissione nel PFX (.pfx)**:
  - Garantita l'inclusione di tutti i certificati della catena (Intermediate Sub-CA e Root CA) all'interno dell'archivio PKCS#12 generato, oltre alla chiave privata e al certificato foglia emesso.
  - Migliorata la diagnostica client-side con contatore e tracciamento esplicito dei certificati intermedi inclusi nel bundle PKCS#12 (`CryptoHelper.createPfxBundle`).
  - Ottimizzato `SubmitViaCertreqAsync` per salvare ed estrarre la catena completa `.p7b` anche durante l'emissione diretta via CLI `certreq.exe`.
- **Interfaccia Utente (UI)**:
  - Esposizione del badge di versione `v2.0.1` in piccolo in alto nella barra di navigazione, posizionato accanto al sottotitolo *Active Directory Certificate Services (AD CS) Modern Gateway* sia nel portale utente (`index.html`) che nel pannello di amministrazione (`admin.html`).
  - Aggiunti stili dedicati `.brand-version` con supporto responsive e tema scuro in `styles.css`.
  - Aggiornato il cache-busting degli script JS con `?v=2.0.1`.
- **Configurazione di Progetto**:
  - Aggiunto versioning semantico esplicito in `PkiPortal.csproj` (`<Version>2.0.1</Version>`, `<AssemblyVersion>2.0.1.0</AssemblyVersion>`).

---

## [2.0.0] - 2026-10-03

### Aggiunto
- **Rilascio Ufficiale della Versione 2.0**:
  - Completa migrazione a .NET 8 LTS e HTML5 Web Crypto API.
  - Generazione di chiavi e CSR interamente client-side nel browser (Zero-Knowledge Private Key).
  - Supporto per foreste Active Directory non trustate con integrazione Windows Credential Manager.
  - Connettore Microsoft AD CS nativo ad alte prestazioni tramite interfacce COM DCOM (`CCertRequest`).
  - Fallback automatico su CLI `certreq.exe` per ambienti con policy DCOM restrittive.
  - Supporto per Certificate Templates con approvazione amministrativa (`RequiresApproval`).
  - Store persistente protetto da DPAPI per richieste trattenute (`held-requests.json`).
  - Pannello di amministrazione dedicato (`admin.html`) con gestione e approvazione richieste, configurazione multi-CA e template discovery.
  - Supporto multilingua completo (Italiano / Inglese).
  - Tema chiaro e scuro responsive.
