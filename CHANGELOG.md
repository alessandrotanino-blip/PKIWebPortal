# Changelog

[🇮🇹 Italiano](CHANGELOG.md) | [🇬🇧 English](CHANGELOG.en.md)

Tutte le modifiche rilevanti apportate a questo progetto saranno documentate in questo file.

Il formato è basato su [Keep a Changelog](https://keepachangelog.com/it/1.0.0/) e questo progetto aderisce al [Semantic Versioning](https://semver.org/lang/it/).

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
