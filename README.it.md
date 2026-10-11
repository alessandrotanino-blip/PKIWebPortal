[🇮🇹 Italiano](README.it.md) | [🇬🇧 English](README.md)

# Enterprise PKI Web Enrollment Portal (AD CS Modern Gateway)

Portale web moderno in **HTML5** e **ASP.NET Core 8 (C#)** progettato per sostituire l'obsoleto e deprecato **Microsoft Web Enrollment (`certsrv`)**, eliminando qualsiasi dipendenza da ActiveX/Internet Explorer e mitigando i rischi di sicurezza NTLM Relay (ESC8).

\---

## 🌟 Caratteristiche Principali

1. **Generazione Chiavi Client-Side (HTML5 Web Crypto)**:

   * La coppia di chiavi (RSA 2048/3072/4096 o ECC) viene generata in memoria direttamente all'interno del browser (`window.crypto.subtle`).
   * La **chiave privata non viaggia mai sulla rete né tocca il server**.
   * All'emissione del certificato da parte di AD CS, il browser genera un pacchetto **PKCS#12 (.pfx)** cifrato con password scelta dall'utente, pronto per essere installato su Windows/IIS.
2. **Caricamento CSR Esistente (Base64 / File)**:

   * Supporto per file `.csr` / `.req` generati esternamente (es. server Linux, firewall, switch, apparati di rete).
   * Parsing e ispezione istantanea dei campi del CSR (Subject, SAN, Algoritmo, Dimensione chiave) prima dell'invio.
3. **Architettura Ibrida per Foreste Non Trustate**:

   * **Modalità Standalone (Affiancata a MSCS)**: Installata localmente all'interno di ciascuna foresta, dialoga con la Sub-CA locale senza alcuna modifica firewall cross-forest.
   * **Modalità Hub Multi-CA (DMZ Interna)**: Unico portale esposto in DMZ che consente all'utente di selezionare la CA di destinazione corretta dal menu a tendina.
4. **Integrazione Nativa Microsoft AD CS**:

   * Connessione ad altissime prestazioni tramite l'interfaccia COM Microsoft `CCertRequest` (`CertificateAuthority.Request` da `certcli.dll`).
   * Fallback automatico su `certreq.exe` CLI.
   * Simulatore integrato per sviluppo, test e ambienti offline (attivabile con `"UseSimulator": true`).
5. **Ritiro Sicuro dei Certificati (Pending o già Emessi)**:

   * Permette il recupero del certificato emesso inserendo il *Request ID* o visualizzando la propria tabella *"I Tuoi Certificati"*.
   * **Controllo di proprietà e sicurezza**: il download è consentito esclusivamente all'utente Windows che ha inviato la richiesta originale (`ctx.User.Identity.Name`) o agli amministratori, prevenendo qualsiasi accesso non autorizzato ai certificati altrui (HTTP 403 Forbidden).
6. **Workflow di Approvazione Manuale (Hold & Review)**:

   * Possibilità di impostare `RequiresApproval: true` sui template sensibili.
   * Il certificato generato viene trattenuto dal portale in stato `PendingApproval` e rilasciato all'utente solo dopo l'autorizzazione di un amministratore.
7. **Controllo Accessi Basato sui Ruoli (RBAC sui Template)**:

   * Assegnazione granulare dei template a specifici gruppi Active Directory (`AllowedGroups`). Gli utenti non appartenenti ai gruppi autorizzati non possono emettere con tali template.
8. **Interfaccia Multilingua & Tema Chiaro/Scuro**:

   * Supporto completo per 5 lingue (**Italiano, Inglese, Francese, Tedesco, Spagnolo**) con cambio dinamico istantaneo.
   * Selezione tema Chiaro/Scuro persistente in memoria locale.
9. **REST API per Automazione (win-acme / PowerShell)**:

   * Espone endpoint RESTful per integrare script di rinnovo automatico e client di automazione come `win-acme`.

---

## 📸 Screenshot

### Portale Utente - Nuova Richiesta Certificato
![Portale Utente - Nuova Richiesta](Screens/1-PKI-UserPortal.jpeg)

### Portale Utente - Emissione Automatica & Download PFX
![Emissione Automatica](Screens/1-PKI-UserPortal_Auto.jpeg)

### Portale Utente - Richiesta in Attesa di Approvazione
![In Attesa di Approvazione](Screens/PendingApproval.png)

### Portale Utente - Ritiro Certificati & Storico Utente
![Ritiro Certificati](Screens/2-PKI-UserPortal.jpeg)

### Portale Utente - Template con Accesso Limitato (Gruppi AD)
![Template Ristretti](Screens/DeniedTemplates.png)

### Pannello Amministrazione - Configurazione Portale, CA & Richieste Trattenute
![Pannello Amministrazione](Screens/3-PKI-UserPortal.jpeg)

---

## 📁 Struttura del Progetto

```text
Portale/
├── Models/
│   ├── AdminConfig.cs           # Configurazione autorizzativa amministratori
│   ├── HeldCertificateRequest.cs# Modello e stati delle richieste trattenute
│   ├── PortalConfig.cs          # Modelli di configurazione CA e Template
│   └── EnrollmentDto.cs         # DTO per richieste/risposte e parsing CSR
├── Services/
│   ├── IHeldRequestStore.cs     # Interfaccia archivio richieste trattenute
│   ├── HeldRequestStore.cs      # Store thread-safe con persistenza JSON
│   ├── IAdcsService.cs          # Interfaccia connettore AD CS
│   ├── AdcsService.cs           # Motore COM CCertRequest + certreq.exe + Simulatore
│   └── CsrParserService.cs      # Servizio di parsing CSR X.509
├── wwwroot/
│   ├── css/styles.css           # UI moderna responsive con supporto Dark/Light
│   ├── js/
│   │   ├── vendor/forge.min.js  # Libreria crittografica per PFX/ASN.1
│   │   ├── crypto-helper.js     # Generazione chiavi e PFX client-side
│   │   ├── i18n.js              # Modulo multilingua (IT, EN, FR, DE, ES)
│   │   └── app.js               # Controller applicativo e gestione form
│   ├── index.html               # Portale utente HTML5/SPA
│   └── admin.html               # Pannello amministrativo (Configurazione & Hold)
├── appsettings.json             # Configurazione CA, Template, RBAC e modalità Hub/Standalone
├── Program.cs                   # Entry point e Minimal API
├── web.config                   # Configurazione IIS (ASP.NET Core Module V2)
├── Add-CaCredential.ps1         # Gestione sicura credenziali cross-forest (Credential Manager)
├── Install-PkiPortal.ps1        # Script di installazione su IIS (a fianco di certsrv)
├── Uninstall-PkiPortal.ps1      # Script di disinstallazione pulita
└── run.ps1                      # Script rapido di avvio in sviluppo
```

\---

## 🖥️ Installazione su IIS (a fianco di certsrv)

Lo script `Install-PkiPortal.ps1` installa il portale come **sito IIS separato** sullo stesso server
dove è attivo Microsoft Web Enrollment (certsrv), **senza modificare né interrompere certsrv**.

### Cosa fa lo script di installazione:

1. Verifica e installa le feature IIS necessarie (senza toccare quelle di certsrv).
2. Verifica/installa il .NET 8 ASP.NET Core Hosting Bundle.
3. Compila e pubblica l'applicazione nella cartella di destinazione.
4. Crea un **Application Pool dedicato** (separato da DefaultAppPool/certsrv).
5. Crea un **nuovo sito IIS** su porta e hostname configurabili.
6. Configura permessi file system e regola firewall.
7. Verifica che certsrv resti inalterato e funzionante.

### Prerequisiti

* Windows Server 2016 o successivo con ruolo IIS
* Privilegi di amministratore locale
* .NET 8 SDK (per la compilazione) o .NET 8 Hosting Bundle (per il solo runtime)

### Esempi di installazione

```powershell
# Installazione base: sito HTTP sulla porta 8443
.\\\\Install-PkiPortal.ps1

# Installazione con gMSA (Group Managed Service Account - nessuna password richiesta)
.\\\\Install-PkiPortal.ps1 -SitePort 8443 -AppPoolIdentity "DOMAIN\\\\gmsa$" -IsGMSA

# Installazione HTTPS con hostname personalizzato e account utente standard
.\\\\Install-PkiPortal.ps1 -SitePort 443 `
    -SiteHostHeader "pki.azienda.lan" `
    -UseHttps `
    -CertThumbprint "A1B2C3D4E5F6..." `
    -AppPoolIdentity "DOMINIO\\\\svc-pki-portal" `
    -AppPoolPassword (Read-Host -AsSecureString "Password")

# Installazione su porta custom con nome sito personalizzato
.\\\\Install-PkiPortal.ps1 -SiteName "PKI-Enrollment-F1" -SitePort 9443

# Installazione senza regola firewall (ambienti gestiti centralmente)
.\\\\Install-PkiPortal.ps1 -SitePort 8443 -SkipFirewall
```

### Parametri disponibili

|Parametro|Default|Descrizione|
|-|-|-|
|`-SiteName`|`PkiWebEnrollment`|Nome del sito IIS|
|`-SitePort`|`8443`|Porta TCP di ascolto|
|`-SiteHostHeader`|*(vuoto = tutti)*|Hostname specifico (es. `pki.azienda.lan`)|
|`-InstallPath`|`C:\\\\inetpub\\\\PkiWebEnrollment`|Cartella di pubblicazione|
|`-AppPoolIdentity`|`ApplicationPoolIdentity`|Identità del pool (`NetworkService`, `LocalSystem`, `DOMINIO\\\\Account$` o `DOMINIO\\\\User`)|
|`-AppPoolPassword`|*(nessuna)*|Password per account utente di dominio standard (non necessaria per gMSA)|
|`-IsGMSA`|*(no)*|Specifica che l'identità è un gMSA (senza password, aggiunge `$` se mancante)|
|`-UseHttps`|*(no)*|Abilita binding HTTPS|
|`-CertThumbprint`|*(nessuno)*|Thumbprint del certificato SSL|
|`-SourcePath`|*(directory corrente)*|Percorso del progetto sorgente|
|`-SkipDotnetPublish`|*(no)*|Salta la compilazione (usa file già pubblicati)|
|`-SkipFirewall`|*(no)*|Non crea la regola firewall|

### Disinstallazione

```powershell
# Rimuove sito IIS, app pool e regola firewall (conserva i file)
.\\\\Uninstall-PkiPortal.ps1

# Rimuove tutto inclusi i file applicativi
.\\\\Uninstall-PkiPortal.ps1 -RemoveFiles
```

> \\\*\\\*⚠️ Garanzia di non intrusività\\\*\\\*: Entrambi gli script operano esclusivamente sul sito
> e sull'app pool dedicato al portale PKI. Il sito "Default Web Site" e l'applicazione
> `/CertSrv` \\\*\\\*non vengono mai toccati né modificati\\\*\\\*.

\---

## ⚙️ Configurazione con le Vere Sub-CA

Modificare il file `appsettings.json` (nella cartella di installazione, es. `C:\\\\inetpub\\\\PkiWebEnrollment\\\\appsettings.json`):

### 1\. Modalità Locale (Installazione a fianco di certsrv nella stessa foresta)

In questa modalità non serve alcuna configurazione di credenziali: il portale usa l'identità dell'App Pool IIS (`AuthMode: "LocalIdentity"`).

```json
{
  "PortalConfig": {
    "PortalMode": "Standalone",
    "PortalTitle": "Enterprise PKI Web Enrollment Portal",
    "DefaultCaId": "ca-foresta1",
    "CAs": \\\[
      {
        "Id": "ca-foresta1",
        "DisplayName": "Foresta 1 - Enterprise Issuing CA (Prod)",
        "ForestOrDomain": "foresta1.lan",
        "ConfigString": "subca01.foresta1.lan\\\\\\\\Foresta1-SubCA",
        "IsDefault": true,
        "UseSimulator": false,
        "AuthMode": "LocalIdentity",
        "Templates": \\\[ ... ]
      }
    ]
  }
}
```

### 2\. Modalità Hub Centralizzata (In DMZ verso più foreste NON trustate)

In questa modalità il portale contatta ciascuna Sub-CA usando l'account di servizio specifico di quella foresta, memorizzato in **Windows Credential Manager** (**nessuna password salvata nei file di configurazione!**):

```json
{
  "PortalConfig": {
    "PortalMode": "Hub",
    "PortalTitle": "Enterprise PKI Web Enrollment Portal",
    "DefaultCaId": "ca-foresta1",
    "CAs": \\\[
      {
        "Id": "ca-foresta1",
        "DisplayName": "Foresta 1 - Enterprise Issuing CA",
        "ForestOrDomain": "foresta1.lan",
        "ConfigString": "subca01.foresta1.lan\\\\\\\\Foresta1-SubCA",
        "IsDefault": true,
        "UseSimulator": false,
        "AuthMode": "CredentialManager",
        "CredentialTarget": "subca01.foresta1.lan",
        "Templates": \\\[ ... ]
      },
      {
        "Id": "ca-foresta2",
        "DisplayName": "Foresta 2 - Enterprise Issuing CA (Non Trustata)",
        "ForestOrDomain": "foresta2.lan",
        "ConfigString": "subca02.foresta2.lan\\\\\\\\Foresta2-SubCA",
        "IsDefault": false,
        "UseSimulator": false,
        "AuthMode": "CredentialManager",
        "CredentialTarget": "subca02.foresta2.lan",
        "Templates": \\\[ ... ]
      }
    ]
  }
}
```

\---

## 🔐 Registrazione Sicura Credenziali (Windows Credential Manager)

Per registrare le credenziali degli account di servizio delle diverse foreste **senza mai scrivere password in chiaro**, utilizzare lo script incluso `Add-CaCredential.ps1`:

```powershell
# Registra l'account per la Sub-CA di Foresta 1 (la password viene chiesta con maschera protetta)
.\\\\Add-CaCredential.ps1 -Target "subca01.foresta1.lan" -UserName "FORESTA1\\\\svc-pki-enroll"

# Registra l'account per la Sub-CA di Foresta 2 (foresta separata non trustata)
.\\\\Add-CaCredential.ps1 -Target "subca02.foresta2.lan" -UserName "FORESTA2\\\\svc-pki-enroll"

# Visualizza i target registrati nel Credential Manager
.\\\\Add-CaCredential.ps1 -List

# Rimuove una credenziale memorizzata
.\\\\Add-CaCredential.ps1 -Target "subca02.foresta2.lan" -Remove
```

> \\\*\\\*Come funziona sotto il cofano\\\*\\\*:
> Quando arriva una richiesta per `ca-foresta2`, il backend interroga `Advapi32.dll` (`CredReadW`) per il target `subca02.foresta2.lan`, crea un token di rete sicuro tramite `LogonUser` (`LOGON32\\\_LOGON\\\_NEW\\\_CREDENTIALS`) ed esegue l'operazione (`CCertRequest` / `certreq`) in un blocco `WindowsIdentity.RunImpersonated`. Le chiamate RPC/DCOM verso la CA remota si presentano così con l'account di quella foresta, superando l'assenza di trust.

\---

## 🚀 Avvio Rapido (Sviluppo Locale)

In una console PowerShell:

```powershell
.\\\\run.ps1
```

Oppure manualmente:

```powershell
$env:PATH = "C:\\\\Program Files\\\\dotnet;$env:PATH"
dotnet run --urls "http://127.0.0.1:5055"
```

Quindi aprire il browser all'indirizzo **`http://127.0.0.1:5055`**.

\---

## 🔒 Sicurezza e Best Practice

* **HTTPS**: In ambiente di produzione, usare sempre HTTPS. Lo script di installazione supporta il parametro `-UseHttps -CertThumbprint`.
* **Service Account**: L'Application Pool di IIS deve eseguire con un account che abbia i permessi *Request Certificates* (Enroll) sui template ADCS desiderati. Per la modalità Standalone all'interno della foresta, `NetworkService` o un Managed Service Account è sufficiente.
* **Hardening ESC8**: Questo portale non espone l'endpoint `certsrv` tradizionale. **Nota importante:** il default di installazione risponde su HTTP in chiaro con Windows Authentication (NTLM negoziabile in chiaro sulla rete, rischio relay) e lo script di installazione richiede ora conferma esplicita per il percorso HTTP. In produzione installare **sempre** con `-UseHttps -CertThumbprint` e abilitare Extended Protection for Authentication (EAAL/EPAL) per mitigare il relay.
* **Separazione da certsrv**: Il portale utilizza un sito IIS e un Application Pool completamente separati, garantendo che un problema sul portale non impatti certsrv e viceversa.



---

## 🛡️ Pannello amministrativo e richieste in approvazione

Il portale include `/admin.html`, protetto da Windows Authentication e da una ACL configurabile nella sezione `AdminConfig` di `appsettings.json`. Gli utenti autorizzati sono definiti tramite `AllowedGroups` e `AllowedUsers`; gli altri ricevono `HTTP 403 Forbidden`.

```json
{
  "AdminConfig": {
    "AllowedGroups": [
      "BUILTIN\\Administrators",
      "CONTOSO\\Domain Admins"
    ],
    "AllowedUsers": [
      "CONTOSO\\user-adm"
    ]
  }
}
```

### Workflow di approvazione manuale (Hold & Review)

Quando un template ha `RequiresApproval: true`:
1. L'utente invia la richiesta tramite Web Crypto o CSR esterno.
2. AD CS elabora la richiesta ed emette tecnicamente il certificato.
3. Il portale intercetta il certificato, lo archivia cifrato/protetto in `held-requests.json` e contrassegna la richiesta come `PendingApproval`.
4. L'utente riceve un Hold ID univoco e viene informato che la richiesta è in attesa di approvazione.
5. Il certificato non può essere scaricato finché un amministratore autorizzato non lo approva dal pannello admin.

Dopo l'approvazione, il certificato diventa scaricabile dal richiedente originale tramite la sezione di ritiro certificati. Gli amministratori possono inoltre rifiutare la richiesta registrando una motivazione.

### Stati delle richieste trattenute

| Stato | Descrizione | Azione disponibile |
|---|---|---|
| `PendingApproval` | Certificato trattenuto in attesa di autorizzazione amministrativa. | Approva e rilascia, oppure Rifiuta. |
| `Approved` | Richiesta approvata da un amministratore. | Download del certificato abilitato per il richiedente. |
| `Issued` | Certificato emesso direttamente (template senza approvazione). | Download diretto abilitato. |
| `UnderSubmission` | Richiesta in sospeso sulla CA AD CS stessa (richiesta marcata Pending dalla CA). | Visualizza stato richiesta. |
| `Rejected` | Richiesta rifiutata da un amministratore. | Visualizza motivazione del rifiuto. |

### Endpoint amministrativi

| Metodo | Endpoint | Descrizione | Autorizzazione |
|---|---|---|---|
| GET | `/api/admin/check` | Verifica se l'utente corrente è amministratore | Utente autenticato |
| GET | `/api/admin/config` | Legge l'intera configurazione del portale | Amministratore |
| PUT | `/api/admin/config` | Salva la configurazione e ricarica il provider a caldo | Amministratore |
| POST | `/api/admin/templates/discover` | Scopre i template pubblicati sulla CA tramite DCOM o LDAP | Amministratore |
| GET | `/api/admin/held-requests?status={filter}` | Elenca le richieste trattenute (`pending`, `approved`, `rejected`, `all`) | Amministratore |
| GET | `/api/admin/held-requests/{holdId}` | Mostra il dettaglio di una richiesta e il certificato archiviato | Amministratore |
| POST | `/api/admin/held-requests/{holdId}/approve` | Approva e autorizza il rilascio del certificato | Amministratore |
| POST | `/api/admin/held-requests/{holdId}/reject` | Rifiuta la richiesta con motivazione opzionale | Amministratore |

## 🔎 Scoperta dei template e validità

La funzione di discovery legge dalla definizione del template AD CS l'attributo `pKIDefaultLifetime` tramite Active Directory e converte il valore in giorni. In modalità Hub, la query usa le credenziali della foresta di destinazione; se LDAP non è disponibile, viene usato il fallback:

```powershell
certutil -config "server\CA" -template NomeTemplate
```

La validità viene salvata in `appsettings.json` e mostrata in sola lettura all'amministratore. Per le CA in modalità simulatore, la validità è tratta dalle definizioni mock.

---

## 👤 Autore

**Alessandro Tanino** (<alessandro.tanino@hotmail.com>)
