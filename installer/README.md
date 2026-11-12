# Installer Windows PkiPortal (Inno Setup)

Setup EXE standard Windows che esegue **le stesse operazioni di `Install-PkiPortal.ps1`**,
ma con una finestra wizard per inserire i parametri, e con disinstallatore che rispecchia
`Uninstall-PkiPortal.ps1`.

- Sorgente: [PkiPortal.iss](PkiPortal.iss)
- Output: `..\build\PkiPortal-Setup-2.5.1.exe` (self-extracting, nessuna dipendenza)
- Compilato con **Inno Setup 6.7.3** (API `[Code]` di Inno 6, non 7.x)

I file applicativi sono **pre-pubblicati** (cartella `..\publish`, v2.5.1): il server di
destinazione **non** richiede .NET SDK né accesso a NuGet. Lo script viene lanciato con
`-SkipDotnetPublish` e la fase di build viene sostituita dal bundle embeddato.

## Pagine del wizard e corrispondenza parametri

| Pagina / Campo | Parametro di `Install-PkiPortal.ps1` | Note |
|---|---|---|
| Nome del sito IIS | `-SiteName` | default `PkiWebEnrollment`; validato (no spazi/caratteri speciali) |
| Porta | `-SitePort` | default `8443`, 1–65535 |
| Host header (facoltativo) | `-SiteHostHeader` | vuoto = non passato |
| Percorso di installazione (pagina standard Inno) | `-InstallPath` | default `C:\inetpub\PkiWebEnrollment` |
| Identità del pool | `-AppPoolIdentity` | `ApplicationPoolIdentity` (default), `NetworkService`, `LocalSystem`, o account di dominio (`DOMINIO\utente`) |
| Password account | `-AppPoolPassword` | solo per account di dominio; mai in riga di comando (vedi sotto) |
| gMSA | `-IsGMSA` | nasconde il campo password; lo script aggiungerà il suffisso `$` e il diritto `SeBatchLogonRight` |
| Protocollo | `-UseHttps` / `-AllowInsecureHttp` | **HTTP in chiaro bloccato** senza spunta esplicita (come lo script ≥ 2.1.0) |
| Certificato SSL | `-CertThumbprint` | elenca i certificati di `Cert:\LocalMachine\My` validi con chiave privata; default = auto (più recente, come lo script); alternativa: thumbprint manuale |
| Regola firewall | `-SkipFirewall` | casella "Non creare regola del firewall" |
| Sovrascrivi configurazione | `-OverwriteConfig` | casella nella pagina Opzioni |
| *(sempre)* | `-SkipDotnetPublish` | il bundle pre-pubblicato sostituisce la build |

Pagine extra del wizard (dopo la pagina percorso di Inno): **Parametri sito** →
**Identità del pool** → **Protocollo e certificato** → **Opzioni**.

## Comportamento dell'installazione

1. **Pre-installazione**: arresta sito e application pool esistenti (`appcmd stop
   site/apppool` + kill dei `w3wp.exe` orfani del pool) per liberare le DLL.
2. **Copia file**: bundle `publish\` completo; `appsettings.json` e `web.config` vengono
   copiati **solo alla prima installazione** o con la casella "Sovrascrivi configurazione"
   spuntata (stessa logica dello script). Le cartelle non tracciate (`App_Data`, `logs`)
   non vengono mai toccate.
3. **Esecuzione script**: `Install-PkiPortal.ps1` in una **console visibile**
   (`SW_SHOWNORMAL`): l'amministratore vede l'intero output e può rispondere ai prompt
   interattivi (`Read-Host`) dello script. Il setup **si interrompe con errore** se lo
   script termina con codice diverso da 0.
4. **Post-installazione**: messaggio con gli URL (portale, pannello `/admin`, endpoint
   ACME) e opzione per aprire il pannello nel browser.

### Gestione della password dell'account del pool

La password **non viene mai passata in riga di comando** (visibile in Task Manager / log):

1. Inno la scrive in `HKLM:\Software\PkiPortal\Install` (valore `AppPoolPassword`);
2. il comando PowerShell di avvio la legge **e la rimuove immediatamente** dal registro,
   prima di lanciare lo script (`ConvertTo-SecureString` → `-AppPoolPassword`);
3. a fine installazione (e anche alla disinstallazione) Inno ripulisce la chiave residua.

Durata della presenza in HKLM: qualche secondo, solo in fase di avvio.

### Disinstallazione

Il disinstallatore (Pannello di controllo / `unins000.exe`) esegue prima
`Uninstall-PkiPortal.ps1 -SiteName <salvato> -InstallPath <salvato>` (rimozione sito,
pool, regole firewall) e poi rimuove i file Inno. I parametri salvati usano il
meccanismo `SetPreviousData`/`GetPreviousData` di Inno (database del disinstallatore);
le cartelle `App_Data`/`logs` restano, come nel default dello script.

## Ricostruire l'EXE

Prerequisito: **Inno Setup 6** (es. `winget install JRSoftware.InnoSetup`).

```powershell
.\build-installer.ps1          # cerca ISCC e compila
```

oppure manualmente:

```powershell
& "C:\Users\<utente>\AppData\Local\Programs\Inno Setup 6\ISCC.exe" installer\PkiPortal.iss
```

Per una nuova versione: aggiornare `MyAppVersion` in cima a `PkiPortal.iss` (il nome
output `PkiPortal-Setup-<ver>.exe` segue da solo), rigenerare `..\publish`
(`dotnet publish -c Release`), ricompilare.

## Note e limiti

- **Console visibile**: in modalità silenziosa Inno (`/SILENT`) il wizard viene saltato e
  i valori restano i default; se lo script dovesse fare un `Read-Host` la console resta
  aperta in attesa. Per installazioni non interattive su molti server, valutare un
  seeding dei parametri o l'uso diretto di `Install-PkiPortal.ps1` con parametri.
- **HTTPS + ACME**: il wizard elenca i certificati già presenti in
  `Cert:\LocalMachine\My`; per l'automazione ACME (Let's Encrypt) lasciare "auto":
  lo script sceglie il certificato più recente valido, come al solito.
- **Log**: `SetupLogging=yes` — il log del setup va in `%TEMP%` (es.
  `%TEMP%\PkiPortal Setup 2026-11-06.log`); l'output completo dello script IIS è nella
  console PowerShell mostrata durante l'installazione.
- **IIS assente**: se `inetsrv` non è installato, il pre-arresto viene saltato e lo
  script stesso gestisce i prerequisiti (come lo script originale).
- **64-bit only** (`x64compatible`), Windows 10/Server 2016+ (`MinVersion=6.1sp1`),
  esecuzione con privilegi di amministratore (`PrivilegesRequired=admin`, UAC).
