; ============================================================================
; PkiPortal - Installer Windows (Inno Setup 6)
;
; Standard Windows setup wizard (Inno Setup 6) matching Install-PkiPortal.ps1:
;   - IIS site name, port, host header
;   - Application Pool identity (ApplicationPoolIdentity / NetworkService
;     / LocalSystem / domain account / gMSA) and password
;   - HTTPS protocol (with certificate selection) or cleartext HTTP override
;   - Firewall rules and configuration overwrite options
;
; Pre-published binaries (../publish folder): target server does NOT
; require .NET SDK or NuGet access.
;
; Build:   powershell .\build-installer.ps1
; Output:  ..\build\PkiPortal-Setup-2.5.1.exe
; ============================================================================

#define MyAppName        "PkiPortal"
#define MyAppVersion     "2.5.1"
#define MyAppPublisher   "Enterprise PKI Team"
#define MyAppExeName     "PkiPortal.exe"

[Setup]
AppId={{6E3B7A41-9C2D-4F5E-8A1B-D4C6F9E2B0A3}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} - PKI Web Enrollment Portal
AppPublisher={#MyAppPublisher}
DefaultDirName=C:\inetpub\PkiWebEnrollment
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64os
MinVersion=6.1sp1
WizardStyle=modern
OutputDir=..\build
OutputBaseFilename=PkiPortal-Setup-{#MyAppVersion}
UninstallDisplayName={#MyAppName} (PKI Web Enrollment Portal)
UninstallDisplayIcon={app}\{#MyAppExeName}
LicenseFile=..\LICENSE
Compression=lzma2/max
SolidCompression=yes
SetupLogging=yes
ShowLanguageDialog=yes
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoProductName=PkiPortal

[Languages]
Name: "english";             MessagesFile: "compiler:Default.isl"
Name: "italian";             MessagesFile: "compiler:Languages\Italian.isl"
Name: "french";              MessagesFile: "compiler:Languages\French.isl"
Name: "german";              MessagesFile: "compiler:Languages\German.isl"
Name: "spanish";             MessagesFile: "compiler:Languages\Spanish.isl"
Name: "portuguese";          MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[CustomMessages]
; --- English (Default) ---
english.SitePageCaption=IIS Site Parameters
english.SitePageDesc=Configure the IIS site name, port, and host header for the portal.
english.SiteNameLabel=IIS site name:
english.SitePortLabel=Port:
english.HostHeaderLabel=Host header (optional):
english.IdentityPageCaption=Application Pool Identity
english.IdentityPageDesc=Identity running the IIS pool. Enter a password for a domain account; not required for a gMSA.
english.IdentityLabel=Identity:
english.IdentityAppPool=ApplicationPoolIdentity (default)
english.IdentityNetService=NetworkService
english.IdentityLocalSystem=LocalSystem
english.IdentityDomain=Domain account / gMSA
english.AccountLabel=Account (e.g. DOMAIN\service):
english.PasswordLabel=Password:
english.GMSACheck=Group Managed Service Account (gMSA) - no password
english.ProtocolPageCaption=Protocol and Certificate
english.ProtocolPageDesc=HTTPS is strongly recommended in production: cleartext HTTP exposes NTLM hashes (relay/capture risk).
english.ProtocolLabel=Protocol:
english.ProtocolHttps=HTTPS (recommended)
english.ProtocolHttp=Cleartext HTTP (isolated test environments only)
english.CertLabel=SSL Certificate (LocalMachine\My):
english.CertAuto=(Auto: most recent valid certificate in store)
english.ManualThumbLabel=Thumbprint (manual entry):
english.AllowHttpCheck=Allow unencrypted HTTP installation (isolated test environments ONLY)
english.OptionsPageCaption=Options
english.OptionsPageDesc=Additional installation settings.
english.SkipFirewallCheck=Do not create Windows Firewall rule (-SkipFirewall)
english.OverwriteConfigCheck=Overwrite existing web.config (-OverwriteConfig)
english.ErrSiteNameRequired=Please enter a name for the IIS site.
english.ErrSiteNameInvalid=The IIS site name must not contain spaces, quotes, or special characters.
english.ErrPortInvalid=Invalid port: enter a number between 1 and 65535.
english.ErrHostHeaderInvalid=The host header must not contain quotes or slashes.
english.ErrInstallPathInvalid=The installation path must not contain quotes or apostrophes.
english.ErrAccountRequired=Please enter the account (e.g. DOMAIN\service or DOMAIN\gmsa$).
english.ErrAccountInvalid=The account name must not contain quotes or apostrophes.
english.ErrPasswordRequired=Please enter the account password, or check gMSA if it is a Group Managed Service Account.
english.ErrHttpBlocked=Installation over unencrypted HTTP is BLOCKED (cleartext NTLM: risk of hash capture, NTLM relay, and exposure of sensitive portal payloads).%n%nSelect HTTPS or check "Allow unencrypted HTTP installation" (isolated test environments only).
english.ErrPowerShellFailed=Unable to launch PowerShell for IIS installation. The installation was not completed.
english.ErrScriptFailed=Installation NOT completed: Install-PkiPortal.ps1 terminated with exit code %1.%n%nDetailed log available at:%n%TEMP%\PkiPortal-Install.log%n%nPlease review the error details, then rerun setup or run the script manually.
english.MsgSuccess=Installation completed successfully.%n%nPortal:    %1%nAdmin:     %2%nACME:      %3%n%nNext steps: configure real Sub-CAs in %4\appsettings.json and verify AppPool identity permissions on AD CS templates.%n%nOpen the administration panel in your browser now?
english.UpgradePageCaption=Previous Version Detected
english.UpgradePageDesc=An existing installation of PkiPortal was found on this server.
english.UpgradeInfoTemplate=Existing installation details:%n• Installed Version: %1%n• Installation Folder: %2%n• IIS Site: %3 (Port: %4, Protocol: %5)%n• Application Pool: %6
english.UpgradeModeQuick=Fast upgrade (recommended)
english.UpgradeModeQuickDesc=Update application files preserving IIS site, ports, certificates, AppPool identity, and configuration without prompting.
english.UpgradeModeCustom=Custom installation (modify parameters)
english.UpgradeModeCustomDesc=Allows modifying the installation path, IIS site name, port, certificate, or AppPool credentials.
english.UpgradeModeClean=Clean installation (reset parameters)
english.UpgradeModeCleanDesc=Resets all parameters to defaults, ignores previous settings, and overwrites existing configuration.
english.ReadyMemoUpgradeTitle=Installation Mode: Fast Upgrade
english.ReadyMemoPrevVersion=Previous version:
english.ReadyMemoInstallDir=Installation folder:
english.ReadyMemoSite=IIS Site:
english.ReadyMemoProtocol=Protocol:
english.ReadyMemoIdentity=Pool identity:
english.ReadyMemoPreserveNote=Existing configuration (appsettings.json), logs, and IIS settings will be preserved.

; --- Italian ---
italian.SitePageCaption=Parametri del sito IIS
italian.SitePageDesc=Configura nome, porta e host header del sito IIS del portale.
italian.SiteNameLabel=Nome del sito IIS:
italian.SitePortLabel=Porta:
italian.HostHeaderLabel=Host header (facoltativo):
italian.IdentityPageCaption=Identità dell'Application Pool
italian.IdentityPageDesc=Identità con cui gira il pool IIS. Per un account di dominio inserire la password; per un gMSA non è necessaria.
italian.IdentityLabel=Identità:
italian.IdentityAppPool=ApplicationPoolIdentity (predefinita)
italian.IdentityNetService=NetworkService
italian.IdentityLocalSystem=LocalSystem
italian.IdentityDomain=Account di dominio / gMSA
italian.AccountLabel=Account (es. DOMINIO\servizio):
italian.PasswordLabel=Password:
italian.GMSACheck=Group Managed Service Account (gMSA) - senza password
italian.ProtocolPageCaption=Protocollo e certificato
italian.ProtocolPageDesc=HTTPS è fortemente consigliato in produzione: in HTTP in chiaro NTLM viaggia non cifrato (rischio capture/relay).
italian.ProtocolLabel=Protocollo:
italian.ProtocolHttps=HTTPS (consigliato)
italian.ProtocolHttp=HTTP in chiaro (solo ambienti di test isolati)
italian.CertLabel=Certificato SSL (LocalMachine\My):
italian.CertAuto=(Auto: più recente certificato valido nello store)
italian.ManualThumbLabel=Thumbprint (immissione manuale):
italian.AllowHttpCheck=Consenti installazione su HTTP in chiaro (SOLO test isolati)
italian.OptionsPageCaption=Opzioni
italian.OptionsPageDesc=Impostazioni aggiuntive dell'installazione.
italian.SkipFirewallCheck=Non creare regola del firewall Windows (-SkipFirewall)
italian.OverwriteConfigCheck=Sovrascrivi web.config esistente (-OverwriteConfig)
italian.ErrSiteNameRequired=Inserire un nome per il sito IIS.
italian.ErrSiteNameInvalid=Il nome del sito IIS non deve contenere spazi, virgolette o caratteri speciali.
italian.ErrPortInvalid=Porta non valida: inserire un numero tra 1 e 65535.
italian.ErrHostHeaderInvalid=L'host header non deve contenere virgolette o slash.
italian.ErrInstallPathInvalid=Il percorso di installazione non deve contenere apostrofi o virgolette.
italian.ErrAccountRequired=Inserire l'account (es. DOMINIO\servizio o DOMINIO\gmsa$).
italian.ErrAccountInvalid=Il nome account non deve contenere apostrofi o virgolette.
italian.ErrPasswordRequired=Inserire la password dell'account, oppure spuntare gMSA se è un Group Managed Service Account.
italian.ErrHttpBlocked=Installazione su HTTP in chiaro BLOCCATA (NTLM non cifrato: rischio capture degli hash, NTLM relay e esposizione dei carichi sensibili del portale).%n%nSelezionare HTTPS oppure spuntare "Consenti installazione su HTTP in chiaro" (solo ambienti di test isolati).
italian.ErrPowerShellFailed=Impossibile avviare PowerShell per l'installazione di IIS. L'installazione non è stata completata.
italian.ErrScriptFailed=Installazione NON completata: Install-PkiPortal.ps1 ha terminato con codice %1.%n%nLog dettagliato disponibile in:%n%TEMP%\PkiPortal-Install.log%n%nRivedere gli errori, poi rieseguire il setup o lo script manuale.
italian.MsgSuccess=Installazione completata con successo.%n%nPortale:    %1%nPannello:   %2%nACME:       %3%n%nProssimi passi: configurare le Sub-CA reali in %4\appsettings.json e verificare i permessi dell'identità del pool sui template AD CS.%n%nAprire ora il pannello di amministrazione nel browser?
italian.UpgradePageCaption=Versione precedente rilevata
italian.UpgradePageDesc=È stata trovata un'installazione esistente di PkiPortal su questo server.
italian.UpgradeInfoTemplate=Dettagli installazione esistente:%n• Versione installata: %1%n• Cartella di installazione: %2%n• Sito IIS: %3 (Porta: %4, Protocollo: %5)%n• Application Pool: %6
italian.UpgradeModeQuick=Aggiornamento rapido (consigliato)
italian.UpgradeModeQuickDesc=Aggiorna i file applicativi preservando sito IIS, porte, certificati, identità del pool e configurazione senza ulteriori richieste.
italian.UpgradeModeCustom=Installazione personalizzata (modifica parametri)
italian.UpgradeModeCustomDesc=Consente di modificare il percorso di installazione, il sito IIS, le porte, i certificati o l'identità del pool.
italian.UpgradeModeClean=Nuova installazione pulita (reimposta parametri)
italian.UpgradeModeCleanDesc=Reimposta tutti i parametri ai valori predefiniti, ignora la configurazione esistente e sovrascrive i file di configurazione.
italian.ReadyMemoUpgradeTitle=Modalità di installazione: Aggiornamento rapido
italian.ReadyMemoPrevVersion=Versione precedente:
italian.ReadyMemoInstallDir=Cartella di installazione:
italian.ReadyMemoSite=Sito IIS:
italian.ReadyMemoProtocol=Protocollo:
italian.ReadyMemoIdentity=Identità pool:
italian.ReadyMemoPreserveNote=La configurazione esistente (appsettings.json), i log e le impostazioni IIS saranno preservati.

; --- French ---
french.SitePageCaption=Paramètres du site IIS
french.SitePageDesc=Configurez le nom, le port et l'en-tête d'hôte du site IIS du portail.
french.SiteNameLabel=Nom du site IIS :
french.SitePortLabel=Port :
french.HostHeaderLabel=En-tête d'hôte (facultatif) :
french.IdentityPageCaption=Identité du pool d'applications
french.IdentityPageDesc=Identité exécutant le pool IIS. Entrez un mot de passe pour un compte de domaine ; non requis pour un gMSA.
french.IdentityLabel=Identité :
french.IdentityAppPool=ApplicationPoolIdentity (par défaut)
french.IdentityNetService=NetworkService
french.IdentityLocalSystem=LocalSystem
french.IdentityDomain=Compte de domaine / gMSA
french.AccountLabel=Compte (ex. DOMAINE\service) :
french.PasswordLabel=Mot de passe :
french.GMSACheck=Group Managed Service Account (gMSA) - sans mot de passe
french.ProtocolPageCaption=Protocole et certificat
french.ProtocolPageDesc=HTTPS est fortement recommandé en production : HTTP en clair expose les hash NTLM (risque capture/relais).
french.ProtocolLabel=Protocole :
french.ProtocolHttps=HTTPS (recommandé)
french.ProtocolHttp=HTTP en clair (environnements de test isolés uniquement)
french.CertLabel=Certificat SSL (LocalMachine\My) :
french.CertAuto=(Auto : certificat valide le plus récent dans le magasin)
french.ManualThumbLabel=Empreinte (saisie manuelle) :
french.AllowHttpCheck=Autoriser l'installation en HTTP clair (tests isolés UNIQUEMENT)
french.OptionsPageCaption=Options
french.OptionsPageDesc=Paramètres d'installation supplémentaires.
french.SkipFirewallCheck=Ne pas créer de règle de pare-feu Windows (-SkipFirewall)
french.OverwriteConfigCheck=Écraser web.config existant (-OverwriteConfig)
french.ErrSiteNameRequired=Veuillez saisir un nom pour le site IIS.
french.ErrSiteNameInvalid=Le nom du site IIS ne doit pas contenir d'espaces, de guillemets ou de caractères spéciaux.
french.ErrPortInvalid=Port invalide : entrez un nombre entre 1 et 65535.
french.ErrHostHeaderInvalid=L'en-tête d'hôte ne doit pas contenir de guillemets ou de barres obliques.
french.ErrInstallPathInvalid=Le chemin d'installation ne doit pas contenir d'apostrophes ou de guillemets.
french.ErrAccountRequired=Veuillez entrer le compte (ex. DOMAINE\service ou DOMAINE\gmsa$).
french.ErrAccountInvalid=Le nom de compte ne doit pas contenir d'apostrophes ou de guillemets.
french.ErrPasswordRequired=Veuillez entrer le mot de passe, ou cochez gMSA s'il s'agit d'un gMSA.
french.ErrHttpBlocked=Installation en HTTP clair BLOQUÉE (NTLM non chiffré : risque de capture et relais NTLM).%n%nSélectionnez HTTPS ou cochez "Autoriser l'installation en HTTP clair".
french.ErrPowerShellFailed=Impossible de lancer PowerShell pour l'installation d'IIS.
french.ErrScriptFailed=Installation NON terminée : Install-PkiPortal.ps1 s'est terminé avec le code %1.
french.MsgSuccess=Installation terminée avec succès.%n%nPortail :    %1%nAdmin :      %2%nACME :       %3%n%nÉtapes suivantes : configurez les sous-CA dans %4\appsettings.json.%n%nOuvrir le panneau d'administration dans le navigateur ?
french.UpgradePageCaption=Version précédente détectée
french.UpgradePageDesc=Une installation existante de PkiPortal a été détectée sur ce serveur.
french.UpgradeInfoTemplate=Détails de l'installation existante :%n• Version installée : %1%n• Dossier d'installation : %2%n• Site IIS : %3 (Port : %4, Protocole : %5)%n• Application Pool : %6
french.UpgradeModeQuick=Mise à niveau rapide (recommandé)
french.UpgradeModeQuickDesc=Met à jour les fichiers applicatifs en conservant le site IIS, les ports, les certificats, l'identité du pool et la configuration.
french.UpgradeModeCustom=Installation personnalisée (modifier les paramètres)
french.UpgradeModeCustomDesc=Permet de modifier le dossier d'installation, le site IIS, les ports, les certificats ou l'identité du pool.
french.UpgradeModeClean=Nouvelle installation propre (réinitialiser les paramètres)
french.UpgradeModeCleanDesc=Réinitialise tous les paramètres par défaut, ignore la configuration existante et écrase les fichiers de configuration.
french.ReadyMemoUpgradeTitle=Mode d'installation : Mise à niveau rapide
french.ReadyMemoPrevVersion=Version précédente :
french.ReadyMemoInstallDir=Dossier d'installation :
french.ReadyMemoSite=Site IIS :
french.ReadyMemoProtocol=Protocole :
french.ReadyMemoIdentity=Identité du pool :
french.ReadyMemoPreserveNote=La configuration existante (appsettings.json), les journaux et les paramètres IIS seront préservés.

; --- German ---
german.SitePageCaption=IIS-Site-Parameter
german.SitePageDesc=Konfigurieren Sie Name, Port und Host-Header der IIS-Site des Portals.
german.SiteNameLabel=IIS-Site-Name:
german.SitePortLabel=Port:
german.HostHeaderLabel=Host-Header (optional):
german.IdentityPageCaption=Identität des Anwendungspools
german.IdentityPageDesc=Identität, unter der der IIS-Pool ausgeführt wird. Kennwort für ein Domänenkonto eingeben; für gMSA nicht erforderlich.
german.IdentityLabel=Identität:
german.IdentityAppPool=ApplicationPoolIdentity (Standard)
german.IdentityNetService=NetworkService
german.IdentityLocalSystem=LocalSystem
german.IdentityDomain=Domänenkonto / gMSA
german.AccountLabel=Konto (z. B. DOMÄNE\Dienst):
german.PasswordLabel=Kennwort:
german.GMSACheck=Group Managed Service Account (gMSA) - kein Kennwort
german.ProtocolPageCaption=Protokoll und Zertifikat
german.ProtocolPageDesc=HTTPS wird in der Produktion dringend empfohlen: Unverschlüsseltes HTTP legt NTLM-Hashes offen.
german.ProtocolLabel=Protokoll:
german.ProtocolHttps=HTTPS (empfohlen)
german.ProtocolHttp=Klartext-HTTP (nur für isolierte Testumgebungen)
german.CertLabel=SSL-Zertifikat (LocalMachine\My):
german.CertAuto=(Auto: Neuestes gültiges Zertifikat im Speicher)
german.ManualThumbLabel=Fingerabdruck (manuelle Eingabe):
german.AllowHttpCheck=Installation über Klartext-HTTP zulassen (NUR isolierte Tests)
german.OptionsPageCaption=Optionen
german.OptionsPageDesc=Zusätzliche Installationseinstellungen.
german.SkipFirewallCheck=Keine Windows-Firewall-Regel erstellen (-SkipFirewall)
german.OverwriteConfigCheck=Vorhandene web.config überschreiben (-OverwriteConfig)
german.ErrSiteNameRequired=Bitte geben Sie einen Namen für die IIS-Site ein.
german.ErrSiteNameInvalid=Der Name der IIS-Site darf keine Leerzeichen, Anführungszeichen oder Sonderzeichen enthalten.
german.ErrPortInvalid=Ungültiger Port: Geben Sie eine Zahl zwischen 1 und 65535 ein.
german.ErrHostHeaderInvalid=Der Host-Header darf keine Anführungszeichen oder Schrägstriche enthalten.
german.ErrInstallPathInvalid=Der Installationspfad darf keine Apostrophe oder Anführungszeichen enthalten.
german.ErrAccountRequired=Bitte geben Sie das Konto ein (z. B. DOMÄNE\Dienst oder DOMÄNE\gmsa$).
german.ErrAccountInvalid=Der Kontoname darf keine Apostrophe oder Anführungszeichen enthalten.
german.ErrPasswordRequired=Bitte geben Sie das Kennwort ein oder aktivieren Sie gMSA.
german.ErrHttpBlocked=Installation über Klartext-HTTP BLOCKIERT (NTLM unverschlüsselt).%n%nWählen Sie HTTPS oder aktivieren Sie "Installation über Klartext-HTTP zulassen".
german.ErrPowerShellFailed=PowerShell konnte für die IIS-Installation nicht gestartet werden.
german.ErrScriptFailed=Installation NICHT abgeschlossen: Install-PkiPortal.ps1 wurde mit Code %1 beendet.
german.MsgSuccess=Installation erfolgreich abgeschlossen.%n%nPortal:    %1%nAdmin:     %2%nACME:      %3%n%nNächste Schritte: Konfigurieren Sie die Sub-CAs in %4\appsettings.json.%n%nAdministrationsbereich jetzt im Browser öffnen?
german.UpgradePageCaption=Vorherige Version erkannt
german.UpgradePageDesc=Eine vorhandene Installation von PkiPortal wurde auf diesem Server gefunden.
german.UpgradeInfoTemplate=Details der vorhandenen Installation:%n• Installierte Version: %1%n• Installationsordner: %2%n• IIS-Site: %3 (Port: %4, Protokoll: %5)%n• Application Pool: %6
german.UpgradeModeQuick=Schnelles Upgrade (empfohlen)
german.UpgradeModeQuickDesc=Aktualisiert Anwendungsdateien unter Beibehaltung von IIS-Site, Ports, Zertifikaten, Pool-Identität und Konfiguration.
german.UpgradeModeCustom=Benutzerdefinierte Installation (Parameter ändern)
german.UpgradeModeCustomDesc=Ermöglicht das Anpassen von Installationspfad, IIS-Site, Ports, Zertifikaten oder Pool-Identität.
german.UpgradeModeClean=Saubere Neuinstallation (Parameter zurücksetzen)
german.UpgradeModeCleanDesc=Setzt alle Parameter auf Standardwerte zurück, ignoriert vorherige Einstellungen und überschreibt die Konfiguration.
german.ReadyMemoUpgradeTitle=Installationsmodus: Schnelles Upgrade
german.ReadyMemoPrevVersion=Vorherige Version:
german.ReadyMemoInstallDir=Installationsordner:
german.ReadyMemoSite=IIS-Site:
german.ReadyMemoProtocol=Protokoll:
german.ReadyMemoIdentity=Pool-Identität:
german.ReadyMemoPreserveNote=Bestehende Konfiguration (appsettings.json), Protokolle und IIS-Einstellungen bleiben erhalten.

; --- Spanish ---
spanish.SitePageCaption=Parámetros del sitio IIS
spanish.SitePageDesc=Configure el nombre, puerto y encabezado de host del sitio IIS del portal.
spanish.SiteNameLabel=Nombre del sitio IIS:
spanish.SitePortLabel=Puerto:
spanish.HostHeaderLabel=Encabezado de host (opcional):
spanish.IdentityPageCaption=Identidad del grupo de aplicaciones
spanish.IdentityPageDesc=Identidad con la que se ejecuta el grupo IIS. Ingrese contraseña para cuenta de dominio; no requerida para gMSA.
spanish.IdentityLabel=Identidad:
spanish.IdentityAppPool=ApplicationPoolIdentity (predeterminada)
spanish.IdentityNetService=NetworkService
spanish.IdentityLocalSystem=LocalSystem
spanish.IdentityDomain=Cuenta de dominio / gMSA
spanish.AccountLabel=Cuenta (ej. DOMINIO\servicio):
spanish.PasswordLabel=Contraseña:
spanish.GMSACheck=Group Managed Service Account (gMSA) - sin contraseña
spanish.ProtocolPageCaption=Protocolo y certificado
spanish.ProtocolPageDesc=HTTPS es muy recomendado en producción: HTTP en texto plano expone hashes NTLM (riesgo de captura/retransmisión).
spanish.ProtocolLabel=Protocolo:
spanish.ProtocolHttps=HTTPS (recomendado)
spanish.ProtocolHttp=HTTP en texto plano (solo entornos de prueba aislados)
spanish.CertLabel=Certificado SSL (LocalMachine\My):
spanish.CertAuto=(Auto: certificado válido más reciente en el almacén)
spanish.ManualThumbLabel=Huella digital (entrada manual):
spanish.AllowHttpCheck=Permitir instalación en HTTP en texto plano (SOLO pruebas aisladas)
spanish.OptionsPageCaption=Opciones
spanish.OptionsPageDesc=Configuración adicional de instalación.
spanish.SkipFirewallCheck=No crear regla de firewall de Windows (-SkipFirewall)
spanish.OverwriteConfigCheck=Sobrescribir web.config existente (-OverwriteConfig)
spanish.ErrSiteNameRequired=Ingrese un nombre para el sitio IIS.
spanish.ErrSiteNameInvalid=El nombre del sitio IIS no debe contener espacios, comillas ni caracteres especiales.
spanish.ErrPortInvalid=Puerto no válido: ingrese un número entre 1 y 65535.
spanish.ErrHostHeaderInvalid=El encabezado de host no debe contener comillas ni barras.
spanish.ErrInstallPathInvalid=La ruta de instalación no debe contener comillas ni apóstrofes.
spanish.ErrAccountRequired=Ingrese la cuenta (ej. DOMINIO\servicio o DOMINIO\gmsa$).
spanish.ErrAccountInvalid=El nombre de cuenta no debe contener comillas ni apóstrofes.
spanish.ErrPasswordRequired=Ingrese la contraseña de la cuenta, o marque gMSA.
spanish.ErrHttpBlocked=Instalación en HTTP en texto plano BLOQUEADA (NTLM no cifrado).%n%nSeleccione HTTPS o marque "Permitir instalación en HTTP en texto plano".
spanish.ErrPowerShellFailed=No se pudo iniciar PowerShell para la instalación de IIS.
spanish.ErrScriptFailed=Instalación NO completada: Install-PkiPortal.ps1 terminó con código %1.
spanish.MsgSuccess=Instalación completada con éxito.%n%nPortal:    %1%nAdmin:     %2%nACME:      %3%n%nPróximos pasos: configure las Sub-CA en %4\appsettings.json.%n%n¿Abrir el panel de administración en el navegador ahora?
spanish.UpgradePageCaption=Versión anterior detectada
spanish.UpgradePageDesc=Se ha encontrado una instalación existente de PkiPortal en este servidor.
spanish.UpgradeInfoTemplate=Detalles de la instalación existente:%n• Versión instalada: %1%n• Carpeta de instalación: %2%n• Sitio IIS: %3 (Puerto: %4, Protocolo: %5)%n• Application Pool: %6
spanish.UpgradeModeQuick=Actualización rápida (recomendado)
spanish.UpgradeModeQuickDesc=Actualiza los archivos de la aplicación conservando el sitio IIS, puertos, certificados, identidad del grupo y configuración.
spanish.UpgradeModeCustom=Instalación personalizada (modificar parámetros)
spanish.UpgradeModeCustomDesc=Permite modificar la ruta de instalación, el sitio IIS, los puertos, los certificados o la identidad del grupo.
spanish.UpgradeModeClean=Nueva instalación limpia (restablecer parámetros)
spanish.UpgradeModeCleanDesc=Restablece todos los parámetros a los valores predeterminados, ignora la configuración previa y sobrescribe la configuración.
spanish.ReadyMemoUpgradeTitle=Modo de instalación: Actualización rápida
spanish.ReadyMemoPrevVersion=Versión anterior:
spanish.ReadyMemoInstallDir=Carpeta de instalación:
spanish.ReadyMemoSite=Sitio IIS:
spanish.ReadyMemoProtocol=Protocolo:
spanish.ReadyMemoIdentity=Identidad del grupo:
spanish.ReadyMemoPreserveNote=La configuración existente (appsettings.json), registros y ajustes de IIS se conservarán.

; --- Portuguese ---
portuguese.SitePageCaption=Parâmetros do site IIS
portuguese.SitePageDesc=Configure o nome, porta e cabeçalho de host do site IIS do portal.
portuguese.SiteNameLabel=Nome do site IIS:
portuguese.SitePortLabel=Porta:
portuguese.HostHeaderLabel=Cabeçalho de host (opcional):
portuguese.IdentityPageCaption=Identidade do Application Pool
portuguese.IdentityPageDesc=Identidade executando o pool IIS. Insira a senha para conta de domínio; não necessária para gMSA.
portuguese.IdentityLabel=Identidade:
portuguese.IdentityAppPool=ApplicationPoolIdentity (padrão)
portuguese.IdentityNetService=NetworkService
portuguese.IdentityLocalSystem=LocalSystem
portuguese.IdentityDomain=Conta de domínio / gMSA
portuguese.AccountLabel=Conta (ex. DOMINIO\serviço):
portuguese.PasswordLabel=Senha:
portuguese.GMSACheck=Group Managed Service Account (gMSA) - sem senha
portuguese.ProtocolPageCaption=Protocolo e certificado
portuguese.ProtocolPageDesc=HTTPS é fortemente recomendado em produção: HTTP em texto simples expõe hashes NTLM.
portuguese.ProtocolLabel=Protocolo:
portuguese.ProtocolHttps=HTTPS (recomendado)
portuguese.ProtocolHttp=HTTP em texto simples (apenas ambientes de teste isolados)
portuguese.CertLabel=Certificado SSL (LocalMachine\My):
portuguese.CertAuto=(Auto: certificado válido mais recente no repositório)
portuguese.ManualThumbLabel=Thumbprint (inserção manual):
portuguese.AllowHttpCheck=Permitir instalação em HTTP em texto simples (APENAS testes isolados)
portuguese.OptionsPageCaption=Opções
portuguese.OptionsPageDesc=Configurações adicionais de instalação.
portuguese.SkipFirewallCheck=Não criar regra de firewall do Windows (-SkipFirewall)
portuguese.OverwriteConfigCheck=Substituir web.config existente (-OverwriteConfig)
portuguese.ErrSiteNameRequired=Insira um nome para o site IIS.
portuguese.ErrSiteNameInvalid=O nome do site IIS não deve conter espaços, aspas ou caracteres especiais.
portuguese.ErrPortInvalid=Porta inválida: insira um número entre 1 e 65535.
portuguese.ErrHostHeaderInvalid=O cabeçalho de host não deve conter aspas ou barras.
portuguese.ErrInstallPathInvalid=O caminho de instalação não deve conter apóstrofos ou aspas.
portuguese.ErrAccountRequired=Insira a conta (ex. DOMINIO\serviço ou DOMINIO\gmsa$).
portuguese.ErrAccountInvalid=O nome da conta não deve conter apóstrofos ou aspas.
portuguese.ErrPasswordRequired=Insira a senha da conta ou marque gMSA.
portuguese.ErrHttpBlocked=Instalação em HTTP em texto simples BLOQUEADA (NTLM não criptografado).%n%nSelecione HTTPS ou marque "Permitir instalação em HTTP em texto simples".
portuguese.ErrPowerShellFailed=Não foi possível iniciar o PowerShell para instalação do IIS.
portuguese.ErrScriptFailed=Instalação NÃO concluída: Install-PkiPortal.ps1 terminou com código %1.
portuguese.MsgSuccess=Instalação concluída com sucesso.%n%nPortal:    %1%nAdmin:     %2%nACME:      %3%n%nPróximos passos: configure as Sub-CAs em %4\appsettings.json.%n%nAbrir o painel de administração no navegador agora?
portuguese.UpgradePageCaption=Versão anterior detetada
portuguese.UpgradePageDesc=Foi encontrada uma instalação existente do PkiPortal neste servidor.
portuguese.UpgradeInfoTemplate=Detalhes da instalação existente:%n• Versão instalada: %1%n• Pasta de instalação: %2%n• Site IIS: %3 (Porta: %4, Protocolo: %5)%n• Application Pool: %6
portuguese.UpgradeModeQuick=Atualização rápida (recomendado)
portuguese.UpgradeModeQuickDesc=Atualiza os ficheiros da aplicação preservando o site IIS, portas, certificados, identidade do pool e configuração sem solicitar parâmetros.
portuguese.UpgradeModeCustom=Instalação personalizada (modificar parâmetros)
portuguese.UpgradeModeCustomDesc=Permite modificar o caminho de instalação, o site IIS, as portas, os certificados ou a identidade do pool.
portuguese.UpgradeModeClean=Nova instalação limpa (repor parâmetros)
portuguese.UpgradeModeCleanDesc=Repõe todos os parâmetros para os valores predefinidos, ignora a configuração anterior e substitui os ficheiros de configuração.
portuguese.ReadyMemoUpgradeTitle=Modo de instalação: Atualização rápida
portuguese.ReadyMemoPrevVersion=Versão anterior:
portuguese.ReadyMemoInstallDir=Pasta de instalação:
portuguese.ReadyMemoSite=Site IIS:
portuguese.ReadyMemoProtocol=Protocolo:
portuguese.ReadyMemoIdentity=Identidade do pool:
portuguese.ReadyMemoPreserveNote=A configuração existente (appsettings.json), registos e definições IIS serão preservados.

; --- Brazilian Portuguese ---
brazilianportuguese.SitePageCaption=Parâmetros do site IIS
brazilianportuguese.SitePageDesc=Configure o nome, porta e cabeçalho de host do site IIS do portal.
brazilianportuguese.SiteNameLabel=Nome do site IIS:
brazilianportuguese.SitePortLabel=Porta:
brazilianportuguese.HostHeaderLabel=Cabeçalho de host (opcional):
brazilianportuguese.IdentityPageCaption=Identidade do Application Pool
brazilianportuguese.IdentityPageDesc=Identidade executando o pool IIS. Insira a senha para conta de domínio; não necessária para gMSA.
brazilianportuguese.IdentityLabel=Identidade:
brazilianportuguese.IdentityAppPool=ApplicationPoolIdentity (padrão)
brazilianportuguese.IdentityNetService=NetworkService
brazilianportuguese.IdentityLocalSystem=LocalSystem
brazilianportuguese.IdentityDomain=Conta de domínio / gMSA
brazilianportuguese.AccountLabel=Conta (ex. DOMINIO\serviço):
brazilianportuguese.PasswordLabel=Senha:
brazilianportuguese.GMSACheck=Group Managed Service Account (gMSA) - sem senha
brazilianportuguese.ProtocolPageCaption=Protocolo e certificado
brazilianportuguese.ProtocolPageDesc=HTTPS é fortemente recomendado em produção: HTTP em texto claro expõe hashes NTLM.
brazilianportuguese.ProtocolLabel=Protocolo:
brazilianportuguese.ProtocolHttps=HTTPS (recomendado)
brazilianportuguese.ProtocolHttp=HTTP em texto claro (apenas ambientes de teste isolados)
brazilianportuguese.CertLabel=Certificado SSL (LocalMachine\My):
brazilianportuguese.CertAuto=(Auto: certificado válido mais recente no repositório)
brazilianportuguese.ManualThumbLabel=Thumbprint (inserção manual):
brazilianportuguese.AllowHttpCheck=Permitir instalação em HTTP em texto claro (APENAS testes isolados)
brazilianportuguese.OptionsPageCaption=Opções
brazilianportuguese.OptionsPageDesc=Configurações adicionais de instalação.
brazilianportuguese.SkipFirewallCheck=Não criar regra de firewall do Windows (-SkipFirewall)
brazilianportuguese.OverwriteConfigCheck=Substituir web.config existente (-OverwriteConfig)
brazilianportuguese.ErrSiteNameRequired=Insira um nome para o site IIS.
brazilianportuguese.ErrSiteNameInvalid=O nome do site IIS não deve conter espaços, aspas ou caracteres especiais.
brazilianportuguese.ErrPortInvalid=Porta inválida: insira um número entre 1 e 65535.
brazilianportuguese.ErrHostHeaderInvalid=O cabeçalho de host não deve conter aspas ou barras.
brazilianportuguese.ErrInstallPathInvalid=O caminho de instalação não deve conter apóstrofos ou aspas.
brazilianportuguese.ErrAccountRequired=Insira a conta (ex. DOMINIO\serviço ou DOMINIO\gmsa$).
brazilianportuguese.ErrAccountInvalid=O nome da conta não deve conter apóstrofos ou aspas.
brazilianportuguese.ErrPasswordRequired=Insira a senha da conta ou marque gMSA.
brazilianportuguese.ErrHttpBlocked=Instalação em HTTP em texto claro BLOQUEADA (NTLM não criptografado).%n%nSelecione HTTPS ou marque "Permitir instalação em HTTP em texto claro".
brazilianportuguese.ErrPowerShellFailed=Não foi possível iniciar o PowerShell para instalação do IIS.
brazilianportuguese.ErrScriptFailed=Instalação NÃO concluída: Install-PkiPortal.ps1 terminou com código %1.
brazilianportuguese.MsgSuccess=Instalação concluída com sucesso.%n%nPortal:    %1%nAdmin:     %2%nACME:      %3%n%nPróximos passos: configure as Sub-CAs em %4\appsettings.json.%n%nAbrir o painel de administração no navegador agora?
brazilianportuguese.UpgradePageCaption=Versão anterior detectada
brazilianportuguese.UpgradePageDesc=Foi encontrada uma instalação existente do PkiPortal neste servidor.
brazilianportuguese.UpgradeInfoTemplate=Detalhes da instalação existente:%n• Versão instalada: %1%n• Pasta de instalação: %2%n• Site IIS: %3 (Porta: %4, Protocolo: %5)%n• Application Pool: %6
brazilianportuguese.UpgradeModeQuick=Atualização rápida (recomendado)
brazilianportuguese.UpgradeModeQuickDesc=Atualiza os arquivos do aplicativo preservando o site IIS, portas, certificados, identidade do pool e configuração sem solicitar parâmetros.
brazilianportuguese.UpgradeModeCustom=Instalação personalizada (modificar parâmetros)
brazilianportuguese.UpgradeModeCustomDesc=Permite modificar o caminho de instalação, o site IIS, as portas, os certificados ou a identidade do pool.
brazilianportuguese.UpgradeModeClean=Nova instalação limpa (redefinir parâmetros)
brazilianportuguese.UpgradeModeCleanDesc=Redefine todos os parâmetros para os padrões, ignora a configuração anterior e substitui os arquivos de configuração.
brazilianportuguese.ReadyMemoUpgradeTitle=Modo de instalação: Atualização rápida
brazilianportuguese.ReadyMemoPrevVersion=Versão anterior:
brazilianportuguese.ReadyMemoInstallDir=Pasta de instalação:
brazilianportuguese.ReadyMemoSite=Site IIS:
brazilianportuguese.ReadyMemoProtocol=Protocolo:
brazilianportuguese.ReadyMemoIdentity=Identidade do pool:
brazilianportuguese.ReadyMemoPreserveNote=A configuração existente (appsettings.json), logs e configurações do IIS serão preservados.

; ----------------------------------------------------------------------------
; File applicativi pre-pubblicati (output di dotnet publish, v2.5.1)
; NOTA: appsettings.json NON viene inserito nell'installer poiché contiene la
; configurazione specifica d'ambiente. Alla prima installazione lo script
; genera appsettings.json partendo dal modello pulito appsettings.example.json;
; durante gli aggiornamenti la configurazione esistente viene preservata al 100%.
; web.config viene copiato alla prima installazione o con "Sovrascrivi web.config".
; ----------------------------------------------------------------------------
[Files]
Source: "..\publish\*";        DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion; Excludes: "appsettings*.json,web.config"
Source: "..\publish\appsettings.example.json"; DestDir: "{app}"
Source: "..\publish\web.config";       DestDir: "{app}"; Check: ShouldCopyConfig('web.config')

; Script di installazione/disinstallazione originali (conservati nella
; cartella di installazione, utili per ri-esecuzioni manuali e documentazione)
Source: "..\Install-PkiPortal.ps1";   DestDir: "{app}"
Source: "..\Uninstall-PkiPortal.ps1"; DestDir: "{app}"
Source: "..\LICENSE";                 DestDir: "{app}"

[Icons]
; Applicazione server: nessun collegamento (il portale si apre dal browser)

[Code]

const
  RowH          = 42;  // altezza riga del layout etichetta+controllo
  // Sottochiave fissa usata SOLO per la password dell'account del pool:
  // vi viene scritta per pochi istanti, letta da PowerShell (che la rimuove)
  // e non è mai esposta sulla riga di comando.
  RegPwKey      = 'Software\PkiPortal\Install';

var
  // --- Rilevamento Aggiornamento / Upgrade ---
  IsUpgrade: Boolean;
  IsQuickUpgrade: Boolean;
  PrevVersion: String;
  PrevInstallPath: String;
  PrevSiteName: String;
  PrevSitePort: String;
  PrevHostHeader: String;
  PrevProtocol: String;
  PrevCertThumb: String;
  PrevAppPoolIdentity: String;
  PrevIsGMSA: Boolean;
  PrevSkipFirewall: Boolean;

  UpgradePage: TWizardPage;
  UpgradeInfoBox: TNewStaticText;
  QuickUpgradeRadio, CustomUpgradeRadio, CleanInstallRadio: TNewRadioButton;
  QuickDescText, CustomDescText, CleanDescText: TNewStaticText;

  // --- Pagina 1: parametri sito ---
  SitePage: TWizardPage;
  SiteNameEdit, SitePortEdit, HostHeaderEdit: TNewEdit;

  // --- Pagina 2: identità Application Pool ---
  IdentityPage: TWizardPage;
  IdentityCombo: TNewComboBox;
  AccountEdit, PasswordEdit: TNewEdit;
  GMSACheck: TNewCheckbox;

  // --- Pagina 3: protocollo e certificato ---
  ProtocolPage: TWizardPage;
  ProtocolCombo: TNewComboBox;
  CertCombo: TNewComboBox;
  ManualThumbEdit: TNewEdit;
  AllowHttpCheck: TNewCheckbox;

  // --- Pagina 4: opzioni ---
  OptionsPage: TWizardPage;
  SkipFirewallCheck, OverwriteConfigCheck: TNewCheckbox;
  CertThumbprints: TStringList;

// ----------------------------------------------------------------------------
// Utility
// ----------------------------------------------------------------------------

function GetPS: String;
begin
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
end;

// Rimuove spazi/tab a capo e a coda (Inno Pascal non espone Trim)
function TrimS(const S: String): String;
var
  L, R: Integer;
  Ch: Char;
begin
  L := 1;
  R := Length(S);
  while L <= R do
  begin
    Ch := S[L];
    if (Ch = ' ') or (Ch = #9) or (Ch = #13) or (Ch = #10) then
      Inc(L)
    else
      Break;
  end;
  while R >= L do
  begin
    Ch := S[R];
    if (Ch = ' ') or (Ch = #9) or (Ch = #13) or (Ch = #10) then
      Dec(R)
    else
      Break;
  end;
  if L > R then
    Result := ''
  else
    Result := Copy(S, L, R - L + 1);
end;

function SelectedIdentity: String;
begin
  case IdentityCombo.ItemIndex of
    1: Result := 'NetworkService';
    2: Result := 'LocalSystem';
    3: Result := 'CUSTOM';
  else
    Result := 'ApplicationPoolIdentity';
  end;
end;

function IsCustomIdentity: Boolean;
begin
  Result := SelectedIdentity = 'CUSTOM';
end;

function SelectedProtocol: String;
begin
  case ProtocolCombo.ItemIndex of
    1: Result := 'http';
  else
    Result := 'https';
  end;
end;

function SelectedCertThumbprint: String;
var
  Idx: Integer;
begin
  Idx := CertCombo.ItemIndex - 1;
  if (Idx >= 0) and (Idx < CertThumbprints.Count) then
    Result := CertThumbprints.Strings[Idx]
  else
    Result := '';
end;

function ShouldCopyConfig(FileName: String): Boolean;
begin
  Result := OverwriteConfigCheck.Checked or
            (not FileExists(ExpandConstant('{app}') + '\' + FileName));
end;

// ----------------------------------------------------------------------------
// Helper di layout: etichetta a sinistra, controllo a destra
// ----------------------------------------------------------------------------

function AddLabel(Page: TWizardPage; Y: Integer; const Caption: String): TNewStaticText;
begin
  Result := TNewStaticText.Create(WizardForm);
  Result.Parent := Page.Surface;
  Result.SetBounds(8, Y, 230, 18);
  Result.Caption := Caption;
end;

function AddEdit(Page: TWizardPage; Y: Integer; Width: Integer): TNewEdit;
begin
  Result := TNewEdit.Create(WizardForm);
  Result.Parent := Page.Surface;
  Result.SetBounds(244, Y, Width, 23);
end;

function AddCombo(Page: TWizardPage; Y: Integer; Width: Integer): TNewComboBox;
begin
  Result := TNewComboBox.Create(WizardForm);
  Result.Parent := Page.Surface;
  Result.SetBounds(244, Y, Width, 100);
  Result.Style := csDropDownList;
end;

function AddCheck(Page: TWizardPage; Y: Integer; const Caption: String): TNewCheckbox;
begin
  Result := TNewCheckbox.Create(WizardForm);
  Result.Parent := Page.Surface;
  Result.SetBounds(8, Y, 510, 18);
  Result.Caption := Caption;
end;

// ----------------------------------------------------------------------------
procedure RefreshIdentityVisibility;
begin
  AccountEdit.Visible  := IsCustomIdentity;
  GMSACheck.Visible    := IsCustomIdentity;
  PasswordEdit.Visible := IsCustomIdentity and (not GMSACheck.Checked);
end;

procedure RefreshProtocolVisibility;
begin
  CertCombo.Visible       := (SelectedProtocol = 'https');
  ManualThumbEdit.Visible := (SelectedProtocol = 'https');
  AllowHttpCheck.Visible  := (SelectedProtocol <> 'https');
end;

procedure IdentityComboChanged(Sender: TObject);
begin
  RefreshIdentityVisibility;
end;

procedure GMSACheckChanged(Sender: TObject);
begin
  RefreshIdentityVisibility;
end;

procedure ProtocolComboChanged(Sender: TObject);
begin
  RefreshProtocolVisibility;
end;

// ----------------------------------------------------------------------------
// Elenca i certificati SSL dello store LocalMachine\My (validi, con chiave
// privata) e li espone nella combo, catturando l'output di PowerShell.
// ----------------------------------------------------------------------------
procedure LoadCertCombo;
var
  TmpFile: String;
  EC: Integer;
  Lines: TArrayOfString;
  I: Integer;
  Line: String;
begin
  CertThumbprints := TStringList.Create;
  TmpFile := ExpandConstant('{tmp}\pkiportal_certs.txt');
  if Exec(GetPS,
    '-NoProfile -NonInteractive -Command "Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey } | ForEach-Object { $_.Thumbprint } | Out-File -FilePath ''' + TmpFile + ''' -Encoding ascii"',
    '', SW_HIDE, ewWaitUntilTerminated, EC) then
  begin
    if LoadStringsFromFile(TmpFile, Lines) then
    begin
      for I := 0 to GetArrayLength(Lines) - 1 do
      begin
        Line := TrimS(Lines[I]);
        if Line <> '' then
        begin
          CertThumbprints.Add(Line);
          CertCombo.Items.Add(Line);
        end;
      end;
    end;
    DeleteFile(TmpFile);
  end;
end;

// ----------------------------------------------------------------------------
// Rilevamento automatico di una versione precedente e dei suoi parametri
// ----------------------------------------------------------------------------
procedure DetectPreviousInstallation;
var
  UninstallKey, DetectScript, TmpIni, IniVal: String;
  EC: Integer;
  DWordVal: Cardinal;
  HasReg, SiteFound, PoolFound: Boolean;
begin
  IsUpgrade := False;
  IsQuickUpgrade := False;
  PrevVersion := '';
  PrevInstallPath := '';
  PrevSiteName := '';
  PrevSitePort := '';
  PrevHostHeader := '';
  PrevProtocol := '';
  PrevCertThumb := '';
  PrevAppPoolIdentity := '';
  PrevIsGMSA := False;
  PrevSkipFirewall := False;

  // 1. Controlla prima il registro dedicato HKLM64\SOFTWARE\PkiPortal
  if RegKeyExists(HKLM64, 'SOFTWARE\PkiPortal') then
  begin
    RegQueryStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'InstallPath', PrevInstallPath);
    RegQueryStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'Version', PrevVersion);
    RegQueryStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'SiteName', PrevSiteName);
    RegQueryStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'SitePort', PrevSitePort);
    RegQueryStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'SiteHostHeader', PrevHostHeader);
    RegQueryStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'AppPoolIdentity', PrevAppPoolIdentity);
    RegQueryStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'Protocol', PrevProtocol);
    RegQueryStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'CertThumbprint', PrevCertThumb);
    if RegQueryDWordValue(HKLM64, 'SOFTWARE\PkiPortal', 'IsGMSA', DWordVal) then
      PrevIsGMSA := (DWordVal = 1);
    if RegQueryDWordValue(HKLM64, 'SOFTWARE\PkiPortal', 'SkipFirewall', DWordVal) then
      PrevSkipFirewall := (DWordVal = 1);
  end;

  // 2. Controlla la chiave Uninstall di Inno Setup
  UninstallKey := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{6E3B7A41-9C2D-4F5E-8A1B-D4C6F9E2B0A3}_is1';
  if RegKeyExists(HKLM64, UninstallKey) then
  begin
    if PrevInstallPath = '' then
      RegQueryStringValue(HKLM64, UninstallKey, 'InstallLocation', PrevInstallPath);
    if PrevVersion = '' then
      RegQueryStringValue(HKLM64, UninstallKey, 'DisplayVersion', PrevVersion);
  end;
  if RegKeyExists(HKLM, UninstallKey) then
  begin
    if PrevInstallPath = '' then
      RegQueryStringValue(HKLM, UninstallKey, 'InstallLocation', PrevInstallPath);
    if PrevVersion = '' then
      RegQueryStringValue(HKLM, UninstallKey, 'DisplayVersion', PrevVersion);
  end;

  // 3. Controlla i parametri salvati da installazioni precedenti con SetPreviousData
  if PrevInstallPath = '' then
    PrevInstallPath := GetPreviousData('InstallPath', '');
  if PrevSiteName = '' then
    PrevSiteName := GetPreviousData('SiteName', '');
  if PrevSitePort = '' then
    PrevSitePort := GetPreviousData('SitePort', '');
  if PrevAppPoolIdentity = '' then
    PrevAppPoolIdentity := GetPreviousData('AppPoolIdentity', '');
  if PrevProtocol = '' then
    PrevProtocol := GetPreviousData('Protocol', '');
  if PrevHostHeader = '' then
    PrevHostHeader := GetPreviousData('SiteHostHeader', '');
  if PrevCertThumb = '' then
    PrevCertThumb := GetPreviousData('CertThumbprint', '');
  if GetPreviousData('IsGMSA', '0') = '1' then
    PrevIsGMSA := True;
  if GetPreviousData('SkipFirewall', '0') = '1' then
    PrevSkipFirewall := True;

  // 4. Controllo filesystem fallback nel percorso predefinito
  HasReg := (PrevInstallPath <> '');
  if (PrevInstallPath = '') and FileExists('C:\inetpub\PkiWebEnrollment\PkiPortal.dll') then
    PrevInstallPath := 'C:\inetpub\PkiWebEnrollment';

  // Se abbiamo trovato una cartella candidata con PkiPortal.dll, interroga IIS per verificare se il sito/pool esiste
  if (PrevInstallPath <> '') and FileExists(PrevInstallPath + '\PkiPortal.dll') then
  begin
    TmpIni := ExpandConstant('{tmp}\pki_detect.ini');
    DetectScript := ExpandConstant('{tmp}\pki_detect.ps1');
    SaveStringToFile(DetectScript,
      '$p = ''' + PrevInstallPath + '''' + #13#10 +
      'Import-Module WebAdministration -ErrorAction SilentlyContinue' + #13#10 +
      '$s = Get-Website | Where-Object { ($_.PhysicalPath -replace "\\$","") -eq ($p -replace "\\$","") -or $_.Name -eq "PkiWebEnrollment" } | Select-Object -First 1' + #13#10 +
      '$hasSite = if ($s) { "1" } else { "0" }' + #13#10 +
      '$dll = Join-Path $p "PkiPortal.dll"' + #13#10 +
      '$ver = if (Test-Path $dll) { [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dll).FileVersion } else { "" }' + #13#10 +
      '$siteName = if ($s) { $s.Name } else { "" }' + #13#10 +
      '$wb = if ($s) { Get-WebBinding -Name $siteName -ErrorAction SilentlyContinue } else { $null }' + #13#10 +
      '$b = if ($wb) { $wb | Where-Object { $_.protocol -eq "https" } | Select-Object -First 1 } else { $null }' + #13#10 +
      'if (-not $b -and $wb) { $b = $wb | Select-Object -First 1 }' + #13#10 +
      '$proto = if ($b -and $b.protocol) { $b.protocol } else { "" }' + #13#10 +
      '$sitePort = if ($b -and $b.bindingInformation) { ($b.bindingInformation -split ":")[1] } else { "" }' + #13#10 +
      '$hh = if ($b -and $b.bindingInformation) { ($b.bindingInformation -split ":")[2] } else { "" }' + #13#10 +
      '$thumb = ""' + #13#10 +
      'if ($proto -eq "https" -and $b -and $b.certificateHash) {' + #13#10 +
      '  $rawH = $b.certificateHash' + #13#10 +
      '  if ($rawH -is [byte[]]) { $thumb = [BitConverter]::ToString($rawH) -replace "-","" }' + #13#10 +
      '  else { $thumb = ($rawH -replace "[\s\-]","").Trim() }' + #13#10 +
      '}' + #13#10 +
      '$pool = if ($s) { $s.ApplicationPool } else { if (Test-Path "IIS:\AppPools\PkiWebEnrollment_Pool") { "PkiWebEnrollment_Pool" } else { "" } }' + #13#10 +
      '$hasPool = if ($pool -and (Test-Path ("IIS:\AppPools\" + $pool))) { "1" } else { "0" }' + #13#10 +
      '$ident = ""; $isGmsa = "0"' + #13#10 +
      'if ($pool) {' + #13#10 +
      '  $ap = Get-ItemProperty ("IIS:\AppPools\" + $pool) -ErrorAction SilentlyContinue' + #13#10 +
      '  if ($ap) {' + #13#10 +
      '    if ($ap.processModel.identityType -eq "SpecificUser") {' + #13#10 +
      '      $ident = $ap.processModel.userName' + #13#10 +
      '      if ($ident -like "*$") { $isGmsa = "1" }' + #13#10 +
      '    } elseif ($ap.processModel.identityType) {' + #13#10 +
      '      $ident = [string]$ap.processModel.identityType' + #13#10 +
      '    }' + #13#10 +
      '  }' + #13#10 +
      '}' + #13#10 +
      '[System.IO.File]::WriteAllLines(''' + TmpIni + ''', @(' + #13#10 +
      '  "[Detected]",' + #13#10 +
      '  ("SiteFound=" + $hasSite),' + #13#10 +
      '  ("PoolFound=" + $hasPool),' + #13#10 +
      '  ("Version=" + $ver),' + #13#10 +
      '  ("SiteName=" + $siteName),' + #13#10 +
      '  ("SitePort=" + $sitePort),' + #13#10 +
      '  ("SiteHostHeader=" + $hh),' + #13#10 +
      '  ("Protocol=" + $proto),' + #13#10 +
      '  ("CertThumbprint=" + $thumb),' + #13#10 +
      '  ("AppPoolIdentity=" + $ident),' + #13#10 +
      '  ("IsGMSA=" + $isGmsa)' + #13#10 +
      '))', False);

    if Exec(GetPS, '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + DetectScript + '"', '', SW_HIDE, ewWaitUntilTerminated, EC) then
    begin
      DeleteFile(DetectScript);
      if FileExists(TmpIni) then
      begin
        SiteFound := (GetIniString('Detected', 'SiteFound', '0', TmpIni) = '1');
        PoolFound := (GetIniString('Detected', 'PoolFound', '0', TmpIni) = '1');

        if HasReg or SiteFound or PoolFound then
        begin
          IsUpgrade := True;
          IniVal := GetIniString('Detected', 'Version', '', TmpIni);
          if IniVal <> '' then PrevVersion := IniVal;

          IniVal := GetIniString('Detected', 'SiteName', '', TmpIni);
          if IniVal <> '' then PrevSiteName := IniVal;

          IniVal := GetIniString('Detected', 'SitePort', '', TmpIni);
          if IniVal <> '' then PrevSitePort := IniVal;

          IniVal := GetIniString('Detected', 'SiteHostHeader', '', TmpIni);
          if IniVal <> '' then PrevHostHeader := IniVal;

          IniVal := GetIniString('Detected', 'Protocol', '', TmpIni);
          if IniVal <> '' then PrevProtocol := IniVal;

          IniVal := GetIniString('Detected', 'CertThumbprint', '', TmpIni);
          if IniVal <> '' then PrevCertThumb := IniVal;

          IniVal := GetIniString('Detected', 'AppPoolIdentity', '', TmpIni);
          if IniVal <> '' then PrevAppPoolIdentity := IniVal;

          if GetIniString('Detected', 'IsGMSA', '0', TmpIni) = '1' then
            PrevIsGMSA := True;
        end
        else
        begin
          // File su disco senza né chiavi di registro né sito/pool in IIS: non è un aggiornamento
          IsUpgrade := False;
          PrevInstallPath := '';
        end;

        DeleteFile(TmpIni);
      end;
    end;
  end;

  if IsUpgrade then
  begin
    // Normalizza default per campi che fossero ancora vuoti solo se è un vero upgrade
    if PrevSiteName = '' then PrevSiteName := 'PkiWebEnrollment';
    if PrevProtocol = '' then PrevProtocol := 'https';
    if PrevSitePort = '' then
    begin
      if PrevProtocol = 'https' then
        PrevSitePort := '443'
      else
        PrevSitePort := '8443';
    end;
    if PrevAppPoolIdentity = '' then PrevAppPoolIdentity := 'ApplicationPoolIdentity';
    if PrevVersion = '' then PrevVersion := '2.x';
    IsQuickUpgrade := True;
  end;
end;

// ----------------------------------------------------------------------------
procedure InitializeWizard;
var
  InfoText: String;
begin
  // Rilevamento installazione precedente
  DetectPreviousInstallation;

  // Se è un upgrade, imposta fin da subito la cartella corretta
  if IsUpgrade and (PrevInstallPath <> '') then
  begin
    WizardForm.DirEdit.Text := PrevInstallPath;
  end;

  // ================= Pagina 0: Rilevamento Aggiornamento =================
  UpgradePage := CreateCustomPage(wpLicense,
    CustomMessage('UpgradePageCaption'),
    CustomMessage('UpgradePageDesc'));

  UpgradeInfoBox := TNewStaticText.Create(WizardForm);
  UpgradeInfoBox.Parent := UpgradePage.Surface;
  UpgradeInfoBox.SetBounds(8, 4, 480, 75);
  InfoText := FmtMessage(CustomMessage('UpgradeInfoTemplate'), [PrevVersion, PrevInstallPath, PrevSiteName, PrevSitePort, PrevProtocol, PrevAppPoolIdentity]);
  UpgradeInfoBox.Caption := InfoText;

  QuickUpgradeRadio := TNewRadioButton.Create(WizardForm);
  QuickUpgradeRadio.Parent := UpgradePage.Surface;
  QuickUpgradeRadio.SetBounds(16, 82, 460, 20);
  QuickUpgradeRadio.Caption := CustomMessage('UpgradeModeQuick');
  QuickUpgradeRadio.Font.Style := [fsBold];
  QuickUpgradeRadio.Checked := True;

  QuickDescText := TNewStaticText.Create(WizardForm);
  QuickDescText.Parent := UpgradePage.Surface;
  QuickDescText.SetBounds(34, 102, 440, 28);
  QuickDescText.Caption := CustomMessage('UpgradeModeQuickDesc');

  CustomUpgradeRadio := TNewRadioButton.Create(WizardForm);
  CustomUpgradeRadio.Parent := UpgradePage.Surface;
  CustomUpgradeRadio.SetBounds(16, 132, 460, 20);
  CustomUpgradeRadio.Caption := CustomMessage('UpgradeModeCustom');
  CustomUpgradeRadio.Font.Style := [fsBold];
  CustomUpgradeRadio.Checked := False;

  CustomDescText := TNewStaticText.Create(WizardForm);
  CustomDescText.Parent := UpgradePage.Surface;
  CustomDescText.SetBounds(34, 152, 440, 28);
  CustomDescText.Caption := CustomMessage('UpgradeModeCustomDesc');

  CleanInstallRadio := TNewRadioButton.Create(WizardForm);
  CleanInstallRadio.Parent := UpgradePage.Surface;
  CleanInstallRadio.SetBounds(16, 182, 460, 20);
  CleanInstallRadio.Caption := CustomMessage('UpgradeModeClean');
  CleanInstallRadio.Font.Style := [fsBold];
  CleanInstallRadio.Checked := False;

  CleanDescText := TNewStaticText.Create(WizardForm);
  CleanDescText.Parent := UpgradePage.Surface;
  CleanDescText.SetBounds(34, 202, 440, 28);
  CleanDescText.Caption := CustomMessage('UpgradeModeCleanDesc');

  // ================= Pagina 1: parametri sito =================
  SitePage := CreateCustomPage(wpSelectDir,
    CustomMessage('SitePageCaption'),
    CustomMessage('SitePageDesc'));
  AddLabel(SitePage, 0, CustomMessage('SiteNameLabel'));
  SiteNameEdit := AddEdit(SitePage, 0, 250);
  if IsUpgrade and (PrevSiteName <> '') then
    SiteNameEdit.Text := PrevSiteName
  else
    SiteNameEdit.Text := 'PkiWebEnrollment';
  AddLabel(SitePage, RowH, CustomMessage('SitePortLabel'));
  SitePortEdit := AddEdit(SitePage, RowH, 80);
  if IsUpgrade and (PrevSitePort <> '') then
    SitePortEdit.Text := PrevSitePort
  else
    SitePortEdit.Text := '8443';
  AddLabel(SitePage, 2 * RowH, CustomMessage('HostHeaderLabel'));
  HostHeaderEdit := AddEdit(SitePage, 2 * RowH, 250);
  if IsUpgrade and (PrevHostHeader <> '') then
    HostHeaderEdit.Text := PrevHostHeader;

  // ================= Pagina 2: identità Application Pool =================
  IdentityPage := CreateCustomPage(SitePage.ID,
    CustomMessage('IdentityPageCaption'),
    CustomMessage('IdentityPageDesc'));
  AddLabel(IdentityPage, 0, CustomMessage('IdentityLabel'));
  IdentityCombo := AddCombo(IdentityPage, 0, 250);
  IdentityCombo.Items.Add(CustomMessage('IdentityAppPool'));
  IdentityCombo.Items.Add(CustomMessage('IdentityNetService'));
  IdentityCombo.Items.Add(CustomMessage('IdentityLocalSystem'));
  IdentityCombo.Items.Add(CustomMessage('IdentityDomain'));
  IdentityCombo.ItemIndex := 0;
  if IsUpgrade then
  begin
    if PrevAppPoolIdentity = 'NetworkService' then
      IdentityCombo.ItemIndex := 1
    else if PrevAppPoolIdentity = 'LocalSystem' then
      IdentityCombo.ItemIndex := 2
    else if (PrevAppPoolIdentity <> 'ApplicationPoolIdentity') and (PrevAppPoolIdentity <> '') then
      IdentityCombo.ItemIndex := 3;
  end;
  IdentityCombo.OnChange := @IdentityComboChanged;
  AddLabel(IdentityPage, RowH, CustomMessage('AccountLabel'));
  AccountEdit := AddEdit(IdentityPage, RowH, 250);
  if IsUpgrade and (IdentityCombo.ItemIndex = 3) then
    AccountEdit.Text := PrevAppPoolIdentity;
  AddLabel(IdentityPage, 2 * RowH, CustomMessage('PasswordLabel'));
  PasswordEdit := AddEdit(IdentityPage, 2 * RowH, 250);
  PasswordEdit.PasswordChar := '*';
  GMSACheck := AddCheck(IdentityPage, 3 * RowH, CustomMessage('GMSACheck'));
  if IsUpgrade then
    GMSACheck.Checked := PrevIsGMSA;
  GMSACheck.OnClick := @GMSACheckChanged;

  // ================= Pagina 3: protocollo e certificato =================
  ProtocolPage := CreateCustomPage(IdentityPage.ID,
    CustomMessage('ProtocolPageCaption'),
    CustomMessage('ProtocolPageDesc'));
  AddLabel(ProtocolPage, 0, CustomMessage('ProtocolLabel'));
  ProtocolCombo := AddCombo(ProtocolPage, 0, 300);
  ProtocolCombo.Items.Add(CustomMessage('ProtocolHttps'));
  ProtocolCombo.Items.Add(CustomMessage('ProtocolHttp'));
  if IsUpgrade and (PrevProtocol = 'http') then
    ProtocolCombo.ItemIndex := 1
  else
    ProtocolCombo.ItemIndex := 0;
  ProtocolCombo.OnChange := @ProtocolComboChanged;
  AddLabel(ProtocolPage, RowH, CustomMessage('CertLabel'));
  CertCombo := AddCombo(ProtocolPage, RowH, 250);
  CertCombo.Items.Add(CustomMessage('CertAuto'));
  LoadCertCombo;
  CertCombo.ItemIndex := 0;
  AddLabel(ProtocolPage, 2 * RowH, CustomMessage('ManualThumbLabel'));
  ManualThumbEdit := AddEdit(ProtocolPage, 2 * RowH, 250);
  if IsUpgrade and (PrevCertThumb <> '') then
    ManualThumbEdit.Text := PrevCertThumb;
  AllowHttpCheck := AddCheck(ProtocolPage, 3 * RowH, CustomMessage('AllowHttpCheck'));
  if IsUpgrade and (PrevProtocol = 'http') then
    AllowHttpCheck.Checked := True;

  // ================= Pagina 4: opzioni =================
  OptionsPage := CreateCustomPage(ProtocolPage.ID,
    CustomMessage('OptionsPageCaption'),
    CustomMessage('OptionsPageDesc'));
  SkipFirewallCheck := AddCheck(OptionsPage, 0, CustomMessage('SkipFirewallCheck'));
  if IsUpgrade then
    SkipFirewallCheck.Checked := PrevSkipFirewall;
  OverwriteConfigCheck := AddCheck(OptionsPage, RowH, CustomMessage('OverwriteConfigCheck'));
  if IsUpgrade then
    OverwriteConfigCheck.Checked := False;

  // ================= Visibilità iniziale =================
  RefreshIdentityVisibility;
  RefreshProtocolVisibility;
end;

// ----------------------------------------------------------------------------
// Validazione dei valori al passaggio alla pagina successiva
// ----------------------------------------------------------------------------
function HasForbiddenQuote(S: String): Boolean;
begin
  Result := (Pos('"', S) > 0) or (Pos('''', S) > 0);
end;

procedure PreInstallStopIIS; forward;

function NextButtonClicked(CurPageID: Integer): Boolean;
var
  S: String;
  Port: Integer;
  DirValue: String;
begin
  Result := True;

  if CurPageID = UpgradePage.ID then
  begin
    if CleanInstallRadio.Checked then
    begin
      IsUpgrade := False;
      IsQuickUpgrade := False;
      WizardForm.DirEdit.Text := 'C:\inetpub\PkiWebEnrollment';
      SiteNameEdit.Text := 'PkiWebEnrollment';
      SitePortEdit.Text := '443';
      HostHeaderEdit.Text := '';
      IdentityCombo.ItemIndex := 0;
      AccountEdit.Text := '';
      PasswordEdit.Text := '';
      GMSACheck.Checked := False;
      ProtocolCombo.ItemIndex := 0;
      ManualThumbEdit.Text := '';
      AllowHttpCheck.Checked := False;
      SkipFirewallCheck.Checked := False;
      OverwriteConfigCheck.Checked := True;
      RefreshIdentityVisibility;
      RefreshProtocolVisibility;
    end
    else if QuickUpgradeRadio.Checked then
    begin
      IsQuickUpgrade := True;
      WizardForm.DirEdit.Text := PrevInstallPath;
      SiteNameEdit.Text := PrevSiteName;
      SitePortEdit.Text := PrevSitePort;
      HostHeaderEdit.Text := PrevHostHeader;
      if PrevAppPoolIdentity = 'NetworkService' then
        IdentityCombo.ItemIndex := 1
      else if PrevAppPoolIdentity = 'LocalSystem' then
        IdentityCombo.ItemIndex := 2
      else if (PrevAppPoolIdentity = 'ApplicationPoolIdentity') or (PrevAppPoolIdentity = '') then
        IdentityCombo.ItemIndex := 0
      else
      begin
        IdentityCombo.ItemIndex := 3;
        AccountEdit.Text := PrevAppPoolIdentity;
        GMSACheck.Checked := PrevIsGMSA;
      end;

      if PrevProtocol = 'http' then
      begin
        ProtocolCombo.ItemIndex := 1;
        AllowHttpCheck.Checked := True;
      end
      else
      begin
        ProtocolCombo.ItemIndex := 0;
        if PrevCertThumb <> '' then
          ManualThumbEdit.Text := PrevCertThumb;
      end;

      SkipFirewallCheck.Checked := PrevSkipFirewall;
      OverwriteConfigCheck.Checked := False;
      RefreshIdentityVisibility;
      RefreshProtocolVisibility;
    end
    else
    begin
      // Installazione personalizzata: consentiamo la modifica di qualsiasi parametro
      IsQuickUpgrade := False;
    end;
    Result := True;
    Exit;
  end
  else if CurPageID = SitePage.ID then
  begin
    S := TrimS(SiteNameEdit.Text);
    if S = '' then
    begin
      MsgBox(CustomMessage('ErrSiteNameRequired'), mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (Pos(' ', S) > 0) or HasForbiddenQuote(S) or (Pos('/', S) > 0) or
       (Pos('\', S) > 0) or (Pos(':', S) > 0) then
    begin
      MsgBox(CustomMessage('ErrSiteNameInvalid'), mbError, MB_OK);
      Result := False;
      Exit;
    end;
    Port := StrToIntDef(TrimS(SitePortEdit.Text), 0);
    if (Port < 1) or (Port > 65535) then
    begin
      MsgBox(CustomMessage('ErrPortInvalid'), mbError, MB_OK);
      Result := False;
      Exit;
    end;
    S := TrimS(HostHeaderEdit.Text);
    if HasForbiddenQuote(S) or (Pos('/', S) > 0) or (Pos('\', S) > 0) then
    begin
      MsgBox(CustomMessage('ErrHostHeaderInvalid'), mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end
  else if CurPageID = wpSelectDir then
  begin
    DirValue := WizardDirValue;
    if HasForbiddenQuote(DirValue) then
    begin
      MsgBox(CustomMessage('ErrInstallPathInvalid'), mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end
  else if CurPageID = IdentityPage.ID then
  begin
    if IsCustomIdentity then
    begin
      S := TrimS(AccountEdit.Text);
      if S = '' then
      begin
        MsgBox(CustomMessage('ErrAccountRequired'), mbError, MB_OK);
        Result := False;
        Exit;
      end;
      if HasForbiddenQuote(S) then
      begin
        MsgBox(CustomMessage('ErrAccountInvalid'), mbError, MB_OK);
        Result := False;
        Exit;
      end;
      if (not GMSACheck.Checked) and (PasswordEdit.Text = '') then
      begin
        MsgBox(CustomMessage('ErrPasswordRequired'), mbError, MB_OK);
        Result := False;
        Exit;
      end;
    end;
  end
  else if CurPageID = ProtocolPage.ID then
  begin
    if SelectedProtocol = 'http' then
    begin
      if AllowHttpCheck.Checked = False then
      begin
        MsgBox(CustomMessage('ErrHttpBlocked'), mbError, MB_OK);
        Result := False;
        Exit;
      end;
    end;
  end
  else if CurPageID = wpReady then
  begin
    PreInstallStopIIS;
  end;
end;

// ----------------------------------------------------------------------------
// Salta le pagine di configurazione se in modalità aggiornamento rapido
// ----------------------------------------------------------------------------
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;

  if PageID = UpgradePage.ID then
  begin
    Result := not IsUpgrade;
    Exit;
  end;

  if IsUpgrade and IsQuickUpgrade then
  begin
    if (PageID = wpSelectDir) or
       (PageID = SitePage.ID) or
       (PageID = IdentityPage.ID) or
       (PageID = ProtocolPage.ID) or
       (PageID = OptionsPage.ID) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

// ----------------------------------------------------------------------------
// Personalizza il riepilogo nella pagina Ready to Install
// ----------------------------------------------------------------------------
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  S: String;
begin
  if IsUpgrade and IsQuickUpgrade then
  begin
    S := CustomMessage('ReadyMemoUpgradeTitle') + NewLine + NewLine;
    S := S + Space + CustomMessage('ReadyMemoPrevVersion') + ' ' + PrevVersion + NewLine;
    S := S + Space + CustomMessage('ReadyMemoInstallDir') + ' ' + WizardDirValue + NewLine;
    S := S + Space + CustomMessage('ReadyMemoSite') + ' ' + SiteNameEdit.Text + ' (' + CustomMessage('SitePortLabel') + ' ' + SitePortEdit.Text + ')' + NewLine;
    S := S + Space + CustomMessage('ReadyMemoProtocol') + ' ' + SelectedProtocol + NewLine;
    S := S + Space + CustomMessage('ReadyMemoIdentity') + ' ' + SelectedIdentity + NewLine + NewLine;
    S := S + CustomMessage('ReadyMemoPreserveNote');
    Result := S;
  end
  else
  begin
    Result := MemoDirInfo + NewLine + NewLine +
              CustomMessage('SitePageCaption') + ':' + NewLine +
              Space + CustomMessage('SiteNameLabel') + ' ' + SiteNameEdit.Text + NewLine +
              Space + CustomMessage('SitePortLabel') + ' ' + SitePortEdit.Text + NewLine +
              Space + CustomMessage('HostHeaderLabel') + ' ' + HostHeaderEdit.Text + NewLine + NewLine +
              CustomMessage('ProtocolPageCaption') + ':' + NewLine +
              Space + CustomMessage('ProtocolLabel') + ' ' + SelectedProtocol + NewLine + NewLine +
              CustomMessage('IdentityPageCaption') + ':' + NewLine +
              Space + CustomMessage('IdentityLabel') + ' ' + SelectedIdentity;
  end;
end;

// ----------------------------------------------------------------------------
// Arresta sito e application pool (se esistenti) prima della copia file,
// per poter sovrascrivere i DLL in uso dal worker w3wp del pool.
// ----------------------------------------------------------------------------
procedure PreInstallStopIIS;
var
  SiteName, Pool, AppCmd, AppDir, StopScript: String;
  EC: Integer;
begin
  SiteName := TrimS(SiteNameEdit.Text);
  if SiteName = '' then
    SiteName := PrevSiteName;
  if SiteName = '' then
    SiteName := 'PkiWebEnrollment';
  Pool := SiteName + '_Pool';
  AppDir := ExpandConstant('{app}');
  if (AppDir = '') and (PrevInstallPath <> '') then
    AppDir := PrevInstallPath;
  if AppDir = '' then
    AppDir := 'C:\inetpub\PkiWebEnrollment';

  AppCmd := ExpandConstant('{sys}\inetsrv\appcmd.exe');
  if FileExists(AppCmd) then
  begin
    Exec(AppCmd, 'stop site /site.name:"' + SiteName + '"', '', SW_HIDE, ewWaitUntilTerminated, EC);
    Exec(AppCmd, 'stop apppool /apppool.name:"' + Pool + '"', '', SW_HIDE, ewWaitUntilTerminated, EC);
  end;

  // Crea app_offline.htm per forzare ANCM a rilasciare immediatamente i binari
  if DirExists(AppDir) then
  begin
    SaveStringToFile(AppDir + '\app_offline.htm', '<html><body>Upgrade in progress</body></html>', False);
  end;

  // Termina con certezza qualsiasi processo che tiene aperti i file del portale
  StopScript := ExpandConstant('{tmp}\pki_stop.ps1');
  SaveStringToFile(StopScript,
    '$appDir = "' + AppDir + '"' + #13#10 +
    '$pool = "' + Pool + '"' + #13#10 +
    '$siteName = "' + SiteName + '"' + #13#10 +
    '$appcmd = "$env:SystemRoot\system32\inetsrv\appcmd.exe"' + #13#10 +
    'if (Test-Path $appcmd) {' + #13#10 +
    '  & $appcmd stop site /site.name:"$siteName" 2>$null' + #13#10 +
    '  & $appcmd stop apppool /apppool.name:"$pool" 2>$null' + #13#10 +
    '  $wpPids = & $appcmd list wp /apppool.name:"$pool" /text:WP.NAME 2>$null' + #13#10 +
    '  foreach ($p in $wpPids) {' + #13#10 +
    '    $cleanP = ($p + "").Trim()' + #13#10 +
    '    if ($cleanP -match "^\d+$") {' + #13#10 +
    '      taskkill.exe /F /PID $cleanP /T 2>$null' + #13#10 +
    '      Stop-Process -Id [int]$cleanP -Force -ErrorAction SilentlyContinue' + #13#10 +
    '    }' + #13#10 +
    '  }' + #13#10 +
    '}' + #13#10 +
    'Get-Process -Name "w3wp", "dotnet", "PkiPortal" -ErrorAction SilentlyContinue | ForEach-Object {' + #13#10 +
    '  $proc = $_' + #13#10 +
    '  $isTarget = ($proc.ProcessName -eq "PkiPortal")' + #13#10 +
    '  if (-not $isTarget) {' + #13#10 +
    '    try {' + #13#10 +
    '      foreach ($m in $proc.Modules) {' + #13#10 +
    '        if ($m.FileName -and $m.FileName -like "$appDir\*") {' + #13#10 +
    '          $isTarget = $true' + #13#10 +
    '          break' + #13#10 +
    '        }' + #13#10 +
    '      }' + #13#10 +
    '    } catch { }' + #13#10 +
    '  }' + #13#10 +
    '  if ($isTarget) {' + #13#10 +
    '    taskkill.exe /F /PID $proc.Id /T 2>$null' + #13#10 +
    '    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue' + #13#10 +
    '  }' + #13#10 +
    '}' + #13#10 +
    '$testFiles = @(' + #13#10 +
    '  (Join-Path $appDir "Microsoft.AspNetCore.Authentication.Negotiate.dll"),' + #13#10 +
    '  (Join-Path $appDir "PkiPortal.dll")' + #13#10 +
    ')' + #13#10 +
    'foreach ($tf in $testFiles) {' + #13#10 +
    '  if (Test-Path $tf) {' + #13#10 +
    '    for ($i = 0; $i -lt 15; $i++) {' + #13#10 +
    '      $unlocked = $false' + #13#10 +
    '      try {' + #13#10 +
    '        $st = [System.IO.File]::Open($tf, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)' + #13#10 +
    '        $st.Close()' + #13#10 +
    '        $st.Dispose()' + #13#10 +
    '        $unlocked = $true' + #13#10 +
    '      } catch {' + #13#10 +
    '        Start-Sleep -Milliseconds 400' + #13#10 +
    '      }' + #13#10 +
    '      if ($unlocked) { break }' + #13#10 +
    '    }' + #13#10 +
    '  }' + #13#10 +
    '}' + #13#10, False);

  Exec(GetPS, '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + StopScript + '"', '', SW_HIDE, ewWaitUntilTerminated, EC);
  DeleteFile(StopScript);
  Sleep(500);
end;

// ----------------------------------------------------------------------------
procedure RunInstallScript;
var
  SiteName, SitePort, HostHeader, InstallPath, Script: String;
  Identity, Password, CertThumb, Protocol: String;
  IsGMSA, UseHttps, SkipFirewall, Overwrite: Boolean;
  ScriptParams, PwParams, CmdFile: String;
  CmdLines: TStringList;
  EC: Integer;
  Url, BaseUrl: String;
begin
  SiteName     := TrimS(SiteNameEdit.Text);
  SitePort     := TrimS(SitePortEdit.Text);
  HostHeader   := TrimS(HostHeaderEdit.Text);
  InstallPath  := ExpandConstant('{app}');
  Script       := InstallPath + '\Install-PkiPortal.ps1';
  Identity     := SelectedIdentity;
  if IsCustomIdentity then
    Identity := TrimS(AccountEdit.Text);
  Password     := PasswordEdit.Text;
  IsGMSA       := GMSACheck.Checked;
  Protocol     := SelectedProtocol;
  UseHttps     := Protocol = 'https';
  SkipFirewall := SkipFirewallCheck.Checked;
  Overwrite    := OverwriteConfigCheck.Checked;
  CertThumb    := TrimS(ManualThumbEdit.Text);
  if CertThumb = '' then
    CertThumb := SelectedCertThumbprint;

  // --- salva i parametri nel database dell'uninstaller (SetPreviousData) ---
  SetPreviousData(0, 'SiteName', SiteName);
  SetPreviousData(0, 'SitePort', SitePort);
  SetPreviousData(0, 'SiteHostHeader', HostHeader);
  SetPreviousData(0, 'InstallPath', InstallPath);
  SetPreviousData(0, 'AppPoolIdentity', Identity);
  SetPreviousData(0, 'Protocol', Protocol);
  SetPreviousData(0, 'CertThumbprint', CertThumb);
  if IsGMSA then
    SetPreviousData(0, 'IsGMSA', '1')
  else
    SetPreviousData(0, 'IsGMSA', '0');
  if SkipFirewall then
    SetPreviousData(0, 'SkipFirewall', '1')
  else
    SetPreviousData(0, 'SkipFirewall', '0');

  // --- salva nel registro HKLM64\SOFTWARE\PkiPortal per upgrade futuri ---
  RegWriteStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'InstallPath', InstallPath);
  RegWriteStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'Version', '{#MyAppVersion}');
  RegWriteStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'SiteName', SiteName);
  RegWriteStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'SitePort', SitePort);
  RegWriteStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'SiteHostHeader', HostHeader);
  RegWriteStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'AppPoolIdentity', Identity);
  if IsGMSA then
    RegWriteDWordValue(HKLM64, 'SOFTWARE\PkiPortal', 'IsGMSA', 1)
  else
    RegWriteDWordValue(HKLM64, 'SOFTWARE\PkiPortal', 'IsGMSA', 0);
  RegWriteStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'Protocol', Protocol);
  RegWriteStringValue(HKLM64, 'SOFTWARE\PkiPortal', 'CertThumbprint', CertThumb);
  if SkipFirewall then
    RegWriteDWordValue(HKLM64, 'SOFTWARE\PkiPortal', 'SkipFirewall', 1)
  else
    RegWriteDWordValue(HKLM64, 'SOFTWARE\PkiPortal', 'SkipFirewall', 0);

  // --- password: memorizzata in registry per pochi istanti, letta da
  //     PowerShell e rimossa PRIMA di avviare lo script (mai in riga
  //     di comando). Non necessaria in modalità aggiornamento rapido. ---
  if (not (IsUpgrade and IsQuickUpgrade)) and
     (Identity <> 'ApplicationPoolIdentity') and (Identity <> 'NetworkService') and
     (Identity <> 'LocalSystem') and (not IsGMSA) and (Password <> '') then
    RegWriteStringValue(HKLM, RegPwKey, 'AppPoolPassword', Password);

  // --- costruzione dei parametri di Install-PkiPortal.ps1 ---
  ScriptParams := ' -SiteName "' + SiteName + '"';
  ScriptParams := ScriptParams + ' -SitePort ' + SitePort;
  if HostHeader <> '' then
    ScriptParams := ScriptParams + ' -SiteHostHeader "' + HostHeader + '"';
  ScriptParams := ScriptParams + ' -InstallPath "' + InstallPath + '"';

  if IsUpgrade and IsQuickUpgrade then
  begin
    ScriptParams := ScriptParams + ' -PreserveAppPoolIdentity';
  end
  else
  begin
    ScriptParams := ScriptParams + ' -AppPoolIdentity "' + Identity + '"';
    if IsGMSA then
      ScriptParams := ScriptParams + ' -IsGMSA';
  end;

  if UseHttps then
  begin
    ScriptParams := ScriptParams + ' -UseHttps';
    if CertThumb <> '' then
      ScriptParams := ScriptParams + ' -CertThumbprint "' + CertThumb + '"';
  end
  else
    ScriptParams := ScriptParams + ' -AllowInsecureHttp';

  if SkipFirewall then
    ScriptParams := ScriptParams + ' -SkipFirewall';
  if Overwrite then
    ScriptParams := ScriptParams + ' -OverwriteConfig';

  // file applicativi forniti dall'installer: nessuna fase di build sul server
  ScriptParams := ScriptParams + ' -SkipDotnetPublish';
  ScriptParams := ScriptParams + ' -Force';

  CmdFile := ExpandConstant('{tmp}\run-install.cmd');
  CmdLines := TStringList.Create;
  try
    CmdLines.Add('@echo off');
    CmdLines.Add('chcp 65001 >nul');
    CmdLines.Add('echo ===============================================================');
    CmdLines.Add('echo  PKI Web Enrollment Portal - Running Installation Script...');
    CmdLines.Add('echo ===============================================================');
    CmdLines.Add('echo.');

    if (not (IsUpgrade and IsQuickUpgrade)) and
       (Identity <> 'ApplicationPoolIdentity') and (Identity <> 'NetworkService') and
       (Identity <> 'LocalSystem') and (not IsGMSA) and (Password <> '') then
    begin
      PwParams := ScriptParams;
      StringChange(PwParams, '"', '''');
      CmdLines.Add('"' + GetPS + '" -NoProfile -ExecutionPolicy Bypass -Command "' +
        '$pw = (Get-ItemProperty -Path ''HKLM:\' + RegPwKey + ''').AppPoolPassword; ' +
        'Remove-ItemProperty -Path ''HKLM:\' + RegPwKey + ''' -Name AppPoolPassword -Force -ErrorAction SilentlyContinue; ' +
        '$ss = $pw | ConvertTo-SecureString -AsPlainText -Force; ' +
        '& ''' + Script + '''' + PwParams + ' -AppPoolPassword $ss"');
    end
    else
    begin
      CmdLines.Add('"' + GetPS + '" -NoProfile -ExecutionPolicy Bypass -File "' + Script + '"' + ScriptParams);
    end;

    CmdLines.Add('set PS_ERR=%ERRORLEVEL%');
    CmdLines.Add('if %PS_ERR% NEQ 0 (');
    CmdLines.Add('  echo.');
    CmdLines.Add('  echo ===============================================================');
    CmdLines.Add('  echo  [ERROR] Installation script terminated with error code %PS_ERR%.');
    CmdLines.Add('  echo  Log: %TEMP%\PkiPortal-Install.log');
    CmdLines.Add('  echo ===============================================================');
    CmdLines.Add('  echo.');
    CmdLines.Add('  echo Press any key to continue... / Premere un tasto per continuare...');
    CmdLines.Add('  pause >nul');
    CmdLines.Add(')');
    CmdLines.Add('exit /b %PS_ERR%');
    CmdLines.SaveToFile(CmdFile);
  finally
    CmdLines.Free;
  end;

  // --- esecuzione in console visibile: l'amministratore vede tutto
  //     l'output e può rispondere ai prompt o verificare errori ---
  if not Exec(ExpandConstant('{cmd}'), '/c "' + CmdFile + '"', '', SW_SHOWNORMAL, ewWaitUntilTerminated, EC) then
  begin
    MsgBox(CustomMessage('ErrPowerShellFailed'), mbError, MB_OK);
    DeleteFile(CmdFile);
  DeleteFile(ExpandConstant('{app}\app_offline.htm'));
    Abort;
  end;
  DeleteFile(CmdFile);
  DeleteFile(ExpandConstant('{app}\app_offline.htm'));

  // pulizia eventuale residua della password e della chiave
  RegDeleteValue(HKLM, RegPwKey, 'AppPoolPassword');
  RegDeleteKeyIfEmpty(HKLM, RegPwKey);

  if EC <> 0 then
  begin
    MsgBox(FmtMessage(CustomMessage('ErrScriptFailed'), [IntToStr(EC)]), mbError, MB_OK);
    Abort;
  end;

  if UseHttps then
    BaseUrl := 'https://localhost:' + SitePort
  else
    BaseUrl := 'http://localhost:' + SitePort;
  Url := BaseUrl + '/admin';
  if MsgBox(FmtMessage(CustomMessage('MsgSuccess'), [BaseUrl, Url, BaseUrl + '/acme/directory', InstallPath]),
            mbInformation, MB_OKCANCEL) = IDOK then
    ShellExec('open', Url, '', '', SW_SHOWNORMAL, ewNoWait, EC);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    PreInstallStopIIS
  else if CurStep = ssPostInstall then
    RunInstallScript;
end;

// ----------------------------------------------------------------------------
// Disinstallazione: esegue Uninstall-PkiPortal.ps1 con i parametri salvati,
// quindi Inno rimuove i file copiati (le cartelle App_Data/logs, non
// tracciate, vengono conservate come nel comportamento default dello script).
// ----------------------------------------------------------------------------
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  SiteName, InstallPath, Script, PSArgs: String;
  EC: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    // parametri salvati con SetPreviousData durante l'installazione
    SiteName    := GetPreviousData('SiteName', 'PkiWebEnrollment');
    InstallPath := GetPreviousData('InstallPath', ExpandConstant('{app}'));

    Script := InstallPath + '\Uninstall-PkiPortal.ps1';
    if FileExists(Script) then
    begin
      PSArgs := '-NoProfile -ExecutionPolicy Bypass -File "' + Script + '" -SiteName "' + SiteName + '" -InstallPath "' + InstallPath + '"';
      Exec(GetPS, PSArgs, '', SW_SHOWNORMAL, ewWaitUntilTerminated, EC);
    end;

    // pulizia residua della chiave password (normalmente già rimossa a
    // installazione completata) e dei parametri di configurazione
    RegDeleteValue(HKLM, RegPwKey, 'AppPoolPassword');
    RegDeleteKeyIfEmpty(HKLM, RegPwKey);
    RegDeleteKeyIncludingSubkeys(HKLM64, 'SOFTWARE\PkiPortal');
  end;
end;
