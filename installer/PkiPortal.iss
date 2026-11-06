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
; Output:  ..\build\PkiPortal-Setup-2.4.0.exe
; ============================================================================

#define MyAppName        "PkiPortal"
#define MyAppVersion     "2.4.0"
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

; ----------------------------------------------------------------------------
; File applicativi pre-pubblicati (output di dotnet publish, v2.4.0)
; NOTA: appsettings.json NON viene inserito nell'installer poiché contiene la
; configurazione specifica d'ambiente. Alla prima installazione lo script
; genera appsettings.json partendo dal modello pulito appsettings.example.json;
; durante gli aggiornamenti la configurazione esistente viene preservata al 100%.
; web.config viene copiato alla prima installazione o con "Sovrascrivi web.config".
; ----------------------------------------------------------------------------
[Files]
Source: "..\publish\*";        DestDir: "{app}"; Flags: recursesubdirs createallsubdirs; Excludes: "appsettings*.json,web.config"
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
procedure InitializeWizard;
begin
  // ================= Pagina 1: parametri sito =================
  SitePage := CreateCustomPage(wpSelectDir,
    CustomMessage('SitePageCaption'),
    CustomMessage('SitePageDesc'));
  AddLabel(SitePage, 0, CustomMessage('SiteNameLabel'));
  SiteNameEdit := AddEdit(SitePage, 0, 250);
  SiteNameEdit.Text := 'PkiWebEnrollment';
  AddLabel(SitePage, RowH, CustomMessage('SitePortLabel'));
  SitePortEdit := AddEdit(SitePage, RowH, 80);
  SitePortEdit.Text := '8443';
  AddLabel(SitePage, 2 * RowH, CustomMessage('HostHeaderLabel'));
  HostHeaderEdit := AddEdit(SitePage, 2 * RowH, 250);

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
  IdentityCombo.OnChange := @IdentityComboChanged;
  AddLabel(IdentityPage, RowH, CustomMessage('AccountLabel'));
  AccountEdit := AddEdit(IdentityPage, RowH, 250);
  AddLabel(IdentityPage, 2 * RowH, CustomMessage('PasswordLabel'));
  PasswordEdit := AddEdit(IdentityPage, 2 * RowH, 250);
  PasswordEdit.PasswordChar := '*';
  GMSACheck := AddCheck(IdentityPage, 3 * RowH, CustomMessage('GMSACheck'));
  GMSACheck.OnClick := @GMSACheckChanged;

  // ================= Pagina 3: protocollo e certificato =================
  ProtocolPage := CreateCustomPage(IdentityPage.ID,
    CustomMessage('ProtocolPageCaption'),
    CustomMessage('ProtocolPageDesc'));
  AddLabel(ProtocolPage, 0, CustomMessage('ProtocolLabel'));
  ProtocolCombo := AddCombo(ProtocolPage, 0, 300);
  ProtocolCombo.Items.Add(CustomMessage('ProtocolHttps'));
  ProtocolCombo.Items.Add(CustomMessage('ProtocolHttp'));
  ProtocolCombo.ItemIndex := 0;
  ProtocolCombo.OnChange := @ProtocolComboChanged;
  AddLabel(ProtocolPage, RowH, CustomMessage('CertLabel'));
  CertCombo := AddCombo(ProtocolPage, RowH, 250);
  CertCombo.Items.Add(CustomMessage('CertAuto'));
  LoadCertCombo;
  CertCombo.ItemIndex := 0;
  AddLabel(ProtocolPage, 2 * RowH, CustomMessage('ManualThumbLabel'));
  ManualThumbEdit := AddEdit(ProtocolPage, 2 * RowH, 250);
  AllowHttpCheck := AddCheck(ProtocolPage, 3 * RowH, CustomMessage('AllowHttpCheck'));

  // ================= Pagina 4: opzioni =================
  OptionsPage := CreateCustomPage(ProtocolPage.ID,
    CustomMessage('OptionsPageCaption'),
    CustomMessage('OptionsPageDesc'));
  SkipFirewallCheck := AddCheck(OptionsPage, 0, CustomMessage('SkipFirewallCheck'));
  OverwriteConfigCheck := AddCheck(OptionsPage, RowH, CustomMessage('OverwriteConfigCheck'));

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

function NextButtonClicked(CurPageID: Integer): Boolean;
var
  S: String;
  Port: Integer;
  DirValue: String;
begin
  Result := True;

  if CurPageID = SitePage.ID then
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
  end;
end;

// ----------------------------------------------------------------------------
// Arresta sito e application pool (se esistenti) prima della copia file,
// per poter sovrascrivere i DLL in uso dal worker w3wp del pool.
// ----------------------------------------------------------------------------
procedure PreInstallStopIIS;
var
  SiteName, Pool, AppCmd: String;
  EC: Integer;
begin
  SiteName := TrimS(SiteNameEdit.Text);
  Pool := SiteName + '_Pool';
  AppCmd := ExpandConstant('{sys}\inetsrv\appcmd.exe');
  if not FileExists(AppCmd) then
    Exit;  // IIS non presente: lo script installerà i prerequisiti
  Exec(AppCmd, 'stop site /site.name:"' + SiteName + '"', '', SW_HIDE, ewWaitUntilTerminated, EC);
  Exec(AppCmd, 'stop apppool /apppool.name:"' + Pool + '"', '', SW_HIDE, ewWaitUntilTerminated, EC);
  Sleep(3000);
  // Eventuali w3wp "appesi" di questo pool
  Exec(GetPS, '-NoProfile -NonInteractive -Command "Get-CimInstance Win32_Process | Where-Object { (Name -eq ''w3wp.exe'') -and (CommandLine -match ''*' + Pool + ''') } | ForEach-Object { Stop-Process -Id ProcessId -Force -ErrorAction SilentlyContinue }"', '', SW_HIDE, ewWaitUntilTerminated, EC);
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
  SetPreviousData(0, 'InstallPath', InstallPath);
  SetPreviousData(0, 'AppPoolIdentity', Identity);
  SetPreviousData(0, 'Protocol', Protocol);

  // --- password: memorizzata in registry per pochi istanti, letta da
  //     PowerShell e rimossa PRIMA di avviare lo script (mai in riga
  //     di comando) ---
  if (Identity <> 'ApplicationPoolIdentity') and (Identity <> 'NetworkService') and
     (Identity <> 'LocalSystem') and (not IsGMSA) and (Password <> '') then
    RegWriteStringValue(HKLM, RegPwKey, 'AppPoolPassword', Password);

  // --- costruzione dei parametri di Install-PkiPortal.ps1 ---
  ScriptParams := ' -SiteName "' + SiteName + '"';
  ScriptParams := ScriptParams + ' -SitePort ' + SitePort;
  if HostHeader <> '' then
    ScriptParams := ScriptParams + ' -SiteHostHeader "' + HostHeader + '"';
  ScriptParams := ScriptParams + ' -InstallPath "' + InstallPath + '"';
  if Identity <> 'ApplicationPoolIdentity' then
    ScriptParams := ScriptParams + ' -AppPoolIdentity "' + Identity + '"';
  if IsGMSA then
    ScriptParams := ScriptParams + ' -IsGMSA';
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

    if (Identity <> 'ApplicationPoolIdentity') and (Identity <> 'NetworkService') and
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
  if CurStep = ssPreInstall then
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
    // installazione completata)
    RegDeleteValue(HKLM, RegPwKey, 'AppPoolPassword');
    RegDeleteKeyIfEmpty(HKLM, RegPwKey);
  end;
end;
