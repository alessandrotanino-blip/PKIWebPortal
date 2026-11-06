; ============================================================================
; PkiPortal - Installer Windows (Inno Setup 6)
;
; Crea un setup EXE standard Windows che esegue le stesse operazioni di
; Install-PkiPortal.ps1, con una finestra wizard per inserire i parametri:
;   - nome sito IIS, porta, host header
;   - identità dell'Application Pool (ApplicationPoolIdentity / NetworkService
;     / LocalSystem / account di dominio / gMSA) e relativa password
;   - protocollo HTTPS (con selezione certificato) oppure HTTP in chiaro
;     (solo con esplicito override, come lo script >= 2.1.0)
;   - opzioni firewall e sovrascrittura configurazione
;
; I file applicativi sono pre-pubblicati (cartella ../publish, v2.4.0): il
; server di destinazione NON richiede .NET SDK né accesso a NuGet.
;
; Compilazione:  "C:\...\Inno Setup 6\ISCC.exe" PkiPortal.iss
; Output:        ..\build\PkiPortal-Setup-2.4.0.exe
; ============================================================================

#define MyAppName        "PkiPortal"
#define MyAppVersion     "2.4.0"
#define MyAppPublisher   "Enterprise PKI Team"
#define MyAppExeName     "PkiPortal.exe"

[Setup]
AppId={{6E3B7A41-9C2D-4F5E-8A1B-D4C6F9E2B0A3}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName=PkiPortal - Portale PKI Web Enrollment
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
UninstallDisplayName={#MyAppName} (Portale PKI Web Enrollment)
UninstallDisplayIcon={app}\{#MyAppExeName}
LicenseFile=..\LICENSE
Compression=lzma2/max
SolidCompression=yes
SetupLogging=yes
ShowLanguageDialog=auto
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoProductName=PkiPortal

[Languages]
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

; ----------------------------------------------------------------------------
; File applicativi pre-pubblicati (output di dotnet publish, v2.4.0)
; appsettings.json e web.config sono copiati solo alla PRIMA installazione
; (o sempre con la casella "Sovrascrivi configurazione"), in modo da
; preservare la configurazione esistente durante gli aggiornamenti,
; esattamente come fa lo script originale.
; ----------------------------------------------------------------------------
[Files]
Source: "..\publish\*";        DestDir: "{app}"; Flags: recursesubdirs createallsubdirs; Excludes: "appsettings.json,web.config"
Source: "..\publish\appsettings.json"; DestDir: "{app}"; Check: ShouldCopyConfig('appsettings.json')
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
  // Come lo script: i file di configurazione vengono copiati solo alla prima
  // installazione, salvo esplicita richiesta di sovrascrittura.
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
// ----------------------------------------------------------------------------
procedure InitializeWizard;
begin
  // ================= Pagina 1: parametri sito =================
  SitePage := CreateCustomPage(wpSelectDir,
    'Parametri del sito IIS',
    'Configura nome, porta e host header del sito IIS del portale.');
  AddLabel(SitePage, 0, 'Nome del sito IIS:');
  SiteNameEdit := AddEdit(SitePage, 0, 250);
  SiteNameEdit.Text := 'PkiWebEnrollment';
  AddLabel(SitePage, RowH, 'Porta:');
  SitePortEdit := AddEdit(SitePage, RowH, 80);
  SitePortEdit.Text := '8443';
  AddLabel(SitePage, 2 * RowH, 'Host header (facoltativo):');
  HostHeaderEdit := AddEdit(SitePage, 2 * RowH, 250);

  // ================= Pagina 2: identità Application Pool =================
  IdentityPage := CreateCustomPage(SitePage.ID,
    'Identità dell''Application Pool',
    'Identità con cui gira il pool IIS. Per un account di dominio inserire la password; per un gMSA non è necessaria.');
  AddLabel(IdentityPage, 0, 'Identità:');
  IdentityCombo := AddCombo(IdentityPage, 0, 250);
  IdentityCombo.Items.Add('ApplicationPoolIdentity (predefinita)');
  IdentityCombo.Items.Add('NetworkService');
  IdentityCombo.Items.Add('LocalSystem');
  IdentityCombo.Items.Add('Account di dominio / gMSA');
  IdentityCombo.ItemIndex := 0;
  IdentityCombo.OnChange := @IdentityComboChanged;
  AddLabel(IdentityPage, RowH, 'Account (es. DOMINIO\servizio):');
  AccountEdit := AddEdit(IdentityPage, RowH, 250);
  AddLabel(IdentityPage, 2 * RowH, 'Password:');
  PasswordEdit := AddEdit(IdentityPage, 2 * RowH, 250);
  PasswordEdit.PasswordChar := '*';
  GMSACheck := AddCheck(IdentityPage, 3 * RowH, 'Group Managed Service Account (gMSA) - senza password');
  GMSACheck.OnClick := @GMSACheckChanged;

  // ================= Pagina 3: protocollo e certificato =================
  ProtocolPage := CreateCustomPage(IdentityPage.ID,
    'Protocollo e certificato',
    'HTTPS è fortemente consigliato in produzione: in HTTP in chiaro NTLM viaggia non cifrato (rischio capture/relay).');
  AddLabel(ProtocolPage, 0, 'Protocollo:');
  ProtocolCombo := AddCombo(ProtocolPage, 0, 300);
  ProtocolCombo.Items.Add('HTTPS (consigliato)');
  ProtocolCombo.Items.Add('HTTP in chiaro (solo ambienti di test isolati)');
  ProtocolCombo.ItemIndex := 0;
  ProtocolCombo.OnChange := @ProtocolComboChanged;
  AddLabel(ProtocolPage, RowH, 'Certificato SSL (LocalMachine\My):');
  CertCombo := AddCombo(ProtocolPage, RowH, 250);
  CertCombo.Items.Add('(Auto: più recente certificato valido nello store)');
  LoadCertCombo;
  CertCombo.ItemIndex := 0;
  AddLabel(ProtocolPage, 2 * RowH, 'Thumbprint (immissione manuale):');
  ManualThumbEdit := AddEdit(ProtocolPage, 2 * RowH, 250);
  AllowHttpCheck := AddCheck(ProtocolPage, 3 * RowH, 'Consenti installazione su HTTP in chiaro (SOLO test isolati)');

  // ================= Pagina 4: opzioni =================
  OptionsPage := CreateCustomPage(ProtocolPage.ID,
    'Opzioni',
    'Impostazioni aggiuntive dell''installazione.');
  SkipFirewallCheck := AddCheck(OptionsPage, 0, 'Non creare regola del firewall Windows (-SkipFirewall)');
  OverwriteConfigCheck := AddCheck(OptionsPage, RowH, 'Sovrascrivi appsettings.json e web.config esistenti (-OverwriteConfig)');

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
      MsgBox('Inserire un nome per il sito IIS.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (Pos(' ', S) > 0) or HasForbiddenQuote(S) or (Pos('/', S) > 0) or
       (Pos('\', S) > 0) or (Pos(':', S) > 0) then
    begin
      MsgBox('Il nome del sito IIS non deve contenere spazi, virgolette o caratteri speciali.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    Port := StrToIntDef(TrimS(SitePortEdit.Text), 0);
    if (Port < 1) or (Port > 65535) then
    begin
      MsgBox('Porta non valida: inserire un numero tra 1 e 65535.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    S := TrimS(HostHeaderEdit.Text);
    if HasForbiddenQuote(S) or (Pos('/', S) > 0) or (Pos('\', S) > 0) then
    begin
      MsgBox('Il host header non deve contenere virgolette o slash.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end
  else if CurPageID = wpSelectDir then
  begin
    DirValue := WizardDirValue;
    if HasForbiddenQuote(DirValue) then
    begin
      MsgBox('Il percorso di installazione non deve contenere apostrofi o virgolette.', mbError, MB_OK);
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
        MsgBox('Inserire l''account (es. DOMINIO\servizio o DOMINIO\gmsa$).', mbError, MB_OK);
        Result := False;
        Exit;
      end;
      if HasForbiddenQuote(S) then
      begin
        MsgBox('Il nome account non deve contenere apostrofi o virgolette.', mbError, MB_OK);
        Result := False;
        Exit;
      end;
      if (not GMSACheck.Checked) and (PasswordEdit.Text = '') then
      begin
        MsgBox('Inserire la password dell''account, oppure spuntare gMSA se è un Group Managed Service Account.', mbError, MB_OK);
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
        MsgBox('Installazione su HTTP in chiaro BLOCCATA (NTLM non cifrato: rischio capture degli hash, NTLM relay e esposizione dei carichi sensibili del portale).' + #13#10 +
              'Selezionare HTTPS oppure spuntare ""Consenti installazione su HTTP in chiaro"" (solo ambienti di test isolati).', mbError, MB_OK);
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
  ScriptParams, PSArgs, PwParams: String;
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

  if (Identity <> 'ApplicationPoolIdentity') and (Identity <> 'NetworkService') and
     (Identity <> 'LocalSystem') and (not IsGMSA) and (Password <> '') then
  begin
    // Versione con password: comando PowerShell in cui i valori sono tra
    // virgolette singole (nessuna virgoletta doppia all'interno, così la
    // quote di riga di comando resta intatta).
    PwParams := ScriptParams;
    StringChange(PwParams, '"', '''');
    PSArgs := '-NoProfile -ExecutionPolicy Bypass -Command "' +
      '$pw = (Get-ItemProperty -Path ''HKLM:\' + RegPwKey + ''').AppPoolPassword; ' +
      'Remove-ItemProperty -Path ''HKLM:\' + RegPwKey + ''' -Name AppPoolPassword -Force -ErrorAction SilentlyContinue; ' +
      '$ss = $pw | ConvertTo-SecureString -AsPlainText -Force; ' +
      '& ''' + Script + '''' +
      PwParams + ' -AppPoolPassword $ss' +
      '"';
  end
  else
  begin
    PSArgs := '-NoProfile -ExecutionPolicy Bypass -File "' + Script + '"' + ScriptParams;
  end;

  // --- esecuzione in console visibile: l'amministratore vede tutto
  //     l'output e può rispondere ai prompt interattivi (Read-Host) ---
  if not Exec(GetPS, PSArgs, '', SW_SHOWNORMAL, ewWaitUntilTerminated, EC) then
  begin
    MsgBox('Impossibile avviare PowerShell per l''installazione di IIS. ' +
           'L''installazione non è stata completata.', mbError, MB_OK);
    Abort;
  end;

  // pulizia eventuale residua della password e della chiave
  RegDeleteValue(HKLM, RegPwKey, 'AppPoolPassword');
  RegDeleteKeyIfEmpty(HKLM, RegPwKey);

  if EC <> 0 then
  begin
    MsgBox('Installazione NON completata: Install-PkiPortal.ps1 ha terminato con codice ' + IntToStr(EC) + '.' + #13#10 +
           'Rivedere gli errori nella finestra di PowerShell, poi rieseguire il setup o lo script manuale.', mbError, MB_OK);
    Abort;
  end;

  if UseHttps then
    BaseUrl := 'https://localhost:' + SitePort
  else
    BaseUrl := 'http://localhost:' + SitePort;
  Url := BaseUrl + '/admin';
  if MsgBox('Installazione completata con successo.' + #13#10 + #13#10 +
            'Portale:    ' + BaseUrl + #13#10 +
            'Pannello:   ' + Url + #13#10 +
            'ACME:       ' + BaseUrl + '/acme/directory' + #13#10 + #13#10 +
            'Prossimi passi: configurare le Sub-CA reali in ' + InstallPath + '\appsettings.json ' +
            'e verificare i permessi dell''identità del pool sui template AD CS.' + #13#10 + #13#10 +
            'Aprire ora il pannello di amministrazione nel browser?',
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

