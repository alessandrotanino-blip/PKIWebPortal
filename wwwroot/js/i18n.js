/**
 * PKI Portal - Internationalization (i18n) Module
 * Supports 5 languages: Italian (it), English (en), French (fr), German (de), Spanish (es).
 * Features flag icons, dropdown language picker, and reactive UI translation.
 */
window.I18N = (function () {
  'use strict';

  const STORAGE_KEY = 'pki_portal_lang';

  const flagSvgs = {
    it: '<svg class="flag-icon" viewBox="0 0 18 12" width="18" height="12"><rect width="6" height="12" fill="#009246"/><rect x="6" width="6" height="12" fill="#ffffff"/><rect x="12" width="6" height="12" fill="#ce2b37"/></svg>',
    en: '<svg class="flag-icon" viewBox="0 0 60 30" width="18" height="12"><clipPath id="uk-clip-i18n"><path d="M0 0 v30 h60 v-30 z"/></clipPath><clipPath id="uk-diag-i18n"><path d="M30 15 h30 v15 z v15 h-30 z h-30 v-15 z v-15 h30 z"/></clipPath><g clip-path="url(#uk-clip-i18n)"><path d="M0 0 v30 h60 v-30 z" fill="#012169"/><path d="M0 0 L60 30 M60 0 L0 30" stroke="#ffffff" stroke-width="6"/><path d="M0 0 L60 30 M60 0 L0 30" clip-path="url(#uk-diag-i18n)" stroke="#C8102E" stroke-width="4"/><path d="M30 0 v30 M0 15 h60" stroke="#ffffff" stroke-width="10"/><path d="M30 0 v30 M0 15 h60" stroke="#C8102E" stroke-width="6"/></g></svg>',
    fr: '<svg class="flag-icon" viewBox="0 0 18 12" width="18" height="12"><rect width="6" height="12" fill="#002395"/><rect x="6" width="6" height="12" fill="#ffffff"/><rect x="12" width="6" height="12" fill="#ed2939"/></svg>',
    de: '<svg class="flag-icon" viewBox="0 0 18 12" width="18" height="12"><rect width="18" height="4" fill="#000000"/><rect y="4" width="18" height="4" fill="#dd0000"/><rect y="8" width="18" height="4" fill="#ffce00"/></svg>',
    es: '<svg class="flag-icon" viewBox="0 0 18 12" width="18" height="12"><rect width="18" height="3" fill="#aa151b"/><rect y="3" width="18" height="6" fill="#f1bf00"/><rect y="9" width="18" height="3" fill="#aa151b"/></svg>'
  };

  const languagesMeta = {
    it: { code: 'IT', name: 'Italiano', flagSvg: flagSvgs.it, locale: 'it-IT' },
    en: { code: 'EN', name: 'English', flagSvg: flagSvgs.en, locale: 'en-US' },
    fr: { code: 'FR', name: 'Français', flagSvg: flagSvgs.fr, locale: 'fr-FR' },
    de: { code: 'DE', name: 'Deutsch', flagSvg: flagSvgs.de, locale: 'de-DE' },
    es: { code: 'ES', name: 'Español', flagSvg: flagSvgs.es, locale: 'es-ES' }
  };

  const resources = {
    it: {
      // General & Header
      portal_title: "Enterprise PKI Web Enrollment",
      portal_subtitle: "Active Directory Certificate Services (AD CS) Modern Gateway",
      theme_toggle_title: "Cambia tema",
      lang_select_title: "Seleziona lingua",
      lang_toggle_title: "Cambia lingua",
      ca_label: "CA di Emissione:",
      portal_mode_hub: "Modalità Hub",
      portal_mode_standalone: "Modalità Singola CA",
      user_checking: "Verifica accesso...",
      admin_btn: "⚙️ Admin",
      back_to_portal: "Torna al Portale",

      // Tabs
      tab_wizard: "Nuova Richiesta (Browser Web Crypto)",
      tab_upload: "Invia CSR Esistente (Base64 / File)",
      tab_pending: "Ritiro Certificati (Pending o Emessi)",
      tab_automation: "Automazione & win-acme",

      // Tab 1 Wizard
      wizard_step1_title: "1. Seleziona il Certificate Template",
      wizard_step1_sub: "Scegli la tipologia di certificato da emettere dalla Sub-CA selezionata:",
      wizard_step2_title: "2. Dati del Soggetto (Subject DN)",
      field_cn: "Common Name (CN) *",
      placeholder_cn: "es. portal.azienda.lan o web01.azienda.lan",
      hint_cn: "Nome principale dell'host o servizio",
      field_o: "Organizzazione (O)",
      placeholder_o: "es. Azienda S.p.A.",
      field_ou: "Unità Organizzativa (OU)",
      placeholder_ou: "es. IT Security / DevOps",
      field_c: "Paese (C)",
      wizard_step3_title: "3. Subject Alternative Names (SAN)",
      wizard_step3_sub: "Aggiungi nomi DNS alternativi o indirizzi IP associati al certificato:",
      btn_add_san: "Aggiungi SAN",
      placeholder_san_val: "es. app.azienda.lan o 10.0.1.50",
      san_empty_hint: "Nessun SAN alternativo aggiunto (il CN verrà inserito automaticamente)",
      wizard_step4_title: "4. Parametri Chiave & Password PFX",
      wizard_step4_sub: "La chiave privata viene generata in memoria direttamente all'interno del browser (Web Crypto). Il server riceve solo la richiesta pubblica CSR.",
      field_key_algo: "Tipo e Dimensione Chiave",
      opt_rsa_2048: "RSA 2048 bit (Standard compatibilità)",
      opt_rsa_4096: "RSA 4096 bit (Alta sicurezza)",
      opt_rsa_3072: "RSA 3072 bit",
      field_pfx_pwd: "Password di Protezione PFX *",
      placeholder_pfx_pwd: "Imposta password per il file .pfx scaricato",
      hint_pfx_pwd: "Necessaria per proteggere il file .pfx contenente la chiave privata",
      btn_submit_wizard: "Genera Chiave & Richiedi Certificato",

      // Tab 2 Upload CSR
      upload_title: "Carica o Incolla una Richiesta CSR (PKCS#10)",
      upload_sub: "Utilizza questa modalità per certificati destinati a server Linux, switch, firewall o apparati di rete la cui chiave privata è già stata generata localmente:",
      field_csr_text: "Richiesta CSR (Formato Base64 / PEM) *",
      btn_select_file: "📁 Seleziona File (.csr / .req)",
      btn_parse_csr: "🔍 Ispeziona CSR",
      csr_preview_title: "Dati Rilevati nel CSR:",
      upload_template_select: "Seleziona Template AD CS di Destinazione *",
      btn_submit_upload: "Invia CSR alla CA",

      // Tab 3 Retrieve
      pending_title: "Ritiro Certificato (Pending o già Emesso)",
      pending_sub: "Inserisci il Request ID della richiesta per ritirare il certificato emesso o verificarne lo stato di approvazione.",
      pending_security_note: "🔒 Controllo Sicurezza: Per tutelare la riservatezza delle chiavi e dei dati, il recupero è consentito esclusivamente all'utente che ha sottomesso la richiesta o a un amministratore.",
      field_req_id: "Request ID (#) *",
      placeholder_req_id: "es. 1042",
      btn_check_pending: "Verifica Stato & Scarica",
      my_requests_title: "📋 I Tuoi Certificati e Richieste",
      my_requests_subtitle: "Tutte le richieste registrate a nome del tuo account utente Windows.",
      btn_refresh: "🔄 Aggiorna Elenco",
      loading_my_requests: "Caricamento delle tue richieste in corso...",
      th_id_date: "ID / Data",
      th_template: "Template",
      th_cn: "Common Name",
      th_ca: "CA",
      th_status: "Stato",
      th_actions: "Azioni",

      // Tab 4 Automation
      automation_title: "Automazione Rilascio Certificati & win-acme",
      automation_sub: "Questo portale espone API RESTful moderne che consentono di automatizzare le richieste da script PowerShell, Ansible, cURL o client ACME:",
      automation_winacme_title: "1. Integrazione con win-acme",
      automation_winacme_desc: "win-acme è un client ACME per Windows. Per utilizzarlo verso la vostra PKI aziendale senza esporre direttamente la CA:",
      automation_winacme_li1: "Il portale funge da Registration Authority (RA) intermediaria.",
      automation_winacme_li2: "I server interni possono eseguire uno script PowerShell di rinnovo automatico schedulato via Windows Task Scheduler senza bisogno di installare componenti DCOM complessi sulle macchine client.",
      automation_ps_title: "2. Esempio Richiesta Automatica via PowerShell",

      // Result Section & PFX Download
      result_title: "Certificato Emesso con Successo!",
      pfx_card_title: "Archivio PFX (.pfx)",
      pfx_card_desc: "Contiene certificato + chiave privata cifrata per Windows / IIS",
      btn_dl_pfx: "Scarica PFX",
      crt_card_title: "Certificato (.crt)",
      crt_card_desc: "Certificato X.509 firmato in formato Base64 PEM",
      btn_dl_crt: "Scarica .CRT",
      chain_card_title: "Catena Completa (.p7b)",
      chain_card_desc: "Include la Sub-CA di emissione e la Root CA aziendale",
      btn_dl_chain: "Scarica Catena",

      // Modals
      progress_title: "Generazione Crittografica in Corso...",
      progress_desc: "Creazione della coppia di chiavi RSA nel browser...",
      pfx_modal_title: "Download Archivio PFX (.pfx)",
      pfx_modal_desc: "Inserisci una password per proteggere il certificato e la chiave privata nel file PKCS#12 (PFX):",
      pfx_modal_pwd_label: "Password PFX *",
      placeholder_pfx_modal_pwd: "Inserisci password di protezione...",
      hint_pfx_modal_pwd: "Questa password sarà richiesta durante l'importazione del certificato su Windows / IIS / Linux.",
      btn_cancel: "Annulla",
      btn_confirm_pfx: "Genera & Scarica PFX",
      footer_text: "Enterprise PKI Web Enrollment Gateway • Sostituto moderno Microsoft AD CS / certsrv • HTML5 & Web Crypto API",
      footer_author_label: "Autore:",

      // Dynamic Badges & Messages
      requires_approval_badge: "Richiede Approvazione",
      auto_issued_badge: "Emissione Automatica",
      access_denied_template: "Non autorizzato (gruppi AD)",
      status_issued: "Emesso",
      status_pending: "In Approvazione",
      status_rejected: "Rifiutato",
      status_under_submission: "In Sottomissione CA",
      no_requests_found: "Nessuna richiesta certificato trovata a tuo nome.",
      login_required: "Effettua l'accesso per visualizzare lo storico delle tue richieste.",
      err_enter_cn: "Inserire almeno il Common Name (CN).",
      err_enter_pfx_pwd: "La password per proteggere il file .pfx è obbligatoria.",
      err_select_template: "Selezionare un template valido.",
      err_enter_csr: "Inserire o caricare un CSR valido.",
      err_enter_req_id: "Inserire un ID richiesta valido.",

      // Approvals & PFX Flow (Nuove traduzioni)
      msg_pending_submission_wizard: "Richiesta inoltrata con successo!\n\nLa richiesta è in attesa di approvazione manuale (Pending).\nRequest ID: #{requestId}\n\nUna volta approvata dall'amministratore, potrai ritirarla dalla scheda \"Ritiro Certificati\" scaricando sia il certificato (.crt) sia l'archivio con chiave privata (.pfx).",
      msg_pending_submission_upload: "Richiesta inviata con successo!\n\nStato: In attesa di approvazione (Pending).\nRequest ID: #{requestId}",
      pending_status_box_title: "Stato Richiesta: In Attesa o Non Disponibile",
      pending_status_box_desc: "Richiesta ancora in attesa di approvazione.",
      pending_ready_title: "Certificato Pronto ed Emesso!",
      pending_ready_desc: "La richiesta #{requestId} è stata approvata/emessa con successo.",
      pending_dl_pfx_btn: "🔐 Scarica Archivio PFX (.pfx)",
      pending_dl_crt_btn: "📄 Scarica Certificato (.crt)",
      pending_dl_p7b_btn: "🔗 Scarica Catena Completa (.p7b)",
      pending_dl_chain_btn: "📜 Scarica Catena (.crt)",
      auth_required_title: "Autenticazione Richiesta",
      auth_required_desc: "È necessario accedere con il proprio account utente per verificare e scaricare i certificati.",
      access_denied_security_title: "Accesso Negato (Controllo di Sicurezza)",
      access_denied_security_desc: "Non sei autorizzato a recuperare questo certificato. Il recupero è consentito esclusivamente a chi ha effettuato la richiesta o a un amministratore.",
      access_denied_security_not_owner: "Accesso negato: La richiesta #{requestId} non risulta associata al tuo account ({currentUser}). Solo il richiedente originale o un amministratore possono recuperare il certificato.",
      cert_not_available_dl: "Certificato non disponibile per il download.",
      requester_label: "Richiedente:",
      unspecified_label: "Non specificato",
      progress_pfx_title: "Creazione Archivio PFX",
      progress_pfx_desc: "Assemblaggio del pacchetto PKCS#12 (.pfx) protetto da password...",
      progress_pfx_retrieving_title: "Recupero Certificato & Chiave",
      progress_pfx_retrieving_desc: "Recupero archivio PKCS#12 per richiesta #{requestId}...",
      err_pfx_creation: "Errore durante la creazione del file PFX: ",
      err_pfx_no_key: "Chiave privata non disponibile per questa richiesta.",
      pfx_prompt_password: "Inserisci la password per proteggere il file PFX (opzionale):",
      th_requester: "Richiedente",
      th_date: "Data",
      th_action: "Azione",
      btn_dl_row_crt_title: "Scarica Certificato .CRT",
      btn_dl_row_pfx_title: "Scarica Archivio PFX con chiave privata",
      days_unit: "giorni",
      progress_crypto_local_title: "Generazione Crittografica Locale",
      progress_crypto_local_desc: "Creazione della coppia di chiavi RSA/ECC nel browser tramite Web Crypto...",
      progress_submitting_ca_title: "Sottomissione alla CA",
      progress_submitting_ca_desc: "Invio sicuro del CSR alla Sub-CA Microsoft AD CS...",
      progress_submitting_csr_title: "Sottomissione CSR",
      progress_submitting_csr_desc: "Invio del CSR Base64 alla Subordinate CA AD CS...",
      progress_retrieving_cert_title: "Recupero Certificato",
      progress_retrieving_cert_desc: "Download certificato per richiesta #{requestId}...",
      progress_checking_status_title: "Verifica Stato Richiesta",
      progress_checking_status_desc: "Interrogazione CA per la richiesta #{requestId}...",
      connected_as: "Connesso come",
      anonymous_user: "Anonimo",
      unauthenticated_user: "Non autenticato",
      all_requests_admin_title: "📋 Tutti i Certificati e Richieste (Amministratore)",
      all_requests_admin_subtitle: "Elenco globale di tutte le richieste registrate nel portale.",
      no_templates_ca: "Nessun template configurato per questa CA.",
      no_templates_avail: "Nessun template disponibile",
      unauthorized_template_alert: "Template non autorizzato: per emettere certificati con questo template è richiesta l'appartenenza a uno dei gruppi AD configurati. Contatta un amministratore del portale.",
      not_authorized_tag: " — Non autorizzato",

      // Admin Screen
      admin_panel_title: "Configurazione Portale PKI",
      admin_panel_sub: "Pannello di Amministrazione",
      admin_header_title: "Pannello Amministrazione Portale PKI",
      access_denied_title: "Accesso Negato",
      access_denied_text: "Non disponi dei permessi necessari per accedere a questa sezione.<br>Contatta un amministratore del server.",
      tab_requests: "📋 Richieste Certificato",
      tab_config: "⚙️ Configurazione Portale & CA",
      filter_status_label: "Filtra per stato:",
      filter_pending: "In Attesa di Approvazione",
      filter_all: "Tutte le Richieste",
      filter_approved: "Solo Approvate",
      filter_rejected: "Solo Rifiutate",
      btn_refresh_list: "🔄 Aggiorna Lista",
      loading_requests: "Caricamento richieste in corso...",
      general_settings_title: "Impostazioni Generali",
      field_portal_title: "Titolo Portale",
      field_portal_mode: "Modalità Portale",
      opt_mode_standalone: "Standalone (CA Singola)",
      opt_mode_hub: "Hub Multi-CA",
      field_default_ca: "CA Predefinita (ID)",
      ca_section_title: "Configurazione Certificate Authorities",
      btn_add_ca: "Aggiungi CA",
      btn_cancel_changes: "Annulla Modifiche",
      btn_save_config: "Salva Configurazione",
      admin_footer: "Enterprise PKI Web Enrollment Gateway • Pannello Amministrativo",
      btn_approve: "✅ Approva",
      btn_reject: "❌ Rifiuta",
      btn_view_cert: "Visualizza Certificato",
      btn_discover: "🔍 Scopri dalla CA",
      btn_add_template_manual: "+ Aggiungi Manualmente",
      confirm_approve: "Approvare questa richiesta?",
      prompt_reject_reason: "Motivo del rifiuto (opzionale):",
      confirm_remove_ca: "Rimuovere questa CA dalla configurazione?",
      confirm_remove_template: "Rimuovere questo template?",
      toast_config_saved: "Configurazione salvata con successo.",
      toast_request_approved: "Richiesta approvata con successo.",
      toast_request_rejected: "Richiesta rifiutata.",
      admin_new_ca: "Nuova CA",
      admin_default_tag: "Predefinita",
      admin_simulator_tag: "Simulatore",
      admin_remove_ca_title: "Rimuovi CA",
      admin_lbl_display_name: "Nome Visualizzato",
      admin_lbl_forest: "Foresta / Dominio",
      admin_lbl_description: "Descrizione",
      admin_lbl_auth_mode: "Modalità Auth",
      admin_lbl_default_ca: "CA Predefinita",
      admin_lbl_simulator: "Usa Simulatore",
      admin_click_discover: "Clicca \"Scopri dalla CA\"",
      admin_btn_add: "+ Aggiungi",
      admin_new_template: "Nuovo Template",
      admin_lbl_sys_name: "Nome Sistema",
      admin_lbl_validity: "Validità (giorni)",
      admin_validity_note: "Prelevata dalla definizione del template AD CS (KeyUsagePeriod); non modificabile manualmente. Aggiorna il valore con \"Scopri dalla CA\".",
      admin_lbl_manual_approval: "Approvazione Manuale",
      admin_lbl_key_types: "Tipi Chiave",
      admin_lbl_allowed_groups: "Gruppi AD Autorizzati",
      admin_allowed_groups_placeholder: "Vuoto = tutti gli utenti (es. VD\\Web-Team, LD\\App-Admin)",
      admin_allowed_groups_hint: "Solo gli utenti di questi gruppi possono emettere con questo template (gli amministratori del portale sono sempre ammessi).",
      admin_no_requests_found: "Nessuna richiesta trovata",
      admin_no_requests_desc: "Non ci sono certificati trattenuti con il filtro selezionato.",
      admin_submitted_label: "Sottomesso:",
      admin_anon_unauth: "Anonimo / Non autenticato",
      admin_requester_notes: "Note Richiedente:",
      admin_reviewed_label: "Revisionato:",
      admin_by_label: "da",
      admin_rejection_reason_label: "Motivo Rifiuto:",
      admin_btn_reject_req: "❌ Rifiuta Richiesta",
      admin_btn_approve_req: "✅ Approva & Rilascia Certificato",
      admin_pending_ca_hint: "In attesa di approvazione sulla CA ADCS",
      admin_user_label: "Utente:",
      admin_confirm_approve_req: "Confermi l'approvazione del certificato con Hold ID '{0}'?\n\nIl certificato diverrà scaricabile dal richiedente.",
      admin_prompt_reject_req: "Inserisci il motivo del rifiuto per la richiesta '{0}' (opzionale):",
      admin_toast_approved: "Certificato approvato con successo!",
      admin_toast_approve_error: "Impossibile approvare",
      admin_toast_rejected: "Richiesta rifiutata.",
      admin_toast_reject_error: "Impossibile rifiutare",
      admin_toast_comm_error: "Errore di comunicazione: ",
      admin_loading_cert: "Caricamento dettagli certificato...",
      admin_no_cert_stored: "Nessun certificato archiviato per questa richiesta.",
      admin_cert_retrieve_error: "Errore nel recupero del certificato: ",
      admin_auth_required: "Autenticazione richiesta.",
      admin_conn_error: "Errore di connessione",
      admin_config_load_error: "Impossibile caricare la configurazione",
      admin_unknown_user: "Sconosciuto"
    },

    en: {
      // General & Header
      portal_title: "Enterprise PKI Web Enrollment",
      portal_subtitle: "Active Directory Certificate Services (AD CS) Modern Gateway",
      theme_toggle_title: "Toggle theme",
      lang_select_title: "Select language",
      lang_toggle_title: "Switch language",
      ca_label: "Issuing CA:",
      portal_mode_hub: "Hub Mode",
      portal_mode_standalone: "Single CA Mode",
      user_checking: "Checking access...",
      admin_btn: "⚙️ Admin",
      back_to_portal: "Back to Portal",

      // Tabs
      tab_wizard: "New Request (Browser Web Crypto)",
      tab_upload: "Submit Existing CSR (Base64 / File)",
      tab_pending: "Retrieve Certificates (Pending or Issued)",
      tab_automation: "Automation & win-acme",

      // Tab 1 Wizard
      wizard_step1_title: "1. Select Certificate Template",
      wizard_step1_sub: "Choose the certificate type to issue from the selected Sub-CA:",
      wizard_step2_title: "2. Subject Data (Subject DN)",
      field_cn: "Common Name (CN) *",
      placeholder_cn: "e.g. portal.domain.lan or web01.domain.lan",
      hint_cn: "Primary hostname or service name",
      field_o: "Organization (O)",
      placeholder_o: "e.g. Acme Corp",
      field_ou: "Organizational Unit (OU)",
      placeholder_ou: "e.g. IT Security / DevOps",
      field_c: "Country (C)",
      wizard_step3_title: "3. Subject Alternative Names (SAN)",
      wizard_step3_sub: "Add alternative DNS names or IP addresses associated with the certificate:",
      btn_add_san: "Add SAN",
      placeholder_san_val: "e.g. app.domain.lan or 10.0.1.50",
      san_empty_hint: "No alternative SANs added (CN will be added automatically)",
      wizard_step4_title: "4. Key Parameters & PFX Password",
      wizard_step4_sub: "The private key is generated in memory directly inside the browser (Web Crypto). The server only receives the public CSR request.",
      field_key_algo: "Key Type and Size",
      opt_rsa_2048: "RSA 2048 bit (Standard compatibility)",
      opt_rsa_4096: "RSA 4096 bit (High security)",
      opt_rsa_3072: "RSA 3072 bit",
      field_pfx_pwd: "PFX Protection Password *",
      placeholder_pfx_pwd: "Set password for downloaded .pfx file",
      hint_pfx_pwd: "Required to protect the .pfx file containing the private key",
      btn_submit_wizard: "Generate Key & Request Certificate",

      // Tab 2 Upload CSR
      upload_title: "Upload or Paste a CSR Request (PKCS#10)",
      upload_sub: "Use this mode for certificates intended for Linux servers, switches, firewalls, or network appliances whose private key has already been generated locally:",
      field_csr_text: "CSR Request (Base64 / PEM format) *",
      btn_select_file: "📁 Select File (.csr / .req)",
      btn_parse_csr: "🔍 Inspect CSR",
      csr_preview_title: "Detected CSR Data:",
      upload_template_select: "Select Target AD CS Template *",
      btn_submit_upload: "Submit CSR to CA",

      // Tab 3 Retrieve
      pending_title: "Retrieve Certificate (Pending or Issued)",
      pending_sub: "Enter the Request ID to retrieve the issued certificate or check its approval status.",
      pending_security_note: "🔒 Security Check: To protect the confidentiality of keys and data, retrieval is allowed exclusively to the user who submitted the request or an administrator.",
      field_req_id: "Request ID (#) *",
      placeholder_req_id: "e.g. 1042",
      btn_check_pending: "Check Status & Download",
      my_requests_title: "📋 Your Certificates and Requests",
      my_requests_subtitle: "All requests registered under your Windows user account.",
      btn_refresh: "🔄 Refresh List",
      loading_my_requests: "Loading your requests...",
      th_id_date: "ID / Date",
      th_template: "Template",
      th_cn: "Common Name",
      th_ca: "CA",
      th_status: "Status",
      th_actions: "Actions",

      // Tab 4 Automation
      automation_title: "Certificate Issuance Automation & win-acme",
      automation_sub: "This portal exposes modern RESTful APIs that allow automating requests from PowerShell, Ansible, cURL, or ACME clients:",
      automation_winacme_title: "1. Integration with win-acme",
      automation_winacme_desc: "win-acme is an ACME client for Windows. To use it against your enterprise PKI without exposing the CA directly:",
      automation_winacme_li1: "The portal acts as an intermediary Registration Authority (RA).",
      automation_winacme_li2: "Internal servers can run an automatic renewal PowerShell script scheduled via Windows Task Scheduler without requiring complex DCOM components on client machines.",
      automation_ps_title: "2. Automatic Request Example via PowerShell",

      // Result Section & PFX Download
      result_title: "Certificate Issued Successfully!",
      pfx_card_title: "PFX Archive (.pfx)",
      pfx_card_desc: "Contains certificate + encrypted private key for Windows / IIS",
      btn_dl_pfx: "Download PFX",
      crt_card_title: "Certificate (.crt)",
      crt_card_desc: "Signed X.509 certificate in Base64 PEM format",
      btn_dl_crt: "Download .CRT",
      chain_card_title: "Full Chain (.p7b)",
      chain_card_desc: "Includes the issuing Sub-CA and enterprise Root CA",
      btn_dl_chain: "Download Chain",

      // Modals
      progress_title: "Cryptographic Generation in Progress...",
      progress_desc: "Creating RSA keypair in browser...",
      pfx_modal_title: "Download PFX Archive (.pfx)",
      pfx_modal_desc: "Enter a password to protect the certificate and private key in the PKCS#12 (PFX) file:",
      pfx_modal_pwd_label: "PFX Password *",
      placeholder_pfx_modal_pwd: "Enter protection password...",
      hint_pfx_modal_pwd: "This password will be required when importing the certificate on Windows / IIS / Linux.",
      btn_cancel: "Cancel",
      btn_confirm_pfx: "Generate & Download PFX",
      footer_text: "Enterprise PKI Web Enrollment Gateway • Modern replacement for Microsoft AD CS / certsrv • HTML5 & Web Crypto API",
      footer_author_label: "Author:",

      // Dynamic Badges & Messages
      requires_approval_badge: "Requires Approval",
      auto_issued_badge: "Automatic Issuance",
      access_denied_template: "Not authorized (AD groups)",
      status_issued: "Issued",
      status_pending: "Pending Approval",
      status_rejected: "Rejected",
      status_under_submission: "CA In-Progress",
      no_requests_found: "No certificate requests found under your account.",
      login_required: "Please log in to view your request history.",
      err_enter_cn: "Please enter at least the Common Name (CN).",
      err_enter_pfx_pwd: "PFX protection password is required.",
      err_select_template: "Please select a valid template.",
      err_enter_csr: "Please enter or upload a valid CSR.",
      err_enter_req_id: "Please enter a valid request ID.",

      // Approvals & PFX Flow
      msg_pending_submission_wizard: "Request submitted successfully!\n\nThe request is pending manual approval.\nRequest ID: #{requestId}\n\nOnce approved by an administrator, you can retrieve it from the \"Retrieve Certificates\" tab, downloading both the certificate (.crt) and the private key archive (.pfx).",
      msg_pending_submission_upload: "Request submitted successfully!\n\nStatus: Pending approval.\nRequest ID: #{requestId}",
      pending_status_box_title: "Request Status: Pending or Unavailable",
      pending_status_box_desc: "Request still pending approval.",
      pending_ready_title: "Certificate Ready and Issued!",
      pending_ready_desc: "Request #{requestId} was successfully approved/issued.",
      pending_dl_pfx_btn: "🔐 Download PFX Archive (.pfx)",
      pending_dl_crt_btn: "📄 Download Certificate (.crt)",
      pending_dl_p7b_btn: "🔗 Download Full Chain (.p7b)",
      pending_dl_chain_btn: "📜 Download Chain (.crt)",
      auth_required_title: "Authentication Required",
      auth_required_desc: "Please sign in with your user account to verify and download certificates.",
      access_denied_security_title: "Access Denied (Security Check)",
      access_denied_security_desc: "You are not authorized to retrieve this certificate. Retrieval is restricted to the original requester or an administrator.",
      access_denied_security_not_owner: "Access denied: Request #{requestId} is not associated with your account ({currentUser}). Only the original requester or an administrator can retrieve the certificate.",
      cert_not_available_dl: "Certificate not available for download.",
      requester_label: "Requester:",
      unspecified_label: "Unspecified",
      progress_pfx_title: "Creating PFX Archive",
      progress_pfx_desc: "Assembling password-protected PKCS#12 (.pfx) bundle...",
      progress_pfx_retrieving_title: "Retrieving Certificate & Key",
      progress_pfx_retrieving_desc: "Retrieving PKCS#12 archive for request #{requestId}...",
      err_pfx_creation: "Error creating PFX file: ",
      err_pfx_no_key: "Private key not available for this request.",
      pfx_prompt_password: "Enter password to protect PFX file (optional):",
      th_requester: "Requester",
      th_date: "Date",
      th_action: "Action",
      btn_dl_row_crt_title: "Download .CRT Certificate",
      btn_dl_row_pfx_title: "Download PFX archive with private key",
      days_unit: "days",
      progress_crypto_local_title: "Local Cryptographic Generation",
      progress_crypto_local_desc: "Creating RSA/ECC keypair in browser using Web Crypto...",
      progress_submitting_ca_title: "Submitting to CA",
      progress_submitting_ca_desc: "Securely sending CSR to Microsoft AD CS Sub-CA...",
      progress_submitting_csr_title: "Submitting CSR",
      progress_submitting_csr_desc: "Sending Base64 CSR to Subordinate CA AD CS...",
      progress_retrieving_cert_title: "Retrieving Certificate",
      progress_retrieving_cert_desc: "Downloading certificate for request #{requestId}...",
      progress_checking_status_title: "Checking Request Status",
      progress_checking_status_desc: "Querying CA for request #{requestId}...",
      connected_as: "Connected as",
      anonymous_user: "Anonymous",
      unauthenticated_user: "Unauthenticated",
      all_requests_admin_title: "📋 All Certificates and Requests (Administrator)",
      all_requests_admin_subtitle: "Global list of all certificate requests registered in the portal.",
      no_templates_ca: "No templates configured for this CA.",
      no_templates_avail: "No templates available",
      unauthorized_template_alert: "Unauthorized template: membership in one of the configured AD groups is required to request certificates with this template. Please contact a portal administrator.",
      not_authorized_tag: " — Not authorized",

      // Admin Screen
      admin_panel_title: "PKI Portal Configuration",
      admin_panel_sub: "Administration Panel",
      admin_header_title: "PKI Portal Administration Panel",
      access_denied_title: "Access Denied",
      access_denied_text: "You do not have the required permissions to access this section.<br>Please contact a server administrator.",
      tab_requests: "📋 Certificate Requests",
      tab_config: "⚙️ Portal & CA Configuration",
      filter_status_label: "Filter by status:",
      filter_pending: "Pending Approval",
      filter_all: "All Requests",
      filter_approved: "Approved Only",
      filter_rejected: "Rejected Only",
      btn_refresh_list: "🔄 Refresh List",
      loading_requests: "Loading requests...",
      general_settings_title: "General Settings",
      field_portal_title: "Portal Title",
      field_portal_mode: "Portal Mode",
      opt_mode_standalone: "Standalone (Single CA)",
      opt_mode_hub: "Hub Multi-CA",
      field_default_ca: "Default CA (ID)",
      ca_section_title: "Certificate Authorities Configuration",
      btn_add_ca: "Add CA",
      btn_cancel_changes: "Cancel Changes",
      btn_save_config: "Save Configuration",
      admin_footer: "Enterprise PKI Web Enrollment Gateway • Administrative Panel",
      btn_approve: "✅ Approve",
      btn_reject: "❌ Reject",
      btn_view_cert: "View Certificate",
      btn_discover: "🔍 Discover from CA",
      btn_add_template_manual: "+ Add Manually",
      confirm_approve: "Approve this request?",
      prompt_reject_reason: "Reason for rejection (optional):",
      confirm_remove_ca: "Remove this CA from configuration?",
      confirm_remove_template: "Remove this template?",
      toast_config_saved: "Configuration saved successfully.",
      toast_request_approved: "Request approved successfully.",
      toast_request_rejected: "Request rejected.",
      admin_new_ca: "New CA",
      admin_default_tag: "Default",
      admin_simulator_tag: "Simulator",
      admin_remove_ca_title: "Remove CA",
      admin_lbl_display_name: "Display Name",
      admin_lbl_forest: "Forest / Domain",
      admin_lbl_description: "Description",
      admin_lbl_auth_mode: "Auth Mode",
      admin_lbl_default_ca: "Default CA",
      admin_lbl_simulator: "Use Simulator",
      admin_click_discover: "Click \"Discover from CA\"",
      admin_btn_add: "+ Add",
      admin_new_template: "New Template",
      admin_lbl_sys_name: "System Name",
      admin_lbl_validity: "Validity (days)",
      admin_validity_note: "Retrieved from AD CS template definition (KeyUsagePeriod); not editable manually. Refresh via \"Discover from CA\".",
      admin_lbl_manual_approval: "Manual Approval",
      admin_lbl_key_types: "Key Types",
      admin_lbl_allowed_groups: "Authorized AD Groups",
      admin_allowed_groups_placeholder: "Empty = all users (e.g. VD\\Web-Team, LD\\App-Admin)",
      admin_allowed_groups_hint: "Only users in these groups can request this template (portal administrators are always allowed).",
      admin_no_requests_found: "No requests found",
      admin_no_requests_desc: "There are no certificate requests matching the selected filter.",
      admin_submitted_label: "Submitted:",
      admin_anon_unauth: "Anonymous / Unauthenticated",
      admin_requester_notes: "Requester Notes:",
      admin_reviewed_label: "Reviewed:",
      admin_by_label: "by",
      admin_rejection_reason_label: "Rejection Reason:",
      admin_btn_reject_req: "❌ Reject Request",
      admin_btn_approve_req: "✅ Approve & Issue Certificate",
      admin_pending_ca_hint: "Pending approval on AD CS CA",
      admin_user_label: "User:",
      admin_confirm_approve_req: "Do you confirm approval of certificate with Hold ID '{0}'?\n\nThe certificate will become downloadable by the requester.",
      admin_prompt_reject_req: "Enter the rejection reason for request '{0}' (optional):",
      admin_toast_approved: "Certificate approved successfully!",
      admin_toast_approve_error: "Unable to approve",
      admin_toast_rejected: "Request rejected.",
      admin_toast_reject_error: "Unable to reject",
      admin_toast_comm_error: "Communication error: ",
      admin_loading_cert: "Loading certificate details...",
      admin_no_cert_stored: "No certificate stored for this request.",
      admin_cert_retrieve_error: "Error retrieving certificate: ",
      admin_auth_required: "Authentication required.",
      admin_conn_error: "Connection error",
      admin_config_load_error: "Unable to load configuration",
      admin_unknown_user: "Unknown"
    },

    fr: {
      // General & Header
      portal_title: "Enterprise PKI Web Enrollment",
      portal_subtitle: "Passerelle moderne Active Directory Certificate Services (AD CS)",
      theme_toggle_title: "Changer de thème",
      lang_select_title: "Choisir la langue",
      lang_toggle_title: "Changer de langue",
      ca_label: "AC émettrice :",
      portal_mode_hub: "Mode Hub",
      portal_mode_standalone: "Mode AC unique",
      user_checking: "Vérification de l'accès...",
      admin_btn: "⚙️ Admin",
      back_to_portal: "Retour au portail",

      // Tabs
      tab_wizard: "Nouvelle demande (Web Crypto intégrée)",
      tab_upload: "Soumettre un CSR existant (Base64 / Fichier)",
      tab_pending: "Récupérer des certificats (En attente ou délivrés)",
      tab_automation: "Automatisation & win-acme",

      // Tab 1 Wizard
      wizard_step1_title: "1. Sélectionner le modèle de certificat",
      wizard_step1_sub: "Choisissez le type de certificat à émettre depuis la sous-autorité sélectionnée :",
      wizard_step2_title: "2. Données du sujet (Subject DN)",
      field_cn: "Common Name (CN) *",
      placeholder_cn: "ex. portal.entreprise.lan ou web01.entreprise.lan",
      hint_cn: "Nom principal de l'hôte ou du service",
      field_o: "Organisation (O)",
      placeholder_o: "ex. Entreprise S.A.",
      field_ou: "Unité organisationnelle (OU)",
      placeholder_ou: "ex. Sécurité IT / DevOps",
      field_c: "Pays (C)",
      wizard_step3_title: "3. Noms alternatifs du sujet (SAN)",
      wizard_step3_sub: "Ajoutez des noms DNS alternatifs ou des adresses IP associés au certificat :",
      btn_add_san: "Ajouter SAN",
      placeholder_san_val: "ex. app.entreprise.lan ou 10.0.1.50",
      san_empty_hint: "Aucun SAN alternatif ajouté (le CN sera ajouté automatiquement)",
      wizard_step4_title: "4. Paramètres de clé & Mot de passe PFX",
      wizard_step4_sub: "La clé privée est générée en mémoire directement dans le navigateur (Web Crypto). Le serveur ne reçoit que la demande CSR publique.",
      field_key_algo: "Type et taille de clé",
      opt_rsa_2048: "RSA 2048 bits (Compatibilité standard)",
      opt_rsa_4096: "RSA 4096 bits (Haute sécurité)",
      opt_rsa_3072: "RSA 3072 bits",
      field_pfx_pwd: "Mot de passe de protection PFX *",
      placeholder_pfx_pwd: "Définir le mot de passe pour le fichier .pfx téléchargé",
      hint_pfx_pwd: "Nécessaire pour protéger le fichier .pfx contenant la clé privée",
      btn_submit_wizard: "Générer la clé & demander le certificat",

      // Tab 2 Upload CSR
      upload_title: "Téléverser ou coller une demande CSR (PKCS#10)",
      upload_sub: "Utilisez ce mode pour les certificats destinés aux serveurs Linux, commutateurs, pare-feux ou équipements réseau dont la clé privée a déjà été générée localement :",
      field_csr_text: "Demande CSR (Format Base64 / PEM) *",
      btn_select_file: "📁 Sélectionner un fichier (.csr / .req)",
      btn_parse_csr: "🔍 Inspecter le CSR",
      csr_preview_title: "Données détectées dans le CSR :",
      upload_template_select: "Sélectionner le modèle AD CS cible *",
      btn_submit_upload: "Envoyer le CSR à l'AC",

      // Tab 3 Retrieve
      pending_title: "Récupération de certificat (En attente ou délivré)",
      pending_sub: "Saisissez l'ID de demande pour récupérer le certificat délivré ou vérifier l'état d'approbation.",
      pending_security_note: "🔒 Contrôle de sécurité : Pour protéger la confidentialité des clés et des données, la récupération est réservée à l'utilisateur ayant soumis la demande ou à un administrateur.",
      field_req_id: "ID de demande (#) *",
      placeholder_req_id: "ex. 1042",
      btn_check_pending: "Vérifier le statut & télécharger",
      my_requests_title: "📋 Vos certificats et demandes",
      my_requests_subtitle: "Toutes les demandes enregistrées sous votre compte utilisateur Windows.",
      btn_refresh: "🔄 Actualiser la liste",
      loading_my_requests: "Chargement de vos demandes en cours...",
      th_id_date: "ID / Date",
      th_template: "Modèle",
      th_cn: "Common Name",
      th_ca: "AC",
      th_status: "Statut",
      th_actions: "Actions",

      // Tab 4 Automation
      automation_title: "Automatisation de la délivrance & win-acme",
      automation_sub: "Ce portail expose des API RESTful modernes permettant d'automatiser les demandes depuis PowerShell, Ansible, cURL ou des clients ACME :",
      automation_winacme_title: "1. Intégration avec win-acme",
      automation_winacme_desc: "win-acme est un client ACME pour Windows. Pour l'utiliser avec votre PKI d'entreprise sans exposer directement l'AC :",
      automation_winacme_li1: "Le portail agit comme une autorité d'enregistrement (RA) intermédiaire.",
      automation_winacme_li2: "Les serveurs internes peuvent exécuter un script PowerShell de renouvellement automatique planifié sans nécessiter de composants DCOM complexes.",
      automation_ps_title: "2. Exemple de demande automatique via PowerShell",

      // Result Section & PFX Download
      result_title: "Certificat Délivré avec Succès !",
      pfx_card_title: "Archive PFX (.pfx)",
      pfx_card_desc: "Contient le certificat + la clé privée chiffrée pour Windows / IIS",
      btn_dl_pfx: "Télécharger PFX",
      crt_card_title: "Certificat (.crt)",
      crt_card_desc: "Certificat X.509 signé au format Base64 PEM",
      btn_dl_crt: "Télécharger .CRT",
      chain_card_title: "Chaîne complète (.p7b)",
      chain_card_desc: "Comprend la sous-autorité émettrice et l'autorité racine de l'entreprise",
      btn_dl_chain: "Télécharger la chaîne",

      // Modals
      progress_title: "Génération Cryptographique en Cours...",
      progress_desc: "Création de la paire de clés RSA dans le navigateur...",
      pfx_modal_title: "Télécharger l'Archive PFX (.pfx)",
      pfx_modal_desc: "Saisissez un mot de passe pour protéger le certificat et la clé privée dans le fichier PKCS#12 (PFX) :",
      pfx_modal_pwd_label: "Mot de passe PFX *",
      placeholder_pfx_modal_pwd: "Saisissez le mot de passe de protection...",
      hint_pfx_modal_pwd: "Ce mot de passe sera requis lors de l'importation du certificat sur Windows / IIS / Linux.",
      btn_cancel: "Annuler",
      btn_confirm_pfx: "Générer & Télécharger PFX",
      footer_text: "Enterprise PKI Web Enrollment Gateway • Remplacement moderne pour Microsoft AD CS / certsrv • HTML5 & Web Crypto API",
      footer_author_label: "Auteur :",

      // Dynamic Badges & Messages
      requires_approval_badge: "Nécessite Approbation",
      auto_issued_badge: "Émission Automatique",
      access_denied_template: "Non autorisé (groupes AD)",
      status_issued: "Délivré",
      status_pending: "En cours d'approbation",
      status_rejected: "Rejeté",
      status_under_submission: "Soumission AC en cours",
      no_requests_found: "Aucune demande de certificat trouvée à votre nom.",
      login_required: "Veuillez vous connecter pour afficher l'historique de vos demandes.",
      err_enter_cn: "Veuillez saisir au moins le Common Name (CN).",
      err_enter_pfx_pwd: "Le mot de passe pour protéger le fichier .pfx est obligatoire.",
      err_select_template: "Veuillez sélectionner un modèle valide.",
      err_enter_csr: "Veuillez saisir ou téléverser un CSR valide.",
      err_enter_req_id: "Veuillez saisir un ID de demande valide.",

      // Approvals & PFX Flow
      msg_pending_submission_wizard: "Demande envoyée avec succès !\n\nLa demande est en attente d'approbation manuelle (En attente).\nID de demande : #{requestId}\n\nUne fois approuvée par un administrateur, vous pourrez la récupérer dans l'onglet « Récupérer des certificats » en téléchargeant le certificat (.crt) et l'archive avec clé privée (.pfx).",
      msg_pending_submission_upload: "Demande envoyée avec succès !\n\nStatut : En attente d'approbation.\nID de demande : #{requestId}",
      pending_status_box_title: "Statut de la demande : En attente ou indisponible",
      pending_status_box_desc: "Demande toujours en attente d'approbation.",
      pending_ready_title: "Certificat Prêt et Délivré !",
      pending_ready_desc: "La demande #{requestId} a été approuvée et délivrée avec succès.",
      pending_dl_pfx_btn: "🔐 Télécharger l'archive PFX (.pfx)",
      pending_dl_crt_btn: "📄 Télécharger le certificat (.crt)",
      pending_dl_p7b_btn: "🔗 Télécharger la chaîne complète (.p7b)",
      pending_dl_chain_btn: "📜 Télécharger la chaîne (.crt)",
      auth_required_title: "Authentification requise",
      auth_required_desc: "Veuillez vous connecter avec votre compte utilisateur pour vérifier et télécharger les certificats.",
      access_denied_security_title: "Accès refusé (contrôle de sécurité)",
      access_denied_security_desc: "Vous n'êtes pas autorisé à récupérer ce certificat. La récupération est réservée au demandeur initial ou à un administrateur.",
      access_denied_security_not_owner: "Accès refusé : la demande #{requestId} n'est pas associée à votre compte ({currentUser}). Seul le demandeur initial ou un administrateur peut récupérer le certificat.",
      cert_not_available_dl: "Certificat non disponible pour le téléchargement.",
      requester_label: "Demandeur :",
      unspecified_label: "Non spécifié",
      progress_pfx_title: "Création de l'archive PFX",
      progress_pfx_desc: "Assemblage du paquet PKCS#12 (.pfx) protégé par mot de passe...",
      progress_pfx_retrieving_title: "Récupération du certificat et de la clé",
      progress_pfx_retrieving_desc: "Récupération de l'archive PKCS#12 pour la demande #{requestId}...",
      err_pfx_creation: "Erreur lors de la création du fichier PFX : ",
      err_pfx_no_key: "Clé privée non disponible pour cette demande.",
      pfx_prompt_password: "Saisissez le mot de passe pour protéger le fichier PFX (optionnel) :",
      th_requester: "Demandeur",
      th_date: "Date",
      th_action: "Action",
      btn_dl_row_crt_title: "Télécharger le certificat .CRT",
      btn_dl_row_pfx_title: "Télécharger l'archive PFX avec clé privée",
      days_unit: "jours",
      progress_crypto_local_title: "Génération cryptographique locale",
      progress_crypto_local_desc: "Création de la paire de clés RSA/ECC dans le navigateur via Web Crypto...",
      progress_submitting_ca_title: "Soumission à l'AC",
      progress_submitting_ca_desc: "Envoi sécurisé du CSR à la sous-autorité Microsoft AD CS...",
      progress_submitting_csr_title: "Soumission du CSR",
      progress_submitting_csr_desc: "Envoi du CSR Base64 à la sous-autorité AD CS...",
      progress_retrieving_cert_title: "Récupération du certificat",
      progress_retrieving_cert_desc: "Téléchargement du certificat pour la demande #{requestId}...",
      progress_checking_status_title: "Vérification de l'état de la demande",
      progress_checking_status_desc: "Interrogation de l'AC pour la demande #{requestId}...",
      connected_as: "Connecté en tant que",
      anonymous_user: "Anonyme",
      unauthenticated_user: "Non authentifié",
      all_requests_admin_title: "📋 Tous les certificats et demandes (Administrateur)",
      all_requests_admin_subtitle: "Liste globale de toutes les demandes enregistrées sur le portail.",
      no_templates_ca: "Aucun modèle configuré pour cette AC.",
      no_templates_avail: "Aucun modèle disponible",
      unauthorized_template_alert: "Modèle non autorisé : l'appartenance à l'un des groupes AD configurés est requise pour demander des certificats avec ce modèle. Veuillez contacter un administrateur.",
      not_authorized_tag: " — Non autorisé",

      // Admin Screen
      admin_panel_title: "Configuration du Portail PKI",
      admin_panel_sub: "Panneau d'administration",
      admin_header_title: "Panneau d'administration du portail PKI",
      access_denied_title: "Accès Refusé",
      access_denied_text: "Vous ne disposez pas des autorisations nécessaires pour accéder à cette section.<br>Veuillez contacter un administrateur du serveur.",
      tab_requests: "📋 Demandes de certificat",
      tab_config: "⚙️ Configuration Portail & AC",
      filter_status_label: "Filtrer par statut :",
      filter_pending: "En attente d'approbation",
      filter_all: "Toutes les demandes",
      filter_approved: "Approuvées uniquement",
      filter_rejected: "Rejetées uniquement",
      btn_refresh_list: "🔄 Actualiser la liste",
      loading_requests: "Chargement des demandes en cours...",
      general_settings_title: "Paramètres généraux",
      field_portal_title: "Titre du portail",
      field_portal_mode: "Mode du portail",
      opt_mode_standalone: "Standalone (AC unique)",
      opt_mode_hub: "Hub Multi-AC",
      field_default_ca: "AC par défaut (ID)",
      ca_section_title: "Configuration des autorités de certification",
      btn_add_ca: "Ajouter une AC",
      btn_cancel_changes: "Annuler les modifications",
      btn_save_config: "Enregistrer la configuration",
      admin_footer: "Enterprise PKI Web Enrollment Gateway • Panneau administratif",
      btn_approve: "✅ Approuver",
      btn_reject: "❌ Rejeter",
      btn_view_cert: "Afficher le certificat",
      btn_discover: "🔍 Découvrir depuis l'AC",
      btn_add_template_manual: "+ Ajouter manuellement",
      confirm_approve: "Approuver cette demande ?",
      prompt_reject_reason: "Motif du rejet (optionnel) :",
      confirm_remove_ca: "Supprimer cette AC de la configuration ?",
      confirm_remove_template: "Supprimer ce modèle ?",
      toast_config_saved: "Configuration enregistrée avec succès.",
      toast_request_approved: "Demande approuvée avec succès.",
      toast_request_rejected: "Demande rejetée.",
      admin_new_ca: "Nouvelle AC",
      admin_default_tag: "Par défaut",
      admin_simulator_tag: "Simulateur",
      admin_remove_ca_title: "Supprimer l'AC",
      admin_lbl_display_name: "Nom affiché",
      admin_lbl_forest: "Forêt / Domaine",
      admin_lbl_description: "Description",
      admin_lbl_auth_mode: "Mode d'authentification",
      admin_lbl_default_ca: "AC par défaut",
      admin_lbl_simulator: "Utiliser le simulateur",
      admin_click_discover: "Cliquez sur « Découvrir depuis l'AC »",
      admin_btn_add: "+ Ajouter",
      admin_new_template: "Nouveau modèle",
      admin_lbl_sys_name: "Nom système",
      admin_lbl_validity: "Validité (jours)",
      admin_validity_note: "Récupéré de la définition du modèle AD CS (KeyUsagePeriod) ; non modifiable manuellement. Actualiser via « Découvrir depuis l'AC ».",
      admin_lbl_manual_approval: "Approbation manuelle",
      admin_lbl_key_types: "Types de clés",
      admin_lbl_allowed_groups: "Groupes AD autorisés",
      admin_allowed_groups_placeholder: "Vide = tous les utilisateurs (ex. VD\\Web-Team, LD\\App-Admin)",
      admin_allowed_groups_hint: "Seuls les utilisateurs de ces groupes peuvent demander ce modèle (les administrateurs sont toujours autorisés).",
      admin_no_requests_found: "Aucune demande trouvée",
      admin_no_requests_desc: "Il n'y a aucune demande correspondant au filtre sélectionné.",
      admin_submitted_label: "Soumis :",
      admin_anon_unauth: "Anonyme / Non authentifié",
      admin_requester_notes: "Remarques du demandeur :",
      admin_reviewed_label: "Examiné :",
      admin_by_label: "par",
      admin_rejection_reason_label: "Motif du refus :",
      admin_btn_reject_req: "❌ Rejeter la demande",
      admin_btn_approve_req: "✅ Approuver & délivrer le certificat",
      admin_pending_ca_hint: "En attente d'approbation sur l'AC AD CS",
      admin_user_label: "Utilisateur :",
      admin_confirm_approve_req: "Confirmez-vous l'approbation du certificat avec l'Hold ID « {0} » ?\n\nLe certificat pourra être téléchargé par le demandeur.",
      admin_prompt_reject_req: "Entrez le motif du refus pour la demande « {0} » (optionnel) :",
      admin_toast_approved: "Certificat approuvé avec succès !",
      admin_toast_approve_error: "Impossible d'approuver",
      admin_toast_rejected: "Demande rejetée.",
      admin_toast_reject_error: "Impossible de rejeter",
      admin_toast_comm_error: "Erreur de communication : ",
      admin_loading_cert: "Chargement des détails du certificat...",
      admin_no_cert_stored: "Aucun certificat archivé pour cette demande.",
      admin_cert_retrieve_error: "Erreur lors de la récupération du certificat : ",
      admin_auth_required: "Authentification requise.",
      admin_conn_error: "Erreur de connexion",
      admin_config_load_error: "Impossible de charger la configuration",
      admin_unknown_user: "Inconnu"
    },

    de: {
      // General & Header
      portal_title: "Enterprise PKI Web Enrollment",
      portal_subtitle: "Modernes Gateway für Active Directory Certificate Services (AD CS)",
      theme_toggle_title: "Design wechseln",
      lang_select_title: "Sprache auswählen",
      lang_toggle_title: "Sprache wechseln",
      ca_label: "Ausstellende CA:",
      portal_mode_hub: "Hub-Modus",
      portal_mode_standalone: "Einzel-CA-Modus",
      user_checking: "Zugriff wird überprüft...",
      admin_btn: "⚙️ Admin",
      back_to_portal: "Zurück zum Portal",

      // Tabs
      tab_wizard: "Neue Anforderung (Browser Web Crypto)",
      tab_upload: "Vorhandenen CSR senden (Base64 / Datei)",
      tab_pending: "Zertifikate abholen (Ausstehend oder ausgestellt)",
      tab_automation: "Automatisierung & win-acme",

      // Tab 1 Wizard
      wizard_step1_title: "1. Zertifikatsvorlage auswählen",
      wizard_step1_sub: "Wählen Sie den Zertifikatstyp, der von der ausgewählten Sub-CA ausgestellt werden soll:",
      wizard_step2_title: "2. Antragstellerdaten (Subject DN)",
      field_cn: "Common Name (CN) *",
      placeholder_cn: "z.B. portal.unternehmen.lan oder web01.unternehmen.lan",
      hint_cn: "Primärer Host- oder Dienstname",
      field_o: "Organisation (O)",
      placeholder_o: "z.B. Unternehmen GmbH",
      field_ou: "Organisationseinheit (OU)",
      placeholder_ou: "z.B. IT-Sicherheit / DevOps",
      field_c: "Land (C)",
      wizard_step3_title: "3. Alternative Antragstellernamen (SAN)",
      wizard_step3_sub: "Fügen Sie alternative DNS-Namen oder IP-Adressen für das Zertifikat hinzu:",
      btn_add_san: "SAN hinzufügen",
      placeholder_san_val: "z.B. app.unternehmen.lan oder 10.0.1.50",
      san_empty_hint: "Keine alternativen SANs hinzugefügt (der CN wird automatisch hinzugefügt)",
      wizard_step4_title: "4. Schlüsselparameter & PFX-Passwort",
      wizard_step4_sub: "Der private Schlüssel wird direkt im Browser (Web Crypto) generiert. Der Server empfängt nur die öffentliche CSR-Anforderung.",
      field_key_algo: "Schlüsseltyp und -größe",
      opt_rsa_2048: "RSA 2048 Bit (Standardkompatibilität)",
      opt_rsa_4096: "RSA 4096 Bit (Hohe Sicherheit)",
      opt_rsa_3072: "RSA 3072 Bit",
      field_pfx_pwd: "PFX-Schutzpasswort *",
      placeholder_pfx_pwd: "Passwort für die heruntergeladene .pfx-Datei festlegen",
      hint_pfx_pwd: "Erforderlich zum Schutz der .pfx-Datei mit dem privaten Schlüssel",
      btn_submit_wizard: "Schlüssel generieren & Zertifikat anfordern",

      // Tab 2 Upload CSR
      upload_title: "CSR-Anforderung hochladen oder einfügen (PKCS#10)",
      upload_sub: "Verwenden Sie diesen Modus für Linux-Server, Switches, Firewalls oder Netzwerkgeräte, deren privater Schlüssel bereits lokal generiert wurde:",
      field_csr_text: "CSR-Anforderung (Base64 / PEM-Format) *",
      btn_select_file: "📁 Datei auswählen (.csr / .req)",
      btn_parse_csr: "🔍 CSR prüfen",
      csr_preview_title: "Im CSR erkannte Daten:",
      upload_template_select: "Ziel-AD-CS-Vorlage auswählen *",
      btn_submit_upload: "CSR an CA senden",

      // Tab 3 Retrieve
      pending_title: "Zertifikat abholen (Ausstehend oder ausgestellt)",
      pending_sub: "Geben Sie die Anforderungs-ID ein, um das ausgestellte Zertifikat abzurufen oder den Genehmigungsstatus zu prüfen.",
      pending_security_note: "🔒 Sicherheitsprüfung: Um die Vertraulichkeit von Schlüsseln und Daten zu schützen, ist der Abruf nur dem Benutzer gestattet, der die Anforderung eingereicht hat, oder einem Administrator.",
      field_req_id: "Anforderungs-ID (#) *",
      placeholder_req_id: "z.B. 1042",
      btn_check_pending: "Status prüfen & herunterladen",
      my_requests_title: "📋 Ihre Zertifikate und Anforderungen",
      my_requests_subtitle: "Alle Anforderungen, die unter Ihrem Windows-Benutzerkonto registriert sind.",
      btn_refresh: "🔄 Liste aktualisieren",
      loading_my_requests: "Ihre Anforderungen werden geladen...",
      th_id_date: "ID / Datum",
      th_template: "Vorlage",
      th_cn: "Common Name",
      th_ca: "CA",
      th_status: "Status",
      th_actions: "Aktionen",

      // Tab 4 Automation
      automation_title: "Zertifikatsausstellungs-Automatisierung & win-acme",
      automation_sub: "Dieses Portal stellt moderne RESTful-APIs bereit, um Anforderungen über PowerShell, Ansible, cURL oder ACME-Clients zu automatisieren:",
      automation_winacme_title: "1. Integration mit win-acme",
      automation_winacme_desc: "win-acme ist ein ACME-Client für Windows. Zur Nutzung mit Ihrer Unternehmens-PKI, ohne die CA direkt offenzulegen:",
      automation_winacme_li1: "Das Portal fungiert als zwischengeschaltete Registrierungsstelle (RA).",
      automation_winacme_li2: "Interne Server können ein PowerShell-Skript zur automatischen Verlängerung über den Aufgabenplaner ausführen, ohne komplexe DCOM-Komponenten zu benötigen.",
      automation_ps_title: "2. Beispiel für eine automatische Anforderung über PowerShell",

      // Result Section & PFX Download
      result_title: "Zertifikat Erfolgreich Ausgestellt!",
      pfx_card_title: "PFX-Archiv (.pfx)",
      pfx_card_desc: "Enthält Zertifikat + verschlüsselten privaten Schlüssel für Windows / IIS",
      btn_dl_pfx: "PFX herunterladen",
      crt_card_title: "Zertifikat (.crt)",
      crt_card_desc: "Signiertes X.509-Zertifikat im Base64-PEM-Format",
      btn_dl_crt: ".CRT herunterladen",
      chain_card_title: "Vollständige Kette (.p7b)",
      chain_card_desc: "Enthält die ausstellende Sub-CA und die Unternehmens-Root-CA",
      btn_dl_chain: "Kette herunterladen",

      // Modals
      progress_title: "Kryptografische Generierung läuft...",
      progress_desc: "Erstellung des RSA-Schlüsselpaars im Browser...",
      pfx_modal_title: "PFX-Archiv herunterladen (.pfx)",
      pfx_modal_desc: "Geben Sie ein Passwort ein, um das Zertifikat und den privaten Schlüssel in der PKCS#12-Datei (PFX) zu schützen:",
      pfx_modal_pwd_label: "PFX-Passwort *",
      placeholder_pfx_modal_pwd: "Schutzpasswort eingeben...",
      hint_pfx_modal_pwd: "Dieses Passwort wird beim Importieren des Zertifikats unter Windows / IIS / Linux benötigt.",
      btn_cancel: "Abbrechen",
      btn_confirm_pfx: "PFX generieren & herunterladen",
      footer_text: "Enterprise PKI Web Enrollment Gateway • Moderner Ersatz für Microsoft AD CS / certsrv • HTML5 & Web Crypto API",
      footer_author_label: "Autor:",

      // Dynamic Badges & Messages
      requires_approval_badge: "Erfordert Genehmigung",
      auto_issued_badge: "Automatische Ausstellung",
      access_denied_template: "Nicht autorisiert (AD-Gruppen)",
      status_issued: "Ausgestellt",
      status_pending: "Ausstehende Genehmigung",
      status_rejected: "Abgelehnt",
      status_under_submission: "In CA-Übermittlung",
      no_requests_found: "Keine Zertifikatsanforderungen für Ihr Konto gefunden.",
      login_required: "Bitte melden Sie sich an, um Ihren Anforderungsverlauf anzuzeigen.",
      err_enter_cn: "Bitte geben Sie mindestens den Common Name (CN) ein.",
      err_enter_pfx_pwd: "Das Passwort zum Schutz der .pfx-Datei ist erforderlich.",
      err_select_template: "Bitte wählen Sie eine gültige Vorlage aus.",
      err_enter_csr: "Bitte geben Sie einen gültigen CSR ein oder laden Sie ihn hoch.",
      err_enter_req_id: "Bitte geben Sie eine gültige Anforderungs-ID ein.",

      // Approvals & PFX Flow
      msg_pending_submission_wizard: "Anforderung erfolgreich übermittelt!\n\nDie Anforderung wartet auf manuelle Genehmigung (Ausstehend).\nAnforderungs-ID: #{requestId}\n\nSobald sie vom Administrator genehmigt wurde, können Sie sie im Reiter „Zertifikate abholen“ abrufen und sowohl das Zertifikat (.crt) als auch das Archiv mit privatem Schlüssel (.pfx) herunterladen.",
      msg_pending_submission_upload: "Anforderung erfolgreich gesendet!\n\nStatus: Genehmigung ausstehend.\nAnforderungs-ID: #{requestId}",
      pending_status_box_title: "Anforderungsstatus: Ausstehend oder nicht verfügbar",
      pending_status_box_desc: "Anforderung wartet noch auf Genehmigung.",
      pending_ready_title: "Zertifikat Bereit und Ausgestellt!",
      pending_ready_desc: "Anforderung #{requestId} wurde erfolgreich genehmigt/ausgestellt.",
      pending_dl_pfx_btn: "🔐 PFX-Archiv herunterladen (.pfx)",
      pending_dl_crt_btn: "📄 Zertifikat herunterladen (.crt)",
      pending_dl_p7b_btn: "🔗 Vollständige Kette herunterladen (.p7b)",
      pending_dl_chain_btn: "📜 Kette herunterladen (.crt)",
      auth_required_title: "Authentifizierung erforderlich",
      auth_required_desc: "Bitte melden Sie sich mit Ihrem Benutzerkonto an, um Zertifikate zu überprüfen und herunterzuladen.",
      access_denied_security_title: "Zugriff verweigert (Sicherheitsprüfung)",
      access_denied_security_desc: "Sie sind nicht berechtigt, dieses Zertifikat abzurufen. Der Abruf ist ausschließlich dem ursprünglichen Antragsteller oder einem Administrator gestattet.",
      access_denied_security_not_owner: "Zugriff verweigert: Die Anforderung #{requestId} ist nicht mit Ihrem Konto ({currentUser}) verknüpft. Nur der ursprüngliche Antragsteller oder ein Administrator kann das Zertifikat abrufen.",
      cert_not_available_dl: "Zertifikat steht nicht zum Download zur Verfügung.",
      requester_label: "Antragsteller:",
      unspecified_label: "Nicht angegeben",
      progress_pfx_title: "PFX-Archiv wird erstellt",
      progress_pfx_desc: "Zusammenstellung des passwortgeschützten PKCS#12-Pakets (.pfx)...",
      progress_pfx_retrieving_title: "Zertifikat & Schlüssel abrufen",
      progress_pfx_retrieving_desc: "PKCS#12-Archiv für Anforderung #{requestId} wird abgerufen...",
      err_pfx_creation: "Fehler beim Erstellen der PFX-Datei: ",
      err_pfx_no_key: "Privater Schlüssel für diese Anforderung nicht verfügbar.",
      pfx_prompt_password: "Passwort zum Schutz der PFX-Datei eingeben (optional):",
      th_requester: "Antragsteller",
      th_date: "Datum",
      th_action: "Aktion",
      btn_dl_row_crt_title: "Zertifikat .CRT herunterladen",
      btn_dl_row_pfx_title: "PFX-Archiv mit privatem Schlüssel herunterladen",
      days_unit: "Tage",
      progress_crypto_local_title: "Lokale kryptografische Generierung",
      progress_crypto_local_desc: "Erstellung des RSA/ECC-Schlüsselpaars im Browser über Web Crypto...",
      progress_submitting_ca_title: "Übermittlung an die CA",
      progress_submitting_ca_desc: "Sichere Übermittlung des CSR an die Microsoft AD CS Sub-CA...",
      progress_submitting_csr_title: "CSR-Übermittlung",
      progress_submitting_csr_desc: "Übermittlung des Base64-CSR an die untergeordnete CA AD CS...",
      progress_retrieving_cert_title: "Zertifikat abrufen",
      progress_retrieving_cert_desc: "Zertifikat für Anforderung #{requestId} wird heruntergeladen...",
      progress_checking_status_title: "Anforderungsstatus überprüfen",
      progress_checking_status_desc: "Abfrage der CA für Anforderung #{requestId}...",
      connected_as: "Verbunden als",
      anonymous_user: "Anonym",
      unauthenticated_user: "Nicht authentifiziert",
      all_requests_admin_title: "📋 Alle Zertifikate und Anforderungen (Administrator)",
      all_requests_admin_subtitle: "Globale Liste aller im Portal registrierten Zertifikatsanforderungen.",
      no_templates_ca: "Keine Vorlagen für diese CA konfiguriert.",
      no_templates_avail: "Keine Vorlagen verfügbar",
      unauthorized_template_alert: "Nicht autorisierte Vorlage: Die Mitgliedschaft in einer der konfigurierten AD-Gruppen ist erforderlich, um Zertifikate mit dieser Vorlage anzufordern. Bitte wenden Sie sich an einen Portal-Administrator.",
      not_authorized_tag: " — Nicht autorisiert",

      // Admin Screen
      admin_panel_title: "PKI-Portal-Konfiguration",
      admin_panel_sub: "Verwaltungskonsole",
      admin_header_title: "PKI-Portal-Verwaltungskonsole",
      access_denied_title: "Zugriff Verweigert",
      access_denied_text: "Sie verfügen nicht über die erforderlichen Berechtigungen für diesen Bereich.<br>Bitte wenden Sie sich an einen Server-Administrator.",
      tab_requests: "📋 Zertifikatsanforderungen",
      tab_config: "⚙️ Portal- & CA-Konfiguration",
      filter_status_label: "Nach Status filtern:",
      filter_pending: "Ausstehende Genehmigung",
      filter_all: "Alle Anforderungen",
      filter_approved: "Nur genehmigte",
      filter_rejected: "Nur abgelehnte",
      btn_refresh_list: "🔄 Liste aktualisieren",
      loading_requests: "Anforderungen werden geladen...",
      general_settings_title: "Allgemeine Einstellungen",
      field_portal_title: "Portal-Titel",
      field_portal_mode: "Portal-Modus",
      opt_mode_standalone: "Standalone (Einzel-CA)",
      opt_mode_hub: "Hub Multi-CA",
      field_default_ca: "Standard-CA (ID)",
      ca_section_title: "Konfiguration der Zertifizierungsstellen",
      btn_add_ca: "CA hinzufügen",
      btn_cancel_changes: "Änderungen verwerfen",
      btn_save_config: "Konfiguration speichern",
      admin_footer: "Enterprise PKI Web Enrollment Gateway • Verwaltungskonsole",
      btn_approve: "✅ Genehmigen",
      btn_reject: "❌ Ablehnen",
      btn_view_cert: "Zertifikat anzeigen",
      btn_discover: "🔍 Von CA erkennen",
      btn_add_template_manual: "+ Manuell hinzufügen",
      confirm_approve: "Diese Anforderung genehmigen?",
      prompt_reject_reason: "Ablehnungsgrund (optional):",
      confirm_remove_ca: "Diese CA aus der Konfiguration entfernen?",
      confirm_remove_template: "Diese Vorlage entfernen?",
      toast_config_saved: "Konfiguration erfolgreich gespeichert.",
      toast_request_approved: "Anforderung erfolgreich genehmigt.",
      toast_request_rejected: "Anforderung abgelehnt.",
      admin_new_ca: "Neue CA",
      admin_default_tag: "Standard",
      admin_simulator_tag: "Simulator",
      admin_remove_ca_title: "CA entfernen",
      admin_lbl_display_name: "Anzeigename",
      admin_lbl_forest: "Gesamtstruktur / Domäne",
      admin_lbl_description: "Beschreibung",
      admin_lbl_auth_mode: "Auth-Modus",
      admin_lbl_default_ca: "Standard-CA",
      admin_lbl_simulator: "Simulator verwenden",
      admin_click_discover: "Klicken Sie auf „Von CA erkennen“",
      admin_btn_add: "+ Hinzufügen",
      admin_new_template: "Neue Vorlage",
      admin_lbl_sys_name: "Systemname",
      admin_lbl_validity: "Gültigkeit (Tage)",
      admin_validity_note: "Aus der AD CS-Vorlagendefinition übernommen (KeyUsagePeriod); nicht manuell bearbeitbar. Über „Von CA erkennen“ aktualisieren.",
      admin_lbl_manual_approval: "Manuelle Genehmigung",
      admin_lbl_key_types: "Schlüsseltypen",
      admin_lbl_allowed_groups: "Autorisierte AD-Gruppen",
      admin_allowed_groups_placeholder: "Leer = alle Benutzer (z.B. VD\\Web-Team, LD\\App-Admin)",
      admin_allowed_groups_hint: "Nur Benutzer in diesen Gruppen können diese Vorlage anfordern (Administratoren sind immer zugelassen).",
      admin_no_requests_found: "Keine Anforderungen gefunden",
      admin_no_requests_desc: "Es gibt keine Zertifikatsanforderungen, die dem ausgewählten Filter entsprechen.",
      admin_submitted_label: "Übermittelt:",
      admin_anon_unauth: "Anonym / Nicht authentifiziert",
      admin_requester_notes: "Hinweise des Anforderers:",
      admin_reviewed_label: "Überprüft:",
      admin_by_label: "von",
      admin_rejection_reason_label: "Ablehnungsgrund:",
      admin_btn_reject_req: "❌ Anforderung ablehnen",
      admin_btn_approve_req: "✅ Genehmigen & Zertifikat ausstellen",
      admin_pending_ca_hint: "Wartet auf Genehmigung auf der AD CS-CA",
      admin_user_label: "Benutzer:",
      admin_confirm_approve_req: "Bestätigen Sie die Genehmigung des Zertifikats mit der Hold-ID „{0}“?\n\nDas Zertifikat steht dem Anforderer anschließend zum Download bereit.",
      admin_prompt_reject_req: "Geben Sie den Ablehnungsgrund für die Anforderung „{0}“ ein (optional):",
      admin_toast_approved: "Zertifikat erfolgreich genehmigt!",
      admin_toast_approve_error: "Genehmigung fehlgeschlagen",
      admin_toast_rejected: "Anforderung abgelehnt.",
      admin_toast_reject_error: "Ablehnung fehlgeschlagen",
      admin_toast_comm_error: "Kommunikationsfehler: ",
      admin_loading_cert: "Zertifikatsdetails werden geladen...",
      admin_no_cert_stored: "Kein Zertifikat für diese Anforderung gespeichert.",
      admin_cert_retrieve_error: "Fehler beim Abrufen des Zertifikats: ",
      admin_auth_required: "Authentifizierung erforderlich.",
      admin_conn_error: "Verbindungsfehler",
      admin_config_load_error: "Konfiguration konnte nicht geladen werden",
      admin_unknown_user: "Unbekannt"
    },

    es: {
      // General & Header
      portal_title: "Enterprise PKI Web Enrollment",
      portal_subtitle: "Pasarela moderna de Active Directory Certificate Services (AD CS)",
      theme_toggle_title: "Cambiar tema",
      lang_select_title: "Seleccionar idioma",
      lang_toggle_title: "Cambiar idioma",
      ca_label: "CA emisora:",
      portal_mode_hub: "Modo Hub",
      portal_mode_standalone: "Modo CA única",
      user_checking: "Comprobando acceso...",
      admin_btn: "⚙️ Admin",
      back_to_portal: "Volver al portal",

      // Tabs
      tab_wizard: "Nueva solicitud (Web Crypto del navegador)",
      tab_upload: "Enviar CSR existente (Base64 / Archivo)",
      tab_pending: "Recuperar certificados (Pendientes o emitidos)",
      tab_automation: "Automatización & win-acme",

      // Tab 1 Wizard
      wizard_step1_title: "1. Seleccione la plantilla de certificado",
      wizard_step1_sub: "Elija el tipo de certificado que emitirá la Sub-CA seleccionada:",
      wizard_step2_title: "2. Datos del sujeto (Subject DN)",
      field_cn: "Common Name (CN) *",
      placeholder_cn: "ej. portal.empresa.lan o web01.empresa.lan",
      hint_cn: "Nombre principal de host o servicio",
      field_o: "Organización (O)",
      placeholder_o: "ej. Empresa S.A.",
      field_ou: "Unidad organizativa (OU)",
      placeholder_ou: "ej. Seguridad TI / DevOps",
      field_c: "País (C)",
      wizard_step3_title: "3. Nombres alternativos del sujeto (SAN)",
      wizard_step3_sub: "Añada nombres DNS alternativos o direcciones IP asociados al certificado:",
      btn_add_san: "Añadir SAN",
      placeholder_san_val: "ej. app.empresa.lan o 10.0.1.50",
      san_empty_hint: "Ningún SAN alternativo añadido (el CN se añadirá automáticamente)",
      wizard_step4_title: "4. Parámetros de clave y contraseña PFX",
      wizard_step4_sub: "La clave privada se genera en memoria directamente dentro del navegador (Web Crypto). El servidor solo recibe la solicitud CSR pública.",
      field_key_algo: "Tipo y tamaño de clave",
      opt_rsa_2048: "RSA 2048 bits (Compatibilidad estándar)",
      opt_rsa_4096: "RSA 4096 bits (Alta seguridad)",
      opt_rsa_3072: "RSA 3072 bits",
      field_pfx_pwd: "Contraseña de protección PFX *",
      placeholder_pfx_pwd: "Establecer contraseña para el archivo .pfx descargado",
      hint_pfx_pwd: "Necesaria para proteger el archivo .pfx que contiene la clave privada",
      btn_submit_wizard: "Generar clave y solicitar certificado",

      // Tab 2 Upload CSR
      upload_title: "Subir o pegar una solicitud CSR (PKCS#10)",
      upload_sub: "Use este modo para certificados destinados a servidores Linux, conmutadores, cortafuegos o dispositivos de red cuya clave privada ya se haya generado localmente:",
      field_csr_text: "Solicitud CSR (Formato Base64 / PEM) *",
      btn_select_file: "📁 Seleccionar archivo (.csr / .req)",
      btn_parse_csr: "🔍 Inspeccionar CSR",
      csr_preview_title: "Datos detectados en el CSR:",
      upload_template_select: "Seleccionar plantilla AD CS de destino *",
      btn_submit_upload: "Enviar CSR a la CA",

      // Tab 3 Retrieve
      pending_title: "Recuperar certificado (Pendiente o emitido)",
      pending_sub: "Introduzca el ID de la solicitud para retirar el certificado emitido o comprobar su estado de aprobación.",
      pending_security_note: "🔒 Control de seguridad: Para proteger la confidencialidad de las claves y datos, la recuperación está permitida exclusivamente al usuario que presentó la solicitud o a un administrador.",
      field_req_id: "ID de solicitud (#) *",
      placeholder_req_id: "ej. 1042",
      btn_check_pending: "Comprobar estado y descargar",
      my_requests_title: "📋 Sus certificados y solicitudes",
      my_requests_subtitle: "Todas las solicitudes registradas a nombre de su cuenta de usuario de Windows.",
      btn_refresh: "🔄 Actualizar lista",
      loading_my_requests: "Cargando sus solicitudes...",
      th_id_date: "ID / Fecha",
      th_template: "Plantilla",
      th_cn: "Common Name",
      th_ca: "CA",
      th_status: "Estado",
      th_actions: "Acciones",

      // Tab 4 Automation
      automation_title: "Automatización de emisión de certificados y win-acme",
      automation_sub: "Este portal expone APIs RESTful modernas que permiten automatizar solicitudes desde PowerShell, Ansible, cURL o clientes ACME:",
      automation_winacme_title: "1. Integración con win-acme",
      automation_winacme_desc: "win-acme es un cliente ACME para Windows. Para utilizarlo con su PKI empresarial sin exponer directamente la CA:",
      automation_winacme_li1: "El portal actúa como una Autoridad de Registro (RA) intermediaria.",
      automation_winacme_li2: "Los servidores internos pueden ejecutar un script de PowerShell de renovación automática programado sin necesidad de componentes DCOM complejos en los clientes.",
      automation_ps_title: "2. Ejemplo de solicitud automática mediante PowerShell",

      // Result Section & PFX Download
      result_title: "¡Certificado Emitido con Éxito!",
      pfx_card_title: "Archivo PFX (.pfx)",
      pfx_card_desc: "Contiene certificado + clave privada cifrada para Windows / IIS",
      btn_dl_pfx: "Descargar PFX",
      crt_card_title: "Certificado (.crt)",
      crt_card_desc: "Certificado X.509 firmado en formato Base64 PEM",
      btn_dl_crt: "Descargar .CRT",
      chain_card_title: "Cadena completa (.p7b)",
      chain_card_desc: "Incluye la Sub-CA emisora y la CA raíz corporativa",
      btn_dl_chain: "Descargar cadena",

      // Modals
      progress_title: "Generación Criptográfica en Curso...",
      progress_desc: "Creando el par de claves RSA en el navegador...",
      pfx_modal_title: "Descargar Archivo PFX (.pfx)",
      pfx_modal_desc: "Introduzca una contraseña para proteger el certificado y la clave privada en el archivo PKCS#12 (PFX):",
      pfx_modal_pwd_label: "Contraseña PFX *",
      placeholder_pfx_modal_pwd: "Ingrese la contraseña de protección...",
      hint_pfx_modal_pwd: "Esta contraseña será requerida al importar el certificado en Windows / IIS / Linux.",
      btn_cancel: "Cancelar",
      btn_confirm_pfx: "Generar y Descargar PFX",
      footer_text: "Enterprise PKI Web Enrollment Gateway • Sustituto moderno para Microsoft AD CS / certsrv • HTML5 & Web Crypto API",
      footer_author_label: "Autor:",

      // Dynamic Badges & Messages
      requires_approval_badge: "Requiere Aprobación",
      auto_issued_badge: "Emisión Automática",
      access_denied_template: "No autorizado (grupos AD)",
      status_issued: "Emitido",
      status_pending: "Pendiente de Aprobación",
      status_rejected: "Rechazado",
      status_under_submission: "En Envío a la CA",
      no_requests_found: "No se encontraron solicitudes de certificados a su nombre.",
      login_required: "Inicie sesión para ver el historial de sus solicitudes.",
      err_enter_cn: "Introduzca al menos el Common Name (CN).",
      err_enter_pfx_pwd: "La contraseña para proteger el archivo .pfx es obligatoria.",
      err_select_template: "Seleccione una plantilla válida.",
      err_enter_csr: "Introduzca o cargue un CSR válido.",
      err_enter_req_id: "Introduzca un ID de solicitud válido.",

      // Approvals & PFX Flow
      msg_pending_submission_wizard: "¡Solicitud enviada con éxito!\n\nLa solicitud está pendiente de aprobación manual (Pendiente).\nID de solicitud: #{requestId}\n\nUna vez aprobada por un administrador, podrá recuperarla en la pestaña «Recuperar certificados» descargando tanto el certificado (.crt) como el archivo con clave privada (.pfx).",
      msg_pending_submission_upload: "¡Solicitud enviada con éxito!\n\nEstado: Pendiente de aprobación.\nID de solicitud: #{requestId}",
      pending_status_box_title: "Estado de solicitud: Pendiente o no disponible",
      pending_status_box_desc: "Solicitud aún pendiente de aprobación.",
      pending_ready_title: "¡Certificado Listo y Emitido!",
      pending_ready_desc: "La solicitud #{requestId} ha sido aprobada y emitida con éxito.",
      pending_dl_pfx_btn: "🔐 Descargar archivo PFX (.pfx)",
      pending_dl_crt_btn: "📄 Descargar certificado (.crt)",
      pending_dl_p7b_btn: "🔗 Descargar cadena completa (.p7b)",
      pending_dl_chain_btn: "📜 Descargar cadena (.crt)",
      auth_required_title: "Autenticación requerida",
      auth_required_desc: "Inicie sesión con su cuenta de usuario para verificar y descargar certificados.",
      access_denied_security_title: "Acceso denegado (control de seguridad)",
      access_denied_security_desc: "No está autorizado para recuperar este certificado. La recuperación está restringida exclusivamente a quien realizó la solicitud o a un administrador.",
      access_denied_security_not_owner: "Acceso denegado: La solicitud #{requestId} no está asociada a su cuenta ({currentUser}). Solo el solicitante original o un administrador pueden recuperar el certificado.",
      cert_not_available_dl: "Certificado no disponible para descargar.",
      requester_label: "Solicitante:",
      unspecified_label: "No especificado",
      progress_pfx_title: "Creando archivo PFX",
      progress_pfx_desc: "Ensamblando el paquete PKCS#12 (.pfx) protegido por contraseña...",
      progress_pfx_retrieving_title: "Recuperando certificado y clave",
      progress_pfx_retrieving_desc: "Recuperando archivo PKCS#12 para la solicitud #{requestId}...",
      err_pfx_creation: "Error al crear el archivo PFX: ",
      err_pfx_no_key: "Clave privada no disponible para esta solicitud.",
      pfx_prompt_password: "Ingrese la contraseña para proteger el archivo PFX (opcional):",
      th_requester: "Solicitante",
      th_date: "Fecha",
      th_action: "Acción",
      btn_dl_row_crt_title: "Descargar certificado .CRT",
      btn_dl_row_pfx_title: "Descargar archivo PFX con clave privada",
      days_unit: "días",
      progress_crypto_local_title: "Generación criptográfica local",
      progress_crypto_local_desc: "Creando el par de claves RSA/ECC en el navegador mediante Web Crypto...",
      progress_submitting_ca_title: "Enviando a la CA",
      progress_submitting_ca_desc: "Envío seguro de la CSR a la Sub-CA de Microsoft AD CS...",
      progress_submitting_csr_title: "Enviando CSR",
      progress_submitting_csr_desc: "Enviando el CSR Base64 a la CA subordinada de AD CS...",
      progress_retrieving_cert_title: "Recuperando certificado",
      progress_retrieving_cert_desc: "Descargando certificado para la solicitud #{requestId}...",
      progress_checking_status_title: "Comprobando estado de solicitud",
      progress_checking_status_desc: "Consultando CA para la solicitud #{requestId}...",
      connected_as: "Conectado como",
      anonymous_user: "Anónimo",
      unauthenticated_user: "No autenticado",
      all_requests_admin_title: "📋 Todos los certificados y solicitudes (Administrador)",
      all_requests_admin_subtitle: "Lista global de todas las solicitudes de certificados registradas en el portal.",
      no_templates_ca: "No hay plantillas configuradas para esta CA.",
      no_templates_avail: "No hay plantillas disponibles",
      unauthorized_template_alert: "Plantilla no autorizada: se requiere pertenecer a uno de los grupos de AD configurados para solicitar certificados con esta plantilla. Póngase en contacto con un administrador del portal.",
      not_authorized_tag: " — No autorizado",

      // Admin Screen
      admin_panel_title: "Configuración del Portal PKI",
      admin_panel_sub: "Panel de Administración",
      admin_header_title: "Panel de Administración del Portal PKI",
      access_denied_title: "Acceso Denegado",
      access_denied_text: "No dispone de los permisos necesarios para acceder a esta sección.<br>Póngase en contacto con un administrador del servidor.",
      tab_requests: "📋 Solicitudes de Certificados",
      tab_config: "⚙️ Configuración Portal & CA",
      filter_status_label: "Filtrar por estado:",
      filter_pending: "Pendientes de Aprobación",
      filter_all: "Todas las Solicitudes",
      filter_approved: "Solo Aprobadas",
      filter_rejected: "Solo Rechazadas",
      btn_refresh_list: "🔄 Actualizar Lista",
      loading_requests: "Cargando solicitudes...",
      general_settings_title: "Configuración General",
      field_portal_title: "Título del Portal",
      field_portal_mode: "Modo del Portal",
      opt_mode_standalone: "Standalone (CA Única)",
      opt_mode_hub: "Hub Multi-CA",
      field_default_ca: "CA Predeterminada (ID)",
      ca_section_title: "Configuración de Autoridades de Certificación",
      btn_add_ca: "Añadir CA",
      btn_cancel_changes: "Cancelar Cambios",
      btn_save_config: "Guardar Configuración",
      admin_footer: "Enterprise PKI Web Enrollment Gateway • Panel de Administración",
      btn_approve: "✅ Aprobar",
      btn_reject: "❌ Rechazar",
      btn_view_cert: "Ver Certificado",
      btn_discover: "🔍 Descubrir de la CA",
      btn_add_template_manual: "+ Añadir Manualmente",
      confirm_approve: "¿Aprobar esta solicitud?",
      prompt_reject_reason: "Motivo del rechazo (opcional):",
      confirm_remove_ca: "¿Eliminar esta CA de la configuración?",
      confirm_remove_template: "¿Eliminar esta plantilla?",
      toast_config_saved: "Configuración guardada con éxito.",
      toast_request_approved: "Solicitud aprobada con éxito.",
      toast_request_rejected: "Solicitud rechazada.",
      admin_new_ca: "Nueva CA",
      admin_default_tag: "Predeterminada",
      admin_simulator_tag: "Simulador",
      admin_remove_ca_title: "Eliminar CA",
      admin_lbl_display_name: "Nombre para mostrar",
      admin_lbl_forest: "Bosque / Dominio",
      admin_lbl_description: "Descripción",
      admin_lbl_auth_mode: "Modo de autenticación",
      admin_lbl_default_ca: "CA predeterminada",
      admin_lbl_simulator: "Usar simulador",
      admin_click_discover: "Haga clic en «Descubrir de la CA»",
      admin_btn_add: "+ Añadir",
      admin_new_template: "Nueva plantilla",
      admin_lbl_sys_name: "Nombre del sistema",
      admin_lbl_validity: "Validez (días)",
      admin_validity_note: "Obtenido de la definición de plantilla AD CS (KeyUsagePeriod); no editable manualmente. Actualizar mediante «Descubrir de la CA».",
      admin_lbl_manual_approval: "Aprobación manual",
      admin_lbl_key_types: "Tipos de claves",
      admin_lbl_allowed_groups: "Grupos de AD autorizados",
      admin_allowed_groups_placeholder: "Vacío = todos los usuarios (ej. VD\\Web-Team, LD\\App-Admin)",
      admin_allowed_groups_hint: "Solo los usuarios de estos grupos pueden emitir con esta plantilla (los administradores siempre están permitidos).",
      admin_no_requests_found: "No se encontraron solicitudes",
      admin_no_requests_desc: "No hay solicitudes de certificados que coincidan con el filtro seleccionado.",
      admin_submitted_label: "Enviado:",
      admin_anon_unauth: "Anónimo / No autenticado",
      admin_requester_notes: "Notas del solicitante:",
      admin_reviewed_label: "Revisado:",
      admin_by_label: "por",
      admin_rejection_reason_label: "Motivo de rechazo:",
      admin_btn_reject_req: "❌ Rechazar solicitud",
      admin_btn_approve_req: "✅ Aprobar y emitir certificado",
      admin_pending_ca_hint: "Pendiente de aprobación en la CA de AD CS",
      admin_user_label: "Usuario:",
      admin_confirm_approve_req: "¿Confirma la aprobación del certificado con Hold ID '{0}'?\n\nEl certificado podrá ser descargado por el solicitante.",
      admin_prompt_reject_req: "Introduzca el motivo del rechazo para la solicitud '{0}' (opcional):",
      admin_toast_approved: "¡Certificado aprobado con éxito!",
      admin_toast_approve_error: "No se pudo aprobar",
      admin_toast_rejected: "Solicitud rechazada.",
      admin_toast_reject_error: "No se pudo rechazar",
      admin_toast_comm_error: "Error de comunicación: ",
      admin_loading_cert: "Cargando detalles del certificado...",
      admin_no_cert_stored: "Ningún certificado archivado para esta solicitud.",
      admin_cert_retrieve_error: "Error al recuperar el certificado: ",
      admin_auth_required: "Autenticación requerida.",
      admin_conn_error: "Error de conexión",
      admin_config_load_error: "No se pudo cargar la configuración",
      admin_unknown_user: "Desconocido"
    }
  };

  let currentLang = localStorage.getItem(STORAGE_KEY) || 'it';
  if (!languagesMeta[currentLang]) {
    currentLang = 'it';
  }

  function getLang() {
    return currentLang;
  }

  function getLocale() {
    return (languagesMeta[currentLang] && languagesMeta[currentLang].locale) || 'it-IT';
  }

  function getLanguages() {
    return Object.keys(languagesMeta).map(key => ({
      code: key,
      labelCode: languagesMeta[key].code,
      name: languagesMeta[key].name,
      flag: languagesMeta[key].flag,
      locale: languagesMeta[key].locale
    }));
  }

  function t(key, fallback, params) {
    const langDict = resources[currentLang] || resources.it;
    let text = undefined;
    if (langDict && langDict[key] !== undefined) {
      text = langDict[key];
    } else if (resources.en && resources.en[key] !== undefined) {
      text = resources.en[key];
    } else if (resources.it && resources.it[key] !== undefined) {
      text = resources.it[key];
    }

    if (text === undefined) {
      text = fallback !== undefined ? fallback : key;
    }

    if (params && typeof params === 'object') {
      text = text.replace(/#\{(\w+)\}/g, (_, k) => params[k] !== undefined ? params[k] : '');
    }

    return text;
  }

  function setLanguage(lang) {
    if (!languagesMeta[lang]) return;
    currentLang = lang;
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch (e) { }

    document.documentElement.lang = lang;
    apply();
    updateUIElements();

    window.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang: currentLang } }));
  }

  function updateUIElements() {
    const meta = languagesMeta[currentLang] || languagesMeta.it;

    // Aggiorna le componenti del dropdown lingua
    document.querySelectorAll('.lang-dropdown').forEach(dropdown => {
      const flagEl = dropdown.querySelector('.lang-flag, #lang-current-flag');
      if (flagEl) flagEl.innerHTML = meta.flagSvg;

      const codeEl = dropdown.querySelector('.lang-code, #lang-current-code');
      if (codeEl) codeEl.textContent = meta.code;

      const btn = dropdown.querySelector('.lang-dropdown-btn');
      if (btn) btn.title = t('lang_select_title', 'Seleziona lingua');

      dropdown.querySelectorAll('.lang-dropdown-item').forEach(item => {
        const itemLang = item.getAttribute('data-lang');
        const m = languagesMeta[itemLang];
        if (m) {
          const itemFlag = item.querySelector('.lang-item-flag, .lang-flag');
          if (itemFlag) itemFlag.innerHTML = m.flagSvg;
        }
        if (itemLang === currentLang) {
          item.classList.add('active');
        } else {
          item.classList.remove('active');
        }
      });
    });

    // Supporto per vecchi pulsanti toggle se ancora presenti
    document.querySelectorAll('.lang-toggle-btn').forEach(btn => {
      const label = btn.querySelector('.lang-label');
      if (label) {
        label.textContent = meta.code;
      }
      btn.title = t('lang_toggle_title', 'Cambia lingua');
    });
  }

  function apply() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (!key) return;
      const val = t(key);
      if (el.getAttribute('data-i18n-html') === 'true') {
        el.innerHTML = val;
      } else {
        el.textContent = val;
      }
    });

    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      const key = el.getAttribute('data-i18n-placeholder');
      if (!key) return;
      el.placeholder = t(key);
    });

    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      const key = el.getAttribute('data-i18n-title');
      if (!key) return;
      el.title = t(key);
    });
  }

  function setupDropdownListeners() {
    // Chiudi tutti i dropdown quando si clicca fuori
    document.addEventListener('click', (e) => {
      const isInside = e.target.closest('.lang-dropdown');
      if (!isInside) {
        document.querySelectorAll('.lang-dropdown.open').forEach(d => {
          d.classList.remove('open');
          const btn = d.querySelector('.lang-dropdown-btn');
          if (btn) btn.setAttribute('aria-expanded', 'false');
        });
      }
    });

    // Chiudi premendo Escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        document.querySelectorAll('.lang-dropdown.open').forEach(d => {
          d.classList.remove('open');
          const btn = d.querySelector('.lang-dropdown-btn');
          if (btn) btn.setAttribute('aria-expanded', 'false');
        });
      }
    });

    document.querySelectorAll('.lang-dropdown').forEach(dropdown => {
      const btn = dropdown.querySelector('.lang-dropdown-btn');
      if (btn && !btn._hasLangDropdownListener) {
        btn._hasLangDropdownListener = true;
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const isOpen = dropdown.classList.contains('open');
          // Chiudi eventuali altri dropdown
          document.querySelectorAll('.lang-dropdown.open').forEach(d => {
            if (d !== dropdown) {
              d.classList.remove('open');
              const b = d.querySelector('.lang-dropdown-btn');
              if (b) b.setAttribute('aria-expanded', 'false');
            }
          });
          dropdown.classList.toggle('open', !isOpen);
          btn.setAttribute('aria-expanded', !isOpen ? 'true' : 'false');
        });
      }

      dropdown.querySelectorAll('.lang-dropdown-item').forEach(item => {
        if (!item._hasLangItemListener) {
          item._hasLangItemListener = true;
          item.addEventListener('click', (e) => {
            e.stopPropagation();
            const chosenLang = item.getAttribute('data-lang');
            if (chosenLang) {
              setLanguage(chosenLang);
            }
            dropdown.classList.remove('open');
            if (btn) btn.setAttribute('aria-expanded', 'false');
          });
        }
      });
    });
  }

  function init() {
    document.documentElement.lang = currentLang;
    apply();
    updateUIElements();
    setupDropdownListeners();

    // Retrocompatibilità per eventuali .lang-toggle-btn
    document.querySelectorAll('.lang-toggle-btn').forEach(btn => {
      if (!btn._hasToggleListener) {
        btn._hasToggleListener = true;
        btn.addEventListener('click', () => {
          const langs = Object.keys(languagesMeta);
          const nextIdx = (langs.indexOf(currentLang) + 1) % langs.length;
          setLanguage(langs[nextIdx]);
        });
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return {
    getLanguage: getLang,
    getLocale: getLocale,
    getLanguages: getLanguages,
    setLanguage: setLanguage,
    t: t,
    apply: apply,
    init: init
  };
})();
