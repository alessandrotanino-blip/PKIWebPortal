/**
 * PKI Portal - Internationalization (i18n) Module
 * Supports seamless Italian (it) / English (en) toggling.
 */
window.I18N = (function () {
  'use strict';

  const STORAGE_KEY = 'pki_portal_lang';

  const resources = {
    it: {
      // General & Header
      portal_title: "Enterprise PKI Web Enrollment",
      portal_subtitle: "Active Directory Certificate Services (AD CS) Modern Gateway",
      theme_toggle_title: "Cambia tema",
      lang_toggle_title: "Switch to English",
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

      // Result Section
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
      toast_request_rejected: "Richiesta rifiutata."
    },

    en: {
      // General & Header
      portal_title: "Enterprise PKI Web Enrollment",
      portal_subtitle: "Active Directory Certificate Services (AD CS) Modern Gateway",
      theme_toggle_title: "Toggle theme",
      lang_toggle_title: "Passa all'Italiano",
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

      // Result Section
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
      toast_request_rejected: "Request rejected."
    }
  };

  let currentLang = localStorage.getItem(STORAGE_KEY) || 'it';
  if (currentLang !== 'it' && currentLang !== 'en') {
    currentLang = 'it';
  }

  function getLang() {
    return currentLang;
  }

  function t(key, fallback) {
    const langDict = resources[currentLang] || resources.it;
    if (langDict && langDict[key] !== undefined) {
      return langDict[key];
    }
    const itDict = resources.it;
    if (itDict && itDict[key] !== undefined) {
      return itDict[key];
    }
    return fallback !== undefined ? fallback : key;
  }

  function setLanguage(lang) {
    if (lang !== 'it' && lang !== 'en') return;
    currentLang = lang;
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch (e) { }

    document.documentElement.lang = lang;
    apply();
    updateToggleButtons();

    window.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang: currentLang } }));
  }

  function toggleLanguage() {
    setLanguage(currentLang === 'it' ? 'en' : 'it');
  }

  function updateToggleButtons() {
    const toggleBtns = document.querySelectorAll('.lang-toggle-btn');
    toggleBtns.forEach(btn => {
      const label = btn.querySelector('.lang-label');
      if (label) {
        label.textContent = currentLang === 'it' ? 'EN' : 'IT';
      }
      btn.title = t('lang_toggle_title');
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

  function init() {
    document.documentElement.lang = currentLang;
    apply();
    updateToggleButtons();

    // Attach click events on any lang toggles
    document.querySelectorAll('.lang-toggle-btn').forEach(btn => {
      btn.removeEventListener('click', toggleLanguage);
      btn.addEventListener('click', toggleLanguage);
    });
  }

  // Auto initialize on DOMContentLoaded if not already loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return {
    getLanguage: getLang,
    setLanguage: setLanguage,
    toggleLanguage: toggleLanguage,
    t: t,
    apply: apply,
    init: init
  };
})();
