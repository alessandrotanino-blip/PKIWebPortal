/**
 * Controller Principale dell'Applicazione PKI Web Enrollment
 */

(function () {
  'use strict';

  // Stato applicativo
  let portalData = null;
  let currentCa = null;
  let selectedTemplate = null;
  let sansList = [];

  // Risultati dell'ultima emissione
  let lastIssuedCertPem = null;
  let lastIssuedChainPem = null;
  let lastIssuedP7bBase64 = null; // Base64 del contenuto standard del file .p7b (PKCS#7 con catena completa)
  let lastGeneratedPfxBlob = null;
  let lastCommonName = 'certificate';

  // Theme management
  function setupThemeToggle() {
    const toggle = document.getElementById('theme-toggle');
    const iconSun = document.getElementById('theme-icon-sun');
    const iconMoon = document.getElementById('theme-icon-moon');
    
    // Load saved theme or detect system preference
    const savedTheme = localStorage.getItem('pki-theme');
    if (savedTheme) {
      document.documentElement.setAttribute('data-theme', savedTheme);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
    
    updateThemeIcon();
    
    toggle.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('pki-theme', next);
      updateThemeIcon();
    });
    
    function updateThemeIcon() {
      const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
      iconSun.style.display = isDark ? 'block' : 'none';
      iconMoon.style.display = isDark ? 'none' : 'block';
    }
  }

  // Inizializzazione al caricamento del DOM
  document.addEventListener('DOMContentLoaded', init);

  async function init() {
    setupThemeToggle();
    setupTabs();
    setupSanManager();
    setupUploadHandlers();
    setupPendingHandlers();
    setupWizardSubmit();

    await checkCurrentUser();
    await loadPortalConfiguration();

    window.addEventListener('languageChanged', () => {
      checkCurrentUser();
      if (currentCa) {
        const templates = currentCa.templates || currentCa.Templates || [];
        renderTemplates(templates);
        renderUploadTemplates(templates);
      }
      const activeTab = document.querySelector('.tab-btn.active');
      if (activeTab && activeTab.dataset.tab === 'tab-pending') {
        loadMyRequests();
      }
    });
  }

  // 1. Caricamento configurazione da /api/config
  async function loadPortalConfiguration() {
    try {
      const response = await fetch('/api/config');
      if (!response.ok) throw new Error('Impossibile caricare la configurazione del portale.');

      portalData = await response.json();
      const casList = portalData.cas || portalData.cAs || portalData.CAs || [];
      portalData.cas = casList;

      document.getElementById('portal-title').textContent = portalData.portalTitle || portalData.PortalTitle || 'Enterprise PKI Web Enrollment';
      
      const badge = document.getElementById('portal-mode-badge');
      badge.textContent = (portalData.portalMode || portalData.PortalMode) === 'Standalone' ? 'Modalità Locale' : 'Modalità Hub Multi-CA';

      const selector = document.getElementById('ca-selector');
      selector.innerHTML = '';

      if (casList.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'Nessuna CA configurata';
        selector.appendChild(opt);
        document.getElementById('ca-info-name').textContent = 'Nessuna CA configurata';
        document.getElementById('ca-info-desc').textContent = 'Accedere alla pagina di amministrazione per configurare una CA.';
        renderTemplates([]);
        renderUploadTemplates([]);
        return;
      }

      casList.forEach(ca => {
        const opt = document.createElement('option');
        opt.value = ca.id || ca.Id;
        opt.textContent = `${ca.displayName || ca.DisplayName || 'CA'} (${ca.forestOrDomain || ca.ForestOrDomain || 'Dominio Locale'})`;
        if (ca.isDefault || ca.IsDefault) opt.selected = true;
        selector.appendChild(opt);
      });

      selector.addEventListener('change', (e) => {
        switchCa(e.target.value);
      });

      // Seleziona la prima CA o quella di default
      const defaultId = portalData.defaultCaId || portalData.DefaultCaId || (casList[0] ? (casList[0].id || casList[0].Id) : null);
      switchCa(defaultId);
    } catch (err) {
      console.error(err);
      alert('Errore di connessione alle API del portale PKI: ' + err.message);
    }
  }

  // 2. Cambio CA corrente
  function switchCa(caId) {
    const casList = portalData ? (portalData.cas || portalData.cAs || portalData.CAs || []) : [];
    if (!casList || casList.length === 0) return;
    currentCa = casList.find(c => (c.id || c.Id) === caId) || casList[0];
    if (!currentCa) return;

    // Aggiorna banner informativo
    document.getElementById('ca-info-name').textContent = currentCa.displayName || currentCa.DisplayName || '';
    document.getElementById('ca-info-desc').textContent = 
      `${currentCa.description || currentCa.Description || ''} • Foresta/Dominio: ${currentCa.forestOrDomain || currentCa.ForestOrDomain || 'N/A'}`;

    const templates = currentCa.templates || currentCa.Templates || [];
    // Popola i template per la nuova CA
    renderTemplates(templates);
    renderUploadTemplates(templates);
  }

  // 3. Render delle schede template
  function renderTemplates(templates) {
    const container = document.getElementById('template-cards-container');
    container.innerHTML = '';
    selectedTemplate = null;

    if (!templates || templates.length === 0) {
      container.innerHTML = `<p style="color: var(--gray-400); font-size: 0.9rem;">${window.I18N ? window.I18N.t('no_templates_ca', 'Nessun template configurato per questa CA.') : 'Nessun template configurato per questa CA.'}</p>`;
      return;
    }

    // Primo template autorizzato come selezione iniziale (i template non
    // autorizzati — vincolati a gruppi AD — non sono selezionabili).
    const firstAllowedIndex = templates.findIndex(t => (t.IsAllowed ?? t.isAllowed ?? true) !== false);

    templates.forEach((tmpl, index) => {
      const isAllowed = (tmpl.IsAllowed ?? tmpl.isAllowed ?? true) !== false;
      const isSelected = index === firstAllowedIndex;
      const card = document.createElement('div');
      card.className = 'template-card' + (isSelected ? ' selected' : '') + (isAllowed ? '' : ' template-locked');
      if (isSelected) selectedTemplate = tmpl;

      const requiresApproval = tmpl.requiresApproval || tmpl.RequiresApproval || false;
      const approvalBadge = requiresApproval 
        ? `<span class="tag tag-warning">${window.I18N ? window.I18N.t('requires_approval_badge', 'Approvazione Richiesta') : 'Approvazione Richiesta'}</span>` 
        : `<span class="tag tag-success">${window.I18N ? window.I18N.t('auto_issued_badge', 'Emissione Immediata') : 'Emissione Immediata'}</span>`;
      const lockBadge = isAllowed
        ? ''
        : `<span class="tag" style="background: #dc2626; color: #ffffff;">${window.I18N ? window.I18N.t('access_denied_template', 'Non autorizzato (Gruppi AD)') : 'Non autorizzato (Gruppi AD)'}</span>`;

      const displayName = tmpl.displayName || tmpl.DisplayName || tmpl.name || tmpl.Name || '';
      const name = tmpl.name || tmpl.Name || '';
      const desc = tmpl.description || tmpl.Description || '';
      const validityDays = tmpl.validityDays || tmpl.ValidityDays || 365;
      const daysText = window.I18N ? window.I18N.t('days_unit', 'giorni') : 'giorni';

      card.innerHTML = `
        <div class="template-name">${escapeHtml(displayName)}</div>
        <div class="template-desc">${escapeHtml(desc)}</div>
        <div class="template-tags">
          ${approvalBadge}
          ${lockBadge}
          <span class="tag">${validityDays} ${daysText}</span>
          <span class="tag">${escapeHtml(name)}</span>
        </div>
      `;

      card.addEventListener('click', () => {
        if (!isAllowed) {
          alert(window.I18N 
            ? window.I18N.t('unauthorized_template_alert', 'Template non autorizzato: per emettere certificati con questo template è richiesta l\'appartenenza a uno dei gruppi AD configurati. Contatta un amministratore del portale.') 
            : 'Template non autorizzato: per emettere certificati con questo template è richiesta l\'appartenenza a uno dei gruppi AD configurati. Contatta un amministratore del portale.');
          return;
        }
        document.querySelectorAll('.template-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        selectedTemplate = tmpl;
      });

      container.appendChild(card);
    });
  }

  function renderUploadTemplates(templates) {
    const select = document.getElementById('upload-template-select');
    select.innerHTML = '';
    if (!templates || templates.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = window.I18N ? window.I18N.t('no_templates_avail', 'Nessun template disponibile') : 'Nessun template disponibile';
      select.appendChild(opt);
      return;
    }
    templates.forEach(tmpl => {
      const opt = document.createElement('option');
      const name = tmpl.name || tmpl.Name || '';
      const displayName = tmpl.displayName || tmpl.DisplayName || name;
      const requiresApproval = tmpl.requiresApproval || tmpl.RequiresApproval || false;
      const isAllowed = (tmpl.IsAllowed ?? tmpl.isAllowed ?? true) !== false;
      opt.value = name;
      const approvalText = requiresApproval 
        ? (window.I18N ? window.I18N.t('requires_approval_badge', 'Richiede Approvazione') : 'Richiede Approvazione')
        : (window.I18N ? window.I18N.t('auto_issued_badge', 'Immediato') : 'Immediato');
      const notAllowedText = window.I18N ? window.I18N.t('not_authorized_tag', ' — Non autorizzato') : ' — Non autorizzato';
      opt.textContent = `${displayName} (${approvalText})${isAllowed ? '' : notAllowedText}`;
      opt.disabled = !isAllowed;
      select.appendChild(opt);
    });
  }

  // 4. Gestione Tab
  function setupTabs() {
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        const target = tab.dataset.tab;
        document.querySelectorAll('.tab-pane').forEach(p => p.style.display = 'none');
        const activePane = document.getElementById(target);
        if (activePane) activePane.style.display = 'block';

        // Nasconde il box risultato al cambio di tab
        document.getElementById('result-box').style.display = 'none';

        if (target === 'tab-pending') {
          loadMyRequests();
        }
      });
    });
  }

  // 5. Gestione SAN (Subject Alternative Names)
  function setupSanManager() {
    const btnAdd = document.getElementById('btn-add-san');
    const inputVal = document.getElementById('san-value');
    const selectType = document.getElementById('san-type');

    function addSan() {
      const val = inputVal.value.trim();
      const type = selectType.value;
      if (!val) return;

      // Evita duplicati
      if (!sansList.some(s => s.type === type && s.value.toLowerCase() === val.toLowerCase())) {
        sansList.push({ type, value: val });
        renderSanChips();
      }
      inputVal.value = '';
      inputVal.focus();
    }

    btnAdd.addEventListener('click', addSan);
    inputVal.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        addSan();
      }
    });
  }

  function renderSanChips() {
    const list = document.getElementById('san-chips-list');
    list.innerHTML = '';

    if (sansList.length === 0) {
      const hint = window.I18N ? window.I18N.t('san_empty_hint', 'Nessun SAN alternativo aggiunto (il CN verrà inserito automaticamente)') : 'Nessun SAN alternativo aggiunto (il CN verrà inserito automaticamente)';
      list.innerHTML = `<span style="font-size: 0.8rem; color: var(--gray-400); margin-left: 0.5rem;">${escapeHtml(hint)}</span>`;
      return;
    }

    sansList.forEach((san, index) => {
      const chip = document.createElement('div');
      chip.className = 'san-chip';
      chip.innerHTML = `
        <strong>${san.type}:</strong> ${escapeHtml(san.value)}
        <span class="remove-san" data-index="${index}">&times;</span>
      `;
      chip.querySelector('.remove-san').addEventListener('click', () => {
        sansList.splice(index, 1);
        renderSanChips();
      });
      list.appendChild(chip);
    });
  }

  // 6. Invio Wizard Web Crypto (Generazione locale + sottomissione)
  function setupWizardSubmit() {
    const btn = document.getElementById('btn-submit-wizard');

    btn.addEventListener('click', async () => {
      const cn = document.getElementById('form-cn').value.trim();
      const o = document.getElementById('form-o').value.trim();
      const ou = document.getElementById('form-ou').value.trim();
      const c = document.getElementById('form-c').value.trim();
      const keyType = document.getElementById('key-algorithm').value;
      const pfxPassword = document.getElementById('pfx-password').value;

      if (!cn) {
        alert(window.I18N ? window.I18N.t('err_enter_cn', 'Il campo Common Name (CN) è obbligatorio.') : 'Il campo Common Name (CN) è obbligatorio.');
        document.getElementById('form-cn').focus();
        return;
      }

      if (!selectedTemplate) {
        alert(window.I18N ? window.I18N.t('err_select_template', 'Selezionare un Certificate Template.') : 'Selezionare un Certificate Template.');
        return;
      }

      if (!pfxPassword) {
        alert(window.I18N ? window.I18N.t('err_enter_pfx_pwd', 'Impostare una password di protezione per il file PFX.') : 'Impostare una password di protezione per il file PFX.');
        document.getElementById('pfx-password').focus();
        return;
      }

      lastCommonName = cn.replace(/[^a-zA-Z0-9.-]/g, '_');

      // Se non è stato specificato alcun SAN DNS corrispondente al CN, lo aggiungiamo automaticamente
      const finalSans = [...sansList];
      if (!finalSans.some(s => s.type === 'DNS' && s.value.toLowerCase() === cn.toLowerCase())) {
        finalSans.unshift({ type: 'DNS', value: cn });
      }

      showProgress(
        window.I18N ? window.I18N.t('progress_crypto_local_title', 'Generazione Crittografica Locale') : 'Generazione Crittografica Locale',
        window.I18N ? window.I18N.t('progress_crypto_local_desc', 'Creazione della coppia di chiavi RSA/ECC nel browser (potrebbe richiedere alcuni secondi)...') : 'Creazione della coppia di chiavi RSA/ECC nel browser (potrebbe richiedere alcuni secondi)...'
      );

      try {
        // Step 1: Generazione CSR in JavaScript
        const { csrPem, privateKey } = await CryptoHelper.generateCsr({
          commonName: cn,
          organization: o,
          organizationalUnit: ou,
          country: c,
          sans: finalSans,
          keyType: keyType
        });

        const privateKeyPem = CryptoHelper.exportPrivateKeyPem(privateKey);

        updateProgress(
          window.I18N ? window.I18N.t('progress_submitting_ca_title', 'Sottomissione alla CA') : 'Sottomissione alla CA',
          window.I18N ? window.I18N.t('progress_submitting_ca_desc', 'Invio sicuro del CSR alla Sub-CA Microsoft AD CS...') : 'Invio sicuro del CSR alla Sub-CA Microsoft AD CS...'
        );

        // Step 2: Sottomissione al backend
        // SECURITY (2.1.0): la chiave privata viene inviata al portale SOLO quando
        // il template richiede approvazione (flusso hold: il server la custodisce
        // cifrata per il ritiro differito del PFX). Nei flussi a emissione
        // immediata il server non ne ha bisogno: il PFX viene assemblato qui nel
        // browser e la chiave privata non lascia il dispositivo.
        const tplRequiresApproval = !!(selectedTemplate.requiresApproval || selectedTemplate.RequiresApproval);
        const requestBody = {
          caId: currentCa.id || currentCa.Id || '',
          templateName: selectedTemplate.name || selectedTemplate.Name || '',
          csrPem: csrPem
        };
        if (tplRequiresApproval) {
          requestBody.privateKeyPem = privateKeyPem;
        }

        const response = await fetch('/api/certificates/request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody)
        });

        const result = await response.json();
        hideProgress();

        if (!result.success && result.disposition !== 'UnderSubmission') {
          alert('Errore emissione certificato: ' + (result.statusMessage || 'Errore sconosciuto.'));
          return;
        }

        if (result.disposition === 'UnderSubmission') {
          const msg = window.I18N
            ? window.I18N.t('msg_pending_submission_wizard', null, { requestId: result.requestId })
            : `Richiesta inoltrata con successo!\n\nLa richiesta è in attesa di approvazione manuale (Pending).\nRequest ID: #${result.requestId}\n\nUna volta approvata dall'amministratore, potrai ritirarla dalla scheda "Ritiro Certificati" scaricando sia il certificato (.crt) sia l'archivio con chiave privata (.pfx).`;
          alert(msg);
          return;
        }

        // Step 3: Emissione completata! Creazione del PFX client-side
        showProgress(
          window.I18N ? window.I18N.t('progress_pfx_title', 'Creazione Archivio PFX') : 'Creazione Archivio PFX',
          window.I18N ? window.I18N.t('progress_pfx_desc', 'Assemblaggio del pacchetto PKCS#12 (.pfx) protetto da password...') : 'Assemblaggio del pacchetto PKCS#12 protetto da password...'
        );

        lastIssuedCertPem = result.certificatePem;
        lastIssuedChainPem = result.certificateChainPem;
        lastIssuedP7bBase64 = result.p7bBase64 || null;

        try {
          lastGeneratedPfxBlob = CryptoHelper.createPfxBundle(
            privateKey,
            lastIssuedCertPem,
            lastIssuedChainPem,
            pfxPassword
          );
        } catch (pfxErr) {
          console.error('=== ERRORE PFX dettagliato ===', pfxErr);
          throw pfxErr;
        }

        hideProgress();

        // Mostra il box dei download
        showResultBox(result.statusMessage || (window.I18N ? window.I18N.t('result_title', 'Certificato emesso con successo!') : 'Certificato emesso con successo!'), true);

      } catch (err) {
        hideProgress();
        console.error(err);
        alert('Si è verificato un errore: ' + err.message);
      }
    });
  }

  // 7. Gestione Upload CSR Esistente
  function setupUploadHandlers() {
    const fileInput = document.getElementById('csr-file-input');
    const textarea = document.getElementById('csr-text');
    const btnParse = document.getElementById('btn-parse-csr');
    const btnSubmit = document.getElementById('btn-submit-upload');

    fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (event) => {
          textarea.value = event.target.result;
          parseAndPreviewCsr(textarea.value);
        };
        reader.readAsText(file);
      }
    });

    btnParse.addEventListener('click', () => {
      parseAndPreviewCsr(textarea.value);
    });

    btnSubmit.addEventListener('click', async () => {
      const csr = textarea.value.trim();
      const template = document.getElementById('upload-template-select').value;

      if (!csr) {
        alert(window.I18N ? window.I18N.t('err_enter_csr', 'Incollare o caricare un file CSR prima di procedere.') : 'Incollare o caricare un file CSR prima di procedere.');
        return;
      }

      showProgress(
        window.I18N ? window.I18N.t('progress_submitting_csr_title', 'Sottomissione CSR') : 'Sottomissione CSR',
        window.I18N ? window.I18N.t('progress_submitting_csr_desc', 'Invio del CSR Base64 alla Subordinate CA AD CS...') : 'Invio del CSR Base64 alla Subordinate CA AD CS...'
      );

      try {
        const response = await fetch('/api/certificates/request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            caId: currentCa.id || currentCa.Id || '',
            templateName: template,
            csrPem: csr
          })
        });

        const result = await response.json();
        hideProgress();

        if (!result.success && result.disposition !== 'UnderSubmission') {
          alert('Errore sottomissione CSR: ' + (result.statusMessage || 'Errore'));
          return;
        }

        if (result.disposition === 'UnderSubmission') {
          const msg = window.I18N
            ? window.I18N.t('msg_pending_submission_upload', null, { requestId: result.requestId })
            : `Richiesta inviata con successo!\n\nStato: In attesa di approvazione (Pending).\nRequest ID: #${result.requestId}`;
          alert(msg);
          return;
        }

        lastIssuedCertPem = result.certificatePem;
        lastIssuedChainPem = result.certificateChainPem;
        lastIssuedP7bBase64 = result.p7bBase64 || null;
        lastGeneratedPfxBlob = null; // Nessuna chiave privata per CSR pre-generato
        lastCommonName = 'cert_' + result.requestId;

        showResultBox(result.statusMessage || (window.I18N ? window.I18N.t('result_title', 'Certificato emesso con successo!') : 'Certificato emesso con successo!'), false);

      } catch (err) {
        hideProgress();
        alert('Errore durante la sottomissione: ' + err.message);
      }
    });
  }

  async function parseAndPreviewCsr(csrText) {
    if (!csrText || !csrText.trim()) return;

    try {
      const resp = await fetch('/api/certificates/parse-csr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csrPem: csrText })
      });

      const data = await resp.json();
      const previewBox = document.getElementById('csr-preview-box');

      if (data.success) {
        document.getElementById('csr-preview-cn').textContent = data.commonName || 'N/A';
        document.getElementById('csr-preview-subject').textContent = data.subject || 'N/A';
        document.getElementById('csr-preview-key').textContent = `${data.keyAlgorithm} ${data.keySize} bit`;
        document.getElementById('csr-preview-sans').textContent = 
          (data.subjectAlternativeNames && data.subjectAlternativeNames.length > 0)
            ? data.subjectAlternativeNames.join(', ')
            : 'Nessun SAN rilevato';

        previewBox.style.display = 'block';
      } else {
        alert('Impossibile interpretare il CSR: ' + (data.errorMessage || 'Formato non valido'));
      }
    } catch (e) {
      console.warn('Errore parsing CSR:', e);
    }
  }

  // Funzione di utilità per download PFX protetto da password
  function promptAndDownloadPfx(privateKeyPem, certPem, chainPem, certCommonName) {
    const modal = document.getElementById('pfx-password-modal');
    const pwdInput = document.getElementById('pfx-modal-password');
    const btnConfirm = document.getElementById('btn-pfx-modal-confirm');
    const btnCancel = document.getElementById('btn-pfx-modal-cancel');

    if (!modal || !pwdInput) {
      // SECURITY (2.1.0): la password del PFX è OBBLIGATORIA anche nel ritiro:
      // un PFX senza password esporrebbe la chiave privata a chi trovi il file.
      const promptText = window.I18N ? window.I18N.t('pfx_prompt_password', 'Inserisci la password per proteggere il file PFX (obbligatoria):') : 'Inserisci la password per proteggere il file PFX (obbligatoria):';
      let pwd;
      for (;;) {
        pwd = prompt(promptText, '');
        if (pwd === null) return; // annullato dall'utente
        if (pwd.trim().length > 0) break;
        alert(window.I18N ? window.I18N.t('err_pfx_pwd_required', 'La password per il file PFX è obbligatoria.') : 'La password per il file PFX è obbligatoria.');
      }
      doGenerateAndDownloadPfx(privateKeyPem, certPem, chainPem, certCommonName, pwd);
      return;
    }

    pwdInput.value = '';
    modal.style.display = 'flex';
    pwdInput.focus();

    function cleanup() {
      modal.style.display = 'none';
      btnConfirm.removeEventListener('click', onConfirm);
      btnCancel.removeEventListener('click', onCancel);
      pwdInput.removeEventListener('keydown', onKeyDown);
    }

    function onConfirm() {
      const password = pwdInput.value;
      // SECURITY (2.1.0): password obbligatoria (stesso criterio del prompt fallback)
      if (!password || password.trim().length === 0) {
        alert(window.I18N ? window.I18N.t('err_pfx_pwd_required', 'La password per il file PFX è obbligatoria.') : 'La password per il file PFX è obbligatoria.');
        pwdInput.focus();
        return;
      }
      cleanup();
      doGenerateAndDownloadPfx(privateKeyPem, certPem, chainPem, certCommonName, password);
    }

    function onCancel() {
      cleanup();
    }

    function onKeyDown(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        onConfirm();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        onCancel();
      }
    }

    btnConfirm.addEventListener('click', onConfirm);
    btnCancel.addEventListener('click', onCancel);
    pwdInput.addEventListener('keydown', onKeyDown);
  }

  function doGenerateAndDownloadPfx(privateKeyPem, certPem, chainPem, certCommonName, password) {
    try {
      showProgress(
        window.I18N ? window.I18N.t('progress_pfx_title', 'Creazione Archivio PFX') : 'Creazione Archivio PFX',
        window.I18N ? window.I18N.t('progress_pfx_desc', 'Assemblaggio del pacchetto PKCS#12 (.pfx) protetto da password...') : 'Assemblaggio del pacchetto PKCS#12 (.pfx) protetto da password...'
      );
      setTimeout(() => {
        try {
          const pfxBlob = CryptoHelper.createPfxBundle(
            privateKeyPem,
            certPem,
            chainPem,
            password
          );
          hideProgress();
          const safeName = (certCommonName || 'certificato').replace(/[^a-zA-Z0-9.-]/g, '_');
          downloadBlob(`${safeName}.pfx`, pfxBlob);
        } catch (err) {
          hideProgress();
          console.error('Errore generazione PFX:', err);
          const errMsg = (window.I18N ? window.I18N.t('err_pfx_creation', 'Errore durante la creazione del file PFX: ') : 'Errore durante la creazione del file PFX: ') + err.message;
          alert(errMsg);
        }
      }, 50);
    } catch (err) {
      hideProgress();
      alert('Errore creazione PFX: ' + err.message);
    }
  }

  // 8. Gestione Pending & Retrieval Requests
  function setupPendingHandlers() {
    const btn = document.getElementById('btn-check-pending');
    if (btn) {
      btn.addEventListener('click', async () => {
        const reqId = document.getElementById('pending-req-id').value;
        if (!reqId) {
          alert(window.I18N ? window.I18N.t('err_enter_req_id', 'Inserire il Request ID.') : 'Inserire il Request ID.');
          return;
        }

        showProgress(
          window.I18N ? window.I18N.t('progress_checking_status_title', 'Verifica Stato Richiesta') : 'Verifica Stato Richiesta',
          window.I18N ? window.I18N.t('progress_checking_status_desc', null, { requestId: reqId }) : `Interrogazione CA per la richiesta #${reqId}...`
        );

        try {
          const response = await fetch(`/api/certificates/status/${currentCa.id || currentCa.Id}/${reqId}`);
          hideProgress();

          const resultArea = document.getElementById('pending-result-area');
          resultArea.style.display = 'block';

          if (response.status === 401) {
            const authTitle = window.I18N ? window.I18N.t('auth_required_title', 'Autenticazione Richiesta') : 'Autenticazione Richiesta';
            const authDesc = window.I18N ? window.I18N.t('auth_required_desc', 'È necessario accedere con il proprio account utente per verificare e scaricare i certificati.') : 'È necessario accedere con il proprio account utente per verificare e scaricare i certificati.';
            resultArea.innerHTML = `
              <div class="alert alert-warning">
                <strong>🔒 ${escapeHtml(authTitle)}</strong>
                <p style="margin-top: 0.25rem;">${escapeHtml(authDesc)}</p>
              </div>
            `;
            return;
          }

          if (response.status === 403) {
            const errData = await response.json();
            const secTitle = window.I18N ? window.I18N.t('access_denied_security_title', 'Accesso Negato (Controllo di Sicurezza)') : 'Accesso Negato (Controllo di Sicurezza)';
            let displayMsg = errData.statusMessage;
            if (errData.errorCode === 'NotOwner' || (errData.statusMessage && errData.statusMessage.includes('non risulta associata'))) {
              const currentUserName = errData.requesterUser || (cachedUserData && cachedUserData.userName) || '';
              displayMsg = window.I18N
                ? window.I18N.t('access_denied_security_not_owner', null, { requestId: reqId, currentUser: currentUserName })
                : `Accesso negato: La richiesta #${reqId} non risulta associata al tuo account (${currentUserName}). Solo il richiedente originale o un amministratore possono recuperare il certificato.`;
            } else if (!displayMsg) {
              displayMsg = window.I18N ? window.I18N.t('access_denied_security_desc', 'Non sei autorizzato a recuperare questo certificato. Il recupero è consentito esclusivamente a chi ha effettuato la richiesta o a un amministratore.') : 'Non sei autorizzato a recuperare questo certificato. Il recupero è consentito esclusivamente a chi ha effettuato la richiesta o a un amministratore.';
            }

            resultArea.innerHTML = `
              <div class="alert alert-danger" style="border-left: 4px solid #ef4444; background: rgba(239, 68, 68, 0.1);">
                <div>
                  <strong style="color: #ef4444; font-size: 1rem;">⛔ ${escapeHtml(secTitle)}</strong>
                  <p style="margin-top: 0.35rem; color: var(--text-color, #e2e8f0);">${escapeHtml(displayMsg)}</p>
                </div>
              </div>
            `;
            return;
          }

          const result = await response.json();

          if (result.success && result.disposition === 'Issued') {
            const hasPfx = !!(result.privateKeyPem || result.hasPrivateKey);
            const readyTitle = window.I18N ? window.I18N.t('pending_ready_title', 'Certificato Pronto ed Emesso!') : 'Certificato Pronto ed Emesso!';
            const readyDesc = window.I18N ? window.I18N.t('pending_ready_desc', null, { requestId: reqId }) : `La richiesta #${reqId} è stata approvata/emessa con successo.`;
            const reqLabel = window.I18N ? window.I18N.t('requester_label', 'Richiedente:') : 'Richiedente:';
            const unspecLabel = window.I18N ? window.I18N.t('unspecified_label', 'Non specificato') : 'Non specificato';
            const dlPfxText = window.I18N ? window.I18N.t('pending_dl_pfx_btn', '🔐 Scarica Archivio PFX (.pfx)') : '🔐 Scarica Archivio PFX (.pfx)';
            const dlCertText = window.I18N ? window.I18N.t('pending_dl_crt_btn', '📄 Scarica Certificato (.crt)') : '📄 Scarica Certificato (.crt)';
            const dlP7bText = window.I18N ? window.I18N.t('pending_dl_p7b_btn', '🔗 Scarica Catena Completa (.p7b)') : '🔗 Scarica Catena Completa (.p7b)';
            const dlChainText = window.I18N ? window.I18N.t('pending_dl_chain_btn', '📜 Scarica Catena (.crt)') : '📜 Scarica Catena (.crt)';

            resultArea.innerHTML = `
              <div class="alert alert-success">
                <div>
                  <strong>${escapeHtml(readyTitle)}</strong>
                  <p style="margin-top: 0.35rem;">${escapeHtml(result.statusMessage || readyDesc)}</p>
                  <div style="margin-top: 0.6rem; font-size: 0.85rem; line-height: 1.6; background: rgba(0,0,0,0.05); padding: 0.6rem 0.8rem; border-radius: 6px; margin-bottom: 0.75rem;">
                    <div><strong>${escapeHtml(reqLabel)}</strong> 👤 ${escapeHtml(result.requesterUser || unspecLabel)}</div>
                    <div><strong>Common Name (CN):</strong> <code>${escapeHtml(result.subjectCommonName || '-')}</code></div>
                    ${result.templateDisplayName ? `<div><strong>Template:</strong> ${escapeHtml(result.templateDisplayName)}</div>` : ''}
                  </div>
                  <div style="margin-top: 0.75rem; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                    ${hasPfx ? `<button type="button" class="btn btn-primary btn-sm" id="btn-dl-pending-pfx">${escapeHtml(dlPfxText)}</button>` : ''}
                    <button type="button" class="btn btn-success btn-sm" id="btn-dl-pending-cert">${escapeHtml(dlCertText)}</button>
                    ${result.p7bBase64 ? `<button type="button" class="btn btn-secondary btn-sm" id="btn-dl-pending-p7b">${escapeHtml(dlP7bText)}</button>` : ''}
                    ${result.certificateChainPem ? `<button type="button" class="btn btn-secondary btn-sm" id="btn-dl-pending-chain">${escapeHtml(dlChainText)}</button>` : ''}
                  </div>
                </div>
              </div>
            `;

            if (hasPfx) {
              const pfxBtn = document.getElementById('btn-dl-pending-pfx');
              if (pfxBtn) {
                pfxBtn.addEventListener('click', () => {
                  promptAndDownloadPfx(
                    result.privateKeyPem,
                    result.certificatePem,
                    result.certificateChainPem,
                    result.subjectCommonName || `cert_${reqId}`
                  );
                });
              }
            }

            document.getElementById('btn-dl-pending-cert').addEventListener('click', () => {
              downloadFile(`${result.subjectCommonName || reqId}.crt`, result.certificatePem, 'application/x-x509-ca-cert');
            });

            if (result.p7bBase64) {
              const p7bBtn = document.getElementById('btn-dl-pending-p7b');
              if (p7bBtn) {
                p7bBtn.addEventListener('click', () => {
                  const p7bText = p7bBase64ToFileText(result.p7bBase64);
                  if (p7bText) {
                    downloadFile(`${result.subjectCommonName || reqId}_chain.p7b`, p7bText, 'application/x-pkcs7-certificates');
                  } else if (result.certificateChainPem) {
                    downloadFile(`${result.subjectCommonName || reqId}_chain.crt`, result.certificateChainPem, 'application/x-x509-ca-cert');
                  }
                });
              }
            }

            if (result.certificateChainPem) {
              const chainBtn = document.getElementById('btn-dl-pending-chain');
              if (chainBtn) {
                chainBtn.addEventListener('click', () => {
                  downloadFile(`${result.subjectCommonName || reqId}_chain.crt`, result.certificateChainPem, 'application/x-x509-ca-cert');
                });
              }
            }

            // Aggiorna lo storico delle proprie richieste
            loadMyRequests();
          } else {
            const pendingTitle = window.I18N ? window.I18N.t('pending_status_box_title', 'Stato Richiesta: In Attesa o Non Disponibile') : 'Stato Richiesta: In Attesa o Non Disponibile';
            const pendingDesc = window.I18N ? window.I18N.t('pending_status_box_desc', 'Richiesta ancora in attesa di approvazione.') : 'Richiesta ancora in attesa di approvazione.';
            const reqLabel = window.I18N ? window.I18N.t('requester_label', 'Richiedente:') : 'Richiedente:';
            resultArea.innerHTML = `
              <div class="alert alert-warning">
                <strong>${escapeHtml(pendingTitle)}</strong>
                <p style="margin-top: 0.25rem;">${escapeHtml(result.statusMessage || pendingDesc)}</p>
                ${result.requesterUser ? `<div style="margin-top:0.35rem; font-size: 0.85rem;"><strong>${escapeHtml(reqLabel)}</strong> 👤 ${escapeHtml(result.requesterUser)}</div>` : ''}
              </div>
            `;
          }
        } catch (err) {
          hideProgress();
          alert('Errore durante la verifica: ' + err.message);
        }
      });
    }

    const refreshBtn = document.getElementById('btn-refresh-my-requests');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', loadMyRequests);
    }
  }

  // 8b. Caricamento lista richieste dell'utente autenticato
  async function loadMyRequests() {
    const area = document.getElementById('my-requests-area');
    if (!area) return;

    try {
      const resp = await fetch('/api/certificates/my-requests');
      if (resp.status === 401) {
        const loginReqMsg = window.I18N ? window.I18N.t('login_required', 'Effettua l\'accesso per visualizzare lo storico delle tue richieste.') : 'Effettua l\'accesso per visualizzare lo storico delle tue richieste.';
        area.innerHTML = `<p style="color: var(--text-muted, #94a3b8); font-size: 0.9rem;">🔒 ${escapeHtml(loginReqMsg)}</p>`;
        return;
      }
      if (!resp.ok) throw new Error('Errore durante il recupero delle richieste.');

      const requests = await resp.json();
      if (!requests || requests.length === 0) {
        const noReqMsg = window.I18N ? window.I18N.t('no_requests_found', 'Nessuna richiesta certificato trovata a tuo nome.') : 'Nessuna richiesta certificato trovata a tuo nome.';
        area.innerHTML = `<p style="color: var(--text-muted, #94a3b8); font-size: 0.9rem;">${escapeHtml(noReqMsg)}</p>`;
        return;
      }

      const thReq = window.I18N ? window.I18N.t('th_requester', 'Richiedente') : 'Richiedente';
      const thDate = window.I18N ? window.I18N.t('th_date', 'Data') : 'Data';
      const thStatus = window.I18N ? window.I18N.t('th_status', 'Stato') : 'Stato';
      const thAction = window.I18N ? window.I18N.t('th_action', 'Azione') : 'Azione';
      const userLocale = window.I18N ? window.I18N.getLocale() : 'it-IT';

      let html = `
        <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 0.5rem;">
          <thead>
            <tr style="border-bottom: 2px solid var(--border-color, #334155); text-align: left;">
              <th style="padding: 0.6rem 0.5rem;">ID (#)</th>
              <th style="padding: 0.6rem 0.5rem;">${escapeHtml(thReq)}</th>
              <th style="padding: 0.6rem 0.5rem;">CA</th>
              <th style="padding: 0.6rem 0.5rem;">Template</th>
              <th style="padding: 0.6rem 0.5rem;">Common Name</th>
              <th style="padding: 0.6rem 0.5rem;">${escapeHtml(thDate)}</th>
              <th style="padding: 0.6rem 0.5rem;">${escapeHtml(thStatus)}</th>
              <th style="padding: 0.6rem 0.5rem; text-align: center;">${escapeHtml(thAction)}</th>
            </tr>
          </thead>
          <tbody>
      `;

      for (const r of requests) {
        const dateStr = r.submittedAt ? new Date(r.submittedAt).toLocaleString(userLocale) : '-';
        let statusBadge = '';
        if (r.status === 'Issued' || r.status === 'Approved') {
          const lbl = window.I18N ? window.I18N.t('status_issued', 'Emesso') : 'Emesso';
          statusBadge = `<span style="background: rgba(34, 197, 94, 0.2); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.4); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 500;">${escapeHtml(lbl)}</span>`;
        } else if (r.status === 'PendingApproval' || r.status === 'UnderSubmission') {
          const lbl = window.I18N ? window.I18N.t('status_pending', 'In Attesa') : 'In Attesa';
          statusBadge = `<span style="background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.4); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 500;">${escapeHtml(lbl)}</span>`;
        } else if (r.status === 'Rejected') {
          const lbl = window.I18N ? window.I18N.t('status_rejected', 'Rifiutato') : 'Rifiutato';
          statusBadge = `<span style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 500;">${escapeHtml(lbl)}</span>`;
        } else {
          statusBadge = `<span style="background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.4); padding: 0.2rem 0.5rem; border-radius: 4px;">${escapeHtml(r.status)}</span>`;
        }

        const canDownload = (r.status === 'Issued' || r.status === 'Approved') && r.hasCertificate;
        let actionHtml = `<span style="color: var(--text-muted, #94a3b8);">-</span>`;
        if (canDownload) {
          const tipCrt = window.I18N ? window.I18N.t('btn_dl_row_crt_title', 'Scarica Certificato .CRT') : 'Scarica Certificato .CRT';
          const tipPfx = window.I18N ? window.I18N.t('btn_dl_row_pfx_title', 'Scarica Archivio PFX con chiave privata') : 'Scarica Archivio PFX con chiave privata';
          actionHtml = `
            <div style="display: inline-flex; gap: 0.35rem; justify-content: center; flex-wrap: wrap;">
              <button type="button" class="btn btn-secondary btn-sm btn-dl-row-crt" data-ca="${escapeHtml(r.caId)}" data-reqid="${r.caRequestId}" data-cn="${escapeHtml(r.subjectCommonName || 'cert')}" style="padding: 0.25rem 0.55rem; font-size: 0.78rem;" title="${escapeHtml(tipCrt)}">.CRT</button>
              ${r.hasPrivateKey ? `<button type="button" class="btn btn-primary btn-sm btn-dl-row-pfx" data-ca="${escapeHtml(r.caId)}" data-reqid="${r.caRequestId}" data-cn="${escapeHtml(r.subjectCommonName || 'cert')}" style="padding: 0.25rem 0.55rem; font-size: 0.78rem;" title="${escapeHtml(tipPfx)}">.PFX</button>` : ''}
            </div>
          `;
        }

        html += `
          <tr style="border-bottom: 1px solid var(--border-color, #334155);">
            <td style="padding: 0.6rem 0.5rem; font-weight: 600;">#${r.caRequestId}</td>
            <td style="padding: 0.6rem 0.5rem;"><span style="display:inline-flex; align-items:center; gap:0.25rem;">👤 ${escapeHtml(r.requesterUser || '-')}</span></td>
            <td style="padding: 0.6rem 0.5rem;">${escapeHtml(r.caId)}</td>
            <td style="padding: 0.6rem 0.5rem;">${escapeHtml(r.templateDisplayName || r.templateName)}</td>
            <td style="padding: 0.6rem 0.5rem; font-family: monospace;">${escapeHtml(r.subjectCommonName || '-')}</td>
            <td style="padding: 0.6rem 0.5rem;">${dateStr}</td>
            <td style="padding: 0.6rem 0.5rem;">${statusBadge}</td>
            <td style="padding: 0.6rem 0.5rem; text-align: center;">${actionHtml}</td>
          </tr>
        `;
      }

      html += `</tbody></table>`;
      area.innerHTML = html;

      // Eventi pulsante .CRT della tabella
      area.querySelectorAll('.btn-dl-row-crt').forEach(button => {
        button.addEventListener('click', async () => {
          const caId = button.dataset.ca;
          const reqId = button.dataset.reqid;
          const cn = button.dataset.cn || `cert_${reqId}`;
          showProgress(
            window.I18N ? window.I18N.t('progress_retrieving_cert_title', 'Recupero Certificato') : 'Recupero Certificato',
            window.I18N ? window.I18N.t('progress_retrieving_cert_desc', null, { requestId: reqId }) : `Download certificato per richiesta #${reqId}...`
          );
          try {
            const resp = await fetch(`/api/certificates/status/${caId}/${reqId}`);
            const result = await resp.json();
            hideProgress();
            if (result.success && result.certificatePem) {
              downloadFile(`${cn}.crt`, result.certificatePem, 'application/x-x509-ca-cert');
            } else {
              let alertMsg = result.statusMessage;
              if (result.errorCode === 'NotOwner' || (result.statusMessage && result.statusMessage.includes('non risulta associata'))) {
                const currentUserName = result.requesterUser || (cachedUserData && cachedUserData.userName) || '';
                alertMsg = window.I18N
                  ? window.I18N.t('access_denied_security_not_owner', null, { requestId: reqId, currentUser: currentUserName })
                  : `Accesso negato: La richiesta #${reqId} non risulta associata al tuo account (${currentUserName}). Solo il richiedente originale o un amministratore possono recuperare il certificato.`;
              }
              alert(alertMsg || (window.I18N ? window.I18N.t('cert_not_available_dl', 'Certificato non disponibile per il download.') : 'Certificato non disponibile per il download.'));
            }
          } catch (err) {
            hideProgress();
            alert('Errore download: ' + err.message);
          }
        });
      });

      // Eventi pulsante .PFX della tabella
      area.querySelectorAll('.btn-dl-row-pfx').forEach(button => {
        button.addEventListener('click', async () => {
          const caId = button.dataset.ca;
          const reqId = button.dataset.reqid;
          const cn = button.dataset.cn || `cert_${reqId}`;
          showProgress(
            window.I18N ? window.I18N.t('progress_pfx_retrieving_title', 'Recupero Certificato & Chiave') : 'Recupero Certificato & Chiave',
            window.I18N ? window.I18N.t('progress_pfx_retrieving_desc', null, { requestId: reqId }) : `Recupero archivio PKCS#12 per richiesta #${reqId}...`
          );
          try {
            const resp = await fetch(`/api/certificates/status/${caId}/${reqId}`);
            const result = await resp.json();
            hideProgress();
            if (result.success && result.certificatePem && result.privateKeyPem) {
              promptAndDownloadPfx(result.privateKeyPem, result.certificatePem, result.certificateChainPem, cn);
            } else {
              let alertMsg = result.statusMessage;
              if (result.errorCode === 'NotOwner' || (result.statusMessage && result.statusMessage.includes('non risulta associata'))) {
                const currentUserName = result.requesterUser || (cachedUserData && cachedUserData.userName) || '';
                alertMsg = window.I18N
                  ? window.I18N.t('access_denied_security_not_owner', null, { requestId: reqId, currentUser: currentUserName })
                  : `Accesso negato: La richiesta #${reqId} non risulta associata al tuo account (${currentUserName}). Solo il richiedente originale o un amministratore possono recuperare il certificato.`;
              }
              const noKeyMsg = window.I18N ? window.I18N.t('err_pfx_no_key', 'Chiave privata non disponibile per questa richiesta.') : 'Chiave privata non disponibile per questa richiesta.';
              alert(alertMsg || noKeyMsg);
            }
          } catch (err) {
            hideProgress();
            alert('Errore download PFX: ' + err.message);
          }
        });
      });

    } catch (err) {
      area.innerHTML = `<p style="color: #ef4444; font-size: 0.9rem;">Errore caricamento richieste: ${escapeHtml(err.message)}</p>`;
    }
  }

  // 8c. Controllo utente autenticato da /api/me
  let cachedUserData = null;
  async function checkCurrentUser() {
    try {
      if (!cachedUserData) {
        const resp = await fetch('/api/me');
        if (resp.ok) {
          cachedUserData = await resp.json();
        }
      }
      const data = cachedUserData;
      const badge = document.getElementById('portal-user-badge');
      const nameSpan = document.getElementById('portal-user-name');
      const connAsText = window.I18N ? window.I18N.t('connected_as', 'Connesso come') : 'Connesso come';
      const anonText = window.I18N ? window.I18N.t('anonymous_user', 'Anonimo') : 'Anonimo';
      const unauthText = window.I18N ? window.I18N.t('unauthenticated_user', 'Non autenticato') : 'Non autenticato';

      if (data && badge && nameSpan) {
        if (data.isAuthenticated) {
          nameSpan.textContent = data.isAdmin ? `${data.userName} (Admin)` : data.userName;
          badge.title = `${connAsText}: ${data.userName}`;
          if (data.isAdmin) {
            const myRequestsTitle = document.getElementById('my-requests-title');
            const myRequestsSubtitle = document.getElementById('my-requests-subtitle');
            if (myRequestsTitle) myRequestsTitle.textContent = window.I18N ? window.I18N.t('all_requests_admin_title', '📋 Tutti i Certificati e Richieste (Amministratore)') : '📋 Tutti i Certificati e Richieste (Amministratore)';
            if (myRequestsSubtitle) myRequestsSubtitle.textContent = window.I18N ? window.I18N.t('all_requests_admin_subtitle', 'Elenco globale di tutte le richieste registrate nel portale.') : 'Elenco globale di tutte le richieste registrate nel portale.';
          }
        } else {
          nameSpan.textContent = anonText;
          badge.title = unauthText;
        }
      } else if (nameSpan) {
        nameSpan.textContent = unauthText;
        if (badge) badge.title = unauthText;
      }
    } catch { }
  }

  // 9. Download Handler & UI Helpers
  function showResultBox(message, hasPfx) {
    const box = document.getElementById('result-box');
    document.getElementById('result-message').textContent = message;

    const pfxCard = document.getElementById('card-download-pfx');
    pfxCard.style.display = hasPfx ? 'flex' : 'none';

    // Handler download PFX
    document.getElementById('btn-dl-pfx').onclick = () => {
      if (lastGeneratedPfxBlob) {
        downloadBlob(`${lastCommonName}.pfx`, lastGeneratedPfxBlob);
      }
    };

    // Handler download CRT
    document.getElementById('btn-dl-crt').onclick = () => {
      if (lastIssuedCertPem) {
        downloadFile(`${lastCommonName}.crt`, lastIssuedCertPem, 'application/x-x509-ca-cert');
      }
    };

    // Handler download Chain
    // Preferisce il PKCS#7 (.p7b) reale restituito dal server (foglia + Sub-CA + Root);
    // in fallback scarica la catena PEM come .crt (MAI testo PEM con estensione .p7b).
    document.getElementById('btn-dl-chain').onclick = () => {
      const p7bText = p7bBase64ToFileText(lastIssuedP7bBase64);
      if (p7bText) {
        downloadFile(`${lastCommonName}_chain.p7b`, p7bText, 'application/x-pkcs7-certificates');
        return;
      }
      const chain = lastIssuedChainPem || lastIssuedCertPem;
      if (chain) {
        downloadFile(`${lastCommonName}_chain.crt`, chain, 'application/x-x509-ca-cert');
      }
    };

    box.style.display = 'block';
    box.scrollIntoView({ behavior: 'smooth' });
  }

  function downloadFile(filename, text, mimeType) {
    const blob = new Blob([text], { type: mimeType });
    downloadBlob(filename, blob);
  }

  function downloadBlob(filename, blob) {
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  }

  /**
   * Decodifica il campo p7bBase64 del server nel contenuto standard di un file
   * .p7b (testo Base64 di un PKCS#7, colonne da 64).
   * Gestisce sia il formato normalizzato (Base64 del file .p7b) sia il formato
   * legacy dei vecchi build (Base64 di un PKCS#7 DER, da riconvertire in testo).
   * Restituisce null se il valore non è interpretabile.
   */
  function p7bBase64ToFileText(p7bB64) {
    try {
      if (!p7bB64 || typeof p7bB64 !== 'string') return null;
      const clean = p7bB64.replace(/\s+/g, '');
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) return null;

      const bin = atob(clean);
      if (!bin) return null;

      // Se il contenuto decodificato è già testo stampabile (file .p7b), lo usiamo così com'è
      let isText = true;
      for (let i = 0; i < bin.length; i++) {
        const c = bin.charCodeAt(i);
        if (!((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13)) {
          isText = false;
          break;
        }
      }
      if (isText) return bin;

      // Contenuto binario (PKCS#7 DER legacy): lo convertiamo in testo Base64 a 64 colonne
      const b64 = btoa(bin);
      return b64.match(/.{1,64}/g).join('\r\n') + '\r\n';
    } catch (e) {
      console.warn('Impossibile decodificare p7bBase64:', e);
      return null;
    }
  }

  function showProgress(title, desc) {
    document.getElementById('progress-step-title').textContent = title;
    document.getElementById('progress-step-desc').textContent = desc;
    document.getElementById('progress-modal').style.display = 'flex';
  }

  function updateProgress(title, desc) {
    document.getElementById('progress-step-title').textContent = title;
    document.getElementById('progress-step-desc').textContent = desc;
  }

  function hideProgress() {
    document.getElementById('progress-modal').style.display = 'none';
  }

  function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/[&<>"']/g, function (m) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
  }

})();
