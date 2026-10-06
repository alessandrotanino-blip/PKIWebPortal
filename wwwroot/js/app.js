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
      const isEn = window.I18N && window.I18N.getLanguage() === 'en';
      container.innerHTML = `<p style="color: var(--gray-400); font-size: 0.9rem;">${isEn ? 'No templates configured for this CA.' : 'Nessun template configurato per questa CA.'}</p>`;
      return;
    }

    // Primo template autorizzato come selezione iniziale (i template non
    // autorizzati — vincolati a gruppi AD — non sono selezionabili).
    const firstAllowedIndex = templates.findIndex(t => (t.IsAllowed ?? t.isAllowed ?? true) !== false);

    const isEn = window.I18N && window.I18N.getLanguage() === 'en';
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

      card.innerHTML = `
        <div class="template-name">${escapeHtml(displayName)}</div>
        <div class="template-desc">${escapeHtml(desc)}</div>
        <div class="template-tags">
          ${approvalBadge}
          ${lockBadge}
          <span class="tag">${validityDays} ${isEn ? 'days' : 'giorni'}</span>
          <span class="tag">${escapeHtml(name)}</span>
        </div>
      `;

      card.addEventListener('click', () => {
        if (!isAllowed) {
          alert(isEn 
            ? 'Unauthorized template: membership in one of the configured AD groups is required to request certificates with this template. Please contact a portal administrator.' 
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
    const isEn = window.I18N && window.I18N.getLanguage() === 'en';
    const select = document.getElementById('upload-template-select');
    select.innerHTML = '';
    if (!templates || templates.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = isEn ? 'No templates available' : 'Nessun template disponibile';
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
      const notAllowedText = isEn ? ' — Not authorized' : ' — Non autorizzato';
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
      list.innerHTML = '<span style="font-size: 0.8rem; color: var(--gray-400); margin-left: 0.5rem;">Nessun SAN alternativo aggiunto (il CN verrà inserito automaticamente)</span>';
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
        alert('Il campo Common Name (CN) è obbligatorio.');
        document.getElementById('form-cn').focus();
        return;
      }

      if (!selectedTemplate) {
        alert('Selezionare un Certificate Template.');
        return;
      }

      if (!pfxPassword) {
        alert('Impostare una password di protezione per il file PFX.');
        document.getElementById('pfx-password').focus();
        return;
      }

      lastCommonName = cn.replace(/[^a-zA-Z0-9.-]/g, '_');

      // Se non è stato specificato alcun SAN DNS corrispondente al CN, lo aggiungiamo automaticamente
      const finalSans = [...sansList];
      if (!finalSans.some(s => s.type === 'DNS' && s.value.toLowerCase() === cn.toLowerCase())) {
        finalSans.unshift({ type: 'DNS', value: cn });
      }

      showProgress('Generazione Crittografica Locale', 'Creazione della coppia di chiavi RSA/ECC nel browser tramite Web Crypto...');

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

        updateProgress('Sottomissione alla CA', 'Invio sicuro del CSR alla Sub-CA Microsoft AD CS...');

        // Step 2: Sottomissione al backend
        const response = await fetch('/api/certificates/request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            caId: currentCa.id || currentCa.Id || '',
            templateName: selectedTemplate.name || selectedTemplate.Name || '',
            csrPem: csrPem,
            privateKeyPem: privateKeyPem
          })
        });

        const result = await response.json();
        hideProgress();

        if (!result.success && result.disposition !== 'UnderSubmission') {
          alert('Errore emissione certificato: ' + (result.statusMessage || 'Errore sconosciuto.'));
          return;
        }

        if (result.disposition === 'UnderSubmission') {
          alert(`Richiesta inoltrata con successo!\n\nLa richiesta è in attesa di approvazione manuale (Pending).\nRequest ID: #${result.requestId}\n\nUna volta approvata dall'amministratore, potrai ritirarla dalla scheda "Ritiro Certificati" scaricando sia il certificato (.crt) sia l'archivio con chiave privata (.pfx).`);
          return;
        }

        // Step 3: Emissione completata! Creazione del PFX client-side
        showProgress('Creazione Archivio PFX', 'Assemblaggio del pacchetto PKCS#12 protetto da password...');

        lastIssuedCertPem = result.certificatePem;
        lastIssuedChainPem = result.certificateChainPem;
        lastIssuedP7bBase64 = result.p7bBase64 || null;

        // === DEBUG: log dei dati ricevuti dal server ===
        console.log('=== DEBUG PFX: dati ricevuti dal server ===');
        console.log('certificatePem type:', typeof lastIssuedCertPem);
        console.log('certificatePem length:', lastIssuedCertPem ? lastIssuedCertPem.length : 'null/undefined');
        console.log('certificatePem (primi 300 char):', lastIssuedCertPem ? lastIssuedCertPem.substring(0, 300) : 'VUOTO');
        console.log('certificatePem (ultimi 100 char):', lastIssuedCertPem ? lastIssuedCertPem.substring(lastIssuedCertPem.length - 100) : 'VUOTO');
        console.log('chainPem type:', typeof lastIssuedChainPem);
        console.log('chainPem length:', lastIssuedChainPem ? lastIssuedChainPem.length : 'null/undefined');
        console.log('chainPem (primi 300 char):', lastIssuedChainPem ? lastIssuedChainPem.substring(0, 300) : 'VUOTO');
        console.log('privateKey type:', typeof privateKey);
        console.log('privateKey has n:', privateKey && privateKey.n ? 'SI' : 'NO');
        console.log('Intero result JSON:', JSON.stringify(result).substring(0, 500));
        console.log('=== FINE DEBUG PFX ===');

        try {
          lastGeneratedPfxBlob = CryptoHelper.createPfxBundle(
            privateKey,
            lastIssuedCertPem,
            lastIssuedChainPem,
            pfxPassword
          );
        } catch (pfxErr) {
          console.error('=== ERRORE PFX dettagliato ===');
          console.error('Messaggio:', pfxErr.message);
          console.error('Stack:', pfxErr.stack);
          console.error('certificatePem COMPLETO:', lastIssuedCertPem);
          console.error('chainPem COMPLETO:', lastIssuedChainPem);
          console.error('=== FINE ERRORE PFX ===');
          throw pfxErr;
        }

        hideProgress();

        // Mostra il box dei download
        showResultBox(result.statusMessage || 'Certificato emesso con successo!', true);

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
        alert('Incollare o caricare un file CSR prima di procedere.');
        return;
      }

      showProgress('Sottomissione CSR', 'Invio del CSR Base64 alla Subordinate CA AD CS...');

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
          alert(`Richiesta inviata con successo!\n\nStato: In attesa di approvazione (Pending).\nRequest ID: #${result.requestId}`);
          return;
        }

        lastIssuedCertPem = result.certificatePem;
        lastIssuedChainPem = result.certificateChainPem;
        lastIssuedP7bBase64 = result.p7bBase64 || null;
        lastGeneratedPfxBlob = null; // Nessuna chiave privata per CSR pre-generato
        lastCommonName = 'cert_' + result.requestId;

        showResultBox(result.statusMessage || 'Certificato emesso con successo!', false);

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
      const pwd = prompt('Inserisci la password per proteggere il file PFX (opzionale):', '');
      if (pwd === null) return;
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
      showProgress('Creazione Archivio PFX', 'Assemblaggio del pacchetto PKCS#12 (.pfx) protetto da password...');
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
          alert('Errore durante la creazione del file PFX: ' + err.message);
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
        const isEn = window.I18N && window.I18N.getLanguage() === 'en';
        const reqId = document.getElementById('pending-req-id').value;
        if (!reqId) {
          alert(isEn ? 'Please enter a Request ID.' : 'Inserire il Request ID.');
          return;
        }

        showProgress(
          isEn ? 'Checking Request Status' : 'Verifica Stato Richiesta',
          isEn ? `Querying CA for request #${reqId}...` : `Interrogazione CA per la richiesta #${reqId}...`
        );

        try {
          const response = await fetch(`/api/certificates/status/${currentCa.id || currentCa.Id}/${reqId}`);
          hideProgress();

          const resultArea = document.getElementById('pending-result-area');
          resultArea.style.display = 'block';

          if (response.status === 401) {
            resultArea.innerHTML = `
              <div class="alert alert-warning">
                <strong>🔒 ${isEn ? 'Authentication Required' : 'Autenticazione Richiesta'}</strong>
                <p style="margin-top: 0.25rem;">${isEn ? 'Please sign in with your user account to verify and download certificates.' : 'È necessario accedere con il proprio account utente per verificare e scaricare i certificati.'}</p>
              </div>
            `;
            return;
          }

          if (response.status === 403) {
            const errData = await response.json();
            resultArea.innerHTML = `
              <div class="alert alert-danger" style="border-left: 4px solid #ef4444; background: rgba(239, 68, 68, 0.1);">
                <div>
                  <strong style="color: #ef4444; font-size: 1rem;">⛔ ${isEn ? 'Access Denied (Security Check)' : 'Accesso Negato (Controllo di Sicurezza)'}</strong>
                  <p style="margin-top: 0.35rem; color: var(--text-color, #e2e8f0);">${escapeHtml(errData.statusMessage || (isEn ? 'You are not authorized to retrieve this certificate. Retrieval is restricted to the original requester or an administrator.' : 'Non sei autorizzato a recuperare questo certificato. Il recupero è consentito esclusivamente a chi ha effettuato la richiesta o a un amministratore.'))}</p>
                </div>
              </div>
            `;
            return;
          }

          const result = await response.json();

          if (result.success && result.disposition === 'Issued') {
            const hasPfx = !!(result.privateKeyPem || result.hasPrivateKey);
            resultArea.innerHTML = `
              <div class="alert alert-success">
                <div>
                  <strong>${isEn ? 'Certificate Ready and Issued!' : 'Certificato Pronto ed Emesso!'}</strong>
                  <p style="margin-top: 0.35rem;">${escapeHtml(result.statusMessage || (isEn ? `Request #${reqId} was successfully approved/issued.` : `La richiesta #${reqId} è stata approvata/emessa con successo.`))}</p>
                  <div style="margin-top: 0.6rem; font-size: 0.85rem; line-height: 1.6; background: rgba(0,0,0,0.05); padding: 0.6rem 0.8rem; border-radius: 6px; margin-bottom: 0.75rem;">
                    <div><strong>${isEn ? 'Requester:' : 'Richiedente:'}</strong> 👤 ${escapeHtml(result.requesterUser || (isEn ? 'Unspecified' : 'Non specificato'))}</div>
                    <div><strong>Common Name (CN):</strong> <code>${escapeHtml(result.subjectCommonName || '-')}</code></div>
                    ${result.templateDisplayName ? `<div><strong>Template:</strong> ${escapeHtml(result.templateDisplayName)}</div>` : ''}
                  </div>
                  <div style="margin-top: 0.75rem; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                    ${hasPfx ? `<button type="button" class="btn btn-primary btn-sm" id="btn-dl-pending-pfx">🔐 ${isEn ? 'Download PFX Archive (.pfx)' : 'Scarica Archivio PFX (.pfx)'}</button>` : ''}
                    <button type="button" class="btn btn-success btn-sm" id="btn-dl-pending-cert">📄 ${isEn ? 'Download Certificate (.crt)' : 'Scarica Certificato (.crt)'}</button>
                    ${result.p7bBase64 ? `<button type="button" class="btn btn-secondary btn-sm" id="btn-dl-pending-p7b">🔗 ${isEn ? 'Download Full Chain (.p7b)' : 'Scarica Catena Completa (.p7b)'}</button>` : ''}
                    ${result.certificateChainPem ? `<button type="button" class="btn btn-secondary btn-sm" id="btn-dl-pending-chain">📜 ${isEn ? 'Download Chain (.crt)' : 'Scarica Catena (.crt)'}</button>` : ''}
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
                  // PKCS#7 (.p7b) reale con la catena completa; fallback sulla catena PEM
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
            resultArea.innerHTML = `
              <div class="alert alert-warning">
                <strong>${isEn ? 'Request Status: Pending or Unavailable' : 'Stato Richiesta: In Attesa o Non Disponibile'}</strong>
                <p style="margin-top: 0.25rem;">${escapeHtml(result.statusMessage || (isEn ? 'Request still pending approval.' : 'Richiesta ancora in attesa di approvazione.'))}</p>
                ${result.requesterUser ? `<div style="margin-top:0.35rem; font-size: 0.85rem;"><strong>${isEn ? 'Requester:' : 'Richiedente:'}</strong> 👤 ${escapeHtml(result.requesterUser)}</div>` : ''}
              </div>
            `;
          }
        } catch (err) {
          hideProgress();
          alert((isEn ? 'Error during verification: ' : 'Errore durante la verifica: ') + err.message);
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
    const isEn = window.I18N && window.I18N.getLanguage() === 'en';

    try {
      const resp = await fetch('/api/certificates/my-requests');
      if (resp.status === 401) {
        area.innerHTML = `<p style="color: var(--text-muted, #94a3b8); font-size: 0.9rem;">🔒 ${isEn ? 'Please log in to view your request history.' : 'Effettua l\'accesso per visualizzare lo storico delle tue richieste.'}</p>`;
        return;
      }
      if (!resp.ok) throw new Error(isEn ? 'Error retrieving requests.' : 'Errore durante il recupero delle richieste.');

      const requests = await resp.json();
      if (!requests || requests.length === 0) {
        area.innerHTML = `<p style="color: var(--text-muted, #94a3b8); font-size: 0.9rem;">${isEn ? 'No certificate requests found for your account.' : 'Nessuna richiesta certificato trovata per il tuo account.'}</p>`;
        return;
      }

      let html = `
        <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 0.5rem;">
          <thead>
            <tr style="border-bottom: 2px solid var(--border-color, #334155); text-align: left;">
              <th style="padding: 0.6rem 0.5rem;">ID (#)</th>
              <th style="padding: 0.6rem 0.5rem;">${isEn ? 'Requester' : 'Richiedente'}</th>
              <th style="padding: 0.6rem 0.5rem;">CA</th>
              <th style="padding: 0.6rem 0.5rem;">Template</th>
              <th style="padding: 0.6rem 0.5rem;">Common Name</th>
              <th style="padding: 0.6rem 0.5rem;">${isEn ? 'Date' : 'Data'}</th>
              <th style="padding: 0.6rem 0.5rem;">${isEn ? 'Status' : 'Stato'}</th>
              <th style="padding: 0.6rem 0.5rem; text-align: center;">${isEn ? 'Action' : 'Azione'}</th>
            </tr>
          </thead>
          <tbody>
      `;

      for (const r of requests) {
        const dateStr = r.submittedAt ? new Date(r.submittedAt).toLocaleString(isEn ? 'en-US' : 'it-IT') : '-';
        let statusBadge = '';
        if (r.status === 'Issued' || r.status === 'Approved') {
          statusBadge = `<span style="background: rgba(34, 197, 94, 0.2); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.4); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 500;">${isEn ? 'Issued' : 'Emesso'}</span>`;
        } else if (r.status === 'PendingApproval' || r.status === 'UnderSubmission') {
          statusBadge = `<span style="background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.4); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 500;">${isEn ? 'Pending' : 'In Attesa'}</span>`;
        } else if (r.status === 'Rejected') {
          statusBadge = `<span style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 500;">${isEn ? 'Rejected' : 'Rifiutato'}</span>`;
        } else {
          statusBadge = `<span style="background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.4); padding: 0.2rem 0.5rem; border-radius: 4px;">${escapeHtml(r.status)}</span>`;
        }

        const canDownload = (r.status === 'Issued' || r.status === 'Approved') && r.hasCertificate;
        let actionHtml = `<span style="color: var(--text-muted, #94a3b8);">-</span>`;
        if (canDownload) {
          actionHtml = `
            <div style="display: inline-flex; gap: 0.35rem; justify-content: center; flex-wrap: wrap;">
              <button type="button" class="btn btn-secondary btn-sm btn-dl-row-crt" data-ca="${escapeHtml(r.caId)}" data-reqid="${r.caRequestId}" data-cn="${escapeHtml(r.subjectCommonName || 'cert')}" style="padding: 0.25rem 0.55rem; font-size: 0.78rem;" title="${isEn ? 'Download .CRT Certificate' : 'Scarica Certificato .CRT'}">.CRT</button>
              ${r.hasPrivateKey ? `<button type="button" class="btn btn-primary btn-sm btn-dl-row-pfx" data-ca="${escapeHtml(r.caId)}" data-reqid="${r.caRequestId}" data-cn="${escapeHtml(r.subjectCommonName || 'cert')}" style="padding: 0.25rem 0.55rem; font-size: 0.78rem;" title="${isEn ? 'Download PFX archive with private key' : 'Scarica Archivio PFX con chiave privata'}">.PFX</button>` : ''}
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
          showProgress(isEn ? 'Retrieving Certificate' : 'Recupero Certificato', isEn ? `Downloading certificate for request #${reqId}...` : `Download certificato per richiesta #${reqId}...`);
          try {
            const resp = await fetch(`/api/certificates/status/${caId}/${reqId}`);
            const result = await resp.json();
            hideProgress();
            if (result.success && result.certificatePem) {
              downloadFile(`${cn}.crt`, result.certificatePem, 'application/x-x509-ca-cert');
            } else {
              alert(result.statusMessage || (isEn ? 'Certificate not available for download.' : 'Certificato non disponibile per il download.'));
            }
          } catch (err) {
            hideProgress();
            alert((isEn ? 'Download error: ' : 'Errore download: ') + err.message);
          }
        });
      });

      // Eventi pulsante .PFX della tabella
      area.querySelectorAll('.btn-dl-row-pfx').forEach(button => {
        button.addEventListener('click', async () => {
          const caId = button.dataset.ca;
          const reqId = button.dataset.reqid;
          const cn = button.dataset.cn || `cert_${reqId}`;
          showProgress(isEn ? 'Retrieving Certificate & Key' : 'Recupero Certificato & Chiave', isEn ? `Retrieving PKCS#12 archive for request #${reqId}...` : `Recupero archivio PKCS#12 per richiesta #${reqId}...`);
          try {
            const resp = await fetch(`/api/certificates/status/${caId}/${reqId}`);
            const result = await resp.json();
            hideProgress();
            if (result.success && result.certificatePem && result.privateKeyPem) {
              promptAndDownloadPfx(result.privateKeyPem, result.certificatePem, result.certificateChainPem, cn);
            } else {
              alert(result.statusMessage || (isEn ? 'Private key not available for this request.' : 'Chiave privata non disponibile per questa richiesta.'));
            }
          } catch (err) {
            hideProgress();
            alert((isEn ? 'PFX download error: ' : 'Errore download PFX: ') + err.message);
          }
        });
      });

    } catch (err) {
      area.innerHTML = `<p style="color: #ef4444; font-size: 0.9rem;">${isEn ? 'Error loading requests: ' : 'Errore caricamento richieste: '}${escapeHtml(err.message)}</p>`;
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
      const isEn = window.I18N && window.I18N.getLanguage() === 'en';
      const badge = document.getElementById('portal-user-badge');
      const nameSpan = document.getElementById('portal-user-name');
      if (data && badge && nameSpan) {
        if (data.isAuthenticated) {
          nameSpan.textContent = data.isAdmin ? `${data.userName} (Admin)` : data.userName;
          badge.title = `${isEn ? 'Connected as' : 'Connesso come'}: ${data.userName}`;
          if (data.isAdmin) {
            const myRequestsTitle = document.getElementById('my-requests-title');
            const myRequestsSubtitle = document.getElementById('my-requests-subtitle');
            if (myRequestsTitle) myRequestsTitle.textContent = isEn ? '📋 All Certificates and Requests (Administrator)' : '📋 Tutti i Certificati e Richieste (Amministratore)';
            if (myRequestsSubtitle) myRequestsSubtitle.textContent = isEn ? 'Global list of all certificate requests registered in the portal.' : 'Elenco globale di tutte le richieste registrate nel portale.';
          }
        } else {
          nameSpan.textContent = isEn ? 'Anonymous' : 'Anonimo';
          badge.title = isEn ? 'Unauthenticated access' : 'Accesso non autenticato';
        }
      } else if (nameSpan) {
        nameSpan.textContent = isEn ? 'Unauthenticated' : 'Non autenticato';
        if (badge) badge.title = isEn ? 'Unauthenticated access' : 'Accesso non autenticato';
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
