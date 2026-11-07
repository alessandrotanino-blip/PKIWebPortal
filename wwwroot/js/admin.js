  (function() {
    'use strict';

    // SECURITY (2.1.0): binding via addEventListener al posto di handler inline
    // (la Content-Security-Policy del portale non ammette script inline).
    const cancelChangesBtn = document.getElementById('btn-cancel-changes');
    if (cancelChangesBtn) {
      cancelChangesBtn.addEventListener('click', () => location.reload());
    }

    function escapeHtml(text) {
      if (!text) return '';
      return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function setupThemeToggle() {
      const toggle = document.getElementById('theme-toggle');
      if (!toggle) return;
      const iconSun = document.getElementById('theme-icon-sun');
      const iconMoon = document.getElementById('theme-icon-moon');

      function updateThemeIcon() {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        if (iconSun) iconSun.style.display = isDark ? 'block' : 'none';
        if (iconMoon) iconMoon.style.display = isDark ? 'none' : 'block';
      }

      updateThemeIcon();

      toggle.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('pki-theme', next);
        updateThemeIcon();
      });
    }

    let portalConfig = null;
    let currentAdminUser = '';

    // SECURITY (2.1.0): token anti-CSRF legato all'identità (emesso da
    // GET /api/admin/csrf, vita 30 min). Ogni richiesta mutante (POST/PUT)
    // lo invia nell'header X-Pki-Portal-Admin. Si rinnova automaticamente
    // quando resta meno di 5 minuti alla scadenza.
    let csrfToken = null;
    let csrfTokenFetchedAt = 0;
    const CSRF_TTL_MS = 25 * 60 * 1000;

    async function ensureCsrfToken() {
      const now = Date.now();
      if (csrfToken && (now - csrfTokenFetchedAt) < CSRF_TTL_MS) {
        return csrfToken;
      }
      const resp = await fetch('/api/admin/csrf');
      if (!resp.ok) {
        throw new Error('Impossibile ottenere il token anti-CSRF (HTTP ' + resp.status + ').');
      }
      const data = await resp.json();
      csrfToken = data.token;
      csrfTokenFetchedAt = now;
      return csrfToken;
    }

    document.addEventListener('DOMContentLoaded', init);

    function updateAdminUserBadge() {
      const userBadge = document.getElementById('admin-user-badge');
      if (userBadge && currentAdminUser) {
        const lblUser = window.I18N ? window.I18N.t('admin_user_label', 'Utente:') : 'Utente:';
        userBadge.textContent = `${lblUser} ${currentAdminUser}`;
      }
    }

    async function init() {
      setupThemeToggle();
      // Check admin access
      try {
        const resp = await fetch('/api/admin/check');
        if (resp.status === 401 || resp.status === 403) {
          const authMsg = window.I18N ? window.I18N.t('admin_auth_required', 'Autenticazione richiesta.') : 'Autenticazione richiesta.';
          showAccessDenied(authMsg);
          return;
        }
        const data = await resp.json();
        if (!data.isAdmin) {
          showAccessDenied(data.userName);
          return;
        }
        currentAdminUser = data.userName;
        updateAdminUserBadge();
        // SECURITY (2.1.0): ottiene il token anti-CSRF legato a questa identità
        await ensureCsrfToken();
      } catch (err) {
        const connMsg = window.I18N ? window.I18N.t('admin_conn_error', 'Errore di connessione') : 'Errore di connessione';
        showAccessDenied(connMsg);
        return;
      }

      // Load config
      try {
        const resp = await fetch('/api/admin/config');
        if (!resp.ok) {
          const cfgMsg = window.I18N ? window.I18N.t('admin_config_load_error', 'Impossibile caricare la configurazione') : 'Impossibile caricare la configurazione';
          showAccessDenied(cfgMsg);
          return;
        }
        portalConfig = await resp.json();
        renderConfig();
        document.getElementById('admin-panel').style.display = 'block';
      } catch (err) {
        showToast('Errore caricamento configurazione: ' + err.message, 'error');
      }

      // Setup event handlers
      setupTabs();
      setupHeldRequestsHandlers();
      loadHeldRequests();
      setupAcmeTab();

      // Setup language changed listener
      window.addEventListener('languageChanged', () => {
        updateAdminUserBadge();
        if (portalConfig) renderConfig();
        loadHeldRequests();
      });

      document.getElementById('btn-add-ca').addEventListener('click', addNewCa);
      document.getElementById('btn-save-config').addEventListener('click', saveConfig);
    }

    function showAccessDenied(userName) {
      document.getElementById('admin-panel').style.display = 'none';
      document.getElementById('access-denied').style.display = 'block';
      const lblUser = window.I18N ? window.I18N.t('admin_user_label', 'Utente:') : 'Utente:';
      const unknownText = window.I18N ? window.I18N.t('admin_unknown_user', 'Sconosciuto') : 'Sconosciuto';
      document.getElementById('denied-user').textContent = `${lblUser} ${userName || unknownText}`;
    }

    function renderConfig() {
      document.getElementById('cfg-title').value = portalConfig.portalTitle || portalConfig.PortalTitle || '';
      document.getElementById('cfg-mode').value = portalConfig.portalMode || portalConfig.PortalMode || 'Standalone';
      document.getElementById('cfg-default-ca').value = portalConfig.defaultCaId || portalConfig.DefaultCaId || '';
      renderCaList();
    }

    function renderCaList() {
      const container = document.getElementById('ca-list');
      container.innerHTML = '';
      const cas = portalConfig.cas || portalConfig.CAs || [];
      cas.forEach((ca, index) => renderCaCard(container, ca, index));
    }

    // Scompone la ConfigString "server\Nome-CA" (o "server/Nome-CA") nei due
    // campi Server CA e Nome CA. Il nome CA non contiene mai barre (validato
    // a livello server): si usa la prima barra incontrata.
    function splitConfigString(cfg) {
      if (!cfg) return ['', ''];
      const s = String(cfg).trim();
      let cut = -1;
      for (const sep of ['\\', '/']) {
        const p = s.indexOf(sep);
        if (p !== -1 && (cut === -1 || p < cut)) cut = p;
      }
      if (cut === -1) return [s, ''];
      return [s.slice(0, cut).trim(), s.slice(cut + 1).trim()];
    }

    function renderCaCard(container, ca, caIndex) {
      const card = document.createElement('div');
      card.className = 'ca-card';

      const isDefault = ca.isDefault || ca.IsDefault || false;
      const useSimulator = ca.useSimulator || ca.UseSimulator || false;
      const displayName = ca.displayName || ca.DisplayName || (window.I18N ? window.I18N.t('admin_new_ca', 'Nuova CA') : 'Nuova CA');
      const id = ca.id || ca.Id || '';
      const forestOrDomain = ca.forestOrDomain || ca.ForestOrDomain || '';
      const configString = ca.configString || ca.ConfigString || '';
      // Server CA e Nome CA: derivati dalla ConfigString esistente (il server
      // li ricostruisce automaticamente al salvataggio). I valori sono
      // mantenuti sull'oggetto CA così che le re-render (es. cambio lingua)
      // e il salvataggio li trovino coerenti.
      const [caServer, caName] = splitConfigString(configString);
      ca.caServer = caServer;
      ca.caName = caName;
      const description = ca.description || ca.Description || '';
      const authMode = ca.authMode || ca.AuthMode || 'LocalIdentity';
      // Credential Target: dedotto automaticamente dal Server CA (è il target
      // della credenziale nel Windows Credential Manager).
      const credentialTarget = caServer || (ca.credentialTarget || ca.CredentialTarget || '');

      const defaultTagText = window.I18N ? window.I18N.t('admin_default_tag', 'Predefinita') : 'Predefinita';
      const simulatorTagText = window.I18N ? window.I18N.t('admin_simulator_tag', 'Simulatore') : 'Simulatore';
      const defaultTag = isDefault ? `<span class="tag tag-success">${escapeHtml(defaultTagText)}</span>` : '';
      const simulatorTag = useSimulator ? `<span class="tag tag-warning">${escapeHtml(simulatorTagText)}</span>` : '';
      const removeCaTitle = window.I18N ? window.I18N.t('admin_remove_ca_title', 'Rimuovi CA') : 'Rimuovi CA';

      const lblDispName = window.I18N ? window.I18N.t('admin_lbl_display_name', 'Nome Visualizzato') : 'Nome Visualizzato';
      const lblForest = window.I18N ? window.I18N.t('admin_lbl_forest', 'Foresta / Dominio') : 'Foresta / Dominio';
      const lblDesc = window.I18N ? window.I18N.t('admin_lbl_description', 'Descrizione') : 'Descrizione';
      const lblAuth = window.I18N ? window.I18N.t('admin_lbl_auth_mode', 'Modalità Auth') : 'Modalità Auth';
      const lblDefCa = window.I18N ? window.I18N.t('admin_lbl_default_ca', 'CA Predefinita') : 'CA Predefinita';
      const lblSim = window.I18N ? window.I18N.t('admin_lbl_simulator', 'Usa Simulatore') : 'Usa Simulatore';
      const btnAddTmplManual = window.I18N ? window.I18N.t('btn_add_template_manual', '+ Aggiungi Manualmente') : '+ Aggiungi Manualmente';
      const btnDiscoverText = window.I18N ? window.I18N.t('btn_discover', '🔍 Scopri dalla CA') : '🔍 Scopri dalla CA';
      const clickDiscoverText = window.I18N ? window.I18N.t('admin_click_discover', 'Clicca "Scopri dalla CA"') : 'Clicca "Scopri dalla CA"';
      const btnAddText = window.I18N ? window.I18N.t('admin_btn_add', '+ Aggiungi') : '+ Aggiungi';
      const lblCaServer = window.I18N ? window.I18N.t('admin_lbl_ca_server', 'Server CA') : 'Server CA';
      const lblCaName = window.I18N ? window.I18N.t('admin_lbl_ca_name', 'Nome CA') : 'Nome CA';
      const btnDiscoverCa = window.I18N ? window.I18N.t('admin_btn_discover_ca', '🔍 Rileva CA') : '🔍 Rileva CA';
      const hintCaName = window.I18N ? window.I18N.t('admin_hint_ca_name', 'Clicca «Rileva CA» per enumerare le CA ospitate sul server: il portale interroga il dominio AD (attributo caDnsName) e, in fallback, la pagina CAPL del server CA.') : 'Clicca «Rileva CA» per enumerare le CA ospitate sul server: il portale interroga il dominio AD (attributo caDnsName) e, in fallback, la pagina CAPL del server CA.';
      const hintConfigString = window.I18N ? window.I18N.t('admin_hint_config_string', 'Costruita automaticamente in forma server\\nome-CA: non richiede input manuale.') : 'Costruita automaticamente in forma server\\nome-CA: non richiede input manuale.';
      const hintCredTarget = window.I18N ? window.I18N.t('admin_hint_credential_target', 'Dedotto automaticamente dal Server CA (target della credenziale nel Windows Credential Manager).') : 'Dedotto automaticamente dal Server CA (target della credenziale nel Windows Credential Manager).';
      const caNamePlaceholder = window.I18N ? window.I18N.t('admin_ca_select_placeholder', '— seleziona un nome CA —') : '— seleziona un nome CA —';
      const autoTag = window.I18N ? window.I18N.t('admin_auto_tag', 'auto') : 'auto';

      card.innerHTML = `
        <div class="ca-card-header">
          <h4>
            <span class="chevron${caIndex === 0 ? ' open' : ''}">▶</span>
            <span style="color:var(--primary); margin: 0 0.4rem;">#${caIndex + 1}</span>
            ${esc(displayName)}
          </h4>
          <div style="display:flex;gap:0.5rem;align-items:center;">
            ${defaultTag}
            ${simulatorTag}
            <button type="button" class="btn btn-danger btn-sm btn-remove-ca" data-index="${caIndex}" title="${escapeHtml(removeCaTitle)}">✕</button>
          </div>
        </div>
        <div class="ca-card-body${caIndex === 0 ? ' open' : ''}">
          <div class="field-row">
            <label>ID</label>
            <input type="text" class="form-control ca-field" data-ca="${caIndex}" data-field="id" value="${esc(id)}">
          </div>
          <div class="field-row">
            <label>${escapeHtml(lblDispName)}</label>
            <input type="text" class="form-control ca-field" data-ca="${caIndex}" data-field="displayName" value="${esc(displayName)}">
          </div>
          <div class="field-row">
            <label>${escapeHtml(lblForest)}</label>
            <input type="text" class="form-control ca-field" data-ca="${caIndex}" data-field="forestOrDomain" value="${esc(forestOrDomain)}">
          </div>
          <div class="field-row">
            <label>${escapeHtml(lblCaServer)}</label>
            <input type="text" class="form-control ca-field" data-ca="${caIndex}" data-field="caServer" value="${esc(caServer)}" placeholder="es. vdpki.vd.ld">
          </div>
          <div class="field-row">
            <label>${escapeHtml(lblCaName)}</label>
            <div style="display:flex; gap:0.5rem; align-items:center;">
              <select class="form-control ca-field" data-ca="${caIndex}" data-field="caName" style="flex:1;">
                <option value="">${escapeHtml(caNamePlaceholder)}</option>
              </select>
              <button type="button" class="btn btn-secondary btn-sm btn-discover-ca" data-ca="${caIndex}">${escapeHtml(btnDiscoverCa)}</button>
            </div>
            <small style="display:block; margin-top:0.25rem; opacity:0.7;">${escapeHtml(hintCaName)}</small>
          </div>
          <div class="field-row">
            <label>Config String <span class="tag tag-success">${escapeHtml(autoTag)}</span></label>
            <input type="text" class="form-control ca-field" data-ca="${caIndex}" data-field="configString" value="${esc(configString)}" disabled>
            <small style="display:block; margin-top:0.25rem; opacity:0.7;">${escapeHtml(hintConfigString)}</small>
          </div>
          <div class="field-row">
            <label>${escapeHtml(lblDesc)}</label>
            <input type="text" class="form-control ca-field" data-ca="${caIndex}" data-field="description" value="${esc(description)}">
          </div>
          <div class="field-row">
            <label>${escapeHtml(lblAuth)}</label>
            <select class="form-control ca-field" data-ca="${caIndex}" data-field="authMode">
              <option value="LocalIdentity" ${authMode === 'LocalIdentity' ? 'selected' : ''}>LocalIdentity (App Pool)</option>
              <option value="CredentialManager" ${authMode === 'CredentialManager' ? 'selected' : ''}>CredentialManager (Multi-Foresta)</option>
            </select>
          </div>
          <div class="field-row">
            <label>Credential Target <span class="tag tag-success">${escapeHtml(autoTag)}</span></label>
            <input type="text" class="form-control ca-field" data-ca="${caIndex}" data-field="credentialTarget" value="${esc(credentialTarget)}" disabled>
            <small style="display:block; margin-top:0.25rem; opacity:0.7;">${escapeHtml(hintCredTarget)}</small>
          </div>
          <div class="field-row">
            <label>${escapeHtml(lblDefCa)}</label>
            <label class="toggle-switch">
              <input type="checkbox" class="ca-toggle" data-ca="${caIndex}" data-field="isDefault" ${isDefault ? 'checked' : ''}>
              <span class="toggle-slider"></span>
            </label>
          </div>
          <div class="field-row">
            <label>${escapeHtml(lblSim)}</label>
            <label class="toggle-switch">
              <input type="checkbox" class="ca-toggle" data-ca="${caIndex}" data-field="useSimulator" ${useSimulator ? 'checked' : ''}>
              <span class="toggle-slider"></span>
            </label>
          </div>
          
          <!-- Templates -->
          <div style="margin-top:1.25rem;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
              <h4 style="font-size:0.95rem;color:var(--gray-900);">📋 Certificate Templates</h4>
              <button type="button" class="btn btn-secondary btn-sm btn-add-template-manual" data-ca="${caIndex}">${escapeHtml(btnAddTmplManual)}</button>
            </div>
            <div class="template-add-bar">
              <button type="button" class="btn btn-discover btn-sm btn-discover-templates" data-ca="${caIndex}">
                ${escapeHtml(btnDiscoverText)}
              </button>
              <select class="form-control discovered-templates-select" data-ca="${caIndex}" disabled>
                <option value="">— ${escapeHtml(clickDiscoverText)} —</option>
              </select>
              <button type="button" class="btn btn-primary btn-sm btn-add-discovered" data-ca="${caIndex}" disabled>${escapeHtml(btnAddText)}</button>
            </div>
            <div class="templates-container" data-ca="${caIndex}"></div>
          </div>
        </div>
      `;
      container.appendChild(card);

      // Collapse/expand handler
      const header = card.querySelector('.ca-card-header');
      header.addEventListener('click', (e) => {
        if (e.target.closest('.btn-remove-ca')) return;
        const body = card.querySelector('.ca-card-body');
        const chevron = card.querySelector('.chevron');
        body.classList.toggle('open');
        chevron.classList.toggle('open');
      });

      // Remove CA handler
      card.querySelector('.btn-remove-ca').addEventListener('click', () => {
        const confirmMsg = window.I18N ? window.I18N.t('confirm_remove_ca', 'Rimuovere questa CA dalla configurazione?') : 'Rimuovere questa CA dalla configurazione?';
        if (!confirm(confirmMsg)) return;
        const cas = portalConfig.cas || portalConfig.CAs || [];
        cas.splice(caIndex, 1);
        renderCaList();
      });

      // CA field change handlers
      card.querySelectorAll('.ca-field').forEach(input => {
        input.addEventListener('change', (e) => {
          const ci = parseInt(e.target.dataset.ca);
          const field = e.target.dataset.field;
          const cas = portalConfig.cas || portalConfig.CAs || [];
          cas[ci][field] = e.target.value;
          // Server CA / Nome CA: ricostruisce i campi derivati
          // (Config String e Credential Target).
          if (field === 'caServer' || field === 'caName') {
            syncDerivedCaFields(e.target.closest('.ca-card'), ci);
          }
        });
      });

      // Rilevamento automatico del Nome CA dal server (endpoint /api/admin/ca/discover)
      card.querySelector('.btn-discover-ca').addEventListener('click', async (e) => {
        const btn = e.target.closest('.btn-discover-ca');
        const ci = parseInt(btn.dataset.ca);
        const cardEl = btn.closest('.ca-card');
        const cas = portalConfig.cas || portalConfig.CAs || [];
        const caObj = cas[ci];

        const forestVal = (cardEl.querySelector('.ca-field[data-field="forestOrDomain"]')?.value || '').trim();
        const serverVal = (cardEl.querySelector('.ca-field[data-field="caServer"]')?.value || '').trim();
        const authModeVal = cardEl.querySelector('.ca-field[data-field="authMode"]')?.value || 'LocalIdentity';
        caObj.forestOrDomain = forestVal;
        caObj.caServer = serverVal;

        if (!serverVal) {
          const msg = window.I18N ? window.I18N.t('admin_ca_server_required', 'Inserisci il Server CA da interrogare.') : 'Inserisci il Server CA da interrogare.';
          showToast(msg, 'error');
          return;
        }

        const spinnerHtml = '<span class="spinner-sm"></span> Rilevamento...';
        btn.disabled = true;
        btn.innerHTML = spinnerHtml;

        try {
          const resp = await fetch('/api/admin/ca/discover', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Pki-Portal-Admin': await ensureCsrfToken() },
            body: JSON.stringify({
              forestOrDomain: forestVal,
              caServer: serverVal,
              authMode: authModeVal,
              credentialTarget: serverVal
            })
          });
          if (!resp.ok) throw new Error('Errore HTTP ' + resp.status);
          const result = await resp.json();
          const rawNames = result.caNames || result.CaNames || [];
          const names = Array.isArray(rawNames) ? rawNames.filter(n => n && String(n).trim()) : [];
          const resultError = result.errorMessage || result.ErrorMessage || '';
          const resultSource = result.source || result.Source || 'AD/CAPL';

          if (names.length === 0) {
            const msg = window.I18N ? window.I18N.t('admin_ca_discover_none', 'Nessuna CA rilevata su «#{server}»: verifica dominio, credenziali o accesso CAPL anonimo.', { server: serverVal }) : `Nessuna CA rilevata su «${serverVal}»: verifica dominio, credenziali o accesso CAPL anonimo.`;
            const detail = resultError ? ` (${resultError})` : '';
            showToast(msg + detail, 'error');
          } else {
            caObj.discoveredCaNames = names;
            populateDiscoveredCaDropdown(cardEl, caObj, ci);
            const okMsg = window.I18N ? window.I18N.t('admin_ca_discover_found', '#{count} nome CA rilevati su «#{server}» (fonte: #{source}).', { count: names.length, server: serverVal, source: resultSource }) : `${names.length} nome CA rilevati su «${serverVal}» (fonte: ${resultSource}).`;
            showToast(okMsg, 'success');
          }
        } catch (err) {
          const msg = window.I18N ? window.I18N.t('admin_ca_discover_error', 'Errore durante il rilevamento: #{error}', { error: err.message }) : `Errore durante il rilevamento: ${err.message}`;
          showToast(msg, 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = window.I18N ? window.I18N.t('admin_btn_discover_ca', '🔍 Rileva CA') : '🔍 Rileva CA';
        }
      });

      // CA toggle change handlers
      card.querySelectorAll('.ca-toggle').forEach(input => {
        input.addEventListener('change', (e) => {
          const ci = parseInt(e.target.dataset.ca);
          const field = e.target.dataset.field;
          const cas = portalConfig.cas || portalConfig.CAs || [];
          cas[ci][field] = e.target.checked;
        });
      });

      // Popola la tendina con i nomi CA rilevati precedentemente per questa CA (se presenti)
      populateDiscoveredCaDropdown(card, ca, caIndex);

      // Popola la tendina con i template scoperti precedentemente per questa CA (se presenti)
      populateDiscoveredDropdown(card, ca, caIndex);

      // Discover templates from CA handler
      card.querySelector('.btn-discover-templates').addEventListener('click', async (e) => {
        const btn = e.target.closest('.btn-discover-templates');
        const ci = parseInt(btn.dataset.ca);
        const cas = portalConfig.cas || portalConfig.CAs || [];
        const caObj = cas[ci];
        const cardEl = btn.closest('.ca-card');

        // Sincronizza i valori correnti presenti nei campi della scheda
        const idVal = cardEl.querySelector('.ca-field[data-field="id"]')?.value?.trim() || caObj.id || caObj.Id || '';
        const cfgStrVal = cardEl.querySelector('.ca-field[data-field="configString"]')?.value?.trim() || caObj.configString || caObj.ConfigString || '';
        const authModeVal = cardEl.querySelector('.ca-field[data-field="authMode"]')?.value || caObj.authMode || caObj.AuthMode || 'LocalIdentity';
        const credTargetVal = cardEl.querySelector('.ca-field[data-field="credentialTarget"]')?.value?.trim() || caObj.credentialTarget || caObj.CredentialTarget || '';
        const useSimVal = cardEl.querySelector('.ca-toggle[data-field="useSimulator"]')?.checked ?? (caObj.useSimulator || caObj.UseSimulator || false);

        caObj.id = idVal;
        caObj.configString = cfgStrVal;
        caObj.authMode = authModeVal;
        caObj.credentialTarget = credTargetVal;
        caObj.useSimulator = useSimVal;

        if (!useSimVal && !cfgStrVal) {
          showToast('Config String non impostata. Inserisci la stringa di connessione (es. server\\Nome-CA).', 'error');
          return;
        }

        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-sm"></span> Interrogazione...';

        try {
          const resp = await fetch('/api/admin/templates/discover', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Pki-Portal-Admin': await ensureCsrfToken() },
            body: JSON.stringify({
              caId: idVal,
              configString: cfgStrVal,
              authMode: authModeVal,
              credentialTarget: credTargetVal,
              useSimulator: useSimVal
            })
          });

          if (!resp.ok) throw new Error('Errore HTTP ' + resp.status);
          const result = await resp.json();
          const templates = Array.isArray(result) ? result : (result.templates || []);
          const isSuccess = Array.isArray(result) ? templates.length > 0 : (result.success ?? (templates.length > 0));
          const errorMsg = Array.isArray(result) ? null : result.errorMessage;

          if (!templates || templates.length === 0) {
            caObj.discoveredTemplates = [];
            populateDiscoveredDropdown(cardEl, caObj, ci);
            showToast(errorMsg || 'Nessun template pubblicato trovato sulla CA.', 'error');
          } else {
            caObj.discoveredTemplates = templates;
            populateDiscoveredDropdown(cardEl, caObj, ci);
            showToast(`${templates.length} template pubblicati trovati sulla CA.`, 'success');
          }
        } catch (err) {
          showToast('Errore durante la scoperta: ' + err.message, 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = '🔍 Scopri dalla CA';
        }
      });

      // Add discovered template handler
      card.querySelector('.btn-add-discovered').addEventListener('click', () => {
        const ci = caIndex;
        const select = card.querySelector(`.discovered-templates-select[data-ca="${ci}"]`);
        const selectedOpt = select.options[select.selectedIndex];
        if (!select.value) {
          showToast('Seleziona un template dalla tendina.', 'error');
          return;
        }

        const cas = portalConfig.cas || portalConfig.CAs || [];
        const templates = cas[ci].templates || cas[ci].Templates || [];
        // La validità NON viene scelta dall'admin: è letta dalla definizione
        // AD CS del template (KeyUsagePeriod) durante la scoperta "Scopri dalla CA".
        // Se non è stata rilevata resta null (mostrata come "n.d."), senza
        // inventare un valore di default.
        const validityDays = parseInt(selectedOpt.dataset.validityDays, 10) || null;
        templates.push({
          name: select.value,
          displayName: selectedOpt.dataset.displayName || select.value,
          description: '',
          requiresApproval: false,
          storePrivateKeyForRetrieval: true,
          validityDays: validityDays,
          allowedKeyTypes: ['RSA-2048', 'RSA-4096'],
          keyUsages: ['DigitalSignature', 'KeyEncipherment'],
          extendedKeyUsages: ['ServerAuthentication'],
          allowedGroups: []
        });
        if (!cas[ci].templates) cas[ci].templates = templates;
        const validityInfo = validityDays != null
          ? `validità ${validityDays} giorni, dalla definizione del template`
          : 'validità non rilevata: riprovare con "Scopri dalla CA"';
        showToast(`Template "${selectedOpt.dataset.displayName || select.value}" aggiunto (${validityInfo}).`, 'success');
        renderCaList();
      });

      // Manual add template handler
      card.querySelector('.btn-add-template-manual').addEventListener('click', () => {
        const cas = portalConfig.cas || portalConfig.CAs || [];
        const templates = cas[caIndex].templates || cas[caIndex].Templates || [];
        templates.push({
          name: '', displayName: 'Nuovo Template', description: '',
          requiresApproval: false, storePrivateKeyForRetrieval: true, validityDays: null,
          allowedKeyTypes: ['RSA-2048', 'RSA-4096'],
          keyUsages: ['DigitalSignature', 'KeyEncipherment'],
          extendedKeyUsages: ['ServerAuthentication'],
          allowedGroups: []
        });
        if (!cas[caIndex].templates) cas[caIndex].templates = templates;
        renderCaList();
      });

      // Render templates
      const tmplContainer = card.querySelector(`.templates-container[data-ca="${caIndex}"]`);
      const templates = ca.templates || ca.Templates || [];
      templates.forEach((tmpl, tIdx) => renderTemplateItem(tmplContainer, tmpl, caIndex, tIdx));
    }

    function renderTemplateItem(container, tmpl, caIndex, tIdx) {
      const tmplEl = document.createElement('div');
      tmplEl.className = 'template-item';

      const name = tmpl.name || tmpl.Name || '';
      const displayName = tmpl.displayName || tmpl.DisplayName || '';
      const description = tmpl.description || tmpl.Description || '';
      // null = validità non rilevata dalla CA: mostrata come "n.d.", non
      // come un valore di default fittizio.
      const validityDays = tmpl.validityDays || tmpl.ValidityDays || null;
      const validityUndetected = window.I18N ? window.I18N.t('validity_undetected', 'n.d. (non rilevata)') : 'n.d. (non rilevata)';
      const requiresApproval = tmpl.requiresApproval || tmpl.RequiresApproval || false;
      const storePrivateKeyForRetrieval = tmpl.storePrivateKeyForRetrieval !== undefined ? tmpl.storePrivateKeyForRetrieval : (tmpl.StorePrivateKeyForRetrieval !== undefined ? tmpl.StorePrivateKeyForRetrieval : true);
      const allowedKeyTypes = (tmpl.allowedKeyTypes || tmpl.AllowedKeyTypes || []).join(', ');
      const keyUsages = (tmpl.keyUsages || tmpl.KeyUsages || []).join(', ');
      const extendedKeyUsages = (tmpl.extendedKeyUsages || tmpl.ExtendedKeyUsages || []).join(', ');
      const allowedGroups = (tmpl.allowedGroups || tmpl.AllowedGroups || []).join(', ');

      const newTmplTitle = window.I18N ? window.I18N.t('admin_new_template', 'Nuovo Template') : 'Nuovo Template';
      const lblSysName = window.I18N ? window.I18N.t('admin_lbl_sys_name', 'Nome Sistema') : 'Nome Sistema';
      const lblDispName = window.I18N ? window.I18N.t('admin_lbl_display_name', 'Nome Visualizzato') : 'Nome Visualizzato';
      const lblDesc = window.I18N ? window.I18N.t('admin_lbl_description', 'Descrizione') : 'Descrizione';
      const lblValidity = window.I18N ? window.I18N.t('admin_lbl_validity', 'Validità (giorni)') : 'Validità (giorni)';
      const validityNote = window.I18N ? window.I18N.t('admin_validity_note', 'Prelevata dalla definizione del template AD CS (KeyUsagePeriod); non modificabile manualmente. Aggiorna il valore con "Scopri dalla CA".') : 'Prelevata dalla definizione del template AD CS (KeyUsagePeriod); non modificabile manualmente. Aggiorna il valore con "Scopri dalla CA".';
      const lblManualAppr = window.I18N ? window.I18N.t('admin_lbl_manual_approval', 'Approvazione Manuale') : 'Approvazione Manuale';
      const lblStoreKey = window.I18N ? window.I18N.t('admin_lbl_store_key_pfx', 'Archivia Chiave per Ritiro PFX') : 'Archivia Chiave per Ritiro PFX';
      const hintStoreKey = window.I18N ? window.I18N.t('admin_hint_store_key_pfx', 'Se attivo (default), la chiave privata viene memorizzata cifrata a riposo (DPAPI/AES-GCM) per consentire il recupero del pacchetto .pfx anche successivamente.') : 'Se attivo (default), la chiave privata viene memorizzata cifrata a riposo (DPAPI/AES-GCM) per consentire il recupero del pacchetto .pfx anche successivamente.';
      const lblKeyTypes = window.I18N ? window.I18N.t('admin_lbl_key_types', 'Tipi Chiave') : 'Tipi Chiave';
      const lblAllowedGroups = window.I18N ? window.I18N.t('admin_lbl_allowed_groups', 'Gruppi AD Autorizzati') : 'Gruppi AD Autorizzati';
      const phAllowedGroups = window.I18N ? window.I18N.t('admin_allowed_groups_placeholder', 'Vuoto = tutti gli utenti (es. VD\\Web-Team, LD\\App-Admin)') : 'Vuoto = tutti gli utenti (es. VD\\Web-Team, LD\\App-Admin)';
      const hintAllowedGroups = window.I18N ? window.I18N.t('admin_allowed_groups_hint', 'Solo gli utenti di questi gruppi possono emettere con questo template (gli amministratori del portale sono sempre ammessi).') : 'Solo gli utenti di questi gruppi possono emettere con questo template (gli amministratori del portale sono sempre ammessi).';

      tmplEl.innerHTML = `
        <div class="template-item-header">
          <h5>${esc(displayName || name || newTmplTitle)}</h5>
          <button type="button" class="btn btn-danger btn-sm btn-remove-tmpl" data-ca="${caIndex}" data-tmpl="${tIdx}">✕</button>
        </div>
        <div class="field-row">
          <label>${escapeHtml(lblSysName)}</label>
          <input type="text" class="form-control tmpl-field" data-ca="${caIndex}" data-tmpl="${tIdx}" data-field="name" value="${esc(name)}">
        </div>
        <div class="field-row">
          <label>${escapeHtml(lblDispName)}</label>
          <input type="text" class="form-control tmpl-field" data-ca="${caIndex}" data-tmpl="${tIdx}" data-field="displayName" value="${esc(displayName)}">
        </div>
        <div class="field-row">
          <label>${escapeHtml(lblDesc)}</label>
          <input type="text" class="form-control tmpl-field" data-ca="${caIndex}" data-tmpl="${tIdx}" data-field="description" value="${esc(description)}">
        </div>
        <div class="field-row">
          <label>${escapeHtml(lblValidity)}</label>
          <input type="text" class="form-control" value="${validityDays != null ? validityDays : escapeHtml(validityUndetected)}" disabled>
          <small style="display:block; margin-top:0.25rem; opacity:0.7;">${escapeHtml(validityNote)}</small>
        </div>
        <div class="field-row">
          <label>${escapeHtml(lblManualAppr)}</label>
          <label class="toggle-switch">
            <input type="checkbox" class="tmpl-toggle" data-ca="${caIndex}" data-tmpl="${tIdx}" data-field="requiresApproval" ${requiresApproval ? 'checked' : ''}>
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="field-row">
          <label>${escapeHtml(lblStoreKey)}</label>
          <label class="toggle-switch">
            <input type="checkbox" class="tmpl-toggle" data-ca="${caIndex}" data-tmpl="${tIdx}" data-field="storePrivateKeyForRetrieval" ${storePrivateKeyForRetrieval ? 'checked' : ''}>
            <span class="toggle-slider"></span>
          </label>
          <small style="display:block; margin-top:0.25rem; opacity:0.7;">${escapeHtml(hintStoreKey)}</small>
        </div>
        <div class="field-row">
          <label>${escapeHtml(lblKeyTypes)}</label>
          <input type="text" class="form-control tmpl-array-field" data-ca="${caIndex}" data-tmpl="${tIdx}" data-field="allowedKeyTypes" value="${esc(allowedKeyTypes)}" placeholder="RSA-2048, RSA-4096, ECDSA-P256">
        </div>
        <div class="field-row">
          <label>Key Usages</label>
          <input type="text" class="form-control tmpl-array-field" data-ca="${caIndex}" data-tmpl="${tIdx}" data-field="keyUsages" value="${esc(keyUsages)}" placeholder="DigitalSignature, KeyEncipherment">
        </div>
        <div class="field-row">
          <label>Extended Key Usages</label>
          <input type="text" class="form-control tmpl-array-field" data-ca="${caIndex}" data-tmpl="${tIdx}" data-field="extendedKeyUsages" value="${esc(extendedKeyUsages)}" placeholder="ServerAuthentication">
        </div>
        <div class="field-row">
          <label>${escapeHtml(lblAllowedGroups)}</label>
          <input type="text" class="form-control tmpl-array-field" data-ca="${caIndex}" data-tmpl="${tIdx}" data-field="allowedGroups" value="${esc(allowedGroups)}" placeholder="${escapeHtml(phAllowedGroups)}">
          <small style="display:block; margin-top:0.25rem; opacity:0.7;">${escapeHtml(hintAllowedGroups)}</small>
        </div>
      `;
      container.appendChild(tmplEl);

      // Remove template handler
      tmplEl.querySelector('.btn-remove-tmpl').addEventListener('click', () => {
        const confirmMsg = window.I18N ? window.I18N.t('confirm_remove_template', 'Rimuovere questo template?') : 'Rimuovere questo template?';
        if (!confirm(confirmMsg)) return;
        const cas = portalConfig.cas || portalConfig.CAs || [];
        const templates = cas[caIndex].templates || cas[caIndex].Templates || [];
        templates.splice(tIdx, 1);
        renderCaList();
      });

      // Template field change handlers
      tmplEl.querySelectorAll('.tmpl-field').forEach(input => {
        input.addEventListener('change', (e) => {
          const ci = parseInt(e.target.dataset.ca);
          const ti = parseInt(e.target.dataset.tmpl);
          const field = e.target.dataset.field;
          const cas = portalConfig.cas || portalConfig.CAs || [];
          const templates = cas[ci].templates || cas[ci].Templates || [];
          templates[ti][field] = e.target.value;

          // Sincronizza la validità dalla definizione AD CS del template:
          // se il nome di sistema corrisponde a un template scoperto dalla CA,
          // la validità (KeyUsagePeriod) viene presa direttamente da lì.
          if (field === 'name') {
            const ca = cas[ci];
            const discovered = (ca.discoveredTemplates || []).find(d =>
              (d.name || '').toLowerCase() === String(e.target.value).trim().toLowerCase());
            if (discovered) {
              const v = parseInt(discovered.validityDays || discovered.ValidityDays, 10);
              if (v) {
                templates[ti].validityDays = v;
                renderCaList();
                showToast(`Validità sincronizzata dalla definizione del template: ${v} giorni.`, 'success');
              }
            }
          }
        });
      });

      // Template toggle handlers
      tmplEl.querySelectorAll('.tmpl-toggle').forEach(input => {
        input.addEventListener('change', (e) => {
          const ci = parseInt(e.target.dataset.ca);
          const ti = parseInt(e.target.dataset.tmpl);
          const field = e.target.dataset.field;
          const cas = portalConfig.cas || portalConfig.CAs || [];
          const templates = cas[ci].templates || cas[ci].Templates || [];
          templates[ti][field] = e.target.checked;
        });
      });

      // Template array field handlers (comma-separated)
      tmplEl.querySelectorAll('.tmpl-array-field').forEach(input => {
        input.addEventListener('change', (e) => {
          const ci = parseInt(e.target.dataset.ca);
          const ti = parseInt(e.target.dataset.tmpl);
          const field = e.target.dataset.field;
          const cas = portalConfig.cas || portalConfig.CAs || [];
          const templates = cas[ci].templates || cas[ci].Templates || [];
          templates[ti][field] = e.target.value.split(',').map(s => s.trim()).filter(s => s);
        });
      });
    }
    function populateDiscoveredDropdown(cardEl, caObj, ci) {
      const select = cardEl.querySelector(`.discovered-templates-select[data-ca="${ci}"]`);
      const addBtn = cardEl.querySelector(`.btn-add-discovered[data-ca="${ci}"]`);
      if (!select || !addBtn) return;

      const discovered = caObj.discoveredTemplates || [];
      if (discovered.length === 0) {
        select.innerHTML = '<option value="">— Clicca "Scopri dalla CA" —</option>';
        select.disabled = true;
        addBtn.disabled = true;
        return;
      }

      // Filtra template già configurati
      const existingNames = (caObj.templates || caObj.Templates || []).map(t => (t.name || t.Name || '').toLowerCase());
      const available = discovered.filter(t => !existingNames.includes((t.name || '').toLowerCase()));

      select.innerHTML = '';
      if (available.length === 0) {
        select.innerHTML = '<option value="">Tutti i template sono già configurati</option>';
        select.disabled = true;
        addBtn.disabled = true;
      } else {
        select.innerHTML = '<option value="">— Seleziona un template —</option>';
        available.forEach(t => {
          const opt = document.createElement('option');
          opt.value = t.name;
          const validity = parseInt(t.validityDays || t.ValidityDays, 10);
          opt.textContent = `${t.displayName || t.name} (${t.name})` + (validity ? ` — validità ${validity} gg` : '');
          opt.dataset.displayName = t.displayName || t.name;
          opt.dataset.validityDays = validity || '';
          select.appendChild(opt);
        });
        select.disabled = false;
        addBtn.disabled = false;
      }
    }

    // Ricostruisce i campi derivati della scheda CA:
    //  - Config String = "server\Nome-CA"
    //  - Credential Target = server CA (target nel Windows Credential Manager)
    function syncDerivedCaFields(cardEl, ci) {
      if (!cardEl) return;
      const cas = portalConfig.cas || portalConfig.CAs || [];
      const caObj = cas[ci];
      const server = (cardEl.querySelector('.ca-field[data-field="caServer"]')?.value || '').trim();
      const name = (cardEl.querySelector('.ca-field[data-field="caName"]')?.value || '').trim();

      const cfgEl = cardEl.querySelector('.ca-field[data-field="configString"]');
      const cfgVal = (server && name) ? `${server}\\${name}` : (server || name || '');
      if (cfgEl) cfgEl.value = cfgVal;
      caObj.configString = cfgVal;

      const credEl = cardEl.querySelector('.ca-field[data-field="credentialTarget"]');
      if (credEl) credEl.value = server;
      caObj.credentialTarget = server || null;
    }

    // Popola la tendina del Nome CA con i nomi rilevati (e il valore corrente,
    // se non presente nella lista). Se il rilevamento trova un solo nome, lo
    // seleziona automaticamente.
    function populateDiscoveredCaDropdown(cardEl, caObj, ci) {
      const select = cardEl.querySelector('.ca-field[data-field="caName"]');
      if (!select) return;

      const current = (caObj.caName || '').trim();
      const placeholder = window.I18N ? window.I18N.t('admin_ca_select_placeholder', '— seleziona un nome CA —') : '— seleziona un nome CA —';

      // Deduplica case-insensitive preservando la forma originale del nome
      const seen = new Set();
      const opts = [];
      for (const raw of [...(caObj.discoveredCaNames || []), current]) {
        const n = String(raw || '').trim();
        if (!n) continue;
        const key = n.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        opts.push(n);
      }

      select.innerHTML = '';
      const phOpt = document.createElement('option');
      phOpt.value = '';
      phOpt.textContent = placeholder;
      select.appendChild(phOpt);
      opts.forEach(n => {
        const o = document.createElement('option');
        o.value = n;
        o.textContent = n;
        select.appendChild(o);
      });

      const currentIdx = opts.findIndex(n => n.toLowerCase() === current.toLowerCase());
      if (currentIdx !== -1) {
        select.value = current;
      } else if (opts.length === 1) {
        // Un solo nome rilevato: selezione automatica
        select.value = opts[0];
      } else {
        select.value = '';
      }

      caObj.caName = select.value;
      syncDerivedCaFields(cardEl, ci);
    }

    function addNewCa() {
      const cas = portalConfig.cas || portalConfig.CAs || [];
      cas.push({
        id: 'ca-nuova-' + (cas.length + 1),
        displayName: 'Nuova Certificate Authority',
        forestOrDomain: '',
        caServer: '',
        caName: '',
        discoveredCaNames: [],
        configString: '',
        isDefault: false,
        useSimulator: true,
        description: '',
        authMode: 'LocalIdentity',
        credentialTarget: '',
        templates: []
      });
      // Ensure the property reference exists
      if (!portalConfig.cas && !portalConfig.CAs) portalConfig.cas = cas;
      renderCaList();
    }

    async function saveConfig() {
      // Build config object with PascalCase properties for C# deserialization
      const cas = portalConfig.cas || portalConfig.CAs || [];
      const configToSave = {
        PortalTitle: document.getElementById('cfg-title').value,
        PortalMode: document.getElementById('cfg-mode').value,
        DefaultCaId: document.getElementById('cfg-default-ca').value,
        CAs: cas.map(ca => {
          // Config String e Credential Target sono campi derivati:
          //  - ConfigString = "ServerCA\NomeCA" (costruita dai due campi)
          //  - CredentialTarget = ServerCA (target nel Windows Credential Manager)
          const server = String(ca.caServer || '').trim();
          const name = String(ca.caName || '').trim();
          let configString = ca.configString || ca.ConfigString || '';
          if (server && name) configString = `${server}\\${name}`;
          else if (server) configString = server;
          return {
            Id: ca.id || ca.Id || '',
            DisplayName: ca.displayName || ca.DisplayName || '',
            ForestOrDomain: ca.forestOrDomain || ca.ForestOrDomain || '',
            ConfigString: configString,
            IsDefault: ca.isDefault || ca.IsDefault || false,
            UseSimulator: ca.useSimulator || ca.UseSimulator || false,
            Description: ca.description || ca.Description || '',
            AuthMode: ca.authMode || ca.AuthMode || 'LocalIdentity',
            CredentialTarget: server || null,
            Templates: (ca.templates || ca.Templates || []).map(t => ({
              Name: t.name || t.Name || '',
              DisplayName: t.displayName || t.DisplayName || '',
              Description: t.description || t.Description || '',
              RequiresApproval: t.requiresApproval || t.RequiresApproval || false,
              StorePrivateKeyForRetrieval: t.storePrivateKeyForRetrieval !== undefined ? t.storePrivateKeyForRetrieval : (t.StorePrivateKeyForRetrieval !== undefined ? t.StorePrivateKeyForRetrieval : true),
              // null se non rilevata: non persistere mai un default fittizio
              ValidityDays: t.validityDays || t.ValidityDays || null,
              AllowedKeyTypes: t.allowedKeyTypes || t.AllowedKeyTypes || [],
              KeyUsages: t.keyUsages || t.KeyUsages || [],
              ExtendedKeyUsages: t.extendedKeyUsages || t.ExtendedKeyUsages || [],
              AllowedGroups: t.allowedGroups || t.AllowedGroups || []
            }))
          };
        })
      };

      try {
        const resp = await fetch('/api/admin/config', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'X-Pki-Portal-Admin': await ensureCsrfToken() },
          body: JSON.stringify(configToSave)
        });
        const result = await resp.json();
        if (resp.ok && result.success) {
          showToast(result.message || 'Configurazione salvata!', 'success');
        } else {
          showToast('Errore: ' + (result.message || result.detail || 'Salvataggio fallito'), 'error');
        }
      } catch (err) {
        showToast('Errore di rete: ' + err.message, 'error');
      }
    }

    // ===== Gestione Tab e Richieste Trattenute =====
    function setupTabs() {
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
          document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
          btn.classList.add('active');
          const targetPane = document.getElementById(btn.getAttribute('data-tab'));
          if (targetPane) targetPane.classList.add('active');
          if (btn.getAttribute('data-tab') === 'pane-requests') {
            loadHeldRequests();
          }
          if (btn.getAttribute('data-tab') === 'pane-acme' && !acmeConfig) {
            loadAcmeConfig();
          }
        });
      });
    }

    let cachedAdminRequests = [];
    let adminFiltersBound = false;

    function setupHeldRequestsHandlers() {
      if (adminFiltersBound) return;
      const statusSelect = document.getElementById('filter-held-status');
      if (statusSelect) {
        statusSelect.addEventListener('change', loadHeldRequests);
      }
      const refreshBtn = document.getElementById('btn-refresh-requests');
      if (refreshBtn) {
        refreshBtn.addEventListener('click', loadHeldRequests);
      }
      const searchInput = document.getElementById('filter-held-search');
      if (searchInput) {
        searchInput.addEventListener('input', applyAndRenderAdminHeldRequests);
      }
      const userSelect = document.getElementById('filter-held-user');
      if (userSelect) {
        userSelect.addEventListener('change', applyAndRenderAdminHeldRequests);
      }
      const tplSelect = document.getElementById('filter-held-template');
      if (tplSelect) {
        tplSelect.addEventListener('change', applyAndRenderAdminHeldRequests);
      }
      const clearBtn = document.getElementById('btn-clear-held-filters');
      if (clearBtn) {
        clearBtn.addEventListener('click', () => {
          if (searchInput) searchInput.value = '';
          if (userSelect) userSelect.value = '';
          if (tplSelect) tplSelect.value = '';
          applyAndRenderAdminHeldRequests();
        });
      }
      adminFiltersBound = true;
    }

    function populateAdminFilterOptions(requests) {
      const userSelect = document.getElementById('filter-held-user');
      const tplSelect = document.getElementById('filter-held-template');
      if (!userSelect || !tplSelect) return;

      const prevUser = userSelect.value;
      const prevTpl = tplSelect.value;

      const allReqLabel = window.I18N ? window.I18N.t('filter_all_requesters', 'Tutti i richiedenti') : 'Tutti i richiedenti';
      const allTplLabel = window.I18N ? window.I18N.t('filter_all_templates', 'Tutti i template') : 'Tutti i template';
      const acmeOnlyLabel = window.I18N ? window.I18N.t('filter_acme_only', '⚡ Solo ACME (tutti)') : '⚡ Solo ACME (tutti)';

      const userSet = new Set();
      let hasAcme = false;
      requests.forEach(r => {
        const u = (r.requesterUser || r.RequesterUser || '').trim();
        const comments = (r.requesterComments || r.RequesterComments || '');
        if (u) {
          if (u.startsWith('ACME')) hasAcme = true;
          userSet.add(u);
        } else if (comments.startsWith('ACME')) {
          hasAcme = true;
          userSet.add('ACME');
        }
      });

      const sortedUsers = Array.from(userSet).sort((a, b) => a.localeCompare(b));
      let userOptionsHtml = `<option value="">${escapeHtml(allReqLabel)}</option>`;
      if (hasAcme) {
        userOptionsHtml += `<option value="__acme__">${escapeHtml(acmeOnlyLabel)}</option>`;
      }
      sortedUsers.forEach(u => {
        userOptionsHtml += `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`;
      });
      userSelect.innerHTML = userOptionsHtml;
      if (prevUser && (sortedUsers.includes(prevUser) || prevUser === '__acme__')) {
        userSelect.value = prevUser;
      }

      const tplSet = new Set();
      requests.forEach(r => {
        const t = (r.templateDisplayName || r.TemplateDisplayName || r.templateName || r.TemplateName || '').trim();
        if (t) tplSet.add(t);
      });
      const sortedTpls = Array.from(tplSet).sort((a, b) => a.localeCompare(b));
      let tplOptionsHtml = `<option value="">${escapeHtml(allTplLabel)}</option>`;
      sortedTpls.forEach(t => {
        tplOptionsHtml += `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`;
      });
      tplSelect.innerHTML = tplOptionsHtml;
      if (prevTpl && sortedTpls.includes(prevTpl)) {
        tplSelect.value = prevTpl;
      }
    }

    function applyAndRenderAdminHeldRequests() {
      const searchVal = (document.getElementById('filter-held-search')?.value || '').trim().toLowerCase();
      const userVal = (document.getElementById('filter-held-user')?.value || '').trim();
      const tplVal = (document.getElementById('filter-held-template')?.value || '').trim().toLowerCase();
      const counterEl = document.getElementById('filter-held-counter');

      const filtered = cachedAdminRequests.filter(r => {
        const reqUser = (r.requesterUser || r.RequesterUser || '').trim();
        const comments = (r.requesterComments || r.RequesterComments || '');
        const isAcme = reqUser.startsWith('ACME') || (!reqUser && comments.startsWith('ACME'));
        const effectiveUser = reqUser || (isAcme ? 'ACME' : '');
        const tplName = (r.templateName || r.TemplateName || '').toLowerCase();
        const tplDisplay = (r.templateDisplayName || r.TemplateDisplayName || '').toLowerCase();
        const cn = (r.subjectCommonName || r.SubjectCommonName || '').toLowerCase();
        const ca = (r.caId || r.CaId || '').toLowerCase();
        const reqId = String(r.caRequestId || r.CaRequestId || '');
        const holdId = (r.holdId || r.HoldId || '').toLowerCase();

        if (userVal) {
          if (userVal === '__acme__') {
            if (!isAcme) return false;
          } else if (effectiveUser !== userVal) {
            return false;
          }
        }

        if (tplVal) {
          if (tplName !== tplVal && tplDisplay !== tplVal) return false;
        }

        if (searchVal) {
          const matches = cn.includes(searchVal) ||
            effectiveUser.toLowerCase().includes(searchVal) ||
            tplName.includes(searchVal) ||
            tplDisplay.includes(searchVal) ||
            ca.includes(searchVal) ||
            reqId.includes(searchVal) ||
            holdId.includes(searchVal);
          if (!matches) return false;
        }

        return true;
      });

      if (counterEl) {
        if (window.I18N) {
          counterEl.textContent = window.I18N.t('filter_counter_format', null, { shown: filtered.length, total: cachedAdminRequests.length });
        } else {
          counterEl.textContent = `Mostrate ${filtered.length} su ${cachedAdminRequests.length} richieste`;
        }
      }

      renderHeldRequests(filtered);
    }

    async function updatePendingBadge() {
      try {
        const resp = await fetch('/api/admin/held-requests?status=pending');
        if (resp.ok) {
          const data = await resp.json();
          const count = data.count !== undefined ? data.count : (data.requests ? data.requests.length : 0);
          const badge = document.getElementById('badge-pending-count');
          if (badge) {
            badge.textContent = count;
            badge.className = 'tab-badge' + (count === 0 ? ' zero' : '');
          }
        }
      } catch (e) {
        console.warn('Errore aggiornamento badge:', e);
      }
    }

    async function loadHeldRequests() {
      const filter = document.getElementById('filter-held-status')?.value || 'pending';
      const container = document.getElementById('held-requests-container');
      if (!container) return;

      setupHeldRequestsHandlers();
      container.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--gray-500);"><div class="spinner-sm"></div> Caricamento richieste in corso...</div>';

      try {
        const resp = await fetch(`/api/admin/held-requests?status=${encodeURIComponent(filter)}`);
        if (!resp.ok) {
          throw new Error(`Errore HTTP ${resp.status}`);
        }
        const data = await resp.json();
        updatePendingBadge();
        cachedAdminRequests = data.requests || [];
        populateAdminFilterOptions(cachedAdminRequests);
        applyAndRenderAdminHeldRequests();
      } catch (err) {
        container.innerHTML = `<div class="alert alert-danger">Impossibile caricare le richieste trattenute: ${esc(err.message)}</div>`;
      }
    }

    function renderHeldRequests(requests) {
      const container = document.getElementById('held-requests-container');
      if (!container) return;

      const noReqTitle = window.I18N ? window.I18N.t('admin_no_requests_found', 'Nessuna richiesta trovata') : 'Nessuna richiesta trovata';
      const noReqDesc = window.I18N ? window.I18N.t('admin_no_requests_desc', 'Non ci sono certificati trattenuti con il filtro selezionato.') : 'Non ci sono certificati trattenuti con il filtro selezionato.';

      if (!requests || requests.length === 0) {
        container.innerHTML = `
          <div class="card" style="text-align:center; padding: 2.5rem; color: var(--gray-500);">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom:0.75rem; opacity:0.6;"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
            <p style="font-size:1rem; font-weight:600; color:var(--gray-700);">${escapeHtml(noReqTitle)}</p>
            <p style="font-size:0.85rem;">${escapeHtml(noReqDesc)}</p>
          </div>
        `;
        return;
      }

      const dateLocale = window.I18N ? window.I18N.getLocale() : 'it-IT';
      const lblSubmitted = window.I18N ? window.I18N.t('admin_submitted_label', 'Sottomesso:') : 'Sottomesso:';
      const lblRequester = window.I18N ? window.I18N.t('requester_label', 'Richiedente:') : 'Richiedente:';
      const lblAnon = window.I18N ? window.I18N.t('admin_anon_unauth', 'Anonimo / Non autenticato') : 'Anonimo / Non autenticato';
      const lblReqNotes = window.I18N ? window.I18N.t('admin_requester_notes', 'Note Richiedente:') : 'Note Richiedente:';
      const lblReviewed = window.I18N ? window.I18N.t('admin_reviewed_label', 'Revisionato:') : 'Revisionato:';
      const lblBy = window.I18N ? window.I18N.t('admin_by_label', 'da') : 'da';
      const lblRejectionReason = window.I18N ? window.I18N.t('admin_rejection_reason_label', 'Motivo Rifiuto:') : 'Motivo Rifiuto:';
      const btnRejectText = window.I18N ? window.I18N.t('admin_btn_reject_req', '❌ Rifiuta Richiesta') : '❌ Rifiuta Richiesta';
      const btnApproveText = window.I18N ? window.I18N.t('admin_btn_approve_req', '✅ Approva & Rilascia Certificato') : '✅ Approva & Rilascia Certificato';
      const btnViewCertText = window.I18N ? window.I18N.t('btn_view_cert', 'Visualizza Certificato') : 'Visualizza Certificato';
      const pendingCaHint = window.I18N ? window.I18N.t('admin_pending_ca_hint', 'In attesa di approvazione sulla CA ADCS') : 'In attesa di approvazione sulla CA ADCS';

      container.innerHTML = '';
      requests.forEach(r => {
        const card = document.createElement('div');
        card.className = 'held-card';

        const status = r.status || r.Status || '';
        const holdId = r.holdId || r.HoldId || '';
        const templateDisplayName = r.templateDisplayName || r.TemplateDisplayName || '';
        const templateName = r.templateName || r.TemplateName || '';
        const requesterUser = r.requesterUser || r.RequesterUser || '';
        const subjectCommonName = r.subjectCommonName || r.SubjectCommonName || '';
        const caId = r.caId || r.CaId || '';
        const caRequestId = r.caRequestId || r.CaRequestId || '';
        const sanAttribute = r.sanAttribute || r.SanAttribute || '';
        const requesterComments = r.requesterComments || r.RequesterComments || '';
        const reviewedBy = r.reviewedBy || r.ReviewedBy || '';
        const rejectionReason = r.rejectionReason || r.RejectionReason || '';
        const submittedAt = r.submittedAt || r.SubmittedAt;
        const reviewedAt = r.reviewedAt || r.ReviewedAt;

        let statusClass = 'status-pending';
        let statusLabel = window.I18N ? window.I18N.t('status_pending', 'In Attesa') : 'In Attesa';

        if (status === 'PendingApproval') {
          statusClass = 'status-pending';
          statusLabel = window.I18N ? window.I18N.t('status_pending', 'In Attesa Approvazione') : 'In Attesa Approvazione';
        } else if (status === 'UnderSubmission') {
          statusClass = 'status-pending';
          statusLabel = window.I18N ? window.I18N.t('status_under_submission', 'In Sospeso (CA)') : 'In Sospeso (CA)';
        } else if (status === 'Approved') {
          statusClass = 'status-approved';
          statusLabel = window.I18N ? window.I18N.t('status_issued', 'Approvato') : 'Approvato';
        } else if (status === 'Issued') {
          statusClass = 'status-approved';
          statusLabel = window.I18N ? window.I18N.t('status_issued', 'Emesso') : 'Emesso';
        } else if (status === 'Rejected') {
          statusClass = 'status-rejected';
          statusLabel = window.I18N ? window.I18N.t('status_rejected', 'Rifiutato') : 'Rifiutato';
        } else {
          statusClass = 'status-pending';
          statusLabel = esc(status);
        }

        const submittedDate = submittedAt ? new Date(submittedAt).toLocaleString(dateLocale) : '-';
        const reviewedDate = reviewedAt ? new Date(reviewedAt).toLocaleString(dateLocale) : null;

        const reqUser = (requesterUser || '').trim();
        const isAcme = reqUser.startsWith('ACME') || (!reqUser && requesterComments && requesterComments.startsWith('ACME'));
        let reqDisplayHtml;
        if (isAcme) {
          const acmeText = reqUser || 'ACME';
          reqDisplayHtml = `<span class="badge" style="display:inline-flex; align-items:center; gap:0.3rem; background:rgba(6, 182, 212, 0.15); color:#0891b2; border:1px solid rgba(6, 182, 212, 0.35); padding:0.18rem 0.5rem; border-radius:4px; font-weight:600; font-size:0.8rem;" title="Certificato emesso via protocollo ACME RFC 8555">⚡ ${esc(acmeText)}</span>`;
        } else {
          reqDisplayHtml = esc(reqUser || lblAnon);
        }

        const certBoxId = `cert-box-${esc(holdId)}`;

        card.innerHTML = `
          <div class="held-header">
            <div>
              <span class="status-badge ${statusClass}">${statusLabel}</span>
              <strong style="margin-left: 0.5rem; font-size: 1rem; color: var(--gray-900);">${esc(templateDisplayName || templateName || 'Template')}</strong>
              <span style="font-size:0.8rem; color:var(--gray-500); margin-left:0.5rem;">(Hold ID: <code>${esc(holdId)}</code>)</span>
            </div>
            <div style="font-size:0.8rem; color:var(--gray-500);">
              ${escapeHtml(lblSubmitted)} <strong>${submittedDate}</strong>
            </div>
          </div>

          <div class="held-details">
            <div><strong>${escapeHtml(lblRequester)}</strong> ${reqDisplayHtml}</div>
            <div><strong>Common Name (CN):</strong> ${esc(subjectCommonName || 'N/D')}</div>
            <div><strong>CA Target:</strong> ${esc(caId)} (Req #${esc(caRequestId)})</div>
            ${sanAttribute ? `<div><strong>SAN:</strong> ${esc(sanAttribute)}</div>` : ''}
            ${requesterComments ? `<div><strong>${escapeHtml(lblReqNotes)}</strong> ${esc(requesterComments)}</div>` : ''}
            ${reviewedDate ? `<div><strong>${escapeHtml(lblReviewed)}</strong> ${reviewedDate} ${escapeHtml(lblBy)} ${esc(reviewedBy || 'Admin')}</div>` : ''}
            ${rejectionReason ? `<div style="grid-column: 1 / -1; color: var(--danger);"><strong>${escapeHtml(lblRejectionReason)}</strong> ${esc(rejectionReason)}</div>` : ''}
          </div>

          <div class="held-actions">
            ${status === 'PendingApproval' ? `
              <button type="button" class="btn btn-danger btn-sm btn-reject-held" data-id="${esc(holdId)}">
                ${escapeHtml(btnRejectText)}
              </button>
              <button type="button" class="btn btn-success btn-sm btn-approve-held" data-id="${esc(holdId)}" style="background-color: var(--success); color: white;">
                ${escapeHtml(btnApproveText)}
              </button>
            ` : ''}
            ${(status === 'Approved' || status === 'Issued') ? `
              <button type="button" class="btn btn-secondary btn-sm btn-toggle-cert" data-target="${certBoxId}" data-id="${esc(holdId)}">
                📄 ${escapeHtml(btnViewCertText)}
              </button>
            ` : ''}
            ${status === 'UnderSubmission' ? `
              <span style="font-size:0.8rem; color:var(--gray-500); font-style:italic;">${escapeHtml(pendingCaHint)}</span>
            ` : ''}
          </div>

          <div id="${certBoxId}" class="cert-view-box"></div>
        `;

        container.appendChild(card);
      });

      // Bind actions
      container.querySelectorAll('.btn-approve-held').forEach(btn => {
        btn.addEventListener('click', () => approveHeldRequest(btn.getAttribute('data-id')));
      });

      container.querySelectorAll('.btn-reject-held').forEach(btn => {
        btn.addEventListener('click', () => rejectHeldRequest(btn.getAttribute('data-id')));
      });

      container.querySelectorAll('.btn-toggle-cert').forEach(btn => {
        btn.addEventListener('click', () => toggleCertView(btn.getAttribute('data-id'), btn.getAttribute('data-target')));
      });
    }

    async function approveHeldRequest(holdId) {
      const confirmTpl = window.I18N
        ? window.I18N.t('admin_confirm_approve_req', "Confermi l'approvazione del certificato con Hold ID '{0}'?\n\nIl certificato diverrà scaricabile dal richiedente.")
        : "Confermi l'approvazione del certificato con Hold ID '{0}'?\n\nIl certificato diverrà scaricabile dal richiedente.";
      const confirmMsg = confirmTpl.replace('{0}', holdId);
      if (!confirm(confirmMsg)) {
        return;
      }

      try {
        const resp = await fetch(`/api/admin/held-requests/${encodeURIComponent(holdId)}/approve`, {
          method: 'POST',
          headers: { 'X-Pki-Portal-Admin': await ensureCsrfToken() }
        });
        const result = await resp.json();
        const successMsg = window.I18N ? window.I18N.t('admin_toast_approved', 'Certificato approvato con successo!') : 'Certificato approvato con successo!';
        const defaultErrMsg = window.I18N ? window.I18N.t('admin_toast_approve_error', 'Impossibile approvare') : 'Impossibile approvare';
        if (resp.ok && result.success) {
          showToast(result.message || successMsg, 'success');
          loadHeldRequests();
        } else {
          showToast('Errore: ' + (result.message || defaultErrMsg), 'error');
        }
      } catch (err) {
        const commErrMsg = window.I18N ? window.I18N.t('admin_toast_comm_error', 'Errore di comunicazione: ') : 'Errore di comunicazione: ';
        showToast(commErrMsg + err.message, 'error');
      }
    }

    async function rejectHeldRequest(holdId) {
      const promptTpl = window.I18N
        ? window.I18N.t('admin_prompt_reject_req', "Inserisci il motivo del rifiuto per la richiesta '{0}' (opzionale):")
        : "Inserisci il motivo del rifiuto per la richiesta '{0}' (opzionale):";
      const promptMsg = promptTpl.replace('{0}', holdId);
      const reason = prompt(promptMsg);
      if (reason === null) return; // annullato

      try {
        const resp = await fetch(`/api/admin/held-requests/${encodeURIComponent(holdId)}/reject`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Pki-Portal-Admin': await ensureCsrfToken() },
          body: JSON.stringify({ reason: reason.trim() })
        });
        const result = await resp.json();
        const successMsg = window.I18N ? window.I18N.t('admin_toast_rejected', 'Richiesta rifiutata.') : 'Richiesta rifiutata.';
        const defaultErrMsg = window.I18N ? window.I18N.t('admin_toast_reject_error', 'Impossibile rifiutare') : 'Impossibile rifiutare';
        if (resp.ok && result.success) {
          showToast(result.message || successMsg, 'success');
          loadHeldRequests();
        } else {
          showToast('Errore: ' + (result.message || defaultErrMsg), 'error');
        }
      } catch (err) {
        const commErrMsg = window.I18N ? window.I18N.t('admin_toast_comm_error', 'Errore di comunicazione: ') : 'Errore di comunicazione: ';
        showToast(commErrMsg + err.message, 'error');
      }
    }

    async function toggleCertView(holdId, boxId) {
      const box = document.getElementById(boxId);
      if (!box) return;

      if (box.style.display === 'block') {
        box.style.display = 'none';
        return;
      }

      const loadingText = window.I18N ? window.I18N.t('admin_loading_cert', 'Caricamento dettagli certificato...') : 'Caricamento dettagli certificato...';
      const noCertText = window.I18N ? window.I18N.t('admin_no_cert_stored', 'Nessun certificato archiviato per questa richiesta.') : 'Nessun certificato archiviato per questa richiesta.';
      const certErrMsg = window.I18N ? window.I18N.t('admin_cert_retrieve_error', 'Errore nel recupero del certificato: ') : 'Errore nel recupero del certificato: ';

      box.innerHTML = escapeHtml(loadingText);
      box.style.display = 'block';

      try {
        const resp = await fetch(`/api/admin/held-requests/${encodeURIComponent(holdId)}`);
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const data = await resp.json();
        box.textContent = data.certificatePem || data.CertificatePem || data.p7bBase64 || data.P7bBase64 || noCertText;
      } catch (err) {
        box.textContent = certErrMsg + err.message;
      }
    }

    function showToast(message, type) {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.className = 'toast ' + type + ' show';
      setTimeout(() => { toast.className = 'toast'; }, 4000);
    }

    function esc(text) {
      if (!text) return '';
      return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function setAcmeDirectoryLink(baseUrl) {
      const trimmedBaseUrl = (baseUrl || '').trim().replace(/\/$/, '');
      let directoryUrl = '/acme/directory';
      if (trimmedBaseUrl) {
        try {
          const parsedBaseUrl = new URL(trimmedBaseUrl);
          if (parsedBaseUrl.protocol === 'http:' || parsedBaseUrl.protocol === 'https:') {
            parsedBaseUrl.pathname = parsedBaseUrl.pathname.replace(/\/$/, '') + '/acme/directory';
            parsedBaseUrl.search = '';
            parsedBaseUrl.hash = '';
            directoryUrl = parsedBaseUrl.href;
          }
        } catch { }
      }

      const dirLink = document.getElementById('acme-directory-link');
      dirLink.href = directoryUrl;
      dirLink.textContent = trimmedBaseUrl ? trimmedBaseUrl + '/acme/directory' : directoryUrl;
    }

    // ===== ACME Configuration Tab =====

    let acmeConfig = null;

    async function loadAcmeConfig() {
      try {
        const resp = await fetch('/api/admin/acme-config');
        if (!resp.ok) {
          showToast('Errore caricamento configurazione ACME: HTTP ' + resp.status, 'error');
          return;
        }
        acmeConfig = await resp.json();
        renderAcmeConfig();
      } catch (err) {
        showToast('Errore di rete ACME: ' + err.message, 'error');
      }
    }

    function renderAcmeConfig() {
      if (!acmeConfig) return;
      const c = acmeConfig;
      document.getElementById('acme-enabled').checked      = c.enabled ?? c.Enabled ?? true;
      document.getElementById('acme-baseurl').value         = c.baseUrl  ?? c.BaseUrl  ?? '';
      document.getElementById('acme-ca-id').value           = c.defaultCaId ?? c.DefaultCaId ?? '';
      document.getElementById('acme-template').value        = c.defaultTemplateName ?? c.DefaultTemplateName ?? 'WebServer';
      const allowedTmpls = c.allowedTemplates ?? c.AllowedTemplates ?? [];
      document.getElementById('acme-allowed-templates').value = Array.isArray(allowedTmpls) ? allowedTmpls.join(', ') : allowedTmpls;
      document.getElementById('acme-validation-mode').value  = c.validationMode ?? c.ValidationMode ?? 'Http01';
      document.getElementById('acme-http-port').value        = c.httpPort ?? c.HttpPort ?? 80;
      document.getElementById('acme-timeout').value          = c.challengeTimeoutSeconds ?? c.ChallengeTimeoutSeconds ?? 15;
      document.getElementById('acme-allow-private-ips').checked = c.allowPrivateIpValidation ?? c.AllowPrivateIpValidation ?? false;
      var allowedDomains = c.allowedDomains ?? c.AllowedDomains;
      document.getElementById('acme-allowed-domains').value  = Array.isArray(allowedDomains) ? allowedDomains.join(', ') : (allowedDomains || '');
      document.getElementById('acme-require-tos').checked    = c.requireTermsOfServiceAgreed ?? c.RequireTermsOfServiceAgreed ?? true;
      document.getElementById('acme-tos-url').value          = c.termsOfServiceUrl ?? c.TermsOfServiceUrl ?? '/acme/terms';

      setAcmeDirectoryLink(document.getElementById('acme-baseurl').value);
    }

    async function saveAcmeConfig() {
      const allowedRaw = document.getElementById('acme-allowed-templates').value;
      const allowedArr = allowedRaw.split(',').map(s => s.trim()).filter(s => s);

      const allowedDomainsRaw = document.getElementById('acme-allowed-domains').value;
      const allowedDomainsArr = allowedDomainsRaw.split(',').map(s => s.trim()).filter(s => s);

      const payload = {
        Enabled:                      document.getElementById('acme-enabled').checked,
        BaseUrl:                      document.getElementById('acme-baseurl').value.trim() || null,
        DefaultCaId:                  document.getElementById('acme-ca-id').value.trim() || null,
        DefaultTemplateName:          document.getElementById('acme-template').value.trim(),
        AllowedTemplates:             allowedArr,
        AllowedDomains:               allowedDomainsArr,
        ValidationMode:               document.getElementById('acme-validation-mode').value,
        HttpPort:                     parseInt(document.getElementById('acme-http-port').value, 10) || 80,
        ChallengeTimeoutSeconds:      parseInt(document.getElementById('acme-timeout').value, 10) || 15,
        AllowPrivateIpValidation:     document.getElementById('acme-allow-private-ips').checked,
        RequireTermsOfServiceAgreed:  document.getElementById('acme-require-tos').checked,
        TermsOfServiceUrl:            document.getElementById('acme-tos-url').value.trim() || '/acme/terms'
      };

      try {
        const resp = await fetch('/api/admin/acme-config', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'X-Pki-Portal-Admin': await ensureCsrfToken() },
          body: JSON.stringify(payload)
        });
        const result = await resp.json();
        if (resp.ok && result.success) {
          acmeConfig = payload;
          showToast(result.message || 'Configurazione ACME salvata!', 'success');
        } else {
          showToast('Errore: ' + (result.message || result.detail || 'Salvataggio fallito'), 'error');
        }
      } catch (err) {
        showToast('Errore di rete: ' + err.message, 'error');
      }
    }

    async function testAcmeDirectory() {
      const resultDiv = document.getElementById('acme-dir-result');
      resultDiv.style.display = 'block';
      resultDiv.innerHTML = '<span class="spinner-sm"></span> Contatto la directory ACME...';

      try {
        const resp = await fetch('/acme/directory');
        if (resp.ok) {
          const data = await resp.json();
          const hasRequired = data.newNonce && data.newAccount && data.newOrder;
          resultDiv.innerHTML = hasRequired
            ? `<span style="color:var(--success);">✅ Directory ACME operativa — endpoint trovati: newNonce, newAccount, newOrder, finalize</span>`
            : `<span style="color:var(--warning);">⚠️ Directory raggiunta ma risposta inattesa: <code>${JSON.stringify(data).substring(0, 200)}</code></span>`;
        } else {
          resultDiv.innerHTML = `<span style="color:var(--danger);">❌ Errore HTTP ${resp.status}: il server ACME potrebbe essere disabilitato o non raggiungibile.</span>`;
        }
      } catch (err) {
        resultDiv.innerHTML = `<span style="color:var(--danger);">❌ Errore di rete: ${err.message}</span>`;
      }
    }

    function setupAcmeTab() {
      document.getElementById('btn-save-acme').addEventListener('click', saveAcmeConfig);
      document.getElementById('btn-cancel-acme').addEventListener('click', () => {
        if (acmeConfig) renderAcmeConfig();
        else loadAcmeConfig();
      });
      document.getElementById('btn-test-acme-dir').addEventListener('click', testAcmeDirectory);

      // Update directory link when BaseUrl changes
      document.getElementById('acme-baseurl').addEventListener('input', (e) => {
        setAcmeDirectoryLink(e.target.value);
      });
    }
  })();
