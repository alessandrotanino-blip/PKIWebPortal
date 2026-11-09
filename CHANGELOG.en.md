# Changelog

[🇬🇧 English](CHANGELOG.en.md) | [🇮🇹 Italiano](CHANGELOG.md)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2026-11-09

### New Features & Improvements

- **Automatic Certification Authority Detection in Configuration (redundant fields removed)**:
  - The CA card in the admin panel no longer requires typing the **Config String** by hand: the **CA Server** and **CA Name** fields build it automatically in `server\CA-Name` form.
  - New **🔍 Detect CAs** button: discovers CAs registered in Active Directory starting from either the **Forest / Domain** alone or the CA Server, offering them in a **dropdown** (auto-selection when a single CA is detected).
  - Selecting a CA automatically fills both **CA Name** and **CA Server** (retrieved from the standard `dNSHostName` attribute in AD).
  - **Credential Target** is no longer a free-form field: it is derived automatically from the CA Server (it always matches the credential target in Windows Credential Manager).
  - New endpoint `POST /api/admin/ca/discover` (admin-only, CSRF-protected) that queries exclusively the AD **Configuration** partition (standard `dNSHostName` attribute and `pKIEnrollmentService` class) via LDAP/LDAPS on the Domain Controller. No HTTP/HTTPS connections (ports 80/443) are made to the CA server. The partition base DN is resolved dynamically via the **rootDSE** (`configurationNamingContext`) and **LDAP referrals** returned by a DC are followed automatically (up to 2 hops).
  - Manual entry option (`✏️ Enter manually...`) for standalone or non-AD-integrated Certification Authorities.
  - Existing Config Strings are automatically split into CA Server + CA Name on load (no migration: legacy `appsettings.json` files remain valid and are re-saved in the same form).
  - Full translations (IT, EN, FR, DE, ES, PT, ZH) in `i18n.js`.

- **Intelligent Fast Upgrade in Setup Installer (Inno Setup & PowerShell)**:
  - The installer automatically detects previous installations of PkiPortal (via `HKLM\SOFTWARE\PkiPortal` registry, Windows Uninstaller, or IIS/filesystem runtime inspection).
  - New dedicated **Previous Version Detected** wizard page with **Fast upgrade (recommended)** enabled by default: instantly updates application files while preserving the installation directory, IIS site, ports, SSL certificates, Application Pool credentials, and `appsettings.json`, automatically skipping intermediate parameter prompts.
  - **Custom installation** option: allows viewing and modifying all parameters, pre-populated with previously configured values.
  - New `-PreserveAppPoolIdentity` switch in `Install-PkiPortal.ps1`: updates IIS while preserving the configured AppPool identity and encrypted passwords without requiring re-entry.

### Installer Fixes & Improvements (v2.5.0)

- **Live IIS Port Detection**: Site port detection now always queries IIS live via `Get-WebBinding` rather than reading cached registry values, fixing mismatches where a site on port 443 was displayed as port 8443.
- **`certificateHash` String and Byte[] Compatibility**: Handled type variance returned by IIS/PowerShell 5.1 (`[byte[]]` vs `[string]`) to prevent malformed thumbprints in SSL certificate detection.
- **`-File` Detection Execution**: Temporary detection script is executed using `-File` instead of `-Command` to prevent interpolation issues with special variables (`$matches`, `$host`).
- **`New-WebBinding` Syntax Fix**: Removed unsupported parameters in PowerShell 5.1 (`-Ssl`, `-Force`).
- **File In-Use Lock Resolution**: Worker process `w3wp.exe` is stopped by PID before file extraction, `app_offline.htm` is placed to release binaries from ANCM, and shutdown sequence is executed on the `ssInstall` step.

## [2.4.0] - 2026-11-06

### New Features & Improvements

- **ACME Requester Identification & Client IP Tracking**:
  - In certificate and request listings (both in the main portal and in the administration panel), certificates issued via the ACME protocol (RFC 8555) are now clearly identified in the *Requester* column/field.
  - Automatic tracking of the ACME client IP address (ACME (<ip>), e.g., ACME (192.168.1.50)) captured during order creation or finalization, with transparent support for X-Forwarded-For proxy headers and IPv6-to-IPv4 mapping.
  - If the client IP address is unavailable, ACME is displayed as the requester.
  - Distinctive high-visibility badge (⚡ ACME (...)) rendered in both the portal table and the admin request cards.
  - Full backwards compatibility: all existing ACME requests stored in the persistent database (held-requests.json) are automatically recognized and labeled as ACME.

- **Advanced Certificate Request Filtering (Portal & Admin)**:
  - New modern filter toolbar embedded in the portal request view (index.html) and the admin request tab (dmin.html).
  - **Requester Filter**: dynamically populated dropdown with all distinct requesters, including a quick option ⚡ ACME Only (all) to immediately isolate all ACME-issued certificates.
  - **Template Filter**: dynamically populated dropdown with all available Certificate Templates.
  - **Status Filter**: filter by Issued/Approved, Pending, or Rejected.
  - **Full-Text Live Search**: instantaneous live search filtering across Common Name (CN), Request ID, Requester (including ACME IPs), Template, and CA.
  - **Live Counter & Reset Button**: real-time counter (Showing X of Y requests) and one-click ✕ Reset button to clear all active filters.

- **RESTful API Filtering**:
  - Endpoints GET /api/certificates/my-requests and GET /api/admin/held-requests now support optional query parameters (?requester=...&template=...&status=...&search=...) enabling native server-side filtering for PowerShell scripts and automation workflows.

### Fixes & Hardening

- **Content Security Policy (CSP) Compliance for `admin.html`**:
  - Extracted the entire JavaScript logic of the administration panel into a dedicated external file `wwwroot/js/admin.js`.
  - Fixed browser blocking (blank/empty panel) caused by the strict `script-src 'self'` CSP directive in `web.config`.
- **ACME Configuration Save in IIS Least-Privilege Environments**:
  - Resolved `System.UnauthorizedAccessException` on `appsettings.json.acmetmp` when saving ACME configuration.
  - Writing is now performed directly onto `appsettings.json` (where the IIS AppPool holds `Modify` permissions), avoiding temporary file creation in the root folder protected with `ReadAndExecute`.
## [2.3.2] - 2026-11-04

### New Features & Intranet ACME Support

- **RFC 1918 Private IP Support for HTTP-01 Validation (`AllowPrivateIpValidation`)**:
  - Added configuration option `AcmeConfig.AllowPrivateIpValidation` (default: `false`).
  - When enabled, allows the ACME server to perform real HTTP-01 challenge validations against corporate intranet servers on private IP ranges (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`; CGNAT `100.64.0.0/10`; IPv6 ULA `fc00::/7`).
  - Provides significantly stronger security than pure `AutoApprove`, enforcing genuine *Proof of Possession* and web server ownership validation within corporate Active Directory networks.
  - **Strict and permanent anti-SSRF defenses**: loopback (`127.0.0.0/8`, `::1`), link-local and cloud metadata endpoints (`169.254.0.0/16`, `169.254.169.254`, `fe80::/10`), multicast (`224.0.0.0/4`, `ff00::/8`), and non-routable addresses (`0.0.0.0/8`) remain **strictly blocked at all times**.
  - **Mandatory security constraint**: when `AllowPrivateIpValidation` is enabled, specifying `AllowedDomains` is **mandatory** (enforced on ACME order creation and in the administration PUT API), preventing ACME clients from probing unauthorized internal endpoints.

### Admin GUI & i18n Improvements

- **Administration Panel (`/admin`)**:
  - Added interactive toggle **Allow Private IPs (Intranet RFC 1918)** with descriptive guidance under the **🤖 Server ACME** tab.
  - Full multilingual localization (EN, IT, FR, DE, ES, PT, ZH) in `i18n.js`.

## [2.3.1] - 2026-11-03

### Security & Hardening (ACME Server Security Review)

- **CSR↔Order binding (critical)**: `finalize` now verifies that the CSR CN and all DNS SANs are a subset of the ACME order identifiers; IP, email and URI SANs are rejected. It is no longer possible to obtain a certificate for names different from the ordered/validated ones (the CSR is parsed at the DER level, .NET 8 compatible).
- **SSRF mitigation via http-01 (critical)**: the challenge identifier must be a public DNS hostname (IP literals, hostnames >253 chars and special characters are rejected). If any resolved address is private/reserved (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, fc00::/7, etc.) the validation is rejected. The HTTP response from the target host is no longer echoed to the client: details stay in server logs only.
- **Domain allowlist (critical)**: new `AcmeConfig.AllowedDomains` (exact or subdomain match). When non-empty, `new-order` for out-of-list domains → 400 `rejectedIdentifier`. In `AutoApprove`/`Http01WithAutoFallback` modes the list is mandatory: without it, no order is accepted. Wildcard domains (`*.`) are always rejected.
- **Account ownership (high)**: reads of `/acme/account/{id}`, `/acme/order/{id}`, `/acme/authz/{id}` now require a valid JWS: unsigned → 401; JWS from a different account → 403 (IDOR fix). JWS with an unregistered key → 404 `accountDoesNotExist` (ephemeral-key authentication no longer possible).
- **Effective certificate revocation (high)**: `revoke-cert` now performs a real revocation on AD CS (`certutil -revoke` under CA account impersonation); if the CA cannot revoke, 500 is returned (no fake success). Revoked certificates can no longer be downloaded (404).
- **Real key change (high)**: `key-change` validates the outer JWS (old key) and the inner JWS (new key), checks the new key strength and updates the account JWK/thumbprint.
- **Full ACME state persistence (high)**: the store now persists JWK, thumbprint, order↔account association, CA, template, request ID, certificate chain and revocation timestamp: after an IIS recycle accounts keep their keys and certificates remain downloadable.
- **JWS hardening**: algorithm allowlist (no `none`/unknown), RSA ≥ 2048-bit with valid exponent, EC curves limited to P-256/P-384/P-521 (alg/curve consistency checked), JWS body ≤ 32 KiB, single-use nonces (replay → `badNonce`) with hard cap and eviction (anti memory growth).
- **Expiry and limits**: orders/authorizations expire (`pending` → `expired`), max 10 identifiers per order, challenge body ≤ 4 KiB, http-01 timeout managed per request (no more mutation of the shared client timeout).
- **Enable flag and TLS**: with `AcmeConfig.Enabled = false`, `/acme/*` endpoints answer 503; non-localhost HTTP requests are redirected to HTTPS (301).
- **Admin API and GUI**: `PUT /api/admin/acme-config` validates Base URL (absolute http/https), `AllowedTemplates`/`DefaultTemplateName` (regex), `AllowedDomains` (hostname per entry), `TermsOfServiceUrl`, and requires a non-empty `AllowedDomains` in `AutoApprove`. `appsettings.json` write is now atomic (temp file + move). New CSV `AllowedDomains` field in the admin panel.
- **Logging robustness**: the logging pipeline is now explicit (console only) — the default Windows EventLog provider, when it lacks write permission, no longer crashes in-flight requests (including security rejection responses).
- **Automated security tests**: added `Test-AcmeSecurity.ps1` with 9 regression scenarios (anonymous 401, unregistered key 404, wildcard, allowlist, CSR binding, IP SAN, nonce replay, oversized JWS, IDOR 403).
- **TODO (external)**: bump `Microsoft.AspNetCore.Authentication.Negotiate` 8.0.31 → **8.0.32** for CVE-2026-70179 (GHSA-vrrp-6v32-2p8g, elevation of privilege in Negotiate/LDAP). Blocked in this environment by TLS MITM on nuget.org; it is a one-line change in `PkiPortal.csproj` (marked with a TODO comment).

### UX Improvements

- **ACME Configuration from Admin Panel**:
  - Added **🤖 Server ACME** tab to the administration panel (`/admin`), allowing the entire `AcmeConfig` block to be read and edited directly from the web UI without manually editing `appsettings.json`.
  - GUI-configurable fields: Enabled, Base URL, Default CA, AD CS Template, Allowed Templates, Validation Mode, HTTP Challenge Port, Challenge Timeout, ToS Acceptance, ToS URL.
  - **🧪 Test Directory** button for live verification of `GET /acme/directory` reachability directly from the panel.
  - Dynamic Base URL → directory link update on input change.
  - Lazy load: ACME config is fetched only on first tab access.
  - New protected admin API endpoints (Windows Auth + CSRF): `GET /api/admin/acme-config` and `PUT /api/admin/acme-config`.
  - Layout fix: **Validation Mode** field now uses a vertical stacked layout with full-width `<select>` to prevent option text truncation.

---## [2.3.0] - 2026-11-03

### Features & Architecture
- **Built-in Native ACME Server (RFC 8555)**:
  - Complete implementation of the ACME protocol (RFC 8555) hosted directly inside the portal's ASP.NET Core runtime, eliminating external ACME bridges or third-party products (e.g., ACME-Server-ADCS, Smallstep, Keyfactor, or EJBCA).
  - Full compatibility with standard ACME clients: **win-acme** (Windows/IIS), **Certbot** (Linux), **Traefik**, **Caddy**, **acme.sh**.
  - Implemented ACME endpoints: `/acme/directory`, `/acme/new-nonce`, `/acme/new-account`, `/acme/account/{id}`, `/acme/account/{id}/orders`, `/acme/new-order`, `/acme/order/{id}`, `/acme/authz/{id}`, `/acme/chall/{authId}/{type}`, `/acme/order/{id}/finalize`, `/acme/cert/{id}`, `/acme/revoke-cert`, `/acme/key-change`, `/acme/terms`.
- **ACME Cryptographic Engine (RFC 7515 & RFC 7638)**:
  - Full JWS parsing and signature verification for both RSA (RS256, RS384, RS512, PS256, PS384, PS512) and ECDSA (ES256, ES384, ES512).
  - Strict RFC 7638 JWK Thumbprint calculation for account key identification and challenge key authorizations.
- **Domain Challenge Validation (RFC 8555 Section 8)**:
  - Automated `http-01` challenge validation over port 80 via `HttpClientFactory`.
  - Configurable `AutoApprove` mode for air-gapped networks, offline testing, and dev labs.
  - `Http01WithAutoFallback` mode for segmented corporate networks with internal firewall boundaries.
- **Direct AD CS Issuance**:
  - Native integration with `IAdcsService` on order finalization, mapping requested SANs with configured AD CS certificate templates and serving the complete X.509 chain (`application/pem-certificate-chain`).
- **Thread-Safe ACME Store with Atomic Persistence**:
  - Concurrent dictionary management for accounts, orders, authorizations, challenges, and anti-replay nonces, persisted atomically to `App_Data/acme-store.json`.
- **End-to-End Test Suite**:
  - Added `Test-AcmeProtocol.ps1` for complete end-to-end testing (in-memory key generation, registration, order creation, challenge validation, CSR generation, AD CS issuance, and X.509 certificate inspection).
- **IIS Hardening & Dual-Auth**:
  - Updated `Install-PkiPortal.ps1` to configure anonymous authentication specifically on `/acme` and `/.well-known`, preserving Windows Authentication (Negotiate) across `/` and `/api/*`.

---
## [2.2.1] - 2026-10-26

### Security & Hardening
- **CodeQL Alert Remediation**:
  - Remediated CodeQL alerts for Cross-Site Scripting (XSS), log forging, and command injection.
  - Hardened client-side DOM handling, log output sanitization, and strict validation of AD CS command arguments.

### Included
- All changes from v2.2.0, including Chinese and Portuguese localization.

---
## [2.2.0] - 2026-10-26

### Features & Internationalization

**New Language Support: Portuguese (pt) and Chinese (zh)**
- **i18n Module Expansion (wwwroot/js/i18n.js)**:
  - Added full support for 7 languages (**English, Italian, French, German, Spanish, Portuguese, Chinese**) with instant dynamic switching and persistent user preferences.
  - Added crisp inline SVG flag icons for Portugal (pt) and China (zh).
  - Translated all 244 localization keys for both languages, covering Web Crypto enrollment wizard, CSR submission, certificate retrieval/history, multi-CA management, request filters, and notification/error prompts.
- **User Interface (wwwroot/index.html, wwwroot/admin.html)**:
  - Added Portuguese (Português) and Chinese (中文) entries to the .lang-dropdown language picker on both user and administration pages.
  - Updated navigation version badges and asset query string cache-busting to 2.2.0.
- **Installation Script & Documentation (Install-PkiPortal.ps1, README.md, README.it.md, DOCUMENTATION.dokuwiki)**:
  - Updated portal version string to 2.2.0 across the PowerShell installer script and project technical documentation.

---
## [2.1.1] - 2026-10-22

### Features & Fixes

**Configurable deferred PFX retrieval per template (StorePrivateKeyForRetrieval)**
- **Fixed PFX retrieval for immediate-issuance templates**: in release 2.1.0 omitting the private key transmission for immediate-issuance flows prevented requesters from subsequently retrieving the complete .pfx archive (only .crt and .p7b were made available).
- **New template parameter StorePrivateKeyForRetrieval**:
  - **Enabled by default (	rue)**: during wizard enrollment, the browser-generated private key is sent over secure HTTPS and stored encrypted at rest on the server (Windows DPAPI machine-scope / AES-256-GCM in App_Data/held-requests.json). This enables the original requester or authorized administrators to retrieve or regenerate the complete password-protected .pfx archive (with leaf, private key, and issuing chain) at any time later.
  - When set to alse, the private key does not leave the client for non-approval templates (zero-knowledge mode), restricting subsequent retrievals to the .crt certificate and .p7b chain.
- **Admin panel integration (/admin.html)**: added "Store Key for PFX Retrieval" toggle switch with descriptions across all 5 supported languages (IT, EN, FR, DE, ES) for both manually added and discovered templates.
- **API exposure**: the setting is delivered via GET /api/config to guide client-side submission logic.

---
## [2.1.0] - 2026-10-15

### Security (hardening across all portal areas)

**Installation and IIS configuration (`Install-PkiPortal.ps1`, `web.config`)**
- **Unencrypted HTTP blocked by default**: installing without `-UseHttps` now aborts with an error. Proceeding requires the explicit `-AllowInsecureHttp` switch (reserved for isolated test environments). With Windows Authentication, cleartext HTTP exposes NTLM hashes (capture/relay) and sensitive portal payloads (CSRs and, in approval flows, private keys).
- **NTLM Extended Protection (EPAL)**: `windowsAuthentication` configured with `extendedProtection:outbound` to protect credentials from NTLM relay to other LAN services.
- **Anonymous authentication disabled** on the IIS site: every request (including static files) goes through the NTLM/Kerberos challenge; the admin panel is no longer anonymously reachable.
- **Least privilege on the file system**: the App Pool identity gets `ReadAndExecute` on the application folder (no more `FullControl` on binaries: prevents DLL swap) and `Modify` only on `appsettings.json` (runtime config save), `App_Data` and `logs` (already locked down with exclusive ACLs).
- **Security headers in `web.config`**: `Strict-Transport-Security` (HSTS) and a restrictive `Content-Security-Policy` (same-origin only, no inline scripts: the theme preloader and the "Cancel Changes" button handler were moved to external files, `js/theme-init.js`).

**Reduced private key exposure (`wwwroot/js/app.js`, `wwwroot/js/crypto-helper.js`)**
- In **immediate-issuance** flows the private key is **no longer sent to the server**: `privateKeyPem` is transmitted only for templates with `RequiresApproval` (hold/deferred PFX retrieval flow, where the server must keep it encrypted for retrieval). Note: for templates with CA-level manual approval, make sure `RequiresApproval: true` is set in the portal configuration.
- **PFX with AES-256-CBC** instead of 3DES (deprecated algorithm, SWEET32 vulnerability).
- **PFX password now mandatory** in the "Certificate Retrieval" flow as well (previously optional: a PFX with an empty password exposed the private key).
- **CSPRNG guard**: if `window.crypto.getRandomValues` is not available (insecure context or obsolete browser) the module refuses to generate keys instead of proceeding with unguaranteed entropy.
- Updated the `crypto-helper.js` header comment to accurately document the key lifecycle.

**Per-session anti-CSRF (`Services/CsrfTokenService.cs`, `Program.cs`, `admin.html`)**
- The public static token `"pki-admin"` was replaced by a **per-identity token**: a `user|expiry` payload (30 minutes) signed with HMAC-SHA256 using a server-side secret persisted in `App_Data/csrf-secret.bin`. New endpoint `GET /api/admin/csrf` (admin only). The admin panel fetches the token at startup and attaches it to all mutating requests (`X-Pki-Portal-Admin`), with automatic renewal before expiry.

**Rate limiting (`Program.cs`)**
- Per-identity request limiting (fallback to source IP) to mitigate abuse/DoS: 5 req/min for certificate submissions (`/api/certificates/request`, which spawns certreq/certutil processes), 20 req/min for CSR parsing, 120 req/min default for portal and admin APIs. Rejection with HTTP 429.

**Encrypted LDAP (`Services/AdcsService.cs`)**
- Reading template validity from AD now starts with **LDAPS (port 636)**: in Hub/CredentialManager mode the service account password no longer traverses the network in cleartext. Fallback to unencrypted LDAP (389) is allowed **only** when no explicit credentials are present (process identity, no password in transit).

**CA credential registration (`Add-CaCredential.ps1`)**
- The password is no longer passed as a command-line argument to `cmdkey` (previously `/pass:$plainPass`, visible in the process command line and potentially in shell logs): with an empty `/pass:`, `cmdkey` prompts for the password interactively, without exposing it in variables, command line, or logs.

**Information disclosure (`Program.cs`)**
- `GET /api/config` no longer exposes `AllowedGroups` (AD group names) to every authenticated user: only the `IsAllowed` flag per template is returned.
- Errors from `PUT /api/admin/config` no longer return `ex.Message` (details remain only in the server log).

### Misc
- Removed the `.tmp-dpapi-test/` development artifact from the checkout.
- Bumped version to `2.1.0` across `.csproj`, installer script, navbar badges, and asset cache-busting parameters.

---

## [2.0.12] - 2026-10-14

### Security & Cryptographic Architecture
- **Mandatory At-Rest Encryption for Private Keys (`HeldRequestStore.cs`)**:
  - Completely eliminated any cleartext persistence of private keys: all private keys stored for deferred retrieval or PFX bundle generation are now strictly encrypted at rest.
  - Implemented DPAPI machine-scope encryption (`CRYPTPROTECT_LOCAL_MACHINE` with persistent 256-bit entropy in `App_Data/store-entropy.bin`) with prefix `PKEY1:`.
  - Fixed Win32 P/Invoke signatures on `crypt32.dll` (`CryptProtectData`, `CryptUnprotectData`) using `CharSet = CharSet.Unicode` and proper unmanaged deallocation with `LocalFree` (`kernel32.dll`), preventing ANSI marshaling bugs and heap corruption.
  - Added an authenticated cross-platform / fallback encryption provider based on **AES-256-GCM** (prefix `AESGCM1:`) with an installation key stored in `App_Data/store-key.bin`.
  - Cryptographic DPAPI self-test at application startup: validates DPAPI operation before enabling it, automatically falling back to AES-256-GCM if unavailable.
  - Strict cleartext prevention: if no cryptographic provider is operational, persistence safely aborts with an exception rather than writing unencrypted keys to disk.
  - **Automatic legacy migration**: on startup, any unencrypted legacy records from earlier versions are automatically detected, decrypted in memory, re-encrypted with DPAPI/AES, and rewritten to `App_Data/held-requests.json`, while cleaning up legacy plaintext root files.

### Documentation & Transparency
- **Documentation Updates (`README.md`, `README.it.md`, `DOCUMENTATION.dokuwiki`)**:
  - Corrected private key lifecycle descriptions: transparently clarified that when using the wizard with PFX generation or deferred administrator approvals (Hold & Review), the private key is transmitted over secure HTTPS and kept strongly encrypted at rest on the server solely to permit authorized requester PFX assembly.
  - Clarified that the pure *Zero-Knowledge* model (private key never leaves the client or touches the server) applies to the Existing CSR Upload tab and REST CSR automation.
  - Updated technical DokuWiki documentation (sections 1.1, file tree, 8.5, and 12.2) detailing DPAPI, AES-256-GCM, and security guarantees.
- **User Interface & i18n Strings (`index.html`, `i18n.js`)**:
  - Updated Step 4 wizard subtitle across all 5 languages (en, it, fr, de, es) to accurately describe in-memory generation and secure at-rest server custody.
- **Installation Script & Versioning (`Install-PkiPortal.ps1`, `PkiPortal.csproj`)**:
  - Added migration support for `store-key.bin` to protected `App_Data`.
  - Bumped version to `2.0.12` across `.csproj`, PowerShell installer, navbar badges, and asset cache-busting parameters.

---

## [2.0.11] - 2026-10-12

### Added & Improved
- **IIS Installation Script Internationalization (`Install-PkiPortal.ps1`)**:
  - Automatic detection of Operating System culture (`CurrentUICulture` / `InstalledUICulture`).
  - When the OS display language is not Italian (`it`), all script logs, step banners, security warnings, interactive prompts (`Read-Host`), and the final summary are displayed in **English**.
  - Unified confirmation inputs supporting both Italian (`S/N`) and English (`Y/N`) user responses.
- **Versioning**: bump to `2.0.11` across the .NET project (`PkiPortal.csproj`), UI navigation badges (`index.html`, `admin.html`), and asset cache-busting strings.

---

## [2.0.10] - 2026-10-12

### Fixed & Improved
- **IIS Installation Script (`Install-PkiPortal.ps1`)**:
  - Fixed `Cannot find path 'IIS:\AppPools\...' because it does not exist` error during clean installs by guarding application pool status check with `Test-Path`.
  - Automatically grants **FullControl** NTFS permissions with inheritance to the Application Pool identity (`$identityAccount`, including gMSA accounts) across `$InstallPath`.
  - Auto-initialization of configuration file: if `appsettings.json` is missing on initial setup, the script automatically renames `appsettings.example.json` to `appsettings.json`.
- **Client-Side Cryptographic Key Generation (`crypto-helper.js`)**:
  - Implemented automatic resilience fallback (15s timeout): if Web Workers fail to respond (e.g. restrictive policies or IE ESC on Windows Server), key generation seamlessly switches to single-thread mode (`workers: 0`), preventing indefinite UI hangs.
  - Updated progress dialog descriptions and localized i18n strings across all 5 languages (en, it, fr, de, es).
- **Documentation (`README.md`, `README.it.md`, `DOCUMENTATION.dokuwiki`)**:
  - Added dedicated **Troubleshooting** sections explaining the **W3C Secure Context (HTTPS)** requirement for browser Web Crypto / Web Workers, IIS permissions, and first-time installation steps.

---

## [2.0.9] - 2026-10-11

### Fixed
- **JavaScript `escapeHtml is not defined` error in Admin Page**:
  - Defined a properly hoisted `escapeHtml()` function at the beginning of the script in `admin.html`, preventing the `ReferenceError` that prevented loading CA and template configuration cards.
- **Administration Panel & System Messages Internationalization (i18n)**:
  - Localized approval confirmation dialogs (`admin_confirm_approve_req`), rejection reason prompts (`admin_prompt_reject_req`), and CA removal prompts (`confirm_remove_ca`) across all 5 supported languages (en, it, fr, de, es).
  - Localized the administrative user badge (`admin_user_label`, e.g. *"User: ..."*) with reactive updates on language switch.
  - Localized HTTP 403 Forbidden security messages when retrieving certificates not associated with the user's account (`access_denied_security_not_owner`).
  - Localized toast notifications and certificate viewing details.
- **Light Theme Accessibility & Contrast**:
  - Fixed low-contrast text on the user badge (`#portal-user-badge`), ensuring full readability in both light and dark modes.
- **Documentation**:
  - Added screenshots gallery (`Screens/`) and aligned English and Italian README documentation.
- **Versioning**: bump to `2.0.9` (`PkiPortal.csproj`, UI badge in `index.html` and `admin.html`, cache-busting scripts and stylesheets `?v=2.0.9`).

---

## [2.0.7] - 2026-10-11

### Added
- **Author Information in Footer**:
  - Added author contact info with `mailto:` link (*Alessandro Tanino*, `mailto:alessandro.tanino@hotmail.com`) in the footer of all pages (`index.html` and `admin.html`).
  - Added localized footer strings in `i18n.js` across all supported languages (en, it, fr, de, es).
  - Dedicated CSS rules for hover and contrast across light and dark themes.
- **Versioning**: bump to `2.0.7` (`PkiPortal.csproj`, UI badge in `index.html` and `admin.html`, script cache-busting `?v=2.0.7`).

---

## [2.0.6] - 2026-10-07

### Fixed
- **COM Submission `CCertRequest::Submit` failing with `0x8007000D ERROR_INVALID_DATA`**:
  - With the `CR_IN_BASE64` flag, `Submit()` expects the CSR in **Base64-encoded PKCS#10 DER** format; the code was passing **armored PEM text** (`-----BEGIN CERTIFICATE REQUEST-----…`), which COM cannot decode, causing every submission to fallback to `certreq.exe`.
  - Added new `PemToBase64Der` helper (armor and whitespace removal) applied to CSR prior to calling `Submit`; removed placeholder constant `CR_IN_FORMATANY` (0x0).
  - Verified that conversion produces valid Base64 decoding to identical DER binary representation.
  - Diagnostic logs now show `COM Submit result: disposition=…` without the `COM submission failed` warning.
- **Versioning**: bump to `2.0.6` (`PkiPortal.csproj`, UI badge, script cache-busting `?v=2.0.6`).

---

## [2.0.5] - 2026-10-06

### Fixed
- **PFX without chain: client-side bug in parsing PEM certificate blocks**:
  - Regex in `pemChainToCertificates` (`crypto-helper.js`) used `[A-Z0-9- ]+` between `BEGIN` and `CERTIFICATE`, which failed to match standard `-----BEGIN CERTIFICATE-----` blocks (expecting type prefix like `X509 CERTIFICATE`). The client received the chain from the server but silently discarded it: PFX always contained only the leaf certificate and private key. Fixed to `[A-Z0-9- ]*` (optional type).
- **Chain containing leaf and missing Root in certreq paths**:
  - Raw extraction `ParseCertreqOutputBytes` from `.p7b` short-circuited `ExtractChainPem`, skipping leaf deduplication and Root completion. The chain is now always constructed via `ExtractChainPem` (leaf deduplication, local store/AIA `ocspNoCheck` completion, final filtering).
- **Self-healing on certificate retrieval**: for requests already saved in the store (e.g. issued with older versions), the status endpoint rebuilds the chain from original saved data (P7B + leaf) and updates the record on download, ensuring retrieved PFXs include the complete chain.
- **Versioning**: bump to `2.0.5` (`PkiPortal.csproj`, UI badge, script cache-busting `?v=2.0.5`).

---

## [2.0.4] - 2026-10-06

### Fixed & Improved
- **Chain incomplete on server (PFX with leaf + Sub-CA but missing Root)**:
  - **AIA `ocspNoCheck` fallback**: when AIA extension does not contain `caIssuers`, the URL of the `ocspNoCheck` entry points directly to the issuer certificate. Server now uses this URL (after `caIssuers`) to download missing issuer, only accepting certificates whose Subject matches the expected Issuer.
  - **RFC 5280 compliant AIA parser**: adapted ASN.1 parser to the real `SEQUENCE OF AccessDescription` structure (handling inner wrapper variants).
- **Leaf certificate erroneously included in the chain**:
  - Final safety net in `ExtractChainPem`: after all extraction and completion steps, the issued leaf certificate (by serial number) is stripped from the chain.
- **Robustness in certreq `.cer` parsing**:
  - Handled double Base64 encapsulation (Base64 of Base64/PEM) in fallback logic with certificate probe validation to avoid dummy certificates from arbitrary bytes.
  - New diagnostic logging for `.cer` inspections.
- **Versioning**: bump to `2.0.4` (`PkiPortal.csproj`, UI badge, script cache-busting `?v=2.0.4`).

---

## [2.0.3] - 2026-10-06

### Fixed & Improved
- **PFX missing chain when CA does not include CA certificates in response**:
  - Guaranteed chain completion: if AD CS P7B response does not include CA certificates (CA option "Include CA certificates in the chain" disabled), server completes chain using local `X509Chain` (system store / runtime AIA) and explicit issuer download from AIA `caIssuers` URL (direct ASN.1 parsing, max 3 hops).
- **PKCS#7 parser robustness**: handled armored PKCS#7 (`-----BEGIN PKCS7-----`).
- **Console diagnostics**: assembly version logged on startup; chain extraction details logged for each issuance/retrieval.
- **Versioning**: bump to `2.0.3` (`PkiPortal.csproj`, UI badge, script cache-busting `?v=2.0.3`).

---

## [2.0.2] - 2026-10-06

### Fixed
- **Full Chain in PFX (.pfx) and P7B (.p7b) Export**:
  - Handled unparsed PKCS#7 in `X509Certificate2Collection.Import()` by introducing deterministic ASN.1 parser (`TryExtractCertificatesFromPkcs7`).
  - Simulator generates authentic P7B in `P7bBase64` with issued certificate + mock Root CA.
  - Fixed double Base64 encapsulation in `certreq.exe` output files.
  - Added chain completion via local store/AIA when Root is absent.
  - Fixed client P7B download formatting (`p7bBase64ToFileText`).
- **Versioning**: bump to `2.0.2` (`PkiPortal.csproj`, UI badge, script cache-busting `?v=2.0.2`).

---

## [2.0.1] - 2026-10-06

### Changed & Improved
- **Full Issuing Chain Inclusion in PFX (.pfx)**:
  - Ensured all intermediate Sub-CAs and Root CA are bundled into the generated PKCS#12 archive.
  - Enhanced client-side diagnostics and counters for intermediate certificates in `CryptoHelper.createPfxBundle`.
  - Optimized `SubmitViaCertreqAsync` to preserve and extract the full `.p7b` chain during CLI execution.
- **User Interface (UI)**:
  - Displayed version badge `v2.0.1` in the navigation bar next to the subtitle in both `index.html` and `admin.html`.
  - Added `.brand-version` styles with responsive and dark mode support in `styles.css`.
  - Updated script cache-busting query strings.
- **Project Configuration**:
  - Added explicit semantic versioning in `PkiPortal.csproj`.

---

## [2.0.0] - 2026-10-03

### Added
- **Official Version 2.0 Release**:
  - Full migration to .NET 8 LTS and HTML5 Web Crypto API.
  - Client-side key and CSR generation in browser (Zero-Knowledge Private Key).
  - Untrusted Active Directory forest support via Windows Credential Manager integration.
  - High-performance native Microsoft AD CS connector via COM DCOM interfaces (`CCertRequest`).
  - Automatic fallback to CLI `certreq.exe` for restrictive DCOM policy environments.
  - Certificate templates with manual administrative approval workflow (`RequiresApproval`).
  - Thread-safe DPAPI-protected store for held requests (`held-requests.json`).
  - Dedicated administration panel (`admin.html`) with request review/approval, multi-CA management, and template discovery.
  - Multi-language support.
  - Responsive Light and Dark themes.
