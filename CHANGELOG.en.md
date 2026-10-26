# Changelog

[🇬🇧 English](CHANGELOG.en.md) | [🇮🇹 Italiano](CHANGELOG.md)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [2.2.1] - 2026-10-26
### Security
- Remediated CodeQL alerts for XSS, log forging, and command injection
- Hardened DOM handling, log output, and AD CS command arguments

### Included
- All changes from v2.2.0, including Chinese and Portuguese localization
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
