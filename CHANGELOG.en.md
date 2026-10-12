# Changelog

[🇬🇧 English](CHANGELOG.en.md) | [🇮🇹 Italiano](CHANGELOG.md)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
