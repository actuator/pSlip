[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/actuator/pSlip)](https://github.com/actuator/pSlip/releases)
[![GitHub stars](https://img.shields.io/github/stars/actuator/pSlip)](https://github.com/actuator/pSlip/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/actuator/pSlip)](https://github.com/actuator/pSlip/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/actuator/pSlip)](https://github.com/actuator/pSlip/graphs/contributors)
<img src="https://github.com/user-attachments/assets/53ff5d6f-c036-4f91-b993-84d0972a04b0" alt="pSlip banner" />

---

## What's New (v1.4.0)

Report-layer release. The HTML report engine was rewritten; the detection, manifest, OAuth, and crypto-recovery passes are byte-identical to v1.3.5, so scan behavior and findings are unchanged.

### Searchable HTML report

The report search box is now a field-scoped query language instead of a package-name filter, and a match returns the *findings* that match, not just the app name:

- Scopes: `pkg:` `issue:` `comp:` `conf:` `details:` `adb:` `sev:` `key:`
- Presence tests: `has:key`, `has:adb`, `has:poc`
- `"quoted phrases"`, `-negation` (scopeable, e.g. `-sev:info`), and `/regex/` (scopeable, e.g. `pkg:/^com\.(samsung|sec)\./`; invalid regex is ignored rather than thrown)
- Terms are ANDed, matching is case-insensitive, 160 ms debounce
- An issue-type dropdown ANDs with the severity chips. A filtered app shows only its matching findings, with a "Show all N" escape.
- Keyboard: `/` focuses search, `Esc` clears, `?` toggles the syntax help panel.

### Key material extraction and export

Recovered crypto/OAuth values are now pulled out of each finding's `Details` and surfaced as structured artifacts (`aes-key`, `des-key`, `iv`, `segment-write-key`, `oauth-client-id`, `oauth-client-secret`; the OAuth secret stays redacted in the report):

- A dedicated **Key Material & Secrets** section, filterable by kind and scopeable to the current search.
- One-click export of the current view, a single app, or all key material as CSV (RFC-4180 with a UTF-8 BOM for Excel), JSON, Markdown, or clipboard copy - including "Export ALL keys".
- Reports open from `file://` with no server; clipboard falls back to a copyable overlay where the browser blocks it.

### Compatibility

No CLI, flag, or environment-variable changes. Existing `-all` / `-allsafe` / `-aes-deep` / `-oauth-poc` workflows and JSON output are unchanged; the new capabilities are entirely inside the generated HTML report.

---

## Previously (v1.3.5)
### androguard is now the primary engine (no Java required)
Manifest parsing, OAuth analysis, and AES/DES/IV detection all run on androguard reading the DEX directly. You no longer need apktool or jadx to scan an app. Those are only used if you opt into the deep AES pass with `-aes-deep`.
### AES/DES/IV detection rewritten on DEX bytecode
It now cross-references `SecretKeySpec`, `IvParameterSpec`, and `Cipher`, then backtraces the key/IV register to its constant source. A byte array key can never be a bare string literal, so a value is only reported if it actually reaches the constructor through `getBytes()` or an array literal. That provenance rule kills the usual false positives (algorithm names like `AES`, KDF names like `PBKDF2WithHmacSHA1`, stray exception strings). Every finding includes the recovered value, the key size, the cipher transform, and the `const -> getBytes -> init` chain, so it is ready to drop into a report.
The same app that used to time out now finishes in well under a minute with no Java involved. If you need keys that are assembled across branches or loaded from static fields, `-aes-deep` runs the old jadx/apktool source pass.
### OAuth scheme-hijack detection
pSlip flags exported components that own an OAuth redirect (a custom scheme or an `https` app link) and reports the leaked `client_id`, the claimable redirect, and the runtime preconditions an attacker still has to confirm before claiming impact.
It also catches the Google "Web application" misconfiguration where an Android app ships a `client_secret` in the APK (the wrong OAuth client type), and it pulls cross-platform client_ids out of the DEX. Detection runs by default. Buildable PoC project generation is behind `-oauth-poc`.
### Split-APK containers
`.xapk`, `.apks`, and `.apkm` bundles are expanded automatically. The base/code APK is analyzed and config/resource splits are skipped.
### Windows: zero-setup dependencies
On a fresh Python install pSlip bootstraps its Python dependencies (tqdm, androguard) and re-runs itself. Set `PSLIP_NO_AUTOINSTALL=1` to turn that off.
