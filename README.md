[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/actuator/pSlip)](https://github.com/actuator/pSlip/releases)
[![GitHub stars](https://img.shields.io/github/stars/actuator/pSlip)](https://github.com/actuator/pSlip/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/actuator/pSlip)](https://github.com/actuator/pSlip/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/actuator/pSlip)](https://github.com/actuator/pSlip/graphs/contributors)

<img src="https://github.com/user-attachments/assets/53ff5d6f-c036-4f91-b993-84d0972a04b0" alt="pSlip banner" />

---

## What's New (v1.3.0)

### androguard is now the primary engine (no Java required)

Manifest parsing, OAuth analysis, and AES/DES/IV detection all run on androguard reading the DEX directly. You no longer need apktool or jadx to scan an app. Those are only used if you opt into the deep AES pass with `-aes-deep`.

### AES/DES/IV detection rewritten on DEX bytecode

It now cross-references `SecretKeySpec`, `IvParameterSpec`, and `Cipher`, then backtraces the key/IV register to its constant source. A byte array key can never be a bare string literal, so a value is only reported if it actually reaches the constructor through `getBytes()` or an array literal. That provenance rule kills the usual false positives (algorithm names like `AES`, KDF names like `PBKDF2WithHmacSHA1`, stray exception strings). Every finding includes the recovered value, the key size, the cipher transform, and the `const -> getBytes -> init` chain, so it is ready to drop into a report.

The same app that used to time out now finishes in well under a minute with no Java involved. If you need keys that are assembled across branches or loaded from static fields, `-aes-deep` runs the old jadx/apktool source pass.

### OAuth scheme-hijack detection (always on)

pSlip flags exported components that own an OAuth redirect (a custom scheme or an `https` app link) and reports the leaked `client_id`, the claimable redirect, and the runtime preconditions an attacker still has to confirm before claiming impact. It also catches the Google "Web application" misconfiguration where an Android app ships a `client_secret` in the APK (the wrong OAuth client type), and it pulls cross-platform client_ids out of the DEX. Detection runs by default. Buildable PoC project generation is behind `-oauth-poc`.
See https://actuator.sh/blog/2026-08-the-wrong-dropdown.html


### Split-APK containers

`.xapk`, `.apks`, and `.apkm` bundles are expanded automatically. The base/code APK is analyzed and config/resource splits are skipped.

### Faster, parallel crypto pass

The AES pass analyzes multiple APKs at once with a bounded worker pool and a per-APK timeout, so one slow or malformed app cannot stall a batch.

### Windows: zero-setup dependencies

On a fresh Python install pSlip bootstraps its Python dependencies (tqdm, androguard) and re-runs itself. Set `PSLIP_NO_AUTOINSTALL=1` to turn that off.

### Clearer environment banner and tool overrides

The startup banner shows which engine is doing what. If jadx or apktool live somewhere off PATH, point pSlip at them with `-jadx <path>` / `-apktool <path>` (or the matching env vars). A tool failing is now reported with the real reason instead of a bare exit code.

---

## Previously (v1.1.5)

- Hardcoded Segment write key detection across Java, Kotlin, JSON, XML, JS/TS, properties, text, and smali.
- Category summaries: Hardening, Component Exposure, Crypto, JavaScript Injection, URL Redirect, Permissions, Secrets.
- Android 15 severity model with exploitability-weighted severity.
- Unified `-all` / `-allsafe` CLI.

---

# pSlip

**pSlip** detects Android applications vulnerable to Permission-Slip / Confused-Deputy paths by analyzing:

- exported Activities, Services, BroadcastReceivers, Providers
- intent filters and unsafe CALL/VIEW handlers
- JavaScript-enabled WebViews and URL schemes
- manifest hardening controls
- unsafe permissions and custom-role exposure
- cryptographic misuse (hardcoded AES/DES keys, hardcoded IVs, weak modes)
- OAuth redirect scheme hijack and Google client_secret-in-APK misconfiguration
- hardcoded secrets such as Segment write keys

pSlip is built for application-security testing, CI/CD pipelines, and bulk APK triage.

---

## Highlights

### Exported Component Triage
- CALL actions
- VIEW + `javascript:` handlers
- Wildcard deep links
- Weak or normal-protection custom permissions

### Crypto, Secrets, and Code Triage
- Hardcoded AES/DES key and IV detection straight from DEX bytecode, with register backtrace and provenance so reported keys are real
- Cipher transform captured per finding, so weak modes such as ECB and static-IV CBC are visible
- Hardcoded Segment write-key detection with case-insensitive name matching for common config styles (currently part of the deep AES pass, `-aes-deep`, since it scans decompiled source and config)

### OAuth Triage
- Exported redirect handlers (custom scheme and `https` app links)
- Leaked `client_id` plus claimable redirect, with the runtime preconditions spelled out
- Google "Web application" wrong-client-type detection (client_secret shipped in the APK)
- Optional buildable PoC projects

### Reporting
- HTML and JSON output
- ADB PoC generation
- Severity and confidence scoring (0 to 100)

---
<img width="928" height="300" alt="image" src="https://github.com/user-attachments/assets/e7fb474b-4823-44aa-86d8-b332fcb7e020" />


---

## Install

```bash
git clone https://github.com/actuator/pSlip.git
cd pSlip
pip install -r requirements.txt
```

That is everything for the default scan. The manifest, OAuth, and AES passes all run on androguard, so no Java or external tools are needed.

Only if you want the deep AES pass (`-aes-deep`), install jadx and/or apktool, which require Java 11 or later:

```bash
# Linux
sudo apt install apktool jadx
```

On Windows you can let pSlip install its Python dependencies on first run, or run `pip install -r requirements.txt` yourself. If jadx/apktool are not on PATH, pass `-jadx <path>` / `-apktool <path>`.

---

## Usage

```bash
# Directory sweep, full scan, HTML + JSON
python pSlip.py . -all -html demo.html -json demo.json

# Fast sweep, skip the AES/crypto pass
python pSlip.py path/to/apks -allsafe -html report.html

# Deep AES pass using jadx/apktool source decompilation
python pSlip.py . -all -aes-deep -html report.html

# jadx installed somewhere off PATH
python pSlip.py . -all -jadx C:\tools\jadx\bin\jadx.bat
```

A single APK, a directory of APKs, or split bundles (`.xapk`, `.apks`, `.apkm`) are all valid targets.

### Supported Flags

```text
-all                   Full analysis: manifest + OAuth + AES (androguard)
-allsafe               Full analysis without the AES/crypto pass
-html <file>           Write HTML report
-json <file>           Write JSON report
-aes-timeout <minutes> Per-APK time limit for the AES pass (default: 5)
-aes-deep              Use the jadx/apktool source-decompile AES pass
                       instead of the default androguard DEX scan
-oauth-poc             Also generate buildable OAuth PoC projects
-oauth-poc-dir <dir>   Output directory for OAuth PoC projects
-jadx <path>           Path to a jadx launcher not on PATH (for -aes-deep)
-apktool <path>        Path to an apktool launcher not on PATH
```

### Environment Variables

```text
PSLIP_AES_PARALLEL     Number of APKs to analyze at once in the AES pass
PSLIP_AES_DEEP=1       Same as -aes-deep
PSLIP_JADX             Path override for jadx (same as -jadx)
PSLIP_APKTOOL          Path override for apktool (same as -apktool)
PSLIP_JADX_TIMEOUT     jadx subprocess timeout in seconds (deep pass)
PSLIP_APKTOOL_TIMEOUT  apktool subprocess timeout in seconds (deep pass)
PSLIP_NO_AUTOINSTALL=1 Do not auto-install Python dependencies
PSLIP_FORCE_COLOR=1    Force ANSI color in the banner/output
```

---

## AES / DES / IV Detection

The default crypto pass reads the DEX directly. It finds every call site of `javax.crypto.spec.SecretKeySpec` and `javax.crypto.spec.IvParameterSpec`, then walks the method backward to find what feeds the key or IV register.

The rule that keeps the output clean: a key or IV argument is a byte array, so a real one cannot be a bare string constant. pSlip only reports a value when it reaches the constructor through `String.getBytes()` or an array literal. Algorithm names, KDF names, and unrelated string constants near the call site are ignored.

Each finding records the recovered value, the key length and size class, the cipher transform from the nearby `Cipher.getInstance`, and the bytecode chain that proves the flow. Example:

```text
Issue Type: Hardcoded AES Key
Details:    Hardcoded AES key (32 bytes, AES-256) recovered from DEX bytecode.
            value='...' (hex ...). algorithm=AES; cipher=AES/ECB/PKCS5Padding.
            provenance: const '...' -> String.getBytes() -> SecretKeySpec.<init>.
            sink=<class>-><method>
```

`-aes-deep` switches to the jadx/apktool path, which decompiles to Java/smali and runs the source-level scanner. It is slower and needs Java, but it can resolve keys the linear bytecode model does not, such as keys built across branches or read from a static field.

---

## OAuth Detection

pSlip looks for exported components that handle an OAuth redirect, either a custom scheme or an `https` app link. When it finds one it reports the provider, the leaked `client_id`, the redirect a rogue app could claim, and the set of preconditions that are not provable from the APK and must be confirmed at runtime before claiming impact.

It also detects the Google "Web application" mistake, where an app is registered with the confidential client type and ships the `client_secret` inside the APK. In that case the secret is reported (redacted in the report, full value only in a generated PoC), and the token exchange recipe is described for the right client type.

Detection runs by default as part of `-all`. Add `-oauth-poc` (optionally with `-oauth-poc-dir <dir>`) to also write buildable PoC projects.

---

## Secret Detection

pSlip detects hardcoded Segment write keys in Java, Kotlin, JSON, XML, JavaScript, TypeScript, properties, text, and smali. This scanner reads decompiled source and config, so it currently runs as part of the deep AES pass (`-aes-deep`).

Examples detected:

```java
private static final String SEGMENT_WRITE_KEY = "pHYN1qhsRsz...";
```

```json
{
  "segmentWriteKey": "CaVz3hRhBJKCNlParpK4kvWJLNUf164N"
}
```

Reported as:

```text
Issue Type: Hardcoded Segment Write Key
Severity: High
Confidence: 95
```

---

## Output

### HTML Output

- Category summaries: Hardening, Exposure, Crypto, Secrets, JS Injection, URL Redirect, Permissions
- Responsive index: table on desktop, cards on mobile
- Per-app findings with severity, confidence, and ADB PoC actions

<img src="https://github.com/actuator/pSlip/blob/main/pslip.gif" alt="pSlip-demo" />

