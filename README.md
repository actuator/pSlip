
[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/actuator/pSlip)](https://github.com/actuator/pSlip/releases)
[![GitHub stars](https://img.shields.io/github/stars/actuator/pSlip)](https://github.com/actuator/pSlip/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/actuator/pSlip)](https://github.com/actuator/pSlip/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/actuator/pSlip)](https://github.com/actuator/pSlip/graphs/contributors)

<img src="https://github.com/user-attachments/assets/53ff5d6f-c036-4f91-b993-84d0972a04b0" alt="pSlip banner" />

---

## What’s New (v1.1.3)

### **Modernized HTML Report**
A new flat, responsive layout improves readability, spacing, and dark-mode rendering.  
The Findings Index now adapts automatically between a desktop table and mobile card layout.

### **Category Summaries**
Reports now include summaries for:
**Hardening**, **Component Exposure**, **Crypto**, **JavaScript Injection**,  
**URL Redirect**, **Permissions**, and **Tapjacking**.

### **Updated Severity Model (Android 15)**
Severity weights now reflect realistic exploitability under modern Android.  
Tapjacking is treated as **Informational** unless paired with sensitive UI actions.

### **Cleaner Detail Sections**
Improved formatting for component names, ADB PoC commands, severity chips,  
and long package paths.

### **Unified CLI (Simpler Flags!)**
Scanning behavior has been simplified into two modes:

- `-all` → Full analysis  
- `-allsafe` → Full analysis without AES/JADX decompilation  

Legacy toggles (`-p`, `-perm`, `-js`, `-call`, `-aes`, `-taptrap`) no longer appear  
and no longer need to be managed individually.

---

# pSlip

**pSlip** detects Android applications vulnerable to **Permission-Slip / Confused-Deputy** paths by analyzing:

- exported Activities, Services, BroadcastReceivers, Providers  
- intent filters and unsafe CALL/VIEW handlers  
- JavaScript-enabled WebViews and URL schemes  
- manifest hardening controls  
- unsafe permissions and custom-role exposure  
- tapjacking/taptrap surface area  
- cryptographic misuse (AES/IV/key/ECB detection)

pSlip is designed for **application-security testing**, **CI/CD pipelines**, and **bulk APK triage**.

---

## Highlights

### Exported Component Triage
- CALL actions  
- VIEW + `javascript:` handlers  
- Wildcard deep links  
- Weak or normal-protection custom permissions

### Crypto & Code Triage
- Hardcoded AES/DES/IV patterns  
- Unsafe mode detection (ECB, static IVs, insecure PRNG)

### UI / Tapjacking Detection
- Layout XML parsing  
- Compose tree heuristics  
- Sensitive-action token scoring

### Reporting
- HTML and JSON output  
- ADB PoC generation  
- Severity + confidence scoring (0–100)

---

<img width="892" height="403" alt="image" src="https://github.com/user-attachments/assets/9f68e3a7-8d61-456e-b04f-a7191c065add" />

---

## Install

```bash
git clone https://github.com/actuator/pSlip.git
cd pSlip
sudo apt install apktool jadx
````

---

## Usage

```bash
# Directory sweep (full scan)
python pSlip.py . -all -html demo.html -json demo.json

# Fast sweep (skip AES/JADX)
python pSlip.py path/to/apks -allsafe -html report.htm
```

### Supported Flags

```
-all                   Full analysis (includes AES/JADX)
-allsafe               Disable AES/JADX for speed/stability
-html <file>           Write HTML report
-json <file>           Write JSON report
-aes-timeout <minutes> Time limit for AES/JADX work (default: 5)
```

---

## Tapjacking Signals

![pSlipVideo2](https://github.com/user-attachments/assets/f6481a73-11f9-4989-b4c0-b0eca4e780f1)


Tokens used for semantic scoring:

```
login | auth | verify | pay | checkout | approve
password | otp | pin | confirm | secure
submit | card | transfer | send
```

---

## Output

### **HTML Output**

* Category summaries (Hardening, Exposure, Crypto, JS Injection, URL Redirect, Permissions, Tapjacking)
* Responsive index (table on desktop, cards on mobile)
* Per-app findings with severity, confidence, and ADB PoC actions

### **JSON Output**

* Structured dataset for automation or SIEM ingestion

<img src="https://github.com/user-attachments/assets/036ab34d-4f37-43fa-934b-eb7c528843fd" />

