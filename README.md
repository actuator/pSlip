
[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/actuator/pSlip)](https://github.com/actuator/pSlip/releases)
[![GitHub stars](https://img.shields.io/github/stars/actuator/pSlip)](https://github.com/actuator/pSlip/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/actuator/pSlip)](https://github.com/actuator/pSlip/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/actuator/pSlip)](https://github.com/actuator/pSlip/graphs/contributors)

<img src="https://github.com/user-attachments/assets/53ff5d6f-c036-4f91-b993-84d0972a04b0" alt="pSlip banner" />

---

## What’s New (v1.1.2)

**Modernized HTML Report**  
A new flat, responsive layout improves readability, spacing, and dark-mode rendering.  
The Findings Index now adapts between a desktop table and mobile cards.

**Category Summaries Added**  
The report now includes summaries for:  
Hardening, Component Exposure, Crypto, JavaScript Injection, URL Redirect, Permissions, and Tapjacking.

**Updated Severity Model (Android 15)**  
Severity levels now reflect realistic exploitability under modern Android.  
Tapjacking is treated as **Informational** unless paired with sensitive actions.

**Cleaner Detail Sections**  
Improved formatting for ADB commands, severity chips, and long component names.

---

# pSlip

pSlip identifies Android applications vulnerable to **Permission-Slip / Confused-Deputy** escalation paths by analyzing exported components, intent filters, provider permissions, tapjacking vectors, and cryptographic misuse.

It is designed for application-security assessments, CI/CD pipelines, and large-scale APK analysis.

---

## Highlights

* Exported component triage  
  - CALL actions  
  - VIEW + `javascript:`  
  - HTTP/HTTPS wildcard filters  
  - Weak or unsafe custom permissions  
* Tapjacking/TapTrap detection (XML + Jetpack Compose)  
* ADB proof-of-concept command generation  
* HTML and JSON reporting with per-app summaries and detailed findings  
* Severity and confidence scoring (0–100)  
* `-allsafe` mode for fast scanning without AES/JADX work

---

<img src="https://github.com/user-attachments/assets/f85cd23a-e738-4438-a59a-673c349954ae" />

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

# Fast sweep (AES disabled)
python pSlip.py path/to/apks -allsafe -html report.htm
```

**Flags:**
`-p`, `-perm`, `-js`, `-call`, `-aes`, `-taptrap`,
`-json <file>`, `-html <file>`,
`-all`, `-allsafe`,
`-aes-timeout <minutes>`

---

## Tapjacking Signals

<img src="https://github.com/user-attachments/assets/6ceb3e6c-bf05-457a-aea8-e70ce8eb4ca1" />



Token recognition used for semantic scoring:

```
login | auth | verify | pay | checkout | approve
password | otp | pin | confirm | secure
submit | card | transfer | send
```

---

## Output

**HTML Output**

* Category summaries (Hardening, Exposure, Crypto, JS Injection, URL Redirect, Permissions, Tapjacking)
* Responsive Findings Index (desktop table + mobile cards)
* Per-app findings with severity, confidence, and ADB PoC commands

**JSON Output**

* Structured vulnerability data for ingestion and automation

<img src="https://github.com/user-attachments/assets/036ab34d-4f37-43fa-934b-eb7c528843fd" />

---
