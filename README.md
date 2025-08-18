
[![License](http://img.shields.io/\:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/actuator/pSlip)](https://github.com/actuator/pSlip/releases)
[![GitHub stars](https://img.shields.io/github/stars/actuator/pSlip)](https://github.com/actuator/pSlip/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/actuator/pSlip)](https://github.com/actuator/pSlip/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/actuator/pSlip)](https://github.com/actuator/pSlip/graphs/contributors)

<img src="https://github.com/user-attachments/assets/53ff5d6f-c036-4f91-b993-84d0972a04b0" alt="pSlip banner" />

>
Whats New?:
**Tapjacking Detection**
> **Why Tapjacking in 2025?**
> Android 15 hardens OS; apps must still block obscured touches. pSlip finds tapjacking-prone controls for security and developers.


# pSlip
This tool is designed to identify Android apps that could be vulnerable instances of the 'Permission-Slip' attack; AKA a 'Confused Deputy'.

This occurs when an application is leveraged into performing actions on behalf of a less privileged app & results in elevated permissions.

---

## Highlights

*  **Exported component triage** (CALL, VIEW+`javascript:`, weak custom permissions)
*  **Tapjacking/TapTrap detector** (Compose & XML; missing obscured-touch filtering)
*  **ADB POC commands** for quick validation
*  **HTML + CSV** reports, with a **Tapjacking Portfolio**
*  **Severity & Confidence (0–100)** on each finding
*  `-allsafe` mode skips AES for fast, stable sweeps

---

## Install

```bash
git clone https://github.com/actuator/pSlip.git
cd pSlip
# tools
sudo apt install apktool jadx   
```
---

## Usage

<img src="https://github.com/user-attachments/assets/defe300c-5ec4-4906-9a9c-67d4d58f352f" />

```bash
# Directory sweep
python pSlip.py . -all -html demo.html     

# Fast sweep (skip AES/jadx)
python pSlip.py path/to/apks -allsafe -html report.htm
```

**Flags:** `-p` (permissions), `-perm`, `-js`, `-call`, `-aes`, **`-taptrap`**, **`-csv <file>`**, `-all`, `-allsafe`.

---

## Tapjacking Signals

<img alt="image" src="https://github.com/user-attachments/assets/94426bce-e3cd-4e57-a1a4-ec2fd69b7eef" />


* **High** when UI semantics match:
  `login | auth | verify | pay | checkout | approve | password | otp | pin | confirm | secure | submit | card | transfer | send`
* **Info** otherwise (defense-in-depth).
---

## Output

* **HTML**: Tapjacking Portfolio (one line per app) + detailed, sorted findings
* **CSV**: vulnerabilities CSV + `report.taptrap.apps.csv` (Tapjacking portfolio)

---

## Changelog (snapshot)

* Added **Tapjacking/TapTrap** detector (Compose + XML)
* **Severity & Confidence** scoring
* New **`-taptrap`** and **`-csv`** flags, portfolio roll-up
* Safer HTML output; clearer `jadx` errors

---

## Contribute

Pull requests are welcome, however for major changes please open an issue first to discuss what you would like to change.

I appreciate any contributions that improve the functionality and usability of the tool.
