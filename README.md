[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/actuator/pSlip)](https://github.com/actuator/pSlip/releases)
[![GitHub stars](https://img.shields.io/github/stars/actuator/pSlip)](https://github.com/actuator/pSlip/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/actuator/pSlip)](https://github.com/actuator/pSlip/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/actuator/pSlip)](https://github.com/actuator/pSlip/graphs/contributors)

<img src="https://github.com/user-attachments/assets/53ff5d6f-c036-4f91-b993-84d0972a04b0" alt="pSlip banner" />


## What’s New
**Tapjacking Detection (BETA)**  
> Android 15 hardens OS; apps must still block obscured touches.  

**AES Timeout**  
> New `-aes-timeout` flag (default 5 minutes) prevents stalls during key analysis.  

**JSON Reporting**  
> Use `-json <file>` for structured, machine-readable output. CSV has been removed.  

---

# pSlip
This tool is designed to identify Android apps that could be vulnerable to the **Permission-Slip** attack (a *Confused Deputy* scenario leading to elevated permissions).

---

## Highlights

* **Exported component triage** (CALL, VIEW+`javascript:`, weak custom permissions)  
* **Tapjacking/TapTrap detection** (Compose & XML; missing obscured-touch filtering)  
* **ADB POC commands** for quick validation  
* **HTML + JSON** reports with Tapjacking Portfolio  
* **Severity & Confidence (0–100)** scoring  
* `-allsafe` mode skips AES for fast sweeps  

---

<img src="https://github.com/user-attachments/assets/f85cd23a-e738-4438-a59a-673c349954ae" />

---

## Install

```bash
git clone https://github.com/actuator/pSlip.git
cd pSlip
sudo apt install apktool jadx
```

---

## Usage

```bash
# Directory sweep
python pSlip.py . -all -html demo.html -json demo.json

# Fast sweep (skip AES/jadx)
python pSlip.py path/to/apks -allsafe -html report.htm
```

**Flags:**  
`-p`, `-perm`, `-js`, `-call`, `-aes`, `-taptrap`, `-json <file>`, `-all`, `-allsafe`, `-aes-timeout <minutes>`

---

## Tapjacking Signals
![pslip](https://github.com/user-attachments/assets/49d028bc-36f1-4947-95cf-efbb4ac4ac96)

  `login | auth | verify | pay | checkout | approve | password | otp | pin | confirm | secure | submit | card | transfer | send`

---

## Output

* **HTML**: Tapjacking Portfolio (one line per app) + detailed findings  
* **JSON**: Full vulnerability details (machine-readable)
<img src="https://github.com/user-attachments/assets/036ab34d-4f37-43fa-934b-eb7c528843fd" />


---

## Changelog (snapshot)

* Added **Tapjacking/TapTrap** detector (Compose + XML)  
* New **`-aes-timeout`** flag (default 5 minutes)  
* Added **JSON reporting** (`-json <file>`); removed CSV  
* Improved scoring and output clarity  

---

## Contribute

Pull requests are welcome. For major changes, please open an issue first to discuss your proposal.
