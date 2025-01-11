
[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/actuator/pSlip)](https://github.com/actuator/pSlip/releases)
[![GitHub stars](https://img.shields.io/github/stars/actuator/pSlip)](https://github.com/actuator/pSlip/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/actuator/pSlip)](https://github.com/actuator/pSlip/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/actuator/pSlip)](https://github.com/actuator/pSlip/graphs/contributors)

<img src="https://github.com/user-attachments/assets/53ff5d6f-c036-4f91-b993-84d0972a04b0">

## Overview

This tool is designed to identify Android apps that could be vulnerable instances of the 'Permission-Slip' attack; AKA a 'Confused Deputy'.

This occurs when an application is leveraged into performing actions on behalf of a less privileged app & results in elevated permissions.

## Features

- Parses APK files to extract manifest information.
- Hardcoded AES keys and IVs in the application code.
- Displays all permissions requested by the application.
- Provides example ADB commands to test identified activities.
- Exported activities that handle `android.intent.action.CALL` intents.
- Exported activities or activity-aliases with intent filters that have the `javascript` scheme.
- Exported activities intent with intent filters that require potentially vulnerable permissions that are set to a 'normal' or weak permission-level. 

## Dependencies

- Python 3
- [apktool](https://ibotpeaches.github.io/Apktool/) (for decoding APK files)
- [jadx](https://github.com/skylot/jadx) (for decompiling APKs, required for AES scanning)

## How It Works

By examining the application's manifest and identifying exported activities that can handle specific intents, **pSlip** helps pinpoint areas where the app might be susceptible to such attacks. 

This enables security researchers and developers to identify and mitigate these vulnerabilities.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/actuator/pSlip.git
   cd pSlip
   
## Usage

<img src="https://github.com/user-attachments/assets/b19fb71f-46ae-4eaf-bd0b-8aceb882317d">

The script supports the following flags:

- `-h`, `--help`    Show help message and exit.
- `-p`              List all permissions requested by the application.
- `-perm`           Scan for custom permissions with a 'normal' protection level.
- `-js`             Scan for JavaScript injection vulnerabilities.
- `-call`           Scan for components using dangerous CALL intents.
- `-aes`            Scan for hardcoded AES keys and IVs.
- `-all`            Scan for all of the above.
- `-allsafe`        Same as `-all` but skips AES check for faster scans and stability
### Example Usage

To analyze a single APK file:

```bash
python pSlip.py path/to/your.apk -js -call -html report.htm
```

To analyze all APK files in a directory:

```bash
python pSlip.py path/to/directory -all -html report.htm
```

Once potential vulnerabilities are detected, the pSlip generates POC ADB commands to test the identified components when applicable.

It is important to note that this tool relies on parsing the Android manifest for intent filter entries, whose presence or absence may not be indicative of exploitability.

## Contributing
Pull requests are welcome, however for major changes please open an issue first to discuss what you would like to change.

I appreciate any contributions that improve the functionality and usability of the tool.





