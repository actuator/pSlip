
<img width="1100" height="400" alt="image" src="https://github.com/user-attachments/assets/43fae364-5510-4bbb-9fdd-7f869aabf98f" />

## Overview

This tool is designed to identify Android apps that could be vulnerable instances of the 'Permission-Slip' attack; AKA a 'Confused Deputy'.

This occurs when an application is leveraged into performing actions on behalf of a less privileged app & results in elevated permissions.

## Features

- Parses APK files to extract manifest information.
- Searches for exported components handling dangerous intents.
- Provides example ADB commands to test identified activities.
- Displays all permissions requested by the application.
- Scans for hardcoded AES keys and IVs in the application code.

## Dependencies

- Python 3
- [apktool](https://ibotpeaches.github.io/Apktool/) (for decoding APK files)
- [jadx](https://github.com/skylot/jadx) (for decompiling APKs, required for AES scanning)

## How It Works

By examining the application's manifest and identifying exported activities that can handle specific intents, **Permission_Slip** helps pinpoint areas where the app might be susceptible to such attacks. This enables security researchers and developers to identify and mitigate these vulnerabilities.

<img src="https://github.com/user-attachments/assets/0771775e-cda0-4e89-9be6-9a4574a0f42f">

## pSlip.py

`pSlip.py` parses APK files to extract their manifest information. It searches for:

- Exported activities that handle `android.intent.action.CALL` intents.
- Exported activities or activity-aliases with intent filters that have the `javascript` scheme.
- Hardcoded AES keys and IVs in the application code.

## Usage

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
python pSlip.py path/to/your.apk -all
```

To analyze all APK files in a directory:

```bash
python pSlip.py path/to/directory -all
```

Once potential vulnerabilities are detected, the tool generates an example ADB command to test the identified components.

**Note:** This project is a work in progress (WIP) and is currently under development.

It is important to note that this tool relies on parsing the Android manifest for intent filter entries, whose presence or absence may not be indicative of exploitability.

## Contributing

If you'd like to contribute please fork the repository, make your changes & submit a pull request. I appreciate any contributions that improve the functionality and usability of the tool.

---
