# AndroidPayloadInjector

AndroidPayloadInjector is an advanced Python tool designed to inject Metasploit payloads into legitimate Android APKs. This project is an enhanced and modified version of the original AndroidEmbedIT tool.

## Features

- Decompiles target and payload APK files
- Locates the main Activity entry point in the target APK
- Injects Metasploit payload code into the target APK
- Modifies the main Activity entry point to execute the payload
- Updates AndroidManifest.xml with necessary permissions
- Recompiles and signs the final APK

## Requirements

- Python 3.6+
- apktool
- keytool
- jarsigner

A Kali Linux distribution is recommended for running this script.

## Usage
```bash
python android_payload_injector.py target.apk payload.apk [-ks KEYSTORE] [-kp KEYSTORE_PASS] [-ka KEY_ALIAS]
```


## Disclaimer

This tool is for educational and authorized penetration testing purposes only. Misuse of this tool may be illegal. The user is solely responsible for any consequences resulting from improper use.

## Credits

This project is based on the original AndroidEmbedIT tool by Joff Thyer (yoda66).
Original repository: https://github.com/yoda66/AndroidEmbedIT
