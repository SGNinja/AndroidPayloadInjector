# AndroidPayloadInjector

AndroidPayloadInjector is an advanced Python tool designed to inject Metasploit payloads into legitimate Android APKs. This project is an enhanced and modified version of the original AndroidEmbedIT tool.

## Features

- Decompiles target and payload APK files
- Locates the main Activity entry point in the target APK
- Injects Metasploit payload code into the target APK
- Modifies the main Activity entry point to execute the payload
- Updates AndroidManifest.xml with necessary permissions
- Recompiles and signs the final APK

## Improvements Over Original

1. Enhanced cross-platform compatibility using `pathlib.Path` for file handling
2. Improved error handling and logging
3. More efficient XML parsing and modification using ElementTree
4. Streamlined payload injection process
5. Updated signing process to use SHA-256 instead of SHA-1
6. Improved method for identifying the main activity in AndroidManifest.xml
7. Increased randomization to enhance stealth
8. Code restructuring for better readability and maintainability
9. Updated to Python 3.6+ syntax and best practices

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
