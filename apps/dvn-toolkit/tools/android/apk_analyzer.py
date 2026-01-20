#!/usr/bin/env python3
"""
APK Analyzer - Android Package Security Analysis
Analyzes APK files for security issues, permissions, and components
For authorized security testing only
"""

import os
import sys
import subprocess
import zipfile
import xml.etree.ElementTree as ET
import re
import json
import hashlib
import argparse
from pathlib import Path
from typing import List, Dict, Optional
from collections import defaultdict

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    E = '\033[0m'

def banner():
    print(f"""{C.M}
    ___    ____  __ __    ___                __
   /   |  / __ \/ //_/   /   |  ____  ____ _/ /_  ______  ___  _____
  / /| | / /_/ / ,<     / /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
 / ___ |/ ____/ /| |   / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /
/_/  |_/_/   /_/ |_|  /_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/
                                           /____/
{C.E}{C.Y}Android APK Security Analyzer{C.E}
""")

# Dangerous permissions
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS': 'Can read SMS messages',
    'android.permission.SEND_SMS': 'Can send SMS messages',
    'android.permission.RECEIVE_SMS': 'Can intercept SMS messages',
    'android.permission.READ_CONTACTS': 'Can read contacts',
    'android.permission.WRITE_CONTACTS': 'Can modify contacts',
    'android.permission.READ_CALL_LOG': 'Can read call history',
    'android.permission.WRITE_CALL_LOG': 'Can modify call history',
    'android.permission.CAMERA': 'Can access camera',
    'android.permission.RECORD_AUDIO': 'Can record audio',
    'android.permission.ACCESS_FINE_LOCATION': 'Can access precise GPS location',
    'android.permission.ACCESS_COARSE_LOCATION': 'Can access approximate location',
    'android.permission.READ_EXTERNAL_STORAGE': 'Can read external storage',
    'android.permission.WRITE_EXTERNAL_STORAGE': 'Can write to external storage',
    'android.permission.INTERNET': 'Can access internet',
    'android.permission.ACCESS_NETWORK_STATE': 'Can view network state',
    'android.permission.RECEIVE_BOOT_COMPLETED': 'Can start at boot',
    'android.permission.SYSTEM_ALERT_WINDOW': 'Can draw over other apps',
    'android.permission.REQUEST_INSTALL_PACKAGES': 'Can request app installation',
    'android.permission.READ_PHONE_STATE': 'Can read phone identifiers',
    'android.permission.CALL_PHONE': 'Can make phone calls',
    'android.permission.PROCESS_OUTGOING_CALLS': 'Can intercept outgoing calls',
    'android.permission.GET_ACCOUNTS': 'Can access accounts on device',
    'android.permission.USE_CREDENTIALS': 'Can use account credentials',
    'android.permission.AUTHENTICATE_ACCOUNTS': 'Can authenticate accounts',
    'android.permission.BIND_DEVICE_ADMIN': 'Can be device admin',
    'android.permission.PACKAGE_USAGE_STATS': 'Can monitor app usage',
    'android.permission.BIND_ACCESSIBILITY_SERVICE': 'Accessibility service (can monitor screen)',
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE': 'Can read notifications',
}

# Suspicious strings to search for
SUSPICIOUS_PATTERNS = {
    'Hardcoded URLs': [
        r'https?://[^\s"\'>]+',
    ],
    'IP Addresses': [
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    ],
    'API Keys': [
        r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]{20,}',
        r'secret["\']?\s*[:=]\s*["\']?[\w-]{20,}',
        r'token["\']?\s*[:=]\s*["\']?[\w-]{20,}',
    ],
    'AWS Keys': [
        r'AKIA[0-9A-Z]{16}',
        r'aws[_-]?secret[_-]?access[_-]?key',
    ],
    'Private Keys': [
        r'-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----',
    ],
    'SQL Queries': [
        r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.+\s+(?:FROM|INTO|SET)',
    ],
    'Crypto': [
        r'AES|DES|RSA|MD5|SHA1|SHA256',
    ],
    'Firebase': [
        r'\.firebaseio\.com',
        r'\.firebaseapp\.com',
    ],
    'Debug/Log': [
        r'Log\.[divwe]\(',
        r'System\.out\.print',
        r'printStackTrace',
    ],
}


class APKAnalyzer:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.temp_dir = None
        self.manifest = None
        self.dex_strings = []

    def analyze(self) -> Dict:
        """Run full analysis"""
        results = {
            'file_info': self.get_file_info(),
            'manifest': self.parse_manifest(),
            'permissions': self.analyze_permissions(),
            'components': self.analyze_components(),
            'security_issues': self.check_security_issues(),
            'strings': self.extract_strings(),
            'suspicious': self.find_suspicious_patterns(),
        }
        return results

    def get_file_info(self) -> Dict:
        """Get basic file information"""
        stat = os.stat(self.apk_path)
        with open(self.apk_path, 'rb') as f:
            content = f.read()
            md5 = hashlib.md5(content).hexdigest()
            sha1 = hashlib.sha1(content).hexdigest()
            sha256 = hashlib.sha256(content).hexdigest()

        return {
            'filename': os.path.basename(self.apk_path),
            'size': stat.st_size,
            'size_human': f'{stat.st_size / 1024 / 1024:.2f} MB',
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
        }

    def parse_manifest(self) -> Dict:
        """Parse AndroidManifest.xml"""
        manifest_data = {}

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Try to read AndroidManifest.xml
                if 'AndroidManifest.xml' in z.namelist():
                    # Binary XML, need to decode
                    manifest_raw = z.read('AndroidManifest.xml')

                    # Try using aapt if available
                    aapt_output = self._run_aapt()
                    if aapt_output:
                        manifest_data = self._parse_aapt_output(aapt_output)
        except Exception as e:
            manifest_data['error'] = str(e)

        return manifest_data

    def _run_aapt(self) -> str:
        """Run aapt to dump APK info"""
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'badging', self.apk_path],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout
        except:
            try:
                result = subprocess.run(
                    ['aapt2', 'dump', 'badging', self.apk_path],
                    capture_output=True, text=True, timeout=30
                )
                return result.stdout
            except:
                return ""

    def _parse_aapt_output(self, output: str) -> Dict:
        """Parse aapt output"""
        data = {}

        # Package name and version
        match = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", output)
        if match:
            data['package'] = match.group(1)
            data['version_code'] = match.group(2)
            data['version_name'] = match.group(3)

        # SDK versions
        match = re.search(r"sdkVersion:'(\d+)'", output)
        if match:
            data['min_sdk'] = match.group(1)

        match = re.search(r"targetSdkVersion:'(\d+)'", output)
        if match:
            data['target_sdk'] = match.group(1)

        # Application info
        match = re.search(r"application-label:'([^']*)'", output)
        if match:
            data['app_name'] = match.group(1)

        # Permissions
        data['permissions'] = re.findall(r"uses-permission: name='([^']+)'", output)

        # Features
        data['features'] = re.findall(r"uses-feature: name='([^']+)'", output)

        # Launchable activity
        match = re.search(r"launchable-activity: name='([^']+)'", output)
        if match:
            data['main_activity'] = match.group(1)

        return data

    def analyze_permissions(self) -> Dict:
        """Analyze permissions for security issues"""
        manifest = self.parse_manifest()
        permissions = manifest.get('permissions', [])

        analysis = {
            'total': len(permissions),
            'dangerous': [],
            'normal': [],
            'custom': [],
        }

        for perm in permissions:
            if perm in DANGEROUS_PERMISSIONS:
                analysis['dangerous'].append({
                    'permission': perm,
                    'description': DANGEROUS_PERMISSIONS[perm]
                })
            elif perm.startswith('android.permission.'):
                analysis['normal'].append(perm)
            else:
                analysis['custom'].append(perm)

        return analysis

    def analyze_components(self) -> Dict:
        """Analyze app components"""
        components = {
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': [],
            'exported': []
        }

        # Use aapt to get components
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'xmltree', self.apk_path, 'AndroidManifest.xml'],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout

            # Parse activities
            activity_matches = re.findall(r'E: activity.*?(?=E: (?:activity|service|receiver|provider)|$)', output, re.DOTALL)
            for match in activity_matches:
                name_match = re.search(r'A: android:name.*?"([^"]+)"', match)
                exported_match = re.search(r'A: android:exported.*?=([^\s]+)', match)

                if name_match:
                    activity = {'name': name_match.group(1)}
                    if exported_match and 'true' in exported_match.group(1).lower():
                        activity['exported'] = True
                        components['exported'].append(f"Activity: {activity['name']}")
                    components['activities'].append(activity)

        except Exception as e:
            components['error'] = str(e)

        return components

    def check_security_issues(self) -> List[Dict]:
        """Check for common security issues"""
        issues = []

        manifest = self.parse_manifest()

        # Check debuggable
        if 'android:debuggable="true"' in str(manifest):
            issues.append({
                'severity': 'HIGH',
                'issue': 'Application is debuggable',
                'description': 'Debuggable apps can be attached to debugger, exposing sensitive data'
            })

        # Check backup
        if manifest.get('allowBackup', 'true') != 'false':
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Application allows backup',
                'description': 'App data can be extracted via adb backup'
            })

        # Check network security config
        if int(manifest.get('target_sdk', '0')) >= 28:
            issues.append({
                'severity': 'INFO',
                'issue': 'Check Network Security Config',
                'description': 'Verify cleartext traffic settings'
            })

        # Check exported components
        components = self.analyze_components()
        if components.get('exported'):
            issues.append({
                'severity': 'MEDIUM',
                'issue': f'Exported components: {len(components["exported"])}',
                'description': 'Review exported components for potential vulnerabilities'
            })

        # Check dangerous permissions
        permissions = self.analyze_permissions()
        if len(permissions.get('dangerous', [])) > 10:
            issues.append({
                'severity': 'HIGH',
                'issue': f'Excessive dangerous permissions: {len(permissions["dangerous"])}',
                'description': 'App requests many dangerous permissions'
            })

        return issues

    def extract_strings(self) -> Dict:
        """Extract strings from DEX files"""
        strings = {
            'urls': [],
            'ips': [],
            'emails': [],
            'files': [],
        }

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for name in z.namelist():
                    if name.endswith('.dex'):
                        dex_content = z.read(name)
                        # Extract printable strings
                        text = dex_content.decode('utf-8', errors='ignore')

                        # URLs
                        urls = re.findall(r'https?://[^\s"\'<>]+', text)
                        strings['urls'].extend(urls[:50])

                        # IPs
                        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
                        strings['ips'].extend([ip for ip in ips if not ip.startswith('0.') and not ip.startswith('127.')])

                        # Emails
                        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
                        strings['emails'].extend(emails[:20])

        except Exception as e:
            strings['error'] = str(e)

        # Deduplicate
        strings['urls'] = list(set(strings['urls']))[:30]
        strings['ips'] = list(set(strings['ips']))[:20]
        strings['emails'] = list(set(strings['emails']))[:20]

        return strings

    def find_suspicious_patterns(self) -> Dict:
        """Search for suspicious patterns"""
        findings = defaultdict(list)

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for name in z.namelist():
                    if name.endswith('.dex') or name.endswith('.so'):
                        content = z.read(name)
                        text = content.decode('utf-8', errors='ignore')

                        for category, patterns in SUSPICIOUS_PATTERNS.items():
                            for pattern in patterns:
                                matches = re.findall(pattern, text, re.IGNORECASE)
                                if matches:
                                    for match in matches[:5]:
                                        if len(match) < 200:
                                            findings[category].append(match)
        except Exception as e:
            findings['error'] = [str(e)]

        # Deduplicate and limit
        return {k: list(set(v))[:10] for k, v in findings.items()}


def print_results(results: Dict):
    """Print analysis results"""

    # File Info
    print(f"\n{C.B}[File Information]{C.E}")
    info = results['file_info']
    print(f"  Filename: {info['filename']}")
    print(f"  Size: {info['size_human']}")
    print(f"  MD5: {info['md5']}")
    print(f"  SHA256: {info['sha256']}")

    # Manifest
    print(f"\n{C.B}[Manifest Info]{C.E}")
    manifest = results['manifest']
    if manifest:
        print(f"  Package: {manifest.get('package', 'N/A')}")
        print(f"  Version: {manifest.get('version_name', 'N/A')} ({manifest.get('version_code', 'N/A')})")
        print(f"  Min SDK: {manifest.get('min_sdk', 'N/A')}")
        print(f"  Target SDK: {manifest.get('target_sdk', 'N/A')}")
        print(f"  Main Activity: {manifest.get('main_activity', 'N/A')}")

    # Permissions
    print(f"\n{C.B}[Permissions Analysis]{C.E}")
    perms = results['permissions']
    print(f"  Total: {perms['total']}")
    print(f"  {C.R}Dangerous: {len(perms['dangerous'])}{C.E}")
    for dp in perms['dangerous'][:10]:
        print(f"    {C.Y}{dp['permission']}{C.E}")
        print(f"      {dp['description']}")

    # Security Issues
    print(f"\n{C.B}[Security Issues]{C.E}")
    for issue in results['security_issues']:
        color = C.R if issue['severity'] == 'HIGH' else C.Y if issue['severity'] == 'MEDIUM' else C.C
        print(f"  {color}[{issue['severity']}]{C.E} {issue['issue']}")
        print(f"    {issue['description']}")

    # Strings
    print(f"\n{C.B}[Extracted Strings]{C.E}")
    strings = results['strings']
    if strings.get('urls'):
        print(f"  {C.C}URLs found:{C.E}")
        for url in strings['urls'][:10]:
            print(f"    {url[:80]}")

    if strings.get('ips'):
        print(f"  {C.C}IP Addresses:{C.E}")
        for ip in strings['ips'][:10]:
            print(f"    {ip}")

    # Suspicious patterns
    print(f"\n{C.B}[Suspicious Patterns]{C.E}")
    suspicious = results['suspicious']
    for category, items in suspicious.items():
        if items and category != 'error':
            print(f"  {C.Y}{category}:{C.E}")
            for item in items[:5]:
                print(f"    {item[:60]}")


def main():
    parser = argparse.ArgumentParser(description='APK Security Analyzer')
    parser.add_argument('apk', help='APK file to analyze')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (JSON only)')
    args = parser.parse_args()

    if not os.path.exists(args.apk):
        print(f"{C.R}[ERROR]{C.E} File not found: {args.apk}")
        sys.exit(1)

    if not args.quiet:
        banner()

    analyzer = APKAnalyzer(args.apk)
    results = analyzer.analyze()

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"{C.G}Results saved to:{C.E} {args.output}")

    if not args.quiet:
        print_results(results)

if __name__ == '__main__':
    main()
