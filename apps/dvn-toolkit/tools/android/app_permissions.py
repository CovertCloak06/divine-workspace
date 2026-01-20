#!/usr/bin/env python3
"""
Android App Permissions Scanner
Scans installed apps and their permissions for security analysis
"""

import os
import sys
import subprocess
import argparse
import json
from collections import defaultdict
from typing import List, Dict, Optional

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    E = '\033[0m'

# Dangerous permission categories
PERMISSION_CATEGORIES = {
    'LOCATION': {
        'permissions': [
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.ACCESS_BACKGROUND_LOCATION',
        ],
        'risk': 'HIGH',
        'description': 'Can track your location'
    },
    'CAMERA': {
        'permissions': [
            'android.permission.CAMERA',
        ],
        'risk': 'HIGH',
        'description': 'Can access camera'
    },
    'MICROPHONE': {
        'permissions': [
            'android.permission.RECORD_AUDIO',
            'android.permission.CAPTURE_AUDIO_OUTPUT',
        ],
        'risk': 'HIGH',
        'description': 'Can record audio'
    },
    'CONTACTS': {
        'permissions': [
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.GET_ACCOUNTS',
        ],
        'risk': 'HIGH',
        'description': 'Can access contacts'
    },
    'SMS': {
        'permissions': [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.RECEIVE_MMS',
        ],
        'risk': 'CRITICAL',
        'description': 'Can read/send SMS'
    },
    'PHONE': {
        'permissions': [
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.PROCESS_OUTGOING_CALLS',
        ],
        'risk': 'HIGH',
        'description': 'Can access phone/calls'
    },
    'STORAGE': {
        'permissions': [
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.MANAGE_EXTERNAL_STORAGE',
        ],
        'risk': 'MEDIUM',
        'description': 'Can access storage'
    },
    'NETWORK': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE',
        ],
        'risk': 'LOW',
        'description': 'Can access network'
    },
    'SYSTEM': {
        'permissions': [
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.REQUEST_INSTALL_PACKAGES',
            'android.permission.WRITE_SETTINGS',
            'android.permission.BIND_DEVICE_ADMIN',
            'android.permission.BIND_ACCESSIBILITY_SERVICE',
            'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
        ],
        'risk': 'CRITICAL',
        'description': 'System-level access'
    },
    'BOOT': {
        'permissions': [
            'android.permission.RECEIVE_BOOT_COMPLETED',
        ],
        'risk': 'LOW',
        'description': 'Can start at boot'
    },
}

def run_adb(args: List[str], timeout: int = 30) -> str:
    """Run ADB command"""
    try:
        cmd = ['adb'] + args
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except:
        return ""

def get_installed_packages(pkg_type: str = None) -> List[str]:
    """Get list of installed packages"""
    cmd = ['shell', 'pm', 'list', 'packages']
    if pkg_type == 'system':
        cmd.append('-s')
    elif pkg_type == 'third_party':
        cmd.append('-3')

    output = run_adb(cmd)
    packages = [line.replace('package:', '') for line in output.split('\n') if line]
    return sorted(packages)

def get_package_permissions(package: str) -> List[str]:
    """Get permissions for a package"""
    output = run_adb(['shell', 'dumpsys', 'package', package])
    permissions = []

    in_perms = False
    for line in output.split('\n'):
        line = line.strip()
        if 'requested permissions:' in line.lower():
            in_perms = True
            continue
        elif 'install permissions:' in line.lower() or line.startswith('User '):
            in_perms = False

        if in_perms and line.startswith('android.permission.'):
            permissions.append(line)

    return permissions

def get_granted_permissions(package: str) -> List[str]:
    """Get runtime permissions granted to package"""
    output = run_adb(['shell', 'dumpsys', 'package', package])
    granted = []

    for line in output.split('\n'):
        if 'granted=true' in line:
            match = line.split(':')[0].strip()
            if 'permission' in match.lower():
                granted.append(match.split('.')[-1] if '.' in match else match)

    return granted

def categorize_permissions(permissions: List[str]) -> Dict:
    """Categorize permissions by type"""
    categorized = defaultdict(list)

    for perm in permissions:
        found = False
        for category, info in PERMISSION_CATEGORIES.items():
            if perm in info['permissions']:
                categorized[category].append(perm)
                found = True
                break
        if not found:
            categorized['OTHER'].append(perm)

    return dict(categorized)

def calculate_risk_score(permissions: List[str]) -> int:
    """Calculate risk score based on permissions"""
    score = 0

    for perm in permissions:
        for category, info in PERMISSION_CATEGORIES.items():
            if perm in info['permissions']:
                if info['risk'] == 'CRITICAL':
                    score += 30
                elif info['risk'] == 'HIGH':
                    score += 15
                elif info['risk'] == 'MEDIUM':
                    score += 5
                elif info['risk'] == 'LOW':
                    score += 1
                break

    return min(score, 100)

def analyze_app(package: str) -> Dict:
    """Analyze a single app"""
    permissions = get_package_permissions(package)
    categorized = categorize_permissions(permissions)
    risk_score = calculate_risk_score(permissions)

    return {
        'package': package,
        'total_permissions': len(permissions),
        'permissions': permissions,
        'categorized': categorized,
        'risk_score': risk_score,
    }

def print_app_report(app: Dict):
    """Print app analysis report"""
    risk_color = C.G if app['risk_score'] < 30 else C.Y if app['risk_score'] < 60 else C.R

    print(f"\n{C.B}Package:{C.E} {app['package']}")
    print(f"{C.B}Risk Score:{C.E} {risk_color}{app['risk_score']}/100{C.E}")
    print(f"{C.B}Total Permissions:{C.E} {app['total_permissions']}")

    if app['categorized']:
        print(f"\n{C.C}Permissions by Category:{C.E}")
        for category, perms in app['categorized'].items():
            if perms:
                info = PERMISSION_CATEGORIES.get(category, {'risk': 'LOW', 'description': 'Other'})
                risk_color = C.R if info['risk'] == 'CRITICAL' else C.Y if info['risk'] == 'HIGH' else C.G

                print(f"  {risk_color}[{info['risk']}]{C.E} {category} ({info.get('description', '')})")
                for perm in perms:
                    print(f"    - {perm.split('.')[-1]}")

def find_risky_apps(packages: List[str], threshold: int = 50) -> List[Dict]:
    """Find apps with high risk scores"""
    risky = []

    for i, pkg in enumerate(packages, 1):
        print(f"\r  Scanning {i}/{len(packages)}: {pkg[:40]}...", end='', flush=True)
        app = analyze_app(pkg)
        if app['risk_score'] >= threshold:
            risky.append(app)

    print()
    return sorted(risky, key=lambda x: x['risk_score'], reverse=True)

def find_apps_with_permission(packages: List[str], permission: str) -> List[str]:
    """Find apps with specific permission"""
    apps = []

    for i, pkg in enumerate(packages, 1):
        print(f"\r  Scanning {i}/{len(packages)}...", end='', flush=True)
        perms = get_package_permissions(pkg)
        if any(permission.lower() in p.lower() for p in perms):
            apps.append(pkg)

    print()
    return apps

def main():
    parser = argparse.ArgumentParser(description='Android App Permissions Scanner')
    parser.add_argument('-p', '--package', help='Analyze specific package')
    parser.add_argument('-t', '--type', choices=['system', 'third_party', 'all'], default='third_party',
                       help='Package type to scan')
    parser.add_argument('-r', '--risky', type=int, metavar='THRESHOLD',
                       help='Find apps with risk score above threshold')
    parser.add_argument('-f', '--find', help='Find apps with specific permission')
    parser.add_argument('-l', '--list', action='store_true', help='List all packages')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--top', type=int, default=20, help='Number of results to show')
    args = parser.parse_args()

    print(f"{C.M}Android App Permissions Scanner{C.E}")
    print(f"{C.Y}Analyzing installed applications...{C.E}\n")

    # Check ADB connection
    devices = run_adb(['devices'])
    if 'device' not in devices:
        print(f"{C.R}[ERROR]{C.E} No device connected. Connect via ADB first.")
        sys.exit(1)

    results = {}

    if args.package:
        # Analyze specific package
        print(f"{C.B}Analyzing:{C.E} {args.package}")
        app = analyze_app(args.package)
        print_app_report(app)
        results = app

    elif args.list:
        # List all packages
        pkg_type = None if args.type == 'all' else args.type
        packages = get_installed_packages(pkg_type)
        print(f"{C.B}Installed Packages ({len(packages)}):{C.E}")
        for pkg in packages:
            print(f"  {pkg}")
        results = {'packages': packages}

    elif args.find:
        # Find apps with specific permission
        pkg_type = None if args.type == 'all' else args.type
        packages = get_installed_packages(pkg_type)
        print(f"{C.B}Searching for permission:{C.E} {args.find}")
        apps = find_apps_with_permission(packages, args.find)
        print(f"\n{C.B}Apps with '{args.find}' ({len(apps)}):{C.E}")
        for app in apps:
            print(f"  {app}")
        results = {'permission': args.find, 'apps': apps}

    elif args.risky:
        # Find risky apps
        pkg_type = None if args.type == 'all' else args.type
        packages = get_installed_packages(pkg_type)
        print(f"{C.B}Scanning {len(packages)} apps for risk score >= {args.risky}...{C.E}")
        risky = find_risky_apps(packages, args.risky)

        print(f"\n{C.R}High Risk Apps ({len(risky)}):{C.E}")
        for app in risky[:args.top]:
            risk_color = C.R if app['risk_score'] >= 70 else C.Y
            print(f"  {risk_color}[{app['risk_score']}]{C.E} {app['package']}")

        results = {'risky_apps': risky}

    else:
        # Default: scan all third-party apps
        pkg_type = None if args.type == 'all' else args.type
        packages = get_installed_packages(pkg_type)
        print(f"{C.B}Scanning {len(packages)} apps...{C.E}")

        all_apps = []
        for i, pkg in enumerate(packages, 1):
            print(f"\r  Progress: {i}/{len(packages)}", end='', flush=True)
            app = analyze_app(pkg)
            all_apps.append(app)
        print()

        # Sort by risk
        all_apps.sort(key=lambda x: x['risk_score'], reverse=True)

        print(f"\n{C.B}Top {args.top} Riskiest Apps:{C.E}")
        for app in all_apps[:args.top]:
            risk_color = C.R if app['risk_score'] >= 70 else C.Y if app['risk_score'] >= 40 else C.G
            print(f"  {risk_color}[{app['risk_score']:3d}]{C.E} {app['package']}")

        # Summary
        print(f"\n{C.B}Summary:{C.E}")
        critical = len([a for a in all_apps if a['risk_score'] >= 70])
        high = len([a for a in all_apps if 40 <= a['risk_score'] < 70])
        medium = len([a for a in all_apps if 20 <= a['risk_score'] < 40])
        low = len([a for a in all_apps if a['risk_score'] < 20])

        print(f"  {C.R}Critical (70+):{C.E} {critical}")
        print(f"  {C.Y}High (40-69):{C.E} {high}")
        print(f"  {C.C}Medium (20-39):{C.E} {medium}")
        print(f"  {C.G}Low (<20):{C.E} {low}")

        results = {'apps': all_apps}

    # Export
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n{C.G}Results saved to:{C.E} {args.output}")

if __name__ == '__main__':
    main()
