#!/usr/bin/env python3
"""
ADB Toolkit - Android Debug Bridge Automation
Comprehensive ADB automation for testing and analysis
For authorized security testing only
"""

import os
import sys
import subprocess
import argparse
import json
import time
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

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
    print(f"""{C.G}
    ___    ____  ____     ______            ____   _ __
   /   |  / __ \/ __ )   /_  __/___  ____  / / /__(_) /_
  / /| | / / / / __  |    / / / __ \/ __ \/ / //_/ / __/
 / ___ |/ /_/ / /_/ /    / / / /_/ / /_/ / / ,< / / /_
/_/  |_/_____/_____/    /_/  \____/\____/_/_/|_/_/\__/
{C.E}{C.Y}Android Debug Bridge Automation{C.E}
""")

class ADBToolkit:
    def __init__(self, device: str = None):
        self.device = device
        self.adb_cmd = self._find_adb()

    def _find_adb(self) -> str:
        """Find ADB binary"""
        locations = [
            '/usr/bin/adb',
            '/usr/local/bin/adb',
            os.path.expanduser('~/platform-tools/adb'),
            os.path.expanduser('~/Android/Sdk/platform-tools/adb'),
            '/opt/android-sdk/platform-tools/adb',
        ]

        for loc in locations:
            if os.path.exists(loc):
                return loc

        # Try PATH
        result = subprocess.run(['which', 'adb'], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()

        print(f"{C.R}[ERROR]{C.E} ADB not found. Install Android platform-tools.")
        sys.exit(1)

    def run(self, args: List[str], timeout: int = 30) -> tuple:
        """Run ADB command"""
        cmd = [self.adb_cmd]
        if self.device:
            cmd.extend(['-s', self.device])
        cmd.extend(args)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", 1
        except Exception as e:
            return "", str(e), 1

    def shell(self, command: str, timeout: int = 30) -> str:
        """Run shell command on device"""
        stdout, stderr, code = self.run(['shell', command], timeout)
        return stdout

    def get_devices(self) -> List[Dict]:
        """List connected devices"""
        stdout, _, _ = self.run(['devices', '-l'])
        devices = []

        for line in stdout.split('\n')[1:]:
            if line.strip() and 'device' in line:
                parts = line.split()
                device_id = parts[0]
                info = {'id': device_id}

                for part in parts[1:]:
                    if ':' in part:
                        key, val = part.split(':', 1)
                        info[key] = val

                devices.append(info)

        return devices

    def get_device_info(self) -> Dict:
        """Get comprehensive device information"""
        info = {
            'model': self.shell('getprop ro.product.model'),
            'manufacturer': self.shell('getprop ro.product.manufacturer'),
            'android_version': self.shell('getprop ro.build.version.release'),
            'sdk_version': self.shell('getprop ro.build.version.sdk'),
            'build_id': self.shell('getprop ro.build.id'),
            'security_patch': self.shell('getprop ro.build.version.security_patch'),
            'serial': self.shell('getprop ro.serialno'),
            'device': self.shell('getprop ro.product.device'),
            'brand': self.shell('getprop ro.product.brand'),
            'hardware': self.shell('getprop ro.hardware'),
            'is_rooted': self._check_root(),
            'bootloader': self.shell('getprop ro.bootloader'),
            'baseband': self.shell('getprop gsm.version.baseband'),
        }
        return info

    def _check_root(self) -> bool:
        """Check if device is rooted"""
        # Check for su binary
        su_check = self.shell('which su 2>/dev/null')
        if su_check:
            return True

        # Check for root apps
        root_apps = ['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.koushikdutta.superuser']
        packages = self.shell('pm list packages')
        for app in root_apps:
            if app in packages:
                return True

        return False

    def list_packages(self, filter_type: str = None) -> List[str]:
        """List installed packages"""
        cmd = 'pm list packages'
        if filter_type == 'system':
            cmd += ' -s'
        elif filter_type == 'third_party':
            cmd += ' -3'
        elif filter_type == 'disabled':
            cmd += ' -d'

        output = self.shell(cmd)
        packages = [line.replace('package:', '') for line in output.split('\n') if line]
        return sorted(packages)

    def get_package_info(self, package: str) -> Dict:
        """Get detailed package information"""
        info = {}

        # Basic info
        dumpsys = self.shell(f'dumpsys package {package}')

        # Extract version
        for line in dumpsys.split('\n'):
            line = line.strip()
            if line.startswith('versionName='):
                info['version'] = line.split('=')[1]
            elif line.startswith('versionCode='):
                info['version_code'] = line.split('=')[1].split()[0]
            elif line.startswith('firstInstallTime='):
                info['install_time'] = line.split('=')[1]
            elif line.startswith('lastUpdateTime='):
                info['update_time'] = line.split('=')[1]

        # Get APK path
        path_output = self.shell(f'pm path {package}')
        if path_output:
            info['apk_path'] = path_output.replace('package:', '')

        # Get permissions
        info['permissions'] = self._get_package_permissions(package)

        return info

    def _get_package_permissions(self, package: str) -> List[str]:
        """Get permissions for a package"""
        output = self.shell(f'dumpsys package {package} | grep permission')
        permissions = []
        for line in output.split('\n'):
            if 'android.permission.' in line:
                perm = line.strip().split(':')[0] if ':' in line else line.strip()
                if perm and perm not in permissions:
                    permissions.append(perm)
        return permissions

    def pull_apk(self, package: str, output_dir: str = '.') -> str:
        """Pull APK from device"""
        path_output = self.shell(f'pm path {package}')
        if not path_output:
            return None

        apk_path = path_output.replace('package:', '').strip()
        output_file = os.path.join(output_dir, f'{package}.apk')

        stdout, stderr, code = self.run(['pull', apk_path, output_file])
        if code == 0:
            return output_file
        return None

    def screenshot(self, output_file: str = None) -> str:
        """Take screenshot"""
        if not output_file:
            output_file = f'screenshot_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'

        self.shell(f'screencap -p /sdcard/screenshot.png')
        self.run(['pull', '/sdcard/screenshot.png', output_file])
        self.shell('rm /sdcard/screenshot.png')
        return output_file

    def screenrecord(self, output_file: str = None, duration: int = 10) -> str:
        """Record screen"""
        if not output_file:
            output_file = f'recording_{datetime.now().strftime("%Y%m%d_%H%M%S")}.mp4'

        remote_path = '/sdcard/recording.mp4'
        self.shell(f'screenrecord --time-limit {duration} {remote_path}')
        time.sleep(duration + 2)
        self.run(['pull', remote_path, output_file])
        self.shell(f'rm {remote_path}')
        return output_file

    def tap(self, x: int, y: int):
        """Tap at coordinates"""
        self.shell(f'input tap {x} {y}')

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration: int = 300):
        """Swipe gesture"""
        self.shell(f'input swipe {x1} {y1} {x2} {y2} {duration}')

    def text(self, text: str):
        """Input text"""
        # Escape special characters
        text = text.replace(' ', '%s').replace("'", "\\'").replace('"', '\\"')
        self.shell(f'input text "{text}"')

    def keyevent(self, keycode: int):
        """Send key event"""
        self.shell(f'input keyevent {keycode}')

    def get_logcat(self, lines: int = 100, filter_tag: str = None) -> str:
        """Get logcat output"""
        cmd = f'logcat -d -t {lines}'
        if filter_tag:
            cmd += f' -s {filter_tag}'
        return self.shell(cmd)

    def clear_logcat(self):
        """Clear logcat buffer"""
        self.shell('logcat -c')

    def get_battery_info(self) -> Dict:
        """Get battery information"""
        output = self.shell('dumpsys battery')
        info = {}
        for line in output.split('\n'):
            if ':' in line:
                key, val = line.strip().split(':', 1)
                info[key.strip()] = val.strip()
        return info

    def get_network_info(self) -> Dict:
        """Get network information"""
        info = {
            'wifi_ip': self.shell('ip addr show wlan0 | grep "inet " | awk \'{print $2}\''),
            'wifi_ssid': self.shell('dumpsys wifi | grep "mWifiInfo" | grep -o "SSID: [^,]*"'),
            'mobile_ip': self.shell('ip addr show rmnet0 | grep "inet " | awk \'{print $2}\''),
        }
        return info

    def install_apk(self, apk_path: str) -> bool:
        """Install APK"""
        stdout, stderr, code = self.run(['install', '-r', apk_path])
        return code == 0

    def uninstall_package(self, package: str) -> bool:
        """Uninstall package"""
        stdout, stderr, code = self.run(['uninstall', package])
        return code == 0

    def start_activity(self, package: str, activity: str = None):
        """Start an activity"""
        if activity:
            self.shell(f'am start -n {package}/{activity}')
        else:
            self.shell(f'monkey -p {package} -c android.intent.category.LAUNCHER 1')

    def force_stop(self, package: str):
        """Force stop an app"""
        self.shell(f'am force-stop {package}')

    def get_running_apps(self) -> List[str]:
        """Get running applications"""
        output = self.shell('ps -A | grep -E "^u[0-9]"')
        apps = set()
        for line in output.split('\n'):
            parts = line.split()
            if len(parts) > 8:
                apps.add(parts[-1])
        return sorted(list(apps))

    def backup_app(self, package: str, output_file: str = None) -> str:
        """Backup app data"""
        if not output_file:
            output_file = f'{package}_backup.ab'
        stdout, stderr, code = self.run(['backup', '-f', output_file, '-apk', package])
        if code == 0:
            return output_file
        return None

    def get_contacts(self) -> List[Dict]:
        """Get contacts (requires permissions)"""
        output = self.shell('content query --uri content://contacts/phones/')
        contacts = []
        # Parse output...
        return contacts

    def get_sms(self) -> List[Dict]:
        """Get SMS messages (requires permissions)"""
        output = self.shell('content query --uri content://sms/')
        messages = []
        # Parse output...
        return messages

    def get_call_log(self) -> List[Dict]:
        """Get call log (requires permissions)"""
        output = self.shell('content query --uri content://call_log/calls/')
        calls = []
        # Parse output...
        return calls


def main():
    parser = argparse.ArgumentParser(description='ADB Toolkit')
    parser.add_argument('-s', '--serial', help='Device serial number')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Devices
    subparsers.add_parser('devices', help='List connected devices')

    # Info
    subparsers.add_parser('info', help='Get device info')

    # Packages
    pkg_parser = subparsers.add_parser('packages', help='List packages')
    pkg_parser.add_argument('-t', '--type', choices=['system', 'third_party', 'disabled'])

    # Package info
    pkg_info = subparsers.add_parser('pkginfo', help='Get package info')
    pkg_info.add_argument('package', help='Package name')

    # Pull APK
    pull_parser = subparsers.add_parser('pull', help='Pull APK')
    pull_parser.add_argument('package', help='Package name')
    pull_parser.add_argument('-o', '--output', default='.', help='Output directory')

    # Screenshot
    ss_parser = subparsers.add_parser('screenshot', help='Take screenshot')
    ss_parser.add_argument('-o', '--output', help='Output file')

    # Screen record
    rec_parser = subparsers.add_parser('record', help='Record screen')
    rec_parser.add_argument('-o', '--output', help='Output file')
    rec_parser.add_argument('-d', '--duration', type=int, default=10, help='Duration in seconds')

    # Tap
    tap_parser = subparsers.add_parser('tap', help='Tap at coordinates')
    tap_parser.add_argument('x', type=int)
    tap_parser.add_argument('y', type=int)

    # Swipe
    swipe_parser = subparsers.add_parser('swipe', help='Swipe gesture')
    swipe_parser.add_argument('x1', type=int)
    swipe_parser.add_argument('y1', type=int)
    swipe_parser.add_argument('x2', type=int)
    swipe_parser.add_argument('y2', type=int)

    # Text
    text_parser = subparsers.add_parser('text', help='Input text')
    text_parser.add_argument('text', help='Text to input')

    # Logcat
    log_parser = subparsers.add_parser('logcat', help='Get logcat')
    log_parser.add_argument('-n', '--lines', type=int, default=100)
    log_parser.add_argument('-t', '--tag', help='Filter tag')

    # Shell
    shell_parser = subparsers.add_parser('shell', help='Run shell command')
    shell_parser.add_argument('cmd', nargs='+', help='Command to run')

    # Install
    install_parser = subparsers.add_parser('install', help='Install APK')
    install_parser.add_argument('apk', help='APK file path')

    # Battery
    subparsers.add_parser('battery', help='Get battery info')

    # Network
    subparsers.add_parser('network', help='Get network info')

    # Running apps
    subparsers.add_parser('running', help='List running apps')

    args = parser.parse_args()

    if not args.command:
        banner()
        parser.print_help()
        return

    banner()
    adb = ADBToolkit(args.serial)

    if args.command == 'devices':
        devices = adb.get_devices()
        print(f"{C.B}Connected Devices:{C.E}")
        for d in devices:
            print(f"  {C.G}{d['id']}{C.E} - {d.get('model', 'Unknown')}")

    elif args.command == 'info':
        info = adb.get_device_info()
        print(f"{C.B}Device Information:{C.E}")
        for key, val in info.items():
            color = C.R if key == 'is_rooted' and val else C.C
            print(f"  {C.Y}{key}:{C.E} {color}{val}{C.E}")

    elif args.command == 'packages':
        packages = adb.list_packages(args.type)
        print(f"{C.B}Installed Packages ({len(packages)}):{C.E}")
        for pkg in packages:
            print(f"  {pkg}")

    elif args.command == 'pkginfo':
        info = adb.get_package_info(args.package)
        print(f"{C.B}Package: {args.package}{C.E}")
        for key, val in info.items():
            if key == 'permissions':
                print(f"  {C.Y}permissions:{C.E}")
                for perm in val[:20]:
                    print(f"    {perm}")
                if len(val) > 20:
                    print(f"    ... and {len(val) - 20} more")
            else:
                print(f"  {C.Y}{key}:{C.E} {val}")

    elif args.command == 'pull':
        output = adb.pull_apk(args.package, args.output)
        if output:
            print(f"{C.G}APK saved to:{C.E} {output}")
        else:
            print(f"{C.R}Failed to pull APK{C.E}")

    elif args.command == 'screenshot':
        output = adb.screenshot(args.output)
        print(f"{C.G}Screenshot saved to:{C.E} {output}")

    elif args.command == 'record':
        print(f"{C.Y}Recording for {args.duration} seconds...{C.E}")
        output = adb.screenrecord(args.output, args.duration)
        print(f"{C.G}Recording saved to:{C.E} {output}")

    elif args.command == 'tap':
        adb.tap(args.x, args.y)
        print(f"{C.G}Tapped at ({args.x}, {args.y}){C.E}")

    elif args.command == 'swipe':
        adb.swipe(args.x1, args.y1, args.x2, args.y2)
        print(f"{C.G}Swiped from ({args.x1}, {args.y1}) to ({args.x2}, {args.y2}){C.E}")

    elif args.command == 'text':
        adb.text(args.text)
        print(f"{C.G}Text input sent{C.E}")

    elif args.command == 'logcat':
        output = adb.get_logcat(args.lines, args.tag)
        print(output)

    elif args.command == 'shell':
        output = adb.shell(' '.join(args.cmd))
        print(output)

    elif args.command == 'install':
        if adb.install_apk(args.apk):
            print(f"{C.G}APK installed successfully{C.E}")
        else:
            print(f"{C.R}Installation failed{C.E}")

    elif args.command == 'battery':
        info = adb.get_battery_info()
        print(f"{C.B}Battery Info:{C.E}")
        for key, val in info.items():
            print(f"  {C.Y}{key}:{C.E} {val}")

    elif args.command == 'network':
        info = adb.get_network_info()
        print(f"{C.B}Network Info:{C.E}")
        for key, val in info.items():
            print(f"  {C.Y}{key}:{C.E} {val}")

    elif args.command == 'running':
        apps = adb.get_running_apps()
        print(f"{C.B}Running Apps ({len(apps)}):{C.E}")
        for app in apps[:30]:
            print(f"  {app}")

if __name__ == '__main__':
    main()
