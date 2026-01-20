#!/usr/bin/env python3
"""
DVN Toolkit - Android App
130+ security and utility tools in one app
Hybrid UI with modern buttons and terminal output
For authorized security testing only
"""

import os
import sys
import subprocess
import threading
from datetime import datetime

# Kivy configuration - must be before other kivy imports
os.environ['KIVY_LOG_LEVEL'] = 'warning'
from kivy.config import Config
Config.set('graphics', 'width', '400')
Config.set('graphics', 'height', '700')
Config.set('kivy', 'keyboard_mode', 'system')

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.spinner import Spinner
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.properties import StringProperty, ListProperty, DictProperty
from kivy.utils import get_color_from_hex
from kivy.core.window import Window

# Theme definitions
THEMES = {
    'cyberpunk': {
        'name': 'Cyberpunk',
        'bg': '#0a0a12',
        'bg_secondary': '#12121f',
        'accent': '#00ff9f',
        'accent_secondary': '#ff00ff',
        'text': '#ffffff',
        'text_dim': '#888899',
        'terminal_bg': '#050508',
        'terminal_text': '#00ff9f',
        'button_bg': '#1a1a2e',
        'button_pressed': '#2a2a4e',
        'danger': '#ff4444',
        'warning': '#ffaa00',
        'success': '#00ff9f',
    },
    'matrix': {
        'name': 'Matrix',
        'bg': '#000000',
        'bg_secondary': '#0a0a0a',
        'accent': '#00ff00',
        'accent_secondary': '#00aa00',
        'text': '#00ff00',
        'text_dim': '#006600',
        'terminal_bg': '#000000',
        'terminal_text': '#00ff00',
        'button_bg': '#001100',
        'button_pressed': '#002200',
        'danger': '#ff0000',
        'warning': '#ffff00',
        'success': '#00ff00',
    },
    'hacker': {
        'name': 'Hacker Red',
        'bg': '#0a0000',
        'bg_secondary': '#120000',
        'accent': '#ff0040',
        'accent_secondary': '#ff4080',
        'text': '#ffffff',
        'text_dim': '#aa6666',
        'terminal_bg': '#050000',
        'terminal_text': '#ff0040',
        'button_bg': '#1a0010',
        'button_pressed': '#2a0020',
        'danger': '#ff0000',
        'warning': '#ff8800',
        'success': '#00ff88',
    },
    'ocean': {
        'name': 'Ocean Blue',
        'bg': '#0a1628',
        'bg_secondary': '#0f1e30',
        'accent': '#00d4ff',
        'accent_secondary': '#0088ff',
        'text': '#ffffff',
        'text_dim': '#668899',
        'terminal_bg': '#050d18',
        'terminal_text': '#00d4ff',
        'button_bg': '#102030',
        'button_pressed': '#1a3050',
        'danger': '#ff4466',
        'warning': '#ffcc00',
        'success': '#00ff88',
    },
    'light': {
        'name': 'Light Mode',
        'bg': '#f5f5f5',
        'bg_secondary': '#ffffff',
        'accent': '#2196F3',
        'accent_secondary': '#1976D2',
        'text': '#212121',
        'text_dim': '#757575',
        'terminal_bg': '#263238',
        'terminal_text': '#80CBC4',
        'button_bg': '#e0e0e0',
        'button_pressed': '#bdbdbd',
        'danger': '#f44336',
        'warning': '#FF9800',
        'success': '#4CAF50',
    },
}

# Tool definitions with categories - All 130+ tools organized by category
TOOLS = {
    # === OFFENSIVE SECURITY ===
    'offensive': {
        'name': 'Offensive Security',
        'icon': '[OFF]',
        'category': 'offensive',
        'tools': [
            {'id': 'nmap_lite', 'name': 'Port Scanner', 'script': 'nmap_lite.py', 'desc': 'Network port scanning with service detection'},
            {'id': 'dns_enum', 'name': 'DNS Enum', 'script': 'dns_enum.py', 'desc': 'DNS enumeration and subdomain discovery'},
            {'id': 'sqli_scanner', 'name': 'SQLi Scanner', 'script': 'sqli_scanner.py', 'desc': 'SQL injection vulnerability testing'},
            {'id': 'xss_scanner', 'name': 'XSS Scanner', 'script': 'xss_scanner.py', 'desc': 'Cross-site scripting detection'},
            {'id': 'lfi_scanner', 'name': 'LFI Scanner', 'script': 'lfi_scanner.py', 'desc': 'Local/remote file inclusion testing'},
            {'id': 'web_fuzzer', 'name': 'Web Fuzzer', 'script': 'web_fuzzer.py', 'desc': 'Directory and file enumeration'},
            {'id': 'bruteforce', 'name': 'Bruteforce', 'script': 'bruteforce.py', 'desc': 'Credential brute force testing'},
            {'id': 'reverse_shells', 'name': 'Reverse Shells', 'script': 'reverse_shells.py', 'desc': 'Generate reverse shell payloads'},
            {'id': 'webshell_gen', 'name': 'Webshell Gen', 'script': 'webshell_gen.py', 'desc': 'Generate webshell files'},
            {'id': 'hash_toolkit', 'name': 'Hash Toolkit', 'script': 'hash_toolkit.py', 'desc': 'Hash identification and cracking'},
            {'id': 'wordlist_gen', 'name': 'Wordlist Gen', 'script': 'wordlist_gen.py', 'desc': 'Custom wordlist generator'},
            {'id': 'payload_encoder', 'name': 'Payload Encoder', 'script': 'payload_encoder.py', 'desc': 'Encode payloads for bypass'},
            {'id': 'smb_enum', 'name': 'SMB Enum', 'script': 'smb_enum.py', 'desc': 'Windows SMB share enumeration'},
        ]
    },
    # === SECURITY TOOLS ===
    'security': {
        'name': 'Security Tools',
        'icon': '[SEC]',
        'category': 'security',
        'tools': [
            {'id': 'creds', 'name': 'Credential Check', 'script': 'creds.py', 'desc': 'Password strength and breach check'},
            {'id': 'dirfuzz', 'name': 'Dir Fuzzer', 'script': 'dirfuzz.py', 'desc': 'Web directory enumeration'},
            {'id': 'encoder', 'name': 'Encoder', 'script': 'encoder.py', 'desc': 'Multi-format encoding/decoding'},
            {'id': 'hashcrack', 'name': 'Hash Crack', 'script': 'hashcrack.py', 'desc': 'Hash cracking with wordlists'},
            {'id': 'hasher', 'name': 'Hasher', 'script': 'hasher.py', 'desc': 'Generate and identify hashes'},
            {'id': 'netsniff', 'name': 'Net Sniffer', 'script': 'netsniff.py', 'desc': 'Network packet sniffer'},
            {'id': 'password_gen', 'name': 'Password Gen', 'script': 'password_gen.py', 'desc': 'Secure password generator'},
            {'id': 'payloads', 'name': 'Payloads', 'script': 'payloads.py', 'desc': 'Security testing payloads'},
            {'id': 'portscan_adv', 'name': 'Port Scan Adv', 'script': 'portscan_adv.py', 'desc': 'Advanced port scanner'},
            {'id': 'recon', 'name': 'Recon', 'script': 'recon.py', 'desc': 'Target reconnaissance'},
            {'id': 'stego', 'name': 'Steganography', 'script': 'stego.py', 'desc': 'Hide data in images'},
            {'id': 'subenum', 'name': 'Subdomain Enum', 'script': 'subenum.py', 'desc': 'Subdomain enumeration'},
            {'id': 'techdetect', 'name': 'Tech Detect', 'script': 'techdetect.py', 'desc': 'Detect web technologies'},
            {'id': 'webscrape', 'name': 'Web Scraper', 'script': 'webscrape.py', 'desc': 'Web page scraping'},
        ]
    },
    # === NETWORK TOOLS ===
    'network': {
        'name': 'Network Tools',
        'icon': '[NET]',
        'category': 'network',
        'tools': [
            {'id': 'arp_scan', 'name': 'ARP Scan', 'script': 'arp_scan.py', 'desc': 'ARP network scanner'},
            {'id': 'bandwidth', 'name': 'Bandwidth', 'script': 'bandwidth.py', 'desc': 'Bandwidth monitor'},
            {'id': 'banner_grab', 'name': 'Banner Grab', 'script': 'banner_grab.py', 'desc': 'Service banner grabber'},
            {'id': 'dns_lookup', 'name': 'DNS Lookup', 'script': 'dns_lookup.py', 'desc': 'DNS record lookup'},
            {'id': 'domain_recon', 'name': 'Domain Recon', 'script': 'domain_recon.py', 'desc': 'Domain reconnaissance'},
            {'id': 'email_osint', 'name': 'Email OSINT', 'script': 'email_osint.py', 'desc': 'Email OSINT lookup'},
            {'id': 'header_analyzer', 'name': 'Header Analyzer', 'script': 'header_analyzer.py', 'desc': 'HTTP header analysis'},
            {'id': 'http_server', 'name': 'HTTP Server', 'script': 'http_server.py', 'desc': 'Quick HTTP server'},
            {'id': 'ip_geolocate', 'name': 'IP Geolocate', 'script': 'ip_geolocate.py', 'desc': 'IP geolocation lookup'},
            {'id': 'mac_lookup', 'name': 'MAC Lookup', 'script': 'mac_lookup.py', 'desc': 'MAC address lookup'},
            {'id': 'net_monitor', 'name': 'Net Monitor', 'script': 'net_monitor.py', 'desc': 'Network traffic monitor'},
            {'id': 'ping_sweep', 'name': 'Ping Sweep', 'script': 'ping_sweep.py', 'desc': 'Network ping sweep'},
            {'id': 'portscanner', 'name': 'Port Scanner', 'script': 'portscanner.py', 'desc': 'Basic port scanner'},
            {'id': 'reverse_dns', 'name': 'Reverse DNS', 'script': 'reverse_dns.py', 'desc': 'Reverse DNS lookup'},
            {'id': 'social_recon', 'name': 'Social Recon', 'script': 'social_recon.py', 'desc': 'Social media recon'},
            {'id': 'speedtest', 'name': 'Speed Test', 'script': 'speedtest.py', 'desc': 'Internet speed test'},
            {'id': 'ssh_manager', 'name': 'SSH Manager', 'script': 'ssh_manager.py', 'desc': 'SSH connection manager'},
            {'id': 'ssl_check', 'name': 'SSL Check', 'script': 'ssl_check.py', 'desc': 'SSL certificate checker'},
            {'id': 'subnet_calc', 'name': 'Subnet Calc', 'script': 'subnet_calc.py', 'desc': 'Subnet calculator'},
            {'id': 'traceroute', 'name': 'Traceroute', 'script': 'traceroute_visual.py', 'desc': 'Visual traceroute'},
            {'id': 'username_search', 'name': 'Username Search', 'script': 'username_search.py', 'desc': 'Username OSINT search'},
            {'id': 'whois', 'name': 'WHOIS', 'script': 'whois_lookup.py', 'desc': 'WHOIS domain lookup'},
            {'id': 'wifi_scan', 'name': 'WiFi Scan', 'script': 'wifi_scan.py', 'desc': 'WiFi network scanner'},
            {'id': 'wol', 'name': 'Wake on LAN', 'script': 'wol.py', 'desc': 'Wake on LAN utility'},
        ]
    },
    # === PENTEST TOOLS ===
    'pentest': {
        'name': 'Linux Pentest',
        'icon': '[PEN]',
        'category': 'pentest',
        'tools': [
            {'id': 'privesc', 'name': 'PrivEsc Checker', 'script': 'privesc_checker.py', 'desc': 'Find privilege escalation vectors'},
            {'id': 'persistence', 'name': 'Persistence Check', 'script': 'persistence_checker.py', 'desc': 'Detect backdoors and persistence'},
            {'id': 'kernel', 'name': 'Kernel Exploits', 'script': 'kernel_exploits.py', 'desc': 'Suggest kernel exploits'},
        ]
    },
    # === ANDROID TOOLS ===
    'android': {
        'name': 'Android Security',
        'icon': '[AND]',
        'category': 'android',
        'tools': [
            {'id': 'adb', 'name': 'ADB Toolkit', 'script': 'adb_toolkit.py', 'desc': 'ADB automation commands'},
            {'id': 'apk', 'name': 'APK Analyzer', 'script': 'apk_analyzer.py', 'desc': 'APK security analysis'},
            {'id': 'logcat', 'name': 'Logcat Parser', 'script': 'logcat_parser.py', 'desc': 'Parse logcat for secrets'},
            {'id': 'permissions', 'name': 'App Permissions', 'script': 'app_permissions.py', 'desc': 'Scan app permissions'},
        ]
    },
    # === CRYPTO TOOLS ===
    'crypto': {
        'name': 'Cryptography',
        'icon': '[CRY]',
        'category': 'crypto',
        'tools': [
            {'id': 'baseconv', 'name': 'Base Convert', 'script': 'baseconv.py', 'desc': 'Base conversion tool'},
            {'id': 'cipher', 'name': 'Cipher', 'script': 'cipher.py', 'desc': 'Classical ciphers'},
            {'id': 'encrypt', 'name': 'Encrypt', 'script': 'encrypt.py', 'desc': 'File encryption'},
        ]
    },
    # === OSINT TOOLS ===
    'osint': {
        'name': 'OSINT',
        'icon': '[OSI]',
        'category': 'osint',
        'tools': [
            {'id': 'google_dork', 'name': 'Google Dork', 'script': 'google_dork.py', 'desc': 'Google dork generator'},
            {'id': 'username_check', 'name': 'Username Check', 'script': 'username_check.py', 'desc': 'Username availability check'},
        ]
    },
    # === FORENSICS ===
    'forensics': {
        'name': 'Forensics',
        'icon': '[FOR]',
        'category': 'forensics',
        'tools': [
            {'id': 'hexview', 'name': 'Hex Viewer', 'script': 'hexview.py', 'desc': 'Hex file viewer'},
        ]
    },
    # === WEB TOOLS ===
    'web': {
        'name': 'Web Tools',
        'icon': '[WEB]',
        'category': 'web',
        'tools': [
            {'id': 'jwt', 'name': 'JWT Decode', 'script': 'jwt_decode.py', 'desc': 'JWT token decoder'},
            {'id': 'regex', 'name': 'Regex Test', 'script': 'regex_test.py', 'desc': 'Regex pattern tester'},
        ]
    },
    # === CLI UTILITIES ===
    'cli': {
        'name': 'CLI Utilities',
        'icon': '[CLI]',
        'category': 'cli',
        'tools': [
            {'id': 'apitest', 'name': 'API Test', 'script': 'apitest.py', 'desc': 'API endpoint tester'},
            {'id': 'asciiart', 'name': 'ASCII Art', 'script': 'asciiart.py', 'desc': 'ASCII art generator'},
            {'id': 'calc', 'name': 'Calculator', 'script': 'calc.py', 'desc': 'Command line calculator'},
            {'id': 'clipboard', 'name': 'Clipboard', 'script': 'clipboard.py', 'desc': 'Clipboard manager'},
            {'id': 'filefinder', 'name': 'File Finder', 'script': 'filefinder.py', 'desc': 'Find duplicate files'},
            {'id': 'fileorg', 'name': 'File Organizer', 'script': 'fileorg.py', 'desc': 'Organize files by type'},
            {'id': 'gitstat', 'name': 'Git Stats', 'script': 'gitstat.py', 'desc': 'Git repository stats'},
            {'id': 'jsonfmt', 'name': 'JSON Format', 'script': 'jsonfmt.py', 'desc': 'JSON formatter'},
            {'id': 'logparse', 'name': 'Log Parser', 'script': 'logparse.py', 'desc': 'Log file parser'},
            {'id': 'portscanner_cli', 'name': 'Port Scanner', 'script': 'portscanner.py', 'desc': 'Basic port scanner'},
            {'id': 'pwgen', 'name': 'Password Gen', 'script': 'pwgen.py', 'desc': 'Password generator'},
            {'id': 'qrcode', 'name': 'QR Code', 'script': 'qrcode.py', 'desc': 'QR code generator'},
            {'id': 'qserver', 'name': 'Quick Server', 'script': 'qserver.py', 'desc': 'Quick HTTP server'},
            {'id': 'sysmon', 'name': 'System Monitor', 'script': 'sysmon.py', 'desc': 'System resource monitor'},
            {'id': 'weather', 'name': 'Weather', 'script': 'weather.py', 'desc': 'Weather lookup'},
        ]
    },
    # === DEV TOOLS ===
    'dev': {
        'name': 'Developer Tools',
        'icon': '[DEV]',
        'category': 'dev',
        'tools': [
            {'id': 'curl_builder', 'name': 'cURL Builder', 'script': 'curl_builder.py', 'desc': 'Build cURL commands'},
            {'id': 'diff', 'name': 'Diff Tool', 'script': 'diff_tool.py', 'desc': 'File diff comparison'},
            {'id': 'env', 'name': 'Env Manager', 'script': 'env_manager.py', 'desc': 'Environment manager'},
            {'id': 'fakedata', 'name': 'Fake Data', 'script': 'fakedata.py', 'desc': 'Generate fake data'},
            {'id': 'githelper', 'name': 'Git Helper', 'script': 'githelper.py', 'desc': 'Git helper utilities'},
            {'id': 'json_tool', 'name': 'JSON Tool', 'script': 'json_tool.py', 'desc': 'JSON manipulation'},
            {'id': 'lorem', 'name': 'Lorem Ipsum', 'script': 'lorem.py', 'desc': 'Lorem ipsum generator'},
            {'id': 'snippets', 'name': 'Snippets', 'script': 'snippets.py', 'desc': 'Code snippets manager'},
            {'id': 'uuid', 'name': 'UUID Gen', 'script': 'uuid_gen.py', 'desc': 'UUID generator'},
        ]
    },
    # === FILE TOOLS ===
    'files': {
        'name': 'File Tools',
        'icon': '[FIL]',
        'category': 'files',
        'tools': [
            {'id': 'archive', 'name': 'Archive Manager', 'script': 'archive_manager.py', 'desc': 'Archive management'},
            {'id': 'bulk_rename', 'name': 'Bulk Rename', 'script': 'bulk_rename.py', 'desc': 'Bulk file renaming'},
            {'id': 'duplicate', 'name': 'Duplicate Finder', 'script': 'duplicate.py', 'desc': 'Find duplicate files'},
            {'id': 'metadata', 'name': 'Metadata', 'script': 'metadata.py', 'desc': 'File metadata viewer'},
            {'id': 'pdf', 'name': 'PDF Tools', 'script': 'pdf_tools.py', 'desc': 'PDF utilities'},
            {'id': 'shred', 'name': 'Shred', 'script': 'shred.py', 'desc': 'Secure file deletion'},
        ]
    },
    # === SYSTEM TOOLS ===
    'system': {
        'name': 'System Tools',
        'icon': '[SYS]',
        'category': 'system',
        'tools': [
            {'id': 'alias', 'name': 'Alias Manager', 'script': 'alias_manager.py', 'desc': 'Shell alias manager'},
            {'id': 'backup', 'name': 'Backup Tool', 'script': 'backup_tool.py', 'desc': 'Backup utility'},
            {'id': 'cron', 'name': 'Cron Manager', 'script': 'cron_manager.py', 'desc': 'Cron job manager'},
            {'id': 'diskusage', 'name': 'Disk Usage', 'script': 'diskusage.py', 'desc': 'Disk usage analyzer'},
            {'id': 'processes', 'name': 'Processes', 'script': 'processes.py', 'desc': 'Process manager'},
            {'id': 'service', 'name': 'Service Manager', 'script': 'service_manager.py', 'desc': 'Service manager'},
            {'id': 'sysinfo', 'name': 'System Info', 'script': 'sysinfo.py', 'desc': 'System information'},
            {'id': 'usb', 'name': 'USB Info', 'script': 'usb_info.py', 'desc': 'USB device info'},
        ]
    },
    # === PRODUCTIVITY ===
    'productivity': {
        'name': 'Productivity',
        'icon': '[PRO]',
        'category': 'productivity',
        'tools': [
            {'id': 'bookmarks', 'name': 'Bookmarks', 'script': 'bookmarks.py', 'desc': 'Bookmark manager'},
            {'id': 'expenses', 'name': 'Expenses', 'script': 'expenses.py', 'desc': 'Expense tracker'},
            {'id': 'flashcards', 'name': 'Flashcards', 'script': 'flashcards.py', 'desc': 'Flashcard study'},
            {'id': 'habits', 'name': 'Habits', 'script': 'habits.py', 'desc': 'Habit tracker'},
            {'id': 'notes', 'name': 'Notes', 'script': 'notes.py', 'desc': 'Note taking'},
            {'id': 'pomodoro', 'name': 'Pomodoro', 'script': 'pomodoro.py', 'desc': 'Pomodoro timer'},
            {'id': 'timer', 'name': 'Timer', 'script': 'timer.py', 'desc': 'Timer/stopwatch'},
            {'id': 'todo', 'name': 'Todo', 'script': 'todo.py', 'desc': 'Todo list manager'},
        ]
    },
    # === MEDIA TOOLS ===
    'media': {
        'name': 'Media Tools',
        'icon': '[MED]',
        'category': 'media',
        'tools': [
            {'id': 'audio', 'name': 'Audio Info', 'script': 'audio_info.py', 'desc': 'Audio file info'},
            {'id': 'color', 'name': 'Color Picker', 'script': 'color_picker.py', 'desc': 'Color picker tool'},
            {'id': 'imgconvert', 'name': 'Image Convert', 'script': 'imgconvert.py', 'desc': 'Image converter'},
            {'id': 'screenshot', 'name': 'Screenshot', 'script': 'screenshot.py', 'desc': 'Screenshot tool'},
            {'id': 'ytdl', 'name': 'YouTube DL', 'script': 'ytdl.py', 'desc': 'YouTube downloader'},
        ]
    },
    # === MONITOR TOOLS ===
    'monitor': {
        'name': 'Monitoring',
        'icon': '[MON]',
        'category': 'monitor',
        'tools': [
            {'id': 'change_detect', 'name': 'Change Detect', 'script': 'change_detect.py', 'desc': 'File change detector'},
            {'id': 'uptime', 'name': 'Uptime', 'script': 'uptime.py', 'desc': 'Uptime monitor'},
        ]
    },
    # === FUN TOOLS ===
    'fun': {
        'name': 'Fun',
        'icon': '[FUN]',
        'category': 'fun',
        'tools': [
            {'id': 'cowsay', 'name': 'Cowsay', 'script': 'cowsay.py', 'desc': 'Cowsay ASCII art'},
            {'id': 'matrix', 'name': 'Matrix', 'script': 'matrix.py', 'desc': 'Matrix rain effect'},
            {'id': 'typing', 'name': 'Typing Test', 'script': 'typing_test.py', 'desc': 'Typing speed test'},
        ]
    },
}

# Base path for tools - handle Android path resolution
def _get_tools_base():
    """Get the tools base directory, handling Android paths"""
    # Try __file__ first
    base = os.path.dirname(os.path.abspath(__file__))
    tools_path = os.path.join(base, 'tools')

    if os.path.exists(tools_path):
        return tools_path

    # On Android, try the app's private files directory
    try:
        from android.storage import app_storage_path
        android_base = app_storage_path()
        tools_path = os.path.join(android_base, 'app', 'tools')
        if os.path.exists(tools_path):
            return tools_path
    except ImportError:
        pass

    # Try common Android paths
    android_paths = [
        '/data/data/com.gh0st.dvntoolkit/files/app/tools',
        '/data/user/0/com.gh0st.dvntoolkit/files/app/tools',
    ]
    for path in android_paths:
        if os.path.exists(path):
            return path

    # Fallback - return the calculated path even if it doesn't exist
    return os.path.join(base, 'tools')

TOOLS_BASE = _get_tools_base()

def get_tool_path(category, script):
    """Get full path to a tool script"""
    return os.path.join(TOOLS_BASE, category, script)


class TerminalOutput(TextInput):
    """Custom terminal-style output widget with scrolling support"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.readonly = True
        self.multiline = True
        self.font_name = 'Roboto'
        self.font_size = '12sp'
        self.padding = [10, 10, 10, 10]
        # Enable scrolling - critical for viewing all output
        self.do_scroll_x = False
        self.do_scroll_y = True
        self.scroll_y = 0  # Start at bottom (most recent output)
        # Disable text selection handles on Android
        self.allow_copy = False
        self.use_bubble = False
        self.use_handles = False

    def append(self, text):
        """Append text to terminal"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.text += f"[{timestamp}] {text}\n"
        # Scroll to bottom to show latest output
        self.cursor = (len(self.text), 0)
        self.scroll_y = 0  # 0 = bottom in Kivy

    def clear_terminal(self):
        """Clear terminal output"""
        self.text = ""
        self.append("Terminal cleared.")


class ToolButton(Button):
    """Styled button for tools"""

    def __init__(self, tool_data, theme, callback, **kwargs):
        super().__init__(**kwargs)
        self.tool_data = tool_data
        self.text = tool_data['name']
        self.callback = callback
        self.size_hint_y = None
        self.height = 60
        self.background_normal = ''
        self.background_down = ''
        self.apply_theme(theme)

    def apply_theme(self, theme):
        self.background_color = get_color_from_hex(theme['button_bg'])
        self.color = get_color_from_hex(theme['text'])

    def on_press(self):
        self.callback(self.tool_data)


class CategoryHeader(BoxLayout):
    """Category header with icon"""

    def __init__(self, category_data, theme, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.size_hint_y = None
        self.height = 40
        self.padding = [10, 5, 10, 5]

        icon = Label(
            text=category_data['icon'],
            size_hint_x=0.15,
            color=get_color_from_hex(theme['accent']),
            font_size='16sp',
            bold=True
        )

        name = Label(
            text=category_data['name'],
            size_hint_x=0.85,
            color=get_color_from_hex(theme['accent']),
            font_size='14sp',
            halign='left',
            valign='middle'
        )
        name.bind(size=name.setter('text_size'))

        self.add_widget(icon)
        self.add_widget(name)


class MainScreen(Screen):
    """Main tool selection screen"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.build_ui()

    def build_ui(self):
        self.clear_widgets()
        theme = self.app.current_theme

        # Main layout - increased spacing for visual separation
        main_layout = BoxLayout(orientation='vertical', spacing=8, padding=[0, 0, 0, 5])

        # Header
        header = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=60,
            padding=[10, 10, 10, 10]
        )
        header.canvas.before.clear()
        from kivy.graphics import Color, Rectangle
        with header.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            self.header_rect = Rectangle(pos=header.pos, size=header.size)
        header.bind(pos=self._update_header, size=self._update_header)

        title = Label(
            text='DVN TOOLKIT',
            font_size='20sp',
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_x=0.7
        )

        settings_btn = Button(
            text='[=]',
            size_hint_x=0.15,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text'])
        )
        settings_btn.bind(on_press=self.open_settings)

        theme_btn = Button(
            text='[T]',
            size_hint_x=0.15,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text'])
        )
        theme_btn.bind(on_press=self.open_theme_picker)

        header.add_widget(title)
        header.add_widget(theme_btn)
        header.add_widget(settings_btn)

        # Tool categories scroll view
        scroll = ScrollView(size_hint=(1, 0.55))
        tools_layout = BoxLayout(
            orientation='vertical',
            spacing=10,
            size_hint_y=None,
            padding=[12, 12, 12, 12]
        )
        tools_layout.bind(minimum_height=tools_layout.setter('height'))

        for cat_id, cat_data in TOOLS.items():
            # Category header
            cat_header = CategoryHeader(cat_data, theme)
            tools_layout.add_widget(cat_header)

            # Tool buttons in category - include category info with each tool
            category = cat_data.get('category', cat_id)
            for tool in cat_data['tools']:
                tool_with_category = {**tool, 'category': category}
                btn = ToolButton(tool_with_category, theme, self.on_tool_select)
                tools_layout.add_widget(btn)

            # Spacer between categories - increased for visual separation
            spacer = BoxLayout(size_hint_y=None, height=15)
            tools_layout.add_widget(spacer)

        scroll.add_widget(tools_layout)

        # Terminal section
        terminal_header = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=40,
            padding=[10, 5, 10, 5]
        )

        term_label = Label(
            text='TERMINAL OUTPUT',
            font_size='12sp',
            color=get_color_from_hex(theme['accent']),
            size_hint_x=0.6,
            halign='left',
            valign='middle'
        )
        term_label.bind(size=term_label.setter('text_size'))

        clear_btn = Button(
            text='CLEAR',
            size_hint_x=0.2,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size='11sp'
        )
        clear_btn.bind(on_press=self.clear_terminal)

        copy_btn = Button(
            text='COPY',
            size_hint_x=0.2,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size='11sp'
        )
        copy_btn.bind(on_press=self.copy_terminal)

        terminal_header.add_widget(term_label)
        terminal_header.add_widget(clear_btn)
        terminal_header.add_widget(copy_btn)

        # Terminal output
        self.terminal = TerminalOutput(
            background_color=get_color_from_hex(theme['terminal_bg']),
            foreground_color=get_color_from_hex(theme['terminal_text']),
            size_hint=(1, 0.35)
        )
        self.terminal.append("DVN Offensive Toolkit initialized.")
        self.terminal.append("Select a tool to begin.")

        # Build main layout
        main_layout.add_widget(header)
        main_layout.add_widget(scroll)
        main_layout.add_widget(terminal_header)
        main_layout.add_widget(self.terminal)

        # Set background
        with main_layout.canvas.before:
            Color(*get_color_from_hex(theme['bg']))
            self.bg_rect = Rectangle(pos=main_layout.pos, size=main_layout.size)
        main_layout.bind(pos=self._update_bg, size=self._update_bg)

        self.add_widget(main_layout)

    def _update_bg(self, instance, value):
        self.bg_rect.pos = instance.pos
        self.bg_rect.size = instance.size

    def _update_header(self, instance, value):
        self.header_rect.pos = instance.pos
        self.header_rect.size = instance.size

    def on_tool_select(self, tool_data):
        """Handle tool selection"""
        self.terminal.append(f"Selected: {tool_data['name']}")
        self.terminal.append(f"  {tool_data['desc']}")
        self.app.show_tool_screen(tool_data)

    def clear_terminal(self, instance):
        self.terminal.clear_terminal()

    def copy_terminal(self, instance):
        Clipboard.copy(self.terminal.text)
        self.terminal.append("Output copied to clipboard.")

    def open_settings(self, instance):
        self.app.show_settings()

    def open_theme_picker(self, instance):
        self.app.show_theme_picker()


class ToolScreen(Screen):
    """Screen for running individual tools"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.current_tool = None
        self.process = None

    def setup_tool(self, tool_data):
        """Setup screen for specific tool"""
        self.current_tool = tool_data
        self.clear_widgets()
        self.build_ui()

    def build_ui(self):
        # Clear existing widgets to prevent overlay issues
        self.clear_widgets()

        theme = self.app.current_theme
        tool = self.current_tool

        # Main layout - generous spacing for clear visual separation
        main_layout = BoxLayout(orientation='vertical', spacing=12, padding=[12, 55, 12, 8])

        # Header with back button and tool name - increased height for better touch targets
        header = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=60,
            padding=[8, 8, 8, 8],
            spacing=10
        )

        back_btn = Button(
            text='< BACK',
            size_hint_x=0.2,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size='12sp'
        )
        back_btn.bind(on_press=self.go_back)

        title = Label(
            text=tool['name'].upper(),
            font_size='16sp',
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_x=0.6
        )

        help_btn = Button(
            text='? HELP',
            size_hint_x=0.2,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['accent']),
            font_size='12sp'
        )
        help_btn.bind(on_press=self.show_help)

        header.add_widget(back_btn)
        header.add_widget(title)
        header.add_widget(help_btn)

        # Separator line under header - thicker and more visible
        separator = BoxLayout(size_hint_y=None, height=3)
        with separator.canvas.before:
            from kivy.graphics import Color, Rectangle
            Color(*get_color_from_hex(theme['accent']))
            separator._line = Rectangle(pos=separator.pos, size=separator.size)
        separator.bind(
            pos=lambda inst, val: setattr(inst._line, 'pos', val),
            size=lambda inst, val: setattr(inst._line, 'size', val)
        )

        # Tool description - wrapped in BoxLayout for proper spacing
        desc_container = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=45,
            padding=[10, 5, 10, 5]
        )
        desc_label = Label(
            text=tool['desc'],
            color=get_color_from_hex(theme['text_dim']),
            font_size='12sp',
            halign='center',
            valign='middle'
        )
        desc_label.bind(size=desc_label.setter('text_size'))
        desc_container.add_widget(desc_label)

        # ═══════════════════════════════════════════════════════════
        # COMMAND ARGUMENTS SECTION - with visible border
        # ═══════════════════════════════════════════════════════════
        input_section = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=220,
            padding=[15, 15, 15, 15],
            spacing=12
        )

        # Add visible border around input section using accent color
        with input_section.canvas.before:
            from kivy.graphics import Color, Line, RoundedRectangle
            # Background
            Color(*get_color_from_hex(theme['bg_secondary']))
            input_section._bg_rect = RoundedRectangle(
                pos=input_section.pos,
                size=input_section.size,
                radius=[10, 10, 10, 10]
            )
            # Border - use accent color with some transparency
            Color(*get_color_from_hex(theme['accent']), 0.5)
            input_section._border = Line(
                rounded_rectangle=(
                    input_section.pos[0], input_section.pos[1],
                    input_section.size[0], input_section.size[1],
                    10, 10, 10, 10, 50
                ),
                width=1.5
            )

        def update_input_section_graphics(inst, val):
            inst._bg_rect.pos = inst.pos
            inst._bg_rect.size = inst.size
            inst._border.rounded_rectangle = (
                inst.pos[0], inst.pos[1],
                inst.size[0], inst.size[1],
                10, 10, 10, 10, 50
            )
        input_section.bind(pos=update_input_section_graphics, size=update_input_section_graphics)

        # Section header - clear visibility
        section_header = Label(
            text='⌨ COMMAND ARGUMENTS',
            size_hint_y=None,
            height=30,
            color=get_color_from_hex(theme['accent']),
            font_size='14sp',
            bold=True,
            halign='left',
            valign='middle'
        )
        section_header.bind(size=section_header.setter('text_size'))

        # Instruction text - properly sized
        instruction = Label(
            text=f'Enter arguments below, then tap RUN to execute {tool["script"]}',
            size_hint_y=None,
            height=30,
            color=get_color_from_hex(theme['text_dim']),
            font_size='11sp',
            halign='left',
            valign='middle'
        )
        instruction.bind(size=instruction.setter('text_size'))

        # Input field container with visible border
        input_field_container = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=55
        )

        # Add border around input field
        with input_field_container.canvas.before:
            from kivy.graphics import Color, Line, RoundedRectangle
            Color(*get_color_from_hex(theme['terminal_bg']))
            input_field_container._bg = RoundedRectangle(
                pos=input_field_container.pos,
                size=input_field_container.size,
                radius=[6, 6, 6, 6]
            )
            Color(*get_color_from_hex(theme['accent']), 0.7)
            input_field_container._border = Line(
                rounded_rectangle=(
                    input_field_container.pos[0], input_field_container.pos[1],
                    input_field_container.size[0], input_field_container.size[1],
                    6, 6, 6, 6, 30
                ),
                width=1.2
            )

        def update_input_field_graphics(inst, val):
            inst._bg.pos = inst.pos
            inst._bg.size = inst.size
            inst._border.rounded_rectangle = (
                inst.pos[0], inst.pos[1],
                inst.size[0], inst.size[1],
                6, 6, 6, 6, 30
            )
        input_field_container.bind(pos=update_input_field_graphics, size=update_input_field_graphics)

        self.cmd_input = TextInput(
            hint_text='e.g., --help or target.com',
            multiline=False,
            background_color=[0, 0, 0, 0],  # Transparent - container has background
            foreground_color=get_color_from_hex(theme['text']),
            hint_text_color=get_color_from_hex(theme['text_dim']),
            cursor_color=get_color_from_hex(theme['accent']),
            font_size='14sp',
            padding=[12, 10, 12, 10]
        )
        input_field_container.add_widget(self.cmd_input)

        # Run and Stop buttons
        btn_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=50,
            spacing=15
        )

        self.run_btn = Button(
            text='▶ RUN',
            background_normal='',
            background_color=get_color_from_hex(theme['success']),
            color=get_color_from_hex('#000000'),
            bold=True,
            font_size='14sp'
        )
        self.run_btn.bind(on_press=self.run_tool)

        self.stop_btn = Button(
            text='■ STOP',
            background_normal='',
            background_color=get_color_from_hex(theme['danger']),
            color=get_color_from_hex('#ffffff'),
            bold=True,
            font_size='14sp'
        )
        self.stop_btn.bind(on_press=self.stop_tool)
        self.stop_btn.disabled = True

        btn_row.add_widget(self.run_btn)
        btn_row.add_widget(self.stop_btn)

        input_section.add_widget(section_header)
        input_section.add_widget(instruction)
        input_section.add_widget(input_field_container)
        input_section.add_widget(btn_row)

        # Terminal output - use TextInput directly without ScrollView wrapper
        # TextInput handles its own scrolling
        self.terminal = TerminalOutput(
            background_color=get_color_from_hex(theme['terminal_bg']),
            foreground_color=get_color_from_hex(theme['terminal_text']),
            size_hint=(1, 1)
        )
        self.terminal.append(f"Tool: {tool['script']}")
        self.terminal.append(f"Description: {tool['desc']}")
        self.terminal.append("Enter arguments and press RUN.")
        self.terminal.append("Use HELP for full documentation.")

        # Quick actions
        quick_actions = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=45,
            padding=[10, 5, 10, 10],
            spacing=5
        )

        clear_btn = Button(
            text='CLEAR',
            size_hint_x=0.33,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size='11sp'
        )
        clear_btn.bind(on_press=lambda x: self.terminal.clear_terminal())

        copy_btn = Button(
            text='COPY OUTPUT',
            size_hint_x=0.34,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size='11sp'
        )
        copy_btn.bind(on_press=self.copy_output)

        examples_btn = Button(
            text='EXAMPLES',
            size_hint_x=0.33,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size='11sp'
        )
        examples_btn.bind(on_press=self.show_examples)

        quick_actions.add_widget(clear_btn)
        quick_actions.add_widget(copy_btn)
        quick_actions.add_widget(examples_btn)

        # Set background
        with main_layout.canvas.before:
            from kivy.graphics import Color, Rectangle
            Color(*get_color_from_hex(theme['bg']))
            self.bg_rect = Rectangle(pos=main_layout.pos, size=main_layout.size)
        main_layout.bind(pos=self._update_bg, size=self._update_bg)

        main_layout.add_widget(header)
        main_layout.add_widget(separator)
        main_layout.add_widget(desc_container)
        main_layout.add_widget(input_section)
        main_layout.add_widget(self.terminal)
        main_layout.add_widget(quick_actions)

        self.add_widget(main_layout)

    def _update_bg(self, instance, value):
        self.bg_rect.pos = instance.pos
        self.bg_rect.size = instance.size

    def go_back(self, instance):
        self.app.go_to_main()

    def show_help(self, instance):
        """Show tool's full help"""
        self.terminal.append("Loading help documentation...")
        tool_path = get_tool_path(self.current_tool['category'], self.current_tool['script'])
        threading.Thread(target=self._run_help, args=(tool_path,), daemon=True).start()

    def _run_help(self, tool_path):
        """Run help using exec() for Android compatibility"""
        try:
            import io
            from contextlib import redirect_stdout, redirect_stderr

            with open(tool_path, 'r') as f:
                tool_code = f.read()

            # Set up sys.argv for help
            old_argv = sys.argv.copy()
            sys.argv = [tool_path, '--help-full']

            output_buffer = io.StringIO()
            tool_globals = {
                '__name__': '__main__',
                '__file__': tool_path,
                '__builtins__': __builtins__,
            }

            try:
                with redirect_stdout(output_buffer), redirect_stderr(output_buffer):
                    exec(compile(tool_code, tool_path, 'exec'), tool_globals)
            except SystemExit:
                pass
            finally:
                sys.argv = old_argv

            output = output_buffer.getvalue()
            if output:
                Clock.schedule_once(lambda dt: self._display_output(output))
            else:
                Clock.schedule_once(lambda dt: self._display_output("No help available for this tool."))
        except Exception as e:
            error_msg = f"Error loading help: {e}"
            Clock.schedule_once(lambda dt, msg=error_msg: self._display_output(msg))

    def run_tool(self, instance):
        """Run the selected tool"""
        args = self.cmd_input.text.strip()
        tool_path = get_tool_path(self.current_tool['category'], self.current_tool['script'])

        if not os.path.exists(tool_path):
            self.terminal.append(f"Error: Tool not found at {tool_path}")
            self.terminal.append(f"Expected: {tool_path}")
            return

        self.terminal.append(f"Running: {self.current_tool['script']} {args}")
        self.terminal.append("-" * 40)

        self.run_btn.disabled = True
        self.stop_btn.disabled = False

        # Run in thread
        threading.Thread(
            target=self._execute_tool,
            args=(tool_path, args),
            daemon=True
        ).start()

    def _execute_tool(self, tool_path, args):
        """Execute tool in background using exec() for Android compatibility"""
        try:
            import io
            from contextlib import redirect_stdout, redirect_stderr

            # Read the tool source code
            with open(tool_path, 'r') as f:
                tool_code = f.read()

            # Set up sys.argv for the tool
            old_argv = sys.argv.copy()
            sys.argv = [tool_path] + (args.split() if args else [])

            # Capture output
            output_buffer = io.StringIO()

            # Create execution namespace
            tool_globals = {
                '__name__': '__main__',
                '__file__': tool_path,
                '__builtins__': __builtins__,
            }

            try:
                with redirect_stdout(output_buffer), redirect_stderr(output_buffer):
                    exec(compile(tool_code, tool_path, 'exec'), tool_globals)
            except SystemExit as e:
                # Tool called sys.exit(), which is normal
                pass
            except Exception as e:
                output_buffer.write(f"\nError: {e}\n")
            finally:
                sys.argv = old_argv

            # Display captured output
            output = output_buffer.getvalue()
            if output:
                for line in output.split('\n'):
                    if line:
                        Clock.schedule_once(lambda dt, l=line: self._display_output(l))

            Clock.schedule_once(lambda dt: self._display_output("-" * 40))
            Clock.schedule_once(lambda dt: self._display_output("Tool execution completed"))

        except Exception as e:
            Clock.schedule_once(lambda dt, err=str(e): self._display_output(f"Error: {err}"))
        finally:
            Clock.schedule_once(lambda dt: self._reset_buttons())

    def _display_output(self, text):
        """Display output in terminal"""
        if text and text.strip():
            self.terminal.append(text.strip())

    def _reset_buttons(self):
        self.run_btn.disabled = False
        self.stop_btn.disabled = True
        self.process = None

    def stop_tool(self, instance):
        """Stop running tool"""
        if self.process:
            self.process.terminate()
            self.terminal.append("Process terminated by user.")
            self._reset_buttons()

    def copy_output(self, instance):
        Clipboard.copy(self.terminal.text)
        self.terminal.append("Output copied to clipboard.")

    def show_examples(self, instance):
        """Show example commands for current tool"""
        examples = self._get_examples()
        self.terminal.append("\n" + "=" * 40)
        self.terminal.append("EXAMPLE COMMANDS:")
        self.terminal.append("=" * 40)
        for ex in examples:
            self.terminal.append(f"  {ex}")
        self.terminal.append("")

    def _get_examples(self):
        """Get example commands for tool"""
        tool_id = self.current_tool['id']
        examples = {
            'nmap_lite': [
                '192.168.1.1',
                '192.168.1.1 -p 1-1000',
                '192.168.1.1 -sV',
                '192.168.1.0/24 --ping',
            ],
            'dns_enum': [
                'example.com',
                'example.com -s',
                'example.com --all',
            ],
            'sqli_scanner': [
                '-u "http://target.com/page?id=1"',
                '-u "http://target.com/page?id=1" --level 3',
            ],
            'xss_scanner': [
                '-u "http://target.com/search?q=test"',
                '-u "http://target.com/search?q=test" --forms',
            ],
            'lfi_scanner': [
                '-u "http://target.com/view?file=index"',
                '-u "http://target.com/view?file=x" --level 3',
            ],
            'reverse_shells': [
                '--list',
                '-t bash -i 10.0.0.1 -p 4444',
                '-t python -i 10.0.0.1 -p 4444',
            ],
            'webshell_gen': [
                '--list',
                '-t php_simple -o shell.php',
                '-t php_simple --obfuscate -o s.php',
            ],
            'bruteforce': [
                '-u http://target.com/login -U admin -P passwords.txt',
                '--ssh root@192.168.1.1 -P passwords.txt',
            ],
            'hash_toolkit': [
                'identify "5f4dcc3b5aa765d61d8327deb882cf99"',
                'generate "password" --all',
                'crack "hash" -w wordlist.txt',
            ],
            'wordlist_gen': [
                '--target "john smith 1985"',
                '--profile -o custom.txt',
            ],
            'payload_encoder': [
                '-p "<script>alert(1)</script>" --all',
                '-p "admin\' OR \'1\'=\'1" --url',
            ],
            'web_fuzzer': [
                'http://target.com',
                'http://target.com -x php,txt,bak',
            ],
            'smb_enum': [
                '192.168.1.100',
                '192.168.1.100 -u user -p pass',
                '192.168.1.0/24 --scan',
            ],
        }
        return examples.get(tool_id, ['No examples available'])


class SettingsScreen(Screen):
    """Settings and preferences screen"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.build_ui()

    def build_ui(self):
        self.clear_widgets()
        theme = self.app.current_theme

        # Add extra top padding to account for Android status bar
        main_layout = BoxLayout(orientation='vertical', spacing=10, padding=[20, 80, 20, 20])

        # Header
        header = BoxLayout(orientation='horizontal', size_hint_y=None, height=50)

        back_btn = Button(
            text='< BACK',
            size_hint_x=0.3,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text'])
        )
        back_btn.bind(on_press=lambda x: self.app.go_to_main())

        title = Label(
            text='SETTINGS',
            font_size='18sp',
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_x=0.7
        )

        header.add_widget(back_btn)
        header.add_widget(title)

        # Settings options
        settings_scroll = ScrollView(size_hint=(1, 1))
        settings_layout = BoxLayout(
            orientation='vertical',
            spacing=15,
            size_hint_y=None,
            padding=[0, 10, 0, 10]
        )
        settings_layout.bind(minimum_height=settings_layout.setter('height'))

        # Theme selection
        theme_label = Label(
            text='Theme:',
            size_hint_y=None,
            height=35,
            color=get_color_from_hex(theme['text']),
            halign='left',
            valign='middle',
            font_size='14sp'
        )
        theme_label.bind(size=theme_label.setter('text_size'))

        theme_spinner = Spinner(
            text=self.app.theme_name,
            values=[t['name'] for t in THEMES.values()],
            size_hint_y=None,
            height=45,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text'])
        )
        theme_spinner.bind(text=self._on_theme_change)

        # Tools path
        path_label = Label(
            text=f'Tools Path:\n{TOOLS_BASE}',
            size_hint_y=None,
            height=70,
            color=get_color_from_hex(theme['text_dim']),
            halign='left',
            valign='top',
            font_size='11sp'
        )
        path_label.bind(size=path_label.setter('text_size'))

        # About section
        about_label = Label(
            text='About DVN Toolkit',
            size_hint_y=None,
            height=40,
            color=get_color_from_hex(theme['accent']),
            font_size='14sp',
            bold=True,
            halign='left',
            valign='middle'
        )
        about_label.bind(size=about_label.setter('text_size'))

        about_text = Label(
            text='DVN Offensive Toolkit\n'
                 'For authorized security testing only.\n\n'
                 'Created for gh0st\n'
                 'January 2026',
            size_hint_y=None,
            height=140,
            color=get_color_from_hex(theme['text_dim']),
            halign='left',
            valign='top',
            font_size='12sp'
        )
        about_text.bind(size=about_text.setter('text_size'))

        settings_layout.add_widget(theme_label)
        settings_layout.add_widget(theme_spinner)
        settings_layout.add_widget(BoxLayout(size_hint_y=None, height=20))
        settings_layout.add_widget(path_label)
        settings_layout.add_widget(BoxLayout(size_hint_y=None, height=20))
        settings_layout.add_widget(about_label)
        settings_layout.add_widget(about_text)

        settings_scroll.add_widget(settings_layout)

        # Set background
        with main_layout.canvas.before:
            from kivy.graphics import Color, Rectangle
            Color(*get_color_from_hex(theme['bg']))
            self.bg_rect = Rectangle(pos=main_layout.pos, size=main_layout.size)
        main_layout.bind(pos=self._update_bg, size=self._update_bg)

        main_layout.add_widget(header)
        main_layout.add_widget(settings_scroll)

        self.add_widget(main_layout)

    def _update_bg(self, instance, value):
        self.bg_rect.pos = instance.pos
        self.bg_rect.size = instance.size

    def _on_theme_change(self, spinner, text):
        for theme_id, theme_data in THEMES.items():
            if theme_data['name'] == text:
                self.app.set_theme(theme_id)
                break


class DVNToolkitApp(App):
    """Main application class"""

    theme_name = StringProperty('Cyberpunk')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.current_theme_id = 'cyberpunk'
        self.current_theme = THEMES['cyberpunk']

    def build(self):
        self.title = 'DVN Toolkit'

        # Screen manager
        self.sm = ScreenManager(transition=SlideTransition())

        # Create screens
        self.main_screen = MainScreen(self, name='main')
        self.tool_screen = ToolScreen(self, name='tool')
        self.settings_screen = SettingsScreen(self, name='settings')

        self.sm.add_widget(self.main_screen)
        self.sm.add_widget(self.tool_screen)
        self.sm.add_widget(self.settings_screen)

        return self.sm

    def set_theme(self, theme_id):
        """Change application theme"""
        if theme_id in THEMES:
            self.current_theme_id = theme_id
            self.current_theme = THEMES[theme_id]
            self.theme_name = THEMES[theme_id]['name']

            # Rebuild screens with new theme
            self.main_screen.build_ui()
            self.settings_screen.build_ui()
            if self.tool_screen.current_tool:
                self.tool_screen.build_ui()

    def show_tool_screen(self, tool_data):
        """Navigate to tool screen"""
        self.tool_screen.setup_tool(tool_data)
        self.sm.current = 'tool'

    def go_to_main(self):
        """Navigate to main screen"""
        self.sm.current = 'main'

    def show_settings(self):
        """Navigate to settings screen"""
        self.settings_screen.build_ui()
        self.sm.current = 'settings'

    def show_theme_picker(self):
        """Show theme picker popup"""
        theme = self.current_theme

        content = BoxLayout(orientation='vertical', spacing=10, padding=[10, 10, 10, 10])

        for theme_id, theme_data in THEMES.items():
            btn = Button(
                text=theme_data['name'],
                size_hint_y=None,
                height=50,
                background_normal='',
                background_color=get_color_from_hex(theme_data['accent']),
                color=get_color_from_hex('#000000' if theme_id == 'light' else '#ffffff')
            )
            btn.bind(on_press=lambda x, tid=theme_id: self._select_theme(tid, popup))
            content.add_widget(btn)

        popup = Popup(
            title='Select Theme',
            content=content,
            size_hint=(0.8, 0.6),
            background_color=get_color_from_hex(theme['bg'])
        )
        popup.open()

    def _select_theme(self, theme_id, popup):
        popup.dismiss()
        self.set_theme(theme_id)


if __name__ == '__main__':
    DVNToolkitApp().run()
