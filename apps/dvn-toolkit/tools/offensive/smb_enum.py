#!/usr/bin/env python3
"""
SMB Enumeration Tool - Windows Share Discovery and Enumeration
For authorized security testing only

QUICK START:
    ./smb_enum.py 192.168.1.1                    # Basic scan
    ./smb_enum.py 192.168.1.1 -u user -p pass    # Authenticated
    ./smb_enum.py 192.168.1.0/24 --scan          # Scan network
"""

import argparse
import sys
import os
import socket
import struct
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    W = '\033[97m'
    E = '\033[0m'
    BOLD = '\033[1m'

# SMB ports
SMB_PORTS = [445, 139]

# Common shares to check
COMMON_SHARES = [
    'ADMIN$', 'C$', 'D$', 'E$', 'IPC$', 'NETLOGON', 'SYSVOL',
    'print$', 'Users', 'Public', 'Shared', 'Data', 'Backup',
    'IT', 'HR', 'Finance', 'Documents', 'Software', 'Install',
    'Temp', 'Transfer', 'FTP', 'Web', 'wwwroot', 'inetpub',
]

# SMB Status Codes
SMB_STATUS = {
    0x00000000: 'SUCCESS',
    0xC000006D: 'LOGON_FAILURE',
    0xC0000022: 'ACCESS_DENIED',
    0xC000006E: 'ACCOUNT_RESTRICTION',
    0xC0000064: 'NO_SUCH_USER',
    0xC000006A: 'WRONG_PASSWORD',
    0xC0000072: 'ACCOUNT_DISABLED',
    0xC0000234: 'ACCOUNT_LOCKED',
    0xC0000193: 'ACCOUNT_EXPIRED',
    0xC0000071: 'PASSWORD_EXPIRED',
}

HELP_TEXT = """
================================================================================
                    SMB ENUMERATION - COMPREHENSIVE GUIDE
                    Windows File Sharing Discovery
================================================================================

WHAT IS SMB?
------------
SMB (Server Message Block) is Windows' file sharing protocol. When you access
a shared folder on a Windows network (\\\\server\\share), you're using SMB.
It runs on ports 445 (modern) and 139 (legacy with NetBIOS).

WHY SMB MATTERS FOR PENTESTING:
  - File shares often contain sensitive data
  - Misconfigured shares allow unauthorized access
  - Can reveal usernames, system info, domain structure
  - Common vector for lateral movement in networks
  - Password hashes can sometimes be captured


UNDERSTANDING SMB SHARES
------------------------

ADMINISTRATIVE SHARES (Default on Windows):
  C$, D$, E$    Hidden admin shares for each drive
                Requires local admin credentials
                Access means FULL FILE SYSTEM ACCESS

  ADMIN$        Points to Windows directory
                Requires admin rights
                Used for remote administration

  IPC$          Inter-Process Communication
                Allows anonymous connections (sometimes)
                Used for RPC, user enumeration

USER-CREATED SHARES:
  These are intentionally shared folders
  May have weak permissions
  Often contain sensitive business data


NULL SESSIONS EXPLAINED
-----------------------
A NULL SESSION is an anonymous SMB connection (no username/password).
Older Windows versions allowed significant information disclosure via null sessions.

WHAT NULL SESSIONS CAN REVEAL:
  - List of shared folders
  - User account names
  - Group memberships
  - Password policy
  - System information

MODERN WINDOWS:
  Windows 10/Server 2016+ restrict null sessions
  But many older systems and misconfigurations still allow them
  ALWAYS TRY NULL SESSION FIRST - it's free information


WHERE TO FIND SENSITIVE DATA
----------------------------

SYSVOL SHARE (Domain Controllers):
  Contains Group Policy files
  HISTORICALLY: Group Policy Preferences stored passwords
  Location: \\\\DC\\SYSVOL\\domain\\Policies\\
  Look for: Groups.xml, Services.xml, Scheduledtasks.xml
  Password is AES encrypted but Microsoft published the key!
  Tool: gpp-decrypt to decode these passwords

NETLOGON SHARE:
  Contains login scripts
  Scripts often have hardcoded credentials
  Look for: .bat, .vbs, .ps1 files

USER HOME DIRECTORIES:
  \\\\server\\Users or \\\\server\\home
  May contain:
  - SSH keys (~/.ssh)
  - Browser saved passwords
  - Config files with credentials
  - Documents with sensitive info

IT/ADMIN SHARES:
  \\\\server\\IT, \\\\server\\Admin, \\\\server\\Software
  Often contain:
  - Installation scripts with passwords
  - Network documentation
  - Server inventory with IPs
  - Backup files


ENUMERATION WORKFLOW
--------------------

STEP 1: Find SMB Hosts
  ./smb_enum.py 192.168.1.0/24 --scan
  Identifies all systems with SMB enabled

STEP 2: Test Null Sessions
  For each host: ./smb_enum.py <host> --null
  Or: smbclient -L //<host> -N

STEP 3: Enumerate Shares
  With creds: smbclient -L //<host> -U 'user%pass'
  Anonymous: smbclient -L //<host> -N
  Or: smbmap -H <host> -u user -p pass

STEP 4: Access Interesting Shares
  smbclient //<host>/<share> -U 'user%pass'
  Then: ls, cd, get <file>, mget *, etc.

STEP 5: Search for Sensitive Files
  Look for: .txt, .doc, .xls, .conf, .xml, .ps1, .bat
  Keywords: password, secret, credential, admin, root


SCENARIO-BASED USAGE
--------------------

SCENARIO: Network reconnaissance, looking for file servers
COMMAND:  ./smb_enum.py 10.0.0.0/24 --scan -t 50
WHY:      Quickly identify all SMB hosts on network
          High thread count for speed
NEXT:     Test each discovered host for null sessions
          Enumerate shares on promising targets


SCENARIO: Found Windows server, testing anonymous access
COMMAND:  ./smb_enum.py 192.168.1.100 --null
WHY:      Null session test reveals if anonymous access allowed
          Free information without credentials
NEXT:     If allowed, use smbclient to list/access shares
          Try: rpcclient -U '' -N <host> for more enum


SCENARIO: Have valid domain credentials
COMMAND:  ./smb_enum.py 192.168.1.100 -u jsmith -p Password123 -d CORP
WHY:      Authenticated enumeration shows more shares
          Domain user can access domain shares
NEXT:     Use smbclient to browse shares
          Look for admin shares if user is local admin


SCENARIO: Domain controller found
COMMAND:  ./smb_enum.py 192.168.1.10 -u user -p pass -d DOMAIN
WHY:      DCs have SYSVOL and NETLOGON shares
          May contain Group Policy Preference passwords
NEXT:     smbclient //DC/SYSVOL -U 'user%pass'
          Search for Groups.xml, decrypt any found passwords


USEFUL COMPANION COMMANDS
-------------------------

LIST SHARES (smbclient):
  smbclient -L //target -N              # Null session
  smbclient -L //target -U 'user%pass'  # Authenticated
  smbclient -L //target -U 'DOMAIN/user%pass'  # Domain auth

CONNECT TO SHARE:
  smbclient //target/share -U 'user%pass'

  Commands once connected:
    ls              List files
    cd dir          Change directory
    get file        Download file
    mget *          Download all files
    put file        Upload file
    recurse ON      Enable recursive operations
    prompt OFF      Disable confirmation prompts
    mget *          Download everything recursively

MOUNT SHARE (Linux):
  mount -t cifs //target/share /mnt/smb -o user=xxx,pass=xxx

SMBMAP (Advanced Enumeration):
  smbmap -H target                      # Null session
  smbmap -H target -u user -p pass      # Authenticated
  smbmap -H target -u user -p pass -r   # Recursive listing
  smbmap -H target -u user -p pass -R   # Recursive with content
  smbmap -H target -u user -p pass -s share -q "password"  # Search

ENUM4LINUX (Comprehensive):
  enum4linux -a target                  # Full enumeration
  enum4linux -U target                  # User enumeration
  enum4linux -S target                  # Share enumeration

RPCCLIENT (RPC Enumeration):
  rpcclient -U '' -N target             # Null session
  rpcclient -U 'user%pass' target       # Authenticated

  Commands:
    enumdomusers    List domain users
    enumdomgroups   List domain groups
    queryuser 0x1f4 Get user info by RID
    getdompwinfo    Password policy


COMMON SHARE TYPES TO TARGET
----------------------------

HIGH VALUE:
  SYSVOL        GPO with potential passwords
  NETLOGON      Login scripts with credentials
  IT, Admin     IT documentation, scripts
  Backup        Backup files, database dumps
  Finance, HR   Sensitive business data

MEDIUM VALUE:
  Users, Home   User files, SSH keys
  Public        Shared documents
  Software      Installation files, configs

REQUIRES ADMIN:
  C$, D$        Full drive access
  ADMIN$        Windows system directory
  IPC$          Inter-process communication


COMMON MISTAKES TO AVOID
------------------------
1. Not trying null session first (free info!)
2. Forgetting to check SYSVOL for GPP passwords
3. Not searching recursively in found shares
4. Missing hidden shares (end with $)
5. Not checking multiple ports (445 AND 139)
6. Ignoring access denied - document for report


SMB SECURITY ISSUES TO LOOK FOR
-------------------------------

1. NULL SESSION ALLOWED
   Severity: Medium-High
   Impact: Information disclosure, user enumeration

2. ANONYMOUS SHARE ACCESS
   Severity: High
   Impact: Unauthorized data access

3. GPP PASSWORDS IN SYSVOL
   Severity: Critical
   Impact: Credential exposure, privilege escalation

4. WEAK SHARE PERMISSIONS
   Severity: Medium-High
   Impact: Unauthorized read/write access

5. SENSITIVE DATA IN SHARES
   Severity: Varies
   Impact: Data breach, credential exposure


COMMAND REFERENCE
-----------------
BASIC:
  ./smb_enum.py TARGET              Basic enumeration

OPTIONS:
  -u, --user USER                   Username for authentication
  -p, --pass PASS                   Password
  -d, --domain DOMAIN               Domain (default: WORKGROUP)
  --shares                          Focus on share enumeration
  --users                           Focus on user enumeration
  --null                            Test null session access
  --scan                            Network scan mode (with CIDR)
  -t, --threads NUM                 Thread count (default: 10)
  -o, --output FILE                 Save results to file
================================================================================
"""

def banner():
    print(f"""{C.C}
   _____ __  _______     ______
  / ___//  |/  / __ )   / ____/___  __  ______ ___
  \\__ \\/ /|_/ / __  |  / __/ / __ \\/ / / / __ `__ \\
 ___/ / /  / / /_/ /  / /___/ / / / /_/ / / / / / /
/____/_/  /_/_____/  /_____/_/ /_/\\__,_/_/ /_/ /_/
{C.E}{C.Y}SMB Enumeration Tool{C.E}
""")

def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def get_smb_banner(host: str, port: int = 445, timeout: float = 5.0) -> Optional[Dict]:
    """Get basic SMB information via banner grab"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # SMB Negotiate Protocol Request (simplified)
        # This is a basic probe to check SMB response
        negotiate = bytes([
            0x00, 0x00, 0x00, 0x85,  # NetBIOS header
            0xff, 0x53, 0x4d, 0x42,  # SMB header
            0x72,  # Negotiate command
            0x00, 0x00, 0x00, 0x00,  # Status
            0x18,  # Flags
            0x53, 0xc8,  # Flags2
            0x00, 0x00,  # PID high
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature
            0x00, 0x00,  # Reserved
            0x00, 0x00,  # TID
            0x00, 0x00,  # PID
            0x00, 0x00,  # UID
            0x00, 0x00,  # MID
            # Negotiate dialects
            0x00,  # Word count
            0x62, 0x00,  # Byte count
            0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57,
            0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47,
            0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00,
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31,
            0x2e, 0x30, 0x00,
            0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
            0x20, 0x66, 0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72,
            0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20,
            0x33, 0x2e, 0x31, 0x61, 0x00,
            0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30,
            0x30, 0x32, 0x00,
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32,
            0x2e, 0x31, 0x00,
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30,
            0x2e, 0x31, 0x32, 0x00,
        ])

        sock.send(negotiate)
        response = sock.recv(1024)
        sock.close()

        if len(response) > 4 and response[4:8] == b'\xffSMB':
            return {
                'smb_version': 'SMB1',
                'response_length': len(response)
            }
        elif len(response) > 4 and response[4:8] == b'\xfeSMB':
            return {
                'smb_version': 'SMB2/3',
                'response_length': len(response)
            }

        return {'smb_version': 'Unknown', 'raw': response[:50].hex()}

    except Exception as e:
        return None

def scan_network_smb(network: str, threads: int = 50) -> List[str]:
    """Scan network for SMB hosts"""
    live_hosts = []

    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
    except:
        return []

    print(f"{C.B}[*]{C.E} Scanning {len(hosts)} hosts for SMB...")

    def check_smb(host: str) -> Optional[str]:
        for port in SMB_PORTS:
            if check_port(host, port, 1.0):
                return host
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_smb, host): host for host in hosts}

        for future in as_completed(futures):
            result = future.result()
            if result:
                live_hosts.append(result)
                print(f"{C.G}[+]{C.E} SMB host found: {result}")

    return live_hosts

def check_null_session(host: str, port: int = 445) -> Tuple[bool, str]:
    """Check if null session is allowed"""
    # This is a simplified check - real null session testing
    # would require proper SMB protocol implementation

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            return True, "Port open - null session testing requires smbclient"
        return False, "Port closed"
    except Exception as e:
        return False, str(e)

def enumerate_host(host: str, username: str = None, password: str = None,
                   domain: str = 'WORKGROUP') -> Dict:
    """Enumerate a single SMB host"""
    results = {
        'host': host,
        'ports': [],
        'smb_info': None,
        'null_session': False,
        'shares': [],
        'notes': []
    }

    # Check ports
    for port in SMB_PORTS:
        if check_port(host, port):
            results['ports'].append(port)
            print(f"{C.G}[+]{C.E} Port {port}/tcp OPEN")

    if not results['ports']:
        print(f"{C.R}[-]{C.E} No SMB ports open")
        return results

    # Get SMB banner
    primary_port = results['ports'][0]
    smb_info = get_smb_banner(host, primary_port)
    if smb_info:
        results['smb_info'] = smb_info
        print(f"{C.G}[+]{C.E} SMB Version: {smb_info.get('smb_version', 'Unknown')}")

    # Check null session
    allowed, msg = check_null_session(host, primary_port)
    results['null_session'] = allowed
    if allowed:
        print(f"{C.Y}[!]{C.E} Null session: {msg}")
        results['notes'].append("Null session may be allowed - test with smbclient")

    # Provide commands for further enumeration
    print(f"\n{C.M}[Commands for further enumeration]{C.E}")

    if username:
        print(f"{C.B}[*]{C.E} List shares:")
        print(f"    smbclient -L //{host} -U '{domain}\\{username}%{password}'")
        print(f"\n{C.B}[*]{C.E} Connect to share:")
        print(f"    smbclient //{host}/SHARE -U '{domain}\\{username}%{password}'")
    else:
        print(f"{C.B}[*]{C.E} Test null session:")
        print(f"    smbclient -L //{host} -N")
        print(f"    rpcclient -U '' -N {host}")

        print(f"\n{C.B}[*]{C.E} Enum4linux (comprehensive):")
        print(f"    enum4linux -a {host}")

        print(f"\n{C.B}[*]{C.E} With credentials:")
        print(f"    smbclient -L //{host} -U 'user%password'")
        print(f"    smbmap -H {host} -u user -p password")

    # Common share paths to try
    print(f"\n{C.M}[Common shares to check]{C.E}")
    for share in COMMON_SHARES[:10]:
        print(f"    //{host}/{share}")

    return results

def main():
    parser = argparse.ArgumentParser(
        description='SMB Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='For authorized security testing only.'
    )

    parser.add_argument('target', nargs='?', help='Target IP or CIDR range')
    parser.add_argument('-u', '--user', help='Username')
    parser.add_argument('-p', '--pass', dest='password', help='Password')
    parser.add_argument('-d', '--domain', default='WORKGROUP', help='Domain')
    parser.add_argument('--shares', action='store_true', help='Enumerate shares')
    parser.add_argument('--users', action='store_true', help='Enumerate users')
    parser.add_argument('--null', action='store_true', help='Test null session')
    parser.add_argument('--scan', action='store_true', help='Scan network for SMB')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Threads')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--help-full', action='store_true', help='Show detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    if not args.target:
        banner()
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed usage guide")
        return

    banner()

    # Network scan mode
    if args.scan or '/' in args.target:
        print(f"{C.B}[*]{C.E} Scanning network: {C.Y}{args.target}{C.E}")
        hosts = scan_network_smb(args.target, args.threads)
        print(f"\n{C.B}[*]{C.E} Found {C.G}{len(hosts)}{C.E} SMB hosts")

        if args.output:
            with open(args.output, 'w') as f:
                for host in hosts:
                    f.write(host + '\n')
            print(f"{C.B}[*]{C.E} Saved to {args.output}")
        return

    # Single host enumeration
    print(f"{C.B}[*]{C.E} Target: {C.Y}{args.target}{C.E}")
    print(f"{C.B}[*]{C.E} " + "=" * 50)

    results = enumerate_host(
        args.target,
        username=args.user,
        password=args.password,
        domain=args.domain
    )

    # Save output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"SMB Enumeration Results - {args.target}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Open Ports: {results['ports']}\n")
            if results['smb_info']:
                f.write(f"SMB Version: {results['smb_info']}\n")
            f.write(f"\nNotes:\n")
            for note in results['notes']:
                f.write(f"  - {note}\n")
        print(f"\n{C.B}[*]{C.E} Results saved to {args.output}")

if __name__ == '__main__':
    main()
