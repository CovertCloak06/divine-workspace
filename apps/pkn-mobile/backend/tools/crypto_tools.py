"""
Crypto Tools - Cryptography Utilities
Encryption, hashing, and cracking utilities.

Tools:
- hash_identify: Identify hash type
- hash_crack: Dictionary attack on hash
- jwt_decode: Decode JWT token
- jwt_forge: Forge JWT with weak algorithm
- base_decode_all: Try all base encodings
- rot_all: ROT1-25 decoder
- xor_decrypt: XOR cipher brute force
- aes_encrypt: AES encryption utility

WARNING: For authorized security testing only.
"""

import base64
import hashlib
import hmac
import json
import re
import binascii
from typing import Optional, List, Dict, Tuple
from langchain_core.tools import tool


# Hash identification patterns
HASH_PATTERNS = [
    (r"^[a-f0-9]{32}$", "MD5"),
    (r"^[a-f0-9]{40}$", "SHA-1"),
    (r"^[a-f0-9]{64}$", "SHA-256"),
    (r"^[a-f0-9]{128}$", "SHA-512"),
    (r"^\$1\$", "MD5 Crypt"),
    (r"^\$2[aby]?\$", "Bcrypt"),
    (r"^\$5\$", "SHA-256 Crypt"),
    (r"^\$6\$", "SHA-512 Crypt"),
    (r"^\$apr1\$", "Apache MD5"),
    (r"^[a-f0-9]{16}$", "MySQL 3.x / Half MD5"),
    (r"^\*[A-F0-9]{40}$", "MySQL 5.x"),
    (r"^[a-z0-9/.]{13}$", "DES Crypt"),
    (r"^[a-f0-9]{56}$", "SHA-224"),
    (r"^[a-f0-9]{96}$", "SHA-384"),
]

# Common wordlist for basic cracking
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "qwerty", "login", "iloveyou",
    "princess", "admin123", "root", "toor", "pass", "test", "guest",
    "abc123", "password1", "12345678", "sunshine", "1234567890",
]


@tool
def hash_identify(hash_value: str) -> str:
    """
    Identify the type of hash.

    Args:
        hash_value: Hash string to identify

    Returns:
        Possible hash types
    """
    results = [f"Hash Analysis: {hash_value[:50]}...", "=" * 50]

    hash_value = hash_value.strip()
    found = []

    for pattern, hash_type in HASH_PATTERNS:
        if re.match(pattern, hash_value, re.IGNORECASE):
            found.append(hash_type)

    if found:
        results.append(f"\nPossible hash types:")
        for ht in found:
            results.append(f"  - {ht}")
    else:
        results.append("\nUnknown hash format")
        results.append(f"Length: {len(hash_value)}")
        results.append(f"Charset: {'hex' if all(c in '0123456789abcdefABCDEF' for c in hash_value) else 'mixed'}")

    # Hashcat mode suggestions
    hashcat_modes = {
        "MD5": "0", "SHA-1": "100", "SHA-256": "1400", "SHA-512": "1700",
        "Bcrypt": "3200", "MD5 Crypt": "500", "MySQL 5.x": "300",
    }

    results.append("\n[Cracking Commands]")
    for ht in found:
        if ht in hashcat_modes:
            results.append(f"  hashcat -m {hashcat_modes[ht]} hash.txt wordlist.txt")

    return "\n".join(results)


@tool
def hash_crack(hash_value: str, wordlist: str = "common", hash_type: str = "auto") -> str:
    """
    Simple dictionary attack on a hash.

    Args:
        hash_value: Hash to crack
        wordlist: "common" for built-in, or comma-separated passwords
        hash_type: "auto", "md5", "sha1", "sha256", "sha512"

    Returns:
        Cracked password or failure message
    """
    results = [f"Hash Cracking: {hash_value[:30]}...", "=" * 50]

    passwords = COMMON_PASSWORDS if wordlist == "common" else wordlist.split(",")
    hash_value = hash_value.lower().strip()

    # Detect hash type
    if hash_type == "auto":
        if len(hash_value) == 32:
            hash_funcs = [("md5", hashlib.md5)]
        elif len(hash_value) == 40:
            hash_funcs = [("sha1", hashlib.sha1)]
        elif len(hash_value) == 64:
            hash_funcs = [("sha256", hashlib.sha256)]
        elif len(hash_value) == 128:
            hash_funcs = [("sha512", hashlib.sha512)]
        else:
            hash_funcs = [("md5", hashlib.md5), ("sha1", hashlib.sha1),
                         ("sha256", hashlib.sha256)]
    else:
        hash_map = {
            "md5": hashlib.md5, "sha1": hashlib.sha1,
            "sha256": hashlib.sha256, "sha512": hashlib.sha512
        }
        hash_funcs = [(hash_type, hash_map.get(hash_type, hashlib.md5))]

    results.append(f"Testing {len(passwords)} passwords...")

    for name, hash_func in hash_funcs:
        for password in passwords:
            computed = hash_func(password.encode()).hexdigest()
            if computed == hash_value:
                results.append(f"\n[!] CRACKED!")
                results.append(f"Password: {password}")
                results.append(f"Hash Type: {name}")
                return "\n".join(results)

    results.append("\nNot cracked with provided wordlist")
    results.append("Try: hashcat or john with larger wordlist")

    return "\n".join(results)


@tool
def jwt_decode(token: str) -> str:
    """
    Decode JWT token without verification.

    Args:
        token: JWT token string

    Returns:
        Decoded header, payload, and signature
    """
    results = ["JWT Token Decode", "=" * 50]

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return "Invalid JWT format (expected 3 parts)"

        # Decode header
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        # Decode payload
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        results.append("\n[Header]")
        results.append(json.dumps(header, indent=2))

        results.append("\n[Payload]")
        results.append(json.dumps(payload, indent=2))

        results.append(f"\n[Signature]")
        results.append(f"  {parts[2][:50]}...")

        # Security analysis
        results.append("\n[Security Analysis]")
        alg = header.get("alg", "unknown")
        if alg == "none":
            results.append("  [VULN] Algorithm 'none' - no signature!")
        elif alg in ["HS256", "HS384", "HS512"]:
            results.append(f"  Algorithm: {alg} (HMAC - brute-forceable)")
        else:
            results.append(f"  Algorithm: {alg}")

        # Check expiration
        if "exp" in payload:
            import time
            exp = payload["exp"]
            if exp < time.time():
                results.append("  [!] Token EXPIRED")
            else:
                results.append(f"  Expires: {exp} (valid)")

    except Exception as e:
        results.append(f"Error decoding: {e}")

    return "\n".join(results)


@tool
def jwt_forge(payload: str, secret: str = "", algorithm: str = "none") -> str:
    """
    Forge JWT with weak/no algorithm.

    Args:
        payload: JSON payload string
        secret: HMAC secret (empty for 'none' algorithm)
        algorithm: "none", "HS256" (with known secret)

    Returns:
        Forged JWT token
    """
    results = ["JWT Token Forge", "=" * 50]

    try:
        payload_data = json.loads(payload)
    except:
        return "Invalid JSON payload"

    # Create header
    header = {"alg": algorithm.upper(), "typ": "JWT"}

    # Encode header and payload
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=").decode()

    if algorithm.lower() == "none":
        # No signature
        token = f"{header_b64}.{payload_b64}."
        results.append("[!] Creating unsigned JWT (algorithm=none)")
    elif algorithm.upper().startswith("HS"):
        if not secret:
            return "HMAC algorithms require a secret"

        # HMAC signature
        message = f"{header_b64}.{payload_b64}"
        if algorithm.upper() == "HS256":
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        elif algorithm.upper() == "HS384":
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
        else:
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()

        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        token = f"{header_b64}.{payload_b64}.{sig_b64}"
    else:
        return f"Unsupported algorithm: {algorithm}"

    results.append(f"\n[Forged Token]")
    results.append(token)

    results.append(f"\n[Header]")
    results.append(json.dumps(header))

    results.append(f"\n[Payload]")
    results.append(json.dumps(payload_data, indent=2))

    return "\n".join(results)


@tool
def base_decode_all(data: str) -> str:
    """
    Try decoding data with multiple base encodings.

    Args:
        data: Encoded string to decode

    Returns:
        All successful decodings
    """
    results = ["Base Encoding Detection", "=" * 50]
    results.append(f"Input: {data[:50]}...")

    decodings = []

    # Base64
    try:
        decoded = base64.b64decode(data + "==").decode("utf-8", errors="ignore")
        if decoded.isprintable() and len(decoded) > 1:
            decodings.append(("Base64", decoded))
    except:
        pass

    # Base64 URL-safe
    try:
        decoded = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
        if decoded.isprintable() and len(decoded) > 1:
            decodings.append(("Base64 URL-safe", decoded))
    except:
        pass

    # Base32
    try:
        decoded = base64.b32decode(data.upper() + "=" * (8 - len(data) % 8)).decode("utf-8", errors="ignore")
        if decoded.isprintable() and len(decoded) > 1:
            decodings.append(("Base32", decoded))
    except:
        pass

    # Base16 (Hex)
    try:
        decoded = bytes.fromhex(data).decode("utf-8", errors="ignore")
        if decoded.isprintable() and len(decoded) > 1:
            decodings.append(("Hex/Base16", decoded))
    except:
        pass

    # ASCII85
    try:
        decoded = base64.a85decode(data.encode()).decode("utf-8", errors="ignore")
        if decoded.isprintable() and len(decoded) > 1:
            decodings.append(("ASCII85", decoded))
    except:
        pass

    if decodings:
        results.append("\n[Successful Decodings]")
        for encoding, decoded in decodings:
            results.append(f"\n{encoding}:")
            results.append(f"  {decoded[:100]}")
    else:
        results.append("\nNo valid decodings found")

    return "\n".join(results)


@tool
def rot_all(text: str) -> str:
    """
    Try all ROT (Caesar cipher) rotations.

    Args:
        text: Text to decode

    Returns:
        All 25 ROT variations
    """
    results = ["ROT/Caesar Cipher Decoder", "=" * 50]
    results.append(f"Input: {text}\n")

    def rotate(c: str, n: int) -> str:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            return chr((ord(c) - base + n) % 26 + base)
        return c

    for rot in range(1, 26):
        rotated = "".join(rotate(c, rot) for c in text)
        results.append(f"ROT{rot:2d}: {rotated}")

    return "\n".join(results)


@tool
def xor_decrypt(data: str, key_range: int = 255) -> str:
    """
    XOR brute force with single-byte keys.

    Args:
        data: Hex-encoded data
        key_range: Max key value to try (default 255)

    Returns:
        Printable results for each key
    """
    results = ["XOR Single-Byte Brute Force", "=" * 50]

    try:
        data_bytes = bytes.fromhex(data)
    except:
        return "Invalid hex input"

    results.append(f"Data length: {len(data_bytes)} bytes\n")
    results.append("[Printable results]")

    for key in range(min(key_range, 256)):
        decrypted = bytes([b ^ key for b in data_bytes])
        try:
            text = decrypted.decode("utf-8")
            if text.isprintable() and len(text.strip()) > 2:
                results.append(f"Key 0x{key:02x} ({key:3d}): {text[:60]}")
        except:
            pass

    return "\n".join(results)


# Export tools
TOOLS = [
    hash_identify,
    hash_crack,
    jwt_decode,
    jwt_forge,
    base_decode_all,
    rot_all,
    xor_decrypt,
]

TOOL_DESCRIPTIONS = {
    "hash_identify": "Identify hash type",
    "hash_crack": "Dictionary attack on hash",
    "jwt_decode": "Decode JWT without verification",
    "jwt_forge": "Forge JWT with weak algorithm",
    "base_decode_all": "Try all base encodings",
    "rot_all": "ROT1-25 decoder",
    "xor_decrypt": "XOR single-byte brute force",
}
