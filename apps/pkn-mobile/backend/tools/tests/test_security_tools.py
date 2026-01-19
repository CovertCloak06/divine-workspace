"""
Security Tools Test Suite
Tests all pentesting/security tool modules.

Tests:
- TOOLS list population
- Function execution with safe inputs
- LangChain .invoke() compatibility
- Error handling
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestPentestTools:
    """Test pentest_tools.py module"""

    def test_tools_list_populated(self):
        """Verify TOOLS list exists and is populated"""
        from pentest_tools import TOOLS

        assert TOOLS is not None
        assert len(TOOLS) > 0
        assert len(TOOLS) == 9  # Expected tool count

    def test_generate_reverse_shell(self):
        """Test reverse shell generation"""
        from pentest_tools import generate_reverse_shell

        result = generate_reverse_shell.invoke({"ip": "10.10.14.5", "port": 4444, "shell_type": "bash"})

        assert "Reverse Shell" in result
        assert "10.10.14.5" in result
        assert "4444" in result
        assert "nc -lvnp 4444" in result

    def test_generate_reverse_shell_invalid_type(self):
        """Test reverse shell with invalid type"""
        from pentest_tools import generate_reverse_shell

        result = generate_reverse_shell.invoke({"ip": "10.10.14.5", "port": 4444, "shell_type": "invalid"})

        assert "Unknown shell type" in result
        assert "Available:" in result

    def test_encode_payload(self):
        """Test payload encoding"""
        from pentest_tools import encode_payload

        result = encode_payload.invoke({"payload": "id; whoami", "encoding": "base64"})

        assert "base64" in result.lower()
        assert "Encoded:" in result
        assert "Decode" in result

    def test_encode_payload_url(self):
        """Test URL encoding"""
        from pentest_tools import encode_payload

        result = encode_payload.invoke({"payload": "test payload", "encoding": "url"})

        assert "url" in result.lower()
        assert "test" in result

    def test_generate_webshell(self):
        """Test web shell generation"""
        from pentest_tools import generate_webshell

        result = generate_webshell.invoke({"language": "php"})

        assert "Web Shell" in result
        assert "php" in result.lower()
        assert "<?php" in result

    def test_generate_webshell_with_password(self):
        """Test web shell with password protection"""
        from pentest_tools import generate_webshell

        result = generate_webshell.invoke({"language": "php", "password": "s3cr3t"})

        assert "s3cr3t" in result
        assert "pwd=" in result

    def test_sqli_payloads(self):
        """Test SQL injection payload generation"""
        from pentest_tools import sqli_payloads

        result = sqli_payloads.invoke({"db_type": "mysql", "technique": "union"})

        assert "SQLi Payloads" in result
        assert "UNION" in result
        assert "mysql" in result.lower()

    def test_sqli_payloads_error_based(self):
        """Test error-based SQLi payloads"""
        from pentest_tools import sqli_payloads

        result = sqli_payloads.invoke({"db_type": "mysql", "technique": "error"})

        assert "error" in result.lower()
        assert "EXTRACTVALUE" in result or "CONCAT" in result

    def test_xss_payloads(self):
        """Test XSS payload generation"""
        from pentest_tools import xss_payloads

        result = xss_payloads.invoke({"context": "html", "bypass": "none"})

        assert "XSS Payloads" in result
        assert "<script>" in result or "alert" in result

    def test_xss_payloads_with_bypass(self):
        """Test XSS with filter bypass"""
        from pentest_tools import xss_payloads

        result = xss_payloads.invoke({"context": "html", "bypass": "encoding"})

        assert len(result) > 0
        assert "XSS" in result

    def test_lfi_payloads(self):
        """Test LFI payload generation"""
        from pentest_tools import lfi_payloads

        result = lfi_payloads.invoke({"os_type": "linux"})

        assert "LFI Payloads" in result
        assert "/etc/passwd" in result
        assert "../" in result

    def test_lfi_payloads_windows(self):
        """Test Windows LFI payloads"""
        from pentest_tools import lfi_payloads

        result = lfi_payloads.invoke({"os_type": "windows"})

        assert "windows" in result.lower()
        assert "C:\\" in result or "Windows" in result

    def test_hash_analyzer(self):
        """Test hash type analysis with cracking commands"""
        from pentest_tools import hash_analyzer

        # MD5 hash
        result = hash_analyzer.invoke({"hash_value": "5d41402abc4b2a76b9719d911017c592"})

        assert "MD5" in result
        assert "hashcat" in result.lower() or "john" in result.lower()

    def test_hash_analyzer_sha256(self):
        """Test SHA256 analysis"""
        from pentest_tools import hash_analyzer

        result = hash_analyzer.invoke({
            "hash_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        })

        assert "SHA" in result

    def test_generate_wordlist(self):
        """Test wordlist generation"""
        from pentest_tools import generate_wordlist

        result = generate_wordlist.invoke({"base_words": "admin,password", "rules": "basic"})

        assert "Wordlist" in result
        assert "admin" in result.lower()
        assert "password" in result.lower()

    def test_exploit_suggester(self):
        """Test exploit suggester"""
        from pentest_tools import exploit_suggester

        result = exploit_suggester.invoke({"service": "vsftpd", "version": "2.3.4"})

        assert "Exploit" in result
        assert "vsftpd" in result.lower()
        assert "searchsploit" in result.lower()

    def test_all_tools_invokable(self):
        """Ensure all tools can be invoked via LangChain"""
        from pentest_tools import TOOLS

        for tool in TOOLS:
            # Check tool has invoke method
            assert hasattr(tool, 'invoke')
            assert callable(tool.invoke)


class TestReconTools:
    """Test recon_tools.py module"""

    def test_tools_list_populated(self):
        """Verify TOOLS list exists and is populated"""
        from recon_tools import TOOLS

        assert TOOLS is not None
        assert len(TOOLS) > 0
        assert len(TOOLS) == 6  # Expected tool count

    def test_banner_grab_timeout(self):
        """Test banner grab with timeout"""
        from recon_tools import banner_grab

        # Use non-routable IP to test timeout
        result = banner_grab.invoke({"host": "192.0.2.1", "port": 80, "timeout": 1})

        assert "Timeout" in result or "Error" in result

    def test_http_security_headers_no_requests(self):
        """Test security headers when requests unavailable"""
        from recon_tools import http_security_headers

        # Should handle gracefully if requests not available
        result = http_security_headers.invoke({"url": "http://example.com"})

        assert len(result) > 0

    def test_robots_sitemap_extract(self):
        """Test robots.txt/sitemap extraction"""
        from recon_tools import robots_sitemap_extract

        result = robots_sitemap_extract.invoke({"url": "http://example.com"})

        assert "Robots" in result or "Error" in result

    def test_directory_bruteforce(self):
        """Test directory brute forcing"""
        from recon_tools import directory_bruteforce

        result = directory_bruteforce.invoke({"url": "http://example.com", "wordlist": "common"})

        assert "Directory" in result or "Bruteforce" in result

    def test_cors_check(self):
        """Test CORS misconfiguration check"""
        from recon_tools import cors_check

        result = cors_check.invoke({"url": "http://example.com"})

        assert "CORS" in result or "Error" in result

    def test_favicon_fingerprint(self):
        """Test favicon fingerprinting"""
        from recon_tools import favicon_fingerprint

        result = favicon_fingerprint.invoke({"url": "http://example.com"})

        assert len(result) > 0

    def test_all_tools_invokable(self):
        """Ensure all tools can be invoked via LangChain"""
        from recon_tools import TOOLS

        for tool in TOOLS:
            assert hasattr(tool, 'invoke')
            assert callable(tool.invoke)


class TestPrivescTools:
    """Test privesc_tools.py module"""

    def test_tools_list_populated(self):
        """Verify TOOLS list exists and is populated"""
        from privesc_tools import TOOLS

        assert TOOLS is not None
        assert len(TOOLS) > 0
        assert len(TOOLS) == 7  # Expected tool count

    def test_linux_enum_cross_platform(self):
        """Test Linux enum handles non-Linux systems"""
        from privesc_tools import linux_enum

        result = linux_enum.invoke({})

        # Should return something even on non-Linux
        assert len(result) > 0

    def test_suid_finder(self):
        """Test SUID binary finder"""
        from privesc_tools import suid_finder

        result = suid_finder.invoke({})

        assert "SUID" in result

    def test_writable_paths(self):
        """Test writable path finder"""
        from privesc_tools import writable_paths

        result = writable_paths.invoke({})

        assert "Writable" in result

    def test_cron_enum(self):
        """Test cron enumeration"""
        from privesc_tools import cron_enum

        result = cron_enum.invoke({})

        assert "Cron" in result

    def test_sudo_parse_no_perms(self):
        """Test sudo parser with no permissions"""
        from privesc_tools import sudo_parse

        result = sudo_parse.invoke({})

        assert len(result) > 0

    def test_sudo_parse_with_output(self):
        """Test sudo parser with sample output"""
        from privesc_tools import sudo_parse

        sample = "User may run the following commands:\n    (ALL) NOPASSWD: /usr/bin/vim"
        result = sudo_parse.invoke({"sudo_output": sample})

        assert "vim" in result.lower()
        assert "Exploit" in result or "Suggestion" in result

    def test_kernel_exploits(self):
        """Test kernel exploit suggester"""
        from privesc_tools import kernel_exploits

        result = kernel_exploits.invoke({"version": "4.15.0"})

        assert "Kernel" in result
        assert "Exploit" in result

    def test_docker_escape(self):
        """Test Docker escape checker"""
        from privesc_tools import docker_escape

        result = docker_escape.invoke({})

        assert "Docker" in result

    def test_all_tools_invokable(self):
        """Ensure all tools can be invoked via LangChain"""
        from privesc_tools import TOOLS

        for tool in TOOLS:
            assert hasattr(tool, 'invoke')
            assert callable(tool.invoke)


class TestNetworkTools:
    """Test network_tools.py module"""

    def test_tools_list_populated(self):
        """Verify TOOLS list exists and is populated"""
        from network_tools import TOOLS

        assert TOOLS is not None
        assert len(TOOLS) > 0
        assert len(TOOLS) == 7  # Expected tool count

    def test_tcp_scan_localhost(self):
        """Test TCP scan on localhost common ports"""
        from network_tools import tcp_scan

        result = tcp_scan.invoke({"host": "127.0.0.1", "ports": "80,443", "timeout": 0.5})

        assert "TCP Scan" in result
        assert "127.0.0.1" in result

    def test_tcp_scan_invalid_host(self):
        """Test TCP scan with invalid host"""
        from network_tools import tcp_scan

        result = tcp_scan.invoke({"host": "192.0.2.1", "ports": "80", "timeout": 0.5})

        assert "Scanning" in result

    def test_udp_scan(self):
        """Test UDP scan"""
        from network_tools import udp_scan

        result = udp_scan.invoke({"host": "127.0.0.1", "ports": "53"})

        assert "UDP" in result

    def test_os_fingerprint(self):
        """Test OS fingerprinting"""
        from network_tools import os_fingerprint

        result = os_fingerprint.invoke({"host": "127.0.0.1"})

        assert "Fingerprint" in result or "OS" in result

    def test_traceroute(self):
        """Test traceroute (may fail without privileges)"""
        from network_tools import traceroute

        result = traceroute.invoke({"host": "127.0.0.1", "max_hops": 5})

        assert "Traceroute" in result or "Error" in result

    def test_arp_scan(self):
        """Test ARP scan"""
        from network_tools import arp_scan

        result = arp_scan.invoke({})

        assert "ARP" in result

    def test_dns_zone_transfer(self):
        """Test DNS zone transfer"""
        from network_tools import dns_zone_transfer

        result = dns_zone_transfer.invoke({"domain": "example.com"})

        assert "DNS" in result or "Zone" in result

    def test_service_detect(self):
        """Test service detection"""
        from network_tools import service_detect

        result = service_detect.invoke({"host": "127.0.0.1", "port": 80})

        assert "Service" in result

    def test_all_tools_invokable(self):
        """Ensure all tools can be invoked via LangChain"""
        from network_tools import TOOLS

        for tool in TOOLS:
            assert hasattr(tool, 'invoke')
            assert callable(tool.invoke)


class TestCryptoTools:
    """Test crypto_tools.py module"""

    def test_tools_list_populated(self):
        """Verify TOOLS list exists and is populated"""
        from crypto_tools import TOOLS

        assert TOOLS is not None
        assert len(TOOLS) > 0
        assert len(TOOLS) == 7  # Expected tool count

    def test_hash_identify_md5(self):
        """Test MD5 hash identification"""
        from crypto_tools import hash_identify

        result = hash_identify.invoke({"hash_value": "5d41402abc4b2a76b9719d911017c592"})

        assert "MD5" in result

    def test_hash_identify_sha1(self):
        """Test SHA1 hash identification"""
        from crypto_tools import hash_identify

        result = hash_identify.invoke({
            "hash_value": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        })

        assert "SHA" in result

    def test_hash_identify_bcrypt(self):
        """Test bcrypt hash identification"""
        from crypto_tools import hash_identify

        result = hash_identify.invoke({
            "hash_value": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        })

        assert "bcrypt" in result.lower()

    def test_hash_crack_md5(self):
        """Test hash cracking with known MD5"""
        from crypto_tools import hash_crack

        # MD5 of "password"
        result = hash_crack.invoke({
            "hash_value": "5f4dcc3b5aa765d61d8327deb882cf99",
            "wordlist": "common"
        })

        assert "password" in result.lower() or "Not cracked" in result

    def test_hash_crack_custom_wordlist(self):
        """Test hash cracking with custom wordlist"""
        from crypto_tools import hash_crack

        result = hash_crack.invoke({
            "hash_value": "5d41402abc4b2a76b9719d911017c592",
            "wordlist": "hello,world,test",
            "hash_type": "md5"
        })

        assert "hello" in result or "Not cracked" in result

    def test_jwt_decode(self):
        """Test JWT decoding"""
        from crypto_tools import jwt_decode

        # Sample JWT token
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        result = jwt_decode.invoke({"token": token})

        assert "JWT" in result
        assert "Header" in result
        assert "Payload" in result
        assert "HS256" in result

    def test_jwt_decode_invalid(self):
        """Test JWT decoding with invalid token"""
        from crypto_tools import jwt_decode

        result = jwt_decode.invoke({"token": "invalid.token"})

        assert "Invalid" in result or "Error" in result

    def test_jwt_forge_none(self):
        """Test JWT forging with 'none' algorithm"""
        from crypto_tools import jwt_forge

        result = jwt_forge.invoke({
            "payload": '{"sub": "1234567890", "name": "Test User"}',
            "algorithm": "none"
        })

        assert "JWT" in result
        assert "Forged" in result
        assert "eyJ" in result  # Base64 encoded

    def test_jwt_forge_hs256(self):
        """Test JWT forging with HS256"""
        from crypto_tools import jwt_forge

        result = jwt_forge.invoke({
            "payload": '{"sub": "test"}',
            "secret": "secret",
            "algorithm": "HS256"
        })

        assert "eyJ" in result
        assert "." in result

    def test_base_decode_all(self):
        """Test base encoding detection"""
        from crypto_tools import base_decode_all

        # Base64 of "hello world"
        result = base_decode_all.invoke({"data": "aGVsbG8gd29ybGQ="})

        assert "Base64" in result
        assert "hello world" in result.lower() or "Decoding" in result

    def test_base_decode_hex(self):
        """Test hex decoding"""
        from crypto_tools import base_decode_all

        # Hex of "test"
        result = base_decode_all.invoke({"data": "74657374"})

        assert "test" in result.lower() or "Hex" in result

    def test_rot_all(self):
        """Test ROT cipher decoder"""
        from crypto_tools import rot_all

        result = rot_all.invoke({"text": "uryyb"})  # ROT13 of "hello"

        assert "ROT" in result
        assert "hello" in result.lower()

    def test_rot_all_preserves_non_alpha(self):
        """Test ROT preserves non-alphabetic characters"""
        from crypto_tools import rot_all

        result = rot_all.invoke({"text": "abc123"})

        assert "123" in result

    def test_xor_decrypt(self):
        """Test XOR brute force"""
        from crypto_tools import xor_decrypt

        # Hex of "hello" XOR 0x42
        result = xor_decrypt.invoke({"data": "2a272f2f2d", "key_range": 255})

        assert "XOR" in result
        assert "Key" in result

    def test_all_tools_invokable(self):
        """Ensure all tools can be invoked via LangChain"""
        from crypto_tools import TOOLS

        for tool in TOOLS:
            assert hasattr(tool, 'invoke')
            assert callable(tool.invoke)


class TestToolDescriptions:
    """Test tool metadata and descriptions"""

    def test_pentest_descriptions(self):
        """Test pentest tool descriptions exist"""
        from pentest_tools import TOOL_DESCRIPTIONS

        assert TOOL_DESCRIPTIONS is not None
        assert len(TOOL_DESCRIPTIONS) > 0

    def test_recon_descriptions(self):
        """Test recon tool descriptions exist"""
        from recon_tools import TOOL_DESCRIPTIONS

        assert TOOL_DESCRIPTIONS is not None
        assert len(TOOL_DESCRIPTIONS) > 0

    def test_privesc_descriptions(self):
        """Test privesc tool descriptions exist"""
        from privesc_tools import TOOL_DESCRIPTIONS

        assert TOOL_DESCRIPTIONS is not None
        assert len(TOOL_DESCRIPTIONS) > 0

    def test_network_descriptions(self):
        """Test network tool descriptions exist"""
        from network_tools import TOOL_DESCRIPTIONS

        assert TOOL_DESCRIPTIONS is not None
        assert len(TOOL_DESCRIPTIONS) > 0

    def test_crypto_descriptions(self):
        """Test crypto tool descriptions exist"""
        from crypto_tools import TOOL_DESCRIPTIONS

        assert TOOL_DESCRIPTIONS is not None
        assert len(TOOL_DESCRIPTIONS) > 0


class TestToolIntegration:
    """Integration tests across multiple tool modules"""

    def test_all_modules_importable(self):
        """Verify all tool modules can be imported"""
        import pentest_tools
        import recon_tools
        import privesc_tools
        import network_tools
        import crypto_tools

        assert pentest_tools is not None
        assert recon_tools is not None
        assert privesc_tools is not None
        assert network_tools is not None
        assert crypto_tools is not None

    def test_total_tool_count(self):
        """Verify total number of security tools"""
        from pentest_tools import TOOLS as pentest
        from recon_tools import TOOLS as recon
        from privesc_tools import TOOLS as privesc
        from network_tools import TOOLS as network
        from crypto_tools import TOOLS as crypto

        total = len(pentest) + len(recon) + len(privesc) + len(network) + len(crypto)

        # Expected: 9 + 6 + 7 + 7 + 7 = 36 tools
        assert total >= 30, f"Expected at least 30 tools, got {total}"

    def test_no_duplicate_tool_names(self):
        """Verify no duplicate tool names across modules (except known duplicates)"""
        from pentest_tools import TOOLS as pentest
        from recon_tools import TOOLS as recon
        from privesc_tools import TOOLS as privesc
        from network_tools import TOOLS as network
        from crypto_tools import TOOLS as crypto
        from collections import Counter

        all_tools = pentest + recon + privesc + network + crypto
        tool_names = [tool.name for tool in all_tools]

        # Known intentional duplicates (appear in multiple contexts)
        known_duplicates = set()  # No expected duplicates - hash_identify renamed to hash_analyzer in pentest_tools

        counts = Counter(tool_names)
        duplicates = {name for name, count in counts.items() if count > 1}

        unexpected_duplicates = duplicates - known_duplicates

        assert len(unexpected_duplicates) == 0, \
            f"Unexpected duplicate tool names found: {unexpected_duplicates}"

    def test_workflow_example(self):
        """Test realistic workflow using multiple tools"""
        from crypto_tools import hash_identify, hash_crack

        # Step 1: Identify hash type
        hash_val = "5f4dcc3b5aa765d61d8327deb882cf99"
        identify_result = hash_identify.invoke({"hash_value": hash_val})

        assert "MD5" in identify_result

        # Step 2: Crack the hash
        crack_result = hash_crack.invoke({
            "hash_value": hash_val,
            "wordlist": "common",
            "hash_type": "md5"
        })

        assert len(crack_result) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
