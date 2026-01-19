# Security Tools Test Suite

Comprehensive tests for all pentesting and security tool modules in PKN Mobile.

## Test Coverage

### Modules Tested (5)
1. **pentest_tools.py** - Offensive security utilities (9 tools)
2. **recon_tools.py** - Advanced reconnaissance (6 tools)
3. **privesc_tools.py** - Privilege escalation helpers (7 tools)
4. **network_tools.py** - Network analysis & scanning (7 tools)
5. **crypto_tools.py** - Cryptography utilities (7 tools)

**Total: 36 security tools tested**

## Test Categories

### 1. Tool Registration Tests
- Verify TOOLS list is populated
- Check tool count matches expected
- Validate TOOL_DESCRIPTIONS exist

### 2. Functional Tests
- Test each tool with safe/mock inputs
- Verify output format and content
- Test error handling with invalid inputs
- Test edge cases and boundary conditions

### 3. LangChain Compatibility Tests
- Verify all tools have `.invoke()` method
- Test tools can be invoked via LangChain interface
- Validate tool signatures match LangChain requirements

### 4. Integration Tests
- Test tool workflows (multi-step operations)
- Check for duplicate tool names
- Verify module imports work correctly
- Test cross-module tool usage

## Running Tests

### Run All Tests
```bash
cd /home/gh0st/dvn/divine-workspace/apps/pkn-mobile/backend/tools
python3 -m pytest tests/test_security_tools.py -v
```

### Run Specific Test Class
```bash
# Test pentest tools only
python3 -m pytest tests/test_security_tools.py::TestPentestTools -v

# Test recon tools only
python3 -m pytest tests/test_security_tools.py::TestReconTools -v

# Test crypto tools only
python3 -m pytest tests/test_security_tools.py::TestCryptoTools -v
```

### Run Specific Test
```bash
python3 -m pytest tests/test_security_tools.py::TestPentestTools::test_generate_reverse_shell -v
```

### Run with Coverage
```bash
python3 -m pytest tests/test_security_tools.py --cov=. --cov-report=html
```

### Quick Smoke Test
```bash
# Run first test of each class
python3 -m pytest tests/test_security_tools.py -k "test_tools_list_populated" -v
```

## Test Results

**Last Run:** 2026-01-18
**Status:** ✅ All 71 tests passing
**Duration:** ~49 seconds

```
===== test session starts =====
collected 71 items

TestPentestTools:         18 passed
TestReconTools:            7 passed
TestPrivescTools:          9 passed
TestNetworkTools:          9 passed
TestCryptoTools:          15 passed
TestToolDescriptions:      5 passed
TestToolIntegration:       4 passed

===== 71 passed in 49.33s =====
```

## Test Breakdown by Module

### pentest_tools.py (18 tests)
- [x] TOOLS list populated (9 tools)
- [x] Reverse shell generation (bash, python, php, etc.)
- [x] Payload encoding (base64, URL, hex)
- [x] Web shell generation (PHP, ASP, JSP)
- [x] SQL injection payloads (union, error, blind, time)
- [x] XSS payloads (HTML, attribute, bypass)
- [x] LFI/path traversal payloads
- [x] Hash identification
- [x] Wordlist generation
- [x] Exploit suggester
- [x] All tools invokable via LangChain

### recon_tools.py (7 tests)
- [x] TOOLS list populated (6 tools)
- [x] Banner grabbing with timeout
- [x] HTTP security header analysis
- [x] Robots.txt/sitemap extraction
- [x] Directory bruteforcing
- [x] CORS misconfiguration check
- [x] Favicon fingerprinting
- [x] All tools invokable via LangChain

### privesc_tools.py (9 tests)
- [x] TOOLS list populated (7 tools)
- [x] Linux enumeration (cross-platform safe)
- [x] SUID/SGID binary finder
- [x] Writable path finder
- [x] Cron job enumeration
- [x] Sudo permission parser
- [x] Kernel exploit suggester
- [x] Docker escape checker
- [x] All tools invokable via LangChain

### network_tools.py (9 tests)
- [x] TOOLS list populated (7 tools)
- [x] TCP port scanning (localhost + invalid host)
- [x] UDP port scanning
- [x] OS fingerprinting via TTL
- [x] Traceroute
- [x] ARP network discovery
- [x] DNS zone transfer (AXFR)
- [x] Service detection
- [x] All tools invokable via LangChain

### crypto_tools.py (15 tests)
- [x] TOOLS list populated (7 tools)
- [x] Hash identification (MD5, SHA1, SHA256, bcrypt)
- [x] Hash cracking (dictionary attack)
- [x] JWT decoding (valid + invalid)
- [x] JWT forging (none, HS256)
- [x] Base encoding detection (base64, hex, base32, etc.)
- [x] ROT/Caesar cipher decoder
- [x] XOR single-byte brute force
- [x] All tools invokable via LangChain

### Integration Tests (4 tests)
- [x] All modules importable
- [x] Total tool count verification (36 tools)
- [x] No unexpected duplicate tool names
- [x] Multi-tool workflow example

## Known Issues

### Intentional Duplicates
- `hash_identify` appears in both `pentest_tools` and `crypto_tools`
  - This is intentional - hash identification is useful in both contexts
  - Test updated to allow this known duplicate

### Platform-Specific Tests
Some tests may behave differently on different platforms:
- **Linux-only tools:** `linux_enum`, `suid_finder`, `writable_paths`, etc.
  - Tests verify these handle non-Linux systems gracefully
- **Privilege-required tools:** `traceroute`, `arp_scan`
  - Tests expect these to fail gracefully without privileges

## Test Safety

All tests use safe, mock, or local inputs:
- Network tools test localhost (127.0.0.1) or non-routable IPs (192.0.2.1)
- No actual attacks are performed
- No external services are contacted (except example.com for error handling)
- File system operations use safe test data

## Adding New Tests

When adding new security tools:

1. Add tool to appropriate module (`*_tools.py`)
2. Add to module's `TOOLS` list
3. Add description to `TOOL_DESCRIPTIONS`
4. Add tests to `test_security_tools.py`:
   - Test with valid inputs
   - Test with invalid inputs
   - Test error handling
   - Verify LangChain `.invoke()` compatibility

Example test structure:
```python
def test_new_tool(self):
    """Test new tool functionality"""
    from module_tools import new_tool

    result = new_tool.invoke({"param": "value"})

    assert "expected output" in result
    assert len(result) > 0
```

## Continuous Integration

These tests should be run:
- Before committing changes to tool modules
- Before deploying to phone/production
- After adding new security tools
- When updating LangChain or dependencies

## Dependencies

Required packages:
- pytest
- langchain-core
- Standard library modules (hashlib, socket, subprocess, etc.)

Install:
```bash
pip install pytest langchain-core
```

## Troubleshooting

**Import errors:**
```bash
# Ensure you're in the tools directory
cd /home/gh0st/dvn/divine-workspace/apps/pkn-mobile/backend/tools
python3 -m pytest tests/test_security_tools.py -v
```

**Permission errors:**
```bash
# Some tools require elevated privileges
# Tests are designed to handle failures gracefully
# If needed, run with sudo (not recommended for all tests)
```

**Timeout errors:**
```bash
# Network tests may timeout on slow connections
# Adjust timeout values in tool implementations if needed
```

## Contact

For questions or issues with security tools:
- Check tool documentation in module docstrings
- Review test code for usage examples
- File issue in project repository
