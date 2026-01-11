#!/usr/bin/env python3
"""
Clean Build Script
Removes cache, temp files, and resets for fresh build
"""

import os
import shutil
from pathlib import Path

PKN_DIR = Path(__file__).parent

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_ok(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.END}")

def print_info(msg):
    print(f"{Colors.CYAN}ℹ {msg}{Colors.END}")

def clean_pycache():
    """Remove Python cache files"""
    print_info("Cleaning Python cache...")
    count = 0

    for pycache in PKN_DIR.rglob("__pycache__"):
        shutil.rmtree(pycache)
        count += 1

    for pyc in PKN_DIR.rglob("*.pyc"):
        pyc.unlink()
        count += 1

    if count > 0:
        print_ok(f"Removed {count} Python cache files/directories")
    else:
        print_ok("No Python cache found")

def clean_logs():
    """Clean log files"""
    print_info("Cleaning logs...")

    log_files = [
        PKN_DIR / "divinenode.log",
        PKN_DIR / "llama.log",
        PKN_DIR / "parakleon.log",
    ]

    count = 0
    for log in log_files:
        if log.exists():
            # Truncate instead of delete (some processes may have it open)
            log.write_text("")
            count += 1

    if count > 0:
        print_ok(f"Cleared {count} log file(s)")
    else:
        print_ok("No logs to clear")

def clean_temp_files():
    """Remove temporary test files"""
    print_info("Cleaning temporary files...")

    temp_patterns = [
        "test_*.html",
        "debug_*.html",
        "verify_*.html",
        "quick_*.html",
        "*_backup_*",
        "*.bak",
        ".DS_Store",
    ]

    count = 0
    for pattern in temp_patterns:
        for file in PKN_DIR.glob(pattern):
            if file.is_file() and file.name not in ['test_free_agents.py', 'test_fixed_agents.py']:
                file.unlink()
                count += 1

    if count > 0:
        print_ok(f"Removed {count} temporary file(s)")
    else:
        print_ok("No temporary files found")

def show_space_saved():
    """Show current directory size"""
    total = sum(f.stat().st_size for f in PKN_DIR.rglob('*') if f.is_file())
    size_mb = total / (1024 * 1024)
    print_info(f"Current PKN directory size: {size_mb:.1f} MB")

def main():
    print(f"{Colors.CYAN}{Colors.BOLD}PKN Clean Build Tool{Colors.END}\n")

    clean_pycache()
    clean_logs()
    clean_temp_files()

    print(f"\n{Colors.BOLD}Clean complete!{Colors.END}\n")
    show_space_saved()

if __name__ == "__main__":
    main()
