#!/usr/bin/env python3
"""
System Health Check - Verify all services and tools
Checks PKN, Code Academy, and required development tools
"""

import subprocess
import sys
from pathlib import Path


def check_command(cmd, name):
    """Check if a command is available."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5
        )
        print(f"✅ {name}: Available")
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print(f"❌ {name}: Not found")
        return False


def check_url(url, name):
    """Check if a URL is accessible."""
    try:
        import urllib.request
        urllib.request.urlopen(url, timeout=2)
        print(f"✅ {name}: Running")
        return True
    except Exception:
        print(f"❌ {name}: Not running")
        return False


def main():
    """Run all health checks."""
    print("🏥 System Health Check")
    print("=" * 60)

    all_healthy = True

    # Check required tools
    print("\n📦 Development Tools:")
    tools = [
        (['node', '--version'], 'Node.js'),
        (['pnpm', '--version'], 'pnpm'),
        (['python3', '--version'], 'Python 3'),
        (['just', '--version'], 'just'),
        (['git', '--version'], 'Git'),
    ]

    for cmd, name in tools:
        if not check_command(cmd, name):
            all_healthy = False

    # Check optional tools
    print("\n🔧 Optional Tools:")
    optional_tools = [
        (['pre-commit', '--version'], 'pre-commit'),
        (['biome', '--version'], 'Biome'),
    ]

    for cmd, name in optional_tools:
        check_command(cmd, name)  # Don't fail on optional

    # Check services
    print("\n🚀 Services:")
    services = [
        ('http://localhost:8010/health', 'PKN Server'),
        ('http://localhost:8011', 'Code Academy'),
    ]

    for url, name in services:
        check_url(url, name)  # Don't fail if not running

    # Check workspace structure
    print("\n📁 Workspace Structure:")
    required_dirs = [
        'apps/pkn',
        'apps/code-academy',
        'apps/pkn-mobile',
        'packages/shared-config',
        'scripts',
    ]

    for dir_path in required_dirs:
        path = Path(dir_path)
        if path.exists():
            print(f"✅ {dir_path}: Exists")
        else:
            print(f"❌ {dir_path}: Missing")
            all_healthy = False

    print("\n" + "=" * 60)
    if all_healthy:
        print("✅ All critical checks passed")
        sys.exit(0)
    else:
        print("⚠️  Some checks failed (see above)")
        sys.exit(1)


if __name__ == '__main__':
    main()
