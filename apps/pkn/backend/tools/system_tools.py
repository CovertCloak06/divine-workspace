"""
System Tools - Terminal & System Control
Inspired by Claude Code's Bash and execution tools.

Tools:
- bash: Execute shell commands (maximum power)
- bash_stream: Execute with streaming output
- process_list: List running processes
- process_kill: Kill processes
- read_logs: Tail log files
- todo_write: Visual task tracking
- system_info: CPU, memory, disk usage
"""

import os
import subprocess
import signal
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from langchain_core.tools import tool


PROJECT_ROOT = Path("/home/gh0st/pkn")


@tool
def bash(
    command: str,
    cwd: Optional[str] = None,
    timeout: int = 120,
    description: Optional[str] = None
) -> str:
    """
    Execute a shell command with full bash capabilities.

    POWERFUL: Can run ANY bash command. Use responsibly!

    Args:
        command: Shell command to execute
        cwd: Working directory (default: project root)
        timeout: Maximum execution time in seconds (default: 120, max: 600)
        description: Optional description of what this command does

    Returns:
        Command output (stdout + stderr)

    Examples:
        bash("ls -la")
        bash("pip install flask", description="Install Flask package")
        bash("./pkn_control.sh start-divinenode")
        bash("grep -r TODO .", timeout=30)

    Safety notes:
        - Commands run with current user permissions
        - Use absolute paths or cwd for clarity
        - Timeout prevents infinite loops
    """
    try:
        # Validate timeout
        if timeout > 600:
            return "Error: timeout cannot exceed 600 seconds (10 minutes)"

        # Set working directory
        working_dir = Path(cwd) if cwd else PROJECT_ROOT
        if not working_dir.is_absolute():
            working_dir = PROJECT_ROOT / working_dir

        # Log command for debugging
        log_msg = f"Executing: {command}"
        if description:
            log_msg += f" ({description})"
        print(log_msg)

        # Execute command
        result = subprocess.run(
            command,
            shell=True,
            cwd=str(working_dir),
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Combine stdout and stderr
        output = []
        if result.stdout:
            output.append("STDOUT:\n" + result.stdout)
        if result.stderr:
            output.append("STDERR:\n" + result.stderr)

        if not output:
            output.append("(Command completed with no output)")

        # Add return code
        output.append(f"\nReturn code: {result.returncode}")

        return '\n'.join(output)

    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout} seconds"
    except Exception as e:
        return f"Error executing command: {e}"


@tool
def bash_background(
    command: str,
    cwd: Optional[str] = None,
    description: Optional[str] = None
) -> str:
    """
    Execute a command in the background (non-blocking).

    Use for long-running processes like servers.

    Args:
        command: Shell command to execute
        cwd: Working directory
        description: What this command does

    Returns:
        Process ID (PID) of background process

    Examples:
        bash_background("python divinenode_server.py", description="Start server")
        bash_background("./llama.cpp/server -m model.gguf")
    """
    try:
        working_dir = Path(cwd) if cwd else PROJECT_ROOT
        if not working_dir.is_absolute():
            working_dir = PROJECT_ROOT / working_dir

        log_msg = f"Starting background: {command}"
        if description:
            log_msg += f" ({description})"
        print(log_msg)

        # Start process in background
        process = subprocess.Popen(
            command,
            shell=True,
            cwd=str(working_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return f"✅ Started background process (PID: {process.pid})"

    except Exception as e:
        return f"Error starting background process: {e}"


@tool
def process_list(filter_pattern: Optional[str] = None) -> str:
    """
    List running processes, optionally filtered by name.

    Args:
        filter_pattern: Optional grep pattern to filter processes

    Returns:
        List of matching processes

    Examples:
        process_list() - All processes
        process_list("python") - Python processes
        process_list("divinenode") - DivineNode processes
    """
    try:
        if filter_pattern:
            cmd = f"ps aux | grep -i {filter_pattern} | grep -v grep"
        else:
            cmd = "ps aux"

        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )

        if not result.stdout.strip():
            return f"No processes found matching: {filter_pattern}"

        return result.stdout

    except Exception as e:
        return f"Error listing processes: {e}"


@tool
def process_kill(pid_or_name: str, force: bool = False) -> str:
    """
    Kill a process by PID or name.

    Args:
        pid_or_name: Process ID (number) or process name (string)
        force: Use SIGKILL instead of SIGTERM (force kill)

    Returns:
        Status message

    Examples:
        process_kill("1234") - Kill PID 1234
        process_kill("divinenode_server.py") - Kill by name
        process_kill("zombie_process", force=True) - Force kill

    Safety:
        - SIGTERM (default) allows graceful shutdown
        - SIGKILL (force=True) immediately terminates
    """
    try:
        # Check if PID or name
        if pid_or_name.isdigit():
            # Kill by PID
            pid = int(pid_or_name)
            sig = signal.SIGKILL if force else signal.SIGTERM
            os.kill(pid, sig)
            return f"✅ Killed process {pid} ({'SIGKILL' if force else 'SIGTERM'})"
        else:
            # Kill by name using pkill
            cmd = ['pkill']
            if force:
                cmd.append('-9')  # SIGKILL
            cmd.append(pid_or_name)

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                return f"✅ Killed process(es) matching: {pid_or_name}"
            else:
                return f"No processes found matching: {pid_or_name}"

    except ProcessLookupError:
        return f"Process not found: {pid_or_name}"
    except PermissionError:
        return f"Permission denied: Cannot kill process {pid_or_name}"
    except Exception as e:
        return f"Error killing process: {e}"


@tool
def read_logs(
    file_path: str,
    lines: int = 50,
    follow: bool = False
) -> str:
    """
    Read log files (like tail command).

    Args:
        file_path: Path to log file
        lines: Number of lines to show (default: 50)
        follow: If True, stream new lines (not implemented in tool version)

    Returns:
        Last N lines of log file

    Examples:
        read_logs("divinenode.log")
        read_logs("llama.log", lines=100)
    """
    try:
        path = Path(file_path)
        if not path.is_absolute():
            path = PROJECT_ROOT / path

        if not path.exists():
            return f"Log file not found: {path}"

        # Use tail command for efficiency
        result = subprocess.run(
            ['tail', '-n', str(lines), str(path)],
            capture_output=True,
            text=True,
            timeout=10
        )

        if not result.stdout:
            return f"Log file is empty: {path}"

        return f"Last {lines} lines of {path}:\n\n{result.stdout}"

    except Exception as e:
        return f"Error reading logs: {e}"


@tool
def todo_write(todos: List[Dict[str, str]]) -> str:
    """
    Create or update a visual task list for the user.

    Each todo must have:
    - content: Description of the task
    - status: "pending", "in_progress", or "completed"
    - activeForm: Present continuous form (e.g., "Installing packages")

    Args:
        todos: List of todo items

    Returns:
        Formatted todo list

    Examples:
        todo_write([
            {"content": "Install dependencies", "status": "completed", "activeForm": "Installing dependencies"},
            {"content": "Start server", "status": "in_progress", "activeForm": "Starting server"},
            {"content": "Run tests", "status": "pending", "activeForm": "Running tests"}
        ])

    Notes:
        - Only ONE task should be "in_progress" at a time
        - Mark tasks completed immediately after finishing
        - Use clear, actionable descriptions
    """
    try:
        # Validate todos
        valid_statuses = {"pending", "in_progress", "completed"}
        for todo in todos:
            if not all(k in todo for k in ["content", "status", "activeForm"]):
                return "Error: Each todo must have 'content', 'status', and 'activeForm'"
            if todo["status"] not in valid_statuses:
                return f"Error: Invalid status '{todo['status']}'. Must be: {valid_statuses}"

        # Format output
        output = ["📋 Task List:", ""]

        status_icons = {
            "pending": "⏳",
            "in_progress": "🔄",
            "completed": "✅"
        }

        for i, todo in enumerate(todos, 1):
            icon = status_icons[todo["status"]]
            status_text = todo["activeForm"] if todo["status"] == "in_progress" else todo["content"]
            output.append(f"{i}. {icon} {status_text}")

        # Add summary
        counts = {status: sum(1 for t in todos if t["status"] == status) for status in valid_statuses}
        output.append("")
        output.append(f"Progress: {counts['completed']}/{len(todos)} completed, "
                     f"{counts['in_progress']} in progress, {counts['pending']} pending")

        return '\n'.join(output)

    except Exception as e:
        return f"Error creating todo list: {e}"


@tool
def system_info() -> str:
    """
    Get system resource usage (CPU, memory, disk).

    Returns:
        System information

    Examples:
        system_info()
    """
    try:
        info = []

        # CPU info
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpu_count = sum(1 for line in f if line.startswith('processor'))
            info.append(f"CPU Cores: {cpu_count}")
        except:
            pass

        # Memory info
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                mem_total = int(lines[0].split()[1]) // 1024  # MB
                mem_avail = int(lines[2].split()[1]) // 1024  # MB
                mem_used = mem_total - mem_avail
                mem_percent = (mem_used / mem_total) * 100
                info.append(f"Memory: {mem_used}/{mem_total} MB ({mem_percent:.1f}%)")
        except:
            pass

        # Disk info
        try:
            result = subprocess.run(
                ['df', '-h', str(PROJECT_ROOT)],
                capture_output=True,
                text=True,
                timeout=5
            )
            disk_lines = result.stdout.strip().split('\n')
            if len(disk_lines) > 1:
                disk_info = disk_lines[1].split()
                info.append(f"Disk: {disk_info[2]}/{disk_info[1]} used ({disk_info[4]})")
        except:
            pass

        # Uptime
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_sec = float(f.read().split()[0])
                uptime_hours = int(uptime_sec // 3600)
                info.append(f"Uptime: {uptime_hours} hours")
        except:
            pass

        if not info:
            return "System info unavailable"

        return '\n'.join(info)

    except Exception as e:
        return f"Error getting system info: {e}"


# Export tools
TOOLS = [
    bash,
    bash_background,
    process_list,
    process_kill,
    read_logs,
    todo_write,
    system_info
]

TOOL_DESCRIPTIONS = {
    'bash': 'Execute any shell command (maximum power)',
    'bash_background': 'Run long processes in background',
    'process_list': 'List running processes',
    'process_kill': 'Kill processes by PID or name',
    'read_logs': 'Read log files (like tail)',
    'todo_write': 'Create visual task lists for user',
    'system_info': 'Get CPU, memory, disk usage',
}
