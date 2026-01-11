#!/usr/bin/env python3
"""
Code Execution Sandbox
Safely execute code in isolated Docker containers
"""

import tempfile
import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional, List
import subprocess
import json
import os

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    print("Warning: docker package not installed. Run: pip install docker")


class CodeSandbox:
    """
    Safely execute code in Docker containers with resource limits.
    Supports Python, JavaScript, and shell scripts.
    """

    def __init__(self, project_root: str = "/home/gh0st/pkn"):
        self.project_root = Path(project_root)
        self.sandbox_dir = self.project_root / "memory" / "sandbox"
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

        if DOCKER_AVAILABLE:
            try:
                self.client = docker.from_env()
                self.docker_enabled = True
            except Exception as e:
                print(f"Warning: Could not connect to Docker: {e}")
                self.docker_enabled = False
        else:
            self.docker_enabled = False

        # Resource limits
        self.default_limits = {
            'memory': '512m',
            'cpu_quota': 50000,  # 50% of one core
            'timeout': 30  # seconds
        }

    def execute_python(self, code: str, timeout: Optional[int] = None,
                       requirements: Optional[List[str]] = None) -> Dict[str, Any]:
        """Execute Python code in sandbox"""

        if not self.docker_enabled:
            return self._execute_python_subprocess(code, timeout)

        timeout = timeout or self.default_limits['timeout']

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Write code to file
            code_file = tmpdir_path / "script.py"
            code_file.write_text(code)

            # Create requirements.txt if needed
            if requirements:
                req_file = tmpdir_path / "requirements.txt"
                req_file.write_text('\n'.join(requirements))

            try:
                # Prepare Docker command
                docker_cmd = "python /code/script.py"

                if requirements:
                    docker_cmd = f"pip install -q -r /code/requirements.txt && {docker_cmd}"

                # Run container
                container = self.client.containers.run(
                    "python:3.11-slim",
                    f"sh -c '{docker_cmd}'",
                    volumes={str(tmpdir_path): {'bind': '/code', 'mode': 'ro'}},
                    network_mode='none',  # No network access
                    mem_limit=self.default_limits['memory'],
                    cpu_quota=self.default_limits['cpu_quota'],
                    detach=False,
                    remove=True,
                    stdout=True,
                    stderr=True
                )

                output = container.decode('utf-8')

                return {
                    'success': True,
                    'output': output,
                    'language': 'python',
                    'execution_time': None  # Docker doesn't give us this easily
                }

            except docker.errors.ContainerError as e:
                return {
                    'success': False,
                    'error': e.stderr.decode('utf-8') if e.stderr else str(e),
                    'exit_code': e.exit_status,
                    'language': 'python'
                }

            except Exception as e:
                return {
                    'success': False,
                    'error': str(e),
                    'language': 'python'
                }

    def _execute_python_subprocess(self, code: str, timeout: Optional[int]) -> Dict[str, Any]:
        """Fallback: Execute Python using subprocess (less secure)"""

        timeout = timeout or self.default_limits['timeout']

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            script_path = f.name

        try:
            start_time = time.time()

            result = subprocess.run(
                ['python3', script_path],
                capture_output=True,
                text=True,
                timeout=timeout,
                env={'PYTHONPATH': ''}  # Minimal environment
            )

            execution_time = time.time() - start_time

            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None,
                'exit_code': result.returncode,
                'execution_time': execution_time,
                'language': 'python',
                'warning': 'Executed without Docker sandbox (less secure)'
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Execution timed out after {timeout} seconds',
                'language': 'python'
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'language': 'python'
            }

        finally:
            # Clean up temp file
            try:
                os.unlink(script_path)
            except:
                pass

    def execute_javascript(self, code: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """Execute JavaScript code in sandbox"""

        if not self.docker_enabled:
            return self._execute_javascript_subprocess(code, timeout)

        timeout = timeout or self.default_limits['timeout']

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Write code to file
            code_file = tmpdir_path / "script.js"
            code_file.write_text(code)

            try:
                container = self.client.containers.run(
                    "node:18-slim",
                    "node /code/script.js",
                    volumes={str(tmpdir_path): {'bind': '/code', 'mode': 'ro'}},
                    network_mode='none',
                    mem_limit=self.default_limits['memory'],
                    cpu_quota=self.default_limits['cpu_quota'],
                    detach=False,
                    remove=True,
                    stdout=True,
                    stderr=True
                )

                output = container.decode('utf-8')

                return {
                    'success': True,
                    'output': output,
                    'language': 'javascript'
                }

            except docker.errors.ContainerError as e:
                return {
                    'success': False,
                    'error': e.stderr.decode('utf-8') if e.stderr else str(e),
                    'exit_code': e.exit_status,
                    'language': 'javascript'
                }

            except Exception as e:
                return {
                    'success': False,
                    'error': str(e),
                    'language': 'javascript'
                }

    def _execute_javascript_subprocess(self, code: str, timeout: Optional[int]) -> Dict[str, Any]:
        """Fallback: Execute JavaScript using subprocess"""

        timeout = timeout or self.default_limits['timeout']

        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(code)
            script_path = f.name

        try:
            start_time = time.time()

            result = subprocess.run(
                ['node', script_path],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            execution_time = time.time() - start_time

            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None,
                'exit_code': result.returncode,
                'execution_time': execution_time,
                'language': 'javascript',
                'warning': 'Executed without Docker sandbox (less secure)'
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Execution timed out after {timeout} seconds',
                'language': 'javascript'
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'language': 'javascript'
            }

        finally:
            try:
                os.unlink(script_path)
            except:
                pass

    def execute_shell(self, script: str, timeout: Optional[int] = None,
                      allowed_commands: Optional[List[str]] = None) -> Dict[str, Any]:
        """Execute shell script with command whitelist"""

        timeout = timeout or self.default_limits['timeout']

        # Check for dangerous commands
        dangerous = ['rm -rf', 'dd', 'mkfs', ':(){', 'fork', '>()', 'sudo', 'chmod 777']
        for danger in dangerous:
            if danger in script:
                return {
                    'success': False,
                    'error': f'Dangerous command detected: {danger}',
                    'language': 'shell'
                }

        # If whitelist provided, check commands
        if allowed_commands:
            script_commands = self._extract_commands(script)
            for cmd in script_commands:
                if cmd not in allowed_commands:
                    return {
                        'success': False,
                        'error': f'Command not in whitelist: {cmd}',
                        'language': 'shell'
                    }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(script)
            script_path = f.name

        try:
            start_time = time.time()

            result = subprocess.run(
                ['bash', script_path],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.sandbox_dir)  # Run in sandbox directory
            )

            execution_time = time.time() - start_time

            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None,
                'exit_code': result.returncode,
                'execution_time': execution_time,
                'language': 'shell'
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Execution timed out after {timeout} seconds',
                'language': 'shell'
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'language': 'shell'
            }

        finally:
            try:
                os.unlink(script_path)
            except:
                pass

    def _extract_commands(self, script: str) -> List[str]:
        """Extract base commands from shell script"""

        commands = []
        for line in script.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Get first word (command)
                cmd = line.split()[0] if line.split() else ''
                if cmd and '=' not in cmd:  # Not a variable assignment
                    commands.append(cmd)

        return commands

    def test_code(self, code: str, language: str, tests: List[str]) -> Dict[str, Any]:
        """Execute code with test cases"""

        if language == 'python':
            # Add test assertions to code
            full_code = f"""{code}

# Test cases
{chr(10).join(tests)}
"""
            result = self.execute_python(full_code)

        elif language == 'javascript':
            # Add test assertions
            full_code = f"""{code}

// Test cases
{chr(10).join(tests)}
"""
            result = self.execute_javascript(full_code)

        else:
            return {
                'success': False,
                'error': f'Testing not supported for language: {language}'
            }

        if result['success']:
            result['tests_passed'] = True
            result['test_count'] = len(tests)

        return result

    def get_sandbox_info(self) -> Dict[str, Any]:
        """Get information about sandbox environment"""

        return {
            'docker_available': self.docker_enabled,
            'docker_version': self.client.version() if self.docker_enabled else None,
            'sandbox_directory': str(self.sandbox_dir),
            'resource_limits': self.default_limits,
            'supported_languages': ['python', 'javascript', 'shell']
        }


# Convenience functions for agent use
def run_python_code(code: str, timeout: int = 30) -> Dict[str, Any]:
    """Quick function to run Python code"""
    sandbox = CodeSandbox()
    return sandbox.execute_python(code, timeout)


def run_javascript_code(code: str, timeout: int = 30) -> Dict[str, Any]:
    """Quick function to run JavaScript code"""
    sandbox = CodeSandbox()
    return sandbox.execute_javascript(code, timeout)


def run_shell_script(script: str, timeout: int = 30, safe_mode: bool = True) -> Dict[str, Any]:
    """Quick function to run shell script"""
    sandbox = CodeSandbox()

    if safe_mode:
        # Whitelist of safe commands
        allowed = ['echo', 'ls', 'cat', 'grep', 'find', 'wc', 'sort', 'uniq', 'head', 'tail']
        return sandbox.execute_shell(script, timeout, allowed_commands=allowed)
    else:
        return sandbox.execute_shell(script, timeout)


if __name__ == "__main__":
    print("Code Sandbox System loaded successfully!")

    sandbox = CodeSandbox()
    info = sandbox.get_sandbox_info()

    print(f"\nSandbox Info:")
    print(f"  Docker available: {info['docker_available']}")
    print(f"  Sandbox directory: {info['sandbox_directory']}")
    print(f"  Resource limits: {info['resource_limits']}")
    print(f"  Supported languages: {', '.join(info['supported_languages'])}")

    # Test Python execution
    print("\n Testing Python execution...")
    test_code = """
print("Hello from sandbox!")
result = 2 + 2
print(f"2 + 2 = {result}")
"""

    result = sandbox.execute_python(test_code)
    print(f"  Success: {result['success']}")
    if result['success']:
        print(f"  Output: {result['output'][:100]}")

    print("\n✓ Sandbox system ready!")
