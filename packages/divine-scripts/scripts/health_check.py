#!/usr/bin/env python3
"""
Health Check Script for Divine Node Production

Checks health of all services in the monorepo:
- PKN server (port 8010)
- llama.cpp (port 8000)
- Ollama (port 11434)
- Code Academy (port 3000)
"""

import requests
import subprocess
import sys
import json
from datetime import datetime
from typing import Dict, List, Tuple


class HealthChecker:
    def __init__(self):
        self.results = {}
        self.failed_checks = []

    def check_http_endpoint(self, name: str, url: str, timeout: int = 5) -> bool:
        """Check if HTTP endpoint is responding"""
        try:
            response = requests.get(url, timeout=timeout)
            healthy = response.status_code == 200
            self.results[name] = {
                "status": "healthy" if healthy else "unhealthy",
                "code": response.status_code,
                "url": url
            }
            if not healthy:
                self.failed_checks.append(name)
            return healthy
        except requests.exceptions.RequestException as e:
            self.results[name] = {
                "status": "down",
                "error": str(e),
                "url": url
            }
            self.failed_checks.append(name)
            return False

    def check_process(self, name: str, process_name: str) -> bool:
        """Check if process is running"""
        try:
            result = subprocess.run(
                ["pgrep", "-f", process_name],
                capture_output=True,
                text=True
            )
            running = result.returncode == 0
            self.results[name] = {
                "status": "running" if running else "stopped",
                "process": process_name
            }
            if not running:
                self.failed_checks.append(name)
            return running
        except Exception as e:
            self.results[name] = {
                "status": "error",
                "error": str(e)
            }
            self.failed_checks.append(name)
            return False

    def check_port(self, name: str, port: int) -> bool:
        """Check if port is listening"""
        try:
            result = subprocess.run(
                ["lsof", "-i", f":{port}", "-t"],
                capture_output=True,
                text=True
            )
            listening = result.returncode == 0 and result.stdout.strip()
            self.results[name] = {
                "status": "listening" if listening else "not_listening",
                "port": port
            }
            if not listening:
                self.failed_checks.append(name)
            return listening
        except Exception as e:
            self.results[name] = {
                "status": "error",
                "error": str(e)
            }
            self.failed_checks.append(name)
            return False

    def run_all_checks(self) -> Dict:
        """Run all health checks"""
        print("🏥 Running Divine Node Health Checks...\n")

        # Check PKN Server
        print("Checking PKN Server...")
        self.check_http_endpoint("PKN Server", "http://localhost:8010/health")
        self.check_port("PKN Port 8010", 8010)

        # Check llama.cpp
        print("Checking llama.cpp...")
        self.check_port("llama.cpp Port 8000", 8000)
        self.check_http_endpoint("llama.cpp Health", "http://localhost:8000/health")

        # Check Ollama
        print("Checking Ollama...")
        self.check_port("Ollama Port 11434", 11434)

        # Check Code Academy
        print("Checking Code Academy...")
        self.check_port("Code Academy Port 3000", 3000)

        # Check critical processes
        print("Checking processes...")
        self.check_process("PKN Process", "divinenode_server.py")

        return {
            "timestamp": datetime.now().isoformat(),
            "results": self.results,
            "failed_checks": self.failed_checks,
            "overall_status": "healthy" if not self.failed_checks else "degraded"
        }

    def print_report(self, results: Dict):
        """Print formatted health report"""
        print("\n" + "="*60)
        print("🏥 DIVINE NODE HEALTH REPORT")
        print("="*60)
        print(f"Timestamp: {results['timestamp']}")
        print(f"Overall Status: {results['overall_status'].upper()}")
        print()

        for name, data in results['results'].items():
            status = data['status']
            emoji = "✅" if status in ["healthy", "running", "listening"] else "❌"
            print(f"{emoji} {name}: {status}")
            if 'url' in data:
                print(f"   URL: {data['url']}")
            if 'port' in data:
                print(f"   Port: {data['port']}")
            if 'error' in data:
                print(f"   Error: {data['error']}")
            print()

        if results['failed_checks']:
            print("⚠️  Failed Checks:")
            for check in results['failed_checks']:
                print(f"   - {check}")
            print()

        print("="*60)

    def save_report(self, results: Dict, filepath: str = "/tmp/divine-health.json"):
        """Save health report to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"📄 Report saved to: {filepath}")


def main():
    checker = HealthChecker()
    results = checker.run_all_checks()
    checker.print_report(results)
    checker.save_report(results)

    # Exit with error code if any checks failed
    sys.exit(1 if results['failed_checks'] else 0)


if __name__ == "__main__":
    main()
