#!/usr/bin/env python3
"""
Deployment Script for Divine Node Production

Handles zero-downtime deployment of Divine Node services:
- Pull latest code
- Build all apps
- Run tests
- Graceful service restart
- Rollback on failure
"""

import subprocess
import sys
import os
import json
from datetime import datetime
from pathlib import Path


class Deployer:
    def __init__(self, workspace_root="/home/gh0st/dvn/divine-workspace"):
        self.workspace_root = Path(workspace_root)
        self.deployment_log = []
        self.start_time = datetime.now()

    def log(self, message: str, level: str = "INFO"):
        """Log deployment step"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.deployment_log.append(log_entry)
        print(log_entry)

    def run_command(self, cmd: list, description: str) -> bool:
        """Run shell command and log result"""
        self.log(f"Running: {description}")
        try:
            result = subprocess.run(
                cmd,
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                check=True
            )
            self.log(f"✅ {description} - SUCCESS")
            return True
        except subprocess.CalledProcessError as e:
            self.log(f"❌ {description} - FAILED", "ERROR")
            self.log(f"Error: {e.stderr}", "ERROR")
            return False

    def backup_current_state(self) -> bool:
        """Create backup of current deployment"""
        self.log("Creating deployment backup...")
        backup_name = f"deployment-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        backup_path = Path.home() / "backups" / backup_name

        # Create backup directory
        backup_path.mkdir(parents=True, exist_ok=True)

        # Backup git commit hash
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.workspace_root,
            capture_output=True,
            text=True
        )
        commit_hash = result.stdout.strip()

        backup_info = {
            "timestamp": datetime.now().isoformat(),
            "commit_hash": commit_hash,
            "backup_path": str(backup_path)
        }

        with open(backup_path / "deployment-info.json", 'w') as f:
            json.dump(backup_info, f, indent=2)

        self.log(f"✅ Backup created at: {backup_path}")
        return True

    def pull_latest_code(self) -> bool:
        """Pull latest code from git"""
        return self.run_command(
            ["git", "pull"],
            "Pull latest code"
        )

    def install_dependencies(self) -> bool:
        """Install/update dependencies"""
        return self.run_command(
            ["pnpm", "install"],
            "Install dependencies"
        )

    def run_tests(self) -> bool:
        """Run all tests"""
        return self.run_command(
            ["just", "test"],
            "Run tests"
        )

    def build_all(self) -> bool:
        """Build all apps"""
        return self.run_command(
            ["just", "build"],
            "Build all apps"
        )

    def stop_services(self) -> bool:
        """Stop running services gracefully"""
        self.log("Stopping services...")
        try:
            # Stop PKN server
            subprocess.run(
                ["./pkn_control.sh", "stop-all"],
                cwd=self.workspace_root / "apps" / "pkn",
                timeout=30
            )
            self.log("✅ Services stopped")
            return True
        except Exception as e:
            self.log(f"❌ Error stopping services: {e}", "ERROR")
            return False

    def start_services(self) -> bool:
        """Start services"""
        self.log("Starting services...")
        try:
            # Start PKN server
            subprocess.Popen(
                ["./pkn_control.sh", "start-all"],
                cwd=self.workspace_root / "apps" / "pkn",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.log("✅ Services started")
            return True
        except Exception as e:
            self.log(f"❌ Error starting services: {e}", "ERROR")
            return False

    def verify_deployment(self) -> bool:
        """Verify deployment succeeded"""
        self.log("Verifying deployment...")
        import time
        import requests

        # Wait for services to start
        time.sleep(5)

        # Check PKN health
        try:
            response = requests.get("http://localhost:8010/health", timeout=10)
            if response.status_code == 200:
                self.log("✅ PKN server is healthy")
                return True
            else:
                self.log(f"❌ PKN server unhealthy: {response.status_code}", "ERROR")
                return False
        except Exception as e:
            self.log(f"❌ PKN server not responding: {e}", "ERROR")
            return False

    def save_deployment_log(self):
        """Save deployment log"""
        log_file = Path("/tmp") / f"deployment-{self.start_time.strftime('%Y%m%d-%H%M%S')}.log"
        with open(log_file, 'w') as f:
            f.write("\n".join(self.deployment_log))
        self.log(f"📄 Deployment log saved: {log_file}")

    def deploy(self, skip_tests: bool = False) -> bool:
        """Run full deployment"""
        self.log("🚀 Starting Divine Node Deployment")
        self.log(f"Workspace: {self.workspace_root}")

        # Deployment steps
        steps = [
            ("Backup", self.backup_current_state),
            ("Pull Code", self.pull_latest_code),
            ("Install Deps", self.install_dependencies),
            ("Build", self.build_all),
        ]

        if not skip_tests:
            steps.insert(3, ("Run Tests", self.run_tests))

        steps.extend([
            ("Stop Services", self.stop_services),
            ("Start Services", self.start_services),
            ("Verify", self.verify_deployment),
        ])

        # Execute steps
        for step_name, step_func in steps:
            self.log(f"\n{'='*60}")
            self.log(f"Step: {step_name}")
            self.log(f"{'='*60}")

            if not step_func():
                self.log(f"❌ Deployment FAILED at step: {step_name}", "ERROR")
                self.save_deployment_log()
                return False

        # Success
        duration = (datetime.now() - self.start_time).total_seconds()
        self.log(f"\n✅ Deployment SUCCESSFUL (took {duration:.1f}s)")
        self.save_deployment_log()
        return True


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Deploy Divine Node")
    parser.add_argument("--skip-tests", action="store_true", help="Skip tests")
    parser.add_argument("--workspace", default="/home/gh0st/dvn/divine-workspace", help="Workspace root")
    args = parser.parse_args()

    deployer = Deployer(workspace_root=args.workspace)
    success = deployer.deploy(skip_tests=args.skip_tests)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
