#!/usr/bin/env python3
"""
Backup Script for Divine Node Production

Creates comprehensive backups of:
- Database files
- Configuration files
- User data
- Logs
- Git state
"""

import subprocess
import shutil
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict


class BackupManager:
    def __init__(self, workspace_root="/home/gh0st/dvn/divine-workspace"):
        self.workspace_root = Path(workspace_root)
        self.backup_root = Path.home() / "backups"
        self.backup_root.mkdir(parents=True, exist_ok=True)

        self.timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.backup_name = f"divine-backup-{self.timestamp}"
        self.backup_path = self.backup_root / self.backup_name

    def create_backup_dir(self):
        """Create backup directory structure"""
        self.backup_path.mkdir(parents=True, exist_ok=True)
        print(f"📁 Created backup directory: {self.backup_path}")

    def backup_git_state(self) -> Dict:
        """Backup git state"""
        print("📦 Backing up git state...")

        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.workspace_root,
            capture_output=True,
            text=True
        )
        commit_hash = result.stdout.strip()

        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=self.workspace_root,
            capture_output=True,
            text=True
        )
        branch = result.stdout.strip()

        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=self.workspace_root,
            capture_output=True,
            text=True
        )
        has_changes = bool(result.stdout.strip())

        git_state = {
            "commit_hash": commit_hash,
            "branch": branch,
            "has_uncommitted_changes": has_changes,
            "timestamp": datetime.now().isoformat()
        }

        with open(self.backup_path / "git-state.json", 'w') as f:
            json.dump(git_state, f, indent=2)

        print(f"  ✅ Commit: {commit_hash[:8]}")
        print(f"  ✅ Branch: {branch}")

        return git_state

    def backup_pkn_data(self):
        """Backup PKN data and configs"""
        print("📦 Backing up PKN data...")

        pkn_path = self.workspace_root / "apps" / "pkn"
        pkn_backup = self.backup_path / "pkn"
        pkn_backup.mkdir(parents=True, exist_ok=True)

        # Backup memory files
        memory_path = pkn_path / "memory"
        if memory_path.exists():
            shutil.copytree(memory_path, pkn_backup / "memory", dirs_exist_ok=True)
            print("  ✅ Memory files backed up")

        # Backup .env
        env_file = pkn_path / ".env"
        if env_file.exists():
            shutil.copy2(env_file, pkn_backup / ".env")
            print("  ✅ .env file backed up")

        # Backup logs
        log_file = pkn_path / "divinenode.log"
        if log_file.exists():
            shutil.copy2(log_file, pkn_backup / "divinenode.log")
            print("  ✅ Logs backed up")

    def backup_code_academy_data(self):
        """Backup Code Academy data"""
        print("📦 Backing up Code Academy data...")

        ca_path = self.workspace_root / "apps" / "code-academy"
        ca_backup = self.backup_path / "code-academy"
        ca_backup.mkdir(parents=True, exist_ok=True)

        # Backup user progress (if exists)
        progress_path = ca_path / "data"
        if progress_path.exists():
            shutil.copytree(progress_path, ca_backup / "data", dirs_exist_ok=True)
            print("  ✅ User data backed up")

    def create_tarball(self) -> Path:
        """Create compressed tarball of backup"""
        print("📦 Creating compressed archive...")

        tarball_path = self.backup_root / f"{self.backup_name}.tar.gz"

        subprocess.run(
            ["tar", "-czf", str(tarball_path), "-C", str(self.backup_path.parent), self.backup_name],
            check=True
        )

        # Remove uncompressed backup
        shutil.rmtree(self.backup_path)

        size_mb = tarball_path.stat().st_size / (1024 * 1024)
        print(f"  ✅ Archive created: {tarball_path.name} ({size_mb:.1f} MB)")

        return tarball_path

    def cleanup_old_backups(self, keep_count: int = 5):
        """Remove old backups, keeping only recent ones"""
        print(f"🧹 Cleaning up old backups (keeping {keep_count} most recent)...")

        backups = sorted(
            self.backup_root.glob("divine-backup-*.tar.gz"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )

        removed_count = 0
        for old_backup in backups[keep_count:]:
            old_backup.unlink()
            removed_count += 1
            print(f"  🗑️  Removed: {old_backup.name}")

        if removed_count == 0:
            print("  ✅ No old backups to remove")
        else:
            print(f"  ✅ Removed {removed_count} old backup(s)")

    def run_backup(self, keep_count: int = 5) -> Path:
        """Run complete backup"""
        print("🔄 Starting Divine Node Backup")
        print(f"Workspace: {self.workspace_root}")
        print(f"Backup: {self.backup_name}\n")

        self.create_backup_dir()
        self.backup_git_state()
        self.backup_pkn_data()
        self.backup_code_academy_data()
        tarball = self.create_tarball()
        self.cleanup_old_backups(keep_count)

        print(f"\n✅ Backup completed successfully!")
        print(f"📦 Backup location: {tarball}")

        return tarball


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Backup Divine Node")
    parser.add_argument("--workspace", default="/home/gh0st/dvn/divine-workspace", help="Workspace root")
    parser.add_argument("--keep", type=int, default=5, help="Number of backups to keep")
    args = parser.parse_args()

    manager = BackupManager(workspace_root=args.workspace)
    manager.run_backup(keep_count=args.keep)


if __name__ == "__main__":
    main()
