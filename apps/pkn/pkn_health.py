#!/usr/bin/env python3
"""
PKN Health Check & Auto-Recovery System
Monitors all PKN services and automatically restarts failed ones
"""

import requests
import time
import subprocess
import os
import sys
from pathlib import Path
from datetime import datetime

class PKNHealthMonitor:
    def __init__(self, project_root: str = "/home/gh0st/pkn"):
        self.project_root = Path(project_root)
        self.services = {
            'divinenode': {
                'port': 8010,
                'health': '/health',
                'start_cmd': 'start-divinenode',
                'critical': True
            },
            'llama': {
                'port': 8000,
                'health': '/v1/models',
                'start_cmd': 'start-llama',
                'critical': True
            },
            'parakleon': {
                'port': 9000,
                'health': '/health',
                'start_cmd': 'start-parakleon',
                'critical': False
            },
            'ollama': {
                'port': 11434,
                'health': '/api/tags',
                'start_cmd': 'start-ollama',
                'critical': False
            }
        }
        self.restart_counts = {k: 0 for k in self.services.keys()}
        self.max_restarts = 3
        self.check_interval = 60  # seconds
        self.log_file = self.project_root / "pkn_health.log"

    def log(self, message: str):
        """Log message to file and console"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_msg = f"[{timestamp}] {message}"

        print(log_msg)

        with open(self.log_file, 'a') as f:
            f.write(log_msg + '\n')

    def check_service(self, name: str, config: dict) -> bool:
        """Check if service is healthy"""
        try:
            url = f"http://localhost:{config['port']}{config['health']}"
            response = requests.get(url, timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False
        except Exception as e:
            self.log(f"⚠️  Unexpected error checking {name}: {e}")
            return False

    def restart_service(self, name: str, config: dict) -> bool:
        """Restart a failed service"""
        if self.restart_counts[name] >= self.max_restarts:
            self.log(f"❌ {name} exceeded max restarts ({self.max_restarts})")
            if config['critical']:
                self.log(f"🚨 CRITICAL SERVICE DOWN: {name}")
            return False

        self.log(f"🔄 Restarting {name}...")
        try:
            # Use pkn_control.sh to start service
            cmd = [str(self.project_root / "pkn_control.sh"), config['start_cmd']]
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                self.log(f"❌ Restart command failed: {result.stderr}")
                return False

            # Wait for service to start
            time.sleep(5)

            # Verify restart
            if self.check_service(name, config):
                self.log(f"✅ {name} restarted successfully")
                self.restart_counts[name] += 1
                return True
            else:
                self.log(f"❌ {name} restart failed - service not responding")
                self.restart_counts[name] += 1
                return False

        except subprocess.TimeoutExpired:
            self.log(f"❌ Restart timeout for {name}")
            return False
        except Exception as e:
            self.log(f"❌ Error restarting {name}: {e}")
            return False

    def check_all_services(self) -> dict:
        """Check all services and return status"""
        status = {}

        for name, config in self.services.items():
            healthy = self.check_service(name, config)
            status[name] = {
                'healthy': healthy,
                'port': config['port'],
                'critical': config['critical'],
                'restart_count': self.restart_counts[name]
            }

            if healthy:
                # Reset restart count on success
                self.restart_counts[name] = 0

        return status

    def monitor_loop(self, interval: int = None):
        """Continuous monitoring loop"""
        if interval:
            self.check_interval = interval

        self.log("🏥 PKN Health Monitor started")
        self.log(f"   Checking every {self.check_interval} seconds")
        self.log(f"   Max restarts per service: {self.max_restarts}")
        self.log("="*60)

        try:
            while True:
                self.log(f"🔍 Health check at {time.strftime('%H:%M:%S')}")

                all_healthy = True
                critical_down = False

                for name, config in self.services.items():
                    healthy = self.check_service(name, config)

                    if healthy:
                        self.log(f"   ✓ {name:12s} (:{config['port']})")
                        self.restart_counts[name] = 0  # Reset on success
                    else:
                        all_healthy = False
                        self.log(f"   ✗ {name:12s} (:{config['port']}) - DOWN")

                        if config['critical']:
                            critical_down = True

                        # Attempt restart
                        self.restart_service(name, config)

                if all_healthy:
                    self.log("   All services healthy ✅")
                elif critical_down:
                    self.log("   ⚠️  CRITICAL SERVICES DOWN")

                self.log("-"*60)
                time.sleep(self.check_interval)

        except KeyboardInterrupt:
            self.log("\n👋 Health monitor stopped by user")
            sys.exit(0)
        except Exception as e:
            self.log(f"\n❌ Monitor error: {e}")
            sys.exit(1)

    def check_once(self) -> bool:
        """Run a single health check and return True if all healthy"""
        self.log("🔍 Running health check...")

        status = self.check_all_services()
        all_healthy = all(s['healthy'] for s in status.values())

        for name, info in status.items():
            symbol = "✓" if info['healthy'] else "✗"
            critical = " [CRITICAL]" if info['critical'] and not info['healthy'] else ""
            self.log(f"   {symbol} {name:12s} (:{info['port']}){critical}")

        if all_healthy:
            self.log("✅ All services healthy")
        else:
            self.log("⚠️  Some services are down")

        return all_healthy


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='PKN Health Monitor')
    parser.add_argument(
        '--once',
        action='store_true',
        help='Run single check and exit'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=60,
        help='Check interval in seconds (default: 60)'
    )
    parser.add_argument(
        '--project-root',
        type=str,
        default='/home/gh0st/pkn',
        help='PKN project root directory'
    )

    args = parser.parse_args()

    monitor = PKNHealthMonitor(args.project_root)

    if args.once:
        # Single check mode
        all_healthy = monitor.check_once()
        sys.exit(0 if all_healthy else 1)
    else:
        # Continuous monitoring mode
        monitor.monitor_loop(interval=args.interval)


if __name__ == "__main__":
    main()
