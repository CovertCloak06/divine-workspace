#!/usr/bin/env python3
"""
Uptime Monitor - Check if websites/services are up and alert on failures
Usage: uptime.py <url> [--interval 60] [--alert]
"""

import urllib.request
import urllib.error
import ssl
import time
import argparse
import json
import os
from datetime import datetime
import subprocess

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def check_url(url, timeout=10):
    """Check if URL is accessible, return (status, response_time, status_code)"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    start = time.time()

    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'UptimeMonitor/1.0'
        })
        response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        elapsed = (time.time() - start) * 1000

        return True, elapsed, response.getcode()

    except urllib.error.HTTPError as e:
        elapsed = (time.time() - start) * 1000
        # Consider 4xx/5xx as "up but erroring"
        return False, elapsed, e.code

    except urllib.error.URLError as e:
        elapsed = (time.time() - start) * 1000
        return False, elapsed, 0

    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return False, elapsed, 0


def check_tcp(host, port, timeout=5):
    """Check TCP port connectivity"""
    import socket
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000
        sock.close()
        return result == 0, elapsed
    except:
        return False, 0


def send_notification(title, message):
    """Send desktop notification"""
    try:
        subprocess.run(['notify-send', '-u', 'critical', title, message], timeout=5)
    except:
        pass


def format_ms(ms):
    """Format milliseconds"""
    if ms < 1000:
        return f"{ms:.0f}ms"
    return f"{ms/1000:.1f}s"


def main():
    parser = argparse.ArgumentParser(description='Uptime Monitor')
    parser.add_argument('targets', nargs='*', help='URLs or host:port to monitor')
    parser.add_argument('--interval', '-i', type=int, default=60, help='Check interval in seconds')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Request timeout')
    parser.add_argument('--alert', '-a', action='store_true', help='Send desktop notifications')
    parser.add_argument('--once', '-1', action='store_true', help='Check once and exit')
    parser.add_argument('--config', '-c', help='Config file with targets')
    args = parser.parse_args()

    # Load targets from config or args
    targets = args.targets

    if args.config and os.path.exists(args.config):
        with open(args.config) as f:
            config = json.load(f)
            targets = config.get('targets', [])

    if not targets:
        # Default example targets
        targets = ['https://google.com', 'https://github.com']
        print(f"\n{YELLOW}No targets specified, using examples{RESET}")
        print(f"{DIM}Usage: uptime.py https://example.com https://mysite.com{RESET}")
        print(f"{DIM}       uptime.py 192.168.1.1:22 (for TCP check){RESET}\n")

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔔 Uptime Monitor                             ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Targets: {len(targets)}{RESET}")
    print(f"  {DIM}Interval: {args.interval}s{RESET}")
    print(f"  {DIM}Alerts: {'enabled' if args.alert else 'disabled'}{RESET}")
    print()

    # Track status history
    history = {t: {'up': 0, 'down': 0, 'last_status': None, 'total_response': 0} for t in targets}

    try:
        check_num = 0
        while True:
            check_num += 1
            now = datetime.now().strftime('%H:%M:%S')

            print(f"  {DIM}[{now}] Check #{check_num}{RESET}")
            print(f"  {DIM}{'─' * 60}{RESET}")

            for target in targets:
                # Determine if TCP or HTTP check
                if re.match(r'^[\w.-]+:\d+$', target):
                    # TCP check
                    host, port = target.rsplit(':', 1)
                    is_up, response_time = check_tcp(host, int(port), args.timeout)
                    status_code = 'TCP'
                else:
                    # HTTP check
                    if not target.startswith(('http://', 'https://')):
                        target = 'https://' + target
                    is_up, response_time, status_code = check_url(target, args.timeout)

                # Update history
                h = history.get(target, {'up': 0, 'down': 0, 'last_status': None, 'total_response': 0})
                was_up = h['last_status']

                if is_up:
                    h['up'] += 1
                    h['total_response'] += response_time
                    status = f"{GREEN}✓ UP{RESET}"
                    time_str = f"{format_ms(response_time)}"
                else:
                    h['down'] += 1
                    status = f"{RED}✗ DOWN{RESET}"
                    time_str = f"timeout/error"

                h['last_status'] = is_up
                history[target] = h

                # Display
                short_target = target[:45] + '...' if len(target) > 48 else target
                code_str = f"({status_code})" if status_code else ""
                print(f"  {status} {short_target:<50} {time_str:>10} {DIM}{code_str}{RESET}")

                # Alert on status change
                if args.alert and was_up is not None and was_up != is_up:
                    if is_up:
                        send_notification('Service Recovered', f'{target} is back online')
                    else:
                        send_notification('Service Down!', f'{target} is not responding')

            print()

            # Show summary every 10 checks
            if check_num % 10 == 0:
                print(f"  {BOLD}Summary (last {check_num} checks):{RESET}")
                for target, h in history.items():
                    total = h['up'] + h['down']
                    uptime = (h['up'] / total * 100) if total > 0 else 0
                    avg_response = (h['total_response'] / h['up']) if h['up'] > 0 else 0
                    color = GREEN if uptime >= 99 else YELLOW if uptime >= 95 else RED
                    print(f"  {color}{uptime:5.1f}%{RESET} {target[:50]} {DIM}avg: {format_ms(avg_response)}{RESET}")
                print()

            if args.once:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n{CYAN}Monitor stopped.{RESET}")

        # Final summary
        print(f"\n{BOLD}Final Summary:{RESET}")
        for target, h in history.items():
            total = h['up'] + h['down']
            uptime = (h['up'] / total * 100) if total > 0 else 0
            avg_response = (h['total_response'] / h['up']) if h['up'] > 0 else 0
            color = GREEN if uptime >= 99 else YELLOW if uptime >= 95 else RED
            print(f"  {color}{uptime:5.1f}%{RESET} uptime | {target}")
            print(f"          {DIM}Up: {h['up']}, Down: {h['down']}, Avg: {format_ms(avg_response)}{RESET}")

        print()


import re

if __name__ == '__main__':
    main()
