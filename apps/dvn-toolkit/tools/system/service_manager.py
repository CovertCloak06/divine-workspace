#!/usr/bin/env python3
"""
Service Manager - View and manage systemd services
Usage: service_manager.py [list|status|start|stop|restart]
"""

import subprocess
import argparse

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def run_systemctl(args, sudo=False):
    """Run systemctl command"""
    cmd = ['sudo', 'systemctl'] if sudo else ['systemctl']
    cmd.extend(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def list_services(filter_type='all'):
    """List systemd services"""
    args = ['list-units', '--type=service', '--no-pager', '--plain']

    if filter_type == 'running':
        args.append('--state=running')
    elif filter_type == 'failed':
        args.append('--state=failed')

    success, stdout, _ = run_systemctl(args)

    if not success:
        return []

    services = []
    for line in stdout.split('\n'):
        parts = line.split()
        if len(parts) >= 4 and '.service' in parts[0]:
            services.append({
                'name': parts[0].replace('.service', ''),
                'load': parts[1],
                'active': parts[2],
                'sub': parts[3],
                'description': ' '.join(parts[4:]) if len(parts) > 4 else ''
            })

    return services


def get_service_status(name):
    """Get detailed service status"""
    success, stdout, stderr = run_systemctl(['status', name, '--no-pager'])

    info = {
        'name': name,
        'active': False,
        'enabled': False,
        'running': False,
        'pid': None,
        'memory': None,
        'uptime': None,
        'description': '',
        'raw': stdout if success else stderr
    }

    for line in stdout.split('\n'):
        line = line.strip()
        if line.startswith('Active:'):
            info['active'] = 'active' in line.lower()
            info['running'] = 'running' in line.lower()
            if 'since' in line:
                try:
                    info['uptime'] = line.split('since')[1].split(';')[1].strip()
                except:
                    pass
        elif line.startswith('Main PID:'):
            try:
                info['pid'] = line.split(':')[1].split()[0].strip()
            except:
                pass
        elif line.startswith('Memory:'):
            try:
                info['memory'] = line.split(':')[1].strip()
            except:
                pass
        elif '- ' in line and not info['description']:
            info['description'] = line.split('- ', 1)[1] if '- ' in line else ''

    # Check if enabled
    success, stdout, _ = run_systemctl(['is-enabled', name])
    info['enabled'] = 'enabled' in stdout.lower()

    return info


def control_service(name, action):
    """Start, stop, restart, or enable/disable service"""
    success, stdout, stderr = run_systemctl([action, name], sudo=True)
    return success, stderr if not success else stdout


def main():
    parser = argparse.ArgumentParser(description='Service Manager')
    parser.add_argument('action', nargs='?', default='list',
                       choices=['list', 'status', 'start', 'stop', 'restart',
                               'enable', 'disable', 'logs'])
    parser.add_argument('service', nargs='?', help='Service name')
    parser.add_argument('--running', '-r', action='store_true', help='Show only running')
    parser.add_argument('--failed', '-f', action='store_true', help='Show only failed')
    parser.add_argument('--lines', '-n', type=int, default=20, help='Log lines to show')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              ⚙️  Service Manager                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.action == 'list':
        filter_type = 'running' if args.running else ('failed' if args.failed else 'all')
        services = list_services(filter_type)

        if not services:
            print(f"  {DIM}No services found{RESET}\n")
            return

        print(f"  {BOLD}Services ({len(services)}):{RESET}")
        print(f"  {DIM}{'─' * 60}{RESET}\n")

        for svc in services[:50]:
            if svc['active'] == 'active':
                status_color = GREEN
                status_icon = '●'
            elif svc['active'] == 'failed':
                status_color = RED
                status_icon = '✗'
            else:
                status_color = YELLOW
                status_icon = '○'

            print(f"  {status_color}{status_icon}{RESET} {GREEN}{svc['name']:<30}{RESET} {DIM}{svc['description'][:30]}{RESET}")

        if len(services) > 50:
            print(f"\n  {DIM}... and {len(services) - 50} more{RESET}")

        print(f"\n  {DIM}Legend: {GREEN}● active{RESET}  {YELLOW}○ inactive{RESET}  {RED}✗ failed{RESET}\n")

    elif args.action == 'status':
        if not args.service:
            args.service = input(f"  {CYAN}Service name:{RESET} ").strip()

        if not args.service:
            print(f"  {RED}Service name required{RESET}\n")
            return

        info = get_service_status(args.service)

        print(f"  {BOLD}Service: {GREEN}{info['name']}{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        # Status
        if info['running']:
            print(f"  {CYAN}Status:{RESET}  {GREEN}● Running{RESET}")
        elif info['active']:
            print(f"  {CYAN}Status:{RESET}  {YELLOW}○ Active (not running){RESET}")
        else:
            print(f"  {CYAN}Status:{RESET}  {RED}○ Inactive{RESET}")

        # Enabled
        if info['enabled']:
            print(f"  {CYAN}Enabled:{RESET} {GREEN}Yes (starts on boot){RESET}")
        else:
            print(f"  {CYAN}Enabled:{RESET} {DIM}No{RESET}")

        # Details
        if info['pid']:
            print(f"  {CYAN}PID:{RESET}     {info['pid']}")
        if info['memory']:
            print(f"  {CYAN}Memory:{RESET}  {info['memory']}")
        if info['uptime']:
            print(f"  {CYAN}Uptime:{RESET}  {info['uptime']}")
        if info['description']:
            print(f"  {CYAN}Info:{RESET}    {info['description']}")

        print()

    elif args.action in ['start', 'stop', 'restart', 'enable', 'disable']:
        if not args.service:
            args.service = input(f"  {CYAN}Service name:{RESET} ").strip()

        if not args.service:
            print(f"  {RED}Service name required{RESET}\n")
            return

        print(f"  {YELLOW}{args.action.capitalize()}ing {args.service}...{RESET}")
        success, message = control_service(args.service, args.action)

        if success:
            print(f"  {GREEN}✓ {args.action.capitalize()}ed successfully{RESET}\n")
        else:
            print(f"  {RED}✗ Failed: {message}{RESET}\n")

    elif args.action == 'logs':
        if not args.service:
            args.service = input(f"  {CYAN}Service name:{RESET} ").strip()

        if not args.service:
            print(f"  {RED}Service name required{RESET}\n")
            return

        print(f"  {BOLD}Logs for {args.service}:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        try:
            result = subprocess.run(
                ['journalctl', '-u', args.service, '-n', str(args.lines), '--no-pager'],
                capture_output=True, text=True
            )
            print(result.stdout)
        except:
            print(f"  {RED}Could not retrieve logs{RESET}\n")

    # Quick actions
    print(f"  {BOLD}Quick Commands:{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {CYAN}status <name>{RESET}   Check service status")
    print(f"  {CYAN}start <name>{RESET}    Start service")
    print(f"  {CYAN}stop <name>{RESET}     Stop service")
    print(f"  {CYAN}restart <name>{RESET}  Restart service")
    print(f"  {CYAN}logs <name>{RESET}     View service logs")
    print()


if __name__ == '__main__':
    main()
