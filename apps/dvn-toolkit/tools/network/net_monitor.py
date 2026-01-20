#!/usr/bin/env python3
"""
Network Monitor - Real-time network connection monitoring
Usage: net_monitor.py [--watch] [--port PORT] [--json]
Monitors active connections, listening ports, and network activity
"""

import sys
import json
import argparse
import subprocess
import re
import time
import os

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def get_connections():
    """Get all network connections using ss or netstat"""
    connections = []

    try:
        # Try ss first (faster, more features)
        result = subprocess.run(
            ['ss', '-tunaop'],
            capture_output=True, text=True, timeout=10
        )

        for line in result.stdout.split('\n')[1:]:
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            conn = {
                'proto': parts[0],
                'state': parts[1] if parts[0] != 'udp' else 'UNCONN',
                'local': parts[4] if len(parts) > 4 else '',
                'remote': parts[5] if len(parts) > 5 else '',
                'process': '',
            }

            # Parse local address
            if conn['local']:
                if ':' in conn['local']:
                    addr_parts = conn['local'].rsplit(':', 1)
                    conn['local_addr'] = addr_parts[0]
                    conn['local_port'] = addr_parts[1] if len(addr_parts) > 1 else ''
                else:
                    conn['local_addr'] = conn['local']
                    conn['local_port'] = ''

            # Parse remote address
            if conn['remote'] and conn['remote'] not in ['*:*', '0.0.0.0:*', '[::]:*']:
                if ':' in conn['remote']:
                    addr_parts = conn['remote'].rsplit(':', 1)
                    conn['remote_addr'] = addr_parts[0]
                    conn['remote_port'] = addr_parts[1] if len(addr_parts) > 1 else ''
                else:
                    conn['remote_addr'] = conn['remote']
                    conn['remote_port'] = ''
            else:
                conn['remote_addr'] = ''
                conn['remote_port'] = ''

            # Try to get process info
            for part in parts[6:]:
                if 'users:' in part:
                    match = re.search(r'"([^"]+)"', part)
                    if match:
                        conn['process'] = match.group(1)
                    break

            connections.append(conn)

    except FileNotFoundError:
        # Fall back to netstat
        try:
            result = subprocess.run(
                ['netstat', '-tunaop'],
                capture_output=True, text=True, timeout=10
            )

            for line in result.stdout.split('\n'):
                if not line.strip() or line.startswith('Active') or line.startswith('Proto'):
                    continue

                parts = line.split()
                if len(parts) < 6:
                    continue

                conn = {
                    'proto': parts[0],
                    'local': parts[3],
                    'remote': parts[4],
                    'state': parts[5] if len(parts) > 5 else '',
                    'process': parts[6] if len(parts) > 6 else '',
                }

                connections.append(conn)
        except:
            pass

    return connections


def get_listening_ports():
    """Get all listening ports"""
    listeners = []

    try:
        result = subprocess.run(
            ['ss', '-tlnp'],
            capture_output=True, text=True, timeout=10
        )

        for line in result.stdout.split('\n')[1:]:
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            local = parts[3]
            if ':' in local:
                addr, port = local.rsplit(':', 1)
                # Clean up address
                addr = addr.replace('[', '').replace(']', '')
                if addr in ['*', '0.0.0.0', '::']:
                    addr = 'all interfaces'

                listener = {
                    'port': int(port) if port.isdigit() else port,
                    'address': addr,
                    'proto': parts[0],
                    'process': '',
                }

                # Get process
                for part in parts[5:]:
                    if 'users:' in part:
                        match = re.search(r'"([^"]+)"', part)
                        if match:
                            listener['process'] = match.group(1)
                        break

                listeners.append(listener)

    except:
        pass

    return sorted(listeners, key=lambda x: x['port'])


def get_connection_stats(connections):
    """Calculate connection statistics"""
    stats = {
        'total': len(connections),
        'tcp': len([c for c in connections if c['proto'].lower().startswith('tcp')]),
        'udp': len([c for c in connections if c['proto'].lower().startswith('udp')]),
        'established': len([c for c in connections if c.get('state', '').upper() == 'ESTAB']),
        'listening': len([c for c in connections if c.get('state', '').upper() == 'LISTEN']),
        'time_wait': len([c for c in connections if c.get('state', '').upper() == 'TIME-WAIT']),
        'close_wait': len([c for c in connections if c.get('state', '').upper() == 'CLOSE-WAIT']),
    }

    # Unique remote IPs
    remote_ips = set()
    for c in connections:
        remote = c.get('remote_addr', '')
        if remote and remote not in ['', '*', '0.0.0.0', '::']:
            remote_ips.add(remote)
    stats['unique_remote_ips'] = len(remote_ips)

    return stats


def get_interface_stats():
    """Get network interface statistics"""
    interfaces = {}

    try:
        # Read from /proc/net/dev
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                if ':' in line:
                    parts = line.split(':')
                    iface = parts[0].strip()
                    stats = parts[1].split()

                    if len(stats) >= 10:
                        interfaces[iface] = {
                            'rx_bytes': int(stats[0]),
                            'rx_packets': int(stats[1]),
                            'rx_errors': int(stats[2]),
                            'tx_bytes': int(stats[8]),
                            'tx_packets': int(stats[9]),
                            'tx_errors': int(stats[10]),
                        }
    except:
        pass

    return interfaces


def format_bytes(bytes_val):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} PB"


def display_connections(connections, filter_port=None, filter_state=None):
    """Display network connections"""
    print(f"\n  {BOLD}Active Connections{RESET}")
    print(f"  {DIM}{'─' * 70}{RESET}\n")

    # Apply filters
    filtered = connections
    if filter_port:
        filtered = [c for c in filtered if c.get('local_port') == str(filter_port) or c.get('remote_port') == str(filter_port)]
    if filter_state:
        filtered = [c for c in filtered if filter_state.upper() in c.get('state', '').upper()]

    if not filtered:
        print(f"  {DIM}No matching connections{RESET}")
        return

    # Group by state
    established = [c for c in filtered if c.get('state', '').upper() == 'ESTAB']
    listening = [c for c in filtered if c.get('state', '').upper() == 'LISTEN']
    other = [c for c in filtered if c.get('state', '').upper() not in ['ESTAB', 'LISTEN']]

    # Show established connections
    if established:
        print(f"  {GREEN}ESTABLISHED ({len(established)}){RESET}")
        for c in established[:15]:
            local = f"{c.get('local_addr', '?')}:{c.get('local_port', '?')}"
            remote = f"{c.get('remote_addr', '?')}:{c.get('remote_port', '?')}"
            proc = c.get('process', '')
            print(f"    {c['proto']:4} {local:25} <-> {remote:25} {DIM}{proc}{RESET}")
        if len(established) > 15:
            print(f"    {DIM}... and {len(established) - 15} more{RESET}")
        print()

    # Show listening
    if listening:
        print(f"  {CYAN}LISTENING ({len(listening)}){RESET}")
        for c in listening[:10]:
            local = f"{c.get('local_addr', '?')}:{c.get('local_port', '?')}"
            proc = c.get('process', '')
            print(f"    {c['proto']:4} {local:25} {DIM}{proc}{RESET}")
        print()

    # Show other states
    if other:
        print(f"  {YELLOW}OTHER STATES ({len(other)}){RESET}")
        for c in other[:10]:
            state = c.get('state', '?')
            local = f"{c.get('local_addr', '?')}:{c.get('local_port', '?')}"
            remote = f"{c.get('remote_addr', '?')}:{c.get('remote_port', '?')}"
            print(f"    {state:12} {local:25} <-> {remote:25}")
        print()


def display_stats(stats, iface_stats):
    """Display network statistics"""
    print(f"\n  {BOLD}Network Statistics{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}\n")

    print(f"  {CYAN}Connections:{RESET}")
    print(f"    Total:       {stats['total']}")
    print(f"    TCP:         {stats['tcp']}")
    print(f"    UDP:         {stats['udp']}")
    print(f"    Established: {GREEN}{stats['established']}{RESET}")
    print(f"    Listening:   {CYAN}{stats['listening']}{RESET}")
    print(f"    Time-Wait:   {YELLOW}{stats['time_wait']}{RESET}")
    print(f"    Close-Wait:  {RED if stats['close_wait'] > 0 else DIM}{stats['close_wait']}{RESET}")
    print(f"    Remote IPs:  {stats['unique_remote_ips']}")
    print()

    if iface_stats:
        print(f"  {CYAN}Interfaces:{RESET}")
        for iface, s in iface_stats.items():
            if iface == 'lo':
                continue
            rx = format_bytes(s['rx_bytes'])
            tx = format_bytes(s['tx_bytes'])
            print(f"    {iface:15} RX: {GREEN}{rx:>12}{RESET}  TX: {YELLOW}{tx:>12}{RESET}")
        print()


def watch_mode(interval=2, filter_port=None):
    """Continuously monitor network"""
    try:
        while True:
            # Clear screen
            os.system('clear' if os.name != 'nt' else 'cls')

            print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
            print(f"{BOLD}{CYAN}  Network Monitor (Live){RESET}")
            print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")
            print(f"  {DIM}Press Ctrl+C to exit | Refresh: {interval}s{RESET}")

            connections = get_connections()
            stats = get_connection_stats(connections)
            iface_stats = get_interface_stats()

            display_stats(stats, iface_stats)
            display_connections(connections, filter_port, 'ESTAB')

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n\n  {GREEN}Monitor stopped{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description='Network Monitor')
    parser.add_argument('--watch', '-w', action='store_true', help='Continuous monitoring')
    parser.add_argument('--interval', '-i', type=int, default=2, help='Refresh interval for watch mode')
    parser.add_argument('--port', '-p', type=int, help='Filter by port')
    parser.add_argument('--state', '-s', help='Filter by state (ESTAB, LISTEN, etc)')
    parser.add_argument('--listeners', '-l', action='store_true', help='Show only listening ports')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    if args.watch:
        watch_mode(args.interval, args.port)
        return

    if not args.json:
        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  Network Monitor{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

    if args.listeners:
        listeners = get_listening_ports()
        if args.json:
            print(json.dumps(listeners, indent=2))
        else:
            print(f"\n  {BOLD}Listening Ports ({len(listeners)}){RESET}")
            print(f"  {DIM}{'─' * 50}{RESET}\n")

            for l in listeners:
                proc = l.get('process', '')
                print(f"  {CYAN}{l['port']:>5}{RESET}  {l['proto']:4}  {l['address']:20}  {DIM}{proc}{RESET}")
            print()
        return

    connections = get_connections()
    stats = get_connection_stats(connections)
    iface_stats = get_interface_stats()

    if args.json:
        output = {
            'stats': stats,
            'interfaces': iface_stats,
            'connections': connections[:100]  # Limit for JSON
        }
        print(json.dumps(output, indent=2))
    else:
        display_stats(stats, iface_stats)
        display_connections(connections, args.port, args.state)


if __name__ == '__main__':
    main()
