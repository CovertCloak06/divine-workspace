#!/usr/bin/env python3
"""
Speed Test - Measure internet connection speed
Usage: speedtest.py [--server url]
"""

import urllib.request
import time
import threading
import sys

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Test files from various CDNs (public, no auth needed)
TEST_URLS = [
    ('Cloudflare', 'https://speed.cloudflare.com/__down?bytes=10000000'),
    ('Google', 'https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png'),
]

UPLOAD_TEST_SIZE = 1024 * 1024  # 1MB


def download_test(url, results, index):
    """Download test file and measure speed"""
    try:
        start = time.time()
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read()
        elapsed = time.time() - start

        size_mb = len(data) / (1024 * 1024)
        speed_mbps = (size_mb * 8) / elapsed

        results[index] = (len(data), elapsed, speed_mbps)
    except Exception as e:
        results[index] = (0, 0, 0)


def measure_latency(host='8.8.8.8'):
    """Measure latency to a host"""
    import subprocess
    try:
        result = subprocess.run(
            ['ping', '-c', '3', '-W', '2', host],
            capture_output=True, text=True, timeout=10
        )
        # Parse average ping time
        for line in result.stdout.split('\n'):
            if 'avg' in line or 'average' in line.lower():
                # Format: rtt min/avg/max/mdev = 1.234/5.678/9.012/1.234 ms
                parts = line.split('=')
                if len(parts) >= 2:
                    times = parts[1].strip().split('/')
                    if len(times) >= 2:
                        return float(times[1])
        return None
    except:
        return None


def progress_bar(current, total, width=40, prefix=''):
    """Display progress bar"""
    percent = current / total if total > 0 else 0
    filled = int(width * percent)
    bar = '█' * filled + '░' * (width - filled)
    sys.stdout.write(f'\r  {prefix} {CYAN}{bar}{RESET} {percent*100:.0f}%')
    sys.stdout.flush()


def main():
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              ⚡ Internet Speed Test                        ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Latency test
    print(f"  {BOLD}Testing latency...{RESET}")
    latency = measure_latency()
    if latency:
        if latency < 20:
            color = GREEN
        elif latency < 50:
            color = YELLOW
        else:
            color = RED
        print(f"  {CYAN}Ping:{RESET} {color}{latency:.1f} ms{RESET}\n")
    else:
        print(f"  {CYAN}Ping:{RESET} {DIM}Could not measure{RESET}\n")

    # Download test
    print(f"  {BOLD}Testing download speed...{RESET}")

    results = [None] * len(TEST_URLS)
    threads = []

    for i, (name, url) in enumerate(TEST_URLS):
        t = threading.Thread(target=download_test, args=(url, results, i))
        threads.append(t)
        t.start()

    # Wait with progress indication
    for i in range(20):
        progress_bar(i + 1, 20, prefix='Download')
        time.sleep(0.3)
        all_done = all(r is not None for r in results)
        if all_done:
            break

    for t in threads:
        t.join(timeout=5)

    print()  # New line after progress bar

    # Calculate average speed
    speeds = [r[2] for r in results if r and r[2] > 0]
    if speeds:
        avg_speed = sum(speeds) / len(speeds)
        max_speed = max(speeds)

        # Color based on speed
        if max_speed > 50:
            color = GREEN
        elif max_speed > 10:
            color = YELLOW
        else:
            color = RED

        print(f"\n  {BOLD}Download Results:{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}")

        for i, (name, url) in enumerate(TEST_URLS):
            if results[i] and results[i][2] > 0:
                size_mb = results[i][0] / (1024 * 1024)
                speed = results[i][2]
                print(f"  {CYAN}{name}:{RESET} {speed:.1f} Mbps ({size_mb:.1f} MB)")

        print(f"\n  {BOLD}Average:{RESET} {color}{avg_speed:.1f} Mbps{RESET}")
        print(f"  {BOLD}Peak:{RESET} {color}{max_speed:.1f} Mbps{RESET}")

        # Speed rating
        print(f"\n  {BOLD}Rating:{RESET}", end=' ')
        if max_speed > 100:
            print(f"{GREEN}Excellent - Fiber-grade connection{RESET}")
        elif max_speed > 50:
            print(f"{GREEN}Very Good - Great for streaming/gaming{RESET}")
        elif max_speed > 25:
            print(f"{YELLOW}Good - Suitable for HD streaming{RESET}")
        elif max_speed > 10:
            print(f"{YELLOW}Fair - Basic streaming OK{RESET}")
        else:
            print(f"{RED}Slow - May struggle with video{RESET}")
    else:
        print(f"\n  {RED}Could not measure download speed{RESET}")
        print(f"  {DIM}Check your internet connection{RESET}")

    print()


if __name__ == '__main__':
    main()
