"""
Network Tools - Network Analysis & Scanning
Pure Python network scanning and analysis utilities.

Tools:
- tcp_scan: TCP connect scan
- udp_scan: UDP port scan
- os_fingerprint: Basic OS detection via TTL
- traceroute: Python traceroute
- arp_scan: Local network discovery
- dns_zone_transfer: Attempt AXFR
- smb_enum: SMB enumeration (basic)
- service_detect: Service detection by banner

WARNING: For authorized security testing only.
"""

import socket
import struct
import time
import subprocess
import platform
from typing import Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from langchain_core.tools import tool


# Common ports for quick scans
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]

# Service signatures
SERVICE_BANNERS = {
    b"SSH": "SSH",
    b"220": "FTP/SMTP",
    b"HTTP": "HTTP",
    b"MySQL": "MySQL",
    b"PostgreSQL": "PostgreSQL",
    b"220 Microsoft": "Microsoft SMTP",
    b"* OK": "IMAP",
    b"+OK": "POP3",
}

# TTL fingerprinting
TTL_OS = {
    (64, 128): "Linux/Unix",
    (128, 256): "Windows",
    (255, 256): "Cisco/Network Device",
}


@tool
def tcp_scan(host: str, ports: str = "common", timeout: float = 1.0, threads: int = 10) -> str:
    """
    TCP connect scan on target host.

    Args:
        host: Target IP or hostname
        ports: "common", "1-1024", or comma-separated list
        timeout: Connection timeout in seconds
        threads: Number of concurrent threads

    Returns:
        List of open ports with service detection
    """
    results = [f"TCP Scan: {host}", "=" * 50]

    # Parse port list
    if ports == "common":
        port_list = COMMON_PORTS
    elif "-" in ports:
        start, end = map(int, ports.split("-"))
        port_list = list(range(start, min(end + 1, 65536)))
    else:
        port_list = [int(p.strip()) for p in ports.split(",")]

    results.append(f"Scanning {len(port_list)} ports...")

    open_ports = []

    def scan_port(port: int) -> Tuple[int, bool, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                # Try banner grab
                banner = ""
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n" if port in [80, 8080] else b"\r\n")
                    data = sock.recv(100)
                    for sig, svc in SERVICE_BANNERS.items():
                        if sig in data:
                            banner = svc
                            break
                except:
                    pass

                sock.close()
                return (port, True, banner)

            sock.close()
            return (port, False, "")
        except:
            return (port, False, "")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, p): p for p in port_list}
        for future in as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))

    results.append(f"\nOpen Ports: {len(open_ports)}")
    for port, service in sorted(open_ports):
        svc = f" ({service})" if service else ""
        results.append(f"  {port}/tcp open{svc}")

    return "\n".join(results)


@tool
def udp_scan(host: str, ports: str = "53,67,68,69,123,161,162,500,514,1900") -> str:
    """
    UDP port scan (limited - requires interpretation).

    Args:
        host: Target IP or hostname
        ports: Comma-separated port list

    Returns:
        UDP scan results (open|filtered)
    """
    results = [f"UDP Scan: {host}", "=" * 50]
    results.append("Note: UDP scanning is unreliable without root/ICMP")

    port_list = [int(p.strip()) for p in ports.split(",")]
    results.append(f"Scanning {len(port_list)} ports...")

    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b"\x00", (host, port))

            try:
                data, addr = sock.recvfrom(1024)
                results.append(f"  {port}/udp open")
            except socket.timeout:
                results.append(f"  {port}/udp open|filtered")

            sock.close()
        except Exception as e:
            results.append(f"  {port}/udp error: {e}")

    return "\n".join(results)


@tool
def os_fingerprint(host: str) -> str:
    """
    Basic OS detection via TTL and TCP characteristics.

    Args:
        host: Target IP or hostname

    Returns:
        OS guess based on network characteristics
    """
    results = [f"OS Fingerprint: {host}", "=" * 50]

    # Get TTL via ping
    if platform.system() == "Windows":
        ping_cmd = f"ping -n 1 {host}"
        ttl_pattern = r"TTL=(\d+)"
    else:
        ping_cmd = f"ping -c 1 {host}"
        ttl_pattern = r"ttl=(\d+)"

    try:
        output = subprocess.run(ping_cmd, shell=True, capture_output=True, text=True, timeout=5)
        import re
        match = re.search(ttl_pattern, output.stdout, re.IGNORECASE)

        if match:
            ttl = int(match.group(1))
            results.append(f"\nTTL: {ttl}")

            # Guess OS
            os_guess = "Unknown"
            for (low, high), os_name in TTL_OS.items():
                if low <= ttl < high:
                    os_guess = os_name
                    break

            results.append(f"OS Guess: {os_guess}")

            # Calculate hops
            if ttl <= 64:
                hops = 64 - ttl
            elif ttl <= 128:
                hops = 128 - ttl
            else:
                hops = 255 - ttl
            results.append(f"Estimated hops: {hops}")
        else:
            results.append("Could not determine TTL")

    except Exception as e:
        results.append(f"Error: {e}")

    # TCP fingerprint
    results.append("\n[TCP Characteristics]")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, 80))
        sock.send(b"GET / HTTP/1.0\r\n\r\n")
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        sock.close()

        if "Server:" in response:
            server = [l for l in response.split("\n") if "Server:" in l][0]
            results.append(f"HTTP Server: {server.strip()}")
    except:
        pass

    return "\n".join(results)


@tool
def traceroute(host: str, max_hops: int = 30) -> str:
    """
    Perform traceroute to target.

    Args:
        host: Target IP or hostname
        max_hops: Maximum number of hops

    Returns:
        Traceroute path
    """
    results = [f"Traceroute to {host}", "=" * 50]

    try:
        # Resolve hostname
        target_ip = socket.gethostbyname(host)
        results.append(f"Target IP: {target_ip}\n")

        for ttl in range(1, max_hops + 1):
            # Create socket
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_socket.settimeout(2)

            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            # Send UDP packet
            send_socket.sendto(b"", (host, 33434 + ttl))
            start_time = time.time()

            try:
                data, addr = recv_socket.recvfrom(512)
                rtt = (time.time() - start_time) * 1000

                try:
                    hostname = socket.gethostbyaddr(addr[0])[0]
                except:
                    hostname = addr[0]

                results.append(f"{ttl:2d}  {hostname} ({addr[0]})  {rtt:.2f} ms")

                if addr[0] == target_ip:
                    break

            except socket.timeout:
                results.append(f"{ttl:2d}  *  *  *")

            recv_socket.close()
            send_socket.close()

    except PermissionError:
        results.append("Error: Traceroute requires root/admin privileges")
        results.append("Alternative: Use 'traceroute' or 'tracert' command directly")
    except Exception as e:
        results.append(f"Error: {e}")

    return "\n".join(results)


@tool
def arp_scan(interface: str = "auto") -> str:
    """
    Discover hosts on local network via ARP.

    Args:
        interface: Network interface (auto-detect if not specified)

    Returns:
        List of discovered hosts
    """
    results = ["Local Network ARP Scan", "=" * 50]

    # Try using system commands (more reliable without scapy)
    if platform.system() == "Linux":
        # Get local IP range
        ip_output = subprocess.run("ip addr", shell=True, capture_output=True, text=True)
        import re
        match = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/\d+", ip_output.stdout)

        if match:
            subnet = match.group(1)
            results.append(f"Scanning subnet: {subnet}.0/24\n")

            # Ping sweep then check ARP cache
            for i in range(1, 255):
                subprocess.run(f"ping -c 1 -W 1 {subnet}.{i} >/dev/null 2>&1 &",
                             shell=True)

            time.sleep(3)  # Wait for pings

            # Read ARP cache
            arp_output = subprocess.run("arp -n", shell=True, capture_output=True, text=True)
            for line in arp_output.stdout.split("\n"):
                if "ether" in line or ":" in line:
                    results.append(f"  {line.strip()}")
        else:
            results.append("Could not determine local subnet")

    else:
        results.append("ARP scan requires Linux")
        results.append("On Windows, use: arp -a")

    return "\n".join(results)


@tool
def dns_zone_transfer(domain: str, nameserver: Optional[str] = None) -> str:
    """
    Attempt DNS zone transfer (AXFR).

    Args:
        domain: Target domain
        nameserver: Specific NS to query (optional)

    Returns:
        Zone transfer results or failure message
    """
    results = [f"DNS Zone Transfer: {domain}", "=" * 50]

    try:
        # Get nameservers if not specified
        if not nameserver:
            import subprocess
            ns_output = subprocess.run(f"dig +short NS {domain}",
                                      shell=True, capture_output=True, text=True)
            nameservers = [ns.strip().rstrip(".") for ns in ns_output.stdout.split("\n") if ns.strip()]
        else:
            nameservers = [nameserver]

        results.append(f"Nameservers: {', '.join(nameservers)}\n")

        for ns in nameservers:
            results.append(f"[Trying AXFR from {ns}]")

            try:
                # Using dig for AXFR
                axfr_output = subprocess.run(
                    f"dig @{ns} {domain} AXFR +short",
                    shell=True, capture_output=True, text=True, timeout=10
                )

                if axfr_output.stdout.strip():
                    results.append("[!] Zone transfer SUCCESSFUL!")
                    for line in axfr_output.stdout.split("\n")[:30]:
                        results.append(f"  {line}")
                else:
                    results.append("  Transfer refused or no data")

            except subprocess.TimeoutExpired:
                results.append("  Timeout")
            except Exception as e:
                results.append(f"  Error: {e}")

    except Exception as e:
        results.append(f"Error: {e}")

    return "\n".join(results)


@tool
def service_detect(host: str, port: int) -> str:
    """
    Detect service running on a specific port via banner.

    Args:
        host: Target host
        port: Port number

    Returns:
        Service detection result
    """
    results = [f"Service Detection: {host}:{port}", "=" * 50]

    probes = [
        (b"\r\n", "Generic"),
        (b"HEAD / HTTP/1.0\r\n\r\n", "HTTP"),
        (b"HELP\r\n", "SMTP/FTP"),
        (b"\x00\x00\x00\xa4\xff\x53\x4d\x42", "SMB"),
    ]

    for probe, probe_type in probes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.send(probe)
            banner = sock.recv(1024)
            sock.close()

            results.append(f"\n[Probe: {probe_type}]")
            results.append(f"Raw: {banner[:100]}")
            results.append(f"ASCII: {banner.decode('utf-8', errors='ignore')[:100]}")

            # Identify service
            for sig, svc in SERVICE_BANNERS.items():
                if sig in banner:
                    results.append(f"\nService: {svc}")
                    break

            break  # Got a response
        except Exception as e:
            continue

    return "\n".join(results)


# Export tools
TOOLS = [
    tcp_scan,
    udp_scan,
    os_fingerprint,
    traceroute,
    arp_scan,
    dns_zone_transfer,
    service_detect,
]

TOOL_DESCRIPTIONS = {
    "tcp_scan": "TCP connect scan with threading",
    "udp_scan": "UDP port scan",
    "os_fingerprint": "OS detection via TTL",
    "traceroute": "Python traceroute",
    "arp_scan": "Local network ARP discovery",
    "dns_zone_transfer": "Attempt AXFR zone transfer",
    "service_detect": "Service detection via banners",
}
