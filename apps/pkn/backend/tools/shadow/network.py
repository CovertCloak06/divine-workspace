#!/usr/bin/env python3
"""
Shadow OSINT - Network Reconnaissance
IP, ASN, geolocation, and infrastructure intelligence
"""

import socket
import struct
from typing import Dict, Any, List, Optional
from datetime import datetime
import requests

from .sources import DATA_SOURCES


class NetworkRecon:
    """Network-focused OSINT reconnaissance."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; ShadowOSINT/1.0)"
        })

    def full_recon(self, ip: str) -> Dict[str, Any]:
        """
        Complete IP reconnaissance.

        Combines all IP checks into one report.
        """
        return {
            "success": True,
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat(),
            "geolocation": self.geolocate(ip),
            "shodan": self.shodan_lookup(ip),
            "reverse_dns": self.reverse_dns(ip),
            "reputation": self.ip_reputation(ip),
        }

    def geolocate(self, ip: str) -> Dict[str, Any]:
        """
        IP geolocation using multiple free APIs.

        Sources: ip-api.com, ipinfo.io
        """
        results = {"ip": ip, "sources": {}}

        # Primary: ip-api.com
        try:
            resp = self.session.get(
                DATA_SOURCES["ip_api"]["url"].format(ip=ip),
                timeout=self.timeout
            )
            data = resp.json()

            if data.get("status") == "success":
                results["sources"]["ip_api"] = {
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "zip": data.get("zip"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                }
                # Use as primary result
                results.update(results["sources"]["ip_api"])
                results["success"] = True
        except Exception as e:
            results["sources"]["ip_api"] = {"error": str(e)}

        # Backup: ipinfo.io
        try:
            resp = self.session.get(
                DATA_SOURCES["ipinfo"]["url"].format(ip=ip),
                timeout=self.timeout
            )
            data = resp.json()

            results["sources"]["ipinfo"] = {
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "loc": data.get("loc"),  # "lat,lon"
                "org": data.get("org"),
                "hostname": data.get("hostname"),
            }
        except Exception as e:
            results["sources"]["ipinfo"] = {"error": str(e)}

        return results

    def shodan_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Query Shodan InternetDB (free, no API key).

        Returns: ports, hostnames, CPEs, vulns, tags
        """
        try:
            resp = self.session.get(
                DATA_SOURCES["internetdb"]["url"].format(ip=ip),
                timeout=self.timeout
            )

            if resp.status_code == 200:
                data = resp.json()
                return {
                    "success": True,
                    "ip": ip,
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "cpes": data.get("cpes", []),
                    "vulns": data.get("vulns", []),
                    "tags": data.get("tags", []),
                    "has_vulns": len(data.get("vulns", [])) > 0,
                }
            elif resp.status_code == 404:
                return {
                    "success": True,
                    "ip": ip,
                    "message": "No data found in Shodan InternetDB",
                    "ports": [],
                    "vulns": [],
                }
            else:
                return {"success": False, "error": f"Status {resp.status_code}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def reverse_dns(self, ip: str) -> Dict[str, Any]:
        """
        Reverse DNS lookup.
        """
        results = {"ip": ip, "hostnames": []}

        # Method 1: Socket
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            results["hostnames"].append(hostname)
            results["primary_hostname"] = hostname
        except socket.herror:
            pass
        except Exception as e:
            results["error"] = str(e)

        # Method 2: HackerTarget API (finds all domains on IP)
        try:
            resp = self.session.get(
                DATA_SOURCES["hackertarget_reverse"]["url"].format(ip=ip),
                timeout=self.timeout
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                domains = [d.strip() for d in resp.text.split("\n") if d.strip()]
                results["hostnames"].extend(domains)
                results["hostnames"] = list(set(results["hostnames"]))
        except Exception:
            pass

        results["success"] = True
        results["count"] = len(results["hostnames"])
        return results

    def ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation/blacklists.

        Uses AbuseIPDB-style checks (without API key).
        """
        results = {
            "ip": ip,
            "checks": {},
            "risk_score": 0,
            "flags": [],
        }

        # Check if private IP
        if self._is_private_ip(ip):
            results["checks"]["private"] = True
            results["flags"].append("Private IP address")
            results["success"] = True
            return results

        # Check Shodan for known issues
        shodan_data = self.shodan_lookup(ip)
        if shodan_data.get("success"):
            if shodan_data.get("vulns"):
                results["checks"]["shodan_vulns"] = shodan_data["vulns"]
                results["flags"].append(f"Has {len(shodan_data['vulns'])} known vulnerabilities")
                results["risk_score"] += len(shodan_data["vulns"]) * 10

            if "proxy" in shodan_data.get("tags", []):
                results["flags"].append("Identified as proxy")
                results["risk_score"] += 20

            if "vpn" in shodan_data.get("tags", []):
                results["flags"].append("Identified as VPN")
                results["risk_score"] += 10

        # Check for common attack ports
        dangerous_ports = [23, 445, 3389, 1433, 3306]
        if shodan_data.get("ports"):
            open_dangerous = [p for p in shodan_data["ports"] if p in dangerous_ports]
            if open_dangerous:
                results["flags"].append(f"Dangerous ports open: {open_dangerous}")
                results["risk_score"] += len(open_dangerous) * 15

        results["success"] = True
        results["risk_level"] = (
            "high" if results["risk_score"] >= 50
            else "medium" if results["risk_score"] >= 20
            else "low"
        )

        return results

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved."""
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) != 4:
                return False

            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
            # 127.0.0.0/8
            if parts[0] == 127:
                return True

            return False
        except Exception:
            return False

    def asn_lookup(self, ip: str) -> Dict[str, Any]:
        """
        ASN (Autonomous System Number) lookup.
        """
        # Use ip-api which includes ASN info
        geo = self.geolocate(ip)

        if geo.get("success") and "as" in geo:
            as_info = geo["as"]
            # Parse "AS12345 Organization Name"
            parts = as_info.split(" ", 1)
            asn = parts[0] if parts else "Unknown"
            org = parts[1] if len(parts) > 1 else "Unknown"

            return {
                "success": True,
                "ip": ip,
                "asn": asn,
                "organization": org,
                "isp": geo.get("isp"),
            }

        return {"success": False, "error": "Could not determine ASN"}

    def port_check(self, ip: str, ports: List[int] = None) -> Dict[str, Any]:
        """
        Quick port check on specific ports.

        Note: For comprehensive scanning, use network_tools.tcp_scan
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]

        results = {
            "ip": ip,
            "open": [],
            "closed": [],
            "scanned": len(ports),
        }

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "unknown"
                    results["open"].append({"port": port, "service": service})
                else:
                    results["closed"].append(port)
            except Exception:
                results["closed"].append(port)

        results["success"] = True
        results["open_count"] = len(results["open"])
        return results

    def traceroute(self, host: str, max_hops: int = 20) -> Dict[str, Any]:
        """
        Simple traceroute implementation.

        Note: May require elevated privileges on some systems.
        """
        import subprocess

        results = {
            "host": host,
            "hops": [],
            "success": False,
        }

        try:
            # Try traceroute command
            cmd = ["traceroute", "-m", str(max_hops), "-w", "2", host]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if proc.returncode == 0:
                lines = proc.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        hop_num = parts[0]
                        hop_ip = parts[1] if parts[1] != "*" else None
                        results["hops"].append({
                            "hop": hop_num,
                            "ip": hop_ip,
                            "raw": line.strip()
                        })
                results["success"] = True
            else:
                results["error"] = proc.stderr or "Traceroute failed"

        except FileNotFoundError:
            results["error"] = "traceroute command not found"
        except subprocess.TimeoutExpired:
            results["error"] = "Traceroute timed out"
        except Exception as e:
            results["error"] = str(e)

        return results
