"""Network discovery module for finding OT/ICS devices on a network."""

from __future__ import annotations

import ipaddress
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from otscan.protocols.base import BaseProtocolScanner, ScanMode, ScanResult


@dataclass
class HostInfo:
    """Information about a discovered host."""

    ip: str
    is_alive: bool = False
    open_ports: list[int] = field(default_factory=list)
    scan_results: list[ScanResult] = field(default_factory=list)
    hostname: Optional[str] = None


def expand_targets(target_spec: str) -> list[str]:
    """Expand a target specification into a list of individual IPs.

    Supports:
    - Single IP: "192.168.1.1"
    - CIDR notation: "192.168.1.0/24"
    - IP range: "192.168.1.1-192.168.1.10"
    - Comma-separated: "192.168.1.1,192.168.1.2"
    """
    targets = []

    for part in target_spec.split(","):
        part = part.strip()
        if not part:
            continue

        if "/" in part:
            # CIDR notation
            network = ipaddress.ip_network(part, strict=False)
            targets.extend(str(ip) for ip in network.hosts())

        elif "-" in part and not part.startswith("-"):
            # IP range: 192.168.1.1-192.168.1.10 or 192.168.1.1-10
            parts = part.split("-")
            if len(parts) == 2:
                start_ip = ipaddress.ip_address(parts[0].strip())
                end_part = parts[1].strip()
                if "." in end_part:
                    end_ip = ipaddress.ip_address(end_part)
                else:
                    # Short form: 192.168.1.1-10
                    base = str(start_ip).rsplit(".", 1)[0]
                    end_ip = ipaddress.ip_address(f"{base}.{end_part}")

                current = int(start_ip)
                end = int(end_ip)
                while current <= end:
                    targets.append(str(ipaddress.ip_address(current)))
                    current += 1
        else:
            # Single IP or hostname
            targets.append(part)

    return targets


def tcp_port_scan(
    target: str,
    ports: list[int],
    timeout: float = 2.0,
    max_workers: int = 20,
) -> list[int]:
    """Scan a target for open TCP ports."""
    open_ports = []

    def check_port(port: int) -> Optional[int]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return port
        except (socket.timeout, OSError):
            pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_port, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    return sorted(open_ports)


def resolve_hostname(ip: str) -> Optional[str]:
    """Attempt reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


# Common OT/ICS ports and their associated protocols
OT_PORTS = {
    # --- Core ICS protocols ---
    102: "S7comm / IEC 61850 MMS",
    502: "Modbus TCP",
    2222: "EtherNet/IP (alt)",
    2404: "IEC 60870-5-104",
    4840: "OPC UA",
    4843: "OPC UA (TLS)",
    5094: "HART-IP",
    9600: "OMRON FINS",
    18245: "GE SRTP",
    20000: "DNP3",
    34962: "PROFINET RT",
    34963: "PROFINET RT",
    34964: "PROFINET DCP",
    44818: "EtherNet/IP",
    47808: "BACnet/IP",
    # --- Vendor-specific ---
    789: "Crimson v3 (Red Lion)",
    1089: "FF HSE",
    1090: "FF HSE",
    1091: "FF HSE",
    1911: "Niagara Fox",
    1962: "PCWorx (Phoenix Contact)",
    2455: "CODESYS V3",
    4000: "Emerson ROC",
    4911: "Niagara Fox (TLS)",
    5007: "Mitsubishi MELSEC-Q",
    # --- Common services on OT networks ---
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    161: "SNMP",
    443: "HTTPS",
    1883: "MQTT",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8883: "MQTT-TLS",
}


class NetworkDiscovery:
    """Discovers OT/ICS devices on a network using protocol-specific probes."""

    def __init__(
        self,
        scanners: list[BaseProtocolScanner],
        timeout: float = 5.0,
        max_workers: int = 10,
        mode: ScanMode = ScanMode.SAFE,
    ):
        self.scanners = scanners
        self.timeout = timeout
        self.max_workers = max_workers
        self.mode = mode

    def discover_host(self, target: str) -> HostInfo:
        """Discover OT/ICS services on a single host."""
        host = HostInfo(ip=target)

        # First, do a port scan of common OT ports
        ot_ports = list(OT_PORTS.keys())
        host.open_ports = tcp_port_scan(target, ot_ports, timeout=self.timeout)

        if host.open_ports:
            host.is_alive = True
            host.hostname = resolve_hostname(target)

        # Run protocol scanners on matching ports
        for scanner in self.scanners:
            default_port = scanner.DEFAULT_PORT
            # Run scanner if default port is open or if we're in active mode
            if default_port in host.open_ports or self.mode == ScanMode.ACTIVE:
                result = scanner.scan(target, default_port)
                if result.is_open or result.is_identified:
                    host.scan_results.append(result)

        return host

    def discover_network(
        self,
        targets: list[str],
        progress_callback=None,
    ) -> list[HostInfo]:
        """Discover OT/ICS devices across multiple targets."""
        hosts = []
        total = len(targets)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {
                executor.submit(self.discover_host, target): target
                for target in targets
            }

            completed = 0
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                completed += 1

                try:
                    host = future.result()
                    if host.is_alive:
                        hosts.append(host)
                except Exception as e:
                    # Log but don't fail the whole scan
                    if progress_callback:
                        progress_callback(
                            completed, total, target, error=str(e)
                        )
                    continue

                if progress_callback:
                    progress_callback(completed, total, target)

        return hosts
