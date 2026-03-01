"""Common service detector for OT environments.

Detects non-ICS services commonly found on OT networks that represent
attack surface: HTTP/HTTPS, SSH, Telnet, FTP, VNC, RDP, MQTT, SNMP.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from otscan.protocols.base import Severity, Vulnerability


@dataclass
class ServiceInfo:
    """Information about a detected service."""

    name: str
    port: int
    banner: str = ""
    version: str = ""
    tls: bool = False
    metadata: dict = field(default_factory=dict)


# Common OT-adjacent service ports
SERVICE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    502: "Modbus TCP",
    1433: "MSSQL",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8883: "MQTT-TLS",
    9090: "HTTP-Mgmt",
    27017: "MongoDB",
    47808: "BACnet/IP",
}


class ServiceDetector:
    """Detects common services on OT network hosts."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def detect_service(self, target: str, port: int) -> Optional[ServiceInfo]:
        """Detect and fingerprint a service on a given port."""
        known = SERVICE_PORTS.get(port, "Unknown")

        # Try TCP banner grab
        banner = self._grab_banner(target, port)
        if banner is None:
            return None

        service = ServiceInfo(name=known, port=port, banner=banner)

        # Fingerprint based on banner content
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            service.name = "SSH"
            service.version = banner.split("\n")[0].strip()
        elif "ftp" in banner_lower:
            service.name = "FTP"
            service.version = banner.split("\n")[0].strip()
        elif banner.startswith("HTTP/") or "html" in banner_lower:
            service.name = "HTTP"
        elif banner.startswith("RFB "):
            service.name = "VNC"
            service.version = banner.strip()
        elif "smtp" in banner_lower:
            service.name = "SMTP"
        elif "mysql" in banner_lower:
            service.name = "MySQL"
        elif "mongo" in banner_lower:
            service.name = "MongoDB"

        return service

    def detect_http_server(self, target: str, port: int) -> Optional[ServiceInfo]:
        """Send HTTP request and extract server information."""
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            sock.sendall(request.encode())
            response = sock.recv(4096)
            sock.close()

            resp_str = response.decode("ascii", errors="replace")
            service = ServiceInfo(name="HTTP", port=port, banner=resp_str[:500])

            # Extract Server header
            for line in resp_str.split("\r\n"):
                if line.lower().startswith("server:"):
                    service.version = line.split(":", 1)[1].strip()
                    break

            # Detect known OT web interfaces from response body
            body_lower = resp_str.lower()
            for keyword, vendor in _OT_WEB_SIGNATURES.items():
                if keyword in body_lower:
                    service.metadata["ot_vendor"] = vendor
                    break

            return service
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def detect_rdp(self, target: str, port: int = 3389) -> Optional[ServiceInfo]:
        """Detect RDP service via X.224 Connection Request."""
        # T.125 / X.224 Connection Request for RDP
        x224_cr = (
            b"\x03\x00"  # TPKT version 3
            b"\x00\x13"  # Length = 19
            b"\x0e"      # X.224 length
            b"\xe0"      # Connection Request
            b"\x00\x00"  # DST reference
            b"\x00\x00"  # SRC reference
            b"\x00"      # Class
            b"\x01\x00\x08"  # Cookie
            b"\x00\x03\x00\x00\x00"  # RDP negotiation request
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            sock.sendall(x224_cr)
            response = sock.recv(1024)
            sock.close()
            # TPKT response starts with 0x03 0x00
            if response and response[0] == 0x03:
                return ServiceInfo(
                    name="RDP",
                    port=port,
                    banner="Microsoft Terminal Services",
                    metadata={"nla_supported": len(response) > 11 and response[11] in (1, 2, 3)},
                )
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return None

    def assess_services(
        self, target: str, open_ports: list[int]
    ) -> list[Vulnerability]:
        """Assess security implications of detected services."""
        vulns = []
        for port in open_ports:
            if port == 23:
                vulns.append(Vulnerability(
                    title="Telnet service exposed on OT network",
                    severity=Severity.HIGH,
                    protocol="Telnet",
                    target=target,
                    port=port,
                    description="Telnet transmits all data including credentials in cleartext.",
                    remediation="Disable Telnet. Use SSH instead.",
                ))
            elif port == 21:
                vulns.append(Vulnerability(
                    title="FTP service exposed on OT network",
                    severity=Severity.MEDIUM,
                    protocol="FTP",
                    target=target,
                    port=port,
                    description=(
                        "FTP transmits credentials in cleartext. On OT devices, "
                        "FTP often provides access to firmware and configuration files."
                    ),
                    remediation="Disable FTP. Use SFTP/SCP instead.",
                ))
            elif port == 3389:
                vulns.append(Vulnerability(
                    title="RDP exposed on OT network",
                    severity=Severity.MEDIUM,
                    protocol="RDP",
                    target=target,
                    port=port,
                    description=(
                        "Remote Desktop Protocol is exposed, providing potential "
                        "remote access to operator/engineering workstations."
                    ),
                    remediation="Restrict RDP via firewall. Enable NLA. Use VPN for remote access.",
                ))
            elif port in (80, 8080, 9090):
                vulns.append(Vulnerability(
                    title=f"Unencrypted HTTP on port {port}",
                    severity=Severity.LOW,
                    protocol="HTTP",
                    target=target,
                    port=port,
                    description="Web interface accessible over unencrypted HTTP.",
                    remediation="Enable HTTPS. Redirect HTTP to HTTPS.",
                ))
            elif port == 1883:
                vulns.append(Vulnerability(
                    title="MQTT broker exposed without TLS",
                    severity=Severity.HIGH,
                    protocol="MQTT",
                    target=target,
                    port=port,
                    description=(
                        "MQTT broker on port 1883 uses plaintext. An attacker "
                        "can sniff or inject SCADA messages."
                    ),
                    remediation="Use MQTT over TLS (port 8883). Require authentication.",
                ))
            elif port in (1433, 3306, 5432, 27017):
                svc = SERVICE_PORTS.get(port, "Database")
                vulns.append(Vulnerability(
                    title=f"Database service ({svc}) exposed on OT network",
                    severity=Severity.MEDIUM,
                    protocol=svc,
                    target=target,
                    port=port,
                    description=(
                        f"Database service ({svc}) is accessible on the OT network. "
                        "Historian and SCADA databases may contain sensitive process data."
                    ),
                    remediation="Restrict database access to authorized hosts only via firewall.",
                ))

        return vulns

    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """Grab banner from a TCP service."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            sock.settimeout(2.0)
            try:
                data = sock.recv(1024)
                banner = data.decode("ascii", errors="replace").strip()
            except socket.timeout:
                banner = ""
            sock.close()
            return banner
        except (ConnectionRefusedError, OSError):
            return None


# Signatures in HTTP response bodies that indicate OT vendor web interfaces
_OT_WEB_SIGNATURES = {
    "siemens": "Siemens",
    "simatic": "Siemens",
    "scalance": "Siemens",
    "schneider": "Schneider Electric",
    "modicon": "Schneider Electric",
    "vijeo": "Schneider Electric",
    "rockwell": "Rockwell Automation",
    "allen-bradley": "Rockwell Automation",
    "factorytalk": "Rockwell Automation",
    "honeywell": "Honeywell",
    "experion": "Honeywell",
    "yokogawa": "Yokogawa",
    "centum": "Yokogawa",
    "emerson": "Emerson",
    "deltav": "Emerson",
    "abb": "ABB",
    "tridium": "Tridium",
    "niagara": "Tridium",
    "moxa": "Moxa",
    "nport": "Moxa",
    "beckhoff": "Beckhoff",
    "twincat": "Beckhoff",
    "wago": "WAGO",
    "phoenix contact": "Phoenix Contact",
    "red lion": "Red Lion",
    "ge fanuc": "GE",
    "omron": "Omron",
    "mitsubishi": "Mitsubishi",
    "melsec": "Mitsubishi",
}
