"""Default credential checker for OT/ICS services.

Tests discovered services against known default credentials.
Only used in ACTIVE scan mode — never attempts credentials in safe/passive mode.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from otscan.credentials.database import (
    SNMP_COMMUNITIES,
    DefaultCredential,
    get_credentials_for_port,
)
from otscan.protocols.base import Severity, Vulnerability


class CredentialChecker:
    """Tests services for default/weak credentials."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def check_snmp(self, target: str, port: int = 161) -> list[Vulnerability]:
        """Check for default SNMP community strings."""
        vulns = []
        for community in SNMP_COMMUNITIES:
            if self._snmp_get_request(target, port, community):
                sev = Severity.CRITICAL if community in ("public", "private") else Severity.HIGH
                vulns.append(Vulnerability(
                    title=f"SNMP default community string: '{community}'",
                    severity=sev,
                    protocol="SNMP",
                    target=target,
                    port=port,
                    description=(
                        f"SNMP agent responds to community string '{community}'. "
                        "This allows unauthenticated read"
                        f"{'write' if community == 'private' else ''} "
                        "access to device configuration, firmware versions, "
                        "and network topology."
                    ),
                    remediation=(
                        "Change default SNMP community strings. Migrate to SNMPv3 "
                        "with authentication and encryption. Restrict SNMP access via ACLs."
                    ),
                ))
        return vulns

    def check_ftp_anonymous(self, target: str, port: int = 21) -> list[Vulnerability]:
        """Check if FTP allows anonymous login."""
        vulns = []
        if self._ftp_check_anonymous(target, port):
            vulns.append(Vulnerability(
                title="FTP anonymous login enabled",
                severity=Severity.HIGH,
                protocol="FTP",
                target=target,
                port=port,
                description=(
                    "FTP server allows anonymous login. On OT devices this often "
                    "provides access to firmware files, configuration backups, "
                    "PLC programs, and log files."
                ),
                remediation=(
                    "Disable anonymous FTP access. Require authentication. "
                    "Consider replacing FTP with SFTP/SCP."
                ),
            ))
        return vulns

    def check_telnet_open(self, target: str, port: int = 23) -> list[Vulnerability]:
        """Check if Telnet is open (any open Telnet on OT is a finding)."""
        vulns = []
        banner = self._grab_banner(target, port)
        if banner is not None:
            vulns.append(Vulnerability(
                title="Telnet service enabled",
                severity=Severity.HIGH,
                protocol="Telnet",
                target=target,
                port=port,
                description=(
                    "Telnet transmits credentials in plaintext. "
                    f"Banner: {banner[:200]!r}"
                ),
                remediation=(
                    "Disable Telnet. Use SSH for remote administration. "
                    "If Telnet is required, restrict access via firewall rules."
                ),
            ))
        return vulns

    def check_vnc(self, target: str, port: int = 5900) -> list[Vulnerability]:
        """Check VNC for no-authentication access."""
        vulns = []
        auth_result = self._vnc_check_auth(target, port)
        if auth_result == "no_auth":
            vulns.append(Vulnerability(
                title="VNC with no authentication",
                severity=Severity.CRITICAL,
                protocol="VNC",
                target=target,
                port=port,
                description=(
                    "VNC server accepts connections without any authentication. "
                    "Full remote desktop access to HMI/operator workstation."
                ),
                remediation=(
                    "Enable VNC authentication. Use a strong password. "
                    "Consider VPN or SSH tunneling for remote HMI access."
                ),
            ))
        elif auth_result == "open":
            vulns.append(Vulnerability(
                title="VNC service exposed",
                severity=Severity.MEDIUM,
                protocol="VNC",
                target=target,
                port=port,
                description="VNC server is reachable and may use weak credentials.",
                remediation="Restrict VNC access. Use strong passwords and network segmentation.",
            ))
        return vulns

    def check_http_default_creds(self, target: str, port: int = 80) -> list[Vulnerability]:
        """Check HTTP basic auth for default credentials."""
        vulns = []
        creds = get_credentials_for_port(port)
        http_creds = [c for c in creds if c.protocol == "http"]
        for cred in http_creds:
            if self._http_basic_auth_check(target, port, cred.username, cred.password):
                vulns.append(Vulnerability(
                    title=f"Default HTTP credentials: {cred.vendor} {cred.product}",
                    severity=Severity.CRITICAL,
                    protocol="HTTP",
                    target=target,
                    port=port,
                    description=(
                        f"Web interface accepts default credentials "
                        f"({cred.username}/{cred.password}) for "
                        f"{cred.vendor} {cred.product}."
                    ),
                    remediation=(
                        "Change default web interface credentials immediately. "
                        "Implement account lockout policies."
                    ),
                    metadata={"vendor": cred.vendor, "product": cred.product},
                ))
        return vulns

    def check_mqtt(self, target: str, port: int = 1883) -> list[Vulnerability]:
        """Check MQTT broker for unauthenticated access."""
        vulns = []
        if self._mqtt_connect_no_auth(target, port):
            vulns.append(Vulnerability(
                title="MQTT broker allows unauthenticated connections",
                severity=Severity.CRITICAL,
                protocol="MQTT",
                target=target,
                port=port,
                description=(
                    "MQTT broker accepts connections without credentials. "
                    "Attacker can subscribe to all topics and publish "
                    "malicious commands to ICS/SCADA systems."
                ),
                remediation=(
                    "Enable MQTT authentication. Use TLS (port 8883). "
                    "Implement topic-level ACLs."
                ),
            ))
        return vulns

    def check_all_services(self, target: str, open_ports: list[int]) -> list[Vulnerability]:
        """Run all credential checks against a target based on open ports."""
        vulns = []
        if 161 in open_ports:
            vulns.extend(self.check_snmp(target, 161))
        if 21 in open_ports:
            vulns.extend(self.check_ftp_anonymous(target, 21))
        if 23 in open_ports:
            vulns.extend(self.check_telnet_open(target, 23))
        if 5900 in open_ports:
            vulns.extend(self.check_vnc(target, 5900))
        if 5901 in open_ports:
            vulns.extend(self.check_vnc(target, 5901))
        if 80 in open_ports:
            vulns.extend(self.check_http_default_creds(target, 80))
        if 443 in open_ports:
            vulns.extend(self.check_http_default_creds(target, 443))
        if 8080 in open_ports:
            vulns.extend(self.check_http_default_creds(target, 8080))
        if 1883 in open_ports:
            vulns.extend(self.check_mqtt(target, 1883))
        return vulns

    # --- Low-level protocol checks ---

    def _snmp_get_request(self, target: str, port: int, community: str) -> bool:
        """Send SNMPv1 GET request for sysDescr.0 and check for valid response."""
        # Build SNMPv1 GET-Request for OID 1.3.6.1.2.1.1.1.0 (sysDescr)
        oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"  # sysDescr.0
        varbind = b"\x30" + bytes([len(oid) + 2]) + oid + b"\x05\x00"
        varbind_list = b"\x30" + bytes([len(varbind)]) + varbind

        # Request ID
        request_id = b"\x02\x01\x01"
        error_status = b"\x02\x01\x00"
        error_index = b"\x02\x01\x00"

        pdu_content = request_id + error_status + error_index + varbind_list
        pdu = b"\xa0" + bytes([len(pdu_content)]) + pdu_content

        # Community string
        comm_bytes = community.encode("ascii")
        comm_tlv = b"\x04" + bytes([len(comm_bytes)]) + comm_bytes

        # SNMP version (v1 = 0)
        version = b"\x02\x01\x00"

        message_content = version + comm_tlv + pdu
        message = b"\x30" + bytes([len(message_content)]) + message_content

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(message, (target, port))
            data, _ = sock.recvfrom(4096)
            sock.close()
            # Any response means the community string is valid
            return len(data) > 2 and data[0] == 0x30
        except (socket.timeout, OSError):
            return False

    def _ftp_check_anonymous(self, target: str, port: int) -> bool:
        """Check if FTP allows anonymous login."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            banner = sock.recv(1024)
            sock.sendall(b"USER anonymous\r\n")
            resp = sock.recv(1024)
            sock.sendall(b"PASS \r\n")
            resp = sock.recv(1024)
            sock.close()
            # 230 = Login successful
            return resp[:3] == b"230"
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """Grab service banner from a TCP port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            # Many services send a banner upon connection
            sock.settimeout(2.0)
            data = sock.recv(1024)
            sock.close()
            return data.decode("ascii", errors="replace").strip()
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _vnc_check_auth(self, target: str, port: int) -> Optional[str]:
        """Check VNC authentication type. Returns 'no_auth', 'open', or None."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            # RFB protocol version handshake
            version = sock.recv(12)
            if not version.startswith(b"RFB "):
                sock.close()
                return None
            # Send our version
            sock.sendall(b"RFB 003.008\n")
            # Get security types
            data = sock.recv(256)
            sock.close()
            if len(data) >= 2:
                num_types = data[0]
                if num_types > 0:
                    types = list(data[1:1 + num_types])
                    if 1 in types:  # Security type 1 = None (no auth)
                        return "no_auth"
                return "open"
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return None

    def _http_basic_auth_check(
        self, target: str, port: int, username: str, password: str
    ) -> bool:
        """Check HTTP basic auth with given credentials."""
        import base64
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Authorization: Basic {auth}\r\n"
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
            # 200 OK or 302/301 redirect (successful login often redirects)
            return " 200 " in resp_str[:50] or " 302 " in resp_str[:50]
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _mqtt_connect_no_auth(self, target: str, port: int) -> bool:
        """Attempt MQTT CONNECT without credentials."""
        # Build MQTT CONNECT packet (no username/password)
        client_id = b"otscan"
        # Variable header: Protocol name + level + flags + keep alive
        var_header = (
            b"\x00\x04MQTT"  # Protocol name
            b"\x04"  # Protocol level (3.1.1)
            b"\x02"  # Connect flags (clean session only)
            b"\x00\x3c"  # Keep alive (60s)
        )
        # Payload: client ID
        payload = struct.pack("!H", len(client_id)) + client_id
        remaining = var_header + payload
        # Fixed header: CONNECT (0x10) + remaining length
        packet = b"\x10" + bytes([len(remaining)]) + remaining

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            sock.sendall(packet)
            response = sock.recv(256)
            sock.close()
            # CONNACK: 0x20, length 2, session present flag, return code
            if len(response) >= 4 and response[0] == 0x20:
                return_code = response[3]
                return return_code == 0  # 0 = Connection Accepted
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return False
