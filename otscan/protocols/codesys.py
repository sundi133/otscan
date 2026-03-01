"""CODESYS V3 runtime scanner.

CODESYS is the most widely used IEC 61131-3 PLC programming environment.
The runtime runs on 350+ device types from 100+ vendors. Port 2455 (TCP).
Known for numerous critical CVEs.
"""

from __future__ import annotations

import struct
from typing import Optional

from otscan.protocols.base import (
    BaseProtocolScanner,
    DeviceInfo,
    ScanResult,
    Severity,
    Vulnerability,
)


class CODESYSScanner(BaseProtocolScanner):
    """Scanner for CODESYS V3 runtime."""

    PROTOCOL_NAME = "CODESYS"
    DEFAULT_PORT = 2455
    DESCRIPTION = "CODESYS V3 PLC runtime (350+ device types)"

    @staticmethod
    def _build_discovery_request() -> bytes:
        """Build CODESYS V3 discovery/identification request.

        The CODESYS V3 protocol uses a proprietary binary format.
        This sends a minimal request to elicit a protocol response.
        """
        # CODESYS V3 block driver header
        magic = b"\xbb\xbb"  # CODESYS block driver magic
        # Service group 0x01 (Device Info), Service 0x01 (Get Device Info)
        header = struct.pack(
            "<HHIBBIH",
            0xBBBB,  # Magic
            0x0000,  # Protocol ID
            0x00000001,  # Session ID
            0x01,  # Service group: Device
            0x01,  # Service: GetDeviceInfo
            0x00000000,  # Tag
            0x0000,  # Data length
        )
        return header

    def _is_codesys_response(self, data: bytes) -> bool:
        """Check if response looks like CODESYS V3."""
        if not data or len(data) < 4:
            return False
        # Check for known CODESYS response patterns
        if data[0:2] == b"\xbb\xbb":
            return True
        # Some CODESYS versions respond with different header
        if len(data) >= 8:
            try:
                magic = struct.unpack("<H", data[0:2])[0]
                return magic == 0xBBBB
            except struct.error:
                pass
        return False

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for CODESYS runtime."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        request = self._build_discovery_request()
        response = self._tcp_send_recv(target, port, request)

        if response:
            result.raw_responses.append(response)
            if self._is_codesys_response(response):
                result.is_open = True
            elif len(response) >= 4:
                # Port is open and something responded
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify CODESYS device."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            device_type="CODESYS V3 PLC Runtime",
        )

        request = self._build_discovery_request()
        response = self._tcp_send_recv(target, port, request)

        if response and self._is_codesys_response(response):
            result.raw_responses.append(response)
            # Attempt to parse device info from response
            try:
                if len(response) > 20:
                    # Device name often follows the header
                    name_area = response[16:].split(b"\x00")[0]
                    if name_area and len(name_area) > 2:
                        device.model = name_area.decode("ascii", errors="replace")
                        result.is_identified = True
            except (IndexError, UnicodeDecodeError):
                pass

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for CODESYS."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        result.vulnerabilities.append(
            Vulnerability(
                title="CODESYS V3 runtime exposed",
                severity=Severity.CRITICAL,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "CODESYS V3 runtime is accessible. Multiple critical CVEs exist: "
                    "CVE-2021-29241 (heap buffer overflow, RCE), "
                    "CVE-2022-31806 (default credentials), "
                    "CVE-2023-37559 (DoS). CODESYS has been repeatedly "
                    "targeted by ICS malware."
                ),
                remediation=(
                    "Update CODESYS runtime to latest version. Enable online user "
                    "management (authentication). Use encrypted communications. "
                    "Restrict network access to port 2455."
                ),
                cve="CVE-2022-31806",
            )
        )

        result.vulnerabilities.append(
            Vulnerability(
                title="CODESYS V3 default credentials may be active",
                severity=Severity.CRITICAL,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "CODESYS V3 runtimes often ship with online user management "
                    "disabled (no authentication) or with default credentials. "
                    "This allows unauthenticated PLC programming access."
                ),
                remediation=(
                    "Enable CODESYS online user management. Set strong passwords. "
                    "Disable guest/anonymous access."
                ),
                cve="CVE-2022-31806",
            )
        )

        result.vulnerabilities.append(
            Vulnerability(
                title="CODESYS protocol lacks encryption",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "CODESYS V3 communications are unencrypted by default. "
                    "PLC programs, variable values, and credentials can be intercepted."
                ),
                remediation="Enable CODESYS encrypted communication in project settings.",
            )
        )

        return result
