"""IEC 60870-5-104 protocol scanner.

IEC 104 is the TCP/IP adaptation of IEC 101, widely used in power grid
SCADA for telecontrol between control centers and substations.
Runs on TCP port 2404.
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

# IEC 104 APCI frame types
STARTDT_ACT = 0x07  # Start data transfer activation
STARTDT_CON = 0x0B  # Start data transfer confirmation
STOPDT_ACT = 0x13
TESTFR_ACT = 0x43
TESTFR_CON = 0x83


class IEC104Scanner(BaseProtocolScanner):
    """Scanner for IEC 60870-5-104 protocol."""

    PROTOCOL_NAME = "IEC 60870-5-104"
    DEFAULT_PORT = 2404
    DESCRIPTION = "Power grid telecontrol (substations, RTUs)"

    @staticmethod
    def _build_u_frame(control: int) -> bytes:
        """Build an IEC 104 U-format APCI frame."""
        # APCI: Start byte (0x68), APDU length (4), control fields
        return struct.pack("!BBBBB", 0x68, 0x04, control, 0x00, 0x00) + b"\x00"

    @staticmethod
    def _build_startdt_act() -> bytes:
        """Build STARTDT ACT frame."""
        return bytes([0x68, 0x04, STARTDT_ACT, 0x00, 0x00, 0x00])

    @staticmethod
    def _build_testfr_act() -> bytes:
        """Build TESTFR ACT frame."""
        return bytes([0x68, 0x04, TESTFR_ACT, 0x00, 0x00, 0x00])

    def _is_iec104_response(self, data: bytes) -> bool:
        """Check if data looks like an IEC 104 response."""
        if not data or len(data) < 6:
            return False
        return data[0] == 0x68  # IEC 104 start byte

    def _parse_response(self, data: bytes) -> dict:
        """Parse IEC 104 APCI frame."""
        info = {}
        if len(data) < 6 or data[0] != 0x68:
            return info
        info["start_byte"] = data[0]
        info["apdu_length"] = data[1]
        control_byte1 = data[2]
        # Determine frame type
        if control_byte1 & 0x01 == 0:
            info["frame_type"] = "I-format"
        elif control_byte1 & 0x03 == 0x01:
            info["frame_type"] = "S-format"
        else:
            info["frame_type"] = "U-format"
            if control_byte1 == STARTDT_CON:
                info["u_type"] = "STARTDT_CON"
            elif control_byte1 == TESTFR_CON:
                info["u_type"] = "TESTFR_CON"
        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for IEC 104 service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # Send TESTFR ACT - safest probe, should get TESTFR CON back
        frame = self._build_testfr_act()
        response = self._tcp_send_recv(target, port, frame)

        if response and self._is_iec104_response(response):
            result.raw_responses.append(response)
            result.is_open = True
        elif self._check_port_open(target, port):
            # Port is open but didn't respond to TESTFR - try STARTDT
            frame = self._build_startdt_act()
            response = self._tcp_send_recv(target, port, frame)
            if response and self._is_iec104_response(response):
                result.raw_responses.append(response)
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify IEC 104 device."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            device_type="IEC 104 RTU/Gateway",
        )

        frame = self._build_testfr_act()
        response = self._tcp_send_recv(target, port, frame)
        if response and self._is_iec104_response(response):
            result.raw_responses.append(response)
            info = self._parse_response(response)
            device.metadata["iec104_info"] = info
            if info.get("u_type") == "TESTFR_CON":
                device.description = "Responds to TESTFR (active station)"
                result.is_identified = True

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for IEC 104."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        result.vulnerabilities.append(
            Vulnerability(
                title="IEC 104 has no built-in authentication",
                severity=Severity.CRITICAL,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "IEC 60870-5-104 does not include authentication or encryption. "
                    "An attacker can establish a connection and send control commands "
                    "(switching, setpoints) to substations and RTUs."
                ),
                remediation=(
                    "Implement IEC 62351 for authentication and TLS encryption. "
                    "Use firewall rules and network segmentation. "
                    "Deploy IDS with IEC 104 deep packet inspection."
                ),
            )
        )

        result.vulnerabilities.append(
            Vulnerability(
                title="IEC 104 traffic is unencrypted",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "All IEC 104 communications are in plaintext, including "
                    "process values, control commands, and interrogation data."
                ),
                remediation=(
                    "Deploy TLS tunneling (IEC 62351-3). Use VPN between "
                    "control center and substations."
                ),
            )
        )

        # Try STARTDT to see if we can establish a data transfer session
        frame = self._build_startdt_act()
        response = self._tcp_send_recv(target, port, frame)
        if response and self._is_iec104_response(response):
            info = self._parse_response(response)
            if info.get("u_type") == "STARTDT_CON":
                result.vulnerabilities.append(
                    Vulnerability(
                        title="IEC 104 accepts unauthenticated STARTDT",
                        severity=Severity.CRITICAL,
                        protocol=self.PROTOCOL_NAME,
                        target=target,
                        port=port,
                        description=(
                            "Station accepted STARTDT activation without authentication. "
                            "An attacker can initiate data transfer and send control "
                            "commands to power grid equipment."
                        ),
                        remediation="Implement connection whitelisting and IEC 62351 authentication.",
                    )
                )

        return result
