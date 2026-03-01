"""Omron FINS (Factory Interface Network Service) scanner.

FINS is Omron's proprietary protocol for communication with CJ, CP, NJ,
and NX series PLCs. Runs on UDP/TCP port 9600.
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

# FINS command codes
FINS_CMD_CONTROLLER_DATA_READ = (0x05, 0x01)
FINS_CMD_CONTROLLER_STATUS_READ = (0x06, 0x01)


class FINSScanner(BaseProtocolScanner):
    """Scanner for Omron FINS protocol."""

    PROTOCOL_NAME = "FINS"
    DEFAULT_PORT = 9600
    DESCRIPTION = "Omron PLC communication protocol"

    @staticmethod
    def _build_fins_tcp_header(fins_frame: bytes) -> bytes:
        """Wrap a FINS frame in the TCP header used by FINS/TCP."""
        # FINS/TCP header: "FINS" magic + length + command + error code
        length = len(fins_frame) + 8
        return (
            b"FINS"
            + struct.pack("!I", length)
            + struct.pack("!I", 0x00000002)  # FINS command (send)
            + struct.pack("!I", 0x00000000)  # Error code
            + fins_frame
        )

    @staticmethod
    def _build_fins_node_address_request() -> bytes:
        """Build FINS/TCP node address resolution request (sent first)."""
        return (
            b"FINS"
            + struct.pack("!I", 12)  # Length
            + struct.pack("!I", 0x00000000)  # Command: node address request
            + struct.pack("!I", 0x00000000)  # Error code
        )

    @staticmethod
    def _build_fins_frame(
        dest_node: int,
        src_node: int,
        command_code: tuple[int, int],
        data: bytes = b"",
    ) -> bytes:
        """Build a FINS command frame."""
        # FINS header (10 bytes)
        header = struct.pack(
            "!BBBBBBBBBB",
            0x80,       # ICF: command, response required
            0x00,       # RSV
            0x02,       # GCT: max 2 bridge gateways
            0x00,       # DNA: destination network (local)
            dest_node,  # DA1: destination node
            0x00,       # DA2: destination unit
            0x00,       # SNA: source network (local)
            src_node,   # SA1: source node
            0x00,       # SA2: source unit
            0x00,       # SID: service ID
        )
        # Command code (2 bytes)
        cmd = struct.pack("!BB", command_code[0], command_code[1])
        return header + cmd + data

    @staticmethod
    def _build_controller_data_read(dest_node: int = 0, src_node: int = 0) -> bytes:
        """Build Controller Data Read command."""
        frame = FINSScanner._build_fins_frame(
            dest_node, src_node, FINS_CMD_CONTROLLER_DATA_READ
        )
        return FINSScanner._build_fins_tcp_header(frame)

    def _parse_node_address_response(self, data: bytes) -> dict:
        """Parse FINS/TCP node address resolution response."""
        info = {}
        if len(data) < 24 or data[0:4] != b"FINS":
            return info
        info["magic"] = True
        cmd = struct.unpack("!I", data[8:12])[0]
        error = struct.unpack("!I", data[12:16])[0]
        info["command"] = cmd
        info["error"] = error
        if cmd == 0x00000001 and len(data) >= 24:  # node address response
            info["client_node"] = struct.unpack("!I", data[16:20])[0]
            info["server_node"] = struct.unpack("!I", data[20:24])[0]
        return info

    def _parse_controller_data(self, data: bytes) -> dict:
        """Parse Controller Data Read response."""
        info = {}
        if len(data) < 16 or data[0:4] != b"FINS":
            return info

        # Skip FINS/TCP header (16 bytes), then FINS header (10 bytes), command (2 bytes)
        offset = 16 + 10 + 2
        if len(data) < offset + 2:
            return info

        # Response code
        resp_code = struct.unpack("!H", data[offset:offset + 2])[0]
        info["response_code"] = resp_code
        offset += 2

        if resp_code != 0x0000:
            return info

        # Controller data: model, version
        remaining = data[offset:]
        if len(remaining) >= 30:
            info["controller_model"] = remaining[0:20].decode("ascii", errors="replace").rstrip("\x00 ")
            info["controller_version"] = remaining[20:40].decode("ascii", errors="replace").rstrip("\x00 ") if len(remaining) >= 40 else ""

        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for FINS service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # First try FINS/TCP node address resolution
        request = self._build_fins_node_address_request()
        response = self._tcp_send_recv(target, port, request)

        if response and len(response) >= 16 and response[0:4] == b"FINS":
            result.raw_responses.append(response)
            result.is_open = True
        else:
            # Try UDP FINS (direct FINS frame without TCP header)
            fins_frame = self._build_fins_frame(
                0, 0, FINS_CMD_CONTROLLER_STATUS_READ
            )
            response = self._udp_send_recv(target, port, fins_frame)
            if response and len(response) >= 12:
                result.raw_responses.append(response)
                # Check for FINS response header
                if response[0] == 0xC0 or response[0] == 0xC1:
                    result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify Omron FINS device."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            vendor="Omron",
            device_type="PLC",
        )

        # Node address resolution first
        request = self._build_fins_node_address_request()
        response = self._tcp_send_recv(target, port, request)

        if response and len(response) >= 16 and response[0:4] == b"FINS":
            result.raw_responses.append(response)
            node_info = self._parse_node_address_response(response)
            device.metadata["node_info"] = node_info

            # Now try Controller Data Read
            src_node = node_info.get("client_node", 0)
            dest_node = node_info.get("server_node", 0)
            ctrl_request = self._build_controller_data_read(dest_node, src_node)
            ctrl_response = self._tcp_send_recv(target, port, ctrl_request)

            if ctrl_response:
                result.raw_responses.append(ctrl_response)
                ctrl_info = self._parse_controller_data(ctrl_response)
                if ctrl_info.get("controller_model"):
                    device.model = ctrl_info["controller_model"]
                    result.is_identified = True
                if ctrl_info.get("controller_version"):
                    device.firmware = ctrl_info["controller_version"]

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for FINS."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        result.vulnerabilities.append(
            Vulnerability(
                title="FINS protocol has no authentication",
                severity=Severity.CRITICAL,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "Omron FINS does not include any authentication mechanism. "
                    "An attacker can read/write PLC memory, change operating modes, "
                    "upload/download programs, and stop the CPU."
                ),
                remediation=(
                    "Use network segmentation and firewall rules to restrict "
                    "FINS access. Enable CIP Security where supported (NJ/NX series). "
                    "Deploy OT-aware IDS/IPS."
                ),
                cve="CVE-2019-18259",
            )
        )

        result.vulnerabilities.append(
            Vulnerability(
                title="FINS traffic is unencrypted",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "All FINS communications are in plaintext. Process data, "
                    "PLC programs, and memory contents can be intercepted."
                ),
                remediation="Use VPN or encrypted tunnels for FINS communications.",
            )
        )

        return result
