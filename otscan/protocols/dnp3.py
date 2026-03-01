"""DNP3 (Distributed Network Protocol 3) scanner.

DNP3 is widely used in electric utility SCADA systems, water treatment,
and oil & gas. It runs on TCP port 20000 by default.
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

# DNP3 data link layer constants
DNP3_START_BYTES = b"\x05\x64"
DNP3_DIR_MASTER = 0x80
DNP3_DIR_OUTSTATION = 0x00
DNP3_PRM_MASTER = 0x40
DNP3_FCV = 0x10
DNP3_FCB = 0x20

# DNP3 function codes
FC_CONFIRM = 0x00
FC_READ = 0x01
FC_WRITE = 0x02
FC_COLD_RESTART = 0x0D
FC_WARM_RESTART = 0x0E
FC_RESPONSE = 0x81
FC_UNSOLICITED = 0x82


def _crc16_dnp3(data: bytes) -> int:
    """Calculate DNP3 CRC-16."""
    crc = 0x0000
    poly = 0xA6BC
    for byte in data:
        temp = crc ^ byte
        for _ in range(8):
            if temp & 0x0001:
                temp = (temp >> 1) ^ poly
            else:
                temp >>= 1
        crc = temp
    return ~crc & 0xFFFF


class DNP3Scanner(BaseProtocolScanner):
    """Scanner for DNP3 protocol."""

    PROTOCOL_NAME = "DNP3"
    DEFAULT_PORT = 20000
    DESCRIPTION = "Distributed Network Protocol for SCADA/utility systems"

    @staticmethod
    def _build_data_link_frame(
        destination: int,
        source: int,
        func_code: int,
        direction: int = DNP3_DIR_MASTER,
        prm: int = DNP3_PRM_MASTER,
    ) -> bytes:
        """Build a DNP3 data link layer frame."""
        control = direction | prm | func_code
        # Header: start(2) + length(1) + control(1) + dest(2) + src(2)
        header = struct.pack("<2sBBHH", DNP3_START_BYTES, 5, control, destination, source)
        crc = _crc16_dnp3(header[2:])  # CRC over length..source
        return header + struct.pack("<H", crc)

    @staticmethod
    def _build_read_request(destination: int = 1, source: int = 3) -> bytes:
        """Build a DNP3 read request for class 0 data."""
        # Transport header: FIN=1, FIR=1, SEQ=0
        transport = 0xC0
        # Application layer: FC=READ, control=0xC0 (FIR+FIN)
        app_control = 0xC0  # FIR + FIN
        app_data = struct.pack("BB", app_control, FC_READ)
        # Object header: Group 60, Var 1, qualifier 0x06 (all)
        app_data += struct.pack("BBB", 60, 1, 0x06)

        payload = struct.pack("B", transport) + app_data

        # Build data link frame
        length = len(payload) + 5  # CRC blocks not counted in standard length field
        control = DNP3_DIR_MASTER | DNP3_PRM_MASTER | 0x04  # Unconfirmed user data
        header = struct.pack("<2sBBHH", DNP3_START_BYTES, length, control, destination, source)
        header_crc = _crc16_dnp3(header[2:])
        frame = header + struct.pack("<H", header_crc)

        # Add payload with CRC (16 bytes per block max)
        block = payload[:16]
        block_crc = _crc16_dnp3(block)
        frame += block + struct.pack("<H", block_crc)

        return frame

    def _is_dnp3_response(self, data: bytes) -> bool:
        """Check if data looks like a DNP3 response."""
        if len(data) < 10:
            return False
        return data[0:2] == DNP3_START_BYTES

    def _parse_dnp3_response(self, data: bytes) -> dict:
        """Parse basic DNP3 response fields."""
        info = {}
        if len(data) < 10:
            return info
        parsed = self._safe_unpack("<2sBBHH", data, 0)
        if not parsed:
            return info
        _, length, control, destination, source = parsed
        info["length"] = length
        info["control"] = control
        info["destination"] = destination
        info["source"] = source
        info["direction"] = "outstation" if not (control & 0x80) else "master"
        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for DNP3 service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # Send a DNP3 link status request
        frame = self._build_data_link_frame(
            destination=1, source=3, func_code=0x09  # Request Link Status
        )
        response = self._tcp_send_recv(target, port, frame)

        if response and self._is_dnp3_response(response):
            result.is_open = True
            result.raw_responses.append(response)
            return result

        # Also try a read request
        frame = self._build_read_request()
        response = self._tcp_send_recv(target, port, frame)

        if response and self._is_dnp3_response(response):
            result.is_open = True
            result.raw_responses.append(response)
        elif response:
            # Port is open but might not be DNP3 - still note it
            result.raw_responses.append(response)
            # Check if port is at least open
            if self._check_port_open(target, port):
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify DNP3 device details."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target, port=port, protocol=self.PROTOCOL_NAME, device_type="RTU/IED"
        )

        # Send read request and parse response
        frame = self._build_read_request()
        response = self._tcp_send_recv(target, port, frame)

        if response and self._is_dnp3_response(response):
            result.raw_responses.append(response)
            info = self._parse_dnp3_response(response)
            if info:
                device.metadata["dnp3_source_address"] = info.get("source", 0)
                device.metadata["dnp3_destination_address"] = info.get("destination", 0)
                device.metadata["direction"] = info.get("direction", "")
                result.is_identified = True

        # Try multiple DNP3 addresses to discover outstations
        discovered_addresses = []
        for addr in range(1, 11):  # Scan addresses 1-10
            frame = self._build_data_link_frame(
                destination=addr, source=3, func_code=0x09
            )
            response = self._tcp_send_recv(target, port, frame)
            if response and self._is_dnp3_response(response):
                discovered_addresses.append(addr)

        if discovered_addresses:
            device.metadata["responding_addresses"] = discovered_addresses

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for DNP3."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # Check: DNP3 Secure Authentication
        result.vulnerabilities.append(
            Vulnerability(
                title="DNP3 operates without Secure Authentication",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "Standard DNP3 has no authentication. DNP3 Secure Authentication "
                    "(SA v5) adds HMAC-based challenge-response, but many devices "
                    "do not support or enable it."
                ),
                remediation=(
                    "Enable DNP3 Secure Authentication v5 if supported. "
                    "Otherwise, implement network segmentation and monitoring."
                ),
            )
        )

        # Check: Unencrypted traffic
        result.vulnerabilities.append(
            Vulnerability(
                title="DNP3 traffic is unencrypted",
                severity=Severity.MEDIUM,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "DNP3 transmits all SCADA data in cleartext including "
                    "control commands and measurement data."
                ),
                remediation="Wrap DNP3 in TLS/VPN. Consider IEC 62351 for transport security.",
            )
        )

        # Check: Broadcast address accessible
        frame = self._build_data_link_frame(
            destination=0xFFFF, source=3, func_code=0x09  # Broadcast
        )
        response = self._tcp_send_recv(target, port, frame)
        if response and self._is_dnp3_response(response):
            result.raw_responses.append(response)
            result.vulnerabilities.append(
                Vulnerability(
                    title="DNP3 broadcast address responds",
                    severity=Severity.MEDIUM,
                    protocol=self.PROTOCOL_NAME,
                    target=target,
                    port=port,
                    description=(
                        "The device responds to DNP3 broadcast address (0xFFFF). "
                        "This could be used for denial-of-service attacks."
                    ),
                    remediation="Disable broadcast address handling if not required.",
                )
            )

        return result
