"""HART-IP protocol scanner.

HART-IP is the IP-based variant of the HART (Highway Addressable Remote
Transducer) protocol, used for field instrument communication in process
industries. Default TCP/UDP port 5094.
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

# HART-IP message types
HART_MSG_REQUEST = 0
HART_MSG_RESPONSE = 1
HART_MSG_PUBLISH = 2

# HART-IP frame types
HART_FRAME_STX = 0x02  # Master to field device
HART_FRAME_ACK = 0x06  # Field device to master

# HART command numbers
CMD_READ_UNIQUE_ID = 0
CMD_READ_PRIMARY_VARIABLE = 1
CMD_READ_CURRENT_AND_PERCENT = 2
CMD_READ_DYNAMIC_VARIABLES = 3
CMD_READ_TAG = 13
CMD_READ_LONG_TAG = 20
CMD_READ_DEVICE_VARIABLE = 33
CMD_READ_SUB_DEVICE_IDENTITY = 84


class HARTIPScanner(BaseProtocolScanner):
    """Scanner for HART-IP protocol."""

    PROTOCOL_NAME = "HART-IP"
    DEFAULT_PORT = 5094
    DESCRIPTION = "Highway Addressable Remote Transducer protocol over IP"

    @staticmethod
    def _build_hart_ip_header(
        msg_type: int = HART_MSG_REQUEST,
        msg_id: int = 1,
        status: int = 0,
        sequence: int = 0,
        payload: bytes = b"",
    ) -> bytes:
        """Build a HART-IP message header."""
        # HART-IP header: version(1) + msgType(1) + msgId(1) + status(1)
        #                + seqNumber(2) + byteCount(2)
        byte_count = 8 + len(payload)  # header size + payload
        header = struct.pack(
            "!BBBBHH",
            1,  # version
            msg_type,
            msg_id,
            status,
            sequence,
            byte_count,
        )
        return header + payload

    @staticmethod
    def _build_read_unique_id() -> bytes:
        """Build HART Command 0 (Read Unique Identifier) in HART-IP frame."""
        # HART PDU: delimiter + address + command + byte_count + [data] + checksum
        delimiter = HART_FRAME_STX
        # Short frame address (polling address 0)
        address = 0x80  # Primary master, address 0

        command = CMD_READ_UNIQUE_ID
        byte_count = 0  # No request data for cmd 0

        pdu = struct.pack("BBBB", delimiter, address, command, byte_count)
        # Checksum: XOR of all bytes
        checksum = 0
        for b in pdu:
            checksum ^= b
        pdu += struct.pack("B", checksum)

        return HARTIPScanner._build_hart_ip_header(
            msg_type=HART_MSG_REQUEST,
            msg_id=0,
            payload=pdu,
        )

    @staticmethod
    def _build_read_tag() -> bytes:
        """Build HART Command 13 (Read Tag) request."""
        delimiter = HART_FRAME_STX
        address = 0x80
        command = CMD_READ_TAG
        byte_count = 0

        pdu = struct.pack("BBBB", delimiter, address, command, byte_count)
        checksum = 0
        for b in pdu:
            checksum ^= b
        pdu += struct.pack("B", checksum)

        return HARTIPScanner._build_hart_ip_header(
            msg_type=HART_MSG_REQUEST,
            msg_id=1,
            payload=pdu,
        )

    def _parse_hart_response(self, data: bytes) -> dict:
        """Parse HART-IP response."""
        info = {}
        if len(data) < 8:
            return info

        # Parse HART-IP header
        parsed = self._safe_unpack("!BBBBHH", data, 0)
        if not parsed:
            return info

        version, msg_type, msg_id, status, sequence, byte_count = parsed
        info["version"] = version
        info["msg_type"] = msg_type
        info["status"] = status

        if msg_type != HART_MSG_RESPONSE:
            return info

        # Parse HART PDU in payload
        if len(data) < 13:  # header(8) + min PDU(5)
            return info

        pdu_offset = 8
        pdu = data[pdu_offset:]

        if len(pdu) < 5:
            return info

        delimiter = pdu[0]
        info["delimiter"] = delimiter

        # Parse response data based on frame type
        if delimiter == HART_FRAME_ACK:
            # Short frame response
            address = pdu[1]
            command = pdu[2]
            resp_code = pdu[3] if len(pdu) > 3 else 0
            resp_byte_count = pdu[4] if len(pdu) > 4 else 0

            info["address"] = address
            info["command"] = command
            info["response_code"] = resp_code

            # Parse Command 0 response data
            if command == CMD_READ_UNIQUE_ID and resp_byte_count >= 12 and len(pdu) > 4 + 12:
                resp_data = pdu[5 : 5 + resp_byte_count]
                if len(resp_data) >= 12:
                    info["expansion_code"] = resp_data[0]
                    info["manufacturer_id"] = (resp_data[1] & 0x3F)
                    info["device_type"] = resp_data[2]
                    info["num_preambles"] = resp_data[3]
                    info["universal_revision"] = resp_data[4]
                    info["device_revision"] = resp_data[5]
                    info["software_revision"] = resp_data[6]
                    info["hardware_revision"] = (resp_data[7] >> 3) & 0x1F
                    info["physical_signaling"] = resp_data[7] & 0x07
                    info["flags"] = resp_data[8]
                    info["device_id"] = struct.unpack("!I", b"\x00" + resp_data[9:12])[0]

        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for HART-IP service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # Try TCP first
        request = self._build_read_unique_id()
        response = self._tcp_send_recv(target, port, request)

        if response and len(response) >= 8:
            result.raw_responses.append(response)
            parsed = self._safe_unpack("!BBBBHH", response, 0)
            if parsed and parsed[0] == 1:  # HART-IP version 1
                result.is_open = True
                return result

        # Try UDP
        response = self._udp_send_recv(target, port, request)
        if response and len(response) >= 8:
            result.raw_responses.append(response)
            parsed = self._safe_unpack("!BBBBHH", response, 0)
            if parsed and parsed[0] == 1:
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify HART-IP device details."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            device_type="Field Instrument",
        )

        # Known HART manufacturer IDs
        manufacturer_map = {
            0: "Unknown",
            6: "Emerson (Rosemount)",
            14: "Honeywell",
            17: "Yokogawa",
            26: "ABB",
            36: "Endress+Hauser",
            38: "Siemens",
            42: "Krohne",
            58: "VEGA",
        }

        # Send Command 0 (Read Unique Identifier)
        request = self._build_read_unique_id()
        response = self._tcp_send_recv(target, port, request)
        if not response:
            response = self._udp_send_recv(target, port, request)

        if response:
            result.raw_responses.append(response)
            info = self._parse_hart_response(response)
            if info:
                device.metadata["hart_info"] = info
                mfr_id = info.get("manufacturer_id", 0)
                device.vendor = manufacturer_map.get(mfr_id, f"MfrID:{mfr_id}")
                device.firmware = str(info.get("software_revision", "Unknown"))
                device.serial = str(info.get("device_id", "Unknown"))
                device.metadata["device_revision"] = info.get("device_revision", 0)
                device.metadata["universal_revision"] = info.get("universal_revision", 0)
                result.is_identified = True

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for HART-IP."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        result.vulnerabilities.append(
            Vulnerability(
                title="HART-IP has no authentication",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "HART-IP does not include authentication. Any host that can "
                    "reach the HART-IP gateway can read process variables and "
                    "send configuration commands to field instruments."
                ),
                remediation=(
                    "Restrict HART-IP access via network segmentation. "
                    "Use HART-IP with TLS if supported by the gateway."
                ),
            )
        )

        result.vulnerabilities.append(
            Vulnerability(
                title="HART-IP traffic is unencrypted",
                severity=Severity.MEDIUM,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "HART-IP transmits process data and configuration in cleartext. "
                    "Measurement values, calibration data, and device configuration "
                    "are visible to network sniffers."
                ),
                remediation="Wrap HART-IP in TLS/VPN. Implement network segmentation.",
            )
        )

        return result
