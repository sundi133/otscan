"""EtherNet/IP (EtherNet/Industrial Protocol) scanner.

EtherNet/IP is a CIP-based industrial protocol used primarily by
Rockwell Automation/Allen-Bradley PLCs. Default TCP port 44818.
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

# EtherNet/IP encapsulation commands
CMD_NOP = 0x0000
CMD_LIST_SERVICES = 0x0004
CMD_LIST_IDENTITY = 0x0063
CMD_LIST_INTERFACES = 0x0064
CMD_REGISTER_SESSION = 0x0065
CMD_UNREGISTER_SESSION = 0x0066
CMD_SEND_RR_DATA = 0x006F
CMD_SEND_UNIT_DATA = 0x0070

# CIP item type IDs
ITEM_NULL = 0x0000
ITEM_LIST_IDENTITY = 0x000C
ITEM_LIST_SERVICES = 0x0100

# Known vendor IDs
VENDOR_MAP = {
    1: "Rockwell Automation",
    2: "Rockwell Automation (A-B)",
    9: "Schneider Electric",
    26: "Omron",
    40: "Molex",
    44: "Turck",
    47: "WAGO",
    49: "Phoenix Contact",
    283: "Anybus (HMS)",
    674: "Prosoft Technology",
    741: "ODVA",
}

# Known device types
DEVICE_TYPE_MAP = {
    0: "Generic Device",
    2: "AC Drive",
    3: "Motor Starter",
    4: "Discrete I/O",
    6: "Photoelectric Sensor",
    7: "PLC (Programmable Logic Controller)",
    12: "Communications Adapter",
    14: "PLC (Programmable Logic Controller)",
    22: "Safety Discrete I/O",
    43: "Generic Safety Device",
}


class EtherNetIPScanner(BaseProtocolScanner):
    """Scanner for EtherNet/IP protocol."""

    PROTOCOL_NAME = "EtherNet/IP"
    DEFAULT_PORT = 44818
    DESCRIPTION = "CIP-based industrial Ethernet protocol (Rockwell/Allen-Bradley)"

    @staticmethod
    def _build_encap_header(
        command: int,
        data: bytes = b"",
        session_handle: int = 0,
    ) -> bytes:
        """Build an EtherNet/IP encapsulation header."""
        return struct.pack(
            "<HHIIQI",
            command,
            len(data),
            session_handle,
            0,  # status
            0,  # sender context
            0,  # options
        ) + data

    @staticmethod
    def _build_list_identity() -> bytes:
        """Build a ListIdentity request."""
        return EtherNetIPScanner._build_encap_header(CMD_LIST_IDENTITY)

    @staticmethod
    def _build_list_services() -> bytes:
        """Build a ListServices request."""
        return EtherNetIPScanner._build_encap_header(CMD_LIST_SERVICES)

    @staticmethod
    def _build_list_interfaces() -> bytes:
        """Build a ListInterfaces request."""
        return EtherNetIPScanner._build_encap_header(CMD_LIST_INTERFACES)

    def _parse_list_identity(self, data: bytes) -> dict:
        """Parse ListIdentity response to extract device information."""
        info = {}
        if len(data) < 24:
            return info

        # Parse encapsulation header
        parsed = self._safe_unpack("<HH", data, 0)
        if not parsed or parsed[0] != CMD_LIST_IDENTITY:
            return info

        # Skip encap header (24 bytes)
        offset = 24

        # Item count
        if offset + 2 > len(data):
            return info
        item_count = struct.unpack("<H", data[offset : offset + 2])[0]
        offset += 2

        if item_count < 1:
            return info

        # Parse first item
        if offset + 4 > len(data):
            return info
        item_type, item_length = struct.unpack("<HH", data[offset : offset + 4])
        offset += 4

        if item_type != ITEM_LIST_IDENTITY:
            return info

        # CIP Identity object
        if offset + 26 > len(data):
            return info

        (
            encap_version,
            socket_family,
            socket_port,
            socket_addr,
            _zero1, _zero2,
            vendor_id,
            device_type,
            product_code,
            revision_major,
            revision_minor,
        ) = struct.unpack(">HHHI4xHHHHBB", data[offset : offset + 26])

        info["encap_version"] = encap_version
        info["vendor_id"] = vendor_id
        info["vendor_name"] = VENDOR_MAP.get(vendor_id, f"Unknown (ID:{vendor_id})")
        info["device_type_id"] = device_type
        info["device_type"] = DEVICE_TYPE_MAP.get(device_type, f"Unknown (Type:{device_type})")
        info["product_code"] = product_code
        info["revision"] = f"{revision_major}.{revision_minor}"

        offset += 26

        # Status and serial
        if offset + 6 <= len(data):
            status, serial = struct.unpack("<HI", data[offset : offset + 6])
            info["status"] = status
            info["serial_number"] = f"{serial:08X}"
            offset += 6

        # Product name (length-prefixed string)
        if offset + 1 <= len(data):
            name_len = data[offset]
            offset += 1
            if offset + name_len <= len(data):
                info["product_name"] = data[offset : offset + name_len].decode(
                    "ascii", errors="replace"
                )

        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for EtherNet/IP service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # ListIdentity works on both TCP and UDP
        request = self._build_list_identity()
        response = self._tcp_send_recv(target, port, request)

        if response and len(response) >= 24:
            result.raw_responses.append(response)
            parsed = self._safe_unpack("<HH", response, 0)
            if parsed and parsed[0] == CMD_LIST_IDENTITY:
                result.is_open = True
                return result

        # Try UDP as well (port 44818)
        response = self._udp_send_recv(target, port, request)
        if response and len(response) >= 24:
            result.raw_responses.append(response)
            parsed = self._safe_unpack("<HH", response, 0)
            if parsed and parsed[0] == CMD_LIST_IDENTITY:
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify EtherNet/IP device details."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            device_type="PLC/IO",
        )

        request = self._build_list_identity()
        response = self._tcp_send_recv(target, port, request)

        if not response:
            response = self._udp_send_recv(target, port, request)

        if response:
            result.raw_responses.append(response)
            info = self._parse_list_identity(response)
            if info:
                device.vendor = info.get("vendor_name", "Unknown")
                device.model = info.get("product_name", "Unknown")
                device.firmware = info.get("revision", "Unknown")
                device.serial = info.get("serial_number", "Unknown")
                device.device_type = info.get("device_type", "Unknown")
                device.metadata["enip_identity"] = info
                result.is_identified = True

        # Also try ListServices
        svc_request = self._build_list_services()
        svc_response = self._tcp_send_recv(target, port, svc_request)
        if svc_response:
            result.raw_responses.append(svc_response)
            device.metadata["supports_list_services"] = True

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for EtherNet/IP."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # Check: CIP has no authentication by default
        result.vulnerabilities.append(
            Vulnerability(
                title="EtherNet/IP CIP has no built-in authentication",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "CIP (Common Industrial Protocol) over EtherNet/IP does not "
                    "require authentication. Any device on the network can establish "
                    "a session and send CIP commands to PLCs."
                ),
                remediation=(
                    "Implement CIP Security (TLS/DTLS) if supported by the device. "
                    "Use network segmentation and EtherNet/IP-aware firewalls."
                ),
            )
        )

        # Check: Session registration without auth
        register_request = self._build_encap_header(
            CMD_REGISTER_SESSION,
            struct.pack("<IH", 1, 0),  # protocol version, options
        )
        response = self._tcp_send_recv(target, port, register_request)
        if response and len(response) >= 24:
            result.raw_responses.append(response)
            status = struct.unpack("<I", response[8:12])[0]
            if status == 0:
                session_handle = struct.unpack("<I", response[4:8])[0]
                result.vulnerabilities.append(
                    Vulnerability(
                        title="Unauthenticated session registration accepted",
                        severity=Severity.HIGH,
                        protocol=self.PROTOCOL_NAME,
                        target=target,
                        port=port,
                        description=(
                            "The EtherNet/IP device accepted a session registration "
                            "without any authentication. This allows full CIP access."
                        ),
                        remediation=(
                            "Enable CIP Security. Restrict session registration to "
                            "authorized IP addresses."
                        ),
                        metadata={"session_handle": session_handle},
                    )
                )

                # Clean up: unregister the session
                unreg = self._build_encap_header(
                    CMD_UNREGISTER_SESSION, session_handle=session_handle
                )
                self._tcp_send_recv(target, port, unreg)

        # Identity disclosure
        request = self._build_list_identity()
        response = self._tcp_send_recv(target, port, request)
        if response:
            info = self._parse_list_identity(response)
            if info.get("product_name") or info.get("serial_number"):
                result.vulnerabilities.append(
                    Vulnerability(
                        title="Device identity information disclosed",
                        severity=Severity.LOW,
                        protocol=self.PROTOCOL_NAME,
                        target=target,
                        port=port,
                        description=(
                            f"Device discloses: vendor={info.get('vendor_name')}, "
                            f"product={info.get('product_name')}, "
                            f"serial={info.get('serial_number')}, "
                            f"firmware={info.get('revision')}. "
                            "This aids reconnaissance."
                        ),
                        remediation="Restrict ListIdentity access if possible.",
                        metadata={"identity_info": info},
                    )
                )

        return result
