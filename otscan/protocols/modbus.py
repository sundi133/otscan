"""Modbus TCP protocol scanner.

Modbus TCP is one of the most widely used industrial protocols for SCADA/HMI
communication with PLCs and RTUs. It runs on TCP port 502 by default.
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

# Modbus function codes
FC_READ_COILS = 0x01
FC_READ_DISCRETE_INPUTS = 0x02
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS = 0x04
FC_WRITE_SINGLE_COIL = 0x05
FC_WRITE_SINGLE_REGISTER = 0x06
FC_READ_EXCEPTION_STATUS = 0x07
FC_DIAGNOSTICS = 0x08
FC_REPORT_SLAVE_ID = 0x11
FC_READ_DEVICE_ID = 0x2B

# Modbus exception codes
EXCEPTION_ILLEGAL_FUNCTION = 0x01
EXCEPTION_ILLEGAL_DATA_ADDRESS = 0x02

# Known Modbus device vendors by ID patterns
VENDOR_IDENTIFIERS = {
    "schneider": "Schneider Electric",
    "modicon": "Schneider Electric (Modicon)",
    "siemens": "Siemens",
    "abb": "ABB",
    "allen-bradley": "Rockwell Automation",
    "rockwell": "Rockwell Automation",
    "honeywell": "Honeywell",
    "ge": "GE",
    "emerson": "Emerson",
    "yokogawa": "Yokogawa",
    "mitsubishi": "Mitsubishi Electric",
    "omron": "Omron",
    "beckhoff": "Beckhoff",
    "wago": "WAGO",
    "phoenix": "Phoenix Contact",
    "moxa": "Moxa",
    "advantech": "Advantech",
}


class ModbusScanner(BaseProtocolScanner):
    """Scanner for Modbus TCP protocol."""

    PROTOCOL_NAME = "Modbus TCP"
    DEFAULT_PORT = 502
    DESCRIPTION = "Industrial SCADA protocol for PLC/RTU communication"

    @staticmethod
    def _build_mbap(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
        """Build a Modbus Application Protocol header + PDU."""
        length = len(pdu) + 1  # PDU + unit ID
        return struct.pack(">HHHB", transaction_id, 0, length, unit_id) + pdu

    @staticmethod
    def _build_read_device_id_request(unit_id: int = 0) -> bytes:
        """Build MEI Read Device Identification request (FC 0x2B)."""
        # FC 0x2B, MEI type 0x0E, Read Device ID code 0x01, Object ID 0x00
        pdu = struct.pack("BBBB", FC_READ_DEVICE_ID, 0x0E, 0x01, 0x00)
        return ModbusScanner._build_mbap(1, unit_id, pdu)

    @staticmethod
    def _build_report_slave_id_request(unit_id: int = 0) -> bytes:
        """Build Report Slave ID request (FC 0x11)."""
        pdu = struct.pack("B", FC_REPORT_SLAVE_ID)
        return ModbusScanner._build_mbap(2, unit_id, pdu)

    @staticmethod
    def _build_read_holding_registers(
        unit_id: int, start: int, count: int
    ) -> bytes:
        """Build Read Holding Registers request (FC 0x03)."""
        pdu = struct.pack(">BHH", FC_READ_HOLDING_REGISTERS, start, count)
        return ModbusScanner._build_mbap(3, unit_id, pdu)

    @staticmethod
    def _build_diagnostics_request(unit_id: int = 0) -> bytes:
        """Build Diagnostics request (FC 0x08, sub 0x00 = Return Query Data)."""
        pdu = struct.pack(">BHH", FC_DIAGNOSTICS, 0x0000, 0x1234)
        return ModbusScanner._build_mbap(4, unit_id, pdu)

    def _parse_device_id_response(self, data: bytes) -> dict[str, str]:
        """Parse MEI Read Device Identification response."""
        info = {}
        if len(data) < 14:
            return info
        # Skip MBAP header (7) + FC (1) + MEI type (1) + Read Device ID code (1)
        offset = 10
        # conformity_level, more_follows, next_object_id, number_of_objects
        if len(data) < offset + 4:
            return info
        _conformity, _more, _next_obj, num_objects = struct.unpack(
            "BBBB", data[offset : offset + 4]
        )
        offset += 4

        object_names = {
            0x00: "vendor_name",
            0x01: "product_code",
            0x02: "major_minor_revision",
            0x03: "vendor_url",
            0x04: "product_name",
            0x05: "model_name",
            0x06: "user_application_name",
        }

        for _ in range(num_objects):
            if offset + 2 > len(data):
                break
            obj_id, obj_len = struct.unpack("BB", data[offset : offset + 2])
            offset += 2
            if offset + obj_len > len(data):
                break
            obj_value = data[offset : offset + obj_len].decode("ascii", errors="replace")
            offset += obj_len
            key = object_names.get(obj_id, f"object_{obj_id}")
            info[key] = obj_value

        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for Modbus TCP service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # Send a Read Holding Registers request (safe, read-only)
        request = self._build_read_holding_registers(0, 0, 1)
        response = self._tcp_send_recv(target, port, request)

        if response is None:
            return result

        result.raw_responses.append(response)

        # Check if this looks like a Modbus response
        if len(response) >= 9:
            # MBAP header: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
            parsed = self._safe_unpack(">HHH", response, 0)
            if parsed and parsed[1] == 0:  # protocol_id should be 0 for Modbus
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify Modbus device details."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target, port=port, protocol=self.PROTOCOL_NAME, device_type="PLC/RTU"
        )

        # Try Read Device Identification (FC 0x2B / MEI)
        request = self._build_read_device_id_request()
        response = self._tcp_send_recv(target, port, request)

        if response and len(response) > 9:
            result.raw_responses.append(response)
            # Check for exception response
            if len(response) >= 9 and not (response[7] & 0x80):
                info = self._parse_device_id_response(response)
                if info:
                    device.vendor = info.get("vendor_name", "Unknown")
                    device.model = info.get("product_name", info.get("model_name", "Unknown"))
                    device.firmware = info.get("major_minor_revision", "Unknown")
                    device.description = info.get("product_code", "")
                    device.metadata["device_id_info"] = info
                    result.is_identified = True

        # Also try Report Slave ID (FC 0x11)
        request = self._build_report_slave_id_request()
        response = self._tcp_send_recv(target, port, request)

        if response and len(response) > 9:
            result.raw_responses.append(response)
            if not (response[7] & 0x80):
                # Parse slave ID response
                if len(response) > 10:
                    byte_count = response[8]
                    slave_data = response[9 : 9 + byte_count]
                    device.metadata["slave_id_raw"] = slave_data.hex()
                    if slave_data:
                        device.metadata["slave_id"] = slave_data[0]
                        device.metadata["run_status"] = (
                            "Running" if len(slave_data) > 1 and slave_data[1] == 0xFF else "Idle"
                        )

        # Try to match vendor from any string data
        if device.vendor == "Unknown":
            all_text = " ".join(
                str(v) for v in device.metadata.values() if isinstance(v, str)
            ).lower()
            for key, vendor in VENDOR_IDENTIFIERS.items():
                if key in all_text:
                    device.vendor = vendor
                    break

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for Modbus TCP."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # Check: No authentication (Modbus has no built-in auth)
        result.vulnerabilities.append(
            Vulnerability(
                title="Modbus TCP has no authentication",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "Modbus TCP does not include any authentication mechanism. "
                    "Any host that can reach this port can read/write registers and coils."
                ),
                remediation=(
                    "Implement network segmentation, use a Modbus-aware firewall or IDS, "
                    "or deploy a Modbus TCP security proxy."
                ),
            )
        )

        # Check: No encryption
        result.vulnerabilities.append(
            Vulnerability(
                title="Modbus TCP traffic is unencrypted",
                severity=Severity.MEDIUM,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "Modbus TCP transmits all data in cleartext. Register values, "
                    "coil states, and commands are visible to network sniffers."
                ),
                remediation="Use VPN or TLS-wrapping for Modbus TCP communication.",
            )
        )

        # Check: Write access (only in ACTIVE mode)
        # In SAFE mode we only do read-only checks
        # Check if function codes that should be restricted are accessible
        diag_request = self._build_diagnostics_request()
        diag_response = self._tcp_send_recv(target, port, diag_request)

        if diag_response and len(diag_response) >= 9:
            result.raw_responses.append(diag_response)
            if not (diag_response[7] & 0x80):
                result.vulnerabilities.append(
                    Vulnerability(
                        title="Diagnostics function code accessible",
                        severity=Severity.MEDIUM,
                        protocol=self.PROTOCOL_NAME,
                        target=target,
                        port=port,
                        description=(
                            "Modbus diagnostics function (FC 0x08) is accessible. "
                            "This can be used to restart the device or clear counters."
                        ),
                        remediation="Restrict diagnostics function codes via firewall rules.",
                    )
                )

        # Check for common unit IDs responding
        responding_units = []
        for unit_id in [0, 1, 2, 247, 255]:
            request = self._build_read_holding_registers(unit_id, 0, 1)
            response = self._tcp_send_recv(target, port, request)
            if response and len(response) >= 9 and not (response[7] & 0x80):
                responding_units.append(unit_id)

        if len(responding_units) > 2:
            result.vulnerabilities.append(
                Vulnerability(
                    title="Multiple Modbus unit IDs respond",
                    severity=Severity.LOW,
                    protocol=self.PROTOCOL_NAME,
                    target=target,
                    port=port,
                    description=(
                        f"Multiple unit IDs respond on this device: {responding_units}. "
                        "This may indicate a gateway or misconfigured device."
                    ),
                    remediation="Restrict accessible unit IDs to only those required.",
                    metadata={"responding_units": responding_units},
                )
            )

        return result
