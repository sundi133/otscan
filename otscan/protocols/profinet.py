"""PROFINET scanner.

PROFINET is the industrial Ethernet standard by Siemens/PROFIBUS International.
It uses DCP (Discovery and Configuration Protocol) for device discovery
on UDP port 34964, and runs real-time IO on Layer 2.
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

# PROFINET DCP constants
DCP_SERVICE_ID_IDENTIFY = 0x05
DCP_SERVICE_TYPE_REQUEST = 0x00
DCP_SERVICE_TYPE_RESPONSE_SUCCESS = 0x01

# DCP block options
DCP_OPT_IP = 0x01
DCP_OPT_DEVICE = 0x02
DCP_OPT_DHCP = 0x03
DCP_OPT_CONTROL = 0x05

# DCP sub-options for Device
DCP_SUB_DEVICE_VENDOR = 0x01
DCP_SUB_DEVICE_NAME = 0x02
DCP_SUB_DEVICE_ID = 0x03
DCP_SUB_DEVICE_ROLE = 0x04
DCP_SUB_DEVICE_OPTIONS = 0x05
DCP_SUB_DEVICE_ALIAS = 0x06
DCP_SUB_DEVICE_INSTANCE = 0x07

# DCP sub-options for IP
DCP_SUB_IP_MAC = 0x01
DCP_SUB_IP_PARAMETER = 0x02

# PROFINET UDP port
PROFINET_DCP_PORT = 34964


class ProfinetScanner(BaseProtocolScanner):
    """Scanner for PROFINET DCP protocol."""

    PROTOCOL_NAME = "PROFINET"
    DEFAULT_PORT = 34964
    DESCRIPTION = "Industrial Ethernet standard by Siemens/PI"

    @staticmethod
    def _build_dcp_identify_all() -> bytes:
        """Build a PROFINET DCP Identify All request."""
        # DCP Header
        service_id = DCP_SERVICE_ID_IDENTIFY
        service_type = DCP_SERVICE_TYPE_REQUEST
        xid = 0x00000001
        response_delay = 0x0001  # 1 * 10ms

        # Block: Option=0xFF (all), SubOption=0xFF (all)
        block = struct.pack("!BBH", 0xFF, 0xFF, 0x0000)

        dcp_length = len(block)
        header = struct.pack(
            "!BBIHH",
            service_id,
            service_type,
            xid,
            response_delay,
            dcp_length,
        )

        return header + block

    def _parse_dcp_response(self, data: bytes) -> dict:
        """Parse PROFINET DCP response blocks."""
        info = {}
        if len(data) < 10:
            return info

        # Parse DCP header
        parsed = self._safe_unpack("!BBIHH", data, 0)
        if not parsed:
            return info

        service_id, service_type, xid, _resp_delay, dcp_length = parsed

        if service_type != DCP_SERVICE_TYPE_RESPONSE_SUCCESS:
            return info

        info["service_id"] = service_id
        info["xid"] = xid

        # Parse DCP blocks
        offset = 10  # After header
        while offset + 4 <= len(data) and offset < 10 + dcp_length:
            option, sub_option, block_length = struct.unpack(
                "!BBH", data[offset : offset + 4]
            )
            offset += 4

            if block_length == 0 or offset + block_length > len(data):
                break

            block_data = data[offset : offset + block_length]

            if option == DCP_OPT_DEVICE:
                # Skip 2 bytes block info (block qualifier)
                bd = block_data[2:] if len(block_data) > 2 else block_data
                if sub_option == DCP_SUB_DEVICE_VENDOR:
                    info["vendor_name"] = bd.decode("ascii", errors="replace").rstrip("\x00")
                elif sub_option == DCP_SUB_DEVICE_NAME:
                    info["device_name"] = bd.decode("ascii", errors="replace").rstrip("\x00")
                elif sub_option == DCP_SUB_DEVICE_ID:
                    if len(bd) >= 4:
                        vendor_id, device_id = struct.unpack("!HH", bd[:4])
                        info["vendor_id"] = vendor_id
                        info["device_id"] = device_id
                elif sub_option == DCP_SUB_DEVICE_ROLE:
                    if len(bd) >= 1:
                        role = bd[0]
                        roles = []
                        if role & 0x01:
                            roles.append("IO-Device")
                        if role & 0x02:
                            roles.append("IO-Controller")
                        if role & 0x04:
                            roles.append("IO-Supervisor")
                        info["device_role"] = roles
                elif sub_option == DCP_SUB_DEVICE_INSTANCE:
                    if len(bd) >= 2:
                        info["device_instance_high"] = bd[0]
                        info["device_instance_low"] = bd[1]

            elif option == DCP_OPT_IP:
                bd = block_data[2:] if len(block_data) > 2 else block_data
                if sub_option == DCP_SUB_IP_PARAMETER and len(bd) >= 12:
                    ip_bytes = bd[0:4]
                    mask_bytes = bd[4:8]
                    gw_bytes = bd[8:12]
                    info["ip_address"] = ".".join(str(b) for b in ip_bytes)
                    info["subnet_mask"] = ".".join(str(b) for b in mask_bytes)
                    info["gateway"] = ".".join(str(b) for b in gw_bytes)

            # Align to even boundary
            offset += block_length
            if block_length % 2:
                offset += 1

        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for PROFINET DCP service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        request = self._build_dcp_identify_all()
        response = self._udp_send_recv(target, port, request)

        if response and len(response) >= 10:
            result.raw_responses.append(response)
            parsed = self._safe_unpack("!BB", response, 0)
            if parsed and parsed[0] == DCP_SERVICE_ID_IDENTIFY:
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify PROFINET device details."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            device_type="PROFINET Device",
        )

        request = self._build_dcp_identify_all()
        response = self._udp_send_recv(target, port, request)

        if response:
            result.raw_responses.append(response)
            info = self._parse_dcp_response(response)
            if info:
                device.vendor = info.get("vendor_name", "Unknown")
                device.model = info.get("device_name", "Unknown")
                device.metadata["profinet_info"] = info

                roles = info.get("device_role", [])
                if roles:
                    device.device_type = " / ".join(roles)

                result.is_identified = True

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for PROFINET."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        result.vulnerabilities.append(
            Vulnerability(
                title="PROFINET DCP has no authentication",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "PROFINET DCP does not include authentication. Attackers can "
                    "discover, reconfigure IP settings, and rename devices on the "
                    "network without credentials."
                ),
                remediation=(
                    "Implement PROFINET Security Class 1 (DCP-Set filtering) or "
                    "Class 2+ (TLS/DTLS). Use managed switches with port security."
                ),
            )
        )

        result.vulnerabilities.append(
            Vulnerability(
                title="PROFINET RT/IRT uses Layer 2 without encryption",
                severity=Severity.MEDIUM,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "PROFINET Real-Time (RT) and Isochronous Real-Time (IRT) "
                    "operate at Layer 2 without encryption or authentication. "
                    "Process data is exposed to network-level attackers."
                ),
                remediation=(
                    "Implement PROFINET Security (IEEE 802.1AE MACsec). "
                    "Use physically isolated PROFINET networks."
                ),
            )
        )

        # Check DCP discovery response
        request = self._build_dcp_identify_all()
        response = self._udp_send_recv(target, port, request)
        if response and len(response) >= 10:
            info = self._parse_dcp_response(response)
            if info:
                result.vulnerabilities.append(
                    Vulnerability(
                        title="PROFINET device discloses configuration via DCP",
                        severity=Severity.LOW,
                        protocol=self.PROTOCOL_NAME,
                        target=target,
                        port=port,
                        description=(
                            f"Device discloses: name={info.get('device_name')}, "
                            f"vendor={info.get('vendor_name')}, "
                            f"IP={info.get('ip_address')}, "
                            f"role={info.get('device_role')}."
                        ),
                        remediation="Restrict DCP to required operations only.",
                        metadata={"dcp_info": info},
                    )
                )

        return result
