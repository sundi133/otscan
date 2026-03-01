"""Siemens S7comm protocol scanner.

S7comm is the proprietary protocol used by Siemens SIMATIC S7 PLCs
(S7-300, S7-400, S7-1200, S7-1500). It runs over ISO-on-TCP (RFC 1006)
on TCP port 102.
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

# TPKT header
TPKT_VERSION = 0x03
TPKT_RESERVED = 0x00

# COTP (ISO 8073)
COTP_CR = 0xE0  # Connection Request
COTP_CC = 0xD0  # Connection Confirm
COTP_DT = 0xF0  # Data Transfer

# S7comm constants
S7_PROTOCOL_ID = 0x32
S7_JOB = 0x01
S7_ACK_DATA = 0x03

# S7comm function codes
S7_FUNC_READ_SZL = 0x04  # Read System Status List
S7_FUNC_SETUP_COMM = 0xF0

# S7 module identification SZL IDs
SZL_MODULE_ID = 0x0011
SZL_COMPONENT_ID = 0x001C

# Siemens PLC types by order code prefix
PLC_TYPES = {
    "6ES7 211": "S7-1200 CPU 1211C",
    "6ES7 212": "S7-1200 CPU 1212C",
    "6ES7 214": "S7-1200 CPU 1214C",
    "6ES7 215": "S7-1200 CPU 1215C",
    "6ES7 217": "S7-1200 CPU 1217C",
    "6ES7 315": "S7-300 CPU 315",
    "6ES7 317": "S7-300 CPU 317",
    "6ES7 318": "S7-300 CPU 318",
    "6ES7 412": "S7-400 CPU 412",
    "6ES7 414": "S7-400 CPU 414",
    "6ES7 416": "S7-400 CPU 416",
    "6ES7 417": "S7-400 CPU 417",
    "6ES7 510": "S7-1500 CPU 1510SP",
    "6ES7 511": "S7-1500 CPU 1511",
    "6ES7 512": "S7-1500 CPU 1512SP",
    "6ES7 513": "S7-1500 CPU 1513",
    "6ES7 515": "S7-1500 CPU 1515",
    "6ES7 516": "S7-1500 CPU 1516",
    "6ES7 517": "S7-1500 CPU 1517",
    "6ES7 518": "S7-1500 CPU 1518",
}


class S7CommScanner(BaseProtocolScanner):
    """Scanner for Siemens S7comm protocol."""

    PROTOCOL_NAME = "S7comm"
    DEFAULT_PORT = 102
    DESCRIPTION = "Siemens SIMATIC S7 PLC communication protocol"

    @staticmethod
    def _build_tpkt(data: bytes) -> bytes:
        """Wrap data in a TPKT header."""
        length = len(data) + 4
        return struct.pack("!BBH", TPKT_VERSION, TPKT_RESERVED, length) + data

    @staticmethod
    def _build_cotp_cr(src_ref: int = 0x0001, dst_ref: int = 0x0000) -> bytes:
        """Build a COTP Connection Request."""
        # Length, PDU type, dst_ref, src_ref, class/options
        cotp = struct.pack(
            "!BBHHB", 17, COTP_CR, dst_ref, src_ref, 0x00
        )
        # Parameters: src-tsap, dst-tsap, tpdu-size
        cotp += b"\xC0\x01\x0A"  # TPDU size = 1024
        cotp += b"\xC1\x02\x01\x00"  # src-tsap
        cotp += b"\xC2\x02\x01\x02"  # dst-tsap (rack 0, slot 2)
        return S7CommScanner._build_tpkt(cotp)

    @staticmethod
    def _build_s7_setup_comm() -> bytes:
        """Build S7comm Setup Communication request."""
        # S7 header: protocol_id, msg_type, reserved, pdu_ref, param_len, data_len
        s7_param = struct.pack(
            "!BHHH",
            S7_FUNC_SETUP_COMM,
            0x0000,  # reserved
            1,  # max AmQ calling
            1,  # max AmQ called
        )
        s7_param += struct.pack("!H", 480)  # PDU length

        s7_header = struct.pack(
            "!BBHHH",
            S7_PROTOCOL_ID,
            S7_JOB,
            0x0000,  # reserved
            0x0100,  # PDU reference
            len(s7_param),
        )
        s7_header += struct.pack("!H", 0)  # data length

        cotp_dt = struct.pack("BBB", 0x02, COTP_DT, 0x80)  # last data unit
        return S7CommScanner._build_tpkt(cotp_dt + s7_header + s7_param)

    @staticmethod
    def _build_szl_request(szl_id: int, szl_index: int = 0x0000) -> bytes:
        """Build S7comm Read SZL (System Status List) request."""
        # Userdata parameter
        param = struct.pack("!BBB", 0x00, 0x01, 0x12)  # parameter head
        param += struct.pack("!BB", 0x04, 0x11)  # param length, method
        param += struct.pack("!BB", 0x44, 0x01)  # type (request), function group (SZL)
        param += struct.pack("!BB", 0x00, 0x00)  # subfunction, sequence

        data = struct.pack("!BB", 0xFF, 0x09)  # return code, transport size
        szl_data = struct.pack("!HH", szl_id, szl_index)
        data += struct.pack("!H", len(szl_data)) + szl_data

        s7_header = struct.pack(
            "!BBHHH",
            S7_PROTOCOL_ID,
            0x07,  # userdata
            0x0000,
            0x0200,
            len(param),
        )
        s7_header += struct.pack("!H", len(data))

        cotp_dt = struct.pack("BBB", 0x02, COTP_DT, 0x80)
        return S7CommScanner._build_tpkt(cotp_dt + s7_header + param + data)

    def _parse_szl_response(self, data: bytes) -> dict:
        """Parse SZL response for module identification."""
        info = {}
        if len(data) < 27:
            return info
        # Find S7 protocol header
        s7_offset = None
        for i in range(len(data) - 1):
            if data[i] == S7_PROTOCOL_ID:
                s7_offset = i
                break
        if s7_offset is None:
            return info

        # Skip to SZL data (variable offset depending on response)
        # Look for the SZL data after the S7 header
        offset = s7_offset + 12  # approximate offset past S7 header + param
        while offset < len(data) - 4:
            if data[offset] == 0xFF and data[offset + 1] == 0x09:
                offset += 4  # skip return code + transport size + length
                break
            offset += 1

        if offset + 4 > len(data):
            return info

        # SZL header: szl_id, szl_index
        if offset + 4 <= len(data):
            szl_id, szl_index = struct.unpack("!HH", data[offset : offset + 4])
            info["szl_id"] = szl_id
            offset += 4

        # SZL data length and count
        if offset + 4 <= len(data):
            szl_data_len, szl_count = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4

            # Parse SZL records
            for i in range(szl_count):
                if offset + szl_data_len > len(data):
                    break
                record = data[offset : offset + szl_data_len]
                # Index field
                if len(record) >= 2:
                    idx = struct.unpack("!H", record[0:2])[0]
                    text = record[2:].rstrip(b"\x00").decode("ascii", errors="replace").strip()
                    if idx == 0x0001:
                        info["order_code"] = text
                    elif idx == 0x0002:
                        info["module_type"] = text
                    elif idx == 0x0003:
                        info["serial_number"] = text
                    elif idx == 0x0004:
                        info["hardware_version"] = text
                    elif idx == 0x0005:
                        info["firmware_version"] = text
                    elif idx == 0x0007:
                        info["module_name"] = text
                offset += szl_data_len

        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for S7comm service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # Step 1: COTP Connection Request
        cotp_cr = self._build_cotp_cr()
        response = self._tcp_send_recv(target, port, cotp_cr)

        if response is None:
            return result

        result.raw_responses.append(response)

        # Check for COTP Connection Confirm
        if len(response) >= 7 and response[0] == TPKT_VERSION:
            pdu_type = response[5] & 0xF0
            if pdu_type == COTP_CC:
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify Siemens S7 PLC details."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            vendor="Siemens",
            device_type="PLC",
        )

        sock = self._tcp_connect(target, port)
        if not sock:
            result.device = device
            return result

        try:
            # Step 1: COTP Connection
            sock.sendall(self._build_cotp_cr())
            resp = sock.recv(4096)
            if not resp or len(resp) < 7 or (resp[5] & 0xF0) != COTP_CC:
                result.device = device
                return result
            result.raw_responses.append(resp)

            # Step 2: S7 Setup Communication
            sock.sendall(self._build_s7_setup_comm())
            resp = sock.recv(4096)
            if resp:
                result.raw_responses.append(resp)

            # Step 3: Read SZL - Module Identification
            sock.sendall(self._build_szl_request(SZL_MODULE_ID))
            resp = sock.recv(4096)
            if resp:
                result.raw_responses.append(resp)
                info = self._parse_szl_response(resp)
                if info:
                    device.metadata["szl_info"] = info
                    order_code = info.get("order_code", "")
                    device.model = info.get("module_name", info.get("module_type", "Unknown"))
                    device.firmware = info.get("firmware_version", "Unknown")
                    device.serial = info.get("serial_number", "Unknown")
                    device.description = order_code

                    # Match PLC type from order code
                    for prefix, plc_type in PLC_TYPES.items():
                        if order_code.startswith(prefix):
                            device.model = plc_type
                            break

                    result.is_identified = True

            # Step 4: Read SZL - Component Identification
            sock.sendall(self._build_szl_request(SZL_COMPONENT_ID))
            resp = sock.recv(4096)
            if resp:
                result.raw_responses.append(resp)
                comp_info = self._parse_szl_response(resp)
                if comp_info:
                    device.metadata["component_info"] = comp_info

        except (OSError, ConnectionResetError):
            pass
        finally:
            sock.close()

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for S7comm."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # S7comm has no authentication in S7-300/400
        result.vulnerabilities.append(
            Vulnerability(
                title="S7comm protocol has no authentication",
                severity=Severity.CRITICAL,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "The classic S7comm protocol (S7-300/S7-400) has no authentication. "
                    "Any host that can reach TCP port 102 can read/write PLC memory, "
                    "upload/download programs, and change the PLC run state (RUN/STOP)."
                ),
                remediation=(
                    "Migrate to S7-1500 with S7comm-plus and enable access protection. "
                    "Implement network segmentation. Use Siemens CP firewalls."
                ),
                cve="CVE-2019-13945",
            )
        )

        # Check: Can we establish a full S7 session?
        sock = self._tcp_connect(target, port)
        if sock:
            try:
                sock.sendall(self._build_cotp_cr())
                resp = sock.recv(4096)
                if resp and len(resp) >= 7 and (resp[5] & 0xF0) == COTP_CC:
                    sock.sendall(self._build_s7_setup_comm())
                    resp = sock.recv(4096)
                    if resp:
                        # Check if S7 setup was successful
                        for i in range(len(resp)):
                            if resp[i] == S7_PROTOCOL_ID and i + 1 < len(resp):
                                if resp[i + 1] == S7_ACK_DATA:
                                    result.vulnerabilities.append(
                                        Vulnerability(
                                            title="Unauthenticated S7 session established",
                                            severity=Severity.CRITICAL,
                                            protocol=self.PROTOCOL_NAME,
                                            target=target,
                                            port=port,
                                            description=(
                                                "Successfully established an S7comm session "
                                                "without any authentication. Full PLC access "
                                                "is possible."
                                            ),
                                            remediation=(
                                                "Enable access protection on the PLC. "
                                                "Use hardware DIP switches to restrict access."
                                            ),
                                        )
                                    )
                                break
            except (OSError, ConnectionResetError):
                pass
            finally:
                sock.close()

        # Check: SZL information disclosure
        result.vulnerabilities.append(
            Vulnerability(
                title="S7 System Status List (SZL) reveals device details",
                severity=Severity.MEDIUM,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "The SZL can be read without authentication, revealing module type, "
                    "order number, serial number, firmware version, and hardware details."
                ),
                remediation="Restrict access to SZL reads via protection level settings.",
            )
        )

        return result
