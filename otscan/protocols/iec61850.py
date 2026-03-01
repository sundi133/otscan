"""IEC 61850 / MMS (Manufacturing Message Specification) scanner.

IEC 61850 is the international standard for substation automation in
electric utilities. It uses MMS over TCP port 102 (shared with ISO-on-TCP)
for client-server communication and GOOSE/SV for real-time data.
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

# TPKT
TPKT_VERSION = 0x03

# COTP
COTP_CR = 0xE0
COTP_CC = 0xD0
COTP_DT = 0xF0

# MMS / ASN.1 tags
MMS_INITIATE_REQUEST = 0xA8
MMS_INITIATE_RESPONSE = 0xA9
MMS_CONFIRMED_REQUEST = 0xA0
MMS_CONFIRMED_RESPONSE = 0xA1

# MMS service tags
MMS_GET_NAME_LIST = 0xA1
MMS_IDENTIFY = 0x82


class IEC61850Scanner(BaseProtocolScanner):
    """Scanner for IEC 61850 / MMS protocol."""

    PROTOCOL_NAME = "IEC 61850 (MMS)"
    DEFAULT_PORT = 102
    DESCRIPTION = "Substation automation standard (MMS-based)"

    @staticmethod
    def _build_tpkt(data: bytes) -> bytes:
        """Wrap data in TPKT header."""
        length = len(data) + 4
        return struct.pack("!BBH", TPKT_VERSION, 0x00, length) + data

    @staticmethod
    def _build_cotp_cr() -> bytes:
        """Build COTP Connection Request for MMS."""
        cotp = struct.pack("!BBHHB", 17, COTP_CR, 0x0000, 0x0001, 0x00)
        # Parameters for MMS
        cotp += b"\xC0\x01\x0A"  # TPDU size = 1024
        cotp += b"\xC1\x02\x00\x01"  # src-tsap
        cotp += b"\xC2\x02\x00\x01"  # dst-tsap
        return IEC61850Scanner._build_tpkt(cotp)

    @staticmethod
    def _build_mms_initiate() -> bytes:
        """Build MMS Initiate-Request PDU."""
        # Simplified MMS initiate request
        # ASN.1 BER encoded MMS-Initiate-RequestPDU
        mms_initiate = bytes([
            MMS_INITIATE_REQUEST, 0x23,  # tag + length
            0x80, 0x01, 0x01,  # localDetailCalling = 1
            0x81, 0x01, 0x01,  # proposedMaxServOutstandingCalling = 1
            0x82, 0x01, 0x01,  # proposedMaxServOutstandingCalled = 1
            0x83, 0x01, 0x01,  # proposedDataStructureNestingLevel = 1
            0xA4, 0x16,  # initRequestDetail
            0x80, 0x01, 0x01,  # proposedVersionNumber = 1
            0x81, 0x03, 0x05, 0xF1, 0x00,  # proposedParameterCBB
            0x82, 0x0C,  # servicesSupportedCalling
            0xEE, 0x1C, 0x00, 0x00, 0x04, 0x08,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ])

        cotp_dt = struct.pack("BBB", 0x02, COTP_DT, 0x80)
        return IEC61850Scanner._build_tpkt(cotp_dt + mms_initiate)

    @staticmethod
    def _build_mms_identify() -> bytes:
        """Build MMS Identify request."""
        # MMS confirmed-request with Identify service
        mms = bytes([
            MMS_CONFIRMED_REQUEST, 0x05,  # tag + length
            0x02, 0x01, 0x01,  # invokeID = 1
            MMS_IDENTIFY, 0x00,  # Identify service, no parameters
        ])
        cotp_dt = struct.pack("BBB", 0x02, COTP_DT, 0x80)
        return IEC61850Scanner._build_tpkt(cotp_dt + mms)

    def _parse_mms_identify_response(self, data: bytes) -> dict:
        """Parse MMS Identify response for vendor/model/revision."""
        info = {}
        # Find MMS confirmed-response
        for i in range(len(data) - 1):
            if data[i] == MMS_CONFIRMED_RESPONSE:
                offset = i + 2  # skip tag + length
                # Skip invokeID
                if offset + 2 < len(data) and data[offset] == 0x02:
                    id_len = data[offset + 1]
                    offset += 2 + id_len

                # Look for Identify response (context tag)
                if offset < len(data) and (data[offset] & 0xE0) == 0x80:
                    offset += 2  # skip tag + length

                    # vendorName (VisibleString)
                    if offset < len(data) and data[offset] == 0x1A:
                        offset += 1
                        vlen = data[offset] if offset < len(data) else 0
                        offset += 1
                        if offset + vlen <= len(data):
                            info["vendor_name"] = data[offset : offset + vlen].decode(
                                "ascii", errors="replace"
                            )
                            offset += vlen

                    # modelName (VisibleString)
                    if offset < len(data) and data[offset] == 0x1A:
                        offset += 1
                        mlen = data[offset] if offset < len(data) else 0
                        offset += 1
                        if offset + mlen <= len(data):
                            info["model_name"] = data[offset : offset + mlen].decode(
                                "ascii", errors="replace"
                            )
                            offset += mlen

                    # revision (VisibleString)
                    if offset < len(data) and data[offset] == 0x1A:
                        offset += 1
                        rlen = data[offset] if offset < len(data) else 0
                        offset += 1
                        if offset + rlen <= len(data):
                            info["revision"] = data[offset : offset + rlen].decode(
                                "ascii", errors="replace"
                            )

                break

        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for IEC 61850 / MMS service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        sock = self._tcp_connect(target, port)
        if not sock:
            return result

        try:
            # COTP Connection Request
            sock.sendall(self._build_cotp_cr())
            resp = sock.recv(4096)
            if not resp or len(resp) < 7:
                return result

            result.raw_responses.append(resp)

            if resp[0] != TPKT_VERSION:
                return result

            pdu_type = resp[5] & 0xF0
            if pdu_type != COTP_CC:
                return result

            # MMS Initiate Request
            sock.sendall(self._build_mms_initiate())
            resp = sock.recv(4096)
            if resp:
                result.raw_responses.append(resp)
                # Check for MMS Initiate Response
                for i in range(len(resp)):
                    if resp[i] == MMS_INITIATE_RESPONSE:
                        result.is_open = True
                        break

        except (OSError, ConnectionResetError):
            pass
        finally:
            sock.close()

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify IEC 61850 / MMS device details."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            device_type="IED (Intelligent Electronic Device)",
        )

        sock = self._tcp_connect(target, port)
        if not sock:
            result.device = device
            return result

        try:
            # COTP + MMS Initiate
            sock.sendall(self._build_cotp_cr())
            resp = sock.recv(4096)
            if not resp or (resp[5] & 0xF0) != COTP_CC:
                result.device = device
                return result

            sock.sendall(self._build_mms_initiate())
            resp = sock.recv(4096)
            if not resp:
                result.device = device
                return result

            # MMS Identify
            sock.sendall(self._build_mms_identify())
            resp = sock.recv(4096)
            if resp:
                result.raw_responses.append(resp)
                info = self._parse_mms_identify_response(resp)
                if info:
                    device.vendor = info.get("vendor_name", "Unknown")
                    device.model = info.get("model_name", "Unknown")
                    device.firmware = info.get("revision", "Unknown")
                    device.metadata["mms_identify"] = info
                    result.is_identified = True

        except (OSError, ConnectionResetError):
            pass
        finally:
            sock.close()

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for IEC 61850."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        result.vulnerabilities.append(
            Vulnerability(
                title="MMS lacks built-in authentication",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "MMS (ISO 9506) does not provide authentication. "
                    "IEC 62351 adds security but is not universally implemented."
                ),
                remediation=(
                    "Implement IEC 62351 Part 4 (MMS security profiles) for "
                    "authentication and encryption. Deploy network segmentation."
                ),
            )
        )

        result.vulnerabilities.append(
            Vulnerability(
                title="GOOSE/SV multicast traffic is unauthenticated",
                severity=Severity.CRITICAL,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "IEC 61850 GOOSE and Sampled Values use Layer 2 multicast "
                    "without authentication. Attackers on the same LAN can inject "
                    "false trip signals or measurement values."
                ),
                remediation=(
                    "Implement IEC 62351-6 for GOOSE/SV authentication. "
                    "Use physically isolated substation LANs."
                ),
            )
        )

        # Check MMS session establishment
        sock = self._tcp_connect(target, port)
        if sock:
            try:
                sock.sendall(self._build_cotp_cr())
                resp = sock.recv(4096)
                if resp and (resp[5] & 0xF0) == COTP_CC:
                    sock.sendall(self._build_mms_initiate())
                    resp = sock.recv(4096)
                    if resp:
                        for i in range(len(resp)):
                            if resp[i] == MMS_INITIATE_RESPONSE:
                                result.vulnerabilities.append(
                                    Vulnerability(
                                        title="Unauthenticated MMS session established",
                                        severity=Severity.HIGH,
                                        protocol=self.PROTOCOL_NAME,
                                        target=target,
                                        port=port,
                                        description=(
                                            "An MMS session was established without "
                                            "authentication. Full read/write access to "
                                            "IEC 61850 data model is possible."
                                        ),
                                        remediation=(
                                            "Enable IEC 62351 security profiles. "
                                            "Restrict MMS access via firewall."
                                        ),
                                    )
                                )
                                break
            except (OSError, ConnectionResetError):
                pass
            finally:
                sock.close()

        return result
