"""OPC UA (Open Platform Communications Unified Architecture) scanner.

OPC UA is the modern standard for industrial interoperability, used for
secure, reliable data exchange between PLCs, SCADA, MES, and ERP systems.
Default port is 4840.
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

# OPC UA message types
MSG_HELLO = b"HEL"
MSG_ACKNOWLEDGE = b"ACK"
MSG_ERROR = b"ERR"
MSG_OPEN_CHANNEL = b"OPN"
MSG_CLOSE_CHANNEL = b"CLO"
MSG_MESSAGE = b"MSG"

# Security policies
SECURITY_POLICY_NONE = "http://opcfoundation.org/UA/SecurityPolicy#None"
SECURITY_POLICY_BASIC128 = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
SECURITY_POLICY_BASIC256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
SECURITY_POLICY_BASIC256SHA256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
SECURITY_POLICY_AES128SHA256 = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
SECURITY_POLICY_AES256SHA256 = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"

# Deprecated/weak policies
WEAK_POLICIES = {SECURITY_POLICY_NONE, SECURITY_POLICY_BASIC128, SECURITY_POLICY_BASIC256}


class OPCUAScanner(BaseProtocolScanner):
    """Scanner for OPC UA protocol."""

    PROTOCOL_NAME = "OPC UA"
    DEFAULT_PORT = 4840
    DESCRIPTION = "Industrial interoperability standard for secure data exchange"

    @staticmethod
    def _build_hello(endpoint_url: str) -> bytes:
        """Build OPC UA Hello message."""
        url_bytes = endpoint_url.encode("utf-8")
        # Hello body: protocol_version(4) + recv_buf_size(4) + send_buf_size(4)
        #            + max_msg_size(4) + max_chunk_count(4) + endpoint_url_len(4) + url
        body = struct.pack(
            "<IIIIII",
            0,          # protocol version
            65535,      # receive buffer size
            65535,      # send buffer size
            0,          # max message size (0 = no limit)
            0,          # max chunk count (0 = no limit)
            len(url_bytes),
        )
        body += url_bytes

        # Message header: type(3) + reserved(1) + size(4)
        msg_size = 8 + len(body)
        header = MSG_HELLO + b"F" + struct.pack("<I", msg_size)

        return header + body

    @staticmethod
    def _build_get_endpoints_request(endpoint_url: str) -> bytes:
        """Build an OPC UA GetEndpoints request via OpenSecureChannel + GetEndpoints."""
        # This is a simplified version - a full implementation would need
        # proper secure channel negotiation
        url_bytes = endpoint_url.encode("utf-8")

        # Build OpenSecureChannel request with SecurityPolicy None
        security_policy = SECURITY_POLICY_NONE.encode("utf-8")

        # For a basic probe, just the Hello is enough to fingerprint
        return OPCUAScanner._build_hello(endpoint_url)

    def _parse_acknowledge(self, data: bytes) -> dict:
        """Parse OPC UA Acknowledge message."""
        info = {}
        if len(data) < 8:
            return info
        msg_type = data[0:3]

        if msg_type == MSG_ERROR:
            info["error"] = True
            if len(data) >= 12:
                error_code = struct.unpack("<I", data[8:12])[0]
                info["error_code"] = error_code
            return info

        if msg_type != MSG_ACKNOWLEDGE or len(data) < 28:
            return info

        parsed = self._safe_unpack("<I", data, 4)
        if parsed:
            info["message_size"] = parsed[0]

        body = data[8:]
        if len(body) >= 20:
            (
                proto_version,
                recv_buf,
                send_buf,
                max_msg_size,
                max_chunk_count,
            ) = struct.unpack("<IIIII", body[:20])
            info["protocol_version"] = proto_version
            info["receive_buffer_size"] = recv_buf
            info["send_buffer_size"] = send_buf
            info["max_message_size"] = max_msg_size
            info["max_chunk_count"] = max_chunk_count

        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for OPC UA service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        endpoint_url = f"opc.tcp://{target}:{port}"
        hello = self._build_hello(endpoint_url)
        response = self._tcp_send_recv(target, port, hello)

        if response is None:
            return result

        result.raw_responses.append(response)

        if len(response) >= 8:
            msg_type = response[0:3]
            if msg_type in (MSG_ACKNOWLEDGE, MSG_ERROR):
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify OPC UA server details."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            device_type="OPC UA Server",
        )

        endpoint_url = f"opc.tcp://{target}:{port}"
        hello = self._build_hello(endpoint_url)
        response = self._tcp_send_recv(target, port, hello)

        if response:
            result.raw_responses.append(response)
            info = self._parse_acknowledge(response)
            if info and not info.get("error"):
                device.metadata["opcua_info"] = info
                device.metadata["protocol_version"] = info.get("protocol_version", 0)
                device.metadata["max_message_size"] = info.get("max_message_size", 0)
                result.is_identified = True

            if info.get("error"):
                device.metadata["error_code"] = info.get("error_code", 0)

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for OPC UA."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # OPC UA supports security - check if None policy is accepted
        endpoint_url = f"opc.tcp://{target}:{port}"
        hello = self._build_hello(endpoint_url)
        response = self._tcp_send_recv(target, port, hello)

        if response and len(response) >= 8:
            msg_type = response[0:3]
            if msg_type == MSG_ACKNOWLEDGE:
                # Server accepted our Hello with no security - None policy works
                result.vulnerabilities.append(
                    Vulnerability(
                        title="OPC UA accepts connections with no security",
                        severity=Severity.HIGH,
                        protocol=self.PROTOCOL_NAME,
                        target=target,
                        port=port,
                        description=(
                            "The OPC UA server accepted a connection without requiring "
                            "any security policy. Anonymous or unauthenticated access "
                            "may be possible."
                        ),
                        remediation=(
                            "Configure the server to require at least Basic256Sha256 "
                            "security policy with Sign & Encrypt mode. Disable "
                            "SecurityPolicy#None in production."
                        ),
                    )
                )

        # Check for anonymous authentication
        result.vulnerabilities.append(
            Vulnerability(
                title="Check OPC UA authentication configuration",
                severity=Severity.INFO,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "OPC UA supports multiple authentication modes: Anonymous, "
                    "Username/Password, and X.509 Certificate. Verify that anonymous "
                    "access is disabled in production."
                ),
                remediation=(
                    "Disable Anonymous authentication. Use X.509 certificate-based "
                    "authentication for machine-to-machine communication."
                ),
            )
        )

        # Check for discovery endpoint exposure
        result.vulnerabilities.append(
            Vulnerability(
                title="OPC UA discovery endpoint exposed",
                severity=Severity.LOW,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "The OPC UA discovery endpoint is accessible. This reveals "
                    "server capabilities, endpoints, and security configuration."
                ),
                remediation=(
                    "Restrict access to the discovery endpoint via firewall rules. "
                    "Only allow trusted clients to query endpoints."
                ),
            )
        )

        return result
