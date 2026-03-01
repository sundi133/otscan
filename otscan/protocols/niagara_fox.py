"""Niagara Fox protocol scanner.

Niagara Framework (by Tridium/Honeywell) is used in building automation,
energy management, and IoT gateways. The Fox protocol runs on TCP port 1911
(unsecured) and 4911 (TLS). Over 500,000 JACE controllers are deployed globally.
"""

from __future__ import annotations

from typing import Optional

from otscan.protocols.base import (
    BaseProtocolScanner,
    DeviceInfo,
    ScanResult,
    Severity,
    Vulnerability,
)


class NiagaraFoxScanner(BaseProtocolScanner):
    """Scanner for Niagara Fox protocol."""

    PROTOCOL_NAME = "Niagara Fox"
    DEFAULT_PORT = 1911
    DESCRIPTION = "Tridium/Honeywell building automation"

    @staticmethod
    def _build_fox_hello() -> bytes:
        """Build a Fox protocol hello/handshake request.

        The Fox protocol is text-based with key-value pairs.
        """
        # Fox hello message
        msg = (
            "fox a 1 -1 fox hello\n"
            "{\n"
            "fox.version=s:1.0\n"
            "id=i:1\n"
            "}\n"
            ";;;\n"
        )
        return msg.encode("ascii")

    def _parse_fox_response(self, data: bytes) -> dict:
        """Parse a Fox protocol response."""
        info = {}
        try:
            text = data.decode("ascii", errors="replace")
        except Exception:
            return info

        info["raw"] = text[:500]

        # Fox responses are key=value pairs between { and }
        if "{" in text and "}" in text:
            block = text[text.index("{") + 1:text.index("}")]
            for line in block.strip().split("\n"):
                line = line.strip()
                if "=" in line:
                    key, _, value = line.partition("=")
                    # Values have type prefix like s: i: b:
                    if ":" in value:
                        value = value.split(":", 1)[1]
                    info[key.strip()] = value.strip()

        # Check for common Fox fields
        if "fox" in text.lower() or "niagara" in text.lower():
            info["is_fox"] = True

        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for Niagara Fox service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        request = self._build_fox_hello()
        response = self._tcp_send_recv(target, port, request)

        if response:
            result.raw_responses.append(response)
            info = self._parse_fox_response(response)
            if info.get("is_fox") or "fox" in response.decode("ascii", errors="replace").lower():
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify Niagara Fox device."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            vendor="Tridium/Honeywell",
            device_type="JACE Controller",
        )

        request = self._build_fox_hello()
        response = self._tcp_send_recv(target, port, request)

        if response:
            result.raw_responses.append(response)
            info = self._parse_fox_response(response)
            device.metadata["fox_info"] = info

            if info.get("hostName"):
                device.model = info["hostName"]
            if info.get("fox.version"):
                device.firmware = f"Fox v{info['fox.version']}"
            if info.get("brandId"):
                device.vendor = info["brandId"]
            if info.get("vmVersion"):
                device.metadata["java_version"] = info["vmVersion"]
            if info.get("osName"):
                device.metadata["os"] = info["osName"]
            if info.get("hostAddress"):
                device.metadata["host_address"] = info["hostAddress"]

            if info.get("is_fox"):
                result.is_identified = True

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for Niagara Fox."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        is_plaintext_port = port in (1911, 4911)

        if port == 1911:
            result.vulnerabilities.append(
                Vulnerability(
                    title="Niagara Fox on unencrypted port 1911",
                    severity=Severity.CRITICAL,
                    protocol=self.PROTOCOL_NAME,
                    target=target,
                    port=port,
                    description=(
                        "Niagara Fox is running on port 1911 (plaintext). "
                        "Credentials and building automation data are transmitted "
                        "without encryption. Thousands of JACE controllers have "
                        "been found Internet-exposed via Shodan."
                    ),
                    remediation=(
                        "Migrate to Fox over TLS (port 4911). Disable port 1911. "
                        "Change default credentials (tridium/tridium)."
                    ),
                    cve="CVE-2017-16744",
                )
            )

        result.vulnerabilities.append(
            Vulnerability(
                title="Niagara default credentials may be active",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "Niagara/JACE controllers commonly ship with default "
                    "credentials: admin/admin or tridium/tridium. "
                    "These provide full administrative access to building "
                    "automation systems (HVAC, lighting, access control)."
                ),
                remediation="Change all default credentials. Enforce strong password policies.",
            )
        )

        # Check what info was disclosed in hello response
        request = self._build_fox_hello()
        response = self._tcp_send_recv(target, port, request)
        if response:
            info = self._parse_fox_response(response)
            disclosed = [k for k in ("hostName", "osName", "vmVersion", "hostAddress", "brandId")
                        if k in info]
            if disclosed:
                result.vulnerabilities.append(
                    Vulnerability(
                        title="Niagara Fox discloses system information",
                        severity=Severity.MEDIUM,
                        protocol=self.PROTOCOL_NAME,
                        target=target,
                        port=port,
                        description=(
                            f"Fox hello response discloses: {', '.join(disclosed)}. "
                            "This aids reconnaissance for targeted attacks."
                        ),
                        remediation="Restrict Fox protocol access. Use TLS with client certificates.",
                        metadata={"disclosed_fields": disclosed},
                    )
                )

        return result
