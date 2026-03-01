"""Base protocol scanner interface and shared data models."""

from __future__ import annotations

import socket
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ScanMode(Enum):
    """Scanning aggressiveness level."""

    PASSIVE = "passive"
    SAFE = "safe"
    ACTIVE = "active"


class Severity(Enum):
    """Vulnerability severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DeviceInfo:
    """Information about a discovered OT/ICS device."""

    ip: str
    port: int
    protocol: str
    vendor: str = "Unknown"
    model: str = "Unknown"
    firmware: str = "Unknown"
    serial: str = "Unknown"
    device_type: str = "Unknown"
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Vulnerability:
    """A detected vulnerability or security concern."""

    title: str
    severity: Severity
    protocol: str
    target: str
    port: int
    description: str
    remediation: str = ""
    cve: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Result from scanning a single target with a specific protocol."""

    target: str
    port: int
    protocol: str
    is_open: bool = False
    is_identified: bool = False
    device: Optional[DeviceInfo] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    raw_responses: list[bytes] = field(default_factory=list)
    scan_time: float = 0.0
    error: Optional[str] = None


class BaseProtocolScanner(ABC):
    """Abstract base class for all OT/ICS protocol scanners."""

    # Subclasses must set these
    PROTOCOL_NAME: str = ""
    DEFAULT_PORT: int = 0
    DESCRIPTION: str = ""

    def __init__(self, timeout: float = 5.0, mode: ScanMode = ScanMode.SAFE):
        self.timeout = timeout
        self.mode = mode

    @abstractmethod
    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Send protocol-specific probes to identify the service."""

    @abstractmethod
    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Attempt to identify device details (vendor, model, firmware)."""

    @abstractmethod
    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Perform security assessment and check for vulnerabilities."""

    def scan(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Full scan: probe, identify, and assess a target."""
        port = port or self.DEFAULT_PORT
        start = time.time()

        result = self.probe(target, port)
        if not result.is_open:
            result.scan_time = time.time() - start
            return result

        id_result = self.identify(target, port)
        result.device = id_result.device
        result.is_identified = id_result.is_identified
        result.raw_responses.extend(id_result.raw_responses)

        if self.mode != ScanMode.PASSIVE:
            vuln_result = self.assess(target, port)
            result.vulnerabilities = vuln_result.vulnerabilities
            result.raw_responses.extend(vuln_result.raw_responses)

        result.scan_time = time.time() - start
        return result

    def _tcp_connect(self, target: str, port: int) -> Optional[socket.socket]:
        """Establish a TCP connection to target:port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            return sock
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _tcp_send_recv(
        self, target: str, port: int, data: bytes, recv_size: int = 4096
    ) -> Optional[bytes]:
        """Send data over TCP and receive response."""
        sock = self._tcp_connect(target, port)
        if not sock:
            return None
        try:
            sock.sendall(data)
            return sock.recv(recv_size)
        except (socket.timeout, ConnectionResetError, OSError):
            return None
        finally:
            sock.close()

    def _udp_send_recv(
        self, target: str, port: int, data: bytes, recv_size: int = 4096
    ) -> Optional[bytes]:
        """Send data over UDP and receive response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(data, (target, port))
            response, _ = sock.recvfrom(recv_size)
            return response
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    def _check_port_open(self, target: str, port: int) -> bool:
        """Quick TCP port check."""
        sock = self._tcp_connect(target, port)
        if sock:
            sock.close()
            return True
        return False

    @staticmethod
    def _safe_unpack(fmt: str, data: bytes, offset: int = 0) -> Optional[tuple]:
        """Safely unpack binary data."""
        size = struct.calcsize(fmt)
        if len(data) < offset + size:
            return None
        return struct.unpack(fmt, data[offset : offset + size])
