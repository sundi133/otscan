"""Main OTScan orchestrator - coordinates protocol scanning, discovery, and assessment."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from otscan.protocols import ALL_SCANNERS
from otscan.protocols.base import (
    BaseProtocolScanner,
    ScanMode,
    ScanResult,
    Severity,
    Vulnerability,
)
from otscan.discovery.network import (
    HostInfo,
    NetworkDiscovery,
    expand_targets,
)


@dataclass
class ScanSummary:
    """Summary of an entire OTScan run."""

    targets_scanned: int = 0
    hosts_alive: int = 0
    devices_identified: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_duration: float = 0.0
    protocols_found: list[str] = field(default_factory=list)


@dataclass
class OTScanResult:
    """Complete result from an OTScan run."""

    hosts: list[HostInfo] = field(default_factory=list)
    all_vulnerabilities: list[Vulnerability] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
    scan_mode: str = "safe"
    start_time: float = 0.0
    end_time: float = 0.0


class OTScanner:
    """Main scanner orchestrator for OTScan."""

    def __init__(
        self,
        mode: ScanMode = ScanMode.SAFE,
        timeout: float = 5.0,
        max_workers: int = 10,
        protocols: Optional[list[str]] = None,
    ):
        self.mode = mode
        self.timeout = timeout
        self.max_workers = max_workers

        # Initialize protocol scanners
        self.scanners: list[BaseProtocolScanner] = []
        for scanner_cls in ALL_SCANNERS:
            scanner = scanner_cls(timeout=timeout, mode=mode)
            if protocols is None or scanner.PROTOCOL_NAME.lower() in [
                p.lower() for p in protocols
            ]:
                self.scanners.append(scanner)

        self.discovery = NetworkDiscovery(
            scanners=self.scanners,
            timeout=timeout,
            max_workers=max_workers,
            mode=mode,
        )

    def scan(
        self,
        target_spec: str,
        progress_callback=None,
    ) -> OTScanResult:
        """Run a complete OT/ICS scan against targets.

        Args:
            target_spec: Target specification (IP, CIDR, range, or comma-separated).
            progress_callback: Optional callback(completed, total, current_target).

        Returns:
            OTScanResult with all findings.
        """
        result = OTScanResult(scan_mode=self.mode.value)
        result.start_time = time.time()

        # Expand targets
        targets = expand_targets(target_spec)
        result.summary.targets_scanned = len(targets)

        # Run network discovery + protocol scanning
        result.hosts = self.discovery.discover_network(
            targets, progress_callback=progress_callback
        )

        # Aggregate results
        result.summary.hosts_alive = len(result.hosts)
        protocols_found = set()

        for host in result.hosts:
            for scan_result in host.scan_results:
                if scan_result.is_identified:
                    result.summary.devices_identified += 1
                    protocols_found.add(scan_result.protocol)

                for vuln in scan_result.vulnerabilities:
                    result.all_vulnerabilities.append(vuln)

        # Count by severity
        for vuln in result.all_vulnerabilities:
            if vuln.severity == Severity.CRITICAL:
                result.summary.critical_count += 1
            elif vuln.severity == Severity.HIGH:
                result.summary.high_count += 1
            elif vuln.severity == Severity.MEDIUM:
                result.summary.medium_count += 1
            elif vuln.severity == Severity.LOW:
                result.summary.low_count += 1
            elif vuln.severity == Severity.INFO:
                result.summary.info_count += 1

        result.summary.total_vulnerabilities = len(result.all_vulnerabilities)
        result.summary.protocols_found = sorted(protocols_found)

        result.end_time = time.time()
        result.summary.scan_duration = result.end_time - result.start_time

        return result

    def scan_single(self, target: str, port: int, protocol: str) -> Optional[ScanResult]:
        """Scan a single target with a specific protocol.

        Args:
            target: IP address or hostname.
            port: Port number.
            protocol: Protocol name to use.

        Returns:
            ScanResult or None if protocol not found.
        """
        for scanner in self.scanners:
            if scanner.PROTOCOL_NAME.lower() == protocol.lower():
                return scanner.scan(target, port)
        return None

    def list_protocols(self) -> list[dict[str, str]]:
        """List all available protocol scanners."""
        return [
            {
                "name": s.PROTOCOL_NAME,
                "port": str(s.DEFAULT_PORT),
                "description": s.DESCRIPTION,
            }
            for s in self.scanners
        ]
