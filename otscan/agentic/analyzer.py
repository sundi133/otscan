"""Agentic AI-powered analysis of OT scan results using Anthropic Claude.

Uses Claude to provide intelligent vulnerability correlation, risk scoring,
attack path analysis, and remediation prioritization for OT/ICS environments.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

# Available Claude models (newest family as of 2025):
#   claude-opus-4-6       — most capable, deep reasoning
#   claude-sonnet-4-6     — balanced speed + intelligence (recommended default)
#   claude-haiku-4-5-20251001 — fastest, lowest cost
DEFAULT_MODEL = "claude-sonnet-4-6"

SUPPORTED_MODELS = [
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-5-20251001",
]

OT_SYSTEM_PROMPT = """\
You are an expert OT/ICS/SCADA cybersecurity analyst. You analyze scan results \
from industrial control system networks and provide actionable security assessments.

Your expertise covers:
- Industrial protocols: Modbus TCP, DNP3, OPC UA, BACnet, EtherNet/IP, S7comm, \
HART-IP, IEC 61850, PROFINET, IEC 60870-5-104, FINS, CODESYS, Niagara Fox
- OT network segmentation (Purdue model / IEC 62443 zones)
- ICS-specific CVEs and attack techniques (MITRE ATT&CK for ICS)
- Safety implications of OT vulnerabilities (physical process impact)
- Regulatory frameworks: NERC CIP, IEC 62443, NIST SP 800-82

When analyzing results:
1. Prioritize findings by real-world exploitability and safety impact
2. Identify attack paths that chain multiple vulnerabilities
3. Flag default credentials and unauthenticated protocols as critical
4. Consider OT-specific constraints (uptime requirements, legacy devices, \
patch limitations)
5. Provide remediation steps ranked by effectiveness and feasibility
6. Output structured JSON when asked for machine-readable analysis
"""


@dataclass
class AgenticConfig:
    """Configuration for the agentic analyzer."""

    api_key: str = ""
    model: str = DEFAULT_MODEL
    max_tokens: int = 4096
    temperature: float = 0.2

    @classmethod
    def from_env(cls, model: Optional[str] = None) -> "AgenticConfig":
        """Load config from environment variables.

        Environment variables:
            ANTHROPIC_API_KEY: API key (required)
            OTSCAN_MODEL: Claude model name (optional)
        """
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        env_model = os.environ.get("OTSCAN_MODEL", DEFAULT_MODEL)
        return cls(
            api_key=api_key,
            model=model or env_model,
        )


@dataclass
class AnalysisResult:
    """Result from agentic analysis."""

    summary: str = ""
    risk_score: float = 0.0
    attack_paths: list[str] = field(default_factory=list)
    prioritized_remediations: list[str] = field(default_factory=list)
    raw_response: str = ""
    model_used: str = ""
    tokens_used: int = 0


class AgenticAnalyzer:
    """AI-powered OT scan result analyzer using Anthropic Claude."""

    def __init__(self, config: Optional[AgenticConfig] = None):
        self.config = config or AgenticConfig.from_env()
        self._client = None

    def _get_client(self):
        """Lazy-initialize the Anthropic client."""
        if self._client is None:
            try:
                import anthropic
            except ImportError:
                raise ImportError(
                    "anthropic package is required for agentic analysis. "
                    "Install it with: pip install 'otscan[agentic]'"
                )
            if not self.config.api_key:
                raise ValueError(
                    "Anthropic API key is required. Set ANTHROPIC_API_KEY env var "
                    "or pass --api-key to the CLI."
                )
            self._client = anthropic.Anthropic(api_key=self.config.api_key)
        return self._client

    def _build_scan_context(self, scan_result) -> str:
        """Convert scan result to a text summary for Claude."""
        lines = []
        lines.append("# OT/ICS Scan Results\n")
        lines.append(f"- Mode: {scan_result.scan_mode}")
        lines.append(f"- Targets scanned: {scan_result.summary.targets_scanned}")
        lines.append(f"- Hosts alive: {scan_result.summary.hosts_alive}")
        lines.append(f"- Devices identified: {scan_result.summary.devices_identified}")
        lines.append(f"- Total vulnerabilities: {scan_result.summary.total_vulnerabilities}")
        lines.append(f"- Protocols: {', '.join(scan_result.summary.protocols_found)}")
        lines.append(f"- Duration: {scan_result.summary.scan_duration:.1f}s\n")

        lines.append("## Severity Breakdown")
        lines.append(f"- Critical: {scan_result.summary.critical_count}")
        lines.append(f"- High: {scan_result.summary.high_count}")
        lines.append(f"- Medium: {scan_result.summary.medium_count}")
        lines.append(f"- Low: {scan_result.summary.low_count}")
        lines.append(f"- Info: {scan_result.summary.info_count}\n")

        for host in scan_result.hosts:
            lines.append(f"## Host: {host.ip}")
            lines.append(f"Open ports: {host.open_ports}\n")

            for sr in host.scan_results:
                if sr.device:
                    d = sr.device
                    lines.append(f"### Device: {d.protocol}")
                    lines.append(f"  Vendor: {d.vendor}")
                    lines.append(f"  Model: {d.model}")
                    lines.append(f"  Firmware: {d.firmware}")
                    lines.append(f"  Type: {d.device_type}\n")

                for vuln in sr.vulnerabilities:
                    lines.append(
                        f"  [{vuln.severity.value.upper()}] {vuln.title} "
                        f"({vuln.protocol} port {vuln.port})"
                    )
                    lines.append(f"    {vuln.description}")
                    if vuln.cve:
                        lines.append(f"    CVE: {vuln.cve}")
                    lines.append("")

        return "\n".join(lines)

    def analyze(self, scan_result) -> AnalysisResult:
        """Run full agentic analysis on scan results.

        Args:
            scan_result: An OTScanResult object from the scanner.

        Returns:
            AnalysisResult with AI-generated analysis.
        """
        client = self._get_client()
        context = self._build_scan_context(scan_result)

        user_prompt = f"""{context}

---

Analyze these OT/ICS scan results. Provide:

1. **Executive Summary** (2-3 sentences on overall risk posture)
2. **Risk Score** (0.0 to 10.0 based on findings severity and exploitability)
3. **Critical Attack Paths** (how an attacker could chain findings to compromise the OT environment)
4. **Prioritized Remediation Plan** (ordered list of actions, most impactful first, \
considering OT constraints like uptime and legacy devices)
5. **IEC 62443 / NIST 800-82 Compliance Gaps** (specific gaps identified from findings)

Format your response as JSON with keys: summary, risk_score, attack_paths, \
prioritized_remediations, compliance_gaps"""

        message = client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            system=OT_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        raw_text = message.content[0].text
        tokens = message.usage.input_tokens + message.usage.output_tokens

        result = AnalysisResult(
            raw_response=raw_text,
            model_used=self.config.model,
            tokens_used=tokens,
        )

        # Parse structured JSON from response
        try:
            parsed = _extract_json(raw_text)
            result.summary = parsed.get("summary", raw_text[:500])
            result.risk_score = float(parsed.get("risk_score", 0.0))
            result.attack_paths = parsed.get("attack_paths", [])
            result.prioritized_remediations = parsed.get("prioritized_remediations", [])
        except (json.JSONDecodeError, ValueError, TypeError):
            result.summary = raw_text[:500]

        return result

    def ask(self, scan_result, question: str) -> str:
        """Ask a follow-up question about scan results.

        Args:
            scan_result: An OTScanResult object.
            question: Free-form question about the findings.

        Returns:
            Claude's response as a string.
        """
        client = self._get_client()
        context = self._build_scan_context(scan_result)

        message = client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            system=OT_SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": f"{context}\n\n---\n\nQuestion: {question}"},
            ],
        )

        return message.content[0].text


def _extract_json(text: str) -> dict:
    """Extract JSON from a response that may contain markdown code fences."""
    text = text.strip()
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try extracting from ```json ... ``` blocks
    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start)
        return json.loads(text[start:end].strip())
    if "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start)
        return json.loads(text[start:end].strip())
    raise json.JSONDecodeError("No JSON found", text, 0)
