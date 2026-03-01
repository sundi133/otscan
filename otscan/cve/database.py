"""CVE mapping database for known OT/ICS device vulnerabilities.

Maps vendor + product + firmware version to known CVEs from ICS-CERT advisories.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from otscan.protocols.base import Severity


@dataclass(frozen=True)
class CVEEntry:
    """A known CVE affecting an OT/ICS product."""

    cve_id: str
    severity: Severity
    vendor: str
    product_pattern: str  # substring match against device model
    firmware_pattern: str  # substring or "all" for all versions
    title: str
    description: str
    remediation: str
    cvss: float = 0.0


# Known ICS CVEs - sourced from ICS-CERT/CISA advisories
CVE_DATABASE: list[CVEEntry] = [
    # === Siemens ===
    CVEEntry(
        "CVE-2019-13945", Severity.CRITICAL, "Siemens", "S7-1200", "all",
        "Siemens S7-1200 Hardware-based Access Control Bypass",
        "S7-1200 CPU allows bypassing access-level restrictions via crafted packets.",
        "Update firmware. Enable S7-1200 access protection.", cvss=9.8,
    ),
    CVEEntry(
        "CVE-2019-13945", Severity.CRITICAL, "Siemens", "S7-1500", "all",
        "Siemens S7-1500 Session Fixation",
        "S7-1500 web server session fixation allows hijacking of authenticated sessions.",
        "Update to latest firmware. Restrict web access.", cvss=9.8,
    ),
    CVEEntry(
        "CVE-2020-15782", Severity.CRITICAL, "Siemens", "S7-1200", "all",
        "Siemens S7-1200/1500 Memory Protection Bypass",
        "Bypass of built-in PLC memory protection allows arbitrary code execution.",
        "Update firmware to V4.5 or later.", cvss=10.0,
    ),
    CVEEntry(
        "CVE-2020-15782", Severity.CRITICAL, "Siemens", "S7-1500", "all",
        "Siemens S7-1200/1500 Memory Protection Bypass",
        "Bypass of built-in PLC memory protection allows arbitrary code execution.",
        "Update firmware to V2.9 or later.", cvss=10.0,
    ),
    CVEEntry(
        "CVE-2022-38465", Severity.CRITICAL, "Siemens", "S7-1200", "all",
        "Siemens S7 Cryptographic Key Extraction",
        "Global hardcoded cryptographic key can be extracted, enabling decryption of all S7 communications.",
        "Update to firmware supporting individual device keys.", cvss=9.8,
    ),
    CVEEntry(
        "CVE-2022-38465", Severity.CRITICAL, "Siemens", "S7-1500", "all",
        "Siemens S7 Cryptographic Key Extraction",
        "Global hardcoded cryptographic key can be extracted.",
        "Update to firmware supporting individual device keys.", cvss=9.8,
    ),

    # === Schneider Electric ===
    CVEEntry(
        "CVE-2021-22779", Severity.CRITICAL, "Schneider", "M340", "all",
        "Schneider Modicon M340 Authentication Bypass",
        "Authentication bypass allows unauthenticated write access to PLC memory and program.",
        "Update firmware. Restrict Modbus access.", cvss=9.8,
    ),
    CVEEntry(
        "CVE-2021-22779", Severity.CRITICAL, "Schneider", "M580", "all",
        "Schneider Modicon M580 Authentication Bypass",
        "Authentication bypass allows unauthenticated write access to PLC memory and program.",
        "Update firmware. Restrict Modbus access.", cvss=9.8,
    ),
    CVEEntry(
        "CVE-2019-6857", Severity.HIGH, "Schneider", "Modicon", "all",
        "Schneider Modicon Denial of Service",
        "Crafted Modbus packets cause PLC to enter error state requiring physical reset.",
        "Update firmware. Deploy Modbus-aware firewall.", cvss=7.5,
    ),

    # === Rockwell / Allen-Bradley ===
    CVEEntry(
        "CVE-2022-1161", Severity.CRITICAL, "Rockwell", "ControlLogix", "all",
        "Rockwell ControlLogix/CompactLogix Remote Code Execution",
        "Unauthenticated attacker can modify PLC logic while reported logic appears unchanged.",
        "Update to latest firmware. Enable CIP Security.", cvss=10.0,
    ),
    CVEEntry(
        "CVE-2022-1161", Severity.CRITICAL, "Rockwell", "CompactLogix", "all",
        "Rockwell CompactLogix Remote Code Execution",
        "Unauthenticated attacker can modify PLC logic.",
        "Update to latest firmware. Enable CIP Security.", cvss=10.0,
    ),
    CVEEntry(
        "CVE-2023-3595", Severity.CRITICAL, "Rockwell", "ControlLogix", "all",
        "Rockwell ControlLogix CIP RCE (APT Exploit)",
        "Remote code execution via CIP protocol. Actively exploited by APT groups.",
        "Apply Rockwell patch immediately. Restrict CIP access.", cvss=9.8,
    ),

    # === CODESYS ===
    CVEEntry(
        "CVE-2022-31806", Severity.CRITICAL, "CODESYS", "CODESYS", "all",
        "CODESYS V3 Default Credentials",
        "CODESYS V3 runtimes ship without authentication by default.",
        "Enable online user management with strong credentials.", cvss=9.8,
    ),
    CVEEntry(
        "CVE-2021-29241", Severity.CRITICAL, "CODESYS", "CODESYS", "all",
        "CODESYS V3 Heap Buffer Overflow (RCE)",
        "Heap buffer overflow in CODESYS V3 runtime allows remote code execution.",
        "Update CODESYS runtime to 3.5.17.0 or later.", cvss=10.0,
    ),
    CVEEntry(
        "CVE-2023-37559", Severity.HIGH, "CODESYS", "CODESYS", "all",
        "CODESYS V3 Denial of Service",
        "Crafted requests cause runtime crash, stopping PLC execution.",
        "Update to latest CODESYS version.", cvss=7.5,
    ),

    # === Omron ===
    CVEEntry(
        "CVE-2022-34151", Severity.CRITICAL, "Omron", "CJ", "all",
        "Omron CJ/CS Series Hardcoded Credentials",
        "Hardcoded credentials in CJ/CS series allow unauthenticated access.",
        "Update firmware. Restrict FINS access.", cvss=9.8,
    ),
    CVEEntry(
        "CVE-2023-0811", Severity.CRITICAL, "Omron", "NJ", "all",
        "Omron NJ/NX Controller Authentication Bypass",
        "Authentication bypass allows unauthenticated PLC programming access.",
        "Update to latest firmware.", cvss=9.1,
    ),

    # === ABB ===
    CVEEntry(
        "CVE-2023-0580", Severity.CRITICAL, "ABB", "AC500", "all",
        "ABB AC500 Unauthorized Access",
        "AC500 PLC allows unauthorized access via crafted requests.",
        "Update firmware. Enable access control.", cvss=9.8,
    ),

    # === Tridium / Niagara ===
    CVEEntry(
        "CVE-2017-16744", Severity.HIGH, "Tridium", "Niagara", "all",
        "Tridium Niagara Path Traversal",
        "Path traversal vulnerability allows reading arbitrary files.",
        "Update Niagara Framework. Use TLS.", cvss=7.5,
    ),
    CVEEntry(
        "CVE-2012-4701", Severity.CRITICAL, "Tridium", "JACE", "all",
        "Tridium JACE Directory Traversal / Credential Disclosure",
        "Allows unauthenticated access to credentials and configuration files.",
        "Update Niagara AX to 3.6 or later.", cvss=9.8,
    ),

    # === GE ===
    CVEEntry(
        "CVE-2018-10936", Severity.CRITICAL, "GE", "PACSystems", "all",
        "GE PACSystems Authentication Bypass",
        "GE SRTP protocol allows unauthenticated access to PLC.",
        "Update firmware. Restrict SRTP access.", cvss=9.8,
    ),

    # === Moxa ===
    CVEEntry(
        "CVE-2024-1222", Severity.CRITICAL, "Moxa", "NPort", "all",
        "Moxa NPort Remote Code Execution",
        "Buffer overflow in Moxa NPort serial device servers allows RCE.",
        "Update firmware to latest version.", cvss=9.8,
    ),
    CVEEntry(
        "CVE-2023-33237", Severity.HIGH, "Moxa", "EDS", "all",
        "Moxa EDS Switch Command Injection",
        "Command injection via web interface of Moxa EDS managed switches.",
        "Update firmware. Restrict web access.", cvss=8.8,
    ),
]


def lookup_cves(
    vendor: str, model: str, firmware: str = ""
) -> list[CVEEntry]:
    """Look up CVEs matching a device's vendor, model, and firmware."""
    matches = []
    vendor_lower = vendor.lower()
    model_lower = model.lower()

    for entry in CVE_DATABASE:
        if entry.vendor.lower() not in vendor_lower and vendor_lower not in entry.vendor.lower():
            continue
        if entry.product_pattern.lower() not in model_lower and model_lower not in entry.product_pattern.lower():
            continue
        if entry.firmware_pattern != "all" and firmware:
            if entry.firmware_pattern.lower() not in firmware.lower():
                continue
        matches.append(entry)

    return matches


def get_all_cves_for_vendor(vendor: str) -> list[CVEEntry]:
    """Get all CVEs for a vendor (case-insensitive partial match)."""
    vendor_lower = vendor.lower()
    return [e for e in CVE_DATABASE if vendor_lower in e.vendor.lower()]
