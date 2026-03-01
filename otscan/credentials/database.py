"""Default credential database for OT/ICS devices.

Sourced from public ICS-CERT advisories, vendor documentation, and
community resources. These are vendor-shipped factory defaults.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DefaultCredential:
    """A known default credential for an OT/ICS device."""

    vendor: str
    product: str
    protocol: str
    port: int
    username: str
    password: str
    source: str = ""
    cve: str = ""


# -- SNMP community strings commonly found on OT devices --
SNMP_COMMUNITIES = [
    "public",
    "private",
    "community",
    "snmpd",
    "mngt",
    "admin",
    "default",
    "monitor",
    "switch",
    "cable-docsis",
    "ILMI",
    "internal",
    "write",
    "secret",
    "cisco",
    "all private",
    "tiv0li",
    "openview",
    "ANYCOM",
    "SECURITY",
]

# -- Known default credentials for OT/ICS devices --
# NOTE: These are publicly documented factory defaults.
DEFAULT_CREDENTIALS: list[DefaultCredential] = [
    # === Siemens ===
    DefaultCredential("Siemens", "SIMATIC S7 (Web)", "http", 80, "admin", "admin"),
    DefaultCredential("Siemens", "SIMATIC S7 (Web)", "http", 80, "user", "user"),
    DefaultCredential("Siemens", "SIMATIC WinCC", "http", 80, "administrator", ""),
    DefaultCredential("Siemens", "SCALANCE Switches", "http", 443, "admin", "admin"),
    DefaultCredential("Siemens", "SCALANCE Switches", "ssh", 22, "admin", "admin"),
    DefaultCredential("Siemens", "SCALANCE Switches", "telnet", 23, "admin", "admin"),
    DefaultCredential("Siemens", "SIMATIC HMI Panels", "vnc", 5900, "", "100"),
    DefaultCredential("Siemens", "LOGO! PLC", "http", 80, "admin", "admin"),

    # === Schneider Electric ===
    DefaultCredential("Schneider Electric", "Modicon M340/M580", "ftp", 21, "USER", "USER"),
    DefaultCredential("Schneider Electric", "Modicon M340/M580", "http", 80, "USER", "USER"),
    DefaultCredential("Schneider Electric", "PowerLogic ION", "http", 80, "admin", "admin"),
    DefaultCredential("Schneider Electric", "Vijeo Citect", "http", 80, "admin", "admin"),
    DefaultCredential("Schneider Electric", "BMX NOE", "ftp", 21, "sysdiag", "factorycast@schneider"),
    DefaultCredential("Schneider Electric", "SCADAPack", "telnet", 23, "", ""),

    # === Rockwell / Allen-Bradley ===
    DefaultCredential("Rockwell", "MicroLogix 1100", "http", 80, "admin", "admin"),
    DefaultCredential("Rockwell", "ControlLogix (Web)", "http", 80, "admin", "1234"),
    DefaultCredential("Rockwell", "Stratix Switches", "ssh", 22, "admin", "admin"),
    DefaultCredential("Rockwell", "Stratix Switches", "telnet", 23, "admin", "admin"),
    DefaultCredential("Rockwell", "PanelView", "vnc", 5900, "", ""),

    # === ABB ===
    DefaultCredential("ABB", "AC500 PLC", "http", 80, "admin", "admin"),
    DefaultCredential("ABB", "AC500 PLC", "ftp", 21, "ftp", "ftp"),
    DefaultCredential("ABB", "Relion 670", "ssh", 22, "admin", "admin"),
    DefaultCredential("ABB", "RTU560", "http", 80, "admin", "admin"),
    DefaultCredential("ABB", "Freelance DCS", "http", 80, "admin", ""),

    # === GE ===
    DefaultCredential("GE", "PACSystems RX3i", "ftp", 21, "anonymous", ""),
    DefaultCredential("GE", "Multilin Relays", "http", 80, "admin", "admin"),
    DefaultCredential("GE", "D20MX", "telnet", 23, "admin", "admin"),

    # === Honeywell ===
    DefaultCredential("Honeywell", "Experion PKS", "http", 80, "admin", "admin"),
    DefaultCredential("Honeywell", "XL Web Controllers", "http", 80, "admin", "admin"),
    DefaultCredential("Honeywell", "JACE Controllers", "http", 80, "tridium", "tridium"),

    # === Tridium / Niagara ===
    DefaultCredential("Tridium", "Niagara AX/N4", "http", 80, "admin", "admin"),
    DefaultCredential("Tridium", "Niagara AX/N4", "http", 80, "tridium", "tridium"),
    DefaultCredential("Tridium", "JACE", "niagara_fox", 4911, "admin", "admin"),

    # === Moxa ===
    DefaultCredential("Moxa", "NPort Series", "telnet", 23, "admin", ""),
    DefaultCredential("Moxa", "NPort Series", "http", 80, "admin", ""),
    DefaultCredential("Moxa", "EDS Switches", "http", 80, "admin", ""),
    DefaultCredential("Moxa", "MGate Gateways", "http", 80, "admin", ""),

    # === Omron ===
    DefaultCredential("Omron", "CJ/CP Series", "http", 80, "admin", "admin"),
    DefaultCredential("Omron", "NX/NJ Series", "http", 80, "admin", "admin"),

    # === Mitsubishi ===
    DefaultCredential("Mitsubishi", "MELSEC-Q", "http", 80, "admin", "mitsubishi"),
    DefaultCredential("Mitsubishi", "GOT HMI", "vnc", 5900, "", ""),

    # === Beckhoff ===
    DefaultCredential("Beckhoff", "TwinCAT (CE)", "http", 80, "webguest", "1"),
    DefaultCredential("Beckhoff", "TwinCAT (CE)", "http", 80, "Administrator", "1"),

    # === Wago ===
    DefaultCredential("WAGO", "750 Series", "http", 80, "admin", "wago"),
    DefaultCredential("WAGO", "750 Series", "ftp", 21, "admin", "wago"),
    DefaultCredential("WAGO", "PFC200", "ssh", 22, "root", "wago"),

    # === Phoenix Contact ===
    DefaultCredential("Phoenix Contact", "ILC/AXC Controllers", "http", 80, "admin", "admin"),
    DefaultCredential("Phoenix Contact", "FL Switch", "http", 80, "admin", "admin"),

    # === Emerson / Fisher ===
    DefaultCredential("Emerson", "ROC800", "http", 80, "admin", "admin"),
    DefaultCredential("Emerson", "DeltaV", "http", 80, "admin", "admin"),

    # === Red Lion ===
    DefaultCredential("Red Lion", "Crimson/DA30", "http", 80, "admin", "admin"),

    # === Yokogawa ===
    DefaultCredential("Yokogawa", "CENTUM VP", "http", 80, "admin", "admin"),
    DefaultCredential("Yokogawa", "STARDOM FCN", "http", 80, "admin", "admin"),

    # === Cisco Industrial ===
    DefaultCredential("Cisco", "IE Industrial Switches", "ssh", 22, "cisco", "cisco"),
    DefaultCredential("Cisco", "IE Industrial Switches", "telnet", 23, "cisco", "cisco"),

    # === Generic HMI/Remote Access ===
    DefaultCredential("Generic", "VNC (no auth)", "vnc", 5900, "", ""),
    DefaultCredential("Generic", "VNC (1234)", "vnc", 5900, "", "1234"),
    DefaultCredential("Generic", "VNC (password)", "vnc", 5900, "", "password"),
    DefaultCredential("Generic", "Telnet (root)", "telnet", 23, "root", "root"),
    DefaultCredential("Generic", "Telnet (admin)", "telnet", 23, "admin", "admin"),
    DefaultCredential("Generic", "FTP (anonymous)", "ftp", 21, "anonymous", ""),
    DefaultCredential("Generic", "SSH (root/root)", "ssh", 22, "root", "root"),

    # === MQTT Brokers ===
    DefaultCredential("Generic", "MQTT (no auth)", "mqtt", 1883, "", ""),
    DefaultCredential("Generic", "MQTT (admin)", "mqtt", 1883, "admin", "admin"),
    DefaultCredential("Generic", "MQTT (mosquitto)", "mqtt", 1883, "admin", "password"),
]


def get_credentials_for_vendor(vendor: str) -> list[DefaultCredential]:
    """Get default credentials matching a vendor name (case-insensitive partial match)."""
    vendor_lower = vendor.lower()
    return [
        c for c in DEFAULT_CREDENTIALS
        if vendor_lower in c.vendor.lower() or vendor_lower in c.product.lower()
    ]


def get_credentials_for_port(port: int) -> list[DefaultCredential]:
    """Get default credentials for services on a specific port."""
    return [c for c in DEFAULT_CREDENTIALS if c.port == port]


def get_credentials_for_protocol(protocol: str) -> list[DefaultCredential]:
    """Get default credentials for a specific protocol (http, ssh, telnet, etc.)."""
    protocol_lower = protocol.lower()
    return [c for c in DEFAULT_CREDENTIALS if c.protocol.lower() == protocol_lower]
