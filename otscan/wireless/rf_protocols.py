"""Wireless/RF protocol awareness for OT environments.

Documents RF protocols commonly found in industrial settings and provides
guidance for their assessment. Actual RF scanning requires specialized
hardware (SDR, Zigbee dongles, etc.) — this module provides the knowledge
base and assessment framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from otscan.protocols.base import Severity, Vulnerability


class RFBand(Enum):
    """Radio frequency bands used in OT."""

    ISM_900 = "900 MHz ISM"
    ISM_2400 = "2.4 GHz ISM"
    ISM_5000 = "5 GHz ISM"
    ISM_868 = "868 MHz ISM"
    SUB_GHZ = "Sub-GHz"
    UHF = "UHF"


@dataclass
class WirelessProtocol:
    """Definition of a wireless protocol used in OT/ICS."""

    name: str
    frequency: RFBand
    range_meters: str
    data_rate: str
    description: str
    encryption: str
    authentication: str
    common_vendors: list[str] = field(default_factory=list)
    known_attacks: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    detection_hardware: str = ""


# Wireless protocols commonly found in OT environments
OT_WIRELESS_PROTOCOLS: list[WirelessProtocol] = [
    WirelessProtocol(
        name="WirelessHART (IEC 62591)",
        frequency=RFBand.ISM_2400,
        range_meters="100-250m",
        data_rate="250 kbps",
        description=(
            "Wireless extension of HART protocol for field instruments. "
            "Uses IEEE 802.15.4 with TDMA and frequency hopping. "
            "Common in process control for temperature, pressure, flow sensors."
        ),
        encryption="AES-128 (CCM mode)",
        authentication="Per-device join keys + network key",
        common_vendors=["Emerson", "Honeywell", "ABB", "Siemens", "Yokogawa"],
        known_attacks=[
            "Join key extraction from configuration files",
            "Selective jamming of TDMA slots",
            "Network key compromise via single device exploitation",
            "Replay attacks if nonces are predictable",
        ],
        vulnerabilities=[
            "All devices share the same network key",
            "Join keys often stored in plaintext in configuration tools",
            "No forward secrecy — compromised key decrypts all past traffic",
            "Physical access to one device can compromise network key",
        ],
        detection_hardware="IEEE 802.15.4 sniffer (e.g., TI CC2531, Atmel RZUSBstick)",
    ),
    WirelessProtocol(
        name="ISA100.11a (IEC 62734)",
        frequency=RFBand.ISM_2400,
        range_meters="100-300m",
        description=(
            "Industrial wireless standard by ISA. Uses IEEE 802.15.4 PHY "
            "with TDMA/CSMA. Competitor to WirelessHART."
        ),
        data_rate="250 kbps",
        encryption="AES-128 (CCM mode)",
        authentication="Per-device keys + DLPDU authentication",
        common_vendors=["Honeywell", "Yokogawa", "ABB"],
        known_attacks=[
            "Selective jamming",
            "Key management attacks",
            "Routing manipulation (graph routing)",
        ],
        vulnerabilities=[
            "Backbone router is single point of failure",
            "Key distribution relies on provisioning security",
        ],
        detection_hardware="IEEE 802.15.4 sniffer",
    ),
    WirelessProtocol(
        name="Zigbee / Zigbee Pro",
        frequency=RFBand.ISM_2400,
        range_meters="10-100m",
        data_rate="250 kbps",
        description=(
            "Used in building automation (lighting, HVAC, metering). "
            "IEEE 802.15.4 based mesh protocol."
        ),
        encryption="AES-128",
        authentication="Trust Center link key",
        common_vendors=["Philips", "Honeywell", "Schneider Electric", "Johnson Controls"],
        known_attacks=[
            "Zigbee network key sniffing during OTA key transport",
            "Default Trust Center link key (ZigBeeAlliance09)",
            "Touchlink commissioning exploitation",
            "Device impersonation after key extraction",
        ],
        vulnerabilities=[
            "Well-known default Trust Center key",
            "Network key sent in the clear during joining (if not pre-provisioned)",
            "No certificate-based authentication",
            "Replay attacks possible on some profiles",
        ],
        detection_hardware="Zigbee sniffer (KillerBee, CC2531, Ubertooth)",
    ),
    WirelessProtocol(
        name="Z-Wave",
        frequency=RFBand.ISM_900,
        range_meters="30-100m",
        data_rate="100 kbps",
        description=(
            "Sub-GHz mesh protocol for building automation and smart home. "
            "Used for HVAC, door locks, lighting in commercial buildings."
        ),
        encryption="AES-128 (S2 framework)",
        authentication="ECDH key exchange (S2)",
        common_vendors=["Silicon Labs", "Honeywell", "Johnson Controls"],
        known_attacks=[
            "S0 downgrade attack (CVE-2018-11438)",
            "S0 key exchange interception",
            "Denial of service via jamming",
            "Z-Shave: S0 network key recovery",
        ],
        vulnerabilities=[
            "Legacy S0 security uses known key exchange weakness",
            "S2 adoption still not universal",
            "Controller is single point of failure",
        ],
        detection_hardware="Z-Wave sniffer (Zniffer, HackRF with Z-Wave firmware)",
    ),
    WirelessProtocol(
        name="Bluetooth Low Energy (BLE)",
        frequency=RFBand.ISM_2400,
        range_meters="10-50m",
        data_rate="1-2 Mbps",
        description=(
            "Used for sensor data collection, asset tracking, and field "
            "device configuration in industrial environments."
        ),
        encryption="AES-128 (LE Secure Connections)",
        authentication="Pairing (Just Works, Passkey, OOB)",
        common_vendors=["Various sensor manufacturers"],
        known_attacks=[
            "Just Works pairing MITM",
            "BLE sniffing (passive eavesdropping)",
            "KNOB attack (key entropy reduction)",
            "BLURtooth cross-transport key derivation",
            "SweynTooth firmware vulnerabilities",
        ],
        vulnerabilities=[
            "Just Works pairing has no MITM protection",
            "Legacy pairing is vulnerable to passive eavesdropping",
            "Many industrial BLE devices use minimal security",
        ],
        detection_hardware="Ubertooth One, nRF52840 dongle, HackRF",
    ),
    WirelessProtocol(
        name="LoRaWAN",
        frequency=RFBand.SUB_GHZ,
        range_meters="2000-15000m",
        data_rate="0.3-50 kbps",
        description=(
            "Long-range, low-power WAN protocol used for remote sensor "
            "monitoring in utilities, agriculture, and water/wastewater."
        ),
        encryption="AES-128 (AppSKey + NwkSKey)",
        authentication="Device-specific keys (OTAA or ABP)",
        common_vendors=["Semtech", "Microchip", "STMicroelectronics"],
        known_attacks=[
            "ABP replay attacks (fixed frame counters)",
            "Bit-flipping on unencrypted MAC commands",
            "Eavesdropping on JOIN requests",
            "ACK spoofing",
        ],
        vulnerabilities=[
            "ABP mode allows replay attacks",
            "No end-to-end encryption (only hop-by-hop)",
            "Network server can read all application data",
            "Frame counter reset enables replay on ABP devices",
        ],
        detection_hardware="LoRa SDR (HackRF, LimeSDR) or LoRa gateway in promiscuous mode",
    ),
    WirelessProtocol(
        name="Wi-Fi (802.11)",
        frequency=RFBand.ISM_2400,
        range_meters="30-100m",
        data_rate="54-600+ Mbps",
        description=(
            "Standard wireless networking. Found on OT networks for HMI "
            "tablets, wireless access points in control rooms, and IP cameras."
        ),
        encryption="WPA2/WPA3 (AES-CCMP)",
        authentication="PSK or 802.1X",
        common_vendors=["Cisco", "Siemens", "Moxa", "Hirschmann"],
        known_attacks=[
            "KRACK (key reinstallation attacks)",
            "PMKID hash capture",
            "Evil twin / rogue AP",
            "Deauthentication flooding",
            "WPS PIN brute force",
        ],
        vulnerabilities=[
            "PSK mode: shared password across all devices",
            "Many OT Wi-Fi networks still use WPA2-PSK",
            "Rogue AP detection often not deployed in OT",
            "Wi-Fi frequently bridges IT and OT zones",
        ],
        detection_hardware="Wi-Fi adapter in monitor mode (Alfa AWUS036ACH, etc.)",
    ),
    WirelessProtocol(
        name="Cellular (4G/5G Private)",
        frequency=RFBand.UHF,
        range_meters="1000-10000m",
        data_rate="10-1000+ Mbps",
        description=(
            "Private LTE/5G networks used for remote site connectivity, "
            "pipeline SCADA, and large facility networking."
        ),
        encryption="128-EEA (LTE), 5G NR encryption",
        authentication="SIM-based (USIM)",
        common_vendors=["Nokia", "Ericsson", "Huawei", "Sierra Wireless"],
        known_attacks=[
            "IMSI catching / Stingray",
            "Diameter protocol attacks",
            "GTP tunnel injection",
            "Rogue base station (LTE)",
        ],
        vulnerabilities=[
            "IMSI exposed in initial attach (LTE, fixed in 5G)",
            "SS7/Diameter interconnect vulnerabilities",
            "Fallback to less secure protocols (2G/3G)",
        ],
        detection_hardware="SDR (BladeRF, USRP) with srsRAN or OpenBTS",
    ),
]


def generate_rf_assessment(protocols_in_use: list[str] | None = None) -> list[Vulnerability]:
    """Generate vulnerability findings for wireless protocols in OT environments.

    If protocols_in_use is None, generates general advisories.
    """
    vulns = []

    if protocols_in_use is None:
        # General wireless advisory
        vulns.append(Vulnerability(
            title="Wireless protocol assessment not performed",
            severity=Severity.INFO,
            protocol="Wireless/RF",
            target="N/A",
            port=0,
            description=(
                "OT environments frequently use wireless protocols "
                "(WirelessHART, Zigbee, Z-Wave, BLE, Wi-Fi, LoRaWAN) "
                "that require specialized RF scanning equipment to assess. "
                "Recommend dedicated wireless assessment."
            ),
            remediation=(
                "Conduct RF site survey. Identify all wireless protocols. "
                "Assess encryption and authentication strength. "
                "Check for rogue access points."
            ),
        ))
        return vulns

    for proto_name in protocols_in_use:
        proto = next(
            (p for p in OT_WIRELESS_PROTOCOLS if p.name.lower() == proto_name.lower()),
            None,
        )
        if not proto:
            continue

        for vuln_desc in proto.vulnerabilities:
            vulns.append(Vulnerability(
                title=f"{proto.name}: {vuln_desc[:80]}",
                severity=Severity.MEDIUM,
                protocol=proto.name,
                target="N/A",
                port=0,
                description=vuln_desc,
                remediation=(
                    f"Review {proto.name} deployment. "
                    f"Encryption: {proto.encryption}. "
                    f"Authentication: {proto.authentication}."
                ),
            ))

    return vulns


def get_rf_protocol_info(name: str) -> WirelessProtocol | None:
    """Look up a wireless protocol by name."""
    for proto in OT_WIRELESS_PROTOCOLS:
        if name.lower() in proto.name.lower():
            return proto
    return None
