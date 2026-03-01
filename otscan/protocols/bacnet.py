"""BACnet (Building Automation and Control Networks) scanner.

BACnet is the dominant protocol for building automation systems including
HVAC, lighting, fire/safety, and access control. Uses UDP port 47808.
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

# BACnet/IP constants
BACNET_IP_PORT = 47808
BVLC_TYPE = 0x81

# BVLC functions
BVLC_ORIGINAL_UNICAST = 0x0A
BVLC_ORIGINAL_BROADCAST = 0x0B

# BACnet PDU types
PDU_CONFIRMED_REQUEST = 0x00
PDU_UNCONFIRMED_REQUEST = 0x10
PDU_COMPLEX_ACK = 0x30

# BACnet services
SERVICE_WHO_IS = 0x08
SERVICE_I_AM = 0x00
SERVICE_READ_PROPERTY = 0x0C
SERVICE_READ_PROPERTY_ACK = 0x0C

# BACnet object properties
PROP_OBJECT_IDENTIFIER = 75
PROP_OBJECT_NAME = 77
PROP_VENDOR_NAME = 121
PROP_VENDOR_IDENTIFIER = 120
PROP_MODEL_NAME = 70
PROP_FIRMWARE_REVISION = 44
PROP_APPLICATION_SOFTWARE_VERSION = 12
PROP_DESCRIPTION = 28
PROP_PROTOCOL_VERSION = 98
PROP_PROTOCOL_REVISION = 139


class BACnetScanner(BaseProtocolScanner):
    """Scanner for BACnet/IP protocol."""

    PROTOCOL_NAME = "BACnet/IP"
    DEFAULT_PORT = 47808
    DESCRIPTION = "Building automation and control protocol"

    @staticmethod
    def _build_whois() -> bytes:
        """Build a BACnet Who-Is broadcast request."""
        # NPDU: version=1, control=0x20 (expecting reply), DNET=0xFFFF, DLEN=0, hop=255
        npdu = struct.pack("BBHBB", 0x01, 0x20, 0xFFFF, 0x00, 0xFF)
        # APDU: unconfirmed request, Who-Is service
        apdu = struct.pack("BB", PDU_UNCONFIRMED_REQUEST, SERVICE_WHO_IS)

        payload = npdu + apdu

        # BVLC header: type, function, length
        bvlc = struct.pack("!BBH", BVLC_TYPE, BVLC_ORIGINAL_BROADCAST, 4 + len(payload))

        return bvlc + payload

    @staticmethod
    def _build_read_property(
        instance: int, property_id: int, object_type: int = 8
    ) -> bytes:
        """Build a BACnet ReadProperty request for a device object."""
        # NPDU: version=1, control=0x04 (expecting reply)
        npdu = struct.pack("BB", 0x01, 0x04)

        # APDU: confirmed request
        # PDU type + flags, max segments=0, max APDU=1476, invoke ID, service
        apdu = struct.pack("BBBBB", 0x00, 0x05, 0x01, 0x00, SERVICE_READ_PROPERTY)

        # Context tag 0: ObjectIdentifier (type + instance)
        obj_id = (object_type << 22) | (instance & 0x3FFFFF)
        apdu += b"\x0C" + struct.pack(">I", obj_id)

        # Context tag 1: PropertyIdentifier
        if property_id <= 254:
            apdu += struct.pack("BB", 0x19, property_id)
        else:
            apdu += struct.pack(">BH", 0x1A, property_id)

        payload = npdu + apdu
        bvlc = struct.pack("!BBH", BVLC_TYPE, BVLC_ORIGINAL_UNICAST, 4 + len(payload))
        return bvlc + payload

    def _parse_iam(self, data: bytes) -> dict:
        """Parse BACnet I-Am response."""
        info = {}
        if len(data) < 12:
            return info

        # Skip BVLC header (4 bytes)
        offset = 4

        # Check BVLC type
        if data[0] != BVLC_TYPE:
            return info

        # Skip NPDU (variable length - parse to find start of APDU)
        npdu_version = data[offset]
        if npdu_version != 0x01:
            return info
        npdu_control = data[offset + 1]
        offset += 2

        # Parse NPDU routing info if present
        if npdu_control & 0x20:  # DNET present
            offset += 2  # DNET
            dlen = data[offset] if offset < len(data) else 0
            offset += 1 + dlen  # DLEN + DADR
        if npdu_control & 0x08:  # SNET present
            offset += 2  # SNET
            slen = data[offset] if offset < len(data) else 0
            offset += 1 + slen  # SLEN + SADR
        if npdu_control & 0x20:  # Hop count
            offset += 1

        if offset >= len(data):
            return info

        # Check for I-Am PDU
        pdu_type = data[offset]
        if (pdu_type & 0xF0) != PDU_UNCONFIRMED_REQUEST:
            return info
        offset += 1

        if offset >= len(data):
            return info
        service = data[offset]
        if service != SERVICE_I_AM:
            return info
        offset += 1

        # Parse I-Am data: ObjectIdentifier, maxAPDUlength, segmentation, vendorID
        if offset + 6 <= len(data):
            # Application tag for ObjectIdentifier
            if (data[offset] & 0xF0) == 0xC0:  # Application tag 12
                offset += 1
                if offset + 4 <= len(data):
                    obj_id = struct.unpack(">I", data[offset : offset + 4])[0]
                    info["object_type"] = (obj_id >> 22) & 0x3FF
                    info["instance_number"] = obj_id & 0x3FFFFF
                    offset += 4

        # Try to get vendor ID
        if offset + 3 <= len(data):
            # Skip max APDU length and segmentation
            while offset < len(data) - 2:
                tag = data[offset]
                if (tag & 0xF0) == 0x20:  # Application tag 2 = Unsigned
                    tag_len = tag & 0x07
                    offset += 1
                    if tag_len <= 2 and offset + tag_len <= len(data):
                        vendor_id = int.from_bytes(
                            data[offset : offset + tag_len], "big"
                        )
                        info["vendor_id"] = vendor_id
                    break
                offset += 1

        return info

    def probe(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Probe target for BACnet/IP service."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        whois = self._build_whois()
        response = self._udp_send_recv(target, port, whois)

        if response and len(response) >= 4:
            result.raw_responses.append(response)
            if response[0] == BVLC_TYPE:
                result.is_open = True

        return result

    def identify(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Identify BACnet device details."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        device = DeviceInfo(
            ip=target,
            port=port,
            protocol=self.PROTOCOL_NAME,
            device_type="BACnet Device",
        )

        # Send Who-Is and parse I-Am
        whois = self._build_whois()
        response = self._udp_send_recv(target, port, whois)

        if response:
            result.raw_responses.append(response)
            info = self._parse_iam(response)
            if info:
                device.metadata["bacnet_info"] = info
                device.metadata["instance_number"] = info.get("instance_number", 0)

                # Map known vendor IDs
                vendor_map = {
                    5: "Johnson Controls",
                    7: "Siemens",
                    15: "Honeywell",
                    24: "Trane",
                    36: "Automated Logic",
                    95: "Reliable Controls",
                    343: "Schneider Electric",
                    404: "Carrier",
                }
                vid = info.get("vendor_id", -1)
                device.vendor = vendor_map.get(vid, f"VendorID:{vid}")
                result.is_identified = True

        result.device = device
        return result

    def assess(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Security assessment for BACnet/IP."""
        port = port or self.DEFAULT_PORT
        result = ScanResult(target=target, port=port, protocol=self.PROTOCOL_NAME)

        # BACnet has no built-in authentication
        result.vulnerabilities.append(
            Vulnerability(
                title="BACnet/IP has no authentication",
                severity=Severity.HIGH,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "BACnet/IP does not include authentication. Any device on the "
                    "network can read/write BACnet object properties, potentially "
                    "affecting HVAC, lighting, and safety systems."
                ),
                remediation=(
                    "Implement BACnet Secure Connect (BACnet/SC) if supported. "
                    "Use network segmentation and BACnet-aware firewalls."
                ),
            )
        )

        # Check: UDP-based (susceptible to spoofing)
        result.vulnerabilities.append(
            Vulnerability(
                title="BACnet/IP uses UDP (spoofable)",
                severity=Severity.MEDIUM,
                protocol=self.PROTOCOL_NAME,
                target=target,
                port=port,
                description=(
                    "BACnet/IP uses UDP transport which is susceptible to source "
                    "address spoofing. Attackers can forge BACnet messages."
                ),
                remediation=(
                    "Deploy BACnet Secure Connect (BACnet/SC) which adds TLS. "
                    "Implement ingress filtering and BACnet-aware IDS."
                ),
            )
        )

        # Check: Who-Is/I-Am can reveal network topology
        whois = self._build_whois()
        response = self._udp_send_recv(target, port, whois)

        if response and len(response) >= 4 and response[0] == BVLC_TYPE:
            result.vulnerabilities.append(
                Vulnerability(
                    title="BACnet device responds to Who-Is discovery",
                    severity=Severity.LOW,
                    protocol=self.PROTOCOL_NAME,
                    target=target,
                    port=port,
                    description=(
                        "Device responds to BACnet Who-Is broadcasts, revealing its "
                        "presence, instance number, vendor, and capabilities."
                    ),
                    remediation=(
                        "Restrict Who-Is handling to trusted sources if possible. "
                        "Monitor for unauthorized discovery activity."
                    ),
                )
            )

        return result
