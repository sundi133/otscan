"""Tests for OTScan core functionality."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from otscan.protocols.base import (
    BaseProtocolScanner,
    DeviceInfo,
    ScanMode,
    ScanResult,
    Severity,
    Vulnerability,
)
from otscan.protocols.modbus import ModbusScanner
from otscan.protocols.dnp3 import DNP3Scanner
from otscan.protocols.opcua import OPCUAScanner
from otscan.protocols.bacnet import BACnetScanner
from otscan.protocols.ethernetip import EtherNetIPScanner
from otscan.protocols.s7comm import S7CommScanner
from otscan.protocols.hartip import HARTIPScanner
from otscan.protocols.iec61850 import IEC61850Scanner
from otscan.protocols.profinet import ProfinetScanner
from otscan.protocols.iec104 import IEC104Scanner
from otscan.protocols.fins import FINSScanner
from otscan.protocols.codesys import CODESYSScanner
from otscan.protocols.niagara_fox import NiagaraFoxScanner
from otscan.protocols import ALL_SCANNERS
from otscan.discovery.network import expand_targets, OT_PORTS
from otscan.scanner import OTScanner, OTScanResult, ScanSummary
from otscan.reporting.report import scan_result_to_dict
from otscan.credentials.database import (
    SNMP_COMMUNITIES,
    DEFAULT_CREDENTIALS,
    get_credentials_for_vendor,
    get_credentials_for_port,
    get_credentials_for_protocol,
)
from otscan.credentials.checker import CredentialChecker
from otscan.cve.database import lookup_cves, get_all_cves_for_vendor, CVE_DATABASE
from otscan.services.detector import ServiceDetector, SERVICE_PORTS
from otscan.wireless.rf_protocols import (
    OT_WIRELESS_PROTOCOLS,
    generate_rf_assessment,
    get_rf_protocol_info,
)


# --- Data model tests ---

class TestDataModels:
    def test_device_info_defaults(self):
        device = DeviceInfo(ip="192.168.1.1", port=502, protocol="Modbus TCP")
        assert device.ip == "192.168.1.1"
        assert device.port == 502
        assert device.vendor == "Unknown"
        assert device.model == "Unknown"
        assert device.firmware == "Unknown"
        assert device.metadata == {}

    def test_vulnerability_creation(self):
        vuln = Vulnerability(
            title="Test vuln",
            severity=Severity.HIGH,
            protocol="Modbus TCP",
            target="192.168.1.1",
            port=502,
            description="Test description",
            remediation="Fix it",
            cve="CVE-2024-1234",
        )
        assert vuln.severity == Severity.HIGH
        assert vuln.cve == "CVE-2024-1234"

    def test_scan_result_defaults(self):
        result = ScanResult(target="10.0.0.1", port=502, protocol="Modbus TCP")
        assert not result.is_open
        assert not result.is_identified
        assert result.device is None
        assert result.vulnerabilities == []
        assert result.error is None

    def test_scan_mode_enum(self):
        assert ScanMode.PASSIVE.value == "passive"
        assert ScanMode.SAFE.value == "safe"
        assert ScanMode.ACTIVE.value == "active"

    def test_severity_enum(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


# --- Protocol scanner tests ---

class TestAllScannersRegistered:
    def test_all_scanners_list(self):
        assert len(ALL_SCANNERS) == 13

    def test_all_scanners_have_required_attributes(self):
        for scanner_cls in ALL_SCANNERS:
            scanner = scanner_cls()
            assert scanner.PROTOCOL_NAME != ""
            assert scanner.DEFAULT_PORT > 0
            assert scanner.DESCRIPTION != ""

    def test_all_scanners_inherit_base(self):
        for scanner_cls in ALL_SCANNERS:
            assert issubclass(scanner_cls, BaseProtocolScanner)


class TestModbusScanner:
    def test_init(self):
        scanner = ModbusScanner()
        assert scanner.PROTOCOL_NAME == "Modbus TCP"
        assert scanner.DEFAULT_PORT == 502

    def test_build_mbap(self):
        pdu = b"\x03\x00\x00\x00\x01"
        frame = ModbusScanner._build_mbap(1, 0, pdu)
        # MBAP header: transaction(2) + protocol(2) + length(2) + unit(1)
        assert len(frame) == 7 + len(pdu)
        trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", frame[:7])
        assert trans_id == 1
        assert proto_id == 0
        assert length == len(pdu) + 1
        assert unit_id == 0

    def test_build_read_device_id(self):
        frame = ModbusScanner._build_read_device_id_request(unit_id=1)
        assert len(frame) > 7
        # Check function code in PDU
        assert frame[7] == 0x2B  # FC Read Device ID

    def test_build_report_slave_id(self):
        frame = ModbusScanner._build_report_slave_id_request(unit_id=0)
        assert frame[7] == 0x11  # FC Report Slave ID

    def test_build_read_holding_registers(self):
        frame = ModbusScanner._build_read_holding_registers(0, 0, 10)
        assert frame[7] == 0x03  # FC Read Holding Registers

    def test_probe_no_connection(self):
        scanner = ModbusScanner(timeout=0.1)
        result = scanner.probe("192.0.2.1", 502)  # RFC 5737 test address
        assert not result.is_open

    def test_parse_device_id_response(self):
        """Test FC 0x2B response parsing correctly extracts vendor/product/revision."""
        scanner = ModbusScanner()
        # Build a realistic MEI response like the simulator sends
        objects = (
            b"\x00\x05OTSim"  # object 0: vendor_name
            b"\x01\x06SimPLC"  # object 1: product_code
            b"\x02\x031.0"  # object 2: major_minor_revision
        )
        # PDU: FC(0x2B) + MEI(0x0E) + ReadDevIdCode(0x01) + Conformity(0x01)
        #      + MoreFollows(0x00) + NextObjId(0x00) + NumObjects(0x03) + objects
        pdu = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x03]) + objects
        # MBAP header: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
        mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 0)
        data = mbap + pdu

        info = scanner._parse_device_id_response(data)
        assert info["vendor_name"] == "OTSim"
        assert info["product_code"] == "SimPLC"
        assert info["major_minor_revision"] == "1.0"

    def test_identify_extracts_device_info(self):
        """Test that identify() populates DeviceInfo from FC 0x2B response."""
        scanner = ModbusScanner(timeout=0.1)
        # Build FC 0x2B response
        objects = (
            b"\x00\x07Siemens"  # vendor
            b"\x01\x03S7-"  # product code
            b"\x02\x055.4.0"  # revision
            b"\x04\x08S7-1200F"  # product name (obj 0x04)
        )
        pdu = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x04]) + objects
        mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 0)
        fc2b_response = mbap + pdu

        # FC 0x11 Report Slave ID - exception response (not supported)
        slave_pdu = bytes([0x91, 0x01])  # exception
        slave_mbap = struct.pack(">HHHB", 2, 0, len(slave_pdu) + 1, 0)
        slave_response = slave_mbap + slave_pdu

        scanner._tcp_send_recv = MagicMock(side_effect=[fc2b_response, slave_response])
        result = scanner.identify("10.0.0.1", 502)
        assert result.is_identified
        assert result.device.vendor == "Siemens"
        assert result.device.model == "S7-1200F"
        assert result.device.firmware == "5.4.0"

    def test_assess_returns_vulnerabilities(self):
        scanner = ModbusScanner(timeout=0.1)
        # Mock _tcp_send_recv to return None (no connection)
        scanner._tcp_send_recv = MagicMock(return_value=None)
        result = scanner.assess("10.0.0.1", 502)
        # Should always report inherent Modbus vulnerabilities
        assert len(result.vulnerabilities) >= 2
        titles = [v.title for v in result.vulnerabilities]
        assert any("authentication" in t.lower() for t in titles)
        assert any("unencrypted" in t.lower() for t in titles)


class TestDNP3Scanner:
    def test_init(self):
        scanner = DNP3Scanner()
        assert scanner.PROTOCOL_NAME == "DNP3"
        assert scanner.DEFAULT_PORT == 20000

    def test_build_data_link_frame(self):
        frame = DNP3Scanner._build_data_link_frame(1, 3, 0x09)
        assert frame[0:2] == b"\x05\x64"  # DNP3 start bytes

    def test_is_dnp3_response(self):
        scanner = DNP3Scanner()
        assert scanner._is_dnp3_response(b"\x05\x64" + b"\x00" * 8)
        assert not scanner._is_dnp3_response(b"\x00\x00" + b"\x00" * 8)
        assert not scanner._is_dnp3_response(b"\x05")

    def test_assess_returns_vulnerabilities(self):
        scanner = DNP3Scanner(timeout=0.1)
        scanner._tcp_send_recv = MagicMock(return_value=None)
        result = scanner.assess("10.0.0.1", 20000)
        assert len(result.vulnerabilities) >= 2


class TestOPCUAScanner:
    def test_init(self):
        scanner = OPCUAScanner()
        assert scanner.PROTOCOL_NAME == "OPC UA"
        assert scanner.DEFAULT_PORT == 4840

    def test_build_hello(self):
        hello = OPCUAScanner._build_hello("opc.tcp://test:4840")
        assert hello[0:3] == b"HEL"
        assert hello[3:4] == b"F"

    def test_parse_acknowledge(self):
        scanner = OPCUAScanner()
        # Build a mock ACK response
        body = struct.pack("<IIIII", 0, 65535, 65535, 0, 0)
        msg = b"ACK" + b"F" + struct.pack("<I", 8 + len(body)) + body
        info = scanner._parse_acknowledge(msg)
        assert info.get("protocol_version") == 0
        assert info.get("receive_buffer_size") == 65535

    def test_parse_error_response(self):
        scanner = OPCUAScanner()
        msg = b"ERR" + b"F" + struct.pack("<II", 12, 0x80010000)
        info = scanner._parse_acknowledge(msg)
        assert info.get("error") is True


class TestBACnetScanner:
    def test_init(self):
        scanner = BACnetScanner()
        assert scanner.PROTOCOL_NAME == "BACnet/IP"
        assert scanner.DEFAULT_PORT == 47808

    def test_build_whois(self):
        whois = BACnetScanner._build_whois()
        assert whois[0] == 0x81  # BVLC type
        assert whois[1] == 0x0B  # Original broadcast

    def test_assess_returns_vulnerabilities(self):
        scanner = BACnetScanner(timeout=0.1)
        scanner._udp_send_recv = MagicMock(return_value=None)
        result = scanner.assess("10.0.0.1", 47808)
        assert len(result.vulnerabilities) >= 2


class TestEtherNetIPScanner:
    def test_init(self):
        scanner = EtherNetIPScanner()
        assert scanner.PROTOCOL_NAME == "EtherNet/IP"
        assert scanner.DEFAULT_PORT == 44818

    def test_build_list_identity(self):
        frame = EtherNetIPScanner._build_list_identity()
        cmd = struct.unpack("<H", frame[0:2])[0]
        assert cmd == 0x0063  # ListIdentity

    def test_build_list_services(self):
        frame = EtherNetIPScanner._build_list_services()
        cmd = struct.unpack("<H", frame[0:2])[0]
        assert cmd == 0x0004  # ListServices


class TestS7CommScanner:
    def test_init(self):
        scanner = S7CommScanner()
        assert scanner.PROTOCOL_NAME == "S7comm"
        assert scanner.DEFAULT_PORT == 102
        assert scanner.scanners if hasattr(scanner, 'scanners') else True

    def test_build_tpkt(self):
        data = b"\x01\x02\x03"
        tpkt = S7CommScanner._build_tpkt(data)
        assert tpkt[0] == 0x03  # TPKT version
        length = struct.unpack("!H", tpkt[2:4])[0]
        assert length == len(data) + 4

    def test_build_cotp_cr(self):
        frame = S7CommScanner._build_cotp_cr()
        assert frame[0] == 0x03  # TPKT version
        assert (frame[5] & 0xF0) == 0xE0  # COTP CR

    def test_assess_returns_vulnerabilities(self):
        scanner = S7CommScanner(timeout=0.1)
        scanner._tcp_connect = MagicMock(return_value=None)
        result = scanner.assess("10.0.0.1", 102)
        assert len(result.vulnerabilities) >= 2
        # S7comm should report critical vulnerability
        severities = [v.severity for v in result.vulnerabilities]
        assert Severity.CRITICAL in severities


class TestHARTIPScanner:
    def test_init(self):
        scanner = HARTIPScanner()
        assert scanner.PROTOCOL_NAME == "HART-IP"
        assert scanner.DEFAULT_PORT == 5094

    def test_build_hart_ip_header(self):
        header = HARTIPScanner._build_hart_ip_header(payload=b"\x01\x02")
        parsed = struct.unpack("!BBBBHH", header[:8])
        assert parsed[0] == 1  # version
        assert parsed[5] == 10  # byte_count = 8 + 2


class TestIEC61850Scanner:
    def test_init(self):
        scanner = IEC61850Scanner()
        assert scanner.PROTOCOL_NAME == "IEC 61850 (MMS)"
        assert scanner.DEFAULT_PORT == 102

    def test_build_cotp_cr(self):
        frame = IEC61850Scanner._build_cotp_cr()
        assert frame[0] == 0x03  # TPKT version

    def test_assess_returns_vulnerabilities(self):
        scanner = IEC61850Scanner(timeout=0.1)
        scanner._tcp_connect = MagicMock(return_value=None)
        result = scanner.assess("10.0.0.1", 102)
        assert len(result.vulnerabilities) >= 2
        severities = [v.severity for v in result.vulnerabilities]
        assert Severity.CRITICAL in severities


class TestProfinetScanner:
    def test_init(self):
        scanner = ProfinetScanner()
        assert scanner.PROTOCOL_NAME == "PROFINET"
        assert scanner.DEFAULT_PORT == 34964

    def test_build_dcp_identify(self):
        frame = ProfinetScanner._build_dcp_identify_all()
        assert frame[0] == 0x05  # DCP Identify service ID

    def test_assess_returns_vulnerabilities(self):
        scanner = ProfinetScanner(timeout=0.1)
        scanner._udp_send_recv = MagicMock(return_value=None)
        result = scanner.assess("10.0.0.1", 34964)
        assert len(result.vulnerabilities) >= 2


# --- Network discovery tests ---

class TestExpandTargets:
    def test_single_ip(self):
        targets = expand_targets("192.168.1.1")
        assert targets == ["192.168.1.1"]

    def test_cidr_24(self):
        targets = expand_targets("192.168.1.0/30")
        assert len(targets) == 2
        assert "192.168.1.1" in targets
        assert "192.168.1.2" in targets

    def test_ip_range(self):
        targets = expand_targets("192.168.1.1-192.168.1.5")
        assert len(targets) == 5
        assert "192.168.1.1" in targets
        assert "192.168.1.5" in targets

    def test_ip_range_short(self):
        targets = expand_targets("192.168.1.1-5")
        assert len(targets) == 5

    def test_comma_separated(self):
        targets = expand_targets("10.0.0.1,10.0.0.2,10.0.0.3")
        assert len(targets) == 3

    def test_empty_string(self):
        targets = expand_targets("")
        assert targets == []

    def test_ot_ports_defined(self):
        assert 502 in OT_PORTS  # Modbus
        assert 44818 in OT_PORTS  # EtherNet/IP
        assert 102 in OT_PORTS  # S7comm
        assert 47808 in OT_PORTS  # BACnet
        assert 20000 in OT_PORTS  # DNP3
        assert 4840 in OT_PORTS  # OPC UA
        assert 5094 in OT_PORTS  # HART-IP
        assert 34964 in OT_PORTS  # PROFINET


# --- Scanner orchestrator tests ---

class TestOTScanner:
    def test_init_default(self):
        scanner = OTScanner()
        assert scanner.mode == ScanMode.SAFE
        assert len(scanner.scanners) == 13

    def test_init_filtered_protocols(self):
        scanner = OTScanner(protocols=["Modbus TCP", "S7comm"])
        assert len(scanner.scanners) == 2

    def test_list_protocols(self):
        scanner = OTScanner()
        protocols = scanner.list_protocols()
        assert len(protocols) == 13
        names = [p["name"] for p in protocols]
        assert "Modbus TCP" in names
        assert "S7comm" in names
        assert "OPC UA" in names
        assert "BACnet/IP" in names
        assert "EtherNet/IP" in names
        assert "DNP3" in names
        assert "HART-IP" in names
        assert "IEC 61850 (MMS)" in names
        assert "PROFINET" in names
        assert "IEC 60870-5-104" in names
        assert "FINS" in names
        assert "CODESYS" in names
        assert "Niagara Fox" in names

    def test_scan_single_unknown_protocol(self):
        scanner = OTScanner()
        result = scanner.scan_single("10.0.0.1", 502, "Unknown Protocol")
        assert result is None


# --- Reporting tests ---

class TestReporting:
    def test_scan_result_to_dict(self):
        from otscan.discovery.network import HostInfo

        result = OTScanResult()
        result.scan_mode = "safe"
        result.summary = ScanSummary(
            targets_scanned=1,
            hosts_alive=1,
            devices_identified=1,
            total_vulnerabilities=1,
            high_count=1,
            scan_duration=1.5,
            protocols_found=["Modbus TCP"],
        )

        host = HostInfo(ip="10.0.0.1", is_alive=True, open_ports=[502])
        scan_result = ScanResult(
            target="10.0.0.1",
            port=502,
            protocol="Modbus TCP",
            is_open=True,
            is_identified=True,
            device=DeviceInfo(
                ip="10.0.0.1",
                port=502,
                protocol="Modbus TCP",
                vendor="Schneider Electric",
                model="M340",
            ),
            vulnerabilities=[
                Vulnerability(
                    title="No auth",
                    severity=Severity.HIGH,
                    protocol="Modbus TCP",
                    target="10.0.0.1",
                    port=502,
                    description="Test",
                    remediation="Fix",
                )
            ],
        )
        host.scan_results = [scan_result]
        result.hosts = [host]

        data = scan_result_to_dict(result)
        assert data["summary"]["targets_scanned"] == 1
        assert data["summary"]["hosts_alive"] == 1
        assert len(data["hosts"]) == 1
        assert data["hosts"][0]["ip"] == "10.0.0.1"
        assert len(data["hosts"][0]["devices"]) == 1
        assert data["hosts"][0]["devices"][0]["vendor"] == "Schneider Electric"
        assert len(data["hosts"][0]["vulnerabilities"]) == 1

    def test_scan_result_to_dict_empty(self):
        result = OTScanResult()
        result.scan_mode = "safe"
        result.summary = ScanSummary()
        result.hosts = []

        data = scan_result_to_dict(result)
        assert data["summary"]["targets_scanned"] == 0
        assert data["hosts"] == []


# --- Base protocol scanner tests ---

class TestBaseProtocolScanner:
    def test_safe_unpack(self):
        data = struct.pack(">HH", 0x1234, 0x5678)
        result = BaseProtocolScanner._safe_unpack(">HH", data)
        assert result == (0x1234, 0x5678)

    def test_safe_unpack_too_short(self):
        data = b"\x01\x02"
        result = BaseProtocolScanner._safe_unpack(">HH", data)
        assert result is None

    def test_safe_unpack_with_offset(self):
        data = b"\x00\x00" + struct.pack(">H", 0xABCD)
        result = BaseProtocolScanner._safe_unpack(">H", data, offset=2)
        assert result == (0xABCD,)


# --- New protocol scanner tests ---

class TestIEC104Scanner:
    def test_init(self):
        scanner = IEC104Scanner()
        assert scanner.PROTOCOL_NAME == "IEC 60870-5-104"
        assert scanner.DEFAULT_PORT == 2404

    def test_build_startdt_act(self):
        frame = IEC104Scanner._build_startdt_act()
        assert frame[0] == 0x68  # IEC 104 start byte
        assert frame[1] == 0x04  # APDU length
        assert frame[2] == 0x07  # STARTDT ACT

    def test_build_testfr_act(self):
        frame = IEC104Scanner._build_testfr_act()
        assert frame[0] == 0x68
        assert frame[2] == 0x43  # TESTFR ACT

    def test_is_iec104_response(self):
        scanner = IEC104Scanner()
        assert scanner._is_iec104_response(b"\x68\x04\x0b\x00\x00\x00")
        assert not scanner._is_iec104_response(b"\x00\x04\x0b\x00\x00\x00")
        assert not scanner._is_iec104_response(b"\x68")

    def test_parse_response_u_format(self):
        scanner = IEC104Scanner()
        # STARTDT CON response
        data = b"\x68\x04\x0b\x00\x00\x00"
        info = scanner._parse_response(data)
        assert info["frame_type"] == "U-format"
        assert info["u_type"] == "STARTDT_CON"

    def test_assess_returns_vulnerabilities(self):
        scanner = IEC104Scanner(timeout=0.1)
        scanner._tcp_send_recv = MagicMock(return_value=None)
        result = scanner.assess("10.0.0.1", 2404)
        assert len(result.vulnerabilities) >= 2
        severities = [v.severity for v in result.vulnerabilities]
        assert Severity.CRITICAL in severities


class TestFINSScanner:
    def test_init(self):
        scanner = FINSScanner()
        assert scanner.PROTOCOL_NAME == "FINS"
        assert scanner.DEFAULT_PORT == 9600

    def test_build_node_address_request(self):
        frame = FINSScanner._build_fins_node_address_request()
        assert frame[0:4] == b"FINS"
        cmd = struct.unpack("!I", frame[8:12])[0]
        assert cmd == 0x00000000  # Node address request

    def test_build_fins_frame(self):
        frame = FINSScanner._build_fins_frame(1, 2, (0x05, 0x01))
        assert frame[0] == 0x80  # ICF
        assert frame[4] == 1  # dest node
        assert frame[7] == 2  # src node
        assert frame[10] == 0x05  # command code MR
        assert frame[11] == 0x01  # command code SR

    def test_assess_returns_vulnerabilities(self):
        scanner = FINSScanner(timeout=0.1)
        scanner._tcp_send_recv = MagicMock(return_value=None)
        result = scanner.assess("10.0.0.1", 9600)
        assert len(result.vulnerabilities) >= 2
        severities = [v.severity for v in result.vulnerabilities]
        assert Severity.CRITICAL in severities


class TestCODESYSScanner:
    def test_init(self):
        scanner = CODESYSScanner()
        assert scanner.PROTOCOL_NAME == "CODESYS"
        assert scanner.DEFAULT_PORT == 2455

    def test_build_discovery_request(self):
        frame = CODESYSScanner._build_discovery_request()
        assert frame[0:2] == b"\xbb\xbb"

    def test_is_codesys_response(self):
        scanner = CODESYSScanner()
        assert scanner._is_codesys_response(b"\xbb\xbb\x00\x00\x01\x01")
        assert not scanner._is_codesys_response(b"\x00\x00")
        assert not scanner._is_codesys_response(b"")

    def test_assess_returns_vulnerabilities(self):
        scanner = CODESYSScanner(timeout=0.1)
        scanner._tcp_send_recv = MagicMock(return_value=None)
        result = scanner.assess("10.0.0.1", 2455)
        assert len(result.vulnerabilities) >= 3
        titles = [v.title for v in result.vulnerabilities]
        assert any("CODESYS V3 runtime exposed" in t for t in titles)
        assert any("default credentials" in t.lower() for t in titles)
        assert any("encryption" in t.lower() for t in titles)


class TestNiagaraFoxScanner:
    def test_init(self):
        scanner = NiagaraFoxScanner()
        assert scanner.PROTOCOL_NAME == "Niagara Fox"
        assert scanner.DEFAULT_PORT == 1911

    def test_build_fox_hello(self):
        hello = NiagaraFoxScanner._build_fox_hello()
        assert b"fox hello" in hello
        assert b"fox.version" in hello

    def test_parse_fox_response(self):
        scanner = NiagaraFoxScanner()
        response = (
            b"fox a 1 -1 fox hello\n"
            b"{\n"
            b"fox.version=s:1.0\n"
            b"hostName=s:JACE-001\n"
            b"osName=s:QNX\n"
            b"}\n"
            b";;;\n"
        )
        info = scanner._parse_fox_response(response)
        assert info.get("fox.version") == "1.0"
        assert info.get("hostName") == "JACE-001"
        assert info.get("osName") == "QNX"
        assert info.get("is_fox") is True

    def test_assess_returns_vulnerabilities(self):
        scanner = NiagaraFoxScanner(timeout=0.1)
        scanner._tcp_send_recv = MagicMock(return_value=None)
        result = scanner.assess("10.0.0.1", 1911)
        assert len(result.vulnerabilities) >= 2
        titles = [v.title for v in result.vulnerabilities]
        assert any("unencrypted" in t.lower() or "1911" in t for t in titles)
        assert any("default credentials" in t.lower() for t in titles)


# --- Credential database tests ---

class TestCredentialDatabase:
    def test_snmp_communities_exist(self):
        assert len(SNMP_COMMUNITIES) >= 5
        assert "public" in SNMP_COMMUNITIES
        assert "private" in SNMP_COMMUNITIES

    def test_default_credentials_not_empty(self):
        assert len(DEFAULT_CREDENTIALS) > 50

    def test_get_credentials_for_vendor_siemens(self):
        creds = get_credentials_for_vendor("Siemens")
        assert len(creds) >= 3
        vendors = {c.vendor for c in creds}
        assert "Siemens" in vendors

    def test_get_credentials_for_vendor_case_insensitive(self):
        creds = get_credentials_for_vendor("siemens")
        assert len(creds) >= 3

    def test_get_credentials_for_port_80(self):
        creds = get_credentials_for_port(80)
        assert len(creds) >= 10

    def test_get_credentials_for_port_22(self):
        creds = get_credentials_for_port(22)
        assert len(creds) >= 3

    def test_get_credentials_for_protocol_vnc(self):
        creds = get_credentials_for_protocol("vnc")
        assert len(creds) >= 3

    def test_get_credentials_for_protocol_mqtt(self):
        creds = get_credentials_for_protocol("mqtt")
        assert len(creds) >= 2

    def test_credential_has_required_fields(self):
        for cred in DEFAULT_CREDENTIALS:
            assert cred.vendor != ""
            assert cred.product != ""
            assert cred.protocol != ""
            assert cred.port > 0


class TestCredentialChecker:
    def test_init(self):
        checker = CredentialChecker(timeout=1.0)
        assert checker.timeout == 1.0

    def test_snmp_get_request_builds_packet(self):
        checker = CredentialChecker(timeout=0.1)
        # Should not crash, just timeout on unreachable target
        result = checker._snmp_get_request("192.0.2.1", 161, "public")
        assert result is False

    def test_check_all_services_empty_ports(self):
        checker = CredentialChecker(timeout=0.1)
        vulns = checker.check_all_services("192.0.2.1", [])
        assert vulns == []


# --- CVE database tests ---

class TestCVEDatabase:
    def test_database_not_empty(self):
        assert len(CVE_DATABASE) >= 20

    def test_lookup_siemens_s7(self):
        cves = lookup_cves("Siemens", "S7-1200")
        assert len(cves) >= 2
        cve_ids = [c.cve_id for c in cves]
        assert any("CVE-2020-15782" in c for c in cve_ids)

    def test_lookup_schneider_modicon(self):
        cves = lookup_cves("Schneider", "M340")
        assert len(cves) >= 1

    def test_lookup_rockwell_controllogix(self):
        cves = lookup_cves("Rockwell", "ControlLogix")
        assert len(cves) >= 2

    def test_lookup_codesys(self):
        cves = lookup_cves("CODESYS", "CODESYS")
        assert len(cves) >= 3

    def test_lookup_unknown_device(self):
        cves = lookup_cves("UnknownVendor", "UnknownModel")
        assert len(cves) == 0

    def test_get_all_cves_for_vendor(self):
        cves = get_all_cves_for_vendor("Siemens")
        assert len(cves) >= 4

    def test_cve_entries_have_required_fields(self):
        for entry in CVE_DATABASE:
            assert entry.cve_id.startswith("CVE-")
            assert entry.vendor != ""
            assert entry.title != ""
            assert entry.severity in Severity


# --- Service detection tests ---

class TestServiceDetector:
    def test_init(self):
        detector = ServiceDetector(timeout=1.0)
        assert detector.timeout == 1.0

    def test_service_ports_defined(self):
        assert 21 in SERVICE_PORTS
        assert 22 in SERVICE_PORTS
        assert 23 in SERVICE_PORTS
        assert 80 in SERVICE_PORTS
        assert 161 in SERVICE_PORTS
        assert 443 in SERVICE_PORTS
        assert 1883 in SERVICE_PORTS
        assert 3389 in SERVICE_PORTS
        assert 5900 in SERVICE_PORTS

    def test_assess_services_telnet(self):
        detector = ServiceDetector(timeout=0.1)
        vulns = detector.assess_services("10.0.0.1", [23])
        assert len(vulns) == 1
        assert vulns[0].protocol == "Telnet"
        assert vulns[0].severity == Severity.HIGH

    def test_assess_services_ftp(self):
        detector = ServiceDetector(timeout=0.1)
        vulns = detector.assess_services("10.0.0.1", [21])
        assert len(vulns) == 1
        assert vulns[0].protocol == "FTP"

    def test_assess_services_rdp(self):
        detector = ServiceDetector(timeout=0.1)
        vulns = detector.assess_services("10.0.0.1", [3389])
        assert len(vulns) == 1
        assert vulns[0].protocol == "RDP"

    def test_assess_services_mqtt(self):
        detector = ServiceDetector(timeout=0.1)
        vulns = detector.assess_services("10.0.0.1", [1883])
        assert len(vulns) == 1
        assert vulns[0].protocol == "MQTT"

    def test_assess_services_http_unencrypted(self):
        detector = ServiceDetector(timeout=0.1)
        vulns = detector.assess_services("10.0.0.1", [80])
        assert len(vulns) == 1
        assert vulns[0].protocol == "HTTP"

    def test_assess_services_database(self):
        detector = ServiceDetector(timeout=0.1)
        vulns = detector.assess_services("10.0.0.1", [1433, 3306])
        assert len(vulns) == 2

    def test_assess_services_multiple_ports(self):
        detector = ServiceDetector(timeout=0.1)
        vulns = detector.assess_services("10.0.0.1", [21, 23, 80, 1883, 3389])
        assert len(vulns) == 5

    def test_assess_services_no_findings_for_ics_ports(self):
        detector = ServiceDetector(timeout=0.1)
        vulns = detector.assess_services("10.0.0.1", [502, 44818, 102])
        assert len(vulns) == 0


# --- Wireless/RF protocol tests ---

class TestWirelessProtocols:
    def test_protocols_defined(self):
        assert len(OT_WIRELESS_PROTOCOLS) >= 7

    def test_protocol_names(self):
        names = [p.name for p in OT_WIRELESS_PROTOCOLS]
        assert any("WirelessHART" in n for n in names)
        assert any("Zigbee" in n for n in names)
        assert any("BLE" in n or "Bluetooth" in n for n in names)
        assert any("Wi-Fi" in n for n in names)
        assert any("LoRa" in n for n in names)
        assert any("Z-Wave" in n for n in names)

    def test_protocol_has_required_fields(self):
        for proto in OT_WIRELESS_PROTOCOLS:
            assert proto.name != ""
            assert proto.encryption != ""
            assert proto.authentication != ""
            assert len(proto.known_attacks) > 0
            assert len(proto.vulnerabilities) > 0

    def test_generate_rf_assessment_no_protocols(self):
        vulns = generate_rf_assessment(None)
        assert len(vulns) == 1
        assert vulns[0].severity == Severity.INFO

    def test_generate_rf_assessment_specific(self):
        vulns = generate_rf_assessment(["Zigbee / Zigbee Pro"])
        assert len(vulns) >= 1

    def test_get_rf_protocol_info(self):
        proto = get_rf_protocol_info("WirelessHART")
        assert proto is not None
        assert "HART" in proto.name

    def test_get_rf_protocol_info_not_found(self):
        proto = get_rf_protocol_info("NonexistentProtocol")
        assert proto is None


# --- Updated OT_PORTS tests ---

class TestExpandedOTPorts:
    def test_new_ics_ports(self):
        assert 2404 in OT_PORTS  # IEC 104
        assert 9600 in OT_PORTS  # FINS
        assert 2455 in OT_PORTS  # CODESYS
        assert 1911 in OT_PORTS  # Niagara Fox
        assert 4911 in OT_PORTS  # Niagara Fox TLS
        assert 5007 in OT_PORTS  # MELSEC-Q

    def test_service_ports(self):
        assert 21 in OT_PORTS  # FTP
        assert 22 in OT_PORTS  # SSH
        assert 23 in OT_PORTS  # Telnet
        assert 80 in OT_PORTS  # HTTP
        assert 161 in OT_PORTS  # SNMP
        assert 443 in OT_PORTS  # HTTPS
        assert 1883 in OT_PORTS  # MQTT
        assert 3389 in OT_PORTS  # RDP
        assert 5900 in OT_PORTS  # VNC
