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
from otscan.protocols import ALL_SCANNERS
from otscan.discovery.network import expand_targets, OT_PORTS
from otscan.scanner import OTScanner, OTScanResult, ScanSummary
from otscan.reporting.report import scan_result_to_dict


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
        assert len(ALL_SCANNERS) == 9

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
        assert len(scanner.scanners) == 9

    def test_init_filtered_protocols(self):
        scanner = OTScanner(protocols=["Modbus TCP", "S7comm"])
        assert len(scanner.scanners) == 2

    def test_list_protocols(self):
        scanner = OTScanner()
        protocols = scanner.list_protocols()
        assert len(protocols) == 9
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
