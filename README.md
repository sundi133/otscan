# OTScan

OT/ICS/SCADA Network Security Scanner — discover, identify, and assess industrial control system devices and their security posture.

## Features

### Protocol Support (13 protocols)

| Protocol | Port | Description | Probe | Identify | Assess |
|----------|------|-------------|:-----:|:--------:|:------:|
| Modbus TCP | 502 | Industrial SCADA protocol for PLC/RTU communication | Yes | Yes | Yes |
| DNP3 | 20000 | Distributed Network Protocol for utility SCADA | Yes | Yes | Yes |
| OPC UA | 4840 | Industrial interoperability standard | Yes | Yes | Yes |
| BACnet/IP | 47808 | Building automation and control | Yes | Yes | Yes |
| EtherNet/IP | 44818 | CIP-based industrial Ethernet (Rockwell/Allen-Bradley) | Yes | Yes | Yes |
| S7comm | 102 | Siemens SIMATIC S7 PLC communication | Yes | Yes | Yes |
| HART-IP | 5094 | Field instrument communication | Yes | Yes | Yes |
| IEC 61850 (MMS) | 102 | Substation automation standard | Yes | Yes | Yes |
| PROFINET | 34964 | Industrial Ethernet (Siemens/PI) | Yes | Yes | Yes |
| IEC 60870-5-104 | 2404 | Power grid telecontrol (substations, RTUs) | Yes | Yes | Yes |
| FINS | 9600 | Omron PLC communication protocol | Yes | Yes | Yes |
| CODESYS | 2455 | CODESYS V3 PLC runtime (350+ device types) | Yes | Yes | Yes |
| Niagara Fox | 1911 | Tridium/Honeywell building automation | Yes | Yes | Yes |

### Default Credential Testing

Checks 60+ known default credentials across OT device vendors (active mode):

| Category | What's Checked |
|----------|---------------|
| SNMP | 20 common community strings (public, private, etc.) |
| Web HMIs | Default admin passwords for Siemens, Schneider, Rockwell, ABB, Honeywell, Moxa, Omron, etc. |
| VNC | No-auth / weak password access to HMI remote desktops |
| FTP | Anonymous login (firmware/config file access) |
| Telnet | Open telnet (plaintext credentials) |
| SSH | Default root/admin passwords |
| MQTT | Unauthenticated broker connections |

### CVE Mapping

Automatically matches identified devices to known ICS-CERT vulnerabilities:

- Siemens S7-1200/1500 (CVE-2020-15782, CVE-2022-38465, etc.)
- Schneider Modicon M340/M580 (CVE-2021-22779)
- Rockwell ControlLogix/CompactLogix (CVE-2022-1161, CVE-2023-3595)
- CODESYS V3 runtime (CVE-2022-31806, CVE-2021-29241)
- Omron CJ/NJ series (CVE-2022-34151, CVE-2023-0811)
- ABB, GE, Tridium, Moxa, and more

### Service Detection (37+ ports)

Scans for non-ICS services commonly found on OT networks:

| Service | Port | Risk |
|---------|------|------|
| FTP | 21 | Plaintext credentials, firmware access |
| SSH | 22 | Default credentials |
| Telnet | 23 | Plaintext credentials |
| HTTP/HTTPS | 80/443/8080 | Default web HMI credentials |
| SNMP | 161 | Default community strings |
| MQTT | 1883/8883 | Unauthenticated pub/sub |
| RDP | 3389 | Remote desktop to operator stations |
| VNC | 5900 | No-auth HMI access |
| Databases | 1433/3306/5432 | Historian/SCADA data exposure |

### Wireless/RF Protocol Awareness

Knowledge base for 8 wireless protocols found in OT environments:

| Protocol | Band | Common In |
|----------|------|-----------|
| WirelessHART (IEC 62591) | 2.4 GHz | Process control sensors |
| ISA100.11a (IEC 62734) | 2.4 GHz | Industrial wireless |
| Zigbee | 2.4 GHz | Building automation |
| Z-Wave | 900 MHz | Building/HVAC |
| BLE | 2.4 GHz | Sensor data, asset tracking |
| LoRaWAN | Sub-GHz | Remote monitoring, utilities |
| Wi-Fi | 2.4/5 GHz | HMI tablets, cameras |
| Cellular (4G/5G) | UHF | Remote SCADA sites |

Includes known attacks, vulnerabilities, and required detection hardware for each.

### Capabilities

| Capability | Description |
|-----------|-------------|
| Network Discovery | Auto-discover OT/ICS devices across subnets via 37+ port scan + protocol probes |
| Device Identification | Extract vendor, model, firmware, serial number via protocol-specific queries |
| Vulnerability Assessment | Detect missing authentication, unencrypted protocols, exposed services |
| Default Credential Testing | Test SNMP, HTTP, VNC, FTP, Telnet, SSH, MQTT for factory defaults (active mode) |
| CVE Mapping | Match identified devices to known ICS-CERT vulnerabilities |
| Service Detection | Find exposed FTP, Telnet, RDP, VNC, MQTT, databases on OT networks |
| Wireless/RF Awareness | Knowledge base for WirelessHART, Zigbee, BLE, LoRa, Wi-Fi assessment |
| Safe Scanning Mode | Non-destructive read-only probes safe for production OT environments |
| Multi-format Reporting | JSON, HTML, and CSV report generation |

### Security Checks

- No authentication on industrial protocols (Modbus, DNP3, BACnet, S7comm, FINS, IEC 104, CODESYS)
- Unencrypted protocol traffic
- Unauthenticated session establishment (EtherNet/IP CIP, S7comm, MMS, IEC 104 STARTDT)
- Default credentials on web HMIs, VNC, FTP, Telnet, SSH, SNMP, MQTT
- SNMP default community strings (public/private)
- VNC with no authentication
- FTP anonymous access to firmware/configs
- Known CVEs matched to identified devices (CVSS scores)
- Device identity information disclosure
- Exposed databases (MSSQL, MySQL, PostgreSQL, MongoDB)
- GOOSE/SV multicast injection risk (IEC 61850)
- DCP configuration exposure (PROFINET)
- CODESYS default credentials (CVE-2022-31806)
- Niagara Fox plaintext protocol exposure

## Quick Start

### Prerequisites

- Python 3.9+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/sundi133/otscan.git
cd otscan

# Install core package
pip install -e .

# Or install with all optional protocol libraries
pip install -e ".[full]"

# For development (includes pytest, mypy, ruff)
pip install -e ".[dev]"
```

### Verify Installation

```bash
# Check CLI is available
otscan --version

# List all supported protocols
otscan list-protocols
```

## Usage

### Network Scan

```bash
# Scan a single host
otscan scan 192.168.1.1

# Scan a subnet
otscan scan 192.168.1.0/24

# Scan an IP range
otscan scan 192.168.1.1-192.168.1.50

# Comma-separated targets
otscan scan 10.0.0.1,10.0.0.2,10.0.0.3

# Scan specific protocols only
otscan scan 10.0.0.0/24 --protocol "Modbus TCP" --protocol "S7comm"

# Active mode scan with HTML report
otscan scan 10.0.0.1 --mode active --format html -o report.html

# Passive mode (port scanning only, no protocol probes)
otscan scan 10.0.0.0/24 --mode passive

# Custom timeout and worker count
otscan scan 10.0.0.0/24 --timeout 10 --workers 20

# CSV output
otscan scan 192.168.1.0/24 --format csv -o vulnerabilities.csv
```

### Single Protocol Probe

```bash
# Probe Modbus TCP
otscan probe 192.168.1.1 502 "Modbus TCP"

# Probe Siemens S7
otscan probe 10.0.0.1 102 S7comm

# Probe EtherNet/IP
otscan probe 10.0.0.5 44818 "EtherNet/IP"

# Probe BACnet
otscan probe 10.0.0.10 47808 "BACnet/IP"

# Probe with active mode and longer timeout
otscan probe 10.0.0.1 502 "Modbus TCP" --mode active --timeout 10
```

### List Supported Protocols

```bash
otscan list-protocols
```

### Using as a Python Library

```python
from otscan.scanner import OTScanner
from otscan.protocols.base import ScanMode

# Create scanner
scanner = OTScanner(
    mode=ScanMode.SAFE,
    timeout=5.0,
    protocols=["Modbus TCP", "S7comm"],
)

# Scan a target
result = scanner.scan("192.168.1.0/24")

# Access results
print(f"Hosts found: {result.summary.hosts_alive}")
print(f"Devices identified: {result.summary.devices_identified}")
print(f"Vulnerabilities: {result.summary.total_vulnerabilities}")

for host in result.hosts:
    for sr in host.scan_results:
        if sr.device:
            print(f"  {sr.device.ip}:{sr.device.port} - {sr.device.vendor} {sr.device.model}")
        for vuln in sr.vulnerabilities:
            print(f"    [{vuln.severity.value}] {vuln.title}")

# Probe a single target
result = scanner.scan_single("192.168.1.1", 502, "Modbus TCP")
```

### CLI Options Reference

```
otscan scan [OPTIONS] TARGET

Options:
  --mode [passive|safe|active]  Scanning mode (default: safe)
  --timeout FLOAT               Connection timeout in seconds (default: 5.0)
  --workers INTEGER             Max concurrent workers (default: 10)
  --protocol TEXT               Specific protocol(s) to scan (repeatable)
  -o, --output TEXT             Output file path
  --format [json|html|csv]      Output format (default: json)
  --no-banner                   Suppress the banner

otscan probe [OPTIONS] TARGET PORT PROTOCOL

Options:
  --timeout FLOAT               Connection timeout in seconds (default: 5.0)
  --mode [passive|safe|active]  Scanning mode (default: safe)
```

## Scan Modes

| Mode | Description |
|------|-------------|
| `passive` | Port scanning only, no protocol probes |
| `safe` (default) | Read-only protocol probes, no write operations |
| `active` | Full assessment including write-capability checks |

## Report Formats

- **JSON** — Machine-readable structured data (default)
- **HTML** — Visual report with severity breakdown and device details
- **CSV** — Spreadsheet-compatible vulnerability listing

## Architecture

```
otscan/
├── cli.py                  # Click-based CLI interface
├── scanner.py              # Main orchestrator (integrates all modules)
├── protocols/
│   ├── base.py             # Base scanner class + data models
│   ├── modbus.py           # Modbus TCP scanner
│   ├── dnp3.py             # DNP3 scanner
│   ├── opcua.py            # OPC UA scanner
│   ├── bacnet.py           # BACnet/IP scanner
│   ├── ethernetip.py       # EtherNet/IP scanner
│   ├── s7comm.py           # Siemens S7comm scanner
│   ├── hartip.py           # HART-IP scanner
│   ├── iec61850.py         # IEC 61850 / MMS scanner
│   ├── profinet.py         # PROFINET DCP scanner
│   ├── iec104.py           # IEC 60870-5-104 scanner
│   ├── fins.py             # Omron FINS scanner
│   ├── codesys.py          # CODESYS V3 scanner
│   └── niagara_fox.py      # Niagara Fox scanner
├── credentials/
│   ├── database.py         # 60+ default credential entries
│   └── checker.py          # SNMP, FTP, VNC, HTTP, MQTT credential testing
├── cve/
│   └── database.py         # CVE mapping for identified OT devices
├── services/
│   └── detector.py         # HTTP, VNC, Telnet, FTP, SSH, RDP, MQTT detection
├── wireless/
│   └── rf_protocols.py     # WirelessHART, Zigbee, BLE, LoRa, Wi-Fi knowledge base
├── discovery/
│   └── network.py          # Network discovery + 37-port scan
├── reporting/
│   └── report.py           # JSON/HTML/CSV report generation
└── utils/
    └── helpers.py           # Utility functions
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=otscan --cov-report=term-missing

# Run a specific test class
pytest tests/test_scanner.py::TestModbusScanner -v

# Run a single test
pytest tests/test_scanner.py::TestExpandTargets::test_cidr_24 -v
```

## License

MIT
