# OTScan

OT/ICS/SCADA Network Security Scanner — discover, identify, and assess industrial control system devices and their security posture.

## Features

### Protocol Support

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

### Capabilities

| Capability | Description |
|-----------|-------------|
| Network Discovery | Auto-discover OT/ICS devices across subnets via port scanning + protocol probes |
| Device Identification | Extract vendor, model, firmware, serial number via protocol-specific queries |
| Vulnerability Assessment | Detect missing authentication, unencrypted protocols, exposed services |
| Safe Scanning Mode | Non-destructive read-only probes safe for production OT environments |
| Multi-format Reporting | JSON, HTML, and CSV report generation |
| Concurrent Scanning | Threaded scanning with configurable parallelism |
| Target Flexibility | Single IP, CIDR ranges, IP ranges, comma-separated lists |

### Security Checks

- No authentication on industrial protocols (Modbus, DNP3, BACnet, S7comm, etc.)
- Unencrypted protocol traffic
- Unauthenticated session establishment (EtherNet/IP CIP, S7comm, MMS)
- Device identity information disclosure
- Broadcast/discovery response exposure
- Diagnostics function access
- GOOSE/SV multicast injection risk (IEC 61850)
- DCP configuration exposure (PROFINET)

## Installation

```bash
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
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

# Scan specific protocols only
otscan scan 10.0.0.0/24 --protocol "Modbus TCP" --protocol "S7comm"

# Active mode scan with HTML report
otscan scan 10.0.0.1 --mode active --format html -o report.html

# Passive mode (no active probes, just port scanning)
otscan scan 10.0.0.0/24 --mode passive
```

### Single Protocol Probe

```bash
# Probe Modbus TCP
otscan probe 192.168.1.1 502 "Modbus TCP"

# Probe Siemens S7
otscan probe 10.0.0.1 102 S7comm

# Probe EtherNet/IP
otscan probe 10.0.0.5 44818 "EtherNet/IP"
```

### List Supported Protocols

```bash
otscan list-protocols
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
├── cli.py              # Click-based CLI interface
├── scanner.py          # Main orchestrator
├── protocols/
│   ├── base.py         # Base scanner class + data models
│   ├── modbus.py       # Modbus TCP scanner
│   ├── dnp3.py         # DNP3 scanner
│   ├── opcua.py        # OPC UA scanner
│   ├── bacnet.py       # BACnet/IP scanner
│   ├── ethernetip.py   # EtherNet/IP scanner
│   ├── s7comm.py       # Siemens S7comm scanner
│   ├── hartip.py       # HART-IP scanner
│   ├── iec61850.py     # IEC 61850 / MMS scanner
│   └── profinet.py     # PROFINET DCP scanner
├── discovery/
│   └── network.py      # Network discovery + port scanning
├── reporting/
│   └── report.py       # JSON/HTML/CSV report generation
└── utils/
    └── helpers.py       # Utility functions
```

## Testing

```bash
pytest tests/ -v
```

## License

MIT
