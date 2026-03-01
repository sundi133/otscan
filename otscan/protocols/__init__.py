"""OT/ICS/SCADA protocol scanners."""

from otscan.protocols.modbus import ModbusScanner
from otscan.protocols.dnp3 import DNP3Scanner
from otscan.protocols.opcua import OPCUAScanner
from otscan.protocols.bacnet import BACnetScanner
from otscan.protocols.ethernetip import EtherNetIPScanner
from otscan.protocols.s7comm import S7CommScanner
from otscan.protocols.hartip import HARTIPScanner
from otscan.protocols.iec61850 import IEC61850Scanner
from otscan.protocols.profinet import ProfinetScanner

ALL_SCANNERS = [
    ModbusScanner,
    DNP3Scanner,
    OPCUAScanner,
    BACnetScanner,
    EtherNetIPScanner,
    S7CommScanner,
    HARTIPScanner,
    IEC61850Scanner,
    ProfinetScanner,
]

__all__ = [
    "ModbusScanner",
    "DNP3Scanner",
    "OPCUAScanner",
    "BACnetScanner",
    "EtherNetIPScanner",
    "S7CommScanner",
    "HARTIPScanner",
    "IEC61850Scanner",
    "ProfinetScanner",
    "ALL_SCANNERS",
]
