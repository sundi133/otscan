"""Multi-protocol OT device simulator for testing otscan.

Runs fake OT services on a single host so you can test all scanning
capabilities without real hardware.

Services started:
  - Modbus TCP    (port 502)   — responds to function codes 0x03, 0x11, 0x2B
  - OPC UA        (port 4840)  — accepts HEL, responds with ACK
  - EtherNet/IP   (port 44818) — responds to ListIdentity
  - S7comm        (port 102)   — accepts COTP CR, responds with CC
  - DNP3          (port 20000) — responds to data link frames
  - BACnet/IP     (port 47808) — responds to Who-Is (UDP)
  - IEC 104       (port 2404)  — responds to TESTFR/STARTDT
  - FINS          (port 9600)  — responds to node address request
  - MQTT broker   (port 1883)  — accepts CONNECT, returns CONNACK
  - FTP           (port 21)    — banner + anonymous login
  - Telnet        (port 23)    — banner
  - HTTP HMI      (port 80)    — fake Siemens web interface
  - VNC           (port 5900)  — RFB handshake, no-auth
  - SNMP          (port 161)   — responds to community "public" (UDP)

Usage:
    python sim/ot_simulator.py
    # Then in another terminal:
    otscan scan 127.0.0.1 --mode active
"""

from __future__ import annotations

import socket
import struct
import threading
import time
import sys
import signal


def log(service: str, msg: str):
    print(f"  [{service:>12}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Modbus TCP simulator (port 502)
# ---------------------------------------------------------------------------
def modbus_handler(conn, addr):
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            if len(data) < 7:
                continue
            # Parse MBAP header
            trans_id = struct.unpack(">H", data[0:2])[0]
            unit_id = data[6]
            fc = data[7] if len(data) > 7 else 0

            if fc == 0x2B:  # Read Device Identification
                # Return vendor="OTSim", product="SimPLC", revision="1.0"
                objects = (
                    b"\x00\x05OTSim"  # vendor
                    b"\x01\x06SimPLC"  # product code
                    b"\x02\x031.0"    # revision
                )
                pdu = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x03]) + objects
            elif fc == 0x11:  # Report Slave ID
                slave_data = b"OTSim Modbus Simulator\xff"
                pdu = bytes([0x11, len(slave_data)]) + slave_data
            elif fc == 0x03:  # Read Holding Registers
                num_regs = struct.unpack(">H", data[10:12])[0] if len(data) >= 12 else 1
                num_regs = min(num_regs, 50)
                reg_data = b"\x00\x42" * num_regs  # value 66 for each register
                pdu = bytes([0x03, num_regs * 2]) + reg_data
            elif fc == 0x01:  # Read Coils
                pdu = bytes([0x01, 0x01, 0xFF])
            else:
                pdu = bytes([fc + 0x80, 0x01])  # exception response

            # Build MBAP response
            length = len(pdu) + 1
            resp = struct.pack(">HHH", trans_id, 0, length) + bytes([unit_id]) + pdu
            conn.sendall(resp)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        conn.close()


def start_modbus(port=502):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("Modbus", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=modbus_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# OPC UA simulator (port 4840)
# ---------------------------------------------------------------------------
def opcua_handler(conn, addr):
    try:
        data = conn.recv(4096)
        if data and data[0:3] == b"HEL":
            # Respond with ACK
            body = struct.pack("<IIIII", 0, 65536, 65536, 0, 4096)
            ack = b"ACKF" + struct.pack("<I", 8 + len(body)) + body
            conn.sendall(ack)
            log("OPC UA", f"HEL/ACK handshake with {addr[0]}")
    except OSError:
        pass
    finally:
        conn.close()


def start_opcua(port=4840):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("OPC UA", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=opcua_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# EtherNet/IP simulator (port 44818)
# ---------------------------------------------------------------------------
def enip_handler(conn, addr):
    try:
        data = conn.recv(4096)
        if data and len(data) >= 2:
            cmd = struct.unpack("<H", data[0:2])[0]
            if cmd == 0x0063:  # ListIdentity
                # Build ListIdentity response
                product_name = b"OTSim EtherNet/IP"
                item_data = struct.pack("<HHIHH", 1, 0x000C, 0,
                                        len(product_name), 0)
                item_data += product_name
                cip_item = struct.pack("<HH", 0x000C, len(item_data)) + item_data
                resp_data = struct.pack("<H", 1) + cip_item
                header = struct.pack("<HHIHIIQQ", 0x0063, len(resp_data), 0, 0, 0, 0, 0, 0)
                conn.sendall(header + resp_data)
                log("EtherNet/IP", f"ListIdentity response to {addr[0]}")
            elif cmd == 0x0004:  # ListServices
                header = struct.pack("<HHIHIIQQ", 0x0004, 0, 0, 0, 0, 0, 0, 0)
                conn.sendall(header)
    except OSError:
        pass
    finally:
        conn.close()


def start_enip(port=44818):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("EtherNet/IP", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=enip_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# S7comm simulator (port 102)
# ---------------------------------------------------------------------------
def s7comm_handler(conn, addr):
    try:
        data = conn.recv(4096)
        if data and len(data) >= 4 and data[0] == 0x03:  # TPKT
            # Check for COTP CR (Connection Request)
            if len(data) > 5 and (data[5] & 0xF0) == 0xE0:
                # Send COTP CC (Connection Confirm)
                cotp_cc = bytes([
                    0x06,  # length
                    0xD0,  # CC
                    0x00, 0x01,  # dst ref
                    0x00, 0x01,  # src ref
                    0x00,  # class/options
                ])
                tpkt = bytes([0x03, 0x00]) + struct.pack("!H", 4 + len(cotp_cc)) + cotp_cc
                conn.sendall(tpkt)
                log("S7comm", f"COTP CC to {addr[0]}")

                # Wait for S7 setup communication
                data2 = conn.recv(4096)
                if data2 and len(data2) > 17:
                    # Send S7 setup response
                    s7_resp = bytes([
                        0x32,  # protocol ID
                        0x03,  # ack_data
                        0x00, 0x00,  # reserved
                        0x00, 0x01,  # pdu ref
                        0x00, 0x00,  # param error
                        0x00, 0x08,  # data length
                        0x00, 0x00,  # error code
                        0xF0, 0x00,  # setup function
                        0x00, 0x01,  # max AmQ calling
                        0x00, 0x01,  # max AmQ called
                        0x01, 0xE0,  # PDU length (480)
                    ])
                    cotp_dt = bytes([0x02, 0xF0, 0x80])  # COTP DT
                    payload = cotp_dt + s7_resp
                    tpkt = bytes([0x03, 0x00]) + struct.pack("!H", 4 + len(payload)) + payload
                    conn.sendall(tpkt)
    except OSError:
        pass
    finally:
        conn.close()


def start_s7comm(port=102):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("S7comm", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=s7comm_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# DNP3 simulator (port 20000)
# ---------------------------------------------------------------------------
def dnp3_handler(conn, addr):
    try:
        data = conn.recv(4096)
        if data and len(data) >= 10 and data[0:2] == b"\x05\x64":
            # Echo back a valid DNP3 response frame
            resp = bytes([
                0x05, 0x64,  # start bytes
                0x05,        # length
                0x00,        # control (response)
                data[5], data[6],  # swap src/dst
                data[3], data[4],
                0x00, 0x00,  # CRC placeholder
            ])
            conn.sendall(resp)
            log("DNP3", f"Response to {addr[0]}")
    except OSError:
        pass
    finally:
        conn.close()


def start_dnp3(port=20000):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("DNP3", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=dnp3_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# BACnet/IP simulator (port 47808 UDP)
# ---------------------------------------------------------------------------
def start_bacnet(port=47808):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    log("BACnet/IP", f"Listening on UDP port {port}")
    while True:
        data, addr = sock.recvfrom(4096)
        if data and len(data) >= 4 and data[0] == 0x81:
            # Send I-Am response
            iam = bytes([
                0x81, 0x0B,  # BVLC
                0x00, 0x19,  # length
                0x01, 0x20,  # NPDU
                0x00, 0x04,  # I-Am
                0xC4, 0x02, 0x00, 0x00, 0x01,  # object ID
                0x22, 0x01, 0xE0,  # max APDU
                0x91, 0x03,  # segmentation
                0x21, 0x18,  # vendor ID (24)
            ])
            sock.sendto(iam, addr)
            log("BACnet/IP", f"I-Am response to {addr[0]}")


# ---------------------------------------------------------------------------
# IEC 60870-5-104 simulator (port 2404)
# ---------------------------------------------------------------------------
def iec104_handler(conn, addr):
    try:
        while True:
            data = conn.recv(1024)
            if not data or len(data) < 6:
                break
            if data[0] != 0x68:
                continue
            ctrl = data[2]
            if ctrl == 0x43:  # TESTFR ACT
                resp = bytes([0x68, 0x04, 0x83, 0x00, 0x00, 0x00])  # TESTFR CON
                conn.sendall(resp)
                log("IEC 104", f"TESTFR CON to {addr[0]}")
            elif ctrl == 0x07:  # STARTDT ACT
                resp = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])  # STARTDT CON
                conn.sendall(resp)
                log("IEC 104", f"STARTDT CON to {addr[0]}")
    except OSError:
        pass
    finally:
        conn.close()


def start_iec104(port=2404):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("IEC 104", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=iec104_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# Omron FINS simulator (port 9600)
# ---------------------------------------------------------------------------
def fins_handler(conn, addr):
    try:
        data = conn.recv(4096)
        if data and len(data) >= 16 and data[0:4] == b"FINS":
            cmd = struct.unpack("!I", data[8:12])[0]
            if cmd == 0x00000000:  # Node address request
                resp = (
                    b"FINS"
                    + struct.pack("!I", 24)         # length
                    + struct.pack("!I", 0x00000001) # node address response
                    + struct.pack("!I", 0x00000000) # error code
                    + struct.pack("!I", 1)          # client node
                    + struct.pack("!I", 10)         # server node
                )
                conn.sendall(resp)
                log("FINS", f"Node address response to {addr[0]}")
    except OSError:
        pass
    finally:
        conn.close()


def start_fins(port=9600):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("FINS", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=fins_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# MQTT broker simulator (port 1883)
# ---------------------------------------------------------------------------
def mqtt_handler(conn, addr):
    try:
        data = conn.recv(4096)
        if data and data[0] == 0x10:  # CONNECT
            # Send CONNACK (connection accepted, no auth required)
            connack = bytes([0x20, 0x02, 0x00, 0x00])
            conn.sendall(connack)
            log("MQTT", f"CONNACK (no auth) to {addr[0]}")
    except OSError:
        pass
    finally:
        conn.close()


def start_mqtt(port=1883):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("MQTT", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=mqtt_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# FTP simulator (port 21) — allows anonymous login
# ---------------------------------------------------------------------------
def ftp_handler(conn, addr):
    try:
        conn.sendall(b"220 OTSim FTP - Schneider Electric BMX NOE\r\n")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            cmd = data.decode("ascii", errors="replace").strip().upper()
            if cmd.startswith("USER"):
                conn.sendall(b"331 Password required\r\n")
            elif cmd.startswith("PASS"):
                conn.sendall(b"230 Login successful.\r\n")
                log("FTP", f"Anonymous login from {addr[0]}")
            elif cmd.startswith("SYST"):
                conn.sendall(b"215 UNIX Type: L8\r\n")
            elif cmd.startswith("QUIT"):
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                conn.sendall(b"500 Unknown command.\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def start_ftp(port=21):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("FTP", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=ftp_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# Telnet simulator (port 23)
# ---------------------------------------------------------------------------
def telnet_handler(conn, addr):
    try:
        conn.sendall(b"\r\nSCALANCE X208 V5.2.6\r\nLogin: ")
        data = conn.recv(1024)
        conn.sendall(b"Password: ")
        data = conn.recv(1024)
        conn.sendall(b"\r\nLogin incorrect\r\n")
        log("Telnet", f"Login attempt from {addr[0]}")
    except OSError:
        pass
    finally:
        conn.close()


def start_telnet(port=23):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("Telnet", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=telnet_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# HTTP HMI simulator (port 80) — fake Siemens web interface
# ---------------------------------------------------------------------------
HMI_PAGE = """\
HTTP/1.1 200 OK\r
Content-Type: text/html\r
Server: Siemens SIMATIC S7-1500 Web Server\r
Connection: close\r
\r
<html>
<head><title>SIMATIC S7-1500 - Web Interface</title></head>
<body>
<h1>SIMATIC S7-1500 CPU 1516-3 PN/DP</h1>
<p>Firmware: V2.9.4</p>
<p>Serial: S C-B1K934562019</p>
<p>Plant: OTSim Test Plant</p>
<table>
<tr><td>Module</td><td>Status</td></tr>
<tr><td>CPU 1516-3 PN/DP</td><td>RUN</td></tr>
<tr><td>DI 32x24VDC</td><td>OK</td></tr>
<tr><td>DQ 32x24VDC/0.5A</td><td>OK</td></tr>
<tr><td>AI 8xU/I/RTD/TC</td><td>OK</td></tr>
</table>
</body>
</html>"""

HTTP_401 = """\
HTTP/1.1 401 Unauthorized\r
WWW-Authenticate: Basic realm="SIMATIC"\r
Content-Type: text/html\r
Server: Siemens SIMATIC S7-1500 Web Server\r
Connection: close\r
\r
<html><body><h1>401 - Unauthorized</h1></body></html>"""


def http_handler(conn, addr):
    try:
        data = conn.recv(4096)
        request = data.decode("ascii", errors="replace")
        # Check for basic auth header with admin:admin (YWRtaW46YWRtaW4=)
        if "Authorization: Basic YWRtaW46YWRtaW4=" in request:
            conn.sendall(HMI_PAGE.encode())
            log("HTTP HMI", f"Admin login from {addr[0]}")
        elif "Authorization:" in request:
            conn.sendall(HTTP_401.encode())
        else:
            # Return the page without auth for now (simulates misconfigured HMI)
            conn.sendall(HMI_PAGE.encode())
            log("HTTP HMI", f"Unauthenticated access from {addr[0]}")
    except OSError:
        pass
    finally:
        conn.close()


def start_http(port=80):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("HTTP HMI", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=http_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# VNC simulator (port 5900) — no authentication
# ---------------------------------------------------------------------------
def vnc_handler(conn, addr):
    try:
        # Send RFB version
        conn.sendall(b"RFB 003.008\n")
        data = conn.recv(12)  # client version
        # Send security types: 1 = None (no auth)
        conn.sendall(bytes([0x01, 0x01]))  # 1 type, type=None
        log("VNC", f"No-auth handshake with {addr[0]}")
    except OSError:
        pass
    finally:
        conn.close()


def start_vnc(port=5900):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    log("VNC", f"Listening on port {port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=vnc_handler, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
# SNMP simulator (port 161 UDP) — responds to community "public"
# ---------------------------------------------------------------------------
def start_snmp(port=161):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    log("SNMP", f"Listening on UDP port {port}")
    while True:
        data, addr = sock.recvfrom(4096)
        if not data or data[0] != 0x30:
            continue
        # Check if community string is in the packet
        # Simple check: look for "public" bytes in the packet
        if b"public" in data:
            # Build a minimal SNMP GET-RESPONSE
            # sysDescr.0 = "OTSim SCALANCE X208 V5.2.6"
            sys_descr = b"OTSim SCALANCE X208 V5.2.6"
            oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
            value = b"\x04" + bytes([len(sys_descr)]) + sys_descr
            varbind = b"\x30" + bytes([len(oid) + len(value)]) + oid + value
            varbind_list = b"\x30" + bytes([len(varbind)]) + varbind

            request_id = b"\x02\x01\x01"
            error_status = b"\x02\x01\x00"
            error_index = b"\x02\x01\x00"

            pdu_content = request_id + error_status + error_index + varbind_list
            pdu = b"\xa2" + bytes([len(pdu_content)]) + pdu_content

            community = b"\x04\x06public"
            version = b"\x02\x01\x00"

            msg_content = version + community + pdu
            message = b"\x30" + bytes([len(msg_content)]) + msg_content

            sock.sendto(message, addr)
            log("SNMP", f"sysDescr response to {addr[0]} (community: public)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
SERVICES = [
    ("Modbus TCP (502)",      start_modbus,   502),
    ("OPC UA (4840)",         start_opcua,    4840),
    ("EtherNet/IP (44818)",   start_enip,     44818),
    ("S7comm (102)",          start_s7comm,   102),
    ("DNP3 (20000)",          start_dnp3,     20000),
    ("BACnet/IP (47808 UDP)", start_bacnet,   47808),
    ("IEC 104 (2404)",        start_iec104,   2404),
    ("FINS (9600)",           start_fins,     9600),
    ("MQTT (1883)",           start_mqtt,     1883),
    ("FTP (21)",              start_ftp,      21),
    ("Telnet (23)",           start_telnet,   23),
    ("HTTP HMI (80)",         start_http,     80),
    ("VNC (5900)",            start_vnc,      5900),
    ("SNMP (161 UDP)",        start_snmp,     161),
]


def main():
    print("=" * 60)
    print("  OTScan Test Lab — Simulated OT/ICS Devices")
    print("=" * 60)
    print()
    print("  Starting 14 simulated services...")
    print()

    threads = []
    for name, func, port in SERVICES:
        t = threading.Thread(target=func, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    print()
    print("=" * 60)
    print("  All services running. Scan with:")
    print()
    print("    otscan scan 127.0.0.1 --mode active")
    print("    otscan scan <container-ip> --mode active")
    print()
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    print()

    try:
        signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
