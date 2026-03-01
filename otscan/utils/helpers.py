"""Utility functions for OTScan."""

from __future__ import annotations

import re
import socket


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Check if a string is valid CIDR notation."""
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"
    return bool(re.match(pattern, cidr))


def format_mac(mac_bytes: bytes) -> str:
    """Format MAC address bytes to string."""
    return ":".join(f"{b:02X}" for b in mac_bytes)


def severity_color(severity: str) -> str:
    """Return a rich color string for a severity level."""
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    return colors.get(severity.lower(), "white")
