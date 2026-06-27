"""
helpers.py — General-Purpose Utility Functions
================================================
Network Traffic Analysis and Intrusion Detection System

A collection of reusable helper functions used throughout the project:
  - IP address classification and validation
  - Timestamp formatting
  - Byte size formatting (human-readable)
  - MAC address normalisation
  - Port-to-service name resolution
  - UUID generation for session identifiers

Author: Network Traffic Analyzer Project
Version: 1.0.0
Python: 3.11+
"""

from __future__ import annotations

import ipaddress
import socket
import uuid
from datetime import datetime, timezone
from typing import Optional

from utils.logger import get_logger

log = get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# TIMESTAMP UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def utc_now_iso() -> str:
    """
    Return the current UTC timestamp as an ISO-8601 string.

    Returns:
        e.g. ``"2025-06-15T14:32:00.123456+00:00"``
    """
    return datetime.now(tz=timezone.utc).isoformat()


def format_timestamp(ts: str, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Parse an ISO-8601 timestamp string and reformat it.

    Args:
        ts:  ISO-8601 timestamp string.
        fmt: Target strftime format string.

    Returns:
        Reformatted timestamp string, or the original on parse failure.
    """
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime(fmt)
    except (ValueError, TypeError):
        log.warning("Could not parse timestamp: '%s'", ts)
        return ts


# ──────────────────────────────────────────────────────────────────────────────
# IP ADDRESS UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def classify_ip(ip_str: str) -> str:
    """
    Classify an IP address as private, public, loopback, multicast, or unknown.

    Args:
        ip_str: Dotted-decimal or IPv6 IP address string.

    Returns:
        One of: ``"private"``, ``"public"``, ``"loopback"``,
        ``"multicast"``, ``"link_local"``, ``"unspecified"``, ``"unknown"``.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback:
            return "loopback"
        if addr.is_multicast:
            return "multicast"
        if addr.is_link_local:
            return "link_local"
        if addr.is_unspecified:
            return "unspecified"
        if addr.is_private:
            return "private"
        return "public"
    except ValueError:
        return "unknown"


def is_valid_ip(ip_str: str) -> bool:
    """
    Check whether a string is a valid IPv4 or IPv6 address.

    Args:
        ip_str: Candidate IP address string.

    Returns:
        True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def extract_subnet(ip_str: str, prefix_len: int = 24) -> Optional[str]:
    """
    Derive the network address for a given IP and prefix length.

    Args:
        ip_str:     Valid IP address string.
        prefix_len: CIDR prefix length (default 24 → /24).

    Returns:
        Network address string (e.g. ``"192.168.1.0/24"``), or None on error.
    """
    try:
        network = ipaddress.ip_interface(f"{ip_str}/{prefix_len}").network
        return str(network)
    except ValueError:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# BYTE SIZE FORMATTING
# ──────────────────────────────────────────────────────────────────────────────

def format_bytes(num_bytes: int) -> str:
    """
    Convert a raw byte count to a human-readable string.

    Args:
        num_bytes: Number of bytes.

    Returns:
        Formatted string such as ``"1.23 KB"``, ``"4.56 MB"``, ``"7.89 GB"``.

    Example:
        >>> format_bytes(1536)
        '1.50 KB'
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0  # type: ignore[assignment]
    return f"{num_bytes:.2f} PB"


def format_bps(bits_per_second: float) -> str:
    """
    Convert a bandwidth value (bits per second) to a human-readable string.

    Args:
        bits_per_second: Raw bandwidth value in bps.

    Returns:
        Formatted string such as ``"512.00 Kbps"`` or ``"1.50 Gbps"``.
    """
    for unit in ("bps", "Kbps", "Mbps", "Gbps", "Tbps"):
        if abs(bits_per_second) < 1000.0:
            return f"{bits_per_second:.2f} {unit}"
        bits_per_second /= 1000.0
    return f"{bits_per_second:.2f} Pbps"


# ──────────────────────────────────────────────────────────────────────────────
# PORT UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def port_to_service(port: int, protocol: str = "tcp") -> str:
    """
    Resolve a port number to its well-known service name.

    Uses the OS service database (``/etc/services`` on Linux/macOS,
    ``%SystemRoot%\\system32\\drivers\\etc\\services`` on Windows).

    Args:
        port:     Port number (0–65535).
        protocol: Transport protocol (``"tcp"`` or ``"udp"``).

    Returns:
        Service name (e.g. ``"ssh"``) or ``"unknown"`` if not found.
    """
    try:
        return socket.getservbyport(port, protocol)
    except (OSError, OverflowError):
        return "unknown"


def is_privileged_port(port: int) -> bool:
    """
    Determine whether a port number is in the privileged range (0–1023).

    Args:
        port: Port number.

    Returns:
        True if 0 ≤ port ≤ 1023, False otherwise.
    """
    return 0 <= port <= 1023


def is_ephemeral_port(port: int) -> bool:
    """
    Determine whether a port falls in the ephemeral (dynamic) range.

    Uses the IANA-recommended range 49152–65535.

    Args:
        port: Port number.

    Returns:
        True if in the ephemeral range, False otherwise.
    """
    return 49152 <= port <= 65535


# ──────────────────────────────────────────────────────────────────────────────
# SESSION IDENTIFIER
# ──────────────────────────────────────────────────────────────────────────────

def generate_session_id() -> str:
    """
    Generate a unique session identifier for packet capture sessions.

    Returns:
        A lowercase UUID4 string (e.g. ``"3f2504e0-4f89-11d3-9a0c-0305e82c3301"``).
    """
    return str(uuid.uuid4())


# ──────────────────────────────────────────────────────────────────────────────
# PROTOCOL UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def protocol_num_to_name(proto_num: int) -> str:
    """
    Map an IP protocol number to its canonical name.

    Args:
        proto_num: IP protocol number (0–255).

    Returns:
        Protocol name string or ``"PROTO_<num>"`` for unknown values.
    """
    from utils.config import config
    return config.network.protocol_map.get(proto_num, f"PROTO_{proto_num}")


# ──────────────────────────────────────────────────────────────────────────────
# TCP FLAG UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

# Bit masks for standard TCP flags
_TCP_FLAGS: dict[str, int] = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}


def decode_tcp_flags(flags_int: int) -> list[str]:
    """
    Decode an integer TCP flags field into a list of set flag names.

    Args:
        flags_int: Integer representation of TCP flags byte.

    Returns:
        List of flag name strings (e.g. ``["SYN", "ACK"]``).
    """
    return [name for name, mask in _TCP_FLAGS.items() if flags_int & mask]


def encode_tcp_flags(flag_names: list[str]) -> int:
    """
    Encode a list of TCP flag names into an integer bitmask.

    Args:
        flag_names: List of flag name strings (case-insensitive).

    Returns:
        Integer bitmask of the specified flags.
    """
    result = 0
    for name in flag_names:
        result |= _TCP_FLAGS.get(name.upper(), 0)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# SEVERITY COLOUR MAPPING (for dashboard display)
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_COLOURS: dict[str, str] = {
    "LOW":      "#27AE60",    # Green
    "MEDIUM":   "#F39C12",    # Orange
    "HIGH":     "#E74C3C",    # Red
    "CRITICAL": "#8E44AD",    # Purple
}

SEVERITY_EMOJI: dict[str, str] = {
    "LOW":      "🟢",
    "MEDIUM":   "🟡",
    "HIGH":     "🔴",
    "CRITICAL": "🟣",
}


def severity_to_colour(severity: str) -> str:
    """
    Map a severity label to its dashboard hex colour code.

    Args:
        severity: One of ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, ``"CRITICAL"``.

    Returns:
        Hex colour string, defaulting to grey for unknown values.
    """
    return SEVERITY_COLOURS.get(severity.upper(), "#7F8C8D")
