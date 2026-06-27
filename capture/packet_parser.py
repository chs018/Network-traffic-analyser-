"""
packet_parser.py — Raw PyShark Packet → Structured PacketRecord
================================================================
Network Traffic Analysis and Intrusion Detection System

Converts raw PyShark packet objects (produced by PcapReader) into
structured :class:`PacketRecord` dataclass instances.

Supported layers:
  - Network:   IPv4, IPv6, ARP
  - Transport: TCP, UDP, ICMP
  - Application: DNS (port 53), HTTP (port 80/8080), HTTPS (port 443)

Design principles:
  - Zero crashes: every field access is wrapped in a safe getter
  - Missing data → None (never raise, never invent values)
  - Protocol normalisation: all protocol strings are upper-cased
  - Timestamp normalisation: all timestamps converted to ISO-8601

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from utils.logger import get_capture_logger

log = get_capture_logger()

# ── Application-layer port hints ───────────────────────────────────────────────
_DNS_PORTS:   frozenset[int] = frozenset({53})
_HTTP_PORTS:  frozenset[int] = frozenset({80, 8080, 8000})
_HTTPS_PORTS: frozenset[int] = frozenset({443, 8443})
_SSH_PORTS:   frozenset[int] = frozenset({22})
_FTP_PORTS:   frozenset[int] = frozenset({20, 21})
_SMTP_PORTS:  frozenset[int] = frozenset({25, 465, 587})


# ──────────────────────────────────────────────────────────────────────────────
# PACKET RECORD DATACLASS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PacketRecord:
    """
    Represents a single fully-parsed network packet.

    All optional fields default to ``None`` when the corresponding
    protocol layer is absent in the raw packet.  This ensures safe
    downstream consumption without attribute checks.

    Attributes:
        packet_number      Sequential packet counter (1-indexed).
        timestamp          ISO-8601 capture timestamp (UTC).
        source_ip          IPv4/IPv6 source address, or None for non-IP frames.
        destination_ip     IPv4/IPv6 destination address.
        protocol           Highest-layer protocol name (e.g. "TCP", "DNS").
        transport_layer    "TCP" | "UDP" | "ICMP" | None.
        packet_length      Total frame length in bytes.
        source_port        TCP/UDP source port, or None.
        destination_port   TCP/UDP destination port, or None.
        ttl                IPv4 TTL / IPv6 hop limit, or None.
        tcp_flags          Hex TCP flags string (e.g. "0x002" = SYN), or None.
        network_layer      "IPv4" | "IPv6" | "ARP" | None.
        app_layer_hint     Application-layer hint ("HTTP", "DNS", etc.), or None.
        ip_version         4 or 6 for IP packets, None for non-IP.
        parse_errors       List of non-fatal field extraction warnings.
    """

    packet_number:     int
    timestamp:         str
    source_ip:         Optional[str]
    destination_ip:    Optional[str]
    protocol:          str
    transport_layer:   Optional[str]
    packet_length:     int
    source_port:       Optional[int]
    destination_port:  Optional[int]
    ttl:               Optional[int]
    tcp_flags:         Optional[str]
    network_layer:     Optional[str]
    app_layer_hint:    Optional[str]     = None
    ip_version:        Optional[int]     = None
    parse_errors:      list[str]         = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialise the record to a plain dict for DataFrame construction.

        ``parse_errors`` is excluded since it is internal diagnostic data
        not intended for storage or analysis.

        Returns:
            Dict mapping field names to values (None for missing fields).
        """
        d = asdict(self)
        d.pop("parse_errors", None)   # Internal field — do not persist
        return d

    def has_ip(self) -> bool:
        """Return True if the packet has a valid IP layer."""
        return self.source_ip is not None and self.destination_ip is not None

    def has_transport(self) -> bool:
        """Return True if the packet has a TCP or UDP transport layer."""
        return self.transport_layer in {"TCP", "UDP"}

    def __post_init__(self) -> None:
        """Normalise protocol and transport_layer strings to upper-case."""
        if self.protocol:
            self.protocol = self.protocol.upper()
        if self.transport_layer:
            self.transport_layer = self.transport_layer.upper()


# ──────────────────────────────────────────────────────────────────────────────
# PACKET PARSER
# ──────────────────────────────────────────────────────────────────────────────

class PacketParser:
    """
    Converts raw PyShark packet objects into :class:`PacketRecord` instances.

    Stateless at the record level — all state (counters, session ID) is
    maintained on the parser instance, not on individual records.

    Attributes:
        session_id (str | None): Capture session UUID, embedded in logs.
        parsed_count (int):      Packets successfully converted.
        error_count (int):       Packets that failed entirely (unrecoverable).

    Example::

        parser = PacketParser(session_id="abc-123")
        for raw_pkt in reader.iterate_packets():
            record = parser.parse_packet(raw_pkt)
            if record:
                records.append(record)
    """

    def __init__(self, session_id: Optional[str] = None) -> None:
        """
        Initialise the PacketParser.

        Args:
            session_id: Optional capture session UUID for log tracing.
        """
        self.session_id: Optional[str] = session_id
        self.parsed_count: int = 0
        self.error_count: int = 0
        self._packet_counter: int = 0   # Sequential packet numbering

        log.debug(
            "PacketParser initialised (session_id='%s').",
            session_id or "none",
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def parse_packet(self, raw_packet: Any) -> Optional[PacketRecord]:
        """
        Parse a single PyShark packet into a :class:`PacketRecord`.

        If a critical error occurs (e.g. the packet object is None),
        returns None. Non-critical field failures result in None values
        for those specific fields only.

        Args:
            raw_packet: A PyShark ``Packet`` object from :class:`PcapReader`.

        Returns:
            A populated :class:`PacketRecord`, or None if unrecoverable.
        """
        if raw_packet is None:
            self.error_count += 1
            log.warning("Received None packet — skipping.")
            return None

        self._packet_counter += 1
        pkt_num = self._packet_counter
        errors: list[str] = []

        try:
            # ── Timestamp ─────────────────────────────────────────────────────
            timestamp = self._extract_timestamp(raw_packet, errors)

            # ── Packet Length ─────────────────────────────────────────────────
            packet_length = self._extract_length(raw_packet, errors)

            # ── Network Layer (IP / ARP) ───────────────────────────────────────
            src_ip, dst_ip, network_layer, ttl, ip_version = \
                self._extract_ip_layer(raw_packet, errors)

            # ── Transport Layer (TCP / UDP / ICMP) ────────────────────────────
            transport_layer, src_port, dst_port, tcp_flags = \
                self._extract_transport_layer(raw_packet, errors)

            # ── Protocol Name (highest-layer approximation) ────────────────────
            protocol = self._determine_protocol(raw_packet, transport_layer, src_port, dst_port, errors)

            # ── Application Layer Hint ─────────────────────────────────────────
            app_hint = self._determine_app_hint(src_port, dst_port, protocol)

            record = PacketRecord(
                packet_number=pkt_num,
                timestamp=timestamp,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=protocol,
                transport_layer=transport_layer,
                packet_length=packet_length,
                source_port=src_port,
                destination_port=dst_port,
                ttl=ttl,
                tcp_flags=tcp_flags,
                network_layer=network_layer,
                app_layer_hint=app_hint,
                ip_version=ip_version,
                parse_errors=errors,
            )
            self.parsed_count += 1

            if errors:
                log.debug(
                    "Packet #%d parsed with %d warnings: %s",
                    pkt_num, len(errors), "; ".join(errors),
                )
            return record

        except Exception as exc:
            self.error_count += 1
            log.error(
                "Unrecoverable error parsing packet #%d: %s",
                pkt_num, exc,
            )
            return None

    def parse_batch(
        self,
        raw_packets: list[Any],
        skip_non_ip: bool = False,
    ) -> list[PacketRecord]:
        """
        Parse a list of raw PyShark packets and return successful records.

        Args:
            raw_packets:  List of PyShark Packet objects.
            skip_non_ip:  If True, packets without an IP layer are discarded.

        Returns:
            List of successfully parsed :class:`PacketRecord` instances.
            Packets that fail are counted in :attr:`error_count` and excluded.
        """
        records: list[PacketRecord] = []
        for raw_pkt in raw_packets:
            record = self.parse_packet(raw_pkt)
            if record is None:
                continue
            if skip_non_ip and not record.has_ip():
                continue
            records.append(record)

        log.info(
            "Batch parsed | total=%d | success=%d | errors=%d",
            len(raw_packets),
            len(records),
            self.error_count,
        )
        return records

    def to_dict_list(self, records: list[PacketRecord]) -> list[dict[str, Any]]:
        """
        Convert a list of PacketRecords to a list of plain dicts.

        Args:
            records: Parsed packet records.

        Returns:
            List of dicts suitable for ``pandas.DataFrame.from_records()``.
        """
        return [r.to_dict() for r in records]

    def get_stats(self) -> dict[str, int]:
        """Return parsing statistics."""
        return {
            "parsed": self.parsed_count,
            "errors": self.error_count,
            "total": self.parsed_count + self.error_count,
        }

    def reset_stats(self) -> None:
        """Reset all counters (use between separate PCAP files)."""
        self.parsed_count = 0
        self.error_count = 0
        self._packet_counter = 0
        log.debug("PacketParser stats reset.")

    # ── Internal Extraction Helpers ────────────────────────────────────────────

    @staticmethod
    def _safe_get(obj: Any, *attrs: str, default: Any = None) -> Any:
        """
        Safely traverse a chain of attribute lookups on a PyShark layer.

        Args:
            obj:     Starting object (e.g. raw_packet.ip).
            *attrs:  Attribute names to traverse in sequence.
            default: Value to return if any lookup fails.

        Returns:
            The final attribute value, or ``default`` on any AttributeError.
        """
        try:
            for attr in attrs:
                obj = getattr(obj, attr)
            return obj
        except AttributeError:
            return default

    def _extract_timestamp(self, pkt: Any, errors: list[str]) -> str:
        """
        Extract the capture timestamp and normalise to ISO-8601 UTC.

        Falls back to the current UTC time if the sniff_timestamp is missing.
        """
        try:
            ts_raw = getattr(pkt, "sniff_timestamp", None)
            if ts_raw is not None:
                # PyShark returns sniff_timestamp as a float (Unix epoch)
                ts_float = float(ts_raw)
                dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
                return dt.isoformat()
        except (ValueError, TypeError, OSError) as exc:
            errors.append(f"timestamp extraction failed: {exc}")

        # Fallback: current UTC time
        return datetime.now(tz=timezone.utc).isoformat()

    @staticmethod
    def _extract_length(pkt: Any, errors: list[str]) -> int:
        """Extract the total packet length in bytes."""
        try:
            # PyShark exposes frame length as pkt.length
            length = getattr(pkt, "length", None)
            if length is not None:
                return int(length)
            # Fallback: try captured length
            cap_len = getattr(pkt, "captured_length", None)
            if cap_len is not None:
                return int(cap_len)
        except (ValueError, TypeError) as exc:
            errors.append(f"length extraction failed: {exc}")
        return 0

    def _extract_ip_layer(
        self,
        pkt: Any,
        errors: list[str],
    ) -> tuple[Optional[str], Optional[str], Optional[str], Optional[int], Optional[int]]:
        """
        Extract IPv4 / IPv6 / ARP network layer fields.

        Returns:
            Tuple of (src_ip, dst_ip, network_layer, ttl, ip_version).
        """
        src_ip = dst_ip = network_layer = ttl = ip_version = None

        # ── IPv4 ──────────────────────────────────────────────────────────────
        if hasattr(pkt, "ip"):
            try:
                src_ip = str(pkt.ip.src)
                dst_ip = str(pkt.ip.dst)
                network_layer = "IPv4"
                ip_version = 4
                ttl_raw = self._safe_get(pkt.ip, "ttl")
                if ttl_raw is not None:
                    ttl = int(ttl_raw)
            except Exception as exc:
                errors.append(f"IPv4 extraction error: {exc}")

        # ── IPv6 ──────────────────────────────────────────────────────────────
        elif hasattr(pkt, "ipv6"):
            try:
                src_ip = str(pkt.ipv6.src)
                dst_ip = str(pkt.ipv6.dst)
                network_layer = "IPv6"
                ip_version = 6
                hop_limit = self._safe_get(pkt.ipv6, "hlim")
                if hop_limit is not None:
                    ttl = int(hop_limit)   # IPv6 calls it hop limit
            except Exception as exc:
                errors.append(f"IPv6 extraction error: {exc}")

        # ── ARP ───────────────────────────────────────────────────────────────
        elif hasattr(pkt, "arp"):
            try:
                src_ip = self._safe_get(pkt.arp, "src_proto_ipv4")
                dst_ip = self._safe_get(pkt.arp, "dst_proto_ipv4")
                if src_ip:
                    src_ip = str(src_ip)
                if dst_ip:
                    dst_ip = str(dst_ip)
                network_layer = "ARP"
            except Exception as exc:
                errors.append(f"ARP extraction error: {exc}")

        return src_ip, dst_ip, network_layer, ttl, ip_version

    def _extract_transport_layer(
        self,
        pkt: Any,
        errors: list[str],
    ) -> tuple[Optional[str], Optional[int], Optional[int], Optional[str]]:
        """
        Extract TCP / UDP / ICMP transport layer fields.

        Returns:
            Tuple of (transport_layer, src_port, dst_port, tcp_flags_hex).
        """
        transport_layer = src_port = dst_port = tcp_flags = None

        # ── TCP ───────────────────────────────────────────────────────────────
        if hasattr(pkt, "tcp"):
            try:
                transport_layer = "TCP"
                sp = self._safe_get(pkt.tcp, "srcport")
                dp = self._safe_get(pkt.tcp, "dstport")
                src_port = int(sp) if sp is not None else None
                dst_port = int(dp) if dp is not None else None

                flags_raw = self._safe_get(pkt.tcp, "flags")
                if flags_raw is not None:
                    # Normalise to hex string, e.g. "0x00000002"
                    try:
                        tcp_flags = hex(int(str(flags_raw), 16))
                    except (ValueError, TypeError):
                        tcp_flags = str(flags_raw)
            except Exception as exc:
                errors.append(f"TCP extraction error: {exc}")

        # ── UDP ───────────────────────────────────────────────────────────────
        elif hasattr(pkt, "udp"):
            try:
                transport_layer = "UDP"
                sp = self._safe_get(pkt.udp, "srcport")
                dp = self._safe_get(pkt.udp, "dstport")
                src_port = int(sp) if sp is not None else None
                dst_port = int(dp) if dp is not None else None
            except Exception as exc:
                errors.append(f"UDP extraction error: {exc}")

        # ── ICMP ──────────────────────────────────────────────────────────────
        elif hasattr(pkt, "icmp"):
            transport_layer = "ICMP"
            # ICMP has no ports
        elif hasattr(pkt, "icmpv6"):
            transport_layer = "ICMPv6"

        return transport_layer, src_port, dst_port, tcp_flags

    @staticmethod
    def _determine_protocol(
        pkt: Any,
        transport_layer: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        errors: list[str],
    ) -> str:
        """
        Determine the best protocol label for a packet.

        Priority:
        1. highest_layer attribute from PyShark
        2. Known application-layer port hints
        3. Transport layer name
        4. Network layer name
        5. Fallback: "UNKNOWN"
        """
        try:
            highest = getattr(pkt, "highest_layer", None)
            if highest and highest.upper() not in {"DATA", "FRAME"}:
                return highest.upper()
        except Exception as exc:
            errors.append(f"highest_layer read failed: {exc}")

        # Port-based hints for well-known services
        ports = {src_port, dst_port} - {None}
        if ports & _DNS_PORTS:
            return "DNS"
        if ports & _HTTPS_PORTS:
            return "HTTPS"
        if ports & _HTTP_PORTS:
            return "HTTP"
        if ports & _SSH_PORTS:
            return "SSH"
        if ports & _FTP_PORTS:
            return "FTP"
        if ports & _SMTP_PORTS:
            return "SMTP"

        # Fall back to transport layer
        if transport_layer:
            return transport_layer.upper()

        # Final fallback
        return "UNKNOWN"

    @staticmethod
    def _determine_app_hint(
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
    ) -> Optional[str]:
        """
        Derive a human-readable application-layer hint from port numbers.

        Args:
            src_port:  Source port or None.
            dst_port:  Destination port or None.
            protocol:  Resolved protocol name.

        Returns:
            Application name string, or None if undetermined.
        """
        ports = {src_port, dst_port} - {None}
        if ports & _DNS_PORTS:
            return "DNS"
        if ports & _HTTPS_PORTS:
            return "HTTPS"
        if ports & _HTTP_PORTS:
            return "HTTP"
        if ports & _SSH_PORTS:
            return "SSH"
        if ports & _FTP_PORTS:
            return "FTP"
        if ports & _SMTP_PORTS:
            return "SMTP"
        if protocol in {"DNS", "HTTP", "HTTPS", "SSH", "FTP", "SMTP"}:
            return protocol
        return None

    def __repr__(self) -> str:
        return (
            f"PacketParser("
            f"session_id='{self.session_id}', "
            f"parsed={self.parsed_count}, "
            f"errors={self.error_count})"
        )
