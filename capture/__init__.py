"""
capture/__init__.py
====================
Network Traffic Analysis and Intrusion Detection System

Packet Capture Package — Phase 2 Implementation.

Provides the complete packet ingestion pipeline:
  PCAP File → PcapReader → PacketParser → FeatureExtractor → DataFrame/CSV/SQLite

Modules:
    pcap_reader         — Validated, generator-based PCAP file reader (PyShark)
    packet_parser       — Raw packet → typed PacketRecord dataclass
    feature_extractor   — PacketRecord list → enriched DataFrame + persistence

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

from capture.pcap_reader import PcapReader
from capture.packet_parser import PacketParser, PacketRecord
from capture.feature_extractor import FeatureExtractor

__all__ = [
    "PcapReader",
    "PacketParser",
    "PacketRecord",
    "FeatureExtractor",
]
