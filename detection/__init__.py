"""
detection/__init__.py
======================
Network Traffic Analysis and Intrusion Detection System

Intrusion Detection Package — Phase 5 (fully implemented).

Provides a production-quality rule-based IDS pipeline with four independent
detectors, a central rule orchestration engine, and an alert management system.

Architecture:
  - RuleEngine     : Central orchestrator; fans out DataFrames to detectors
  - BaseDetector   : Abstract base class for the Strategy pattern
  - SecurityAlert  : Standardised alert dataclass (emitted by all detectors)
  - AlertManager   : Alert repository, deduplication, and viz data provider

Detectors (in execution priority order):
  1. DDoSDetector       — Volume flood, bandwidth flood, distributed, protocol
  2. SYNFloodDetector   — SYN dominance, low ACK ratio, high SYN rate
  3. PortScanDetector   — Horizontal, vertical, and SYN stealth scans
  4. BruteForceDetector — Service brute force, credential spray, rapid reconnect

Modules:
    rule_engine         — BaseDetector ABC, SecurityAlert, RuleEngine
    ddos_detector       — Distributed Denial-of-Service detection
    synflood_detector   — TCP SYN flood detection
    portscan_detector   — Port scanning behaviour detection
    bruteforce_detector — Brute-force login attempt detection
    alert_manager       — Alert storage, dedup, and analytics

Author: Network Traffic Analyzer Project
Version: 5.0.0
"""

from detection.rule_engine import BaseDetector, RuleEngine, SecurityAlert
from detection.ddos_detector import DDoSDetector
from detection.synflood_detector import SYNFloodDetector
from detection.portscan_detector import PortScanDetector
from detection.bruteforce_detector import BruteForceDetector
from detection.alert_manager import AlertManager

__all__ = [
    # Core
    "BaseDetector",
    "RuleEngine",
    "SecurityAlert",
    # Detectors
    "DDoSDetector",
    "SYNFloodDetector",
    "PortScanDetector",
    "BruteForceDetector",
    # Alert management
    "AlertManager",
]
