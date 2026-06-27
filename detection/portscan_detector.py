"""
portscan_detector.py — Port Scan Detector
==========================================
Network Traffic Analysis and Intrusion Detection System

Detects port scanning activity using deterministic, rule-based heuristics.
No machine learning is used. Every alert is fully explainable.

Detection Rules:
  1. Horizontal Scan  — one source IP probing many ports on one or few targets
  2. Vertical Scan    — one source IP probing one port across many targets
  3. SYN Stealth      — high SYN packets with very low ACK (RST back from target)
  4. Rapid Scan Rate  — unique ports probed per second exceeds threshold

Scan type classification:
  - Sequential scan:  sorted port list with small gaps
  - Random scan:      port list with large variance

Classes:
    ScanType         — Enum of recognised scan categories
    ScanTracker      — Per-source-IP stateful accumulator
    PortScanDetector — BaseDetector implementation (Phase 5 — fully implemented)

Author: Network Traffic Analyzer Project
Version: 5.0.0
Python: 3.11+
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

import numpy as np
import pandas as pd

from database.db_manager import AlertRecord, DatabaseManager
from detection.rule_engine import BaseDetector, SecurityAlert
from utils.config import config
from utils.helpers import utc_now_iso
from utils.logger import get_detection_logger

log = get_detection_logger()


# ──────────────────────────────────────────────────────────────────────────────
# ENUMS & DATACLASSES
# ──────────────────────────────────────────────────────────────────────────────

class ScanType(Enum):
    """Enumeration of recognised port scan patterns."""

    HORIZONTAL = auto()    # Many ports, one or few targets
    VERTICAL = auto()      # One port, many targets
    SYN_STEALTH = auto()   # SYN without completing handshake
    SEQUENTIAL = auto()    # Sequential port ordering
    RANDOM = auto()        # Random port ordering
    RAPID = auto()         # Very high scan rate per second


@dataclass
class ScanTracker:
    """
    Per-source-IP state accumulated during a single detection pass.

    Used to track how many unique ports and hosts a single source IP
    has probed, enabling multi-rule evaluation in one DataFrame scan.
    """

    src_ip: str
    probed_ports: set = field(default_factory=set)
    probed_hosts: set = field(default_factory=set)
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    total_packets: int = 0
    avg_packet_size: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    duration_seconds: float = 0.0
    ports_per_second: float = 0.0


# ──────────────────────────────────────────────────────────────────────────────
# PORT SCAN DETECTOR
# ──────────────────────────────────────────────────────────────────────────────

class PortScanDetector(BaseDetector):
    """
    Rule-based port scan detector.

    Tracks per-source-IP connection patterns within the packet DataFrame
    and raises alerts when probe counts exceed configured thresholds.

    All detection is vectorised where possible for performance:
      - GroupBy src_ip → collect unique dst_ports and dst_ips
      - Filter SYN-only packets via tcp_flags bitmask
      - Compute ports-per-second from timestamps

    The detector is stateless across calls — each detect() invocation
    performs a fresh analysis of the supplied DataFrame.
    """

    PRIORITY: int = 20   # Second after DDoS

    def __init__(
        self,
        enabled: bool = True,
        cfg_overrides: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Initialise the PortScanDetector.

        Args:
            enabled:       Whether the detector is active.
            cfg_overrides: Optional dict to override specific threshold keys.
        """
        super().__init__(name="Port Scan Detector", enabled=enabled)
        self._thresholds = config.thresholds
        self._overrides: dict[str, Any] = cfg_overrides or {}
        self._trackers: dict[str, ScanTracker] = {}

    # ── BaseDetector Interface ────────────────────────────────────────────────

    def detect(
        self,
        df: pd.DataFrame,
        traffic_stats=None,
        protocol_analysis=None,
        bandwidth_monitor=None,
        health_report=None,
        db_manager: Optional[DatabaseManager] = None,
        cfg: Optional[dict] = None,
    ) -> list[SecurityAlert]:
        """
        Run port scan detection rules on the packet DataFrame.

        Args:
            df:  Parsed packet DataFrame with columns:
                 src_ip, dst_ip, dst_port, tcp_flags (optional),
                 packet_length, timestamp.

        Returns:
            List of :class:`SecurityAlert` objects.
        """
        if df is None or df.empty:
            log.debug("PortScanDetector: empty DataFrame — skipping.")
            return []

        overrides = cfg or self._overrides
        port_threshold = int(
            overrides.get("portscan_unique_ports",
                          self._thresholds.portscan_unique_ports)
        )
        syn_ratio_threshold = float(
            overrides.get("portscan_syn_ratio",
                          self._thresholds.portscan_syn_ratio)
        )

        alerts: list[SecurityAlert] = []

        # Ensure required columns exist
        has_dst_port = "dst_port" in df.columns
        has_src_ip = "src_ip" in df.columns
        has_dst_ip = "dst_ip" in df.columns
        has_flags = "tcp_flags" in df.columns

        if not (has_src_ip and has_dst_ip):
            log.debug("PortScanDetector: missing src_ip or dst_ip columns.")
            return []

        # Build per-source trackers using vectorised groupby
        self._trackers = self._build_trackers(df)

        for src_ip, tracker in self._trackers.items():
            if tracker.total_packets < 3:
                # Too few packets to determine scanning behaviour
                continue

            port_count = len(tracker.probed_ports)
            host_count = len(tracker.probed_hosts)

            # ── Rule 1: Horizontal Scan ────────────────────────────────────
            if port_count >= port_threshold:
                scan_type = self._classify_scan_pattern(tracker)
                severity = self._rate_severity(port_count / port_threshold)
                evidence = {
                    "rule": "HORIZONTAL_SCAN",
                    "scan_type": scan_type.name,
                    "unique_ports_probed": port_count,
                    "threshold_ports": port_threshold,
                    "target_hosts": host_count,
                    "primary_target": self._primary_target(tracker),
                    "syn_count": tracker.syn_count,
                    "ack_count": tracker.ack_count,
                    "rst_count": tracker.rst_count,
                    "avg_packet_size": round(tracker.avg_packet_size, 1),
                    "ports_per_second": round(tracker.ports_per_second, 2),
                    "duration_seconds": round(tracker.duration_seconds, 2),
                    "sampled_ports": sorted(list(tracker.probed_ports))[:20],
                }
                confidence = self.confidence_score(evidence)
                alerts.append(self.generate_alert(
                    evidence=evidence,
                    attack_type="PortScan-Horizontal",
                    severity=severity,
                    confidence=confidence,
                    source_ip=src_ip,
                    destination_ip=self._primary_target(tracker),
                ))
                log.warning(
                    "Port scan [HORIZONTAL] from %s: %d unique ports probed.",
                    src_ip, port_count,
                )

            # ── Rule 2: Vertical Scan (same port, many hosts) ──────────────
            elif host_count >= port_threshold and port_count <= 5:
                evidence = {
                    "rule": "VERTICAL_SCAN",
                    "scan_type": "VERTICAL",
                    "unique_hosts_probed": host_count,
                    "threshold_hosts": port_threshold,
                    "probed_ports": sorted(list(tracker.probed_ports)),
                    "syn_count": tracker.syn_count,
                    "ack_count": tracker.ack_count,
                    "duration_seconds": round(tracker.duration_seconds, 2),
                }
                confidence = self.confidence_score(evidence)
                severity = self._rate_severity(host_count / port_threshold)
                alerts.append(self.generate_alert(
                    evidence=evidence,
                    attack_type="PortScan-Vertical",
                    severity=severity,
                    confidence=confidence,
                    source_ip=src_ip,
                    destination_ip="MULTIPLE",
                ))
                log.warning(
                    "Port scan [VERTICAL] from %s: %d unique hosts probed.",
                    src_ip, host_count,
                )

            # ── Rule 3: SYN Stealth Scan ───────────────────────────────────
            # High SYN / (SYN + ACK) ratio indicates half-open scanning
            total_flags = tracker.syn_count + tracker.ack_count
            if total_flags >= 5:
                syn_ratio = tracker.syn_count / max(total_flags, 1)
                if syn_ratio >= syn_ratio_threshold and port_count >= max(5, port_threshold // 4):
                    evidence = {
                        "rule": "SYN_STEALTH",
                        "scan_type": "SYN_STEALTH",
                        "syn_count": tracker.syn_count,
                        "ack_count": tracker.ack_count,
                        "rst_count": tracker.rst_count,
                        "syn_ratio": round(syn_ratio, 3),
                        "threshold_syn_ratio": syn_ratio_threshold,
                        "unique_ports_probed": port_count,
                        "primary_target": self._primary_target(tracker),
                    }
                    confidence = self.confidence_score(evidence)
                    alerts.append(self.generate_alert(
                        evidence=evidence,
                        attack_type="PortScan-SYNStealth",
                        severity="HIGH",
                        confidence=confidence,
                        source_ip=src_ip,
                        destination_ip=self._primary_target(tracker),
                    ))
                    log.warning(
                        "SYN stealth scan from %s: SYN ratio=%.2f, %d ports.",
                        src_ip, syn_ratio, port_count,
                    )

        return alerts

    def generate_alert(
        self,
        evidence: dict[str, Any],
        attack_type: str = "PortScan",
        severity: str = "MEDIUM",
        confidence: float = 0.75,
        source_ip: str = "UNKNOWN",
        destination_ip: str = "UNKNOWN",
        **kwargs,
    ) -> SecurityAlert:
        """
        Construct a port scan :class:`SecurityAlert`.

        Args:
            evidence:       Dict of supporting metrics.
            attack_type:    Scan variant (Horizontal, Vertical, SYNStealth).
            severity:       LOW | MEDIUM | HIGH | CRITICAL.
            confidence:     Detection confidence [0, 1].
            source_ip:      Scanning source IP.
            destination_ip: Primary scan target.

        Returns:
            Fully populated :class:`SecurityAlert`.
        """
        scan_type = evidence.get("scan_type", "UNKNOWN")
        port_count = evidence.get("unique_ports_probed",
                                  evidence.get("unique_hosts_probed", 0))
        pps = evidence.get("ports_per_second", 0)

        description = (
            f"{attack_type} detected [{scan_type}]: "
            f"{source_ip} probed {port_count} unique "
            f"{'ports' if 'VERTICAL' not in scan_type else 'hosts'} "
            f"on {destination_ip}. "
            f"Rate={pps:.1f} ports/s. Confidence={confidence:.0%}."
        )

        return SecurityAlert(
            alert_id=str(uuid.uuid4()),
            attack_type=attack_type,
            severity=severity,
            confidence=confidence,
            source_ip=source_ip,
            destination_ip=destination_ip,
            timestamp=utc_now_iso(),
            evidence=evidence,
            recommendation=self.recommendation(attack_type, evidence),
            detector_name=self.name,
            protocol="TCP",
            description=description,
        )

    def confidence_score(self, evidence: dict[str, Any]) -> float:
        """
        Compute scan detection confidence.

        Rule:
          - Port count relative to threshold → primary signal
          - SYN ratio → corroboration
          - Small packet sizes → corroboration (typical of SYN-only scans)

        Args:
            evidence: Detection evidence dict.

        Returns:
            Float in [0.0, 1.0].
        """
        rule = evidence.get("rule", "")
        base = 0.60

        if rule == "HORIZONTAL_SCAN":
            port_count = evidence.get("unique_ports_probed", 0)
            threshold = evidence.get("threshold_ports", 20)
            ratio = port_count / max(threshold, 1)
            base = min(0.97, 0.55 + 0.25 * min(ratio - 1, 4) / 4)
            # Corroborate: very small average packet → SYN-only probes
            avg_pkt = evidence.get("avg_packet_size", 200)
            if avg_pkt < 80:
                base = min(0.99, base + 0.05)
            # Corroborate: high RST count → target rejected connections
            rst = evidence.get("rst_count", 0)
            syn = evidence.get("syn_count", 1)
            if rst / max(syn, 1) > 0.5:
                base = min(0.99, base + 0.04)

        elif rule == "VERTICAL_SCAN":
            host_count = evidence.get("unique_hosts_probed", 0)
            threshold = evidence.get("threshold_hosts", 20)
            ratio = host_count / max(threshold, 1)
            base = min(0.95, 0.55 + 0.25 * min(ratio - 1, 4) / 4)

        elif rule == "SYN_STEALTH":
            syn_ratio = evidence.get("syn_ratio", 0)
            thr = evidence.get("threshold_syn_ratio", 0.85)
            excess = max(0, syn_ratio - thr)
            base = min(0.98, 0.65 + 0.30 * (excess / (1 - thr + 1e-9)))

        return round(base, 3)

    def recommendation(self, attack_type: str, evidence: dict[str, Any]) -> str:
        """
        Return an analyst recommendation for the detected scan type.

        Args:
            attack_type: Scan variant string.
            evidence:    Supporting metrics.

        Returns:
            Actionable recommendation string.
        """
        src = evidence.get("src_ip", "the source IP")
        rule = evidence.get("rule", "")
        ports = evidence.get("unique_ports_probed", 0)

        if rule == "SYN_STEALTH":
            return (
                f"Block {src} at the perimeter firewall immediately — "
                f"SYN stealth scanning is a precursor to targeted exploitation. "
                f"Enable TCP stateful inspection. "
                f"Review IDS signatures for the probed ports."
            )
        if rule == "VERTICAL_SCAN":
            probed_ports = evidence.get("probed_ports", [])
            port_str = ", ".join(str(p) for p in probed_ports[:5])
            return (
                f"Block {src} and investigate intent. "
                f"Vertical scan targets port(s) {port_str} across many hosts — "
                f"likely reconnaissance for a specific service vulnerability. "
                f"Review firewall rules for those ports."
            )
        return (
            f"Block {src} at the firewall. {ports} unique ports probed — "
            f"likely automated reconnaissance. "
            f"Investigate whether any probed ports responded. "
            f"Check for subsequent exploitation attempts."
        )

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _build_trackers(self, df: pd.DataFrame) -> dict[str, ScanTracker]:
        """
        Build per-source-IP ScanTracker objects using vectorised Pandas groupby.

        Args:
            df: Full packet DataFrame.

        Returns:
            Dict mapping src_ip → ScanTracker.
        """
        trackers: dict[str, ScanTracker] = {}

        # Parse timestamps once
        timestamps: Optional[pd.Series] = None
        if "timestamp" in df.columns:
            timestamps = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

        # Vectorised groupby by source IP
        grp = df.groupby("src_ip", sort=False)

        for src_ip, group in grp:
            tracker = ScanTracker(src_ip=str(src_ip))
            tracker.total_packets = len(group)

            if "dst_port" in group.columns:
                tracker.probed_ports = set(
                    group["dst_port"].dropna().astype(int).tolist()
                )
            if "dst_ip" in group.columns:
                tracker.probed_hosts = set(
                    group["dst_ip"].dropna().tolist()
                )

            # Average packet size (small = SYN-only probe)
            if "packet_length" in group.columns:
                tracker.avg_packet_size = float(
                    group["packet_length"].fillna(0).mean()
                )

            # Duration and ports per second
            if timestamps is not None:
                ts_grp = timestamps.loc[group.index].dropna()
                if len(ts_grp) >= 2:
                    duration = (ts_grp.max() - ts_grp.min()).total_seconds()
                    tracker.duration_seconds = duration
                    if duration > 0 and len(tracker.probed_ports) > 0:
                        tracker.ports_per_second = (
                            len(tracker.probed_ports) / duration
                        )
                    tracker.first_seen = str(ts_grp.min())
                    tracker.last_seen = str(ts_grp.max())

            # TCP flag breakdown
            if "tcp_flags" in group.columns:
                flags = group["tcp_flags"].fillna("0")

                def _flag(f: Any, mask: int) -> bool:
                    try:
                        return bool(int(str(f), 0) & mask)
                    except (ValueError, TypeError):
                        return False

                tracker.syn_count = int(flags.map(lambda f: _flag(f, 0x02)).sum())
                tracker.ack_count = int(flags.map(lambda f: _flag(f, 0x10)).sum())
                tracker.rst_count = int(flags.map(lambda f: _flag(f, 0x04)).sum())
                tracker.fin_count = int(flags.map(lambda f: _flag(f, 0x01)).sum())

            trackers[str(src_ip)] = tracker

        return trackers

    @staticmethod
    def _classify_scan_pattern(tracker: ScanTracker) -> ScanType:
        """
        Classify whether the scan appears sequential or random.

        Sequential: sorted port list has monotonically increasing differences
                    with low variance (±10).
        Random:     high variance in port differences.

        Args:
            tracker: Populated ScanTracker.

        Returns:
            :class:`ScanType`.
        """
        if not tracker.probed_ports:
            return ScanType.HORIZONTAL
        ports = sorted(tracker.probed_ports)
        if len(ports) < 3:
            return ScanType.HORIZONTAL
        diffs = [ports[i + 1] - ports[i] for i in range(len(ports) - 1)]
        variance = float(np.var(diffs))
        return ScanType.SEQUENTIAL if variance < 100 else ScanType.RANDOM

    @staticmethod
    def _primary_target(tracker: ScanTracker) -> str:
        """Return the most frequently probed destination host."""
        if not tracker.probed_hosts:
            return "UNKNOWN"
        return str(next(iter(tracker.probed_hosts)))

    @staticmethod
    def _rate_severity(ratio: float) -> str:
        """Map excess ratio to severity."""
        if ratio >= 5.0:
            return "CRITICAL"
        if ratio >= 3.0:
            return "HIGH"
        if ratio >= 1.5:
            return "MEDIUM"
        return "LOW"

    def reset(self) -> None:
        """Clear all scan trackers and reset counter."""
        super().reset()
        self._trackers.clear()

    # ── Legacy Compatibility ───────────────────────────────────────────────────

    def _build_alert(
        self,
        src_ip: str,
        dst_ip: str,
        scan_type: ScanType,
        port_count: int,
        severity: str = "MEDIUM",
    ) -> AlertRecord:
        """
        Legacy method — construct an AlertRecord (Phase 1 API).

        Retained for backward compatibility. New code should use generate_alert().
        """
        import json
        desc = (
            f"{scan_type.name} port scan detected from {src_ip} → {dst_ip}. "
            f"{port_count} unique ports probed."
        )
        return AlertRecord(
            timestamp=utc_now_iso(),
            alert_type="PortScan",
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            description=desc,
            raw_evidence=json.dumps(
                {"scan_type": scan_type.name, "probed_ports": port_count}
            ),
        )
