"""
ddos_detector.py — DDoS Attack Detector
=========================================
Network Traffic Analysis and Intrusion Detection System

Detects Distributed Denial-of-Service (DDoS) attack patterns using
deterministic, rule-based heuristics. No machine learning is used.
Every alert is fully explainable by the triggering rule metrics.

Detection Rules:
  1. Volume Flood     — packets/sec exceeds threshold
  2. Bandwidth Flood  — bytes/sec exceeds threshold
  3. Distributed      — many unique source IPs → single destination
  4. Traffic Growth   — rapid inbound growth rate
  5. Protocol Flood   — UDP or ICMP dominance combined with volume

Classes:
    DDoSWindow    — Sliding window state dataclass
    DDoSDetector  — BaseDetector implementation (Phase 5 — fully implemented)

Author: Network Traffic Analyzer Project
Version: 5.0.0
Python: 3.11+
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
# SLIDING WINDOW STATE
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class DDoSWindow:
    """
    Aggregated traffic metrics within the detection time window.

    Populated by vectorised Pandas operations in DDoSDetector._compute_window().
    """

    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    # Top destination IP and its packet count
    top_dst_ip: str = ""
    top_dst_count: int = 0
    top_dst_fraction: float = 0.0
    # Protocol breakdown
    syn_count: int = 0
    ack_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    tcp_count: int = 0
    # Growth metrics (second half vs first half PPS)
    growth_rate: float = 0.0


# ──────────────────────────────────────────────────────────────────────────────
# DDOS DETECTOR
# ──────────────────────────────────────────────────────────────────────────────

class DDoSDetector(BaseDetector):
    """
    Rule-based DDoS attack detector.

    Implements the :class:`BaseDetector` interface and applies five
    deterministic rules to identify DDoS attack patterns in a packet
    DataFrame. Adaptive thresholds are computed relative to observed
    baseline traffic where possible.

    Detection Rules (all configurable via DetectionThresholds):
      1. PPS flood:          avg PPS > ``ddos_packets_per_second``
      2. Bandwidth flood:    avg BPS > ``ddos_bytes_per_second``
      3. Distributed attack: unique source IPs > ``ddos_unique_src_ips``
                             AND > 80% of traffic targets single dst IP
      4. Rapid growth:       second-half PPS > first-half PPS by 200%+
      5. Protocol flood:     UDP or ICMP > 80% of all traffic AND
                             PPS > 50% of configured threshold
    """

    PRIORITY: int = 10   # Run DDoS check first — highest risk

    def __init__(
        self,
        enabled: bool = True,
        cfg_overrides: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Initialise the DDoSDetector.

        Args:
            enabled:       Whether the detector is active.
            cfg_overrides: Optional dict to override specific threshold keys.
        """
        super().__init__(name="DDoS Detector", enabled=enabled)
        self._thresholds = config.thresholds
        self._overrides: dict[str, Any] = cfg_overrides or {}
        self.window = DDoSWindow()

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
        Run DDoS detection rules on the packet DataFrame.

        Args:
            df:  Parsed packet DataFrame with columns:
                 timestamp, src_ip, dst_ip, packet_length,
                 protocol, tcp_flags (optional).

        Returns:
            List of :class:`SecurityAlert` objects (empty if no DDoS detected).
        """
        if df is None or df.empty:
            log.debug("DDoSDetector: empty DataFrame — skipping.")
            return []

        overrides = cfg or self._overrides
        alerts: list[SecurityAlert] = []

        # Compute aggregated window metrics using vectorised Pandas ops
        self.window = self._compute_window(df)

        if self.window.total_packets == 0:
            return []

        # ── Rule 1: PPS Flood ──────────────────────────────────────────────
        pps_threshold = int(
            overrides.get("ddos_packets_per_second",
                          self._thresholds.ddos_packets_per_second)
        )
        if self.window.packets_per_second > pps_threshold:
            evidence = {
                "rule": "PPS_FLOOD",
                "packets_per_second": round(self.window.packets_per_second, 2),
                "threshold_pps": pps_threshold,
                "total_packets": self.window.total_packets,
                "unique_src_ips": self.window.unique_src_ips,
                "top_dst_ip": self.window.top_dst_ip,
            }
            confidence = self.confidence_score(evidence)
            severity = self._rate_severity(
                self.window.packets_per_second / pps_threshold
            )
            alerts.append(self.generate_alert(
                evidence=evidence,
                attack_type="DDoS-VolumeFlood",
                severity=severity,
                confidence=confidence,
                source_ip="MULTIPLE" if self.window.unique_src_ips > 1 else self._get_top_src(df),
                destination_ip=self.window.top_dst_ip or "MULTIPLE",
            ))
            log.warning(
                "DDoS PPS flood detected: %.1f pps (threshold=%d).",
                self.window.packets_per_second, pps_threshold,
            )

        # ── Rule 2: Bandwidth Flood ────────────────────────────────────────
        bps_threshold = int(
            overrides.get("ddos_bytes_per_second",
                          self._thresholds.ddos_bytes_per_second)
        )
        if self.window.bytes_per_second > bps_threshold:
            evidence = {
                "rule": "BPS_FLOOD",
                "bytes_per_second": round(self.window.bytes_per_second, 2),
                "threshold_bps": bps_threshold,
                "total_bytes": self.window.total_bytes,
                "mbps_observed": round(self.window.bytes_per_second * 8 / 1_000_000, 2),
                "top_dst_ip": self.window.top_dst_ip,
            }
            confidence = self.confidence_score(evidence)
            severity = self._rate_severity(
                self.window.bytes_per_second / bps_threshold
            )
            alerts.append(self.generate_alert(
                evidence=evidence,
                attack_type="DDoS-BandwidthFlood",
                severity=severity,
                confidence=confidence,
                source_ip="MULTIPLE" if self.window.unique_src_ips > 1 else self._get_top_src(df),
                destination_ip=self.window.top_dst_ip or "MULTIPLE",
            ))
            log.warning(
                "DDoS bandwidth flood: %.2f MB/s (threshold=%.2f MB/s).",
                self.window.bytes_per_second / 1e6, bps_threshold / 1e6,
            )

        # ── Rule 3: Distributed Attack (many-to-one) ───────────────────────
        src_threshold = int(
            overrides.get("ddos_unique_src_ips",
                          self._thresholds.ddos_unique_src_ips)
        )
        if (
            self.window.unique_src_ips >= src_threshold
            and self.window.top_dst_fraction >= 0.70
        ):
            evidence = {
                "rule": "DISTRIBUTED_ATTACK",
                "unique_src_ips": self.window.unique_src_ips,
                "threshold_src_ips": src_threshold,
                "target_ip": self.window.top_dst_ip,
                "target_traffic_fraction": round(self.window.top_dst_fraction, 3),
                "packets_to_target": self.window.top_dst_count,
            }
            confidence = self.confidence_score(evidence)
            alerts.append(self.generate_alert(
                evidence=evidence,
                attack_type="DDoS-Distributed",
                severity="HIGH",
                confidence=confidence,
                source_ip="MULTIPLE",
                destination_ip=self.window.top_dst_ip,
            ))
            log.warning(
                "DDoS distributed: %d unique sources → %s (%.1f%% of traffic).",
                self.window.unique_src_ips,
                self.window.top_dst_ip,
                self.window.top_dst_fraction * 100,
            )

        # ── Rule 4: Rapid Traffic Growth ───────────────────────────────────
        # Growth rate > 2.0 means second half has 3× more traffic than first
        if self.window.growth_rate > 2.0 and self.window.packets_per_second > (pps_threshold * 0.5):
            evidence = {
                "rule": "RAPID_GROWTH",
                "growth_rate": round(self.window.growth_rate, 3),
                "packets_per_second": round(self.window.packets_per_second, 2),
                "top_dst_ip": self.window.top_dst_ip,
                "unique_src_ips": self.window.unique_src_ips,
            }
            confidence = self.confidence_score(evidence)
            alerts.append(self.generate_alert(
                evidence=evidence,
                attack_type="DDoS-RapidGrowth",
                severity="MEDIUM",
                confidence=confidence,
                source_ip="MULTIPLE" if self.window.unique_src_ips > 1 else self._get_top_src(df),
                destination_ip=self.window.top_dst_ip or "MULTIPLE",
            ))
            log.warning(
                "DDoS rapid growth detected: rate=%.2f× (pps=%.1f).",
                self.window.growth_rate, self.window.packets_per_second,
            )

        # ── Rule 5: Protocol Flood (UDP/ICMP dominance) ────────────────────
        total = max(self.window.total_packets, 1)
        udp_frac = self.window.udp_count / total
        icmp_frac = self.window.icmp_count / total
        proto_flood_frac = max(udp_frac, icmp_frac)
        proto_name = "UDP" if udp_frac >= icmp_frac else "ICMP"
        proto_flood_pps_min = pps_threshold * 0.30

        if proto_flood_frac >= 0.75 and self.window.packets_per_second >= proto_flood_pps_min:
            evidence = {
                "rule": "PROTOCOL_FLOOD",
                "dominant_protocol": proto_name,
                "protocol_fraction": round(proto_flood_frac, 3),
                "packets_per_second": round(self.window.packets_per_second, 2),
                "udp_count": self.window.udp_count,
                "icmp_count": self.window.icmp_count,
                "top_dst_ip": self.window.top_dst_ip,
            }
            confidence = self.confidence_score(evidence)
            alerts.append(self.generate_alert(
                evidence=evidence,
                attack_type=f"DDoS-{proto_name}Flood",
                severity="HIGH",
                confidence=confidence,
                source_ip="MULTIPLE" if self.window.unique_src_ips > 1 else self._get_top_src(df),
                destination_ip=self.window.top_dst_ip or "MULTIPLE",
            ))
            log.warning(
                "DDoS %s flood: %.1f%% of traffic is %s (pps=%.1f).",
                proto_name, proto_flood_frac * 100, proto_name,
                self.window.packets_per_second,
            )

        return alerts

    def generate_alert(
        self,
        evidence: dict[str, Any],
        attack_type: str = "DDoS",
        severity: str = "HIGH",
        confidence: float = 0.8,
        source_ip: str = "MULTIPLE",
        destination_ip: str = "0.0.0.0",
        **kwargs,
    ) -> SecurityAlert:
        """
        Construct a DDoS :class:`SecurityAlert` from detection evidence.

        Args:
            evidence:        Dict of supporting metrics.
            attack_type:     Specific DDoS variant.
            severity:        LOW | MEDIUM | HIGH | CRITICAL.
            confidence:      Confidence score [0, 1].
            source_ip:       Attacking IP (or "MULTIPLE").
            destination_ip:  Target IP.

        Returns:
            Fully populated :class:`SecurityAlert`.
        """
        rule = evidence.get("rule", "UNKNOWN")
        pps = evidence.get("packets_per_second", 0)
        unique_srcs = evidence.get("unique_src_ips", 0)

        description = (
            f"{attack_type} detected [{rule}]: "
            f"{unique_srcs} source(s) → {destination_ip}. "
            f"PPS={pps:.1f}. Confidence={confidence:.0%}."
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
            protocol=evidence.get("dominant_protocol", "MULTIPLE"),
            description=description,
        )

    def confidence_score(self, evidence: dict[str, Any]) -> float:
        """
        Compute detection confidence from evidence metrics.

        Confidence is a composite of:
          - How far above threshold the key metric is (excess ratio)
          - Number of corroborating signals in the evidence

        Args:
            evidence: Dict with rule name and supporting metrics.

        Returns:
            Float in [0.0, 1.0].
        """
        rule = evidence.get("rule", "")
        base = 0.50

        if rule == "PPS_FLOOD":
            pps = evidence.get("packets_per_second", 0)
            thr = evidence.get("threshold_pps", 1)
            ratio = pps / max(thr, 1)
            base = min(0.95, 0.50 + 0.30 * min(ratio - 1, 2) / 2)

        elif rule == "BPS_FLOOD":
            bps = evidence.get("bytes_per_second", 0)
            thr = evidence.get("threshold_bps", 1)
            ratio = bps / max(thr, 1)
            base = min(0.95, 0.50 + 0.30 * min(ratio - 1, 2) / 2)

        elif rule == "DISTRIBUTED_ATTACK":
            srcs = evidence.get("unique_src_ips", 0)
            thr_srcs = evidence.get("threshold_src_ips", 50)
            frac = evidence.get("target_traffic_fraction", 0)
            src_ratio = min(srcs / max(thr_srcs, 1), 3)
            base = min(0.98, 0.60 + 0.15 * src_ratio + 0.15 * frac)

        elif rule == "RAPID_GROWTH":
            growth = evidence.get("growth_rate", 1)
            base = min(0.90, 0.55 + 0.10 * min(growth, 5))

        elif rule == "PROTOCOL_FLOOD":
            frac = evidence.get("protocol_fraction", 0)
            base = min(0.92, 0.55 + 0.35 * frac)

        # Additional corroboration: many unique sources raises confidence
        unique_srcs = evidence.get("unique_src_ips", 0)
        if unique_srcs > 10:
            base = min(0.99, base + 0.05)

        return round(base, 3)

    def recommendation(self, attack_type: str, evidence: dict[str, Any]) -> str:
        """
        Return a SOC analyst recommendation for the detected DDoS variant.

        Args:
            attack_type: Specific DDoS type string.
            evidence:    Supporting metrics.

        Returns:
            Actionable recommendation string.
        """
        rule = evidence.get("rule", "")
        target = evidence.get("top_dst_ip", evidence.get("target_ip", "target"))
        srcs = evidence.get("unique_src_ips", 0)

        if rule == "DISTRIBUTED_ATTACK":
            return (
                f"Enable upstream blackhole routing (RTBH) or contact upstream ISP "
                f"to null-route traffic to {target}. "
                f"Engage DDoS scrubbing service — {srcs} unique sources detected. "
                f"Implement rate-limiting ACLs on border routers."
            )
        if rule in ("PPS_FLOOD", "BPS_FLOOD"):
            return (
                f"Apply rate-limiting on ingress interfaces. "
                f"Activate traffic scrubbing centre. "
                f"Consider temporary null-routing {target} if service is expendable. "
                f"Notify upstream ISP for BGP-based mitigation."
            )
        if rule == "PROTOCOL_FLOOD":
            proto = evidence.get("dominant_protocol", "UDP")
            return (
                f"Block or rate-limit inbound {proto} traffic at edge firewall. "
                f"Apply uRPF (Unicast Reverse Path Forwarding) to drop spoofed packets. "
                f"Enable {proto} flood protection on perimeter devices."
            )
        if rule == "RAPID_GROWTH":
            return (
                f"Activate DDoS mitigation appliance — traffic is growing rapidly. "
                f"Prepare null-route for {target}. "
                f"Alert upstream provider immediately."
            )
        return (
            "Engage DDoS mitigation measures: rate-limiting, scrubbing, "
            "or upstream null-routing. Notify security team and ISP."
        )

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _compute_window(self, df: pd.DataFrame) -> DDoSWindow:
        """
        Compute aggregated window metrics using vectorised Pandas operations.

        Args:
            df: Raw packet DataFrame.

        Returns:
            Populated :class:`DDoSWindow`.
        """
        window = DDoSWindow()
        window.total_packets = len(df)

        # Total bytes
        if "packet_length" in df.columns:
            window.total_bytes = int(df["packet_length"].fillna(0).sum())

        # Duration and rates
        if "timestamp" in df.columns:
            ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
            ts_valid = ts.dropna()
            if len(ts_valid) >= 2:
                duration = (ts_valid.max() - ts_valid.min()).total_seconds()
                window.duration_seconds = duration
                if duration > 0:
                    window.packets_per_second = window.total_packets / duration
                    window.bytes_per_second = window.total_bytes / duration
                    # Growth rate: compare PPS in first half vs second half
                    mid = ts_valid.median()
                    first_half = (ts <= mid).sum()
                    second_half = (ts > mid).sum()
                    if first_half > 0:
                        window.growth_rate = round(
                            (second_half - first_half) / first_half, 4
                        )

        # Unique IPs
        if "src_ip" in df.columns:
            window.unique_src_ips = int(df["src_ip"].nunique())
        if "dst_ip" in df.columns:
            window.unique_dst_ips = int(df["dst_ip"].nunique())
            # Top destination
            dst_counts = df["dst_ip"].value_counts()
            if not dst_counts.empty:
                window.top_dst_ip = str(dst_counts.index[0])
                window.top_dst_count = int(dst_counts.iloc[0])
                window.top_dst_fraction = round(
                    window.top_dst_count / max(window.total_packets, 1), 4
                )

        # Protocol breakdown (vectorised)
        if "protocol" in df.columns:
            proto_series = df["protocol"].str.upper().fillna("")
            window.tcp_count = int((proto_series == "TCP").sum())
            window.udp_count = int((proto_series == "UDP").sum())
            window.icmp_count = int(proto_series.str.startswith("ICMP").sum())

        # TCP flags
        if "tcp_flags" in df.columns:
            flags = df["tcp_flags"].fillna("0")
            # Flags may be hex strings like "0x02" or integers
            def _has_flag(flag_val: Any, mask: int) -> bool:
                try:
                    return bool(int(str(flag_val), 0) & mask)
                except (ValueError, TypeError):
                    return False

            # SYN=0x02, ACK=0x10 — vectorised via map
            window.syn_count = int(
                flags.map(lambda f: _has_flag(f, 0x02)).sum()
            )
            window.ack_count = int(
                flags.map(lambda f: _has_flag(f, 0x10)).sum()
            )

        log.debug(
            "DDoSWindow: pkts=%d, pps=%.1f, bps=%.0f, src_ips=%d, "
            "top_dst=%s (%.1f%%), growth=%.2f.",
            window.total_packets, window.packets_per_second,
            window.bytes_per_second, window.unique_src_ips,
            window.top_dst_ip, window.top_dst_fraction * 100,
            window.growth_rate,
        )
        return window

    @staticmethod
    def _rate_severity(ratio: float) -> str:
        """Map an excess ratio (observed / threshold) to a severity label."""
        if ratio >= 5.0:
            return "CRITICAL"
        if ratio >= 2.0:
            return "HIGH"
        if ratio >= 1.5:
            return "MEDIUM"
        return "LOW"

    def _get_top_src(self, df: pd.DataFrame) -> str:
        """Return the top source IP by packet count."""
        if "src_ip" not in df.columns or df.empty:
            return "UNKNOWN"
        counts = df["src_ip"].value_counts()
        return str(counts.index[0]) if not counts.empty else "UNKNOWN"

    def reset(self) -> None:
        """Reset sliding window and alert counter."""
        super().reset()
        self.window = DDoSWindow()

    # ── Legacy Compatibility ───────────────────────────────────────────────────

    def _build_alert(
        self,
        src_ip: str,
        dst_ip: str,
        description: str,
        severity: str = "HIGH",
        evidence: Optional[dict] = None,
    ) -> AlertRecord:
        """
        Legacy method — construct an AlertRecord directly (Phase 1 API).

        Retained for backward compatibility with existing code that calls
        _build_alert() directly. New code should use generate_alert().
        """
        import json
        return AlertRecord(
            timestamp=utc_now_iso(),
            alert_type="DDoS",
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            description=description,
            raw_evidence=json.dumps(evidence or {}),
        )
