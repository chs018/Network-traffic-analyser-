"""
synflood_detector.py — SYN Flood Attack Detector
==================================================
Network Traffic Analysis and Intrusion Detection System

Detects TCP SYN Flood attacks using deterministic, rule-based heuristics.
No machine learning — every alert is fully explainable by the triggering
metrics.

A SYN flood exploits the TCP three-way handshake: the attacker sends
large volumes of TCP SYN packets without completing the handshake,
exhausting the target's connection state table (half-open connections).

Detection Rules:
  1. SYN Dominance     — SYN packets > threshold fraction of all TCP
  2. Low ACK Ratio     — SYN/(SYN+ACK) ratio exceeds threshold
  3. High-Volume SYN   — absolute SYN count per second exceeds threshold
  4. Half-Open Estimate— estimated half-open connections exceed safe limit

Metrics tracked:
  - SYN count and SYN/s rate
  - ACK count and ACK/s rate
  - SYN-to-(SYN+ACK) ratio
  - Estimated half-open connection count (SYN without matching ACK)

Classes:
    SYNFloodWindow   — Aggregated window metrics dataclass
    SYNFloodDetector — BaseDetector implementation (Phase 5 — fully implemented)

Author: Network Traffic Analyzer Project
Version: 5.0.0
Python: 3.11+
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Optional

import pandas as pd

from database.db_manager import DatabaseManager
from detection.rule_engine import BaseDetector, SecurityAlert
from utils.config import config
from utils.helpers import utc_now_iso
from utils.logger import get_detection_logger

log = get_detection_logger()


# ──────────────────────────────────────────────────────────────────────────────
# WINDOW STATE DATACLASS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SYNFloodWindow:
    """
    Aggregated TCP flag metrics within the detection window.

    Populated by vectorised Pandas operations in SYNFloodDetector._compute_window().
    """

    total_packets: int = 0
    total_tcp_packets: int = 0
    syn_count: int = 0
    ack_count: int = 0
    syn_ack_count: int = 0    # Packets with both SYN and ACK set
    rst_count: int = 0
    fin_count: int = 0
    duration_seconds: float = 0.0

    # Rates
    syn_per_second: float = 0.0
    ack_per_second: float = 0.0
    pps: float = 0.0

    # Ratios
    syn_fraction_of_tcp: float = 0.0    # SYN / total TCP
    syn_ack_ratio: float = 0.0          # SYN / (SYN + ACK)
    half_open_estimate: int = 0         # SYN - ACK (lower bound half-opens)

    # IP context
    unique_src_ips: int = 0
    top_dst_ip: str = ""
    top_dst_syn_count: int = 0
    top_dst_fraction: float = 0.0


# ──────────────────────────────────────────────────────────────────────────────
# SYN FLOOD DETECTOR
# ──────────────────────────────────────────────────────────────────────────────

class SYNFloodDetector(BaseDetector):
    """
    Rule-based SYN Flood attack detector.

    Extracts TCP flags from the packet DataFrame using vectorised operations,
    computes SYN/ACK ratios and rates, then applies four independent rules
    to identify SYN flood conditions.

    All thresholds are configurable via DetectionThresholds or cfg_overrides.
    """

    PRIORITY: int = 15   # Between DDoS (10) and PortScan (20)

    # Default configurable thresholds (can be overridden via cfg_overrides)
    _DEFAULT_SYN_RATIO_THRESHOLD: float = 0.85     # SYN/(SYN+ACK)
    _DEFAULT_SYN_DOMINANCE_THRESHOLD: float = 0.70  # SYN / all TCP
    _DEFAULT_SYN_PER_SECOND: float = 500.0          # Absolute SYN/s threshold
    _DEFAULT_HALF_OPEN_LIMIT: int = 100             # Estimated half-open limit

    def __init__(
        self,
        enabled: bool = True,
        cfg_overrides: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Initialise the SYNFloodDetector.

        Args:
            enabled:       Whether the detector is active.
            cfg_overrides: Optional dict to override threshold values.
        """
        super().__init__(name="SYN Flood Detector", enabled=enabled)
        self._thresholds = config.thresholds
        self._overrides: dict[str, Any] = cfg_overrides or {}
        self.window = SYNFloodWindow()

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
        Run SYN flood detection rules on the packet DataFrame.

        Args:
            df:  Parsed packet DataFrame. Requires 'tcp_flags' column for full
                 analysis; can use 'protocol' column as fallback for SYN count
                 estimation from TCP-only traffic.

        Returns:
            List of :class:`SecurityAlert` objects (empty if no SYN flood).
        """
        if df is None or df.empty:
            log.debug("SYNFloodDetector: empty DataFrame — skipping.")
            return []

        overrides = cfg or self._overrides

        # Thresholds (with override support)
        syn_ratio_thr = float(
            overrides.get("synflood_syn_ack_ratio", self._DEFAULT_SYN_RATIO_THRESHOLD)
        )
        syn_dominance_thr = float(
            overrides.get("synflood_syn_dominance", self._DEFAULT_SYN_DOMINANCE_THRESHOLD)
        )
        syn_pps_thr = float(
            overrides.get("synflood_syn_per_second", self._DEFAULT_SYN_PER_SECOND)
        )
        half_open_limit = int(
            overrides.get("synflood_half_open_limit", self._DEFAULT_HALF_OPEN_LIMIT)
        )

        # Compute aggregated window metrics
        self.window = self._compute_window(df)
        alerts: list[SecurityAlert] = []

        if self.window.total_tcp_packets < 5:
            log.debug(
                "SYNFloodDetector: insufficient TCP packets (%d) for analysis.",
                self.window.total_tcp_packets,
            )
            return []

        # ── Rule 1: SYN Dominance (high SYN fraction of all TCP) ──────────
        if self.window.syn_fraction_of_tcp >= syn_dominance_thr:
            evidence = {
                "rule": "SYN_DOMINANCE",
                "syn_count": self.window.syn_count,
                "total_tcp": self.window.total_tcp_packets,
                "syn_fraction_of_tcp": round(self.window.syn_fraction_of_tcp, 3),
                "threshold_syn_dominance": syn_dominance_thr,
                "ack_count": self.window.ack_count,
                "half_open_estimate": self.window.half_open_estimate,
                "unique_src_ips": self.window.unique_src_ips,
                "top_dst_ip": self.window.top_dst_ip,
            }
            confidence = self.confidence_score(evidence)
            severity = self._rate_severity(
                self.window.syn_fraction_of_tcp / syn_dominance_thr
            )
            alerts.append(self.generate_alert(
                evidence=evidence,
                attack_type="SYNFlood-Dominance",
                severity=severity,
                confidence=confidence,
                source_ip="MULTIPLE" if self.window.unique_src_ips > 1 else "",
                destination_ip=self.window.top_dst_ip,
            ))
            log.warning(
                "SYN dominance: %.1f%% of TCP is SYN-only (threshold=%.0f%%).",
                self.window.syn_fraction_of_tcp * 100, syn_dominance_thr * 100,
            )

        # ── Rule 2: Low ACK Ratio (SYN without completing handshake) ──────
        if self.window.syn_ack_ratio >= syn_ratio_thr and self.window.syn_count >= 10:
            evidence = {
                "rule": "LOW_ACK_RATIO",
                "syn_count": self.window.syn_count,
                "ack_count": self.window.ack_count,
                "syn_ack_ratio": round(self.window.syn_ack_ratio, 3),
                "threshold_ratio": syn_ratio_thr,
                "half_open_estimate": self.window.half_open_estimate,
                "unique_src_ips": self.window.unique_src_ips,
                "top_dst_ip": self.window.top_dst_ip,
                "top_dst_fraction": round(self.window.top_dst_fraction, 3),
            }
            confidence = self.confidence_score(evidence)
            severity = self._rate_severity(
                self.window.syn_ack_ratio / syn_ratio_thr
            )
            alerts.append(self.generate_alert(
                evidence=evidence,
                attack_type="SYNFlood-LowACK",
                severity=severity,
                confidence=confidence,
                source_ip="MULTIPLE" if self.window.unique_src_ips > 1 else "",
                destination_ip=self.window.top_dst_ip,
            ))
            log.warning(
                "SYN flood [LOW ACK]: SYN/ACK ratio=%.3f (threshold=%.3f), "
                "half-open est.=%d.",
                self.window.syn_ack_ratio, syn_ratio_thr,
                self.window.half_open_estimate,
            )

        # ── Rule 3: High-Volume SYN Rate ───────────────────────────────────
        if self.window.syn_per_second >= syn_pps_thr:
            evidence = {
                "rule": "HIGH_SYN_RATE",
                "syn_per_second": round(self.window.syn_per_second, 2),
                "threshold_syn_pps": syn_pps_thr,
                "syn_count": self.window.syn_count,
                "duration_seconds": round(self.window.duration_seconds, 2),
                "ack_per_second": round(self.window.ack_per_second, 2),
                "unique_src_ips": self.window.unique_src_ips,
                "top_dst_ip": self.window.top_dst_ip,
            }
            confidence = self.confidence_score(evidence)
            severity = self._rate_severity(
                self.window.syn_per_second / syn_pps_thr
            )
            alerts.append(self.generate_alert(
                evidence=evidence,
                attack_type="SYNFlood-HighRate",
                severity=severity,
                confidence=confidence,
                source_ip="MULTIPLE" if self.window.unique_src_ips > 1 else "",
                destination_ip=self.window.top_dst_ip,
            ))
            log.warning(
                "SYN flood [HIGH RATE]: %.1f SYN/s (threshold=%.1f).",
                self.window.syn_per_second, syn_pps_thr,
            )

        # ── Rule 4: High Half-Open Connection Estimate ─────────────────────
        if (
            self.window.half_open_estimate >= half_open_limit
            and self.window.syn_ack_ratio >= 0.60
        ):
            evidence = {
                "rule": "HALF_OPEN_EXHAUSTION",
                "half_open_estimate": self.window.half_open_estimate,
                "half_open_limit": half_open_limit,
                "syn_count": self.window.syn_count,
                "ack_count": self.window.ack_count,
                "syn_ack_ratio": round(self.window.syn_ack_ratio, 3),
                "unique_src_ips": self.window.unique_src_ips,
                "top_dst_ip": self.window.top_dst_ip,
            }
            confidence = self.confidence_score(evidence)
            severity = self._rate_severity(
                self.window.half_open_estimate / max(half_open_limit, 1)
            )
            alerts.append(self.generate_alert(
                evidence=evidence,
                attack_type="SYNFlood-HalfOpen",
                severity=severity,
                confidence=confidence,
                source_ip="MULTIPLE" if self.window.unique_src_ips > 1 else "",
                destination_ip=self.window.top_dst_ip,
            ))
            log.warning(
                "SYN flood [HALF-OPEN]: ~%d half-open connections estimated "
                "(limit=%d).",
                self.window.half_open_estimate, half_open_limit,
            )

        return alerts

    def generate_alert(
        self,
        evidence: dict[str, Any],
        attack_type: str = "SYNFlood",
        severity: str = "HIGH",
        confidence: float = 0.80,
        source_ip: str = "MULTIPLE",
        destination_ip: str = "0.0.0.0",
        **kwargs,
    ) -> SecurityAlert:
        """
        Construct a SYN flood :class:`SecurityAlert`.

        Args:
            evidence:       Supporting detection metrics.
            attack_type:    SYN flood variant.
            severity:       LOW | MEDIUM | HIGH | CRITICAL.
            confidence:     Detection confidence [0, 1].
            source_ip:      Source IP or "MULTIPLE".
            destination_ip: Target IP.

        Returns:
            Fully populated :class:`SecurityAlert`.
        """
        rule = evidence.get("rule", "UNKNOWN")
        syn = evidence.get("syn_count", 0)
        ack = evidence.get("ack_count", 0)
        ratio = evidence.get("syn_ack_ratio", 0)
        half_open = evidence.get("half_open_estimate", 0)

        if not source_ip or source_ip == "":
            # Try to extract a single source from the top dst data
            source_ip = "MULTIPLE"

        description = (
            f"{attack_type} detected [{rule}]: "
            f"SYN={syn}, ACK={ack}, SYN/ACK ratio={ratio:.3f}. "
            f"Est. half-open={half_open}. "
            f"Target={destination_ip}. Confidence={confidence:.0%}."
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
        Compute SYN flood confidence from evidence metrics.

        Factors:
          - SYN/ACK ratio (primary signal)
          - SYN fraction of all TCP (corroboration)
          - Half-open estimate magnitude

        Args:
            evidence: Detection evidence dict.

        Returns:
            Float in [0.0, 1.0].
        """
        rule = evidence.get("rule", "")
        base = 0.60

        if rule == "SYN_DOMINANCE":
            frac = evidence.get("syn_fraction_of_tcp", 0)
            thr = evidence.get("threshold_syn_dominance", 0.70)
            excess = max(0, frac - thr)
            base = min(0.97, 0.55 + 0.35 * (excess / (1 - thr + 1e-9)))

        elif rule == "LOW_ACK_RATIO":
            ratio = evidence.get("syn_ack_ratio", 0)
            thr = evidence.get("threshold_ratio", 0.85)
            excess = max(0, ratio - thr)
            base = min(0.98, 0.60 + 0.35 * (excess / (1 - thr + 1e-9)))
            # Corroborate: high half-open estimate
            half_open = evidence.get("half_open_estimate", 0)
            if half_open > 100:
                base = min(0.99, base + 0.04)

        elif rule == "HIGH_SYN_RATE":
            syn_pps = evidence.get("syn_per_second", 0)
            thr = evidence.get("threshold_syn_pps", 500)
            ratio = syn_pps / max(thr, 1)
            base = min(0.97, 0.55 + 0.30 * min(ratio - 1, 4) / 4)

        elif rule == "HALF_OPEN_EXHAUSTION":
            half_open = evidence.get("half_open_estimate", 0)
            limit = evidence.get("half_open_limit", 100)
            ratio = half_open / max(limit, 1)
            base = min(0.95, 0.60 + 0.25 * min(ratio - 1, 4) / 4)

        return round(base, 3)

    def recommendation(self, attack_type: str, evidence: dict[str, Any]) -> str:
        """
        Return an analyst recommendation for the SYN flood variant.

        Args:
            attack_type: SYN flood variant string.
            evidence:    Supporting metrics.

        Returns:
            Actionable recommendation string.
        """
        rule = evidence.get("rule", "")
        target = evidence.get("top_dst_ip", "the target")
        half_open = evidence.get("half_open_estimate", 0)

        if rule == "HALF_OPEN_EXHAUSTION":
            return (
                f"Enable SYN cookies on {target} immediately — "
                f"~{half_open} half-open connections estimated. "
                f"Apply 'tcp_syncookies=1' (Linux) or SYN Attack Protection (Windows). "
                f"Reduce SYN backlog timeout. "
                f"Enable rate-limiting on perimeter firewall for new TCP connections."
            )
        if rule in ("SYN_DOMINANCE", "LOW_ACK_RATIO"):
            return (
                f"Enable SYN cookies on the target server ({target}). "
                f"Deploy SYN flood mitigation on perimeter firewall "
                f"(e.g., Cisco IOS TCP intercept, or iptables recent module). "
                f"Engage upstream provider for traffic scrubbing. "
                f"Consider connection rate-limiting per source IP."
            )
        return (
            f"SYN flood mitigation required for {target}: "
            f"Enable SYN cookies, deploy rate-limiting ACLs, "
            f"and engage upstream DDoS scrubbing. "
            f"Monitor server connection table usage."
        )

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _compute_window(self, df: pd.DataFrame) -> SYNFloodWindow:
        """
        Compute TCP flag metrics using vectorised Pandas operations.

        Handles tcp_flags as:
          - Integer bitmask (e.g. 2 for SYN)
          - Hex string (e.g. "0x02")
          - Named string (e.g. "S", "SA", "SYN", "SYN-ACK")

        Args:
            df: Full packet DataFrame.

        Returns:
            Populated :class:`SYNFloodWindow`.
        """
        window = SYNFloodWindow()
        window.total_packets = len(df)

        # Duration and PPS
        if "timestamp" in df.columns:
            ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
            ts_valid = ts.dropna()
            if len(ts_valid) >= 2:
                window.duration_seconds = (
                    ts_valid.max() - ts_valid.min()
                ).total_seconds()
                if window.duration_seconds > 0:
                    window.pps = window.total_packets / window.duration_seconds

        # Filter to TCP packets
        if "protocol" in df.columns:
            tcp_mask = df["protocol"].str.upper().fillna("") == "TCP"
            df_tcp = df[tcp_mask]
        else:
            df_tcp = df   # Assume all TCP if no protocol column

        window.total_tcp_packets = len(df_tcp)

        if window.total_tcp_packets == 0:
            return window

        # Parse TCP flags
        if "tcp_flags" in df_tcp.columns:
            flags = df_tcp["tcp_flags"].fillna("0")
            # Normalise flags to integer bitmasks
            flag_ints = flags.map(self._parse_flags)
            window.syn_count = int((flag_ints & 0x02 > 0).sum())
            window.ack_count = int((flag_ints & 0x10 > 0).sum())
            window.syn_ack_count = int(((flag_ints & 0x12) == 0x12).sum())
            window.rst_count = int((flag_ints & 0x04 > 0).sum())
            window.fin_count = int((flag_ints & 0x01 > 0).sum())
        else:
            # No flags column — use heuristics: all TCP = potential SYN
            log.debug("SYNFloodDetector: no tcp_flags column; estimating SYN from TCP count.")
            window.syn_count = window.total_tcp_packets
            window.ack_count = 0

        # Compute SYN/ACK rate metrics
        if window.duration_seconds > 0:
            window.syn_per_second = window.syn_count / window.duration_seconds
            window.ack_per_second = window.ack_count / window.duration_seconds

        # Ratios
        syn_plus_ack = window.syn_count + window.ack_count
        if syn_plus_ack > 0:
            window.syn_ack_ratio = window.syn_count / syn_plus_ack

        if window.total_tcp_packets > 0:
            window.syn_fraction_of_tcp = window.syn_count / window.total_tcp_packets

        # Half-open estimate: SYN without a matching ACK response
        window.half_open_estimate = max(0, window.syn_count - window.ack_count)

        # IP context
        if "src_ip" in df_tcp.columns:
            window.unique_src_ips = int(df_tcp["src_ip"].nunique())
        if "dst_ip" in df_tcp.columns:
            dst_counts = df_tcp["dst_ip"].value_counts()
            if not dst_counts.empty:
                window.top_dst_ip = str(dst_counts.index[0])
                window.top_dst_syn_count = int(dst_counts.iloc[0])
                window.top_dst_fraction = round(
                    window.top_dst_syn_count / max(window.total_tcp_packets, 1), 4
                )

        log.debug(
            "SYNFloodWindow: syn=%d, ack=%d, ratio=%.3f, half_open=%d, "
            "syn/s=%.1f, top_dst=%s.",
            window.syn_count, window.ack_count, window.syn_ack_ratio,
            window.half_open_estimate, window.syn_per_second, window.top_dst_ip,
        )
        return window

    @staticmethod
    def _parse_flags(flag_val: Any) -> int:
        """
        Normalise a TCP flags value to an integer bitmask.

        Handles:
          - Integer: returned as-is
          - Hex string "0x02": parsed via int()
          - Named abbreviations: "S"=SYN, "A"=ACK, "SA"=SYN+ACK, etc.

        Args:
            flag_val: Raw flags value from DataFrame.

        Returns:
            Integer bitmask (0 on parse failure).
        """
        if flag_val is None:
            return 0
        # Already numeric
        if isinstance(flag_val, (int, float)) and not isinstance(flag_val, bool):
            return int(flag_val) if flag_val == flag_val else 0  # NaN check

        s = str(flag_val).strip()
        if not s or s in ("None", "nan", ""):
            return 0

        # Hex string
        if s.startswith("0x") or s.startswith("0X"):
            try:
                return int(s, 16)
            except ValueError:
                pass

        # Decimal string
        try:
            return int(s)
        except ValueError:
            pass

        # Named flag abbreviations (common in Scapy / pyshark output)
        flag_map: dict[str, int] = {
            "F": 0x01, "FIN": 0x01,
            "S": 0x02, "SYN": 0x02,
            "R": 0x04, "RST": 0x04,
            "P": 0x08, "PSH": 0x08,
            "A": 0x10, "ACK": 0x10,
            "U": 0x20, "URG": 0x20,
            "E": 0x40, "ECE": 0x40,
            "C": 0x80, "CWR": 0x80,
            # Common combinations
            "SA": 0x12,   # SYN-ACK
            "FA": 0x11,   # FIN-ACK
            "RA": 0x14,   # RST-ACK
            "PA": 0x18,   # PSH-ACK
        }
        result = 0
        for token in s.upper().split():
            result |= flag_map.get(token, 0)
        if result == 0:
            # Try character-by-character (e.g. "SFP" → S|F|P)
            for ch in s.upper():
                result |= flag_map.get(ch, 0)
        return result

    @staticmethod
    def _rate_severity(ratio: float) -> str:
        """Map excess ratio to severity label."""
        if ratio >= 3.0:
            return "CRITICAL"
        if ratio >= 2.0:
            return "HIGH"
        if ratio >= 1.3:
            return "MEDIUM"
        return "LOW"

    def reset(self) -> None:
        """Reset window state and alert counter."""
        super().reset()
        self.window = SYNFloodWindow()
