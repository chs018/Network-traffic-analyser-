"""
bottleneck_detector.py — Network Bottleneck Detection Engine
=============================================================
Network Traffic Analysis and Intrusion Detection System

Identifies network congestion and performance bottlenecks by applying
configurable statistical thresholds to Phase 3 analytics outputs:

  - High bandwidth utilisation (absolute and rolling-peak comparison)
  - Traffic spike detection  (Z-score / IQR over per-second volumes)
  - Excessive packet rate (PPS threshold breach)
  - Oversized or anomalous packet sizes (IQR fence)
  - Protocol dominance (single protocol ≥ threshold of all traffic)
  - Abnormal host concentration (top-talker saturation)
  - Queue growth indicators (monotonic increase in per-interval volume)

Every detected issue produces a :class:`BottleneckEvent` with:
  - ISO-8601 timestamp
  - Severity level  (LOW / MEDIUM / HIGH / CRITICAL)
  - Description
  - Recommendation

Classes:
    Severity           — Enum: event severity levels
    BottleneckEvent    — Dataclass: single detected bottleneck event
    BottleneckDetector — Main detection engine (Phase 4 full implementation)

NOTE:
    The Phase 1 ``BottleneckDetector`` stub is REPLACED by this full
    Phase 4 implementation. The legacy ``detect(df, bps)`` method and
    ``BottleneckType`` enum are retained for backward compatibility.

Author: Network Traffic Analyzer Project
Version: 4.0.0
Python: 3.11+
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Optional

import numpy as np
import pandas as pd

from utils.config import config
from utils.logger import get_analysis_logger
from analysis.traffic_statistics import TrafficStatistics, TrafficSummary
from analysis.protocol_analysis import ProtocolAnalysis, ProtocolReport
from analysis.bandwidth_monitor import BandwidthMonitor, BandwidthReport

log = get_analysis_logger()


# ──────────────────────────────────────────────────────────────────────────────
# ENUMS
# ──────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """Bottleneck event severity levels (ordered LOW→CRITICAL)."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric rank for comparison (higher = more severe)."""
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:
        return self.rank > other.rank


# Phase 1 compatibility enum — retained so existing imports don't break
class BottleneckType(Enum):
    """Categories of detected network bottlenecks (Phase 1 compat)."""
    BANDWIDTH_SATURATION = auto()
    HIGH_RETRANSMISSION  = auto()
    ELEPHANT_FLOW        = auto()
    LATENCY_ANOMALY      = auto()


# ──────────────────────────────────────────────────────────────────────────────
# DATACLASSES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class BottleneckEvent:
    """
    Describes a single detected network bottleneck or congestion event.

    Attributes:
        timestamp:       ISO-8601 detection timestamp.
        check_name:      Identifier of the detector that raised this event.
        severity:        :class:`Severity` enum value.
        description:     Human-readable summary of the detected issue.
        recommendation:  Suggested corrective action.
        metric_name:     Name of the measured metric (e.g. ``"avg_bps"``).
        metric_value:    Observed value that triggered the event.
        threshold_value: Threshold that was exceeded.
        affected_ip:     Source / destination IP (if applicable).
        evidence:        Raw supporting data dictionary.

        # Phase 1 backward-compatibility fields
        bottleneck_type:  Legacy BottleneckType enum (always BANDWIDTH_SATURATION for new events).
        affected_src_ip:  Alias for affected_ip (Phase 1 compat).
        affected_dst_ip:  Optional destination IP.
        affected_interface: Optional interface name.
        raw_evidence:     Legacy evidence dict alias.
    """

    timestamp: str
    check_name: str
    severity: Severity
    description: str
    recommendation: str
    metric_name: str = ""
    metric_value: float = 0.0
    threshold_value: float = 0.0
    affected_ip: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)

    # Phase 1 backward-compatibility fields
    bottleneck_type: BottleneckType = BottleneckType.BANDWIDTH_SATURATION
    affected_src_ip: Optional[str] = None
    affected_dst_ip: Optional[str] = None
    affected_interface: Optional[str] = None
    raw_evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dictionary."""
        return {
            "timestamp":       self.timestamp,
            "check_name":      self.check_name,
            "severity":        self.severity.value,
            "description":     self.description,
            "recommendation":  self.recommendation,
            "metric_name":     self.metric_name,
            "metric_value":    round(self.metric_value, 4),
            "threshold_value": round(self.threshold_value, 4),
            "affected_ip":     self.affected_ip,
        }


@dataclass
class BottleneckReport:
    """Complete bottleneck detection report."""

    computed_at: str = ""
    total_checks: int = 0
    events: list[BottleneckEvent] = field(default_factory=list)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.events:
            return None
        return max(self.events, key=lambda e: e.severity.rank).severity

    @property
    def critical_count(self) -> int:
        return sum(1 for e in self.events if e.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for e in self.events if e.severity == Severity.HIGH)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable report dictionary."""
        return {
            "computed_at":    self.computed_at,
            "total_checks":   self.total_checks,
            "event_count":    self.event_count,
            "max_severity":   self.max_severity.value if self.max_severity else "NONE",
            "critical_count": self.critical_count,
            "high_count":     self.high_count,
            "events": [e.to_dict() for e in self.events],
        }


# ──────────────────────────────────────────────────────────────────────────────
# BOTTLENECK DETECTOR ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class BottleneckDetector:
    """
    Phase 4 Network Bottleneck Detection Engine.

    Applies statistical and threshold-based algorithms to Phase 3 analytics
    outputs to identify network congestion events.

    Each ``detect_*`` method runs independently and appends
    :class:`BottleneckEvent` objects to the internal ``events`` list.
    Call :meth:`generate_bottleneck_report` to run all checks at once.

    Args:
        link_speed_bps:          Nominal link capacity (bits/s). Default 1 Gbps.
        bw_warn_pct:             Bandwidth warn threshold (0–1 fraction).
        bw_critical_pct:         Bandwidth critical threshold (0–1 fraction).
        spike_zscore_threshold:  Z-score threshold for spike detection.
        spike_iqr_multiplier:    IQR fence multiplier for spike detection.
        protocol_dominance_pct:  Single-protocol fraction threshold (0–1).
        host_concentration_pct:  Top-talker fraction threshold (0–1).
        packet_size_iqr_mult:    IQR multiplier for oversized packet detection.
        pps_warn:                PPS warn threshold.
        pps_critical:            PPS critical threshold.
        queue_growth_window:     Number of intervals to test monotonic growth.

    Usage::

        ts = TrafficStatistics(); ts.load_data()
        pa = ProtocolAnalysis();  pa.load_data()
        bm = BandwidthMonitor();  bm.load_data()

        det = BottleneckDetector()
        report = det.generate_bottleneck_report(ts, pa, bm)
        print(report.event_count, "bottlenecks detected")
    """

    def __init__(
        self,
        link_speed_bps: float = 1_000_000_000.0,
        bw_warn_pct: float = 0.60,
        bw_critical_pct: float = 0.90,
        spike_zscore_threshold: float = 3.0,
        spike_iqr_multiplier: float = 1.5,
        protocol_dominance_pct: float = 0.80,
        host_concentration_pct: float = 0.70,
        packet_size_iqr_mult: float = 3.0,
        pps_warn: float = 50_000.0,
        pps_critical: float = 500_000.0,
        queue_growth_window: int = 3,
    ) -> None:
        self.link_speed_bps = link_speed_bps
        self.bw_warn_pct = bw_warn_pct
        self.bw_critical_pct = bw_critical_pct
        self.spike_zscore_threshold = spike_zscore_threshold
        self.spike_iqr_multiplier = spike_iqr_multiplier
        self.protocol_dominance_pct = protocol_dominance_pct
        self.host_concentration_pct = host_concentration_pct
        self.packet_size_iqr_mult = packet_size_iqr_mult
        self.pps_warn = pps_warn
        self.pps_critical = pps_critical
        self.queue_growth_window = queue_growth_window

        # Pull additional thresholds from central config
        self._cfg_thresholds = config.thresholds

        # Accumulated events across all checks
        self.events: list[BottleneckEvent] = []
        log.debug("BottleneckDetector (Phase 4) initialised.")

    # ── Master Report ─────────────────────────────────────────────────────────

    def generate_bottleneck_report(
        self,
        traffic_stats: TrafficStatistics,
        protocol_analysis: ProtocolAnalysis,
        bandwidth_monitor: BandwidthMonitor,
        db_manager=None,
    ) -> BottleneckReport:
        """
        Run all bottleneck checks and return a :class:`BottleneckReport`.

        Args:
            traffic_stats:     Loaded :class:`TrafficStatistics`.
            protocol_analysis: Loaded :class:`ProtocolAnalysis`.
            bandwidth_monitor: Loaded :class:`BandwidthMonitor`.
            db_manager:        Optional DatabaseManager for persistence.

        Returns:
            Populated :class:`BottleneckReport`.
        """
        log.info("Running bottleneck detection…")
        self.clear_events()

        ts_summary = traffic_stats.generate_summary()
        proto_report = protocol_analysis.generate_protocol_report()
        bw_report = bandwidth_monitor.generate_bandwidth_report()

        checks_run = 0

        checks_run += self.detect_bandwidth_bottleneck(bw_report)
        checks_run += self.detect_packet_rate_spike(bw_report, bandwidth_monitor)
        checks_run += self.detect_protocol_imbalance(proto_report)
        checks_run += self.detect_host_concentration(ts_summary)
        checks_run += self.detect_packet_size_anomaly(traffic_stats)
        checks_run += self.detect_network_congestion(bw_report, bandwidth_monitor)

        # Optional persistence
        if db_manager is not None:
            self._persist_events(db_manager)

        report = BottleneckReport(
            computed_at=datetime.now(tz=timezone.utc).isoformat(),
            total_checks=checks_run,
            events=list(self.events),
        )
        log.info(
            "Bottleneck report: %d checks, %d events (max severity: %s).",
            checks_run,
            report.event_count,
            report.max_severity.value if report.max_severity else "NONE",
        )
        return report

    # ── Detection Methods ─────────────────────────────────────────────────────

    def detect_bandwidth_bottleneck(self, bw_report: BandwidthReport) -> int:
        """
        Detect high bandwidth utilisation against the configured link speed.

        Raises events for WARN (>bw_warn_pct) and CRITICAL (>bw_critical_pct)
        levels based on both average and peak byte rates.

        Args:
            bw_report: BandwidthReport from BandwidthMonitor.

        Returns:
            Number of sub-checks executed.
        """
        link_bps = self.link_speed_bps / 8.0  # convert bits→bytes
        checks = 0

        # -- Average utilisation check ----------------------------------------
        avg_bps = bw_report.metrics.avg_bytes_per_second
        avg_util = avg_bps / link_bps if link_bps > 0 else 0.0
        checks += 1

        if avg_util >= self.bw_critical_pct:
            self._add_event(
                check_name="bandwidth_avg",
                severity=Severity.CRITICAL,
                description=(
                    f"Average bandwidth utilisation at {avg_util*100:.1f}% "
                    f"({avg_bps:.0f} B/s) — link approaching saturation."
                ),
                recommendation="Upgrade link capacity or implement traffic shaping immediately.",
                metric_name="avg_bytes_per_second",
                metric_value=avg_bps,
                threshold_value=link_bps * self.bw_critical_pct,
            )
        elif avg_util >= self.bw_warn_pct:
            self._add_event(
                check_name="bandwidth_avg",
                severity=Severity.MEDIUM,
                description=(
                    f"Average bandwidth utilisation at {avg_util*100:.1f}% "
                    f"({avg_bps:.0f} B/s) — elevated load."
                ),
                recommendation="Monitor closely; consider QoS policies.",
                metric_name="avg_bytes_per_second",
                metric_value=avg_bps,
                threshold_value=link_bps * self.bw_warn_pct,
            )

        # -- Peak utilisation check -------------------------------------------
        peak_bps = bw_report.metrics.peak_bytes_per_second
        peak_util = peak_bps / link_bps if link_bps > 0 else 0.0
        checks += 1

        if peak_util >= self.bw_critical_pct:
            self._add_event(
                check_name="bandwidth_peak",
                severity=Severity.HIGH,
                description=(
                    f"Peak bandwidth at {peak_util*100:.1f}% "
                    f"({peak_bps:.0f} B/s) — burst saturation detected."
                ),
                recommendation="Implement burst-limiting or traffic prioritisation.",
                metric_name="peak_bytes_per_second",
                metric_value=peak_bps,
                threshold_value=link_bps * self.bw_critical_pct,
            )

        return checks

    def detect_packet_rate_spike(
        self,
        bw_report: BandwidthReport,
        bandwidth_monitor: BandwidthMonitor,
    ) -> int:
        """
        Detect packet rate spikes using Z-score and IQR fence methods on
        the per-second packet count time series.

        Args:
            bw_report:        BandwidthReport for aggregate PPS metrics.
            bandwidth_monitor: BandwidthMonitor for per-second timeline access.

        Returns:
            Number of sub-checks executed.
        """
        checks = 0

        # -- Absolute PPS threshold -------------------------------------------
        avg_pps = bw_report.metrics.avg_packets_per_second
        peak_pps = bw_report.metrics.peak_packets_per_second
        checks += 1

        if avg_pps >= self.pps_critical:
            self._add_event(
                check_name="pps_avg",
                severity=Severity.CRITICAL,
                description=f"Average PPS={avg_pps:.0f} — critical packet rate.",
                recommendation="Investigate source; apply rate limiting.",
                metric_name="avg_packets_per_second",
                metric_value=avg_pps,
                threshold_value=self.pps_critical,
            )
        elif avg_pps >= self.pps_warn:
            self._add_event(
                check_name="pps_avg",
                severity=Severity.MEDIUM,
                description=f"Average PPS={avg_pps:.0f} — elevated packet rate.",
                recommendation="Monitor for further increase.",
                metric_name="avg_packets_per_second",
                metric_value=avg_pps,
                threshold_value=self.pps_warn,
            )

        # -- Statistical spike on per-second series ---------------------------
        checks += 1
        try:
            per_sec_df = bandwidth_monitor.calculate_throughput()
            if not per_sec_df.empty and "packets_per_second" in per_sec_df.columns:
                series = per_sec_df["packets_per_second"].astype(float)
                spike_events = self._detect_spikes_zscore(
                    series=series,
                    check_name="pps_spike_zscore",
                    metric_name="packets_per_second",
                    severity=Severity.HIGH,
                    description_template="PPS spike detected: {value:.0f} pps (Z={z:.2f})",
                    recommendation="Investigate burst source; consider DDoS guard activation.",
                )
                self.events.extend(spike_events)

                # IQR fence
                iqr_events = self._detect_spikes_iqr(
                    series=series,
                    check_name="pps_spike_iqr",
                    metric_name="packets_per_second",
                    severity=Severity.MEDIUM,
                    description_template="PPS outlier: {value:.0f} pps (IQR fence={fence:.1f})",
                    recommendation="Verify no application sending abnormal burst traffic.",
                )
                self.events.extend(iqr_events)
        except Exception as exc:
            log.warning("PPS spike detection failed: %s", exc)

        return checks

    def detect_protocol_imbalance(self, proto_report: ProtocolReport) -> int:
        """
        Detect protocol dominance — a single protocol carrying an abnormally
        high fraction of all traffic, which may indicate misconfiguration or
        an active flood.

        Args:
            proto_report: ProtocolReport from ProtocolAnalysis.

        Returns:
            Number of sub-checks executed.
        """
        checks = 1
        total = proto_report.total_packets or 1

        for entry in proto_report.all_protocols:
            frac = entry.packet_count / total
            if frac >= self.protocol_dominance_pct:
                sev = Severity.CRITICAL if frac >= 0.95 else Severity.HIGH
                self._add_event(
                    check_name="protocol_dominance",
                    severity=sev,
                    description=(
                        f"Protocol '{entry.protocol}' accounts for {frac*100:.1f}% "
                        f"of all traffic ({entry.packet_count:,} packets)."
                    ),
                    recommendation=(
                        f"Investigate why '{entry.protocol}' dominates; check for "
                        f"flood or misconfigured application."
                    ),
                    metric_name=f"protocol_{entry.protocol}_fraction",
                    metric_value=round(frac * 100, 2),
                    threshold_value=self.protocol_dominance_pct * 100,
                )

        # Flag high malformed percentage separately
        checks += 1
        if proto_report.malformed_pct >= 15.0:
            sev = Severity.CRITICAL if proto_report.malformed_pct >= 30.0 else Severity.HIGH
            self._add_event(
                check_name="malformed_packets",
                severity=sev,
                description=(
                    f"Malformed packet rate: {proto_report.malformed_pct:.1f}% "
                    f"— possible hardware fault or active attack."
                ),
                recommendation="Inspect switch/NIC hardware and driver logs.",
                metric_name="malformed_pct",
                metric_value=proto_report.malformed_pct,
                threshold_value=15.0,
            )
        elif proto_report.malformed_pct >= 5.0:
            self._add_event(
                check_name="malformed_packets",
                severity=Severity.MEDIUM,
                description=f"Malformed packet rate elevated: {proto_report.malformed_pct:.1f}%.",
                recommendation="Monitor hardware health; schedule maintenance window.",
                metric_name="malformed_pct",
                metric_value=proto_report.malformed_pct,
                threshold_value=5.0,
            )

        return checks

    def detect_host_concentration(self, ts_summary: TrafficSummary) -> int:
        """
        Detect abnormal host concentration — one or more hosts generating a
        disproportionate share of total traffic (top-talker saturation).

        Args:
            ts_summary: TrafficSummary from TrafficStatistics.

        Returns:
            Number of sub-checks executed.
        """
        checks = 1
        total_pkts = ts_summary.basic.total_packets or 1
        top_src = ts_summary.ip.top_src_ips

        if not top_src:
            return checks

        # Check top-1 source concentration
        top_ip, top_count = top_src[0]
        concentration = top_count / total_pkts

        if concentration >= self.host_concentration_pct:
            sev = (
                Severity.CRITICAL if concentration >= 0.85
                else Severity.HIGH
            )
            self._add_event(
                check_name="host_top_talker",
                severity=sev,
                description=(
                    f"Host {top_ip} generates {concentration*100:.1f}% of all traffic "
                    f"({top_count:,} of {total_pkts:,} packets)."
                ),
                recommendation=f"Investigate {top_ip} for flood, scan, or misconfiguration.",
                metric_name="top_talker_fraction",
                metric_value=round(concentration * 100, 2),
                threshold_value=self.host_concentration_pct * 100,
                affected_ip=top_ip,
            )

        # Check top-3 combined concentration
        checks += 1
        if len(top_src) >= 3:
            top3_count = sum(cnt for _, cnt in top_src[:3])
            top3_frac = top3_count / total_pkts
            if top3_frac >= 0.90:
                self._add_event(
                    check_name="host_concentration_top3",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Top 3 hosts account for {top3_frac*100:.1f}% of traffic — "
                        f"concentration risk."
                    ),
                    recommendation="Review traffic policy for top-3 hosts.",
                    metric_name="top3_concentration_fraction",
                    metric_value=round(top3_frac * 100, 2),
                    threshold_value=90.0,
                )

        return checks

    def detect_packet_size_anomaly(self, traffic_stats: TrafficStatistics) -> int:
        """
        Detect anomalous packet sizes using the IQR fence method on the
        ``packet_length`` column.

        Flags oversized or unusually small packets that may indicate
        fragmentation, tunnelling, or crafted traffic.

        Args:
            traffic_stats: Loaded TrafficStatistics (data must be loaded).

        Returns:
            Number of sub-checks executed.
        """
        checks = 1
        try:
            df = traffic_stats.get_dataframe()
            if df.empty or "packet_length" not in df.columns:
                return checks

            sizes = df["packet_length"].dropna().astype(float)
            if len(sizes) < 4:
                return checks

            q1 = sizes.quantile(0.25)
            q3 = sizes.quantile(0.75)
            iqr = q3 - q1
            upper_fence = q3 + self.packet_size_iqr_mult * iqr
            lower_fence = max(0.0, q1 - self.packet_size_iqr_mult * iqr)

            oversized = (sizes > upper_fence).sum()
            undersized = (sizes < lower_fence).sum()
            total = len(sizes)

            oversized_pct = (oversized / total) * 100
            undersized_pct = (undersized / total) * 100

            if oversized_pct >= 5.0:
                sev = Severity.HIGH if oversized_pct >= 15.0 else Severity.MEDIUM
                self._add_event(
                    check_name="oversized_packets",
                    severity=sev,
                    description=(
                        f"{oversized_pct:.1f}% of packets exceed IQR fence "
                        f"({upper_fence:.0f} bytes) — possible fragmentation or tunnelling."
                    ),
                    recommendation="Check for MTU mismatches or large-frame applications.",
                    metric_name="oversized_packet_pct",
                    metric_value=round(oversized_pct, 2),
                    threshold_value=upper_fence,
                )

            if undersized_pct >= 10.0:
                self._add_event(
                    check_name="undersized_packets",
                    severity=Severity.LOW,
                    description=(
                        f"{undersized_pct:.1f}% of packets are below IQR lower fence "
                        f"({lower_fence:.0f} bytes) — high proportion of tiny frames."
                    ),
                    recommendation="Audit applications generating excessive small packets.",
                    metric_name="undersized_packet_pct",
                    metric_value=round(undersized_pct, 2),
                    threshold_value=lower_fence,
                )

        except Exception as exc:
            log.warning("Packet size anomaly detection failed: %s", exc)

        return checks

    def detect_network_congestion(
        self,
        bw_report: BandwidthReport,
        bandwidth_monitor: BandwidthMonitor,
    ) -> int:
        """
        Detect queue-growth congestion indicators by checking whether
        per-interval byte volumes show a sustained monotonic increase across
        the last ``queue_growth_window`` intervals.

        A monotonically growing byte volume in successive time buckets
        suggests queuing / bufferbloat.

        Args:
            bw_report:        BandwidthReport for aggregate metrics.
            bandwidth_monitor: BandwidthMonitor for timeline access.

        Returns:
            Number of sub-checks executed.
        """
        checks = 1
        try:
            df = bandwidth_monitor.traffic_timeline(freq="1min")
            if df.empty or "bytes_transferred" not in df.columns:
                return checks

            series = df["bytes_transferred"].astype(float).tolist()
            window = self.queue_growth_window

            if len(series) < window + 1:
                return checks

            # Slide a window and count monotonically increasing runs
            monotonic_runs = 0
            for i in range(len(series) - window):
                window_slice = series[i: i + window]
                if all(
                    window_slice[j] < window_slice[j + 1]
                    for j in range(len(window_slice) - 1)
                ):
                    monotonic_runs += 1

            total_windows = len(series) - window
            growth_fraction = monotonic_runs / total_windows if total_windows > 0 else 0.0

            if growth_fraction >= 0.70:
                self._add_event(
                    check_name="queue_growth",
                    severity=Severity.HIGH,
                    description=(
                        f"Queue growth indicator: {growth_fraction*100:.0f}% of "
                        f"{window}-interval windows show sustained byte-volume growth — "
                        f"possible bufferbloat."
                    ),
                    recommendation="Investigate QoS and buffer settings; check for TCP slow-start storms.",
                    metric_name="queue_growth_fraction",
                    metric_value=round(growth_fraction * 100, 2),
                    threshold_value=70.0,
                )
            elif growth_fraction >= 0.50:
                self._add_event(
                    check_name="queue_growth",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Moderate queue growth: {growth_fraction*100:.0f}% of "
                        f"windows show sustained growth."
                    ),
                    recommendation="Monitor for further growth; consider traffic shaping.",
                    metric_name="queue_growth_fraction",
                    metric_value=round(growth_fraction * 100, 2),
                    threshold_value=50.0,
                )

        except Exception as exc:
            log.warning("Congestion detection failed: %s", exc)

        return checks

    # ── Visualization Helpers ─────────────────────────────────────────────────

    def get_alert_table(self, report: BottleneckReport) -> pd.DataFrame:
        """
        Return a DataFrame of all bottleneck events for dashboard display.

        Columns: Timestamp, Check, Severity, Description, Recommendation
        """
        if not report.events:
            return pd.DataFrame(
                columns=["Timestamp", "Check", "Severity", "Description", "Recommendation"]
            )
        rows = [
            {
                "Timestamp":      e.timestamp[:19],
                "Check":          e.check_name,
                "Severity":       e.severity.value,
                "Description":    e.description,
                "Recommendation": e.recommendation,
            }
            for e in report.events
        ]
        return pd.DataFrame(rows)

    def get_bar_chart_data(self, report: BottleneckReport) -> dict[str, list]:
        """
        Return severity distribution for a bar chart.

        Returns::

            {"labels": ["LOW","MEDIUM","HIGH","CRITICAL"], "values": [0,1,2,0]}
        """
        counts = {s.value: 0 for s in Severity}
        for e in report.events:
            counts[e.severity.value] += 1
        return {
            "labels": list(counts.keys()),
            "values": list(counts.values()),
        }

    def get_line_chart_data(
        self, bandwidth_monitor: BandwidthMonitor
    ) -> dict[str, list]:
        """
        Return per-minute byte throughput for overlay with bottleneck markers.

        Returns::

            {"labels": ["2026-..."], "values": [468735, ...]}
        """
        return bandwidth_monitor.get_line_chart_data("bytes_per_minute")

    def get_heatmap_data(self, report: BottleneckReport) -> pd.DataFrame:
        """Return per-check event counts as a DataFrame."""
        if not report.events:
            return pd.DataFrame(columns=["Check", "Count", "MaxSeverity"])
        rows: dict[str, dict] = {}
        for e in report.events:
            if e.check_name not in rows:
                rows[e.check_name] = {"Check": e.check_name, "Count": 0, "MaxSeverity": e.severity.rank}
            rows[e.check_name]["Count"] += 1
            if e.severity.rank > rows[e.check_name]["MaxSeverity"]:
                rows[e.check_name]["MaxSeverity"] = e.severity.rank
        df = pd.DataFrame(list(rows.values()))
        sev_labels = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
        df["MaxSeverity"] = df["MaxSeverity"].map(sev_labels)
        return df

    # ── Phase 1 Backward-Compatibility API ───────────────────────────────────

    def detect(self, df: pd.DataFrame, bps: float = 0.0) -> list[BottleneckEvent]:
        """
        Phase 1 compatibility entry point.

        Runs a simplified bandwidth check using the provided ``bps`` value.

        Args:
            df:  Traffic DataFrame (unused in Phase 4; kept for API compat).
            bps: Current bytes-per-second for utilisation check.

        Returns:
            List of :class:`BottleneckEvent` objects (may be empty).
        """
        log.debug("BottleneckDetector.detect() — Phase 1 compat wrapper.")
        link_bps = self.link_speed_bps / 8.0
        util = bps / link_bps if link_bps > 0 else 0.0

        events: list[BottleneckEvent] = []
        if util >= self.bw_critical_pct:
            events.append(
                BottleneckEvent(
                    timestamp=datetime.now(tz=timezone.utc).isoformat(),
                    check_name="bandwidth_avg",
                    severity=Severity.CRITICAL,
                    description=f"BPS={bps:.0f} — critical utilisation {util*100:.1f}%.",
                    recommendation="Upgrade link or apply traffic shaping.",
                    bottleneck_type=BottleneckType.BANDWIDTH_SATURATION,
                    metric_value=bps,
                    threshold_value=link_bps * self.bw_critical_pct,
                )
            )
        return events

    def clear_events(self) -> None:
        """Remove all recorded events."""
        self.events.clear()

    def get_events_by_severity(self, severity: Severity) -> list[BottleneckEvent]:
        """Filter events by exact severity level."""
        return [e for e in self.events if e.severity == severity]

    def get_events_by_type(self, bottleneck_type: BottleneckType) -> list[BottleneckEvent]:
        """Phase 1 compat: filter by BottleneckType."""
        return [e for e in self.events if e.bottleneck_type == bottleneck_type]

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _add_event(
        self,
        check_name: str,
        severity: Severity,
        description: str,
        recommendation: str,
        metric_name: str = "",
        metric_value: float = 0.0,
        threshold_value: float = 0.0,
        affected_ip: Optional[str] = None,
    ) -> None:
        """Create and append a :class:`BottleneckEvent`."""
        event = BottleneckEvent(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            check_name=check_name,
            severity=severity,
            description=description,
            recommendation=recommendation,
            metric_name=metric_name,
            metric_value=metric_value,
            threshold_value=threshold_value,
            affected_ip=affected_ip,
            bottleneck_type=BottleneckType.BANDWIDTH_SATURATION,
            affected_src_ip=affected_ip,
        )
        self.events.append(event)
        log.debug(
            "[%s] %s: %s",
            severity.value, check_name, description[:80],
        )

    def _detect_spikes_zscore(
        self,
        series: pd.Series,
        check_name: str,
        metric_name: str,
        severity: Severity,
        description_template: str,
        recommendation: str,
    ) -> list[BottleneckEvent]:
        """Detect outliers using Z-score (mean ± N*std)."""
        events: list[BottleneckEvent] = []
        if len(series) < 3:
            return events
        mean_val = float(series.mean())
        std_val = float(series.std())
        if std_val == 0:
            return events
        threshold = self.spike_zscore_threshold

        for val in series:
            z = abs((val - mean_val) / std_val)
            if z >= threshold:
                events.append(
                    BottleneckEvent(
                        timestamp=datetime.now(tz=timezone.utc).isoformat(),
                        check_name=check_name,
                        severity=severity,
                        description=description_template.format(value=val, z=z),
                        recommendation=recommendation,
                        metric_name=metric_name,
                        metric_value=float(val),
                        threshold_value=mean_val + threshold * std_val,
                    )
                )
                break  # Report first spike only to avoid flooding
        return events

    def _detect_spikes_iqr(
        self,
        series: pd.Series,
        check_name: str,
        metric_name: str,
        severity: Severity,
        description_template: str,
        recommendation: str,
    ) -> list[BottleneckEvent]:
        """Detect outliers using Tukey IQR fence."""
        events: list[BottleneckEvent] = []
        if len(series) < 4:
            return events
        q1 = float(series.quantile(0.25))
        q3 = float(series.quantile(0.75))
        iqr = q3 - q1
        fence = q3 + self.spike_iqr_multiplier * iqr

        spikes = series[series > fence]
        if not spikes.empty:
            val = float(spikes.max())
            events.append(
                BottleneckEvent(
                    timestamp=datetime.now(tz=timezone.utc).isoformat(),
                    check_name=check_name,
                    severity=severity,
                    description=description_template.format(value=val, fence=fence),
                    recommendation=recommendation,
                    metric_name=metric_name,
                    metric_value=val,
                    threshold_value=fence,
                )
            )
        return events

    def _persist_events(self, db_manager) -> None:
        """Persist HIGH and CRITICAL events to the alerts table."""
        try:
            from database.db_manager import AlertRecord
            for e in self.events:
                if e.severity in (Severity.HIGH, Severity.CRITICAL):
                    alert = AlertRecord(
                        timestamp=e.timestamp,
                        alert_type=f"Bottleneck:{e.check_name}",
                        severity=e.severity.value,
                        src_ip=e.affected_ip or "N/A",
                        dst_ip="N/A",
                        description=e.description[:500],
                    )
                    db_manager.insert_alert(alert)
        except Exception as exc:
            log.warning("Failed to persist bottleneck events: %s", exc)
