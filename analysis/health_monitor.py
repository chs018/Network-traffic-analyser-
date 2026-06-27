"""
health_monitor.py — Network Health Monitor
==========================================
Network Traffic Analysis and Intrusion Detection System

Computes a composite network health score (0–100) by aggregating metrics
from Phase 3 analytics engines:

  - Bandwidth utilisation relative to link capacity
  - Packets-per-second and bytes-per-second rates
  - Average packet size and size distribution health
  - Protocol diversity (Shannon entropy)
  - Unique active host count and growth
  - Malformed-packet ratio
  - Traffic stability (coefficient of variation on per-interval volumes)
  - Packet-growth rate between successive time windows

Classes:
    HealthConfig        — Configurable scoring parameters (dataclass)
    ComponentScore      — Dataclass: single scored component result
    NetworkHealthReport — Dataclass: master health report
    NetworkHealthMonitor — Main computation engine (Phase 4)

Health Statuses (Health Score → Status):
    90–100  Excellent
    75–89   Good
    55–74   Moderate
    35–54   Poor
    0–34    Critical

Author: Network Traffic Analyzer Project
Version: 4.0.0
Python: 3.11+
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
# HEALTH CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class HealthConfig:
    """
    Tunable parameters for health scoring.

    All thresholds are calibrated relative to ``link_speed_bps``.
    Override these values to match your network environment.
    """

    # ── Link capacity ─────────────────────────────────────────────────────────
    link_speed_bps: float = 1_000_000_000.0        # 1 Gbps reference

    # ── Bandwidth thresholds (fraction of link capacity) ──────────────────────
    bw_warn_fraction: float = 0.60       # Above → score penalty begins
    bw_high_fraction: float = 0.80       # Above → heavy penalty
    bw_critical_fraction: float = 0.95   # Above → critical

    # ── Packet rate thresholds (pps) ──────────────────────────────────────────
    pps_warn: float = 50_000.0
    pps_high: float = 100_000.0
    pps_critical: float = 500_000.0

    # ── Malformed packet thresholds (fraction of total) ───────────────────────
    malformed_warn: float = 0.05         # 5% malformed → warning
    malformed_high: float = 0.15         # 15% → high concern
    malformed_critical: float = 0.30     # 30% → critical

    # ── Protocol diversity (Shannon entropy — bits) ───────────────────────────
    diversity_excellent: float = 2.5     # High diversity → excellent
    diversity_warn: float = 1.0          # Low entropy → warn

    # ── Host concentration (top-talker share of all traffic) ─────────────────
    host_concentration_warn: float = 0.60    # Single host >60% → warn
    host_concentration_critical: float = 0.85

    # ── Traffic stability (coefficient of variation on per-min volumes) ───────
    stability_warn_cv: float = 1.5       # CV > 1.5 → unstable
    stability_critical_cv: float = 3.0

    # ── Rolling window for stability computation ───────────────────────────────
    rolling_window_minutes: int = 5

    # ── Component weights (must sum to 1.0) ───────────────────────────────────
    weight_bandwidth: float = 0.25
    weight_packet_rate: float = 0.15
    weight_malformed: float = 0.20
    weight_protocol_diversity: float = 0.15
    weight_host_activity: float = 0.10
    weight_stability: float = 0.15


# ──────────────────────────────────────────────────────────────────────────────
# DATACLASSES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ComponentScore:
    """Score and metadata for a single health component."""

    name: str
    score: float          # 0.0–100.0
    weight: float         # Contribution weight (0.0–1.0)
    metric_value: float   # Raw observed value
    threshold: float      # Reference threshold for this component
    status: str           # "OK" | "WARN" | "HIGH" | "CRITICAL"
    detail: str = ""      # Human-readable explanation


@dataclass
class NetworkHealthReport:
    """
    Master network health report produced by :class:`NetworkHealthMonitor`.

    Contains both the composite health score and per-component breakdowns.
    """

    # Overall
    health_score: float = 0.0         # 0–100
    health_status: str = "Unknown"    # Excellent / Good / Moderate / Poor / Critical
    computed_at: str = ""

    # Component scores
    components: list[ComponentScore] = field(default_factory=list)

    # Key metrics (flattened for easy dashboard access)
    bandwidth_utilisation_pct: float = 0.0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    avg_packet_size: float = 0.0
    malformed_pct: float = 0.0
    protocol_diversity_entropy: float = 0.0
    unique_hosts: int = 0
    traffic_stability: str = "Unknown"
    packet_growth_rate: float = 0.0

    # Issues and recommendations
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a flat JSON-serialisable dictionary."""
        return {
            "health_score": round(self.health_score, 1),
            "health_status": self.health_status,
            "computed_at": self.computed_at,
            "bandwidth_utilisation_pct": round(self.bandwidth_utilisation_pct, 4),
            "packets_per_second": round(self.packets_per_second, 2),
            "bytes_per_second": round(self.bytes_per_second, 2),
            "avg_packet_size": round(self.avg_packet_size, 2),
            "malformed_pct": round(self.malformed_pct, 2),
            "protocol_diversity_entropy": round(self.protocol_diversity_entropy, 4),
            "unique_hosts": self.unique_hosts,
            "traffic_stability": self.traffic_stability,
            "packet_growth_rate": round(self.packet_growth_rate, 4),
            "issues": self.issues,
            "recommendations": self.recommendations,
            "components": [
                {
                    "name": c.name,
                    "score": round(c.score, 1),
                    "weight": c.weight,
                    "metric_value": round(c.metric_value, 4),
                    "threshold": c.threshold,
                    "status": c.status,
                    "detail": c.detail,
                }
                for c in self.components
            ],
        }


# ──────────────────────────────────────────────────────────────────────────────
# NETWORK HEALTH MONITOR ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class NetworkHealthMonitor:
    """
    Phase 4 Network Health Monitoring Engine.

    Accepts pre-loaded Phase 3 analytics objects and computes a composite
    health score (0–100) using a weighted multi-component model.

    Args:
        health_config: Tunable :class:`HealthConfig` parameters.

    Usage::

        ts = TrafficStatistics(); ts.load_data()
        pa = ProtocolAnalysis(); pa.load_data()
        bm = BandwidthMonitor(); bm.load_data()

        monitor = NetworkHealthMonitor()
        report  = monitor.generate_health_report(ts, pa, bm)
        print(report.health_score, report.health_status)
    """

    # Status thresholds (score → label)
    _STATUS_THRESHOLDS: tuple[tuple[float, str], ...] = (
        (90.0, "Excellent"),
        (75.0, "Good"),
        (55.0, "Moderate"),
        (35.0, "Poor"),
        (0.0,  "Critical"),
    )

    def __init__(self, health_config: Optional[HealthConfig] = None) -> None:
        """Initialise the NetworkHealthMonitor."""
        self._cfg = health_config or HealthConfig()
        self._thresholds = config.thresholds
        log.debug("NetworkHealthMonitor initialised.")

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_health_report(
        self,
        traffic_stats: TrafficStatistics,
        protocol_analysis: ProtocolAnalysis,
        bandwidth_monitor: BandwidthMonitor,
        db_manager=None,
    ) -> NetworkHealthReport:
        """
        Generate a complete :class:`NetworkHealthReport`.

        Args:
            traffic_stats:     Loaded :class:`TrafficStatistics` instance.
            protocol_analysis: Loaded :class:`ProtocolAnalysis` instance.
            bandwidth_monitor: Loaded :class:`BandwidthMonitor` instance.
            db_manager:        Optional :class:`DatabaseManager` for persistence.

        Returns:
            Fully populated :class:`NetworkHealthReport`.
        """
        log.info("Generating network health report…")

        # Retrieve sub-reports
        traffic_summary: TrafficSummary = traffic_stats.generate_summary()
        proto_report: ProtocolReport = protocol_analysis.generate_protocol_report()
        bw_report: BandwidthReport = bandwidth_monitor.generate_bandwidth_report()

        # Compute individual component scores
        bw_component = self.calculate_network_load(bw_report)
        pkt_rate_component = self._score_packet_rate(bw_report)
        malformed_component = self._score_malformed(proto_report)
        diversity_component = self.calculate_protocol_health(proto_report)
        host_component = self.calculate_host_activity(traffic_summary)
        stability_component = self._score_stability(bandwidth_monitor)

        components = [
            bw_component,
            pkt_rate_component,
            malformed_component,
            diversity_component,
            host_component,
            stability_component,
        ]

        # Weighted composite score
        health_score = sum(c.score * c.weight for c in components)
        health_score = max(0.0, min(100.0, health_score))
        health_status = self._score_to_status(health_score)

        # Build issues / recommendations
        issues, recommendations = self._collect_issues(components)

        # Packet growth rate: compare first vs second half packet counts
        packet_growth_rate = self._compute_growth_rate(bandwidth_monitor)

        # Traffic stability label
        stability_label = self._stability_label(stability_component.metric_value)

        # Bandwidth utilisation %
        link_bytes_per_sec = self._cfg.link_speed_bps / 8.0
        bw_util_pct = 0.0
        if link_bytes_per_sec > 0:
            bw_util_pct = min(
                bw_report.metrics.avg_bytes_per_second / link_bytes_per_sec * 100,
                100.0,
            )

        report = NetworkHealthReport(
            health_score=round(health_score, 2),
            health_status=health_status,
            computed_at=datetime.now(tz=timezone.utc).isoformat(),
            components=components,
            bandwidth_utilisation_pct=round(bw_util_pct, 4),
            packets_per_second=bw_report.metrics.avg_packets_per_second,
            bytes_per_second=bw_report.metrics.avg_bytes_per_second,
            avg_packet_size=traffic_summary.packets.avg_packet_size,
            malformed_pct=proto_report.malformed_pct,
            protocol_diversity_entropy=diversity_component.metric_value,
            unique_hosts=traffic_summary.ip.unique_src_ips,
            traffic_stability=stability_label,
            packet_growth_rate=packet_growth_rate,
            issues=issues,
            recommendations=recommendations,
        )

        log.info(
            "Health report: score=%.1f status=%s issues=%d",
            report.health_score, report.health_status, len(issues),
        )

        # Optional persistence
        if db_manager is not None:
            self._persist_report(report, db_manager)

        return report

    def calculate_network_load(self, bw_report: BandwidthReport) -> ComponentScore:
        """
        Score the bandwidth utilisation component.

        Uses the average bytes/sec relative to the configured link speed.

        Args:
            bw_report: BandwidthReport from BandwidthMonitor.

        Returns:
            :class:`ComponentScore` for bandwidth.
        """
        link_bytes_per_sec = self._cfg.link_speed_bps / 8.0
        avg_bps = bw_report.metrics.avg_bytes_per_second
        utilisation = avg_bps / link_bytes_per_sec if link_bytes_per_sec > 0 else 0.0

        warn_frac = self._cfg.bw_warn_fraction
        high_frac = self._cfg.bw_high_fraction
        crit_frac = self._cfg.bw_critical_fraction

        if utilisation >= crit_frac:
            score = 10.0
            status = "CRITICAL"
            detail = f"Bandwidth at {utilisation*100:.1f}% — link saturated."
        elif utilisation >= high_frac:
            score = 40.0 * (1 - (utilisation - high_frac) / (crit_frac - high_frac + 1e-9))
            status = "HIGH"
            detail = f"Bandwidth at {utilisation*100:.1f}% — approaching saturation."
        elif utilisation >= warn_frac:
            score = 40.0 + 40.0 * (1 - (utilisation - warn_frac) / (high_frac - warn_frac + 1e-9))
            status = "WARN"
            detail = f"Bandwidth at {utilisation*100:.1f}% — moderate load."
        else:
            score = 80.0 + 20.0 * (1 - utilisation / (warn_frac + 1e-9))
            status = "OK"
            detail = f"Bandwidth at {utilisation*100:.1f}% — normal."

        return ComponentScore(
            name="Bandwidth Utilisation",
            score=round(min(100.0, max(0.0, score)), 2),
            weight=self._cfg.weight_bandwidth,
            metric_value=round(utilisation * 100, 4),
            threshold=warn_frac * 100,
            status=status,
            detail=detail,
        )

    def calculate_protocol_health(self, proto_report: ProtocolReport) -> ComponentScore:
        """
        Score protocol diversity using Shannon entropy.

        Higher entropy (more evenly distributed protocols) yields a higher
        score. Monoculture traffic (one dominant protocol) lowers the score.

        Args:
            proto_report: ProtocolReport from ProtocolAnalysis.

        Returns:
            :class:`ComponentScore` for protocol diversity.
        """
        total = proto_report.total_packets or 1
        counts = [e.packet_count for e in proto_report.all_protocols if e.packet_count > 0]

        entropy = 0.0
        if counts:
            probs = [c / total for c in counts]
            entropy = -sum(p * math.log2(p) for p in probs if p > 0)

        excellent_e = self._cfg.diversity_excellent
        warn_e = self._cfg.diversity_warn

        if entropy >= excellent_e:
            score = 95.0
            status = "OK"
            detail = f"Protocol entropy {entropy:.2f} bits — diverse mix."
        elif entropy >= warn_e:
            # Linear interpolation between warn and excellent
            frac = (entropy - warn_e) / (excellent_e - warn_e + 1e-9)
            score = 50.0 + 45.0 * frac
            status = "OK"
            detail = f"Protocol entropy {entropy:.2f} bits — adequate diversity."
        else:
            score = max(10.0, 50.0 * (entropy / (warn_e + 1e-9)))
            status = "WARN"
            detail = f"Protocol entropy {entropy:.2f} bits — traffic concentrated."

        return ComponentScore(
            name="Protocol Diversity",
            score=round(score, 2),
            weight=self._cfg.weight_protocol_diversity,
            metric_value=round(entropy, 4),
            threshold=self._cfg.diversity_warn,
            status=status,
            detail=detail,
        )

    def calculate_host_activity(self, traffic_summary: TrafficSummary) -> ComponentScore:
        """
        Score host-activity health based on top-talker concentration.

        A single host dominating all traffic (high concentration) suggests
        congestion or abnormal behaviour.

        Args:
            traffic_summary: TrafficSummary from TrafficStatistics.

        Returns:
            :class:`ComponentScore` for host activity.
        """
        total_pkts = traffic_summary.basic.total_packets or 1
        top_src = traffic_summary.ip.top_src_ips

        concentration = 0.0
        if top_src:
            top_count = top_src[0][1]
            concentration = top_count / total_pkts

        crit_c = self._cfg.host_concentration_critical
        warn_c = self._cfg.host_concentration_warn

        if concentration >= crit_c:
            score = 10.0
            status = "CRITICAL"
            detail = f"Top host owns {concentration*100:.1f}% of traffic — extreme concentration."
        elif concentration >= warn_c:
            frac = (concentration - warn_c) / (crit_c - warn_c + 1e-9)
            score = 40.0 * (1 - frac)
            status = "WARN"
            detail = f"Top host owns {concentration*100:.1f}% — high concentration."
        else:
            score = 80.0 + 20.0 * (1 - concentration / (warn_c + 1e-9))
            status = "OK"
            detail = f"Top host owns {concentration*100:.1f}% — healthy distribution."

        return ComponentScore(
            name="Host Concentration",
            score=round(min(100.0, max(0.0, score)), 2),
            weight=self._cfg.weight_host_activity,
            metric_value=round(concentration * 100, 4),
            threshold=warn_c * 100,
            status=status,
            detail=detail,
        )

    # ── Visualization Helpers ─────────────────────────────────────────────────

    def get_gauge_data(self, report: NetworkHealthReport) -> dict[str, Any]:
        """
        Return Plotly gauge chart data for the health score.

        Returns::

            {
                "value": 94.0,
                "status": "Excellent",
                "color": "#00C851",
                "ranges": [...]
            }
        """
        color_map = {
            "Excellent": "#00C851",
            "Good":      "#44BB99",
            "Moderate":  "#FF8800",
            "Poor":      "#FF4444",
            "Critical":  "#CC0000",
        }
        color = color_map.get(report.health_status, "#AAAAAA")
        return {
            "value": report.health_score,
            "status": report.health_status,
            "color": color,
            "ranges": [
                {"label": "Critical",  "min": 0,  "max": 35,  "color": "#CC0000"},
                {"label": "Poor",      "min": 35, "max": 55,  "color": "#FF4444"},
                {"label": "Moderate",  "min": 55, "max": 75,  "color": "#FF8800"},
                {"label": "Good",      "min": 75, "max": 90,  "color": "#44BB99"},
                {"label": "Excellent", "min": 90, "max": 100, "color": "#00C851"},
            ],
        }

    def get_line_chart_data(self, report: NetworkHealthReport) -> dict[str, list]:
        """
        Return component scores as a bar/line chart dataset.

        Returns::

            {"labels": ["Bandwidth", ...], "values": [95.0, ...]}
        """
        return {
            "labels": [c.name for c in report.components],
            "values": [round(c.score, 1) for c in report.components],
            "weights": [c.weight for c in report.components],
            "statuses": [c.status for c in report.components],
        }

    def get_heatmap_data(self, report: NetworkHealthReport) -> pd.DataFrame:
        """
        Return a DataFrame suitable for a Plotly heatmap of component scores.

        Columns: Component, Score, Status, Weight, MetricValue
        """
        rows = []
        for c in report.components:
            rows.append({
                "Component": c.name,
                "Score": round(c.score, 1),
                "Status": c.status,
                "Weight": c.weight,
                "MetricValue": round(c.metric_value, 4),
            })
        return pd.DataFrame(rows)

    def get_alert_table(self, report: NetworkHealthReport) -> pd.DataFrame:
        """
        Return a DataFrame of issues and recommendations for the alert table.
        """
        rows = [{"Type": "Issue",          "Message": msg} for msg in report.issues]
        rows += [{"Type": "Recommendation", "Message": msg} for msg in report.recommendations]
        return pd.DataFrame(rows) if rows else pd.DataFrame(columns=["Type", "Message"])

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _score_packet_rate(self, bw_report: BandwidthReport) -> ComponentScore:
        """Score the average packets-per-second rate."""
        avg_pps = bw_report.metrics.avg_packets_per_second
        warn_pps = self._cfg.pps_warn
        high_pps = self._cfg.pps_high
        crit_pps = self._cfg.pps_critical

        if avg_pps >= crit_pps:
            score, status = 10.0, "CRITICAL"
            detail = f"PPS={avg_pps:.0f} — extremely high packet rate."
        elif avg_pps >= high_pps:
            frac = (avg_pps - high_pps) / (crit_pps - high_pps + 1e-9)
            score, status = 40.0 * (1 - frac), "HIGH"
            detail = f"PPS={avg_pps:.0f} — high packet rate."
        elif avg_pps >= warn_pps:
            frac = (avg_pps - warn_pps) / (high_pps - warn_pps + 1e-9)
            score, status = 60.0 + 20.0 * (1 - frac), "WARN"
            detail = f"PPS={avg_pps:.0f} — elevated packet rate."
        else:
            score = min(100.0, 80.0 + 20.0 * (1 - avg_pps / (warn_pps + 1e-9)))
            status = "OK"
            detail = f"PPS={avg_pps:.0f} — normal."

        return ComponentScore(
            name="Packet Rate",
            score=round(min(100.0, max(0.0, score)), 2),
            weight=self._cfg.weight_packet_rate,
            metric_value=round(avg_pps, 2),
            threshold=warn_pps,
            status=status,
            detail=detail,
        )

    def _score_malformed(self, proto_report: ProtocolReport) -> ComponentScore:
        """Score based on the malformed-packet percentage."""
        malformed_pct = proto_report.malformed_pct  # 0–100 scale
        malformed_frac = malformed_pct / 100.0

        warn_f = self._cfg.malformed_warn
        high_f = self._cfg.malformed_high
        crit_f = self._cfg.malformed_critical

        if malformed_frac >= crit_f:
            score, status = 5.0, "CRITICAL"
            detail = f"Malformed={malformed_pct:.1f}% — network integrity severely degraded."
        elif malformed_frac >= high_f:
            frac = (malformed_frac - high_f) / (crit_f - high_f + 1e-9)
            score, status = 20.0 * (1 - frac), "HIGH"
            detail = f"Malformed={malformed_pct:.1f}% — significant packet corruption."
        elif malformed_frac >= warn_f:
            frac = (malformed_frac - warn_f) / (high_f - warn_f + 1e-9)
            score, status = 55.0 + 25.0 * (1 - frac), "WARN"
            detail = f"Malformed={malformed_pct:.1f}% — elevated malformed rate."
        else:
            score = 80.0 + 20.0 * (1 - malformed_frac / (warn_f + 1e-9))
            status = "OK"
            detail = f"Malformed={malformed_pct:.1f}% — healthy."

        return ComponentScore(
            name="Malformed Packets",
            score=round(min(100.0, max(0.0, score)), 2),
            weight=self._cfg.weight_malformed,
            metric_value=round(malformed_pct, 4),
            threshold=warn_f * 100,
            status=status,
            detail=detail,
        )

    def _score_stability(self, bandwidth_monitor: BandwidthMonitor) -> ComponentScore:
        """
        Score traffic stability using the coefficient of variation (CV) on
        per-minute byte volumes from BandwidthMonitor.
        """
        try:
            df = bandwidth_monitor.traffic_timeline(freq="1min")
            if df.empty or "bytes_transferred" not in df.columns or len(df) < 2:
                return ComponentScore(
                    name="Traffic Stability",
                    score=70.0,
                    weight=self._cfg.weight_stability,
                    metric_value=0.0,
                    threshold=self._cfg.stability_warn_cv,
                    status="OK",
                    detail="Insufficient intervals for stability analysis.",
                )
            series = df["bytes_transferred"].astype(float)
            mean_val = series.mean()
            std_val = series.std()
            cv = std_val / mean_val if mean_val > 0 else 0.0
        except Exception as exc:
            log.warning("Stability score computation failed: %s", exc)
            cv = 0.0

        warn_cv = self._cfg.stability_warn_cv
        crit_cv = self._cfg.stability_critical_cv

        if cv >= crit_cv:
            score, status = 10.0, "CRITICAL"
            detail = f"CV={cv:.2f} — highly unstable traffic."
        elif cv >= warn_cv:
            frac = (cv - warn_cv) / (crit_cv - warn_cv + 1e-9)
            score, status = 40.0 * (1 - frac), "WARN"
            detail = f"CV={cv:.2f} — moderate traffic fluctuations."
        else:
            score = min(100.0, 80.0 + 20.0 * (1 - cv / (warn_cv + 1e-9)))
            status = "OK"
            detail = f"CV={cv:.2f} — stable traffic pattern."

        return ComponentScore(
            name="Traffic Stability",
            score=round(min(100.0, max(0.0, score)), 2),
            weight=self._cfg.weight_stability,
            metric_value=round(cv, 4),
            threshold=warn_cv,
            status=status,
            detail=detail,
        )

    def _compute_growth_rate(self, bandwidth_monitor: BandwidthMonitor) -> float:
        """
        Compute the packet-count growth rate between first and second half of
        the capture window.

        Returns:
            Fractional growth rate (positive = growth, negative = decline).
        """
        try:
            df = bandwidth_monitor.traffic_timeline(freq="1s")
            if df.empty or len(df) < 2:
                return 0.0
            mid = len(df) // 2
            first_half = df.iloc[:mid]["packets_transferred"].sum()
            second_half = df.iloc[mid:]["packets_transferred"].sum()
            if first_half == 0:
                return 0.0
            return round((second_half - first_half) / first_half, 4)
        except Exception as exc:
            log.warning("Growth rate computation failed: %s", exc)
            return 0.0

    def _stability_label(self, cv: float) -> str:
        """Convert coefficient of variation to a human-readable label."""
        if cv >= self._cfg.stability_critical_cv:
            return "Highly Unstable"
        if cv >= self._cfg.stability_warn_cv:
            return "Unstable"
        if cv >= 0.5:
            return "Moderate"
        return "Stable"

    @staticmethod
    def _score_to_status(score: float) -> str:
        """Map a numeric score to a health status label."""
        thresholds = (
            (90.0, "Excellent"),
            (75.0, "Good"),
            (55.0, "Moderate"),
            (35.0, "Poor"),
            (0.0,  "Critical"),
        )
        for threshold, label in thresholds:
            if score >= threshold:
                return label
        return "Critical"

    def _collect_issues(
        self, components: list[ComponentScore]
    ) -> tuple[list[str], list[str]]:
        """Collect issues and recommendations from component scores."""
        issues: list[str] = []
        recommendations: list[str] = []

        _recs: dict[str, str] = {
            "Bandwidth Utilisation": "Consider upgrading link capacity or implementing QoS/traffic shaping.",
            "Packet Rate":           "Investigate traffic sources; consider rate-limiting or load balancing.",
            "Malformed Packets":     "Inspect network devices for hardware faults or driver issues.",
            "Protocol Diversity":    "Audit network for unexpected protocol usage or misconfigurations.",
            "Host Concentration":    "Investigate top-talker host for abnormal behaviour or misconfiguration.",
            "Traffic Stability":     "Identify bursty applications; consider traffic smoothing policies.",
        }

        for c in components:
            if c.status in ("WARN", "HIGH", "CRITICAL"):
                issues.append(f"[{c.status}] {c.name}: {c.detail}")
                rec = _recs.get(c.name)
                if rec and rec not in recommendations:
                    recommendations.append(rec)

        return issues, recommendations

    def _persist_report(self, report: NetworkHealthReport, db_manager) -> None:
        """
        Optionally persist the health report as an alert record in SQLite.

        Only persists if health_status is NOT 'Excellent' or 'Good', to
        avoid flooding the alerts table with routine checks.
        """
        if report.health_status in ("Excellent", "Good"):
            return
        try:
            from database.db_manager import AlertRecord
            severity_map = {
                "Moderate": "LOW",
                "Poor":     "HIGH",
                "Critical": "CRITICAL",
            }
            severity = severity_map.get(report.health_status, "MEDIUM")
            alert = AlertRecord(
                timestamp=report.computed_at,
                alert_type="NetworkHealth",
                severity=severity,
                src_ip="N/A",
                dst_ip="N/A",
                description=(
                    f"Health score {report.health_score:.1f} — "
                    f"{report.health_status}. "
                    f"Issues: {'; '.join(report.issues[:3])}"
                ),
            )
            db_manager.insert_alert(alert)
            log.info("Health alert persisted (status=%s).", report.health_status)
        except Exception as exc:
            log.warning("Failed to persist health report: %s", exc)
