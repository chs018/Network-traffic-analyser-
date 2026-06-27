"""
network_quality.py — Network Quality Analyzer
==============================================
Network Traffic Analysis and Intrusion Detection System

Estimates network quality dimensions that cannot be directly measured
from packet captures alone, using proxy metrics derived from Phase 3:

  - Estimated Latency Score      (proxy: TTL dispersion + avg packet size)
  - Estimated Congestion Score   (proxy: bandwidth utilisation + PPS burst ratio)
  - Packet Delivery Efficiency   (proxy: inverse of malformed % + size consistency)
  - Traffic Balance Score        (proxy: src/dst IP symmetry + protocol diversity)
  - Network Stability Score      (proxy: coefficient of variation on byte timeline)
  - Overall Quality Index        (weighted composite of the five dimensions)

Quality Levels (Quality Index → Label):
    90–100  Excellent
    75–89   Good
    55–74   Fair
    0–54    Poor

Classes:
    QualityDimension  — Dataclass: single quality dimension result
    QualityReport     — Dataclass: complete quality analysis output
    NetworkQualityAnalyzer — Main engine (Phase 4)

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
# DATACLASSES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class QualityDimension:
    """
    Score and metadata for a single network quality dimension.

    Attributes:
        name:         Dimension identifier (e.g. ``"Latency Score"``).
        score:        Dimension score 0.0–100.0.
        weight:       Contribution weight in composite index.
        proxy_metric: Name of the proxy metric used to estimate this dimension.
        proxy_value:  Observed proxy metric value.
        quality:      Quality label for this dimension.
        explanation:  Human-readable computation note.
    """
    name: str
    score: float
    weight: float
    proxy_metric: str
    proxy_value: float
    quality: str
    explanation: str = ""


@dataclass
class QualityReport:
    """
    Complete network quality analysis result.

    Produced by :meth:`NetworkQualityAnalyzer.generate_quality_report`.
    """

    # Overall
    quality_index: float = 0.0          # 0–100 composite
    quality_level: str = "Unknown"       # Excellent / Good / Fair / Poor
    computed_at: str = ""

    # Per-dimension results
    dimensions: list[QualityDimension] = field(default_factory=list)

    # Individual scores (flattened for easy dashboard access)
    latency_score: float = 0.0
    congestion_score: float = 0.0
    delivery_efficiency: float = 0.0
    traffic_balance_score: float = 0.0
    stability_score: float = 0.0

    # Interpretation notes
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable flat dictionary."""
        return {
            "quality_index":       round(self.quality_index, 1),
            "quality_level":       self.quality_level,
            "computed_at":         self.computed_at,
            "latency_score":       round(self.latency_score, 1),
            "congestion_score":    round(self.congestion_score, 1),
            "delivery_efficiency": round(self.delivery_efficiency, 1),
            "traffic_balance_score": round(self.traffic_balance_score, 1),
            "stability_score":     round(self.stability_score, 1),
            "notes":               self.notes,
            "dimensions": [
                {
                    "name":         d.name,
                    "score":        round(d.score, 1),
                    "weight":       d.weight,
                    "proxy_metric": d.proxy_metric,
                    "proxy_value":  round(d.proxy_value, 4),
                    "quality":      d.quality,
                    "explanation":  d.explanation,
                }
                for d in self.dimensions
            ],
        }


# ──────────────────────────────────────────────────────────────────────────────
# NETWORK QUALITY ANALYZER ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class NetworkQualityAnalyzer:
    """
    Phase 4 Network Quality Estimation Engine.

    Estimates five network quality dimensions using proxy metrics derived
    from Phase 3 analytics outputs. All scores are in the range 0–100.

    .. note::
        Because this system analyses packet captures rather than active probes,
        the scores are *estimates* based on observable traffic characteristics.
        Latency is never directly measured — TTL dispersion serves as a proxy.

    Args:
        link_speed_bps:         Nominal link capacity in bits/second.
        latency_weight:         Weight for latency score in composite (0–1).
        congestion_weight:      Weight for congestion score.
        delivery_weight:        Weight for delivery efficiency.
        balance_weight:         Weight for traffic balance.
        stability_weight:       Weight for stability score.
        ttl_std_warn:           TTL standard deviation that begins score penalty.
        ttl_std_critical:       TTL std dev at which score reaches minimum.
        congestion_bw_thresh:   BW utilisation fraction above which congestion
                                score begins declining.

    Usage::

        ts = TrafficStatistics(); ts.load_data()
        pa = ProtocolAnalysis();  pa.load_data()
        bm = BandwidthMonitor();  bm.load_data()

        qa = NetworkQualityAnalyzer()
        report = qa.generate_quality_report(ts, pa, bm)
        print(f"Quality Index: {report.quality_index} ({report.quality_level})")
    """

    _QUALITY_THRESHOLDS = (
        (90.0, "Excellent"),
        (75.0, "Good"),
        (55.0, "Fair"),
        (0.0,  "Poor"),
    )

    def __init__(
        self,
        link_speed_bps: float = 1_000_000_000.0,
        latency_weight: float = 0.20,
        congestion_weight: float = 0.25,
        delivery_weight: float = 0.25,
        balance_weight: float = 0.15,
        stability_weight: float = 0.15,
        ttl_std_warn: float = 20.0,
        ttl_std_critical: float = 60.0,
        congestion_bw_thresh: float = 0.50,
    ) -> None:
        self.link_speed_bps = link_speed_bps
        self.latency_weight = latency_weight
        self.congestion_weight = congestion_weight
        self.delivery_weight = delivery_weight
        self.balance_weight = balance_weight
        self.stability_weight = stability_weight
        self.ttl_std_warn = ttl_std_warn
        self.ttl_std_critical = ttl_std_critical
        self.congestion_bw_thresh = congestion_bw_thresh

        log.debug("NetworkQualityAnalyzer initialised.")

    # ── Master Report ─────────────────────────────────────────────────────────

    def generate_quality_report(
        self,
        traffic_stats: TrafficStatistics,
        protocol_analysis: ProtocolAnalysis,
        bandwidth_monitor: BandwidthMonitor,
        db_manager=None,
    ) -> QualityReport:
        """
        Generate a complete :class:`QualityReport`.

        Args:
            traffic_stats:     Loaded :class:`TrafficStatistics`.
            protocol_analysis: Loaded :class:`ProtocolAnalysis`.
            bandwidth_monitor: Loaded :class:`BandwidthMonitor`.
            db_manager:        Optional DatabaseManager (currently unused).

        Returns:
            Populated :class:`QualityReport`.
        """
        log.info("Generating network quality report…")

        ts_summary = traffic_stats.generate_summary()
        proto_report = protocol_analysis.generate_protocol_report()
        bw_report = bandwidth_monitor.generate_bandwidth_report()

        # Compute all five dimensions
        latency_dim     = self._estimate_latency_score(traffic_stats)
        congestion_dim  = self._estimate_congestion_score(bw_report)
        delivery_dim    = self._estimate_delivery_efficiency(proto_report, ts_summary)
        balance_dim     = self._estimate_traffic_balance(ts_summary, proto_report)
        stability_dim   = self._estimate_stability_score(bandwidth_monitor)

        dimensions = [latency_dim, congestion_dim, delivery_dim, balance_dim, stability_dim]

        # Composite quality index
        quality_index = sum(d.score * d.weight for d in dimensions)
        quality_index = max(0.0, min(100.0, quality_index))
        quality_level = self._score_to_quality(quality_index)

        # Notes
        notes = self._build_notes(dimensions)

        report = QualityReport(
            quality_index=round(quality_index, 2),
            quality_level=quality_level,
            computed_at=datetime.now(tz=timezone.utc).isoformat(),
            dimensions=dimensions,
            latency_score=latency_dim.score,
            congestion_score=congestion_dim.score,
            delivery_efficiency=delivery_dim.score,
            traffic_balance_score=balance_dim.score,
            stability_score=stability_dim.score,
            notes=notes,
        )

        log.info(
            "Quality report: index=%.1f level=%s",
            report.quality_index, report.quality_level,
        )
        return report

    # ── Dimension Estimators ──────────────────────────────────────────────────

    def _estimate_latency_score(
        self, traffic_stats: TrafficStatistics
    ) -> QualityDimension:
        """
        Estimate a latency-quality proxy from TTL standard deviation.

        High TTL variability suggests diverse path lengths or TTL manipulation,
        which correlates with higher latency variance.

        A consistent TTL (low std dev) → high score.
        High TTL dispersion → lower score.
        """
        try:
            df = traffic_stats.get_dataframe()
            if df.empty or "ttl" not in df.columns:
                raise ValueError("No TTL column available.")
            ttl_vals = pd.to_numeric(df["ttl"], errors="coerce").dropna()
            if len(ttl_vals) < 2:
                raise ValueError("Insufficient TTL observations.")

            ttl_std = float(ttl_vals.std())
            ttl_mean = float(ttl_vals.mean())

            warn = self.ttl_std_warn
            crit = self.ttl_std_critical

            if ttl_std >= crit:
                score = 20.0
                quality = "Poor"
                explanation = (
                    f"TTL std={ttl_std:.1f} — high path length dispersion "
                    f"(mean TTL={ttl_mean:.1f})."
                )
            elif ttl_std >= warn:
                frac = (ttl_std - warn) / (crit - warn + 1e-9)
                score = 60.0 - 40.0 * frac
                quality = "Fair"
                explanation = (
                    f"TTL std={ttl_std:.1f} — moderate path variability."
                )
            else:
                score = min(100.0, 80.0 + 20.0 * (1 - ttl_std / (warn + 1e-9)))
                quality = "Good" if score < 90 else "Excellent"
                explanation = (
                    f"TTL std={ttl_std:.1f} — consistent path lengths."
                )

            proxy_value = round(ttl_std, 4)
            proxy_metric = "ttl_standard_deviation"

        except Exception as exc:
            log.debug("Latency proxy unavailable: %s — using avg_packet_size fallback.", exc)
            # Fallback: use average packet size as proxy
            # Larger avg size → lower latency score (more data in flight)
            try:
                df = traffic_stats.get_dataframe()
                avg_size = float(df["packet_length"].mean()) if "packet_length" in df.columns else 500.0
            except Exception:
                avg_size = 500.0

            # Typical LAN: 200–600 bytes is normal
            if avg_size > 1200:
                score, quality = 50.0, "Fair"
            elif avg_size > 800:
                score, quality = 70.0, "Good"
            else:
                score, quality = 85.0, "Good"

            proxy_value = round(avg_size, 2)
            proxy_metric = "avg_packet_size_fallback"
            explanation = f"TTL unavailable — proxy via avg packet size={avg_size:.0f} B."

        return QualityDimension(
            name="Estimated Latency Score",
            score=round(min(100.0, max(0.0, score)), 2),
            weight=self.latency_weight,
            proxy_metric=proxy_metric,
            proxy_value=proxy_value,
            quality=quality,
            explanation=explanation,
        )

    def _estimate_congestion_score(
        self, bw_report: BandwidthReport
    ) -> QualityDimension:
        """
        Estimate network congestion by combining:
          1. Bandwidth utilisation (avg bps relative to link)
          2. Burst ratio (peak bps / avg bps — high ratio → bursty)

        High utilisation + high burst ratio → congested → low score.
        """
        link_bps = self.link_speed_bps / 8.0
        avg_bps = bw_report.metrics.avg_bytes_per_second
        peak_bps = bw_report.metrics.peak_bytes_per_second

        util_frac = avg_bps / link_bps if link_bps > 0 else 0.0
        burst_ratio = (peak_bps / avg_bps) if avg_bps > 0 else 1.0
        burst_ratio = min(burst_ratio, 20.0)  # Cap at 20x

        # Utilisation sub-score (0–100)
        thresh = self.congestion_bw_thresh
        if util_frac >= 0.90:
            util_score = 5.0
        elif util_frac >= thresh:
            frac = (util_frac - thresh) / (0.90 - thresh + 1e-9)
            util_score = 60.0 * (1 - frac)
        else:
            util_score = min(100.0, 100.0 * (1 - util_frac / (thresh + 1e-9)) + 40.0)
            util_score = min(util_score, 100.0)

        # Burst ratio sub-score (0–100): burst_ratio of 1 = perfect, 10+ = bad
        burst_score = max(10.0, 100.0 - (burst_ratio - 1.0) * 10.0)

        # Composite congestion score
        congestion_score = 0.60 * util_score + 0.40 * burst_score

        if congestion_score >= 90:
            quality = "Excellent"
        elif congestion_score >= 75:
            quality = "Good"
        elif congestion_score >= 55:
            quality = "Fair"
        else:
            quality = "Poor"

        explanation = (
            f"BW util={util_frac*100:.2f}%, burst ratio={burst_ratio:.1f}x — "
            f"util_score={util_score:.0f}, burst_score={burst_score:.0f}."
        )

        return QualityDimension(
            name="Estimated Congestion Score",
            score=round(min(100.0, max(0.0, congestion_score)), 2),
            weight=self.congestion_weight,
            proxy_metric="bw_util_and_burst_ratio",
            proxy_value=round(util_frac * 100, 4),
            quality=quality,
            explanation=explanation,
        )

    def _estimate_delivery_efficiency(
        self,
        proto_report: ProtocolReport,
        ts_summary: TrafficSummary,
    ) -> QualityDimension:
        """
        Estimate packet delivery efficiency from:
          1. Inverse malformed packet ratio (high malformed → low efficiency)
          2. Packet size consistency (inverse of std/mean coefficient of variation)

        High efficiency → high score.
        """
        # Component 1: malformed ratio
        malformed_frac = proto_report.malformed_pct / 100.0
        malformed_score = max(0.0, 100.0 * (1.0 - malformed_frac * 5.0))
        malformed_score = min(100.0, malformed_score)

        # Component 2: size consistency (CV of packet sizes)
        avg_size = ts_summary.packets.avg_packet_size
        std_size = ts_summary.packets.std_packet_size
        cv = std_size / avg_size if avg_size > 0 else 0.0
        # CV=0 (all same size) → perfect. CV=2+ → very inconsistent.
        consistency_score = max(10.0, 100.0 - cv * 30.0)
        consistency_score = min(100.0, consistency_score)

        efficiency = 0.60 * malformed_score + 0.40 * consistency_score

        if efficiency >= 90:
            quality = "Excellent"
        elif efficiency >= 75:
            quality = "Good"
        elif efficiency >= 55:
            quality = "Fair"
        else:
            quality = "Poor"

        explanation = (
            f"Malformed={proto_report.malformed_pct:.1f}% (score={malformed_score:.0f}), "
            f"size CV={cv:.2f} (score={consistency_score:.0f})."
        )

        return QualityDimension(
            name="Packet Delivery Efficiency",
            score=round(min(100.0, max(0.0, efficiency)), 2),
            weight=self.delivery_weight,
            proxy_metric="malformed_pct_and_size_cv",
            proxy_value=round(proto_report.malformed_pct, 4),
            quality=quality,
            explanation=explanation,
        )

    def _estimate_traffic_balance(
        self,
        ts_summary: TrafficSummary,
        proto_report: ProtocolReport,
    ) -> QualityDimension:
        """
        Estimate traffic balance from:
          1. Src/Dst IP symmetry: similar number of unique sources and destinations
             suggests balanced bidirectional communication.
          2. Protocol diversity (Shannon entropy — reused from health monitor logic).

        Well-balanced traffic → high score.
        """
        # IP symmetry score
        src_count = max(ts_summary.ip.unique_src_ips, 1)
        dst_count = max(ts_summary.ip.unique_dst_ips, 1)
        ratio = min(src_count, dst_count) / max(src_count, dst_count)
        ip_symmetry_score = 50.0 + 50.0 * ratio  # 50–100

        # Protocol diversity score (Shannon entropy)
        total = proto_report.total_packets or 1
        counts = [e.packet_count for e in proto_report.all_protocols if e.packet_count > 0]
        entropy = 0.0
        if counts:
            probs = [c / total for c in counts]
            entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        max_entropy = math.log2(max(len(counts), 1))
        norm_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
        diversity_score = 40.0 + 60.0 * norm_entropy  # 40–100

        balance = 0.50 * ip_symmetry_score + 0.50 * diversity_score

        if balance >= 90:
            quality = "Excellent"
        elif balance >= 75:
            quality = "Good"
        elif balance >= 55:
            quality = "Fair"
        else:
            quality = "Poor"

        explanation = (
            f"IP symmetry ratio={ratio:.2f} (score={ip_symmetry_score:.0f}), "
            f"entropy={entropy:.2f} bits (score={diversity_score:.0f})."
        )

        return QualityDimension(
            name="Traffic Balance Score",
            score=round(min(100.0, max(0.0, balance)), 2),
            weight=self.balance_weight,
            proxy_metric="ip_symmetry_and_protocol_entropy",
            proxy_value=round(ratio, 4),
            quality=quality,
            explanation=explanation,
        )

    def _estimate_stability_score(
        self, bandwidth_monitor: BandwidthMonitor
    ) -> QualityDimension:
        """
        Estimate network stability from the coefficient of variation (CV)
        of per-minute byte volumes.

        Low CV → stable → high score.
        High CV → bursty/unstable → low score.
        """
        try:
            df = bandwidth_monitor.traffic_timeline(freq="1min")
            if df.empty or "bytes_transferred" not in df.columns or len(df) < 2:
                raise ValueError("Insufficient timeline data for stability.")

            series = df["bytes_transferred"].astype(float)
            mean_val = series.mean()
            std_val = series.std()
            cv = std_val / mean_val if mean_val > 0 else 0.0

            # CV=0 → perfect stability (score=100). CV=3+ → very unstable.
            score = max(10.0, 100.0 - cv * 25.0)
            score = min(100.0, score)

            if score >= 90:
                quality = "Excellent"
            elif score >= 75:
                quality = "Good"
            elif score >= 55:
                quality = "Fair"
            else:
                quality = "Poor"

            explanation = (
                f"Per-minute volume CV={cv:.3f} across {len(df)} intervals "
                f"(mean={mean_val:.0f} B, std={std_val:.0f} B)."
            )
            proxy_value = round(cv, 4)

        except Exception as exc:
            log.debug("Stability estimation failed: %s — using default.", exc)
            score = 70.0
            quality = "Good"
            explanation = "Insufficient data for stability estimation — default assigned."
            proxy_value = 0.0

        return QualityDimension(
            name="Network Stability Score",
            score=round(min(100.0, max(0.0, score)), 2),
            weight=self.stability_weight,
            proxy_metric="per_minute_bytes_cv",
            proxy_value=proxy_value,
            quality=quality,
            explanation=explanation,
        )

    # ── Visualization Helpers ─────────────────────────────────────────────────

    def get_gauge_data(self, report: QualityReport) -> dict[str, Any]:
        """
        Return Plotly gauge chart data for the Quality Index.

        Returns::

            {
                "value": 92.0,
                "level": "Excellent",
                "color": "#00C851",
                "ranges": [...]
            }
        """
        color_map = {
            "Excellent": "#00C851",
            "Good":      "#44BB99",
            "Fair":      "#FF8800",
            "Poor":      "#FF4444",
        }
        color = color_map.get(report.quality_level, "#AAAAAA")
        return {
            "value": report.quality_index,
            "level": report.quality_level,
            "color": color,
            "ranges": [
                {"label": "Poor",      "min": 0,  "max": 55,  "color": "#FF4444"},
                {"label": "Fair",      "min": 55, "max": 75,  "color": "#FF8800"},
                {"label": "Good",      "min": 75, "max": 90,  "color": "#44BB99"},
                {"label": "Excellent", "min": 90, "max": 100, "color": "#00C851"},
            ],
        }

    def get_line_chart_data(self, report: QualityReport) -> dict[str, list]:
        """
        Return all dimension scores as a line/bar dataset.

        Returns::

            {"labels": ["Latency", ...], "values": [85.0, ...]}
        """
        return {
            "labels": [d.name for d in report.dimensions],
            "values": [round(d.score, 1) for d in report.dimensions],
            "qualities": [d.quality for d in report.dimensions],
        }

    def get_heatmap_data(self, report: QualityReport) -> pd.DataFrame:
        """Return dimensions as a DataFrame for heatmap or table display."""
        rows = [
            {
                "Dimension":    d.name,
                "Score":        round(d.score, 1),
                "Quality":      d.quality,
                "Weight":       d.weight,
                "ProxyMetric":  d.proxy_metric,
                "ProxyValue":   round(d.proxy_value, 4),
                "Explanation":  d.explanation,
            }
            for d in report.dimensions
        ]
        return pd.DataFrame(rows)

    def get_alert_table(self, report: QualityReport) -> pd.DataFrame:
        """Return notes as an alert/info table."""
        if not report.notes:
            return pd.DataFrame(columns=["Type", "Note"])
        rows = [{"Type": "Quality Note", "Note": n} for n in report.notes]
        return pd.DataFrame(rows)

    # ── Internal Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _score_to_quality(score: float) -> str:
        """Map a numeric score to a quality level label."""
        thresholds = (
            (90.0, "Excellent"),
            (75.0, "Good"),
            (55.0, "Fair"),
            (0.0,  "Poor"),
        )
        for threshold, label in thresholds:
            if score >= threshold:
                return label
        return "Poor"

    @staticmethod
    def _build_notes(dimensions: list[QualityDimension]) -> list[str]:
        """Collect informational notes for sub-optimal dimensions."""
        notes: list[str] = []
        for d in dimensions:
            if d.quality in ("Fair", "Poor"):
                notes.append(
                    f"{d.name} is {d.quality} (score={d.score:.0f}): {d.explanation}"
                )
        return notes
