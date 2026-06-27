"""
bandwidth_monitor.py — Network Bandwidth Analytics Engine
==========================================================
Network Traffic Analysis and Intrusion Detection System

Analyses network utilisation from captured packet data:
  - Total bytes and average/peak bytes-per-second
  - Average/peak packets-per-second
  - Traffic volume per minute and per second
  - Bandwidth utilisation estimate relative to a link speed
  - Top traffic intervals (busiest time windows)
  - Time-series data for Plotly charts

Data Sources:
    - CSV mode: data/processed/packets.csv
    - SQLite mode: traffic_logs table (via DatabaseManager)

Classes:
    BandwidthSample   — Dataclass: single measurement snapshot (legacy compat)
    BandwidthMetrics  — Dataclass: aggregate bandwidth metrics
    IntervalStats     — Dataclass: statistics for a single time interval
    BandwidthReport   — Dataclass: complete bandwidth analysis result
    BandwidthMonitor  — Analytics engine (Phase 3, fully implemented)

Note:
    The Phase 1 ``BandwidthMonitor`` ring-buffer API is extended with
    full Phase 3 analytics methods. Existing ``record()`` / ``samples``
    functionality is preserved for live-capture integration.

Author: Network Traffic Analyzer Project
Version: 3.0.0
Python: 3.11+
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import numpy as np

from utils.config import config
from utils.logger import get_analysis_logger

log = get_analysis_logger()


# ──────────────────────────────────────────────────────────────────────────────
# DATACLASSES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class BandwidthSample:
    """
    A point-in-time bandwidth measurement (retained from Phase 1).

    Used by the live-capture ring-buffer maintained in ``self.samples``.
    """

    timestamp: str
    bytes_per_second: float
    packets_per_second: float
    utilisation_pct: float       # 0.0–100.0
    interface: str = "unknown"


@dataclass
class BandwidthMetrics:
    """Aggregate bandwidth metrics computed from a packet dataset."""

    total_bytes: int = 0
    total_packets: int = 0
    capture_duration_seconds: float = 0.0

    # Byte rate
    avg_bytes_per_second: float = 0.0
    peak_bytes_per_second: float = 0.0

    # Packet rate
    avg_packets_per_second: float = 0.0
    peak_packets_per_second: float = 0.0

    # Utilisation (relative to link speed)
    bandwidth_utilisation_pct: float = 0.0   # 0.0–100.0

    # Window
    capture_start: str = ""
    capture_end: str = ""


@dataclass
class IntervalStats:
    """Statistics for a single time interval (per-second or per-minute)."""

    timestamp: str
    bytes_transferred: int = 0
    packets_transferred: int = 0
    bytes_per_second: float = 0.0
    packets_per_second: float = 0.0


@dataclass
class BandwidthReport:
    """
    Complete bandwidth analysis result produced by
    :meth:`BandwidthMonitor.generate_bandwidth_report`.
    """

    metrics: BandwidthMetrics = field(default_factory=BandwidthMetrics)
    per_minute: list[IntervalStats] = field(default_factory=list)
    per_second: list[IntervalStats] = field(default_factory=list)
    top_intervals: list[IntervalStats] = field(default_factory=list)

    # DataFrames for dashboard tables / Plotly charts
    per_minute_df: Optional[pd.DataFrame] = None
    per_second_df: Optional[pd.DataFrame] = None


# ──────────────────────────────────────────────────────────────────────────────
# BANDWIDTH ANALYTICS ENGINE  (Phase 3)
# ──────────────────────────────────────────────────────────────────────────────

class BandwidthMonitor:
    """
    Phase 3 Bandwidth Analytics Engine.

    Provides both:
    - **Historical analysis**: Load packets.csv or DB and compute
      throughput, peak rates, timeline data, and utilisation estimates.
    - **Live monitoring** (Phase 1 ring-buffer): ``record()`` + ``samples``
      deque for real-time capture integration.

    Args:
        link_speed_bps (float): Nominal link capacity in bits/second.
                                Default 1 Gbps. Used only for utilisation %.
        window_size (int):      Ring-buffer capacity for live samples.
        top_n (int):            Number of top traffic intervals to return.
        csv_path (Path):        Override path to packets.csv.

    Usage::

        bm = BandwidthMonitor(link_speed_bps=1e9, top_n=5)
        bm.load_data()
        report = bm.generate_bandwidth_report()
        line_data = bm.get_line_chart_data("bytes_per_minute")
    """

    _COL_MAP: dict[str, str] = {
        "source_ip": "src_ip",
        "destination_ip": "dst_ip",
        "source_port": "src_port",
        "destination_port": "dst_port",
    }

    def __init__(
        self,
        link_speed_bps: float = 1_000_000_000.0,   # 1 Gbps
        window_size: int = 120,
        top_n: int = 5,
        csv_path: Optional[Path] = None,
    ) -> None:
        self.link_speed_bps: float = link_speed_bps
        self.window_size: int = window_size
        self.top_n: int = top_n
        self.csv_path: Path = csv_path or (
            config.paths.processed_data_dir / "packets.csv"
        )

        # Phase 1 ring-buffer
        self.samples: deque[BandwidthSample] = deque(maxlen=window_size)
        self.peak_bytes_per_second: float = 0.0

        # Internal DataFrame (Phase 3)
        self._df: Optional[pd.DataFrame] = None

        log.debug(
            "BandwidthMonitor initialised (link=%.2f Gbps, window=%d, top_n=%d).",
            link_speed_bps / 1e9, window_size, top_n,
        )

    # ── Data Loading ──────────────────────────────────────────────────────────

    def load_data(
        self,
        source: str = "csv",
        db_manager=None,
        limit: int = 100_000,
    ) -> pd.DataFrame:
        """
        Load traffic data for bandwidth analysis.

        Args:
            source:     ``"csv"`` (default) or ``"db"``.
            db_manager: DatabaseManager (required for ``source="db"``).
            limit:      Max rows from DB.

        Returns:
            Cleaned DataFrame with validated timestamps.
        """
        if source == "csv":
            if not self.csv_path.exists():
                raise FileNotFoundError(
                    f"packets.csv not found: {self.csv_path}"
                )
            df = pd.read_csv(self.csv_path, low_memory=False)
        elif source == "db":
            if db_manager is None:
                raise ValueError("db_manager required for source='db'.")
            rows = db_manager.fetch_recent_traffic(limit=limit)
            df = pd.DataFrame(rows) if rows else pd.DataFrame()
        else:
            raise ValueError(f"Unknown source: '{source}'.")

        self._df = self._prepare_dataframe(df)
        log.info(
            "BandwidthMonitor loaded %d records from '%s'.",
            len(self._df), source,
        )
        return self._df

    def _prepare_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Rename, coerce types, parse timestamps, and validate.

        Ensures ``packet_length`` is numeric and ``timestamp`` is a
        timezone-aware datetime column. Rows with either missing are
        dropped, since they cannot contribute to bandwidth metrics.
        """
        if df.empty:
            return df

        df = df.rename(columns=self._COL_MAP)

        # Coerce packet_length
        if "packet_length" in df.columns:
            df["packet_length"] = pd.to_numeric(df["packet_length"], errors="coerce")

        # Parse timestamp
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(
                df["timestamp"], errors="coerce", utc=True
            )

        # Drop rows without timestamp or size
        required = [c for c in ["timestamp", "packet_length"] if c in df.columns]
        before = len(df)
        df = df.dropna(subset=required)
        dropped = before - len(df)
        if dropped:
            log.debug("Dropped %d rows with invalid timestamp/packet_length.", dropped)

        return df.sort_values("timestamp").reset_index(drop=True)

    # ── Core Bandwidth Calculations ───────────────────────────────────────────

    def calculate_bandwidth(self) -> BandwidthMetrics:
        """
        Compute aggregate bandwidth metrics.

        Returns:
            :class:`BandwidthMetrics` with totals and averages.
        """
        self._assert_loaded()
        df = self._df

        if df.empty or "packet_length" not in df.columns:
            return BandwidthMetrics()

        total_bytes = int(df["packet_length"].sum())
        total_packets = len(df)

        duration_sec = 0.0
        capture_start = ""
        capture_end = ""

        if "timestamp" in df.columns and not df["timestamp"].empty:
            t_start = df["timestamp"].min()
            t_end = df["timestamp"].max()
            duration_sec = (t_end - t_start).total_seconds()
            capture_start = str(t_start)
            capture_end = str(t_end)

        # Average rates
        avg_bps = round(total_bytes / duration_sec, 4) if duration_sec > 0 else 0.0
        avg_pps = round(total_packets / duration_sec, 4) if duration_sec > 0 else 0.0

        # Peak: use per-second aggregation
        peak_bps = 0.0
        peak_pps = 0.0
        if "timestamp" in df.columns:
            per_sec = self._aggregate_by_interval(freq="1s")
            if not per_sec.empty:
                peak_bps = float(per_sec["bytes_per_second"].max())
                peak_pps = float(per_sec["packets_per_second"].max())

        # Utilisation: peak bytes/s as % of link capacity
        link_bytes_per_sec = self.link_speed_bps / 8.0
        utilisation_pct = (
            round(peak_bps / link_bytes_per_sec * 100, 4)
            if link_bytes_per_sec > 0 else 0.0
        )

        metrics = BandwidthMetrics(
            total_bytes=total_bytes,
            total_packets=total_packets,
            capture_duration_seconds=round(duration_sec, 4),
            avg_bytes_per_second=avg_bps,
            peak_bytes_per_second=round(peak_bps, 4),
            avg_packets_per_second=avg_pps,
            peak_packets_per_second=round(peak_pps, 4),
            bandwidth_utilisation_pct=min(utilisation_pct, 100.0),
            capture_start=capture_start,
            capture_end=capture_end,
        )
        log.debug(
            "BandwidthMetrics: avg_bps=%.2f, peak_bps=%.2f, util=%.2f%%",
            metrics.avg_bytes_per_second,
            metrics.peak_bytes_per_second,
            metrics.bandwidth_utilisation_pct,
        )
        return metrics

    def calculate_throughput(self) -> pd.DataFrame:
        """
        Return per-second throughput as a DataFrame.

        Columns: ``timestamp``, ``bytes_per_second``, ``packets_per_second``.

        Returns:
            DataFrame indexed by second-resolution timestamps.
        """
        self._assert_loaded()
        return self._aggregate_by_interval(freq="1s")

    # ── Timeline Analytics ────────────────────────────────────────────────────

    def traffic_timeline(self, freq: str = "1min") -> pd.DataFrame:
        """
        Aggregate traffic into time-bucketed intervals.

        Args:
            freq: Pandas offset alias — ``"1s"``, ``"1min"``, ``"5min"``,
                  ``"1h"``, etc.

        Returns:
            DataFrame with columns: ``timestamp``, ``bytes_transferred``,
            ``packets_transferred``, ``bytes_per_second``,
            ``packets_per_second``.
        """
        self._assert_loaded()
        return self._aggregate_by_interval(freq=freq)

    def peak_usage_periods(
        self, freq: str = "1min", top_n: Optional[int] = None
    ) -> list[IntervalStats]:
        """
        Identify the top-N busiest traffic intervals.

        Args:
            freq:  Aggregation frequency (default ``"1min"``).
            top_n: Override the instance top_n.

        Returns:
            List of :class:`IntervalStats` sorted by bytes descending.
        """
        self._assert_loaded()
        n = top_n or self.top_n
        df = self._aggregate_by_interval(freq=freq)
        if df.empty:
            return []

        top_df = df.nlargest(n, "bytes_transferred")
        intervals: list[IntervalStats] = []
        for _, row in top_df.iterrows():
            intervals.append(
                IntervalStats(
                    timestamp=str(row["timestamp"]),
                    bytes_transferred=int(row["bytes_transferred"]),
                    packets_transferred=int(row["packets_transferred"]),
                    bytes_per_second=float(row["bytes_per_second"]),
                    packets_per_second=float(row["packets_per_second"]),
                )
            )
        log.debug("Peak usage periods: found %d intervals.", len(intervals))
        return intervals

    # ── Report Generation ─────────────────────────────────────────────────────

    def generate_bandwidth_report(self) -> BandwidthReport:
        """
        Generate a complete :class:`BandwidthReport`.

        Computes:
        - Aggregate metrics
        - Per-minute timeline
        - Per-second throughput
        - Top-N busiest intervals

        Returns:
            Populated :class:`BandwidthReport`.
        """
        self._assert_loaded()
        log.info("Generating bandwidth report…")

        metrics = self.calculate_bandwidth()
        per_min_df = self.traffic_timeline(freq="1min")
        per_sec_df = self.traffic_timeline(freq="1s")
        top_intervals = self.peak_usage_periods()

        # Convert DataFrames to lists of IntervalStats
        def _df_to_intervals(df: pd.DataFrame) -> list[IntervalStats]:
            out: list[IntervalStats] = []
            for row in df.itertuples(index=False):
                out.append(
                    IntervalStats(
                        timestamp=str(row.timestamp),
                        bytes_transferred=int(row.bytes_transferred),
                        packets_transferred=int(row.packets_transferred),
                        bytes_per_second=float(row.bytes_per_second),
                        packets_per_second=float(row.packets_per_second),
                    )
                )
            return out

        report = BandwidthReport(
            metrics=metrics,
            per_minute=_df_to_intervals(per_min_df),
            per_second=_df_to_intervals(per_sec_df),
            top_intervals=top_intervals,
            per_minute_df=per_min_df,
            per_second_df=per_sec_df,
        )
        log.info(
            "Bandwidth report: total_bytes=%d, avg_bps=%.2f, peak_bps=%.2f",
            metrics.total_bytes,
            metrics.avg_bytes_per_second,
            metrics.peak_bytes_per_second,
        )
        return report

    # ── Visualization Helpers ─────────────────────────────────────────────────

    def get_bar_chart_data(
        self, metric: str = "bytes_per_minute", top_n: Optional[int] = None
    ) -> dict[str, list]:
        """
        Return label/value pairs for a bar chart of top intervals.

        Args:
            metric: ``"bytes_per_minute"`` | ``"packets_per_minute"``.
            top_n:  Number of top bars to return.

        Returns:
            ``{"labels": [...], "values": [...]}``
        """
        self._assert_loaded()
        n = top_n or self.top_n
        df = self._aggregate_by_interval(freq="1min")
        if df.empty:
            return {"labels": [], "values": []}

        val_col = (
            "bytes_transferred" if "bytes" in metric else "packets_transferred"
        )
        top = df.nlargest(n, val_col)
        return {
            "labels": [str(ts) for ts in top["timestamp"].tolist()],
            "values": top[val_col].tolist(),
        }

    def get_pie_chart_data(
        self, metric: str = "protocol_bytes"
    ) -> dict[str, list]:
        """
        Return label/value pairs suitable for a pie chart.

        Args:
            metric: ``"protocol_bytes"`` — bytes per protocol.

        Returns:
            ``{"labels": [...], "values": [...]}``
        """
        self._assert_loaded()

        if "protocol" not in self._df.columns or "packet_length" not in self._df.columns:
            return {"labels": [], "values": []}

        dist = (
            self._df.groupby("protocol")["packet_length"]
            .sum()
            .sort_values(ascending=False)
        )
        return {
            "labels": dist.index.tolist(),
            "values": dist.values.tolist(),
        }

    def get_line_chart_data(
        self, metric: str = "bytes_per_minute"
    ) -> dict[str, list]:
        """
        Return time-series data for a line chart.

        Args:
            metric: ``"bytes_per_minute"`` | ``"packets_per_minute"``
                    | ``"bytes_per_second"`` | ``"packets_per_second"``.

        Returns:
            ``{"labels": [...], "values": [...]}``
        """
        self._assert_loaded()

        if "second" in metric:
            df = self._aggregate_by_interval(freq="1s")
            val_col = (
                "bytes_per_second" if "bytes" in metric else "packets_per_second"
            )
        else:
            df = self._aggregate_by_interval(freq="1min")
            val_col = (
                "bytes_per_second" if "bytes" in metric else "packets_per_second"
            )

        if df.empty:
            return {"labels": [], "values": []}

        return {
            "labels": [str(ts) for ts in df["timestamp"].tolist()],
            "values": df[val_col].round(4).tolist(),
        }

    # ── Report Dictionary ─────────────────────────────────────────────────────

    def to_report_dict(self) -> dict[str, Any]:
        """
        Return a flat dictionary of all bandwidth metrics.

        Returns:
            Dictionary compatible with JSON serialisation.
        """
        self._assert_loaded()
        report = self.generate_bandwidth_report()
        m = report.metrics
        return {
            "total_bytes": m.total_bytes,
            "total_packets": m.total_packets,
            "capture_duration_seconds": m.capture_duration_seconds,
            "avg_bytes_per_second": m.avg_bytes_per_second,
            "peak_bytes_per_second": m.peak_bytes_per_second,
            "avg_packets_per_second": m.avg_packets_per_second,
            "peak_packets_per_second": m.peak_packets_per_second,
            "bandwidth_utilisation_pct": m.bandwidth_utilisation_pct,
            "capture_start": m.capture_start,
            "capture_end": m.capture_end,
            "top_intervals": [
                {
                    "timestamp": iv.timestamp,
                    "bytes": iv.bytes_transferred,
                    "packets": iv.packets_transferred,
                    "bps": iv.bytes_per_second,
                    "pps": iv.packets_per_second,
                }
                for iv in report.top_intervals
            ],
        }

    # ── Phase 1 Live-Capture API (Preserved) ──────────────────────────────────

    def record(
        self,
        bytes_count: int,
        packet_count: int,
        interface: str = "unknown",
    ) -> BandwidthSample:
        """
        Record a live bandwidth sample into the ring buffer.

        This method is retained from Phase 1 for integration with the
        live-capture pipeline. Each call appends one :class:`BandwidthSample`
        to ``self.samples`` (bounded by ``window_size``).

        Args:
            bytes_count:   Bytes observed in the last sampling interval.
            packet_count:  Packets observed in the last sampling interval.
            interface:     Network interface name.

        Returns:
            The :class:`BandwidthSample` appended to the ring buffer.
        """
        link_bytes_per_sec = self.link_speed_bps / 8.0
        utilisation_pct = (
            min(bytes_count / link_bytes_per_sec * 100.0, 100.0)
            if link_bytes_per_sec > 0
            else 0.0
        )

        sample = BandwidthSample(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            bytes_per_second=float(bytes_count),
            packets_per_second=float(packet_count),
            utilisation_pct=round(utilisation_pct, 4),
            interface=interface,
        )
        self.samples.append(sample)

        # Track peak
        if sample.bytes_per_second > self.peak_bytes_per_second:
            self.peak_bytes_per_second = sample.bytes_per_second

        log.debug(
            "Live sample: %.0f B/s | %.0f pps | util=%.2f%%",
            sample.bytes_per_second,
            sample.packets_per_second,
            sample.utilisation_pct,
        )
        return sample

    def current_utilisation(self) -> float:
        """
        Return the most recent link utilisation percentage (0.0–100.0).

        Returns:
            Utilisation %, or 0.0 if no samples recorded.
        """
        if not self.samples:
            return 0.0
        return self.samples[-1].utilisation_pct

    def average_bps(self, last_n: Optional[int] = None) -> float:
        """
        Compute mean bytes-per-second over the last ``n`` live samples.

        Args:
            last_n: Number of recent samples to average (None = all).

        Returns:
            Mean Bps as a float.
        """
        data = list(self.samples)[-last_n:] if last_n else list(self.samples)
        if not data:
            return 0.0
        return sum(s.bytes_per_second for s in data) / len(data)

    def reset(self) -> None:
        """Clear live samples and reset peak counter."""
        self.samples.clear()
        self.peak_bytes_per_second = 0.0
        log.debug("BandwidthMonitor ring-buffer reset.")

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _assert_loaded(self) -> None:
        """Raise RuntimeError if load_data() has not been called."""
        if self._df is None:
            raise RuntimeError(
                "Data not loaded. Call load_data() first."
            )

    def _aggregate_by_interval(self, freq: str = "1min") -> pd.DataFrame:
        """
        Resample packet data into regular time intervals.

        Args:
            freq: Pandas offset alias (``"1s"``, ``"1min"``, ``"5min"``…).

        Returns:
            DataFrame with columns: timestamp, bytes_transferred,
            packets_transferred, bytes_per_second, packets_per_second.
        """
        if self._df is None or self._df.empty:
            return pd.DataFrame()

        if "timestamp" not in self._df.columns or "packet_length" not in self._df.columns:
            return pd.DataFrame()

        df = self._df.set_index("timestamp").sort_index()

        agg = df["packet_length"].resample(freq).agg(
            bytes_transferred="sum",
            packets_transferred="count",
        ).reset_index()

        # Compute per-second rates based on freq duration
        freq_seconds = self._freq_to_seconds(freq)
        if freq_seconds > 0:
            agg["bytes_per_second"] = (
                agg["bytes_transferred"] / freq_seconds
            ).round(4)
            agg["packets_per_second"] = (
                agg["packets_transferred"] / freq_seconds
            ).round(4)
        else:
            agg["bytes_per_second"] = agg["bytes_transferred"]
            agg["packets_per_second"] = agg["packets_transferred"]

        agg = agg.rename(columns={"timestamp": "timestamp"})
        agg = agg[agg["packets_transferred"] > 0]
        agg["bytes_transferred"] = agg["bytes_transferred"].astype(int)
        agg["packets_transferred"] = agg["packets_transferred"].astype(int)
        agg["timestamp"] = agg["timestamp"].astype(str)

        return agg

    @staticmethod
    def _freq_to_seconds(freq: str) -> float:
        """
        Convert a Pandas frequency string to seconds.

        Handles common aliases: ``"1s"``, ``"1min"``, ``"5min"``,
        ``"1h"``, ``"T"`` (minute), ``"S"`` (second).
        """
        freq = freq.strip()
        aliases: dict[str, float] = {
            "s": 1.0,
            "sec": 1.0,
            "min": 60.0,
            "t": 60.0,       # legacy minute alias
            "h": 3600.0,
            "hr": 3600.0,
        }
        # Parse leading number
        import re
        m = re.match(r"^(\d+)?\s*([a-zA-Z]+)$", freq)
        if m:
            multiplier = int(m.group(1)) if m.group(1) else 1
            unit = m.group(2).lower()
            factor = aliases.get(unit, 1.0)
            return multiplier * factor
        return 60.0  # fallback: 1 minute
