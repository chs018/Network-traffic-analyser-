"""
traffic_statistics.py — Traffic Aggregate Statistics Engine
============================================================
Network Traffic Analysis and Intrusion Detection System

Computes comprehensive statistical summaries over captured traffic records:
  - Total packet and byte counts
  - Unique IP address analysis
  - Packet size distribution (avg, min, max, median, std-dev)
  - Capture duration, packets-per-second, bytes-per-second
  - Top-N source and destination IPs
  - Chart-ready output for Plotly / Streamlit

Data Sources:
    - CSV mode: data/processed/packets.csv
    - SQLite mode: traffic_logs table (via DatabaseManager)

Classes:
    BasicStats          — Dataclass: raw numerical summaries
    IPStatistics        — Dataclass: per-IP packet counts
    PacketStatistics    — Dataclass: size distribution metrics
    TrafficSummary      — Dataclass: master aggregated result
    TrafficStatistics   — Computation engine (Phase 3, fully implemented)

Author: Network Traffic Analyzer Project
Version: 3.0.0
Python: 3.11+
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import numpy as np

from utils.config import config
from utils.logger import get_analysis_logger

log = get_analysis_logger()

# Suppress copy-on-write warnings where applicable (pandas version-safe)
warnings.filterwarnings("ignore", message=".*SettingWithCopyWarning.*")


# ──────────────────────────────────────────────────────────────────────────────
# DATACLASSES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class BasicStats:
    """Raw numerical traffic counters."""

    total_packets: int = 0
    total_bytes: int = 0
    capture_duration_seconds: float = 0.0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    capture_start: str = ""
    capture_end: str = ""


@dataclass
class IPStatistics:
    """Unique IP counts and top-talker rankings."""

    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    top_src_ips: list[tuple[str, int]] = field(default_factory=list)
    top_dst_ips: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class PacketStatistics:
    """Packet size distribution metrics."""

    avg_packet_size: float = 0.0
    min_packet_size: int = 0
    max_packet_size: int = 0
    median_packet_size: float = 0.0
    std_packet_size: float = 0.0


@dataclass
class TrafficSummary:
    """
    Master aggregated statistics produced by :class:`TrafficStatistics`.

    Combines all sub-statistics into a single, reportable structure.
    """

    basic: BasicStats = field(default_factory=BasicStats)
    ip: IPStatistics = field(default_factory=IPStatistics)
    packets: PacketStatistics = field(default_factory=PacketStatistics)
    protocol_distribution: dict[str, int] = field(default_factory=dict)
    packet_timeline: dict[str, int] = field(default_factory=dict)
    byte_timeline: dict[str, int] = field(default_factory=dict)

    # Flattened convenience accessors (populated by generate_summary())
    total_packets: int = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    avg_packet_size: float = 0.0
    top_source_ips: list[tuple[str, int]] = field(default_factory=list)
    top_destination_ips: list[tuple[str, int]] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────────
# TRAFFIC STATISTICS ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class TrafficStatistics:
    """
    Phase 3 Traffic Analytics Engine.

    Loads packet data from CSV or SQLite and computes comprehensive
    network traffic statistics using vectorised Pandas operations.

    Designed to be called by the Streamlit dashboard refresh loop and
    the Phase 3 test harness (test_phase3.py).

    Attributes:
        top_n (int):          Number of top items in ranked lists.
        csv_path (Path):      Resolved path to packets.csv.
        _df (DataFrame|None): Loaded and cleaned DataFrame (internal).

    Usage::

        ts = TrafficStatistics(top_n=10)
        ts.load_data()                         # CSV mode (default)
        summary = ts.generate_summary()
        bar_data = ts.get_bar_chart_data("top_src_ips")
    """

    # Columns expected (minimum) from packets.csv / traffic_logs
    _REQUIRED_COLS: tuple[str, ...] = (
        "timestamp",
        "packet_length",
    )

    # Column aliases: CSV column → canonical name used internally
    _COL_MAP: dict[str, str] = {
        "source_ip": "src_ip",
        "destination_ip": "dst_ip",
        "source_port": "src_port",
        "destination_port": "dst_port",
    }

    def __init__(
        self,
        top_n: int = 10,
        csv_path: Optional[Path] = None,
    ) -> None:
        """
        Initialise the TrafficStatistics engine.

        Args:
            top_n:    Number of items in top-N ranked lists (default 10).
            csv_path: Override path to packets.csv. Defaults to
                      ``config.paths.processed_data_dir / "packets.csv"``.
        """
        self.top_n: int = top_n
        self.csv_path: Path = csv_path or (
            config.paths.processed_data_dir / "packets.csv"
        )
        self._df: Optional[pd.DataFrame] = None

        log.debug(
            "TrafficStatistics initialised (top_n=%d, csv=%s).",
            top_n, self.csv_path,
        )

    # ── Data Loading ──────────────────────────────────────────────────────────

    def load_data(
        self,
        source: str = "csv",
        db_manager=None,
        limit: int = 100_000,
    ) -> pd.DataFrame:
        """
        Load traffic data from CSV or SQLite into an internal DataFrame.

        Args:
            source:     ``"csv"`` (default) or ``"db"``.
            db_manager: A :class:`~database.db_manager.DatabaseManager`
                        instance (required when ``source="db"``).
            limit:      Maximum rows to load from DB (ignored for CSV).

        Returns:
            The cleaned DataFrame (also stored as ``self._df``).

        Raises:
            FileNotFoundError: If packets.csv does not exist.
            ValueError:        If an unknown source is specified.
        """
        if source == "csv":
            self._df = self._load_from_csv()
        elif source == "db":
            if db_manager is None:
                raise ValueError("db_manager is required when source='db'.")
            self._df = self._load_from_db(db_manager, limit)
        else:
            raise ValueError(f"Unknown data source: '{source}'. Use 'csv' or 'db'.")

        self._df = self._clean_dataframe(self._df)
        log.info(
            "Loaded %d traffic records from '%s'.", len(self._df), source
        )
        return self._df

    def _load_from_csv(self) -> pd.DataFrame:
        """Read packets.csv from disk."""
        if not self.csv_path.exists():
            raise FileNotFoundError(
                f"packets.csv not found at: {self.csv_path}\n"
                "Run the Phase 2 pipeline first to generate this file."
            )
        log.debug("Reading CSV: %s", self.csv_path)
        df = pd.read_csv(
            self.csv_path,
            low_memory=False,
        )
        return df

    def _load_from_db(self, db_manager, limit: int) -> pd.DataFrame:
        """Fetch traffic records from SQLite via DatabaseManager."""
        log.debug("Loading from DB (limit=%d).", limit)
        rows = db_manager.fetch_recent_traffic(limit=limit)
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame(rows)

    def _clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalise, rename, and coerce columns to expected dtypes.

        Steps:
          1. Rename CSV column aliases → canonical names
          2. Coerce ``timestamp`` → datetime
          3. Coerce ``packet_length`` → numeric
          4. Drop rows with unusable core fields
          5. Remove duplicate packets

        Returns:
            Cleaned DataFrame.
        """
        if df.empty:
            log.warning("Empty DataFrame received — skipping cleaning.")
            return df

        # Step 1: rename aliases
        df = df.rename(columns=self._COL_MAP)

        # Step 2: parse timestamp
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(
                df["timestamp"], errors="coerce", utc=True
            )
        else:
            log.warning("No 'timestamp' column found in data.")

        # Step 3: numeric coercion
        numeric_cols = [
            "packet_length", "src_port", "dst_port", "ttl",
            "protocol_num", "window_size",
        ]
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        # Step 4: drop rows where packet_length is missing
        before = len(df)
        df = df.dropna(subset=["packet_length"])
        dropped = before - len(df)
        if dropped:
            log.debug("Dropped %d rows with missing packet_length.", dropped)

        # Step 5: drop exact duplicates (keep first)
        before = len(df)
        df = df.drop_duplicates()
        dupes = before - len(df)
        if dupes:
            log.debug("Removed %d duplicate rows.", dupes)

        return df.reset_index(drop=True)

    # ── Core Metrics ──────────────────────────────────────────────────────────

    def calculate_basic_stats(self) -> BasicStats:
        """
        Compute fundamental counters and rate metrics.

        Returns:
            :class:`BasicStats` populated with totals and rates.

        Raises:
            RuntimeError: If data has not been loaded.
        """
        self._assert_loaded()
        df = self._df

        total_packets = len(df)
        total_bytes = int(df["packet_length"].sum())

        # Capture window
        capture_start = ""
        capture_end = ""
        duration_sec = 0.0
        pps = 0.0
        bps = 0.0

        if "timestamp" in df.columns and df["timestamp"].notna().any():
            ts_valid = df["timestamp"].dropna()
            t_start = ts_valid.min()
            t_end = ts_valid.max()
            capture_start = str(t_start)
            capture_end = str(t_end)
            duration_sec = (t_end - t_start).total_seconds()
            if duration_sec > 0:
                pps = round(total_packets / duration_sec, 4)
                bps = round(total_bytes / duration_sec, 4)

        stats = BasicStats(
            total_packets=total_packets,
            total_bytes=total_bytes,
            capture_duration_seconds=round(duration_sec, 4),
            packets_per_second=pps,
            bytes_per_second=bps,
            capture_start=capture_start,
            capture_end=capture_end,
        )
        log.debug(
            "BasicStats: packets=%d, bytes=%d, pps=%.2f, bps=%.2f",
            total_packets, total_bytes, pps, bps,
        )
        return stats

    def calculate_ip_statistics(self) -> IPStatistics:
        """
        Compute unique IP counts and top-N talker rankings.

        Returns:
            :class:`IPStatistics` with unique counts and ranked lists.
        """
        self._assert_loaded()
        df = self._df

        src_col = "src_ip" if "src_ip" in df.columns else None
        dst_col = "dst_ip" if "dst_ip" in df.columns else None

        unique_src = 0
        unique_dst = 0
        top_src: list[tuple[str, int]] = []
        top_dst: list[tuple[str, int]] = []

        if src_col:
            src_series = df[src_col].dropna()
            unique_src = src_series.nunique()
            top_src = (
                src_series
                .value_counts()
                .head(self.top_n)
                .reset_index()
                .values.tolist()
            )
            # Ensure tuples of (str, int)
            top_src = [(str(ip), int(cnt)) for ip, cnt in top_src]

        if dst_col:
            dst_series = df[dst_col].dropna()
            unique_dst = dst_series.nunique()
            top_dst = (
                dst_series
                .value_counts()
                .head(self.top_n)
                .reset_index()
                .values.tolist()
            )
            top_dst = [(str(ip), int(cnt)) for ip, cnt in top_dst]

        ip_stats = IPStatistics(
            unique_src_ips=unique_src,
            unique_dst_ips=unique_dst,
            top_src_ips=top_src,
            top_dst_ips=top_dst,
        )
        log.debug(
            "IPStatistics: unique_src=%d, unique_dst=%d.",
            unique_src, unique_dst,
        )
        return ip_stats

    def calculate_packet_statistics(self) -> PacketStatistics:
        """
        Compute packet size distribution metrics.

        Returns:
            :class:`PacketStatistics` with size distribution values.
        """
        self._assert_loaded()
        sizes = self._df["packet_length"].dropna()

        if sizes.empty:
            return PacketStatistics()

        pkt_stats = PacketStatistics(
            avg_packet_size=round(float(sizes.mean()), 2),
            min_packet_size=int(sizes.min()),
            max_packet_size=int(sizes.max()),
            median_packet_size=round(float(sizes.median()), 2),
            std_packet_size=round(float(sizes.std()), 2),
        )
        log.debug(
            "PacketStatistics: avg=%.1f, min=%d, max=%d, median=%.1f, std=%.2f",
            pkt_stats.avg_packet_size, pkt_stats.min_packet_size,
            pkt_stats.max_packet_size, pkt_stats.median_packet_size,
            pkt_stats.std_packet_size,
        )
        return pkt_stats

    def generate_summary(self) -> TrafficSummary:
        """
        Generate a complete :class:`TrafficSummary` from loaded data.

        Calls all sub-calculators and assembles a single, reportable
        object with both nested sub-stats and flattened convenience fields.

        Returns:
            Populated :class:`TrafficSummary`.
        """
        self._assert_loaded()
        log.info("Generating traffic summary…")

        basic = self.calculate_basic_stats()
        ip = self.calculate_ip_statistics()
        packets = self.calculate_packet_statistics()

        # Protocol distribution
        proto_dist: dict[str, int] = {}
        if "protocol" in self._df.columns:
            proto_dist = (
                self._df["protocol"]
                .dropna()
                .value_counts()
                .astype(int)
                .to_dict()
            )

        # Time-bucketed timelines (1-minute buckets)
        packet_timeline: dict[str, int] = {}
        byte_timeline: dict[str, int] = {}
        if (
            "timestamp" in self._df.columns
            and self._df["timestamp"].notna().any()
        ):
            df_ts = self._df[self._df["timestamp"].notna()].copy()
            df_ts = df_ts.set_index("timestamp").sort_index()
            packet_timeline = (
                df_ts["packet_length"]
                .resample("1min")
                .count()
                .astype(int)
                .to_dict()
            )
            packet_timeline = {str(k): int(v) for k, v in packet_timeline.items()}
            byte_timeline = (
                df_ts["packet_length"]
                .resample("1min")
                .sum()
                .astype(int)
                .to_dict()
            )
            byte_timeline = {str(k): int(v) for k, v in byte_timeline.items()}

        summary = TrafficSummary(
            basic=basic,
            ip=ip,
            packets=packets,
            protocol_distribution=proto_dist,
            packet_timeline=packet_timeline,
            byte_timeline=byte_timeline,
            # Flattened aliases
            total_packets=basic.total_packets,
            unique_src_ips=ip.unique_src_ips,
            unique_dst_ips=ip.unique_dst_ips,
            avg_packet_size=packets.avg_packet_size,
            top_source_ips=ip.top_src_ips,
            top_destination_ips=ip.top_dst_ips,
        )
        log.info(
            "Summary complete: %d packets | %d src IPs | %d dst IPs.",
            summary.total_packets,
            summary.unique_src_ips,
            summary.unique_dst_ips,
        )
        return summary

    # ── Visualization Helpers ─────────────────────────────────────────────────

    def get_bar_chart_data(
        self, metric: str = "top_src_ips", top_n: Optional[int] = None
    ) -> dict[str, list]:
        """
        Return label/value pairs for a bar chart.

        Args:
            metric: One of ``"top_src_ips"``, ``"top_dst_ips"``,
                    ``"protocol_distribution"``.
            top_n:  Override top-N limit for this call.

        Returns:
            ``{"labels": [...], "values": [...]}``
        """
        self._assert_loaded()
        n = top_n or self.top_n

        if metric == "top_src_ips":
            col = "src_ip" if "src_ip" in self._df.columns else None
            return self._top_n_chart_data(col, n)
        elif metric == "top_dst_ips":
            col = "dst_ip" if "dst_ip" in self._df.columns else None
            return self._top_n_chart_data(col, n)
        elif metric == "protocol_distribution":
            col = "protocol" if "protocol" in self._df.columns else None
            return self._top_n_chart_data(col, n)
        else:
            log.warning("Unknown bar chart metric: '%s'.", metric)
            return {"labels": [], "values": []}

    def get_pie_chart_data(
        self, metric: str = "protocol_distribution"
    ) -> dict[str, list]:
        """
        Return label/value pairs for a pie chart.

        Args:
            metric: Currently supports ``"protocol_distribution"`` and
                    ``"packet_size_category"`` (if column present).

        Returns:
            ``{"labels": [...], "values": [...]}``
        """
        self._assert_loaded()

        col_map = {
            "protocol_distribution": "protocol",
            "packet_size_category": "packet_size_category",
            "transport_layer": "transport_layer",
        }
        col = col_map.get(metric)
        if col is None or col not in self._df.columns:
            log.warning("Column not available for pie chart metric: '%s'.", metric)
            return {"labels": [], "values": []}

        series = self._df[col].dropna().value_counts()
        return {
            "labels": series.index.tolist(),
            "values": series.values.tolist(),
        }

    def get_line_chart_data(
        self, metric: str = "packet_timeline"
    ) -> dict[str, list]:
        """
        Return time-series label/value pairs for a line chart.

        Args:
            metric: ``"packet_timeline"`` or ``"byte_timeline"``.

        Returns:
            ``{"labels": [...], "values": [...]}`` where labels are
            ISO-8601 timestamp strings and values are counts/bytes.
        """
        self._assert_loaded()

        if "timestamp" not in self._df.columns or not self._df["timestamp"].notna().any():
            return {"labels": [], "values": []}

        df_ts = self._df[self._df["timestamp"].notna()].copy()
        df_ts = df_ts.set_index("timestamp").sort_index()

        if metric == "byte_timeline":
            series = df_ts["packet_length"].resample("1min").sum()
        else:  # packet_timeline
            series = df_ts["packet_length"].resample("1min").count()

        return {
            "labels": [str(ts) for ts in series.index.tolist()],
            "values": series.astype(int).tolist(),
        }

    def get_dataframe(self) -> pd.DataFrame:
        """Return the internal cleaned DataFrame (for dashboard integration)."""
        self._assert_loaded()
        return self._df.copy()

    # ── Report Generation ─────────────────────────────────────────────────────

    def to_report_dict(self) -> dict[str, Any]:
        """
        Generate a structured traffic summary report dictionary.

        Returns:
            A flat dictionary with all key metrics, suitable for JSON
            serialisation or dashboard display.

        Example::

            {
                "total_packets": 1000,
                "unique_src_ips": 20,
                "avg_packet_size": 468.7,
                "top_source_ips": [("192.168.1.16", 48), ...],
                ...
            }
        """
        self._assert_loaded()
        summary = self.generate_summary()

        return {
            # Basic
            "total_packets": summary.basic.total_packets,
            "total_bytes": summary.basic.total_bytes,
            "capture_duration_seconds": summary.basic.capture_duration_seconds,
            "packets_per_second": summary.basic.packets_per_second,
            "bytes_per_second": summary.basic.bytes_per_second,
            "capture_start": summary.basic.capture_start,
            "capture_end": summary.basic.capture_end,
            # IPs
            "unique_src_ips": summary.ip.unique_src_ips,
            "unique_dst_ips": summary.ip.unique_dst_ips,
            "top_source_ips": summary.ip.top_src_ips,
            "top_destination_ips": summary.ip.top_dst_ips,
            # Packet sizes
            "avg_packet_size": summary.packets.avg_packet_size,
            "min_packet_size": summary.packets.min_packet_size,
            "max_packet_size": summary.packets.max_packet_size,
            "median_packet_size": summary.packets.median_packet_size,
            "std_packet_size": summary.packets.std_packet_size,
            # Protocols
            "protocol_distribution": summary.protocol_distribution,
        }

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _assert_loaded(self) -> None:
        """Raise RuntimeError if data has not been loaded."""
        if self._df is None:
            raise RuntimeError(
                "Data not loaded. Call load_data() first."
            )

    def _top_n_chart_data(
        self, col: Optional[str], n: int
    ) -> dict[str, list]:
        """Build bar/pie chart data from a single categorical column."""
        if col is None or col not in self._df.columns:
            return {"labels": [], "values": []}
        series = self._df[col].dropna().value_counts().head(n)
        return {
            "labels": [str(x) for x in series.index.tolist()],
            "values": series.values.tolist(),
        }
