"""
protocol_analysis.py — Protocol Distribution Analyser
======================================================
Network Traffic Analysis and Intrusion Detection System

Analyses the protocol composition of captured network traffic:
  - Transport layer distribution (TCP / UDP / ICMP / ARP / Other)
  - Application layer hints (HTTP / HTTPS / DNS / NTP / …)
  - Network-layer protocol breakdown
  - Protocol ranking table
  - Protocol usage trends over time
  - Malformed packet normalisation (_WS.MALFORMED → MALFORMED)

Data Sources:
    - CSV mode: data/processed/packets.csv
    - SQLite mode: traffic_logs table (via DatabaseManager)

Classes:
    ProtocolEntry    — Dataclass: per-protocol metrics
    ProtocolStats    — Dataclass: per-protocol statistics (legacy compat)
    ProtocolReport   — Dataclass: full analysis result
    ProtocolAnalysis — Main analysis class (Phase 3, fully implemented)

Note:
    The existing Phase 1 ``ProtocolAnalyzer`` stub is kept for backward
    compatibility with the ``analysis/__init__.py`` public API. The new
    ``ProtocolAnalysis`` class is the full Phase 3 implementation.

Author: Network Traffic Analyzer Project
Version: 3.0.0
Python: 3.11+
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import numpy as np

from utils.config import config
from utils.logger import get_analysis_logger

log = get_analysis_logger()


# ──────────────────────────────────────────────────────────────────────────────
# PROTOCOL NORMALISATION MAP
# ──────────────────────────────────────────────────────────────────────────────

# Any protocol token matching these patterns is normalised to the canonical form.
_MALFORMED_PATTERN = re.compile(r"_WS\.MALFORMED|MALFORMED", re.IGNORECASE)

# Application-layer port → protocol hint
_PORT_PROTOCOL_MAP: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP",
    443: "HTTPS",
    445: "SMB",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

# Transport layer canonical names
_TRANSPORT_PROTOCOLS: frozenset[str] = frozenset({"TCP", "UDP", "ICMP", "ARP"})


# ──────────────────────────────────────────────────────────────────────────────
# DATACLASSES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ProtocolEntry:
    """Metrics for a single normalised protocol."""

    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    percentage: float = 0.0          # % of total packets
    byte_percentage: float = 0.0     # % of total bytes
    avg_packet_size: float = 0.0
    rank: int = 0                     # 1 = highest volume


@dataclass
class ProtocolStats:
    """
    Per-protocol statistics (retained for Phase 1 API compatibility).

    The Phase 3 preferred dataclass is :class:`ProtocolEntry`.
    """

    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    percentage: float = 0.0
    avg_packet_size: float = 0.0
    unique_src_ips: int = 0
    unique_dst_ports: int = 0
    is_anomalous: bool = False
    anomaly_reason: str = ""


@dataclass
class ProtocolReport:
    """Full protocol analysis result returned by :meth:`generate_protocol_report`."""

    # Aggregate counts
    total_packets: int = 0
    total_protocols: int = 0

    # Distribution tables
    all_protocols: list[ProtocolEntry] = field(default_factory=list)
    transport_distribution: dict[str, int] = field(default_factory=dict)
    application_distribution: dict[str, int] = field(default_factory=dict)

    # Key percentages
    tcp_pct: float = 0.0
    udp_pct: float = 0.0
    icmp_pct: float = 0.0
    arp_pct: float = 0.0
    http_pct: float = 0.0
    https_pct: float = 0.0
    dns_pct: float = 0.0
    ntp_pct: float = 0.0
    malformed_pct: float = 0.0
    unknown_pct: float = 0.0

    # Ranked top protocols
    top_protocols: list[ProtocolEntry] = field(default_factory=list)

    # DataFrame-ready summary table
    summary_df: Optional[pd.DataFrame] = None


# ──────────────────────────────────────────────────────────────────────────────
# PROTOCOL ANALYSIS ENGINE  (Phase 3 Implementation)
# ──────────────────────────────────────────────────────────────────────────────

class ProtocolAnalysis:
    """
    Phase 3 Protocol Analytics Engine.

    Loads packet data and breaks down traffic by network, transport,
    and application-layer protocols using vectorised Pandas operations.

    Usage::

        pa = ProtocolAnalysis(top_n=10)
        pa.load_data()                        # CSV mode (default)
        report = pa.generate_protocol_report()
        pie_data = pa.get_pie_chart_data("transport")
    """

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
        Initialise the ProtocolAnalysis engine.

        Args:
            top_n:    Number of top protocols to highlight.
            csv_path: Override path to packets.csv.
        """
        self.top_n: int = top_n
        self.csv_path: Path = csv_path or (
            config.paths.processed_data_dir / "packets.csv"
        )
        self._df: Optional[pd.DataFrame] = None
        log.debug("ProtocolAnalysis initialised (top_n=%d).", top_n)

    # ── Data Loading ──────────────────────────────────────────────────────────

    def load_data(
        self,
        source: str = "csv",
        db_manager=None,
        limit: int = 100_000,
    ) -> pd.DataFrame:
        """
        Load and clean traffic data.

        Args:
            source:     ``"csv"`` (default) or ``"db"``.
            db_manager: DatabaseManager (required for ``source="db"``).
            limit:      Max rows from DB.

        Returns:
            Cleaned DataFrame (also stored as ``self._df``).
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

        self._df = self._clean_and_normalise(df)
        log.info(
            "ProtocolAnalysis loaded %d records from '%s'.",
            len(self._df), source,
        )
        return self._df

    def _clean_and_normalise(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean DataFrame and normalise protocol names.

        - Renames column aliases
        - Normalises ``_WS.MALFORMED`` → ``MALFORMED``
        - Fills missing protocols with ``UNKNOWN``
        - Coerces numeric columns
        """
        if df.empty:
            return df

        df = df.rename(columns=self._COL_MAP)

        # Coerce numerics
        for col in ["packet_length", "src_port", "dst_port"]:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        # Normalise protocol column
        if "protocol" in df.columns:
            df["protocol"] = (
                df["protocol"]
                .fillna("UNKNOWN")
                .astype(str)
                .str.strip()
                .apply(self._normalise_protocol)
            )

        # Normalise transport_layer column (if present)
        if "transport_layer" in df.columns:
            df["transport_layer"] = (
                df["transport_layer"]
                .fillna("UNKNOWN")
                .astype(str)
                .str.strip()
                .apply(self._normalise_protocol)
            )

        # Drop rows with no packet_length (unusable)
        if "packet_length" in df.columns:
            df = df.dropna(subset=["packet_length"])

        return df.reset_index(drop=True)

    @staticmethod
    def _normalise_protocol(raw: str) -> str:
        """
        Normalise a raw protocol string to a clean canonical form.

        - ``_WS.MALFORMED`` → ``MALFORMED``
        - Strips leading/trailing whitespace and uppercases
        """
        stripped = raw.strip()
        if _MALFORMED_PATTERN.match(stripped):
            return "MALFORMED"
        return stripped.upper()

    # ── Analysis Methods ──────────────────────────────────────────────────────

    def protocol_distribution(self) -> dict[str, int]:
        """
        Compute packet counts per normalised protocol.

        Returns:
            ``{"TCP": 264, "UDP": 188, …}`` sorted by count descending.
        """
        self._assert_loaded()
        col = "protocol" if "protocol" in self._df.columns else None
        if col is None:
            log.warning("No 'protocol' column found.")
            return {}
        dist = (
            self._df[col]
            .value_counts()
            .astype(int)
            .to_dict()
        )
        log.debug("Protocol distribution computed: %d protocols.", len(dist))
        return dist

    def transport_layer_distribution(self) -> dict[str, int]:
        """
        Compute TCP / UDP / ICMP / ARP breakdown.

        Uses the ``transport_layer`` column if present; otherwise falls
        back to filtering ``protocol`` for known transport names.

        Returns:
            ``{"TCP": 300, "UDP": 150, "ICMP": 50, "ARP": 10}``
        """
        self._assert_loaded()

        if "transport_layer" in self._df.columns:
            series = self._df["transport_layer"].dropna()
        elif "protocol" in self._df.columns:
            series = self._df["protocol"].where(
                self._df["protocol"].isin(_TRANSPORT_PROTOCOLS)
            ).dropna()
        else:
            return {}

        dist = series.value_counts().astype(int).to_dict()
        log.debug("Transport distribution: %s", dist)
        return dist

    def application_layer_distribution(self) -> dict[str, int]:
        """
        Infer application-layer protocol from destination port.

        Requires a ``dst_port`` column. Unmapped ports are labelled
        ``"OTHER"``.

        Returns:
            ``{"DNS": 66, "HTTP": 40, "HTTPS": 35, "OTHER": 59, …}``
        """
        self._assert_loaded()

        if "dst_port" not in self._df.columns:
            log.warning("No 'dst_port' column — cannot infer app layer.")
            return {}

        # Check if app_layer_hint column already exists
        if "app_layer_hint" in self._df.columns:
            series = self._df["app_layer_hint"].fillna("OTHER")
            dist = series.value_counts().astype(int).to_dict()
            log.debug("App-layer distribution from hint col: %d types.", len(dist))
            return dist

        # Map by port
        mapped = (
            self._df["dst_port"]
            .map(_PORT_PROTOCOL_MAP)
            .fillna("OTHER")
        )
        dist = mapped.value_counts().astype(int).to_dict()
        log.debug("App-layer distribution from port mapping: %d types.", len(dist))
        return dist

    def generate_protocol_report(self) -> ProtocolReport:
        """
        Generate a complete :class:`ProtocolReport`.

        Combines protocol distribution, transport breakdown, application
        breakdown, key percentages, and a ranked top-N list.

        Returns:
            Fully populated :class:`ProtocolReport`.
        """
        self._assert_loaded()
        log.info("Generating protocol report…")

        total = len(self._df)
        total_bytes = (
            int(self._df["packet_length"].sum())
            if "packet_length" in self._df.columns
            else 0
        )

        proto_dist = self.protocol_distribution()
        transport_dist = self.transport_layer_distribution()
        app_dist = self.application_layer_distribution()

        # Build per-protocol entries
        entries: list[ProtocolEntry] = []
        for rank, (proto, count) in enumerate(
            sorted(proto_dist.items(), key=lambda x: -x[1]), start=1
        ):
            if "packet_length" in self._df.columns:
                proto_df = self._df[self._df["protocol"] == proto]
                byte_count = int(proto_df["packet_length"].sum())
                avg_size = round(float(proto_df["packet_length"].mean()), 2)
            else:
                byte_count = 0
                avg_size = 0.0

            entries.append(
                ProtocolEntry(
                    protocol=proto,
                    packet_count=int(count),
                    byte_count=byte_count,
                    percentage=round(count / total * 100, 2) if total else 0.0,
                    byte_percentage=(
                        round(byte_count / total_bytes * 100, 2)
                        if total_bytes else 0.0
                    ),
                    avg_packet_size=avg_size,
                    rank=rank,
                )
            )

        # Key protocol percentages
        def _pct(names: list[str]) -> float:
            c = sum(proto_dist.get(n, 0) for n in names)
            return round(c / total * 100, 2) if total else 0.0

        # Build summary DataFrame
        if entries:
            summary_df = pd.DataFrame(
                [
                    {
                        "Rank": e.rank,
                        "Protocol": e.protocol,
                        "Packets": e.packet_count,
                        "Bytes": e.byte_count,
                        "Pct (%)": e.percentage,
                        "Avg Size (B)": e.avg_packet_size,
                    }
                    for e in entries
                ]
            )
        else:
            summary_df = pd.DataFrame()

        report = ProtocolReport(
            total_packets=total,
            total_protocols=len(proto_dist),
            all_protocols=entries,
            transport_distribution=transport_dist,
            application_distribution=app_dist,
            tcp_pct=_pct(["TCP"]),
            udp_pct=_pct(["UDP"]),
            icmp_pct=_pct(["ICMP"]),
            arp_pct=_pct(["ARP"]),
            http_pct=_pct(["HTTP", "HTTP-ALT"]),
            https_pct=_pct(["HTTPS", "HTTPS-ALT"]),
            dns_pct=_pct(["DNS"]),
            ntp_pct=_pct(["NTP"]),
            malformed_pct=_pct(["MALFORMED"]),
            unknown_pct=_pct(["UNKNOWN"]),
            top_protocols=entries[: self.top_n],
            summary_df=summary_df,
        )
        log.info(
            "Protocol report: %d protocols | TCP=%.1f%% UDP=%.1f%% ICMP=%.1f%%",
            report.total_protocols, report.tcp_pct, report.udp_pct, report.icmp_pct,
        )
        return report

    # ── Visualization Helpers ─────────────────────────────────────────────────

    def get_bar_chart_data(
        self, metric: str = "protocol_distribution", top_n: Optional[int] = None
    ) -> dict[str, list]:
        """
        Return label/value pairs for a bar chart.

        Args:
            metric: ``"protocol_distribution"`` | ``"transport_layer"``
                    | ``"application_layer"``.
            top_n:  Override the instance top_n for this call.

        Returns:
            ``{"labels": [...], "values": [...]}``
        """
        self._assert_loaded()
        n = top_n or self.top_n

        if metric == "transport_layer":
            dist = self.transport_layer_distribution()
        elif metric == "application_layer":
            dist = self.application_layer_distribution()
        else:
            dist = self.protocol_distribution()

        top = sorted(dist.items(), key=lambda x: -x[1])[:n]
        return {
            "labels": [p for p, _ in top],
            "values": [c for _, c in top],
        }

    def get_pie_chart_data(
        self, metric: str = "protocol_distribution"
    ) -> dict[str, list]:
        """
        Return label/value pairs for a pie chart.

        Args:
            metric: ``"protocol_distribution"`` | ``"transport_layer"``
                    | ``"application_layer"``.

        Returns:
            ``{"labels": [...], "values": [...]}``
        """
        return self.get_bar_chart_data(metric=metric, top_n=len(self._df) if self._df is not None else 0)

    def get_line_chart_data(
        self, protocol: Optional[str] = None
    ) -> dict[str, list]:
        """
        Return time-series packet counts for a single protocol (or all).

        Args:
            protocol: Filter to a specific protocol (e.g. ``"TCP"``).
                      If None, returns total packet counts per minute.

        Returns:
            ``{"labels": [...], "values": [...]}``
        """
        self._assert_loaded()

        if "timestamp" not in self._df.columns:
            return {"labels": [], "values": []}

        df = self._df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.dropna(subset=["timestamp"])

        if protocol:
            df = df[df["protocol"] == protocol.upper()]

        if df.empty:
            return {"labels": [], "values": []}

        series = (
            df.set_index("timestamp")["packet_length"]
            .resample("1min")
            .count()
            .astype(int)
        )
        return {
            "labels": [str(ts) for ts in series.index.tolist()],
            "values": series.tolist(),
        }

    def get_summary_dataframe(self) -> pd.DataFrame:
        """Return a DataFrame table summarising all protocol stats."""
        report = self.generate_protocol_report()
        return report.summary_df if report.summary_df is not None else pd.DataFrame()

    # ── Report Dictionary ─────────────────────────────────────────────────────

    def to_report_dict(self) -> dict[str, Any]:
        """
        Generate a structured protocol report as a plain dictionary.

        Returns:
            Dictionary with all key protocol metrics.
        """
        self._assert_loaded()
        report = self.generate_protocol_report()
        return {
            "total_packets": report.total_packets,
            "total_protocols": report.total_protocols,
            "protocol_distribution": self.protocol_distribution(),
            "transport_distribution": report.transport_distribution,
            "application_distribution": report.application_distribution,
            "tcp_pct": report.tcp_pct,
            "udp_pct": report.udp_pct,
            "icmp_pct": report.icmp_pct,
            "arp_pct": report.arp_pct,
            "http_pct": report.http_pct,
            "https_pct": report.https_pct,
            "dns_pct": report.dns_pct,
            "ntp_pct": report.ntp_pct,
            "malformed_pct": report.malformed_pct,
            "unknown_pct": report.unknown_pct,
            "top_protocols": [
                {
                    "protocol": e.protocol,
                    "packet_count": e.packet_count,
                    "percentage": e.percentage,
                    "rank": e.rank,
                }
                for e in report.top_protocols
            ],
        }

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _assert_loaded(self) -> None:
        """Raise RuntimeError if data has not been loaded."""
        if self._df is None:
            raise RuntimeError("Data not loaded. Call load_data() first.")


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 1 STUB — Retained for backward compatibility
# ──────────────────────────────────────────────────────────────────────────────

class ProtocolAnalyzer:
    """
    Phase 1 stub retained for backward compatibility.

    For Phase 3 analytics use :class:`ProtocolAnalysis`.
    """

    def __init__(self) -> None:
        """Initialise the ProtocolAnalyzer."""
        self._baseline: dict[str, float] = {}
        log.debug("ProtocolAnalyzer (legacy stub) initialised.")

    def analyse(self, df: pd.DataFrame) -> list[ProtocolStats]:
        """Compute per-protocol statistics for the given DataFrame."""
        if df.empty:
            return []

        proto_col = "protocol" if "protocol" in df.columns else None
        if proto_col is None:
            return []

        total = len(df)
        results: list[ProtocolStats] = []

        for proto, grp in df.groupby(proto_col):
            count = len(grp)
            byte_col_val = int(grp["packet_length"].sum()) if "packet_length" in grp.columns else 0
            avg_size = float(grp["packet_length"].mean()) if "packet_length" in grp.columns else 0.0
            src_col = "src_ip" if "src_ip" in grp.columns else "source_ip"
            u_src = grp[src_col].nunique() if src_col in grp.columns else 0
            dst_port_col = "dst_port" if "dst_port" in grp.columns else "destination_port"
            u_ports = grp[dst_port_col].nunique() if dst_port_col in grp.columns else 0

            results.append(
                ProtocolStats(
                    protocol=str(proto),
                    packet_count=count,
                    byte_count=byte_col_val,
                    percentage=round(count / total * 100, 2),
                    avg_packet_size=round(avg_size, 2),
                    unique_src_ips=u_src,
                    unique_dst_ports=u_ports,
                )
            )

        return sorted(results, key=lambda x: -x.packet_count)

    def set_baseline(self, df: pd.DataFrame) -> None:
        """Compute and store a protocol distribution baseline."""
        if df.empty or "protocol" not in df.columns:
            return
        total = len(df)
        self._baseline = {
            proto: round(count / total * 100, 2)
            for proto, count in df["protocol"].value_counts().to_dict().items()
        }
        log.debug("Baseline set: %d protocols.", len(self._baseline))

    def detect_anomalies(
        self, current: list[ProtocolStats]
    ) -> list[ProtocolStats]:
        """Flag protocols whose usage deviates from the baseline."""
        if not self._baseline:
            return current
        for stat in current:
            baseline_pct = self._baseline.get(stat.protocol, 0.0)
            delta = abs(stat.percentage - baseline_pct)
            if delta > 20.0:
                stat.is_anomalous = True
                stat.anomaly_reason = (
                    f"Usage shifted {delta:.1f}% from baseline "
                    f"({baseline_pct:.1f}% → {stat.percentage:.1f}%)"
                )
        return current
