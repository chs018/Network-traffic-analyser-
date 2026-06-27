"""
feature_extractor.py — Packet Records → Analysis-Ready DataFrame
=================================================================
Network Traffic Analysis and Intrusion Detection System

Converts a list of :class:`PacketRecord` instances into a cleaned,
enriched Pandas DataFrame ready for:
  - Statistical analysis and visualisation
  - CSV export to ``data/processed/``
  - Batch persistence into the SQLite ``traffic_logs`` table via DatabaseManager
  - Feature engineering for the Phase 3 ML pipeline

Engineered features added beyond the raw packet fields:
  - ``is_tcp``               Binary flag: 1 if TCP, else 0
  - ``is_udp``               Binary flag: 1 if UDP, else 0
  - ``is_icmp``              Binary flag: 1 if ICMP/ICMPv6, else 0
  - ``packet_size_category`` "small" (<200B) | "medium" (200–1000B) | "large" (>1000B)
  - ``source_ip_frequency``  Count of packets sharing the same source IP
  - ``destination_ip_frequency`` Count of packets sharing the same destination IP
  - ``hour_of_day``          Hour extracted from timestamp (0–23)
  - ``is_private_src``       1 if source IP is RFC-1918 private, else 0
  - ``is_private_dst``       1 if destination IP is RFC-1918 private, else 0

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from __future__ import annotations

import ipaddress
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd

from capture.packet_parser import PacketRecord
from database.db_manager import DatabaseManager
from utils.config import config
from utils.logger import get_capture_logger

log = get_capture_logger()

# ── DataFrame column order for consistent CSV output ──────────────────────────
_BASE_COLUMNS: list[str] = [
    "packet_number",
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "transport_layer",
    "packet_length",
    "source_port",
    "destination_port",
    "ttl",
    "tcp_flags",
    "network_layer",
    "app_layer_hint",
    "ip_version",
]

_ENGINEERED_COLUMNS: list[str] = [
    "is_tcp",
    "is_udp",
    "is_icmp",
    "packet_size_category",
    "source_ip_frequency",
    "destination_ip_frequency",
    "hour_of_day",
    "is_private_src",
    "is_private_dst",
]

# ── traffic_logs table DDL (new table, extending the existing schema) ──────────
_TRAFFIC_LOGS_DDL = """
CREATE TABLE IF NOT EXISTS traffic_logs (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_number           INTEGER NOT NULL,
    timestamp               TEXT    NOT NULL,
    source_ip               TEXT,
    destination_ip          TEXT,
    protocol                TEXT    NOT NULL DEFAULT 'UNKNOWN',
    transport_layer         TEXT,
    packet_length           INTEGER NOT NULL DEFAULT 0,
    source_port             INTEGER,
    destination_port        INTEGER,
    ttl                     INTEGER,
    tcp_flags               TEXT,
    network_layer           TEXT,
    app_layer_hint          TEXT,
    ip_version              INTEGER,
    is_tcp                  INTEGER NOT NULL DEFAULT 0,
    is_udp                  INTEGER NOT NULL DEFAULT 0,
    is_icmp                 INTEGER NOT NULL DEFAULT 0,
    packet_size_category    TEXT,
    source_ip_frequency     INTEGER DEFAULT 0,
    destination_ip_frequency INTEGER DEFAULT 0,
    hour_of_day             INTEGER,
    is_private_src          INTEGER NOT NULL DEFAULT 0,
    is_private_dst          INTEGER NOT NULL DEFAULT 0,
    session_id              TEXT,
    created_at              TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""

_TRAFFIC_LOGS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON traffic_logs(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_logs_src_ip    ON traffic_logs(source_ip);",
    "CREATE INDEX IF NOT EXISTS idx_logs_dst_ip    ON traffic_logs(destination_ip);",
    "CREATE INDEX IF NOT EXISTS idx_logs_protocol  ON traffic_logs(protocol);",
    "CREATE INDEX IF NOT EXISTS idx_logs_session   ON traffic_logs(session_id);",
]

_BATCH_INSERT_SQL = """
INSERT INTO traffic_logs (
    packet_number, timestamp, source_ip, destination_ip,
    protocol, transport_layer, packet_length, source_port, destination_port,
    ttl, tcp_flags, network_layer, app_layer_hint, ip_version,
    is_tcp, is_udp, is_icmp, packet_size_category,
    source_ip_frequency, destination_ip_frequency,
    hour_of_day, is_private_src, is_private_dst, session_id
) VALUES (
    :packet_number, :timestamp, :source_ip, :destination_ip,
    :protocol, :transport_layer, :packet_length, :source_port, :destination_port,
    :ttl, :tcp_flags, :network_layer, :app_layer_hint, :ip_version,
    :is_tcp, :is_udp, :is_icmp, :packet_size_category,
    :source_ip_frequency, :destination_ip_frequency,
    :hour_of_day, :is_private_src, :is_private_dst, :session_id
);
"""


# ──────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _is_private_ip(ip_str: Optional[str]) -> bool:
    """Return True if ip_str is an RFC-1918 private address (or loopback)."""
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def _categorise_size(length: int) -> str:
    """Map a packet length in bytes to a size category string."""
    if length < 200:
        return "small"
    if length <= 1000:
        return "medium"
    return "large"


def _extract_hour(ts: Optional[str]) -> Optional[int]:
    """Extract the hour of day (0–23) from an ISO-8601 timestamp string."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
        return dt.hour
    except (ValueError, TypeError):
        return None


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTOR
# ──────────────────────────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Transforms a list of :class:`PacketRecord` instances into an enriched
    Pandas DataFrame and persists results to both CSV and SQLite.

    Usage (typical pipeline)::

        extractor = FeatureExtractor(session_id="abc-123")
        df = extractor.records_to_dataframe(records)
        df = extractor.clean_dataframe(df)
        df = extractor.engineer_features(df)
        extractor.export_csv(df)
        extractor.save_to_database(df)
        stats = extractor.generate_summary(df)

    Attributes:
        session_id (str | None):  Session UUID, embedded in DB rows.
        db_manager (DatabaseManager): Shared database manager instance.
        csv_output_path (Path):   Destination path for CSV export.
        db_batch_size (int):      Number of rows per SQLite transaction.
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        db_manager: Optional[DatabaseManager] = None,
        csv_output_path: Optional[Path] = None,
        db_batch_size: int = 500,
    ) -> None:
        """
        Initialise the FeatureExtractor.

        Args:
            session_id:       Capture session UUID (embeds in DB rows).
            db_manager:       Existing DatabaseManager instance. If None,
                              a new one is created automatically.
            csv_output_path:  Override the default CSV output path.
                              Defaults to ``data/processed/packets.csv``.
            db_batch_size:    Rows per SQLite batch insert (default 500).
        """
        self.session_id: Optional[str] = session_id
        self.db_manager: DatabaseManager = db_manager or DatabaseManager()
        self.csv_output_path: Path = (
            csv_output_path
            or config.paths.processed_data_dir / "packets.csv"
        )
        self.db_batch_size: int = db_batch_size

        # Ensure the traffic_logs table and its indexes exist
        self._ensure_traffic_logs_table()

        log.info(
            "FeatureExtractor initialised | session='%s' | csv='%s'",
            session_id or "none",
            self.csv_output_path,
        )

    # ── Schema Setup ───────────────────────────────────────────────────────────

    def _ensure_traffic_logs_table(self) -> None:
        """
        Create the ``traffic_logs`` table if it does not already exist.

        Extends the existing Phase 1 schema without modifying any existing
        tables. Uses the DatabaseManager's internal connection.
        """
        try:
            conn = self.db_manager._get_connection()
            cursor = conn.cursor()
            cursor.execute(_TRAFFIC_LOGS_DDL)
            for idx_sql in _TRAFFIC_LOGS_INDEXES:
                cursor.execute(idx_sql)
            conn.commit()
            log.debug("traffic_logs table and indexes ensured.")
        except sqlite3.Error as exc:
            log.error("Failed to create traffic_logs table: %s", exc)
            raise

    # ── DataFrame Construction ─────────────────────────────────────────────────

    def records_to_dataframe(self, records: list[PacketRecord]) -> pd.DataFrame:
        """
        Convert a list of :class:`PacketRecord` instances to a DataFrame.

        Args:
            records: List of parsed packet records (from PacketParser).

        Returns:
            DataFrame with one row per packet.  Column order follows
            ``_BASE_COLUMNS``.  Returns an empty DataFrame if ``records``
            is empty.
        """
        if not records:
            log.warning("records_to_dataframe called with 0 records.")
            return pd.DataFrame(columns=_BASE_COLUMNS)

        dict_list = [r.to_dict() for r in records]
        df = pd.DataFrame.from_records(dict_list)

        # Reorder / ensure all base columns are present
        for col in _BASE_COLUMNS:
            if col not in df.columns:
                df[col] = None

        df = df[_BASE_COLUMNS + [c for c in df.columns if c not in _BASE_COLUMNS]]

        log.info("records_to_dataframe: %d records -> DataFrame shape %s", len(records), df.shape)
        return df

    # ── Data Cleaning ──────────────────────────────────────────────────────────

    def clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply data cleaning rules to the raw packet DataFrame.

        Cleaning steps (in order):
        1. Remove exact duplicate rows.
        2. Enforce correct column dtypes.
        3. Normalise protocol strings to upper-case.
        4. Normalise timestamps to ISO-8601 UTC strings.
        5. Fill missing ``packet_length`` with 0 (not None).
        6. Fill missing ``protocol`` with "UNKNOWN".
        7. Ensure port values are integers or None (not floats).

        Args:
            df: Raw DataFrame from :meth:`records_to_dataframe`.

        Returns:
            Cleaned DataFrame.
        """
        original_len = len(df)
        if df.empty:
            return df

        log.info("Cleaning DataFrame (%d rows)…", original_len)

        # ── 1. Duplicate removal ───────────────────────────────────────────────
        df = df.drop_duplicates()
        dupes_removed = original_len - len(df)
        if dupes_removed:
            log.debug("Removed %d duplicate rows.", dupes_removed)

        # ── 2. Protocol normalisation ──────────────────────────────────────────
        if "protocol" in df.columns:
            df["protocol"] = (
                df["protocol"]
                .fillna("UNKNOWN")
                .astype(str)
                .str.upper()
                .str.strip()
            )

        if "transport_layer" in df.columns:
            df["transport_layer"] = (
                df["transport_layer"]
                .astype(str)
                .str.upper()
                .str.strip()
                .replace({"NAN": None, "NONE": None})
            )

        if "network_layer" in df.columns:
            df["network_layer"] = (
                df["network_layer"]
                .astype(str)
                .str.upper()
                .str.strip()
                .replace({"NAN": None, "NONE": None})
            )

        # ── 3. Packet length validation ────────────────────────────────────────
        if "packet_length" in df.columns:
            df["packet_length"] = (
                pd.to_numeric(df["packet_length"], errors="coerce")
                .fillna(0)
                .astype(int)
            )
            # Sanity bound: packet lengths cannot exceed Ethernet jumbo frame
            df["packet_length"] = df["packet_length"].clip(lower=0, upper=65_535)

        # ── 4. Port dtype normalisation ────────────────────────────────────────
        for port_col in ("source_port", "destination_port"):
            if port_col in df.columns:
                df[port_col] = pd.to_numeric(df[port_col], errors="coerce")
                # Keep as nullable int (pd.Int32Dtype preserves NaN)
                df[port_col] = df[port_col].astype("Int32")

        # ── 5. TTL dtype normalisation ─────────────────────────────────────────
        if "ttl" in df.columns:
            df["ttl"] = pd.to_numeric(df["ttl"], errors="coerce").astype("Int32")

        # ── 6. IP version ─────────────────────────────────────────────────────
        if "ip_version" in df.columns:
            df["ip_version"] = pd.to_numeric(df["ip_version"], errors="coerce").astype("Int32")

        # ── 7. Timestamp validation ────────────────────────────────────────────
        if "timestamp" in df.columns:
            df["timestamp"] = df["timestamp"].fillna(
                datetime.now(tz=timezone.utc).isoformat()
            )

        # ── 8. IP address cleanup ──────────────────────────────────────────────
        for ip_col in ("source_ip", "destination_ip"):
            if ip_col in df.columns:
                df[ip_col] = df[ip_col].where(
                    df[ip_col].notna() & (df[ip_col] != "None"),
                    other=None,
                )

        log.info(
            "Cleaning complete: %d -> %d rows (removed %d dupes).",
            original_len,
            len(df),
            dupes_removed,
        )
        return df.reset_index(drop=True)

    # ── Feature Engineering ────────────────────────────────────────────────────

    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add engineered features to the cleaned DataFrame.

        New columns added:
        - ``is_tcp``, ``is_udp``, ``is_icmp``   — Binary protocol flags
        - ``packet_size_category``               — "small" | "medium" | "large"
        - ``source_ip_frequency``                — Packet count per source IP
        - ``destination_ip_frequency``           — Packet count per destination IP
        - ``hour_of_day``                        — Hour of capture (0–23)
        - ``is_private_src``                     — 1 if source IP is private
        - ``is_private_dst``                     — 1 if destination IP is private

        Args:
            df: Cleaned DataFrame from :meth:`clean_dataframe`.

        Returns:
            DataFrame with engineered feature columns appended.
        """
        if df.empty:
            return df

        log.info("Engineering features on %d rows…", len(df))

        # ── Protocol binary flags ──────────────────────────────────────────────
        transport_upper = df.get("transport_layer", pd.Series(dtype=str)).fillna("").str.upper()
        df["is_tcp"]  = (transport_upper == "TCP").astype(int)
        df["is_udp"]  = (transport_upper == "UDP").astype(int)
        df["is_icmp"] = transport_upper.str.startswith("ICMP").astype(int)

        # ── Packet size category ──────────────────────────────────────────────
        df["packet_size_category"] = df["packet_length"].apply(_categorise_size)

        # ── IP frequency (how often each IP appears in this capture) ──────────
        if "source_ip" in df.columns:
            src_freq = df["source_ip"].value_counts()
            df["source_ip_frequency"] = df["source_ip"].map(src_freq).fillna(0).astype(int)
        else:
            df["source_ip_frequency"] = 0

        if "destination_ip" in df.columns:
            dst_freq = df["destination_ip"].value_counts()
            df["destination_ip_frequency"] = df["destination_ip"].map(dst_freq).fillna(0).astype(int)
        else:
            df["destination_ip_frequency"] = 0

        # ── Hour of day ───────────────────────────────────────────────────────
        df["hour_of_day"] = df["timestamp"].apply(_extract_hour)
        df["hour_of_day"] = pd.to_numeric(df["hour_of_day"], errors="coerce").astype("Int32")

        # ── Private IP flags ──────────────────────────────────────────────────
        df["is_private_src"] = df["source_ip"].apply(_is_private_ip).astype(int)
        df["is_private_dst"] = df["destination_ip"].apply(_is_private_ip).astype(int)

        log.info("Feature engineering complete. New columns: %s", _ENGINEERED_COLUMNS)
        return df

    # ── CSV Export ─────────────────────────────────────────────────────────────

    def export_csv(
        self,
        df: pd.DataFrame,
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Export the DataFrame to a CSV file.

        Args:
            df:          DataFrame to export.
            output_path: Override the default CSV output path.

        Returns:
            Absolute path to the written CSV file.

        Raises:
            IOError: If the CSV cannot be written.
        """
        target = Path(output_path) if output_path else self.csv_output_path
        target.parent.mkdir(parents=True, exist_ok=True)

        if df.empty:
            log.warning("export_csv called with empty DataFrame — writing headers only.")

        try:
            df.to_csv(target, index=False, encoding="utf-8")
            size_kb = target.stat().st_size / 1024
            log.info(
                "CSV exported: %s | rows=%d | size=%.2f KB",
                target,
                len(df),
                size_kb,
            )
        except IOError as exc:
            log.error("Failed to export CSV: %s", exc)
            raise

        return target

    # ── Database Persistence ───────────────────────────────────────────────────

    def save_to_database(
        self,
        df: pd.DataFrame,
        session_id: Optional[str] = None,
    ) -> int:
        """
        Persist the DataFrame to the ``traffic_logs`` SQLite table in batches.

        Uses the existing :class:`DatabaseManager` connection so no separate
        connection is opened, and WAL-mode benefits from Phase 1 PRAGMA setup.

        Args:
            df:         DataFrame to persist (should be cleaned + engineered).
            session_id: Override the instance-level session ID.

        Returns:
            Total number of rows inserted.

        Raises:
            sqlite3.Error: On fatal database errors.
        """
        if df.empty:
            log.warning("save_to_database called with empty DataFrame — nothing written.")
            return 0

        sid = session_id or self.session_id
        total_inserted = 0
        total_rows = len(df)

        log.info(
            "Persisting %d rows to traffic_logs | session='%s' | batch_size=%d",
            total_rows,
            sid or "none",
            self.db_batch_size,
        )

        # Convert DataFrame to list of plain dicts for sqlite3.executemany
        records = df.copy()

        # Ensure columns that must exist for the INSERT are present
        required_cols = [
            "packet_number", "timestamp", "source_ip", "destination_ip",
            "protocol", "transport_layer", "packet_length", "source_port",
            "destination_port", "ttl", "tcp_flags", "network_layer",
            "app_layer_hint", "ip_version", "is_tcp", "is_udp", "is_icmp",
            "packet_size_category", "source_ip_frequency",
            "destination_ip_frequency", "hour_of_day",
            "is_private_src", "is_private_dst",
        ]
        for col in required_cols:
            if col not in records.columns:
                records[col] = None

        # Convert nullable integers back to Python None/int for sqlite3
        for col in ["source_port", "destination_port", "ttl", "ip_version", "hour_of_day"]:
            if col in records.columns:
                records[col] = records[col].where(records[col].notna(), other=None)

        # Add session_id column
        records["session_id"] = sid

        rows_dicts = records[required_cols + ["session_id"]].to_dict(orient="records")

        try:
            conn = self.db_manager._get_connection()
            cursor = conn.cursor()

            # Process in batches
            for start_idx in range(0, total_rows, self.db_batch_size):
                batch = rows_dicts[start_idx : start_idx + self.db_batch_size]

                # Sanitise values: convert pandas NA/NaN to None
                clean_batch = [
                    {k: (None if pd.isna(v) else v) if not isinstance(v, str) else v
                     for k, v in row.items()}
                    for row in batch
                ]

                cursor.executemany(_BATCH_INSERT_SQL, clean_batch)
                conn.commit()
                total_inserted += len(batch)

                log.debug(
                    "DB batch inserted: rows %d–%d (%d inserted so far)",
                    start_idx + 1,
                    min(start_idx + self.db_batch_size, total_rows),
                    total_inserted,
                )

            log.info(
                "Database write complete: %d rows -> traffic_logs",
                total_inserted,
            )

        except sqlite3.Error as exc:
            log.error("Database write failed at row ~%d: %s", total_inserted, exc)
            raise

        return total_inserted

    # ── Summary Statistics ─────────────────────────────────────────────────────

    def generate_summary(self, df: pd.DataFrame) -> dict[str, Any]:
        """
        Generate descriptive statistics from the packet DataFrame.

        Args:
            df: Cleaned (and optionally enriched) DataFrame.

        Returns:
            Dict with keys:

            - ``total_packets``           (int)
            - ``unique_source_ips``       (int)
            - ``unique_destination_ips``  (int)
            - ``protocol_distribution``   (dict: protocol → count)
            - ``avg_packet_size``         (float, bytes)
            - ``max_packet_size``         (int, bytes)
            - ``min_packet_size``         (int, bytes)
            - ``top_10_source_ips``       (list of [ip, count] pairs)
            - ``top_10_destination_ips``  (list of [ip, count] pairs)
            - ``transport_distribution``  (dict: transport → count)
            - ``packets_with_ip``         (int)
            - ``packets_without_ip``      (int)
            - ``capture_start``           (str, first timestamp)
            - ``capture_end``             (str, last timestamp)
        """
        if df.empty:
            log.warning("generate_summary called on empty DataFrame.")
            return {"total_packets": 0, "error": "Empty DataFrame"}

        log.info("Generating summary statistics for %d packets…", len(df))

        summary: dict[str, Any] = {}

        # ── Volume metrics ─────────────────────────────────────────────────────
        summary["total_packets"] = int(len(df))

        # ── IP uniqueness ──────────────────────────────────────────────────────
        summary["unique_source_ips"] = int(df["source_ip"].nunique())
        summary["unique_destination_ips"] = int(df["destination_ip"].nunique())

        # ── Protocol distribution ──────────────────────────────────────────────
        if "protocol" in df.columns:
            proto_counts = df["protocol"].value_counts()
            summary["protocol_distribution"] = proto_counts.to_dict()
        else:
            summary["protocol_distribution"] = {}

        # ── Transport distribution ─────────────────────────────────────────────
        if "transport_layer" in df.columns:
            transport_counts = df["transport_layer"].value_counts(dropna=True)
            summary["transport_distribution"] = transport_counts.to_dict()
        else:
            summary["transport_distribution"] = {}

        # ── Packet size statistics ─────────────────────────────────────────────
        if "packet_length" in df.columns:
            summary["avg_packet_size"] = round(float(df["packet_length"].mean()), 2)
            summary["max_packet_size"] = int(df["packet_length"].max())
            summary["min_packet_size"] = int(df["packet_length"].min())
        else:
            summary["avg_packet_size"] = 0.0
            summary["max_packet_size"] = 0
            summary["min_packet_size"] = 0

        # ── Top 10 source IPs ─────────────────────────────────────────────────
        if "source_ip" in df.columns:
            top_src = df["source_ip"].dropna().value_counts().head(10)
            summary["top_10_source_ips"] = [[ip, int(cnt)] for ip, cnt in top_src.items()]
        else:
            summary["top_10_source_ips"] = []

        # ── Top 10 destination IPs ─────────────────────────────────────────────
        if "destination_ip" in df.columns:
            top_dst = df["destination_ip"].dropna().value_counts().head(10)
            summary["top_10_destination_ips"] = [[ip, int(cnt)] for ip, cnt in top_dst.items()]
        else:
            summary["top_10_destination_ips"] = []

        # ── IP presence ────────────────────────────────────────────────────────
        if "source_ip" in df.columns:
            has_ip_mask = df["source_ip"].notna() & (df["source_ip"] != "None")
            summary["packets_with_ip"] = int(has_ip_mask.sum())
            summary["packets_without_ip"] = int((~has_ip_mask).sum())
        else:
            summary["packets_with_ip"] = 0
            summary["packets_without_ip"] = summary["total_packets"]

        # ── Temporal range ─────────────────────────────────────────────────────
        if "timestamp" in df.columns and len(df) > 0:
            sorted_ts = df["timestamp"].dropna().sort_values()
            summary["capture_start"] = str(sorted_ts.iloc[0]) if len(sorted_ts) > 0 else "N/A"
            summary["capture_end"]   = str(sorted_ts.iloc[-1]) if len(sorted_ts) > 0 else "N/A"
        else:
            summary["capture_start"] = "N/A"
            summary["capture_end"]   = "N/A"

        log.info(
            "Summary generated: %d packets | %d unique src IPs | %d protocols",
            summary["total_packets"],
            summary["unique_source_ips"],
            len(summary["protocol_distribution"]),
        )
        return summary

    # ── Full Pipeline Shortcut ─────────────────────────────────────────────────

    def run_pipeline(
        self,
        records: list[PacketRecord],
        export_csv: bool = True,
        save_db: bool = True,
    ) -> tuple[pd.DataFrame, dict[str, Any]]:
        """
        Run the complete extraction pipeline in a single call.

        Steps:
        1. ``records_to_dataframe()``
        2. ``clean_dataframe()``
        3. ``engineer_features()``
        4. ``export_csv()`` (if requested)
        5. ``save_to_database()`` (if requested)
        6. ``generate_summary()``

        Args:
            records:    Parsed packet records from :class:`PacketParser`.
            export_csv: Write the enriched DataFrame to CSV.
            save_db:    Persist the DataFrame to SQLite.

        Returns:
            Tuple of (enriched DataFrame, summary dict).
        """
        log.info("Running full feature extraction pipeline on %d records…", len(records))

        df = self.records_to_dataframe(records)
        df = self.clean_dataframe(df)
        df = self.engineer_features(df)

        if export_csv:
            self.export_csv(df)

        if save_db:
            self.save_to_database(df)

        summary = self.generate_summary(df)
        log.info("Pipeline complete.")
        return df, summary

    def __repr__(self) -> str:
        return (
            f"FeatureExtractor("
            f"session_id='{self.session_id}', "
            f"csv='{self.csv_output_path.name}')"
        )
