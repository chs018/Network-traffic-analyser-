"""
alert_manager.py — Security Alert Management System
=====================================================
Network Traffic Analysis and Intrusion Detection System

The AlertManager is the central repository for security alerts generated
by the Phase 5 detector pipeline. It provides:

  - In-memory alert storage with automatic deduplication
  - Severity-based classification and ranking
  - Database persistence via DatabaseManager
  - Alert summary generation for dashboards and reports
  - Chart-ready output methods for Plotly / Streamlit integration

Severity Levels (ascending order):
  LOW → MEDIUM → HIGH → CRITICAL

Classes:
    AlertManager — Central alert repository and analytics engine

Author: Network Traffic Analyzer Project
Version: 5.0.0
Python: 3.11+
"""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import pandas as pd

from database.db_manager import AlertRecord, DatabaseManager
from detection.rule_engine import SecurityAlert
from utils.logger import get_detection_logger

log = get_detection_logger()


# ──────────────────────────────────────────────────────────────────────────────
# ALERT MANAGER
# ──────────────────────────────────────────────────────────────────────────────

class AlertManager:
    """
    Central alert management system for the Phase 5 IDS pipeline.

    Responsibilities:
      - Store all SecurityAlert objects from the RuleEngine
      - Assign sequential IDs and timestamps
      - Deduplicate repeated alerts (same src+type within dedup window)
      - Rank by severity for prioritised analyst review
      - Persist alerts to the database
      - Generate chart-ready aggregation data

    Usage::

        manager = AlertManager(db_manager=db)
        manager.ingest(alerts)                    # Add alerts from RuleEngine

        summary = manager.generate_summary()      # Overall report
        counts  = manager.get_attack_counts()     # By attack type
        dist    = manager.get_severity_distribution()
        df      = manager.get_alert_table()       # Pandas DataFrame
    """

    # Severity ordering for comparisons
    _SEVERITY_RANK: dict[str, int] = {
        "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
    }

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        dedup_window_seconds: int = 300,
        max_in_memory: int = 10_000,
    ) -> None:
        """
        Initialise the AlertManager.

        Args:
            db_manager:            Optional DatabaseManager for persistence.
            dedup_window_seconds:  Window (seconds) to suppress identical alerts.
            max_in_memory:         Maximum alerts stored in memory before pruning.
        """
        self._db: Optional[DatabaseManager] = db_manager
        self._dedup_window: int = dedup_window_seconds
        self._max_in_memory: int = max_in_memory

        # Primary alert store: alert_id → SecurityAlert
        self._alerts: dict[str, SecurityAlert] = {}
        # Ordered insertion log for timeline queries
        self._insertion_order: list[str] = []
        # Dedup cache: (src_ip, attack_type) → last insertion epoch
        self._dedup_cache: dict[tuple[str, str], float] = {}

        log.info(
            "AlertManager initialised (dedup=%ds, max_memory=%d).",
            dedup_window_seconds, max_in_memory,
        )

    # ── Alert Ingestion ────────────────────────────────────────────────────────

    def ingest(self, alerts: list[SecurityAlert]) -> int:
        """
        Ingest a batch of alerts from the RuleEngine.

        Each alert is:
          1. Deduplicated against the in-memory cache
          2. Assigned a sequential store ID
          3. Persisted to the database (if db_manager is configured)

        Args:
            alerts: List of SecurityAlert objects from RuleEngine.

        Returns:
            Number of alerts actually stored (after deduplication).
        """
        stored = 0
        import time
        now = time.time()

        for alert in alerts:
            key = (alert.source_ip, alert.attack_type)
            last_seen = self._dedup_cache.get(key, 0.0)

            if (now - last_seen) < self._dedup_window:
                log.debug(
                    "AlertManager: suppressed duplicate [%s from %s] "
                    "(%.0fs ago).",
                    alert.attack_type, alert.source_ip, now - last_seen,
                )
                continue

            # Ensure alert_id is set
            if not alert.alert_id:
                alert.alert_id = str(uuid.uuid4())

            self._alerts[alert.alert_id] = alert
            self._insertion_order.append(alert.alert_id)
            self._dedup_cache[key] = now
            stored += 1

            # Database persistence
            if self._db:
                try:
                    record = alert.to_alert_record()
                    self._db.insert_alert(record)
                except Exception as exc:
                    log.error(
                        "AlertManager: failed to persist alert '%s': %s",
                        alert.alert_id, exc,
                    )

        # Prune if over memory limit
        if len(self._alerts) > self._max_in_memory:
            self._prune()

        log.info(
            "AlertManager ingested %d new alert(s) (total stored=%d).",
            stored, len(self._alerts),
        )
        return stored

    def add_alert(self, alert: SecurityAlert) -> bool:
        """
        Add a single alert directly (without batch dedup check).

        Useful for manually constructed alerts or unit testing.

        Args:
            alert: SecurityAlert to store.

        Returns:
            True if stored, False if alert_id already exists.
        """
        if alert.alert_id in self._alerts:
            return False
        if not alert.alert_id:
            alert.alert_id = str(uuid.uuid4())
        self._alerts[alert.alert_id] = alert
        self._insertion_order.append(alert.alert_id)
        return True

    # ── Query Methods ──────────────────────────────────────────────────────────

    def get_all_alerts(self) -> list[SecurityAlert]:
        """
        Return all stored alerts in insertion order.

        Returns:
            List of SecurityAlert objects.
        """
        return [self._alerts[aid] for aid in self._insertion_order
                if aid in self._alerts]

    def get_alerts_by_type(self, attack_type: str) -> list[SecurityAlert]:
        """
        Return alerts matching the given attack type.

        Args:
            attack_type: Exact attack type string (e.g. "DDoS-VolumeFlood").
                         Also matches partial prefix (e.g. "DDoS").

        Returns:
            Filtered list of SecurityAlert objects.
        """
        return [
            a for a in self._alerts.values()
            if a.attack_type.startswith(attack_type)
        ]

    def get_alerts_by_severity(self, severity: str) -> list[SecurityAlert]:
        """
        Return alerts at or above the given severity level.

        Args:
            severity: Minimum severity ("LOW", "MEDIUM", "HIGH", "CRITICAL").

        Returns:
            Filtered and sorted list of SecurityAlert objects.
        """
        min_rank = self._SEVERITY_RANK.get(severity.upper(), 0)
        filtered = [
            a for a in self._alerts.values()
            if self._SEVERITY_RANK.get(a.severity, 0) >= min_rank
        ]
        return sorted(
            filtered,
            key=lambda a: self._SEVERITY_RANK.get(a.severity, 0),
            reverse=True,
        )

    def get_highest_severity(self) -> str:
        """
        Return the highest severity level across all stored alerts.

        Returns:
            Severity string ("LOW", "MEDIUM", "HIGH", "CRITICAL", or "NONE").
        """
        if not self._alerts:
            return "NONE"
        return max(
            self._alerts.values(),
            key=lambda a: self._SEVERITY_RANK.get(a.severity, 0),
        ).severity

    def count(self) -> int:
        """Return total number of stored alerts."""
        return len(self._alerts)

    def count_by_type(self, prefix: str) -> int:
        """
        Count alerts whose attack_type starts with the given prefix.

        Args:
            prefix: Attack type prefix (e.g. "DDoS", "PortScan").

        Returns:
            Integer count.
        """
        return sum(
            1 for a in self._alerts.values()
            if a.attack_type.startswith(prefix)
        )

    # ── Visualization Data Methods ─────────────────────────────────────────────

    def get_attack_counts(self) -> dict[str, int]:
        """
        Return alert counts grouped by attack type prefix.

        Groups are: DDoS, PortScan, BruteForce, SYNFlood, Other.

        Returns:
            Dict mapping group name → count.

        Example::

            {
                "DDoS": 3,
                "PortScan": 1,
                "BruteForce": 2,
                "SYNFlood": 0,
                "Other": 0,
            }
        """
        groups = {
            "DDoS": 0,
            "PortScan": 0,
            "BruteForce": 0,
            "SYNFlood": 0,
            "Other": 0,
        }
        for alert in self._alerts.values():
            matched = False
            for key in ("DDoS", "PortScan", "BruteForce", "SYNFlood"):
                if alert.attack_type.startswith(key):
                    groups[key] += 1
                    matched = True
                    break
            if not matched:
                groups["Other"] += 1
        return groups

    def get_severity_distribution(self) -> dict[str, int]:
        """
        Return alert counts grouped by severity level.

        Returns:
            Dict mapping severity → count (all four levels present).

        Example::

            {"LOW": 0, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 1}
        """
        dist: dict[str, int] = {
            "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0,
        }
        for alert in self._alerts.values():
            sev = alert.severity.upper()
            if sev in dist:
                dist[sev] += 1
            else:
                dist["LOW"] += 1
        return dist

    def get_attack_timeline(
        self,
        freq: str = "1min",
    ) -> dict[str, list]:
        """
        Return time-bucketed alert counts for a timeline chart.

        Args:
            freq: Pandas frequency string (e.g. "1min", "5min", "1h").

        Returns:
            Dict with "labels" (timestamp strings) and "values" (counts).

        Example::

            {"labels": ["2025-01-01 10:00", ...], "values": [3, 0, 5, ...]}
        """
        if not self._alerts:
            return {"labels": [], "values": [], "attack_types": []}

        rows = [
            {
                "timestamp": pd.to_datetime(a.timestamp, errors="coerce", utc=True),
                "attack_type": a.attack_type,
                "severity": a.severity,
            }
            for a in self._alerts.values()
        ]
        df = pd.DataFrame(rows).dropna(subset=["timestamp"])
        if df.empty:
            return {"labels": [], "values": [], "attack_types": []}

        df = df.set_index("timestamp").sort_index()
        counts = df["attack_type"].resample(freq).count()

        return {
            "labels": [str(ts) for ts in counts.index.tolist()],
            "values": counts.astype(int).tolist(),
            "attack_types": df["attack_type"].unique().tolist(),
        }

    def get_alert_table(self) -> pd.DataFrame:
        """
        Return all alerts as a Pandas DataFrame for dashboard table display.

        Columns: alert_id, timestamp, attack_type, severity, confidence,
                 source_ip, destination_ip, detector_name, description.

        Sorted by severity (descending), then timestamp (descending).

        Returns:
            DataFrame with one row per stored alert.
        """
        if not self._alerts:
            return pd.DataFrame(columns=[
                "alert_id", "timestamp", "attack_type", "severity",
                "confidence", "source_ip", "destination_ip",
                "detector_name", "description",
            ])

        rows = [
            {
                "alert_id": a.alert_id[:8] + "…",
                "timestamp": a.timestamp,
                "attack_type": a.attack_type,
                "severity": a.severity,
                "confidence": f"{a.confidence:.0%}",
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "detector_name": a.detector_name,
                "description": a.description[:120] if a.description else "",
            }
            for a in self._alerts.values()
        ]
        df = pd.DataFrame(rows)
        # Sort by severity rank desc, then timestamp desc
        df["_sev_rank"] = df["severity"].map(
            lambda s: self._SEVERITY_RANK.get(s, 0)
        )
        df = df.sort_values(
            ["_sev_rank", "timestamp"], ascending=[False, False]
        ).drop(columns=["_sev_rank"]).reset_index(drop=True)
        return df

    # ── Summary Report ────────────────────────────────────────────────────────

    def generate_summary(self) -> dict[str, Any]:
        """
        Generate a complete alert summary report.

        Returns a flat, JSON-serialisable dictionary suitable for the
        INTRUSION DETECTION REPORT banner.

        Returns:
            Dict with keys: total_alerts, by_type, severity_distribution,
            highest_severity, top_sources, top_targets, detectors.
        """
        total = self.count()
        by_type = self.get_attack_counts()
        severity_dist = self.get_severity_distribution()
        highest = self.get_highest_severity()

        # Top attacking source IPs
        src_counter: Counter = Counter(
            a.source_ip for a in self._alerts.values()
            if a.source_ip not in ("MULTIPLE", "UNKNOWN", "")
        )
        top_sources = src_counter.most_common(10)

        # Top targeted destination IPs
        dst_counter: Counter = Counter(
            a.destination_ip for a in self._alerts.values()
            if a.destination_ip not in ("MULTIPLE", "UNKNOWN", "")
        )
        top_targets = dst_counter.most_common(10)

        # Per-detector alert counts
        detector_counts: Counter = Counter(
            a.detector_name for a in self._alerts.values()
        )

        # Average confidence
        confidences = [a.confidence for a in self._alerts.values()]
        avg_confidence = round(sum(confidences) / max(len(confidences), 1), 3)

        return {
            "total_alerts": total,
            "by_attack_type": by_type,
            "severity_distribution": severity_dist,
            "highest_severity": highest,
            "avg_confidence": avg_confidence,
            "top_sources": [{"ip": ip, "count": cnt} for ip, cnt in top_sources],
            "top_targets": [{"ip": ip, "count": cnt} for ip, cnt in top_targets],
            "detector_counts": dict(detector_counts),
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    # ── Persistence ───────────────────────────────────────────────────────────

    def persist_all(self) -> int:
        """
        Persist all in-memory alerts to the database.

        Useful for batch persistence after a detection run.

        Returns:
            Number of alerts successfully persisted.
        """
        if not self._db:
            log.warning("AlertManager: no db_manager configured — skipping persistence.")
            return 0

        persisted = 0
        for alert in self._alerts.values():
            try:
                record = alert.to_alert_record()
                self._db.insert_alert(record)
                persisted += 1
            except Exception as exc:
                log.error("AlertManager: persistence error for %s: %s", alert.alert_id, exc)

        log.info("AlertManager: persisted %d alert(s) to database.", persisted)
        return persisted

    # ── Maintenance ───────────────────────────────────────────────────────────

    def clear(self) -> None:
        """Clear all in-memory alerts and dedup cache."""
        self._alerts.clear()
        self._insertion_order.clear()
        self._dedup_cache.clear()
        log.debug("AlertManager cleared.")

    def _prune(self) -> None:
        """
        Remove oldest alerts when exceeding the memory limit.

        Retains the most recent ``_max_in_memory`` alerts.
        """
        excess = len(self._alerts) - self._max_in_memory
        if excess <= 0:
            return
        # Remove oldest (by insertion order)
        to_remove = self._insertion_order[:excess]
        for aid in to_remove:
            self._alerts.pop(aid, None)
        self._insertion_order = self._insertion_order[excess:]
        log.debug("AlertManager pruned %d old alert(s).", excess)

    def __repr__(self) -> str:
        return (
            f"AlertManager("
            f"alerts={len(self._alerts)}, "
            f"highest={self.get_highest_severity()})"
        )
