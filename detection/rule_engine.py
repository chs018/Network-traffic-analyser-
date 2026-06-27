"""
rule_engine.py — Central Detection Rule Orchestrator
======================================================
Network Traffic Analysis and Intrusion Detection System

The RuleEngine is the central coordinator for all rule-based intrusion
detection. It:
  1. Accepts a pandas DataFrame of parsed packets plus Phase 3/4 analytics
     objects as inputs
  2. Fans them out to registered Detector instances in priority order
  3. Collects SecurityAlert objects from each detector
  4. Suppresses duplicate alerts within a configurable time window
  5. Scores and aggregates alerts across all detectors
  6. Persists alerts to the database via DatabaseManager

Design Patterns:
  - Observer / Event-Bus for detector registration
  - Strategy pattern for pluggable detector implementations
  - Dependency Injection for analytics objects

Classes:
    BaseDetector  — Abstract base class for all detectors
    RuleEngine    — Orchestration engine (Phase 5 — fully implemented)

Author: Network Traffic Analyzer Project
Version: 5.0.0
Python: 3.11+
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

import pandas as pd

from database.db_manager import AlertRecord, DatabaseManager
from utils.config import config
from utils.logger import get_detection_logger

if TYPE_CHECKING:
    from analysis.bandwidth_monitor import BandwidthMonitor
    from analysis.health_monitor import NetworkHealthReport
    from analysis.protocol_analysis import ProtocolAnalysis
    from analysis.traffic_statistics import TrafficStatistics

log = get_detection_logger()


# ──────────────────────────────────────────────────────────────────────────────
# SECURITY ALERT DATACLASS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SecurityAlert:
    """
    Standardised security alert emitted by every detector.

    Every field is populated by the detector so alerts are fully
    self-contained for storage, dashboard display, and analyst review.
    """

    alert_id: str                         # UUID or deterministic hash
    attack_type: str                      # e.g. "DDoS", "PortScan"
    severity: str                         # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float                     # 0.0 – 1.0
    source_ip: str                        # Primary attacker IP (or "MULTIPLE")
    destination_ip: str                   # Target IP
    timestamp: str                        # ISO-8601
    evidence: dict[str, Any]             # Key metrics / rule matches
    recommendation: str                   # Analyst guidance
    detector_name: str                    # Originating detector
    dst_port: Optional[int] = None        # Target port if applicable
    protocol: Optional[str] = None        # Associated protocol
    description: str = ""                 # Human-readable summary

    def to_alert_record(self) -> AlertRecord:
        """Convert to a :class:`AlertRecord` for database persistence."""
        import json
        return AlertRecord(
            timestamp=self.timestamp,
            alert_type=self.attack_type,
            severity=self.severity,
            src_ip=self.source_ip,
            dst_ip=self.destination_ip,
            dst_port=self.dst_port,
            protocol=self.protocol,
            description=self.description or f"{self.attack_type} detected by {self.detector_name}",
            raw_evidence=json.dumps(self.evidence, default=str),
        )

    def __repr__(self) -> str:
        return (
            f"SecurityAlert(type={self.attack_type!r}, severity={self.severity!r}, "
            f"src={self.source_ip!r}, confidence={self.confidence:.2f})"
        )


# ──────────────────────────────────────────────────────────────────────────────
# BASE DETECTOR ABSTRACT CLASS
# ──────────────────────────────────────────────────────────────────────────────

class BaseDetector(ABC):
    """
    Abstract base class that all attack detectors must implement.

    Enforces a consistent interface so the RuleEngine can treat all
    detectors polymorphically (Strategy pattern).

    Every detector receives the full analytics context (DataFrame + Phase 3/4
    objects) and is responsible only for its own detection domain.
    No detector may call another detector — they are completely independent.

    Subclasses must implement:
        detect()          — Primary detection logic; returns SecurityAlerts
        generate_alert()  — Construct a SecurityAlert from raw evidence
        confidence_score()— Compute a [0,1] confidence for given evidence
        recommendation()  — Return analyst guidance string for the attack type
    """

    # Detector priority: lower number = higher priority = runs first
    PRIORITY: int = 50

    def __init__(self, name: str, enabled: bool = True) -> None:
        """
        Initialise the detector.

        Args:
            name:    Human-readable detector name (used in alerts).
            enabled: Whether this detector is active (default True).
        """
        self.name: str = name
        self.enabled: bool = enabled
        self.alert_count: int = 0
        log.debug("Detector '%s' initialised (enabled=%s, priority=%d).",
                  name, enabled, self.PRIORITY)

    # ── Abstract Interface ─────────────────────────────────────────────────────

    @abstractmethod
    def detect(
        self,
        df: pd.DataFrame,
        traffic_stats: Optional[Any] = None,
        protocol_analysis: Optional[Any] = None,
        bandwidth_monitor: Optional[Any] = None,
        health_report: Optional[Any] = None,
        db_manager: Optional[DatabaseManager] = None,
        cfg: Optional[Any] = None,
    ) -> list[SecurityAlert]:
        """
        Run detection logic on the supplied packet DataFrame and analytics.

        Args:
            df:                 Parsed packet DataFrame (from packets.csv / DB).
            traffic_stats:      Loaded TrafficStatistics instance.
            protocol_analysis:  Loaded ProtocolAnalysis instance.
            bandwidth_monitor:  Loaded BandwidthMonitor instance.
            health_report:      NetworkHealthReport from Phase 4.
            db_manager:         Optional DatabaseManager for context queries.
            cfg:                Optional configuration override dict.

        Returns:
            List of :class:`SecurityAlert` objects (empty if no threat found).
        """
        ...

    @abstractmethod
    def generate_alert(self, evidence: dict[str, Any], **kwargs) -> SecurityAlert:
        """
        Construct a :class:`SecurityAlert` from raw detection evidence.

        Args:
            evidence: Dict of metrics/rule triggers that justify the alert.
            **kwargs: Attack-type-specific overrides.

        Returns:
            Fully populated :class:`SecurityAlert`.
        """
        ...

    @abstractmethod
    def confidence_score(self, evidence: dict[str, Any]) -> float:
        """
        Compute the detection confidence for a given evidence bundle.

        Args:
            evidence: Rule match metrics from the detection pass.

        Returns:
            Float in [0.0, 1.0] — 1.0 = certainty.
        """
        ...

    @abstractmethod
    def recommendation(self, attack_type: str, evidence: dict[str, Any]) -> str:
        """
        Generate a human-readable analyst recommendation.

        Args:
            attack_type: The specific variant detected.
            evidence:    Supporting metrics.

        Returns:
            Recommendation string for the SOC analyst.
        """
        ...

    # ── Backward-compatibility shim ────────────────────────────────────────────

    def analyse(self, records: list) -> list[AlertRecord]:
        """
        Legacy interface used by the Phase 1 RuleEngine.run() path.

        Detectors may override this, but the preferred Phase 5 path is
        detect() which operates on a DataFrame.

        Args:
            records: List of TrafficRecord dataclass instances.

        Returns:
            Empty list (Phase 1 stub; Phase 5 uses detect()).
        """
        return []

    # ── Shared Utilities ───────────────────────────────────────────────────────

    def reset(self) -> None:
        """Reset internal state. Override in stateful subclasses."""
        self.alert_count = 0

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"name={self.name!r}, enabled={self.enabled}, "
            f"priority={self.PRIORITY})"
        )


# ──────────────────────────────────────────────────────────────────────────────
# RULE ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class RuleEngine:
    """
    Central rule orchestration engine (Phase 5 — fully implemented).

    Manages a registry of :class:`BaseDetector` instances and fans out
    the packet DataFrame and analytics objects to each enabled detector
    in priority order.

    Features:
        - Detector registration with priority ordering
        - Execution pipeline with per-detector error isolation
        - Duplicate alert suppression (same src/type within time window)
        - Alert scoring across the detection pass
        - Result aggregation with overall severity ranking

    Attributes:
        detectors (list[BaseDetector]): Registered detector instances.
        total_alerts (int):             Running total of alerts emitted.

    Example::

        engine = RuleEngine(db_manager=db)
        engine.register(DDoSDetector())
        engine.register(PortScanDetector())
        engine.register(BruteForceDetector())
        engine.register(SYNFloodDetector())

        alerts = engine.run_detection(df, traffic_stats, protocol_analysis, bm)
        print(f"Alerts: {len(alerts)}")
    """

    # Severity ordering for comparison
    _SEVERITY_RANK: dict[str, int] = {
        "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
    }

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        dedup_window_seconds: int = 60,
    ) -> None:
        """
        Initialise the RuleEngine.

        Args:
            db_manager:            Optional :class:`DatabaseManager` for
                                   auto-persisting alerts.
            dedup_window_seconds:  Window (seconds) within which identical
                                   (src_ip, attack_type) pairs are suppressed.
        """
        self.detectors: list[BaseDetector] = []
        self.total_alerts: int = 0
        self._db: Optional[DatabaseManager] = db_manager
        self._dedup_window: int = dedup_window_seconds
        # Maps (src_ip, attack_type) → last alert timestamp (epoch float)
        self._dedup_cache: dict[tuple[str, str], float] = {}
        log.info("RuleEngine initialised (dedup_window=%ds).", dedup_window_seconds)

    # ── Detector Registry ─────────────────────────────────────────────────────

    def register(self, detector: BaseDetector) -> None:
        """
        Register a detector with the engine.

        Detectors are stored in ascending priority order (lowest PRIORITY
        value runs first). Duplicate registrations by name are rejected.

        Args:
            detector: A :class:`BaseDetector` subclass instance.
        """
        if any(d.name == detector.name for d in self.detectors):
            log.warning("Detector '%s' already registered — skipping.", detector.name)
            return
        self.detectors.append(detector)
        # Keep sorted by PRIORITY (ascending = highest priority first)
        self.detectors.sort(key=lambda d: d.PRIORITY)
        log.info("Detector '%s' registered (priority=%d).", detector.name, detector.PRIORITY)

    def unregister(self, name: str) -> bool:
        """
        Remove a detector by name.

        Args:
            name: The detector's name string.

        Returns:
            True if found and removed; False if not found.
        """
        before = len(self.detectors)
        self.detectors = [d for d in self.detectors if d.name != name]
        removed = len(self.detectors) < before
        if removed:
            log.info("Detector '%s' unregistered.", name)
        return removed

    def enable_all(self) -> None:
        """Enable all registered detectors."""
        for d in self.detectors:
            d.enabled = True

    def disable_all(self) -> None:
        """Disable all registered detectors (useful during maintenance)."""
        for d in self.detectors:
            d.enabled = False

    # ── Main Execution Pipeline ───────────────────────────────────────────────

    def run_detection(
        self,
        df: pd.DataFrame,
        traffic_stats: Optional[Any] = None,
        protocol_analysis: Optional[Any] = None,
        bandwidth_monitor: Optional[Any] = None,
        health_report: Optional[Any] = None,
        cfg: Optional[dict] = None,
    ) -> list[SecurityAlert]:
        """
        Fan out the packet DataFrame to all enabled detectors and collect alerts.

        Execution order follows detector PRIORITY (lowest value first).
        Each detector runs in isolation — exceptions are caught and logged
        without aborting the pipeline.

        Duplicate alerts (same source IP + attack type within dedup_window)
        are suppressed to reduce analyst fatigue.

        Args:
            df:                Parsed packet DataFrame.
            traffic_stats:     TrafficStatistics instance (Phase 3).
            protocol_analysis: ProtocolAnalysis instance (Phase 3).
            bandwidth_monitor: BandwidthMonitor instance (Phase 3).
            health_report:     NetworkHealthReport (Phase 4).
            cfg:               Optional configuration override dict.

        Returns:
            Combined, deduplicated list of :class:`SecurityAlert` objects.
        """
        if df is None or df.empty:
            log.warning("RuleEngine.run_detection() called with empty DataFrame.")
            return []

        all_alerts: list[SecurityAlert] = []
        active_detectors = [d for d in self.detectors if d.enabled]

        log.info(
            "RuleEngine executing %d detector(s) on %d packets.",
            len(active_detectors), len(df),
        )

        for detector in active_detectors:
            try:
                t0 = time.perf_counter()
                alerts = detector.detect(
                    df=df,
                    traffic_stats=traffic_stats,
                    protocol_analysis=protocol_analysis,
                    bandwidth_monitor=bandwidth_monitor,
                    health_report=health_report,
                    db_manager=self._db,
                    cfg=cfg,
                )
                elapsed = time.perf_counter() - t0

                # Deduplicate within window
                unique_alerts = self._deduplicate(alerts)
                all_alerts.extend(unique_alerts)
                detector.alert_count += len(unique_alerts)

                log.info(
                    "Detector '%s' completed in %.3fs — %d alert(s) (raw=%d, suppressed=%d).",
                    detector.name, elapsed, len(unique_alerts),
                    len(alerts), len(alerts) - len(unique_alerts),
                )

            except Exception as exc:  # noqa: BLE001
                log.error(
                    "Detector '%s' raised an exception: %s",
                    detector.name, exc, exc_info=True,
                )

        self.total_alerts += len(all_alerts)

        # Persist to database if configured
        if self._db and all_alerts:
            self._persist_alerts(all_alerts)

        log.info(
            "RuleEngine pass complete — %d unique alert(s) across %d detector(s).",
            len(all_alerts), len(active_detectors),
        )
        return all_alerts

    # ── Legacy Interface ───────────────────────────────────────────────────────

    def run(self, records: list) -> list[AlertRecord]:
        """
        Legacy Phase 1 interface. Passes records to detector.analyse().

        Args:
            records: Batch of :class:`TrafficRecord` instances.

        Returns:
            Combined list of :class:`AlertRecord` objects.
        """
        all_alerts: list[AlertRecord] = []
        for detector in self.detectors:
            if not detector.enabled:
                continue
            try:
                alerts = detector.analyse(records)
                all_alerts.extend(alerts)
                detector.alert_count += len(alerts)
            except Exception as exc:
                log.error("Detector '%s' raised an exception: %s", detector.name, exc)
        self.total_alerts += len(all_alerts)
        return all_alerts

    # ── Deduplication ─────────────────────────────────────────────────────────

    def _deduplicate(self, alerts: list[SecurityAlert]) -> list[SecurityAlert]:
        """
        Filter out duplicate alerts within the dedup window.

        An alert is a duplicate if the same (source_ip, attack_type) pair
        was emitted within the last ``_dedup_window`` seconds.

        Args:
            alerts: Raw alerts from a single detector pass.

        Returns:
            Filtered list with duplicates removed.
        """
        now = time.time()
        unique: list[SecurityAlert] = []
        for alert in alerts:
            key = (alert.source_ip, alert.attack_type)
            last_seen = self._dedup_cache.get(key, 0.0)
            if (now - last_seen) >= self._dedup_window:
                unique.append(alert)
                self._dedup_cache[key] = now
            else:
                log.debug(
                    "Suppressed duplicate alert: %s from %s (last=%.0fs ago).",
                    alert.attack_type, alert.source_ip, now - last_seen,
                )
        return unique

    # ── Database Persistence ───────────────────────────────────────────────────

    def _persist_alerts(self, alerts: list[SecurityAlert]) -> None:
        """Bulk-persist SecurityAlerts to the database."""
        for alert in alerts:
            try:
                record = alert.to_alert_record()
                self._db.insert_alert(record)  # type: ignore[union-attr]
            except Exception as exc:
                log.error("Failed to persist alert '%s': %s", alert.alert_id, exc)

    # ── Status & Reporting ────────────────────────────────────────────────────

    def get_status(self) -> list[dict]:
        """
        Return the status of all registered detectors.

        Returns:
            List of status dicts with ``name``, ``enabled``,
            ``alert_count``, ``priority``.
        """
        return [
            {
                "name": d.name,
                "enabled": d.enabled,
                "alert_count": d.alert_count,
                "priority": d.PRIORITY,
            }
            for d in self.detectors
        ]

    def get_highest_severity(self, alerts: list[SecurityAlert]) -> str:
        """
        Return the highest severity level across all provided alerts.

        Args:
            alerts: List of SecurityAlert objects.

        Returns:
            Severity string ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            or "NONE" if the list is empty.
        """
        if not alerts:
            return "NONE"
        return max(
            alerts,
            key=lambda a: self._SEVERITY_RANK.get(a.severity, 0),
        ).severity

    def clear_dedup_cache(self) -> None:
        """Clear the deduplication cache (e.g. between analysis sessions)."""
        self._dedup_cache.clear()
        log.debug("Deduplication cache cleared.")

    def __repr__(self) -> str:
        return (
            f"RuleEngine("
            f"detectors={len(self.detectors)}, "
            f"total_alerts={self.total_alerts})"
        )
