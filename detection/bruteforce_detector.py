"""
bruteforce_detector.py — Brute Force Login Attack Detector
============================================================
Network Traffic Analysis and Intrusion Detection System

Detects brute-force credential attacks by monitoring repeated connection
attempts to authentication services. No machine learning — pure
deterministic rules. Every alert is fully explainable.

Detection Rules:
  1. Service Attack     — attempts from same host to same (dst_ip, dst_port)
                          exceed threshold within time window
  2. Credential Spray   — attempts from same host across many (dst_ip, port)
                          tuples (password spray pattern)
  3. Rapid Reconnect    — very high connection rate to auth port signals
                          automated tooling (Hydra, Medusa, etc.)

Monitored Services (default):
  SSH   (22)  |  FTP (21)  |  RDP (3389)
  HTTP  (80)  |  HTTPS (443)  |  SMTP (25/587/465)
  POP3  (110) |  IMAP (143)   |  MySQL (3306)
  PostgreSQL (5432)

Classes:
    ServiceTarget       — Frozen dataclass identifying a target flow
    BruteForceTracker   — Per-flow attempt statistics
    BruteForceDetector  — BaseDetector implementation (Phase 5)

Author: Network Traffic Analyzer Project
Version: 5.0.0
Python: 3.11+
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

import pandas as pd

from database.db_manager import AlertRecord, DatabaseManager
from detection.rule_engine import BaseDetector, SecurityAlert
from utils.config import config
from utils.helpers import port_to_service, utc_now_iso
from utils.logger import get_detection_logger

log = get_detection_logger()


# ──────────────────────────────────────────────────────────────────────────────
# DATACLASSES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ServiceTarget:
    """
    Immutable key identifying a unique attacker → service flow.

    Used as a dict key in the BruteForceDetector tracker map.
    """

    src_ip: str
    dst_ip: str
    dst_port: int


@dataclass
class BruteForceTracker:
    """Tracks brute-force attempt statistics for a single ServiceTarget."""

    target: ServiceTarget
    attempt_count: int = 0
    connection_rate: float = 0.0    # connections per second
    first_seen: str = ""
    last_seen: str = ""
    duration_seconds: float = 0.0
    alerted: bool = False            # Prevent duplicate alerts per session
    avg_packet_size: float = 0.0
    tcp_syn_count: int = 0
    tcp_ack_count: int = 0


# ──────────────────────────────────────────────────────────────────────────────
# BRUTE FORCE DETECTOR
# ──────────────────────────────────────────────────────────────────────────────

class BruteForceDetector(BaseDetector):
    """
    Rule-based brute-force login attack detector.

    Maintains per-flow attempt counters derived from the packet DataFrame
    and fires alerts when:
      1. Attempts to the same (src_ip, dst_ip, dst_port) exceed the threshold
      2. A single source attacks many different auth ports (credential spray)
      3. Connection rate to an auth port is abnormally high

    The detector is stateless across calls — each detect() runs a fresh
    analysis of the supplied DataFrame.
    """

    PRIORITY: int = 30   # Third in pipeline

    # Default authentication port set (built from config + well-known extras)
    _DEFAULT_AUTH_PORTS: frozenset[int] = frozenset({
        21, 22, 23, 25, 80, 110, 143, 389, 443, 445,
        465, 587, 993, 995, 3306, 3389, 5432, 5900,
        6379, 8080, 8443,
    })

    def __init__(
        self,
        enabled: bool = True,
        cfg_overrides: Optional[dict[str, Any]] = None,
        custom_ports: Optional[set[int]] = None,
    ) -> None:
        """
        Initialise the BruteForceDetector.

        Args:
            enabled:       Whether the detector is active.
            cfg_overrides: Optional dict to override threshold values.
            custom_ports:  Additional ports to monitor beyond defaults.
        """
        super().__init__(name="Brute Force Detector", enabled=enabled)
        self._thresholds = config.thresholds
        self._overrides: dict[str, Any] = cfg_overrides or {}
        self._trackers: dict[ServiceTarget, BruteForceTracker] = {}

        # Build monitored port set from config + defaults
        config_ports: set[int] = {
            self._thresholds.bruteforce_ssh_port,
            self._thresholds.bruteforce_rdp_port,
            self._thresholds.bruteforce_ftp_port,
            self._thresholds.bruteforce_http_port,
            self._thresholds.bruteforce_https_port,
            587, 465, 110, 143, 3306, 5432,
        }
        extra = custom_ports or set()
        self._monitored_ports: frozenset[int] = frozenset(
            config_ports | self._DEFAULT_AUTH_PORTS | extra
        )

        log.debug(
            "BruteForceDetector initialised. Monitoring %d ports.",
            len(self._monitored_ports),
        )

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
        Run brute-force detection rules on the packet DataFrame.

        Args:
            df:  Parsed packet DataFrame with columns:
                 src_ip, dst_ip, dst_port, timestamp,
                 packet_length, tcp_flags (optional).

        Returns:
            List of :class:`SecurityAlert` objects.
        """
        if df is None or df.empty:
            log.debug("BruteForceDetector: empty DataFrame — skipping.")
            return []

        required = {"src_ip", "dst_ip", "dst_port"}
        if not required.issubset(df.columns):
            log.debug(
                "BruteForceDetector: missing columns %s.",
                required - set(df.columns),
            )
            return []

        overrides = cfg or self._overrides
        attempt_threshold = int(
            overrides.get("bruteforce_failed_attempts",
                          self._thresholds.bruteforce_failed_attempts)
        )
        # Rapid-reconnect: connections/second threshold for automation detection
        rapid_rate_threshold = float(overrides.get("bruteforce_rapid_rate", 2.0))
        # Spray: unique service targets from one source
        spray_threshold = int(overrides.get("bruteforce_spray_targets", 5))

        alerts: list[SecurityAlert] = []

        # Filter to authentication ports only
        df_auth = self._filter_auth_traffic(df)
        if df_auth.empty:
            log.debug("BruteForceDetector: no traffic to monitored auth ports.")
            return []

        # Build per-flow trackers
        self._trackers = self._build_trackers(df_auth)

        # ── Rule 1: Service Brute Force (per-flow attempt threshold) ───────
        for target, tracker in self._trackers.items():
            if tracker.attempt_count >= attempt_threshold and not tracker.alerted:
                service = port_to_service(target.dst_port)
                evidence = {
                    "rule": "SERVICE_BRUTEFORCE",
                    "service": service,
                    "dst_port": target.dst_port,
                    "attempt_count": tracker.attempt_count,
                    "threshold": attempt_threshold,
                    "connection_rate": round(tracker.connection_rate, 3),
                    "first_seen": tracker.first_seen,
                    "last_seen": tracker.last_seen,
                    "duration_seconds": round(tracker.duration_seconds, 2),
                    "avg_packet_size": round(tracker.avg_packet_size, 1),
                }
                severity = self._rate_severity(
                    tracker.attempt_count / attempt_threshold
                )
                confidence = self.confidence_score(evidence)
                alerts.append(self.generate_alert(
                    evidence=evidence,
                    attack_type=f"BruteForce-{service.upper()}",
                    severity=severity,
                    confidence=confidence,
                    source_ip=target.src_ip,
                    destination_ip=target.dst_ip,
                    dst_port=target.dst_port,
                ))
                tracker.alerted = True
                log.warning(
                    "Brute force [%s] from %s → %s:%d — %d attempts.",
                    service.upper(), target.src_ip, target.dst_ip,
                    target.dst_port, tracker.attempt_count,
                )

        # ── Rule 2: Credential Spray (one source → many service targets) ───
        spray_alerts = self._detect_spray(
            df_auth, spray_threshold, attempt_threshold
        )
        alerts.extend(spray_alerts)

        # ── Rule 3: Rapid Reconnect (automated tooling signature) ─────────
        rapid_alerts = self._detect_rapid_reconnect(
            df_auth, rapid_rate_threshold, attempt_threshold
        )
        alerts.extend(rapid_alerts)

        return alerts

    def generate_alert(
        self,
        evidence: dict[str, Any],
        attack_type: str = "BruteForce",
        severity: str = "HIGH",
        confidence: float = 0.80,
        source_ip: str = "UNKNOWN",
        destination_ip: str = "UNKNOWN",
        dst_port: Optional[int] = None,
        **kwargs,
    ) -> SecurityAlert:
        """
        Construct a brute-force :class:`SecurityAlert`.

        Args:
            evidence:       Supporting detection metrics.
            attack_type:    Specific variant (e.g. BruteForce-SSH).
            severity:       LOW | MEDIUM | HIGH | CRITICAL.
            confidence:     Detection confidence [0, 1].
            source_ip:      Attacking source IP.
            destination_ip: Target host IP.
            dst_port:       Target service port.

        Returns:
            Fully populated :class:`SecurityAlert`.
        """
        service = evidence.get("service", "UNKNOWN")
        attempts = evidence.get("attempt_count", evidence.get("total_attempts", 0))
        rate = evidence.get("connection_rate", 0)
        rule = evidence.get("rule", "UNKNOWN")

        description = (
            f"{attack_type} detected [{rule}]: "
            f"{source_ip} → {destination_ip}:{dst_port or '?'} ({service}). "
            f"{attempts} connection(s). "
            f"Rate={rate:.2f}/s. Confidence={confidence:.0%}."
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
            dst_port=dst_port,
            protocol="TCP",
            description=description,
        )

    def confidence_score(self, evidence: dict[str, Any]) -> float:
        """
        Compute brute-force detection confidence.

        Factors:
          - Attempt count relative to threshold
          - Connection rate (high rate → automated tool → higher confidence)
          - Duration (sustained attack → higher confidence)

        Args:
            evidence: Detection evidence dict.

        Returns:
            Float in [0.0, 1.0].
        """
        rule = evidence.get("rule", "")
        base = 0.65

        if rule == "SERVICE_BRUTEFORCE":
            attempts = evidence.get("attempt_count", 0)
            threshold = evidence.get("threshold", 10)
            ratio = attempts / max(threshold, 1)
            base = min(0.97, 0.60 + 0.25 * min(ratio - 1, 5) / 5)
            # Corroborate: high rate → automated tool
            rate = evidence.get("connection_rate", 0)
            if rate >= 5.0:
                base = min(0.99, base + 0.04)
            # Corroborate: sustained attack
            duration = evidence.get("duration_seconds", 0)
            if duration >= 30:
                base = min(0.99, base + 0.03)

        elif rule == "CREDENTIAL_SPRAY":
            targets = evidence.get("unique_targets", 0)
            threshold = evidence.get("spray_threshold", 5)
            ratio = targets / max(threshold, 1)
            base = min(0.95, 0.60 + 0.25 * min(ratio - 1, 3) / 3)

        elif rule == "RAPID_RECONNECT":
            rate = evidence.get("connection_rate", 0)
            thr = evidence.get("rate_threshold", 2)
            ratio = rate / max(thr, 1)
            base = min(0.94, 0.60 + 0.25 * min(ratio - 1, 4) / 4)

        return round(base, 3)

    def recommendation(self, attack_type: str, evidence: dict[str, Any]) -> str:
        """
        Return an analyst recommendation for the brute-force variant.

        Args:
            attack_type: Attack type string.
            evidence:    Supporting metrics.

        Returns:
            Actionable recommendation string.
        """
        src = evidence.get("src_ip", "the source IP")
        service = evidence.get("service", "the service")
        port = evidence.get("dst_port", "")
        rule = evidence.get("rule", "")
        attempts = evidence.get("attempt_count", evidence.get("total_attempts", 0))

        if rule == "CREDENTIAL_SPRAY":
            return (
                f"Block {src} immediately — credential spray targeting multiple services. "
                f"Enforce MFA on all authentication endpoints. "
                f"Investigate whether any attempts succeeded (check auth logs). "
                f"Add src IP to threat intelligence blocklist."
            )
        if rule == "RAPID_RECONNECT":
            return (
                f"Block {src} — automated brute-force tool signature detected "
                f"(high reconnect rate to port {port}). "
                f"Enable account lockout policy. "
                f"Consider Fail2ban or similar rate-limiting for {service}."
            )
        # SERVICE_BRUTEFORCE
        return (
            f"Block {src} at firewall (port {port}/{service}). "
            f"{attempts} connection attempts detected. "
            f"Enable account lockout after 5 failed attempts. "
            f"Enforce SSH key authentication / disable password auth for SSH. "
            f"Enable MFA for RDP/VPN. "
            f"Review {service} authentication logs for successful compromise."
        )

    # ── Internal Detection Helpers ────────────────────────────────────────────

    def _filter_auth_traffic(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Filter the DataFrame to rows targeting monitored auth ports.

        Uses vectorised Pandas isin() for O(n) performance.

        Args:
            df: Full packet DataFrame.

        Returns:
            Filtered DataFrame (may be empty).
        """
        dst_port_series = pd.to_numeric(df["dst_port"], errors="coerce")
        mask = dst_port_series.isin(self._monitored_ports)
        return df[mask].copy()

    def _build_trackers(
        self, df_auth: pd.DataFrame
    ) -> dict[ServiceTarget, BruteForceTracker]:
        """
        Build per-flow BruteForceTracker objects via vectorised groupby.

        Groups by (src_ip, dst_ip, dst_port) and counts packet attempts.

        Args:
            df_auth: DataFrame filtered to auth port traffic.

        Returns:
            Dict mapping ServiceTarget → BruteForceTracker.
        """
        trackers: dict[ServiceTarget, BruteForceTracker] = {}

        timestamps: Optional[pd.Series] = None
        if "timestamp" in df_auth.columns:
            timestamps = pd.to_datetime(
                df_auth["timestamp"], errors="coerce", utc=True
            )

        grp_cols = ["src_ip", "dst_ip", "dst_port"]
        for keys, group in df_auth.groupby(grp_cols, sort=False):
            src_ip, dst_ip, dst_port = str(keys[0]), str(keys[1]), int(keys[2])
            target = ServiceTarget(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port)
            tracker = BruteForceTracker(target=target)
            tracker.attempt_count = len(group)

            if "packet_length" in group.columns:
                tracker.avg_packet_size = float(
                    group["packet_length"].fillna(0).mean()
                )

            if timestamps is not None:
                ts_grp = timestamps.loc[group.index].dropna()
                if len(ts_grp) >= 2:
                    duration = (ts_grp.max() - ts_grp.min()).total_seconds()
                    tracker.duration_seconds = duration
                    tracker.first_seen = str(ts_grp.min())
                    tracker.last_seen = str(ts_grp.max())
                    if duration > 0:
                        tracker.connection_rate = tracker.attempt_count / duration

            if "tcp_flags" in group.columns:
                flags = group["tcp_flags"].fillna("0")

                def _flag(f: Any, mask: int) -> bool:
                    try:
                        return bool(int(str(f), 0) & mask)
                    except (ValueError, TypeError):
                        return False

                tracker.tcp_syn_count = int(
                    flags.map(lambda f: _flag(f, 0x02)).sum()
                )
                tracker.tcp_ack_count = int(
                    flags.map(lambda f: _flag(f, 0x10)).sum()
                )

            trackers[target] = tracker

        return trackers

    def _detect_spray(
        self,
        df_auth: pd.DataFrame,
        spray_threshold: int,
        min_attempts: int,
    ) -> list[SecurityAlert]:
        """
        Detect credential spray: one source → many (dst, port) combinations.

        Args:
            df_auth:          Auth-filtered DataFrame.
            spray_threshold:  Minimum unique service targets to trigger.
            min_attempts:     Minimum total attempts to avoid noise.

        Returns:
            List of spray SecurityAlerts.
        """
        alerts: list[SecurityAlert] = []

        for src_ip, group in df_auth.groupby("src_ip", sort=False):
            if len(group) < min_attempts:
                continue
            # Unique (dst_ip, dst_port) service targets
            unique_targets = group.groupby(["dst_ip", "dst_port"]).ngroups
            if unique_targets >= spray_threshold:
                services_hit = (
                    group["dst_port"]
                    .dropna()
                    .astype(int)
                    .map(port_to_service)
                    .unique()
                    .tolist()
                )
                evidence = {
                    "rule": "CREDENTIAL_SPRAY",
                    "src_ip": str(src_ip),
                    "unique_targets": unique_targets,
                    "spray_threshold": spray_threshold,
                    "total_attempts": len(group),
                    "services_targeted": services_hit[:10],
                }
                confidence = self.confidence_score(evidence)
                alerts.append(self.generate_alert(
                    evidence=evidence,
                    attack_type="BruteForce-CredentialSpray",
                    severity="HIGH",
                    confidence=confidence,
                    source_ip=str(src_ip),
                    destination_ip="MULTIPLE",
                ))
                log.warning(
                    "Credential spray from %s: %d unique service targets.",
                    src_ip, unique_targets,
                )
        return alerts

    def _detect_rapid_reconnect(
        self,
        df_auth: pd.DataFrame,
        rate_threshold: float,
        min_attempts: int,
    ) -> list[SecurityAlert]:
        """
        Detect rapid reconnect: automated tooling signature.

        Automated brute-force tools like Hydra/Medusa reconnect very fast
        (>2 connections/second to the same auth port).

        Args:
            df_auth:        Auth-filtered DataFrame.
            rate_threshold: Connections/second to trigger.
            min_attempts:   Minimum absolute attempts to reduce noise.

        Returns:
            List of rapid-reconnect SecurityAlerts.
        """
        alerts: list[SecurityAlert] = []

        for target, tracker in self._trackers.items():
            if tracker.alerted:
                continue   # Already alerted via Rule 1
            if (
                tracker.connection_rate >= rate_threshold
                and tracker.attempt_count >= min_attempts
            ):
                service = port_to_service(target.dst_port)
                evidence = {
                    "rule": "RAPID_RECONNECT",
                    "service": service,
                    "dst_port": target.dst_port,
                    "connection_rate": round(tracker.connection_rate, 3),
                    "rate_threshold": rate_threshold,
                    "attempt_count": tracker.attempt_count,
                    "duration_seconds": round(tracker.duration_seconds, 2),
                    "first_seen": tracker.first_seen,
                    "last_seen": tracker.last_seen,
                }
                confidence = self.confidence_score(evidence)
                alerts.append(self.generate_alert(
                    evidence=evidence,
                    attack_type=f"BruteForce-RapidReconnect",
                    severity="MEDIUM",
                    confidence=confidence,
                    source_ip=target.src_ip,
                    destination_ip=target.dst_ip,
                    dst_port=target.dst_port,
                ))
                log.warning(
                    "Rapid reconnect from %s → %s:%d at %.2f/s.",
                    target.src_ip, target.dst_ip, target.dst_port,
                    tracker.connection_rate,
                )
        return alerts

    @staticmethod
    def _rate_severity(ratio: float) -> str:
        """Map attempt ratio (observed / threshold) to severity label."""
        if ratio >= 10.0:
            return "CRITICAL"
        if ratio >= 5.0:
            return "HIGH"
        if ratio >= 2.0:
            return "MEDIUM"
        return "LOW"

    def reset(self) -> None:
        """Clear all trackers and reset counter."""
        super().reset()
        self._trackers.clear()

    # ── Legacy Compatibility ───────────────────────────────────────────────────

    def _build_alert(
        self,
        tracker: BruteForceTracker,
        severity: str = "HIGH",
    ) -> AlertRecord:
        """
        Legacy method — construct an AlertRecord (Phase 1 API).

        Retained for backward compatibility. New code should use generate_alert().
        """
        import json
        target = tracker.target
        service = port_to_service(target.dst_port)
        desc = (
            f"Brute-force attack detected: {target.src_ip} → "
            f"{target.dst_ip}:{target.dst_port} ({service}). "
            f"{tracker.attempt_count} attempts in window."
        )
        return AlertRecord(
            timestamp=utc_now_iso(),
            alert_type="BruteForce",
            severity=severity,
            src_ip=target.src_ip,
            dst_ip=target.dst_ip,
            dst_port=target.dst_port,
            protocol="TCP",
            description=desc,
            raw_evidence=json.dumps({
                "service": service,
                "attempts": tracker.attempt_count,
                "first_seen": tracker.first_seen,
                "last_seen": tracker.last_seen,
            }),
        )
