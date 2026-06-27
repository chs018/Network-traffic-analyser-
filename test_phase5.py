"""
test_phase5.py — Phase 5 Intrusion Detection System Validation
===============================================================
Network Traffic Analysis and Intrusion Detection System

Validates the Phase 5 rule-based IDS by:

  1. Loading data/processed/packets.csv (Phase 2 output)
  2. Running all Phase 3 analytics engines (TrafficStatistics, ProtocolAnalysis,
     BandwidthMonitor)
  3. Running Phase 4 health monitor and bottleneck detector
  4. Building and executing the RuleEngine with all four detectors
  5. Passing alerts to the AlertManager for aggregation
  6. Printing the INTRUSION DETECTION REPORT banner

Expected Output:
=====================================
INTRUSION DETECTION REPORT
=====================================
Packets Analysed : 1000
Detectors Loaded : 4
Alerts Generated : X
DDoS Alerts      : X
Port Scan Alerts : X
Brute Force Alerts: X
SYN Flood Alerts  : X
Highest Severity  : MEDIUM/HIGH/CRITICAL
Processing Time   : X sec
=====================================

Exit Codes:
    0  All tests passed
    1  packets.csv not found — run Phase 2 first
    2  Analytics computation error
    3  IDS validation failures

Usage:
    python test_phase5.py
    python test_phase5.py --csv data/processed/packets.csv
    python test_phase5.py --top 10 --link-gbps 1.0 --dedup 30

Author: Network Traffic Analyzer Project
Version: 5.0.0
Python: 3.11+
"""

from __future__ import annotations

import argparse
import io
import sys
import time
import traceback
from pathlib import Path
from typing import Any

# ── Force UTF-8 on Windows ────────────────────────────────────────────────────
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )

# ── Ensure project root is on sys.path ────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from utils.config import config
from utils.logger import get_logger

# Phase 3 analytics
from analysis.traffic_statistics import TrafficStatistics
from analysis.protocol_analysis import ProtocolAnalysis
from analysis.bandwidth_monitor import BandwidthMonitor

# Phase 4 health & bottleneck
from analysis.health_monitor import NetworkHealthMonitor, HealthConfig
from analysis.bottleneck_detector import BottleneckDetector

# Phase 5 IDS pipeline
from detection.rule_engine import RuleEngine, SecurityAlert
from detection.ddos_detector import DDoSDetector
from detection.synflood_detector import SYNFloodDetector
from detection.portscan_detector import PortScanDetector
from detection.bruteforce_detector import BruteForceDetector
from detection.alert_manager import AlertManager

# Database (optional)
from database.db_manager import DatabaseManager

log = get_logger("test_phase5")


# ══════════════════════════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

_W = 53   # Banner width


def _sep(char: str = "=", width: int = _W) -> None:
    print(char * width)


def _header(title: str, char: str = "=", width: int = _W) -> None:
    print(f"\n{char * width}")
    print(f"  {title}")
    print(f"{char * width}")


def _section(title: str, width: int = _W) -> None:
    print(f"\n{'-' * width}")
    print(f"  {title}")
    print(f"{'-' * width}")


def _kv(label: str, value: Any, width: int = 22) -> None:
    print(f"  {label:<{width}}: {value}")


def _severity_icon(sev: str) -> str:
    icons = {
        "LOW": "[L]", "MEDIUM": "[M]",
        "HIGH": "[H]", "CRITICAL": "[!]",
    }
    return icons.get(sev.upper(), "[?]")


def _bar(fraction: float, width: int = 20) -> str:
    """ASCII progress bar."""
    fraction = max(0.0, min(1.0, fraction))
    filled = int(fraction * width)
    return "#" * filled + "." * (width - filled)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — LOAD PHASE 3 ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════

def load_phase3(
    csv_path: Path, top_n: int, link_gbps: float
) -> tuple[TrafficStatistics, ProtocolAnalysis, BandwidthMonitor]:
    """
    Load all three Phase 3 analytics engines from packets.csv.

    Args:
        csv_path:   Path to packets.csv.
        top_n:      Top-N ranked lists size.
        link_gbps:  Reference link speed.

    Returns:
        Tuple of (TrafficStatistics, ProtocolAnalysis, BandwidthMonitor).
    """
    _header("LOADING PHASE 3 ANALYTICS")
    t0 = time.perf_counter()

    ts = TrafficStatistics(top_n=top_n, csv_path=csv_path)
    ts.load_data(source="csv")

    pa = ProtocolAnalysis(top_n=top_n, csv_path=csv_path)
    pa.load_data(source="csv")

    bm = BandwidthMonitor(
        link_speed_bps=link_gbps * 1e9,
        top_n=top_n,
        csv_path=csv_path,
    )
    bm.load_data(source="csv")

    elapsed = time.perf_counter() - t0
    df = ts.get_dataframe()
    _kv("CSV path", csv_path)
    _kv("Packets loaded", len(df))
    _kv("Load time", f"{elapsed:.3f}s")
    print(f"\n  [OK] Phase 3 analytics loaded.")
    return ts, pa, bm


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — PHASE 4 HEALTH & BOTTLENECK
# ══════════════════════════════════════════════════════════════════════════════

def run_phase4(
    ts: TrafficStatistics,
    pa: ProtocolAnalysis,
    bm: BandwidthMonitor,
    link_gbps: float,
) -> dict[str, Any]:
    """
    Run Phase 4 NetworkHealthMonitor and BottleneckDetector.

    Args:
        ts, pa, bm:   Phase 3 analytics objects.
        link_gbps:    Reference link speed.

    Returns:
        Dict with 'health' and 'bottleneck' report dicts.
    """
    _header("RUNNING PHASE 4 ANALYTICS")
    t0 = time.perf_counter()

    # Health monitor
    cfg = HealthConfig(link_speed_bps=link_gbps * 1e9)
    monitor = NetworkHealthMonitor(health_config=cfg)
    health_report = monitor.generate_health_report(ts, pa, bm)

    # Bottleneck detector
    detector = BottleneckDetector(link_speed_bps=link_gbps * 1e9)
    bn_report = detector.generate_bottleneck_report(ts, pa, bm)

    elapsed = time.perf_counter() - t0

    _section("Phase 4 Results")
    _kv("Health Score", f"{health_report.health_score:.1f} / 100")
    _kv("Health Status", health_report.health_status)
    _kv("Bottlenecks", bn_report.event_count)
    _kv("Phase 4 time", f"{elapsed:.3f}s")
    print(f"\n  [OK] Phase 4 analytics complete.")

    return {
        "health": health_report.to_dict(),
        "bottleneck": bn_report.to_dict(),
        "health_report_obj": health_report,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — BUILD AND EXECUTE RULE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def run_ids_pipeline(
    ts: TrafficStatistics,
    pa: ProtocolAnalysis,
    bm: BandwidthMonitor,
    health_report_obj: Any,
    dedup_seconds: int,
    db_manager: DatabaseManager,
    cfg_overrides: dict[str, Any],
) -> tuple[RuleEngine, AlertManager, list[SecurityAlert]]:
    """
    Build the RuleEngine, register all 4 detectors, and execute detection.

    Args:
        ts, pa, bm:         Phase 3 analytics objects.
        health_report_obj:  NetworkHealthReport from Phase 4.
        dedup_seconds:      Alert deduplication window.
        db_manager:         DatabaseManager for persistence.
        cfg_overrides:      Threshold overrides (lowered for CSV data testing).

    Returns:
        Tuple of (RuleEngine, AlertManager, list_of_alerts).
    """
    _header("PHASE 5 — INTRUSION DETECTION ENGINE")

    # ── Build RuleEngine ───────────────────────────────────────────────────
    engine = RuleEngine(
        db_manager=db_manager,
        dedup_window_seconds=dedup_seconds,
    )

    # ── Register all 4 detectors ───────────────────────────────────────────
    engine.register(DDoSDetector(enabled=True, cfg_overrides=cfg_overrides))
    engine.register(SYNFloodDetector(enabled=True, cfg_overrides=cfg_overrides))
    engine.register(PortScanDetector(enabled=True, cfg_overrides=cfg_overrides))
    engine.register(BruteForceDetector(enabled=True, cfg_overrides=cfg_overrides))

    _section("Registered Detectors")
    for status in engine.get_status():
        icon = "[ON]" if status["enabled"] else "[OFF]"
        print(
            f"  {icon} Priority={status['priority']:3d}  {status['name']}"
        )

    # ── Get packet DataFrame from TrafficStatistics ────────────────────────
    df = ts.get_dataframe()
    _kv("Packet DataFrame shape", f"{df.shape[0]} rows × {df.shape[1]} cols")

    # ── Execute detection pipeline ─────────────────────────────────────────
    _section("Running Detection Pipeline")
    t0 = time.perf_counter()
    alerts = engine.run_detection(
        df=df,
        traffic_stats=ts,
        protocol_analysis=pa,
        bandwidth_monitor=bm,
        health_report=health_report_obj,
        cfg=cfg_overrides,
    )
    elapsed = time.perf_counter() - t0
    _kv("Detection time", f"{elapsed:.3f}s")
    _kv("Raw alerts", len(alerts))

    # ── AlertManager: ingest and aggregate ────────────────────────────────
    manager = AlertManager(db_manager=db_manager, dedup_window_seconds=0)
    for alert in alerts:
        manager.add_alert(alert)

    return engine, manager, alerts


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — ALERT DETAIL REPORT
# ══════════════════════════════════════════════════════════════════════════════

def print_alert_details(alerts: list[SecurityAlert]) -> None:
    """Print detail lines for each generated alert."""
    _header("ALERT DETAILS")
    if not alerts:
        print("  No alerts generated — network traffic appears benign.")
        return

    for i, alert in enumerate(alerts, start=1):
        icon = _severity_icon(alert.severity)
        print(
            f"\n  [{i:03d}] {icon} [{alert.severity}] {alert.attack_type}"
        )
        print(f"        Detector : {alert.detector_name}")
        print(f"        Source   : {alert.source_ip}")
        print(f"        Target   : {alert.destination_ip}")
        print(f"        Conf.    : {alert.confidence:.0%}")
        print(f"        Rule     : {alert.evidence.get('rule', 'N/A')}")
        if alert.description:
            print(f"        Desc     : {alert.description[:90]}")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — VISUALIZATION DATA VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def validate_viz_data(manager: AlertManager) -> list[str]:
    """
    Validate all AlertManager visualization methods return expected shapes.

    Args:
        manager: Populated AlertManager.

    Returns:
        List of failure messages. Empty = all passed.
    """
    failures: list[str] = []
    _section("Visualization Data Validation")

    # get_attack_counts()
    try:
        counts = manager.get_attack_counts()
        expected_keys = {"DDoS", "PortScan", "BruteForce", "SYNFlood", "Other"}
        if not expected_keys.issubset(counts.keys()):
            failures.append(
                f"get_attack_counts(): missing keys {expected_keys - set(counts.keys())}"
            )
        if not all(isinstance(v, int) for v in counts.values()):
            failures.append("get_attack_counts(): values must be int.")
        _kv("get_attack_counts()", f"{counts}")
    except Exception as exc:
        failures.append(f"get_attack_counts() raised: {exc}")

    # get_severity_distribution()
    try:
        dist = manager.get_severity_distribution()
        expected_sev = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if not expected_sev.issubset(dist.keys()):
            failures.append(
                f"get_severity_distribution(): missing keys {expected_sev - set(dist.keys())}"
            )
        total = sum(dist.values())
        _kv("get_severity_distribution()", f"{dist} (total={total})")
    except Exception as exc:
        failures.append(f"get_severity_distribution() raised: {exc}")

    # get_attack_timeline()
    try:
        timeline = manager.get_attack_timeline(freq="1min")
        if not isinstance(timeline, dict):
            failures.append("get_attack_timeline(): must return dict.")
        elif "labels" not in timeline or "values" not in timeline:
            failures.append("get_attack_timeline(): missing 'labels' or 'values'.")
        else:
            _kv("get_attack_timeline()", f"{len(timeline['labels'])} time bucket(s)")
    except Exception as exc:
        failures.append(f"get_attack_timeline() raised: {exc}")

    # get_alert_table()
    try:
        df_table = manager.get_alert_table()
        expected_cols = {
            "alert_id", "timestamp", "attack_type", "severity",
            "confidence", "source_ip", "destination_ip",
        }
        if not expected_cols.issubset(df_table.columns):
            failures.append(
                f"get_alert_table(): missing columns {expected_cols - set(df_table.columns)}"
            )
        _kv("get_alert_table() shape", f"{df_table.shape[0]} rows × {df_table.shape[1]} cols")
    except Exception as exc:
        failures.append(f"get_alert_table() raised: {exc}")

    # generate_summary()
    try:
        summary = manager.generate_summary()
        if not isinstance(summary.get("total_alerts"), int):
            failures.append("generate_summary(): total_alerts must be int.")
        if "severity_distribution" not in summary:
            failures.append("generate_summary(): missing severity_distribution.")
        _kv("generate_summary() keys", list(summary.keys()))
    except Exception as exc:
        failures.append(f"generate_summary() raised: {exc}")

    return failures


# ══════════════════════════════════════════════════════════════════════════════
# MASTER IDS REPORT BANNER
# ══════════════════════════════════════════════════════════════════════════════

def print_ids_report(
    df_packet_count: int,
    engine: RuleEngine,
    manager: AlertManager,
    alerts: list[SecurityAlert],
    elapsed_total: float,
) -> None:
    """Print the final INTRUSION DETECTION REPORT banner."""
    counts = manager.get_attack_counts()
    dist = manager.get_severity_distribution()
    highest = manager.get_highest_severity()

    print()
    _sep("=")
    print("  INTRUSION DETECTION REPORT")
    _sep("=")
    print()
    _kv("Packets Analysed", f"{df_packet_count:,}")
    _kv("Detectors Loaded", len(engine.detectors))
    _kv("Alerts Generated", manager.count())
    print()
    _kv("DDoS Alerts", counts.get("DDoS", 0))
    _kv("Port Scan Alerts", counts.get("PortScan", 0))
    _kv("Brute Force Alerts", counts.get("BruteForce", 0))
    _kv("SYN Flood Alerts", counts.get("SYNFlood", 0))
    print()
    _kv("LOW Alerts", dist.get("LOW", 0))
    _kv("MEDIUM Alerts", dist.get("MEDIUM", 0))
    _kv("HIGH Alerts", dist.get("HIGH", 0))
    _kv("CRITICAL Alerts", dist.get("CRITICAL", 0))
    print()
    _kv("Highest Severity", highest)
    _kv("Processing Time", f"{elapsed_total:.3f} sec")
    print()
    _sep("=")

    # Per-detector summary
    _section("Detector Summary")
    for status in engine.get_status():
        icon = "[ON]" if status["enabled"] else "[OFF]"
        print(
            f"  {icon} {status['name']:<28} {status['alert_count']:>3} alert(s)"
        )


# ══════════════════════════════════════════════════════════════════════════════
# VALIDATION CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def _validate_ids(
    engine: RuleEngine,
    manager: AlertManager,
    alerts: list[SecurityAlert],
    df_packet_count: int,
) -> list[str]:
    """
    Run sanity checks on the IDS output.

    Returns:
        List of failure messages. Empty = all checks passed.
    """
    failures: list[str] = []

    # Check 4 detectors were registered
    if len(engine.detectors) != 4:
        failures.append(
            f"Expected 4 detectors, got {len(engine.detectors)}."
        )

    # All detectors enabled
    disabled = [d.name for d in engine.detectors if not d.enabled]
    if disabled:
        failures.append(f"Detectors disabled unexpectedly: {disabled}")

    # Alerts must be SecurityAlert instances
    for alert in alerts:
        from detection.rule_engine import SecurityAlert as SA
        if not isinstance(alert, SA):
            failures.append(f"Alert is not a SecurityAlert: {type(alert)}")
            break

    # Alert fields required
    for alert in alerts:
        if not alert.alert_id:
            failures.append(f"Alert missing alert_id: {alert}")
        if alert.severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            failures.append(f"Invalid severity '{alert.severity}' in alert {alert.alert_id}")
        if not (0.0 <= alert.confidence <= 1.0):
            failures.append(
                f"Confidence {alert.confidence} out of range in alert {alert.alert_id}"
            )
        if not alert.detector_name:
            failures.append(f"Alert missing detector_name: {alert}")
        if not alert.recommendation:
            failures.append(f"Alert missing recommendation: {alert}")
        if not alert.evidence:
            failures.append(f"Alert missing evidence: {alert}")

    # Manager count matches alert list
    if manager.count() != len(alerts):
        failures.append(
            f"AlertManager count ({manager.count()}) ≠ alerts list length ({len(alerts)})."
        )

    # DataFrame packet count must be positive
    if df_packet_count <= 0:
        failures.append(f"DataFrame packet count must be > 0, got {df_packet_count}.")

    return failures


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Phase 5 Test — Rule-Based Intrusion Detection System\n"
            "Validates DDoSDetector, SYNFloodDetector, "
            "PortScanDetector, BruteForceDetector."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python test_phase5.py\n"
            "  python test_phase5.py --csv data/processed/packets.csv\n"
            "  python test_phase5.py --top 10 --link-gbps 1.0 --dedup 30\n"
        ),
    )
    parser.add_argument(
        "--csv", "-c",
        type=str, default=None,
        help="Path to packets.csv (default: data/processed/packets.csv).",
    )
    parser.add_argument(
        "--top", "-n",
        type=int, default=10,
        help="Top-N ranked list size (default: 10).",
    )
    parser.add_argument(
        "--link-gbps",
        type=float, default=1.0,
        help="Nominal link speed in Gbps (default: 1.0).",
    )
    parser.add_argument(
        "--dedup",
        type=int, default=0,
        help="Alert deduplication window in seconds (default: 0 = no dedup).",
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Skip database persistence.",
    )
    return parser.parse_args()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    """Main entry point. Returns exit code."""
    args = parse_args()

    # ── Resolve CSV path ───────────────────────────────────────────────────
    csv_path = Path(args.csv) if args.csv else (
        config.paths.processed_data_dir / "packets.csv"
    )

    # ── Pre-flight check ───────────────────────────────────────────────────
    _header("PHASE 5 IDS VALIDATION", "=")
    print(f"\n  CSV Source  : {csv_path}")
    print(f"  Top-N       : {args.top}")
    print(f"  Link Speed  : {args.link_gbps} Gbps")
    print(f"  Dedup Window: {args.dedup}s")

    if not csv_path.exists():
        print(
            f"\n  [FAIL] packets.csv not found: {csv_path}\n"
            "     Run Phase 2 first:\n"
            "       python test_phase2.py --generate\n"
        )
        log.error("packets.csv not found: %s", csv_path)
        return 1

    config.initialise_directories()
    total_start = time.perf_counter()

    # ── Database ───────────────────────────────────────────────────────────
    db_manager: DatabaseManager | None = None
    if not args.no_db:
        try:
            db_manager = DatabaseManager()
            db_manager.initialise()
            log.info("Database initialised at: %s", config.paths.database_path)
        except Exception as exc:
            log.warning("Could not initialise database: %s — continuing without DB.", exc)
            db_manager = None

    # ── Lowered thresholds for CSV test data ──────────────────────────────
    # Real-world CSV data from packets.csv is typically benign with few
    # packets, so we lower thresholds to exercise all detection rules.
    cfg_overrides: dict[str, Any] = {
        # DDoS — lower thresholds for test data
        "ddos_packets_per_second": 5,          # flag at 5 pps
        "ddos_bytes_per_second": 50_000,       # flag at 50 KB/s
        "ddos_unique_src_ips": 3,              # flag at 3 unique sources
        # Port scan — flag at 5 unique ports
        "portscan_unique_ports": 5,
        "portscan_syn_ratio": 0.50,
        # Brute force — flag at 3 attempts
        "bruteforce_failed_attempts": 3,
        "bruteforce_rapid_rate": 0.5,
        "bruteforce_spray_targets": 3,
        # SYN flood — lower thresholds
        "synflood_syn_per_second": 5.0,
        "synflood_syn_ack_ratio": 0.50,
        "synflood_syn_dominance": 0.40,
        "synflood_half_open_limit": 10,
    }

    try:
        # ── Phase 3 ───────────────────────────────────────────────────────
        ts, pa, bm = load_phase3(csv_path, args.top, args.link_gbps)
        df = ts.get_dataframe()
        df_packet_count = len(df)

        # ── Phase 4 ───────────────────────────────────────────────────────
        phase4_results = run_phase4(ts, pa, bm, args.link_gbps)
        health_report_obj = phase4_results["health_report_obj"]

        # ── Phase 5 IDS pipeline ──────────────────────────────────────────
        engine, manager, alerts = run_ids_pipeline(
            ts=ts,
            pa=pa,
            bm=bm,
            health_report_obj=health_report_obj,
            dedup_seconds=args.dedup,
            db_manager=db_manager,
            cfg_overrides=cfg_overrides,
        )

    except FileNotFoundError as exc:
        print(f"\n  [FAIL] File not found: {exc}\n")
        log.error("FileNotFoundError: %s", exc)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"\n  [FAIL] Runtime error: {exc}\n")
        log.error("Unexpected Phase 5 error:\n%s", traceback.format_exc())
        return 2

    elapsed_total = time.perf_counter() - total_start

    # ── Alert details ──────────────────────────────────────────────────────
    print_alert_details(alerts)

    # ── Visualization data checks ──────────────────────────────────────────
    viz_failures = validate_viz_data(manager)

    # ── IDS validation ─────────────────────────────────────────────────────
    ids_failures = _validate_ids(engine, manager, alerts, df_packet_count)

    all_failures = viz_failures + ids_failures

    if all_failures:
        _header("VALIDATION FAILURES", "!")
        for msg in all_failures:
            print(f"  [FAIL] {msg}")
        print(f"\n  {len(all_failures)} validation error(s) found.\n")
        log.error("Phase 5 validation failed: %d error(s).", len(all_failures))
        return 3

    # ── Final IDS Report Banner ────────────────────────────────────────────
    print_ids_report(df_packet_count, engine, manager, alerts, elapsed_total)

    # ── Phase 4 backward compat ────────────────────────────────────────────
    _section("Phase 4 Health Summary (context)")
    h = phase4_results["health"]
    _kv("Health Score",    f"{h.get('health_score', 0):.0f}")
    _kv("Health Status",   h.get("health_status", "Unknown"))
    _kv("Bottlenecks",     phase4_results["bottleneck"].get("event_count", 0))

    # ── Sign-off ───────────────────────────────────────────────────────────
    print()
    _sep()
    print("  [OK] All Phase 5 Tests Completed Successfully")
    _sep()
    print()

    log.info(
        "Phase 5 test complete in %.3fs — "
        "Packets=%d, Detectors=%d, Alerts=%d, Highest=%s.",
        elapsed_total,
        df_packet_count,
        len(engine.detectors),
        manager.count(),
        manager.get_highest_severity(),
    )
    return 0


# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sys.exit(main())
