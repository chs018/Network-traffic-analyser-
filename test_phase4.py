"""
test_phase4.py — Phase 4 Network Health & Bottleneck Detection Test
====================================================================
Network Traffic Analysis and Intrusion Detection System

Validates the Phase 4 analytics engine by loading the Phase 2 output
(data/processed/packets.csv) and running all modules in sequence:

  1. TrafficStatistics   (Phase 3 — data foundation)
  2. ProtocolAnalysis    (Phase 3 — protocol breakdown)
  3. BandwidthMonitor    (Phase 3 — throughput metrics)
  4. NetworkHealthMonitor (Phase 4 — health scoring)
  5. BottleneckDetector   (Phase 4 — congestion detection)
  6. NetworkQualityAnalyzer (Phase 4 — quality estimation)

Expected Exit Codes:
    0  All tests passed
    1  packets.csv not found — run Phase 2 first
    2  Analytics computation error
    3  Validation failures

Usage:
    python test_phase4.py
    python test_phase4.py --csv data/processed/packets.csv
    python test_phase4.py --top 10 --link-gbps 1.0

Author: Network Traffic Analyzer Project
Version: 4.0.0
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

# Phase 3
from analysis.traffic_statistics import TrafficStatistics
from analysis.protocol_analysis import ProtocolAnalysis
from analysis.bandwidth_monitor import BandwidthMonitor

# Phase 4
from analysis.health_monitor import NetworkHealthMonitor, HealthConfig
from analysis.bottleneck_detector import BottleneckDetector, Severity
from analysis.network_quality import NetworkQualityAnalyzer

log = get_logger("test_phase4")


# ============================================================================
# DISPLAY HELPERS
# ============================================================================

_W = 64  # Print width


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


def _kv(label: str, value: Any, width: int = 28) -> None:
    print(f"  {label:<{width}}: {value}")


def _format_bytes(byte_count: float) -> str:
    """Human-readable byte count."""
    for unit in ["B", "KB", "MB", "GB"]:
        if byte_count < 1024:
            return f"{byte_count:.1f} {unit}"
        byte_count /= 1024
    return f"{byte_count:.1f} TB"


def _bar(fraction: float, width: int = 24) -> str:
    """ASCII progress bar."""
    fraction = max(0.0, min(1.0, fraction))
    filled = int(fraction * width)
    return "#" * filled + "." * (width - filled)


def _severity_icon(sev: str) -> str:
    icons = {"LOW": "[L]", "MEDIUM": "[M]", "HIGH": "[H]", "CRITICAL": "[!]"}
    return icons.get(sev, "[?]")


# ============================================================================
# SECTION 1 — PHASE 3 DATA LOADING
# ============================================================================

def load_phase3_analytics(
    csv_path: Path, top_n: int, link_gbps: float
) -> tuple[TrafficStatistics, ProtocolAnalysis, BandwidthMonitor]:
    """
    Instantiate and load all three Phase 3 analytics engines.

    Returns:
        Tuple of loaded (TrafficStatistics, ProtocolAnalysis, BandwidthMonitor).
    """
    _header("LOADING PHASE 3 ANALYTICS ENGINES")
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
    _kv("CSV Path", csv_path)
    _kv("Phase 3 Load Time", f"{elapsed:.3f}s")
    print(f"\n  [OK] Phase 3 engines loaded.")
    return ts, pa, bm


# ============================================================================
# SECTION 2 — NETWORK HEALTH MONITOR
# ============================================================================

def run_health_monitor(
    ts: TrafficStatistics,
    pa: ProtocolAnalysis,
    bm: BandwidthMonitor,
    link_gbps: float,
) -> dict[str, Any]:
    """
    Run NetworkHealthMonitor and print a formatted health report.

    Returns:
        The raw report dictionary.
    """
    _header("SECTION 1 -- NETWORK HEALTH MONITOR")
    t0 = time.perf_counter()

    cfg = HealthConfig(link_speed_bps=link_gbps * 1e9)
    monitor = NetworkHealthMonitor(health_config=cfg)
    report = monitor.generate_health_report(ts, pa, bm)
    elapsed = time.perf_counter() - t0

    report_dict = report.to_dict()

    # ── Overall Health ─────────────────────────────────────────────────────
    _section("Overall Network Health")
    score = report.health_score
    bar = _bar(score / 100)
    print(f"\n  Health Score : {score:.1f} / 100   {bar}")
    print(f"  Health Status: {report.health_status}")
    print()

    # ── Key Metrics ────────────────────────────────────────────────────────
    _section("Key Health Metrics")
    _kv("Bandwidth Utilisation", f"{report.bandwidth_utilisation_pct:.4f}%")
    _kv("Packets / Second", f"{report.packets_per_second:.2f} pps")
    _kv("Bytes / Second", f"{_format_bytes(report.bytes_per_second)}/s")
    _kv("Avg Packet Size", f"{report.avg_packet_size:.1f} bytes")
    _kv("Malformed Packets", f"{report.malformed_pct:.1f}%")
    _kv("Protocol Entropy", f"{report.protocol_diversity_entropy:.4f} bits")
    _kv("Unique Source Hosts", report.unique_hosts)
    _kv("Traffic Stability", report.traffic_stability)
    _kv("Packet Growth Rate", f"{report.packet_growth_rate:+.4f}")

    # ── Component Scores ───────────────────────────────────────────────────
    _section("Health Component Scores")
    print(f"  {'Component':<26} {'Score':>6} {'Status':<10} {'Detail'}")
    print(f"  {'-'*26} {'-'*6} {'-'*10} {'-'*20}")
    for c in report.components:
        print(
            f"  {c.name:<26} {c.score:>6.1f} {c.status:<10} {c.detail[:45]}"
        )

    # ── Issues & Recommendations ──────────────────────────────────────────
    if report.issues:
        _section("Active Issues")
        for issue in report.issues:
            print(f"  {issue}")

    if report.recommendations:
        _section("Recommendations")
        for rec in report.recommendations:
            print(f"  -> {rec}")

    # ── Visualization Data ─────────────────────────────────────────────────
    gauge = monitor.get_gauge_data(report)
    line = monitor.get_line_chart_data(report)
    heatmap_df = monitor.get_heatmap_data(report)
    alert_df = monitor.get_alert_table(report)
    _section("Visualization Data Shapes")
    _kv("Gauge chart ready", f"value={gauge['value']:.1f}, color={gauge['color']}")
    _kv("Line chart series", f"{len(line['labels'])} components")
    _kv("Heatmap rows", len(heatmap_df))
    _kv("Alert table rows", len(alert_df))
    _kv("Computed in", f"{elapsed:.3f}s")

    print(f"\n  [OK] Network Health Monitor -- PASSED")
    log.info("NetworkHealthMonitor complete in %.3fs. Score=%.1f (%s).",
             elapsed, report.health_score, report.health_status)
    return report_dict


# ============================================================================
# SECTION 3 — BOTTLENECK DETECTOR
# ============================================================================

def run_bottleneck_detector(
    ts: TrafficStatistics,
    pa: ProtocolAnalysis,
    bm: BandwidthMonitor,
    link_gbps: float,
) -> dict[str, Any]:
    """
    Run BottleneckDetector and print a formatted report.

    Returns:
        The raw report dictionary.
    """
    _header("SECTION 2 -- BOTTLENECK DETECTOR")
    t0 = time.perf_counter()

    detector = BottleneckDetector(
        link_speed_bps=link_gbps * 1e9,
        bw_warn_pct=0.60,
        bw_critical_pct=0.90,
        spike_zscore_threshold=3.0,
        spike_iqr_multiplier=1.5,
        protocol_dominance_pct=0.80,
        host_concentration_pct=0.70,
        packet_size_iqr_mult=3.0,
        pps_warn=50_000.0,
        pps_critical=500_000.0,
        queue_growth_window=3,
    )
    report = detector.generate_bottleneck_report(ts, pa, bm)
    elapsed = time.perf_counter() - t0
    report_dict = report.to_dict()

    # ── Summary ────────────────────────────────────────────────────────────
    _section("Bottleneck Summary")
    _kv("Total Checks Run", report.total_checks)
    _kv("Events Detected", report.event_count)
    _kv("Max Severity", report.max_severity.value if report.max_severity else "NONE")
    _kv("CRITICAL Events", report.critical_count)
    _kv("HIGH Events", report.high_count)

    # ── Event List ─────────────────────────────────────────────────────────
    if report.events:
        _section("Detected Bottleneck Events")
        for ev in report.events:
            icon = _severity_icon(ev.severity.value)
            print(f"  {icon} [{ev.severity.value}] {ev.check_name}")
            print(f"      Desc : {ev.description[:70]}")
            print(f"      Rec  : {ev.recommendation[:70]}")
            if ev.metric_name:
                print(f"      Metric: {ev.metric_name} = {ev.metric_value:.4f} "
                      f"(threshold={ev.threshold_value:.4f})")
            print()
    else:
        _section("Bottleneck Events")
        print("  No bottleneck events detected — network operating normally.")

    # ── Severity Distribution ─────────────────────────────────────────────
    bar_data = detector.get_bar_chart_data(report)
    _section("Severity Distribution")
    for sev, count in zip(bar_data["labels"], bar_data["values"]):
        bar = _bar(count / max(max(bar_data["values"]), 1))
        print(f"  {sev:<10} {count:>4}  {bar}")

    # ── Visualization Data ─────────────────────────────────────────────────
    alert_df = detector.get_alert_table(report)
    heatmap_df = detector.get_heatmap_data(report)
    _section("Visualization Data Shapes")
    _kv("Alert table rows", len(alert_df))
    _kv("Heatmap rows", len(heatmap_df))
    _kv("Computed in", f"{elapsed:.3f}s")

    # ── Phase 1 backward-compat smoke test ────────────────────────────────
    _section("Phase 1 Compat Smoke Test")
    legacy_events = detector.detect(
        __import__("pandas").DataFrame(), bps=1_200_000_000 / 8
    )
    _kv("Legacy detect() triggered", f"{len(legacy_events)} event(s)")

    print(f"\n  [OK] Bottleneck Detector -- PASSED")
    log.info("BottleneckDetector complete in %.3fs. %d event(s).", elapsed, report.event_count)
    return report_dict


# ============================================================================
# SECTION 4 — NETWORK QUALITY ANALYZER
# ============================================================================

def run_quality_analyzer(
    ts: TrafficStatistics,
    pa: ProtocolAnalysis,
    bm: BandwidthMonitor,
    link_gbps: float,
) -> dict[str, Any]:
    """
    Run NetworkQualityAnalyzer and print a formatted report.

    Returns:
        The raw report dictionary.
    """
    _header("SECTION 3 -- NETWORK QUALITY ANALYZER")
    t0 = time.perf_counter()

    qa = NetworkQualityAnalyzer(link_speed_bps=link_gbps * 1e9)
    report = qa.generate_quality_report(ts, pa, bm)
    elapsed = time.perf_counter() - t0
    report_dict = report.to_dict()

    # ── Overall Quality ────────────────────────────────────────────────────
    _section("Overall Network Quality")
    bar = _bar(report.quality_index / 100)
    print(f"\n  Quality Index : {report.quality_index:.1f} / 100   {bar}")
    print(f"  Quality Level : {report.quality_level}")
    print()

    # ── Dimension Scores ───────────────────────────────────────────────────
    _section("Quality Dimensions")
    print(f"  {'Dimension':<32} {'Score':>6} {'Quality':<12} {'Proxy Value'}")
    print(f"  {'-'*32} {'-'*6} {'-'*12} {'-'*14}")
    for d in report.dimensions:
        print(
            f"  {d.name:<32} {d.score:>6.1f} {d.quality:<12} "
            f"{d.proxy_metric}={d.proxy_value:.4f}"
        )

    # ── Individual Scores ──────────────────────────────────────────────────
    _section("Component Scores")
    _kv("Latency Score", f"{report.latency_score:.1f}")
    _kv("Congestion Score", f"{report.congestion_score:.1f}")
    _kv("Delivery Efficiency", f"{report.delivery_efficiency:.1f}")
    _kv("Traffic Balance Score", f"{report.traffic_balance_score:.1f}")
    _kv("Stability Score", f"{report.stability_score:.1f}")

    # ── Notes ──────────────────────────────────────────────────────────────
    if report.notes:
        _section("Quality Notes")
        for note in report.notes:
            print(f"  -> {note[:80]}")

    # ── Visualization Data ─────────────────────────────────────────────────
    gauge = qa.get_gauge_data(report)
    line = qa.get_line_chart_data(report)
    heatmap_df = qa.get_heatmap_data(report)
    alert_df = qa.get_alert_table(report)
    _section("Visualization Data Shapes")
    _kv("Gauge chart ready", f"value={gauge['value']:.1f}, level={gauge['level']}")
    _kv("Line chart series", f"{len(line['labels'])} dimensions")
    _kv("Heatmap rows", len(heatmap_df))
    _kv("Alert/notes rows", len(alert_df))
    _kv("Computed in", f"{elapsed:.3f}s")

    print(f"\n  [OK] Network Quality Analyzer -- PASSED")
    log.info(
        "NetworkQualityAnalyzer complete in %.3fs. Index=%.1f (%s).",
        elapsed, report.quality_index, report.quality_level,
    )
    return report_dict


# ============================================================================
# VALIDATION CHECKS
# ============================================================================

def _validate_reports(
    health: dict[str, Any],
    bottleneck: dict[str, Any],
    quality: dict[str, Any],
) -> list[str]:
    """
    Run basic sanity checks on the three Phase 4 report dictionaries.

    Returns:
        List of failure messages. Empty list = all checks passed.
    """
    failures: list[str] = []

    # Health checks
    if not (0.0 <= health.get("health_score", -1) <= 100.0):
        failures.append("Health: health_score must be in [0, 100].")
    if health.get("health_status") not in (
        "Excellent", "Good", "Moderate", "Poor", "Critical"
    ):
        failures.append(f"Health: unexpected health_status '{health.get('health_status')}'.")
    if not isinstance(health.get("components"), list) or not health["components"]:
        failures.append("Health: components must be a non-empty list.")

    # Bottleneck checks
    if bottleneck.get("total_checks", 0) <= 0:
        failures.append("Bottleneck: total_checks must be > 0.")
    if not isinstance(bottleneck.get("events"), list):
        failures.append("Bottleneck: events must be a list.")
    if bottleneck.get("event_count", -1) < 0:
        failures.append("Bottleneck: event_count must be >= 0.")

    # Quality checks
    if not (0.0 <= quality.get("quality_index", -1) <= 100.0):
        failures.append("Quality: quality_index must be in [0, 100].")
    if quality.get("quality_level") not in ("Excellent", "Good", "Fair", "Poor"):
        failures.append(f"Quality: unexpected quality_level '{quality.get('quality_level')}'.")
    if not isinstance(quality.get("dimensions"), list) or not quality["dimensions"]:
        failures.append("Quality: dimensions must be a non-empty list.")

    return failures


# ============================================================================
# MASTER SUMMARY BANNER
# ============================================================================

def _print_master_summary(
    health: dict[str, Any],
    bottleneck: dict[str, Any],
    quality: dict[str, Any],
    elapsed_total: float,
) -> None:
    """Print the final NETWORK HEALTH REPORT summary banner."""
    _header("NETWORK HEALTH REPORT", "=")
    print()
    _kv("Health Score",        f"{health.get('health_score', 0):.0f}")
    _kv("Status",              health.get("health_status", "Unknown"))
    print()
    _kv("Bandwidth Utilisation", f"{health.get('bandwidth_utilisation_pct', 0):.2f}%")
    _kv("Traffic Stability",    health.get("traffic_stability", "Unknown"))
    _kv("Protocol Health",      _proto_health_label(health))
    print()
    _kv("Network Quality Index", f"{quality.get('quality_index', 0):.0f}")
    _kv("Quality Level",         quality.get("quality_level", "Unknown"))
    print()
    _kv("Bottlenecks Detected",  bottleneck.get("event_count", 0))
    _kv("Warnings (MEDIUM+)",   _count_warnings(bottleneck))
    print()
    _kv("Total Run Time",        f"{elapsed_total:.3f}s")
    print()


def _proto_health_label(health: dict) -> str:
    """Map malformed % to protocol health label."""
    malformed = health.get("malformed_pct", 0.0)
    if malformed < 5:
        return "Good"
    if malformed < 15:
        return "Moderate"
    return "Poor"


def _count_warnings(bottleneck: dict) -> int:
    """Count events with severity MEDIUM or above."""
    return sum(
        1 for e in bottleneck.get("events", [])
        if e.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")
    )


# ============================================================================
# CLI
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Phase 4 Test — Network Health & Bottleneck Detection Engine\n"
            "Validates NetworkHealthMonitor, BottleneckDetector, NetworkQualityAnalyzer."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python test_phase4.py\n"
            "  python test_phase4.py --csv data/processed/packets.csv\n"
            "  python test_phase4.py --top 10 --link-gbps 0.1\n"
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
        help="Number of top-N items in ranked lists (default: 10).",
    )
    parser.add_argument(
        "--link-gbps",
        type=float, default=1.0,
        help="Nominal link speed in Gbps for utilisation scoring (default: 1.0).",
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point. Returns exit code."""
    args = parse_args()

    # ── Resolve CSV path ────────────────────────────────────────────────────
    csv_path = Path(args.csv) if args.csv else (
        config.paths.processed_data_dir / "packets.csv"
    )

    # ── Pre-flight ──────────────────────────────────────────────────────────
    _header("PHASE 4 HEALTH & BOTTLENECK ENGINE -- VALIDATION", "=")
    print(f"\n  CSV Source  : {csv_path}")
    print(f"  Top-N       : {args.top}")
    print(f"  Link Speed  : {args.link_gbps} Gbps")

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

    # ── Run all analytics ───────────────────────────────────────────────────
    try:
        ts, pa, bm = load_phase3_analytics(csv_path, args.top, args.link_gbps)

        health_report   = run_health_monitor(ts, pa, bm, args.link_gbps)
        bn_report       = run_bottleneck_detector(ts, pa, bm, args.link_gbps)
        quality_report  = run_quality_analyzer(ts, pa, bm, args.link_gbps)

    except FileNotFoundError as exc:
        print(f"\n  [FAIL] File not found: {exc}\n")
        log.error("FileNotFoundError: %s", exc)
        return 1

    except Exception as exc:  # noqa: BLE001
        print(f"\n  [FAIL] Runtime error: {exc}\n")
        log.error("Unexpected Phase 4 error:\n%s", traceback.format_exc())
        return 2

    elapsed_total = time.perf_counter() - total_start

    # ── Validation ──────────────────────────────────────────────────────────
    failures = _validate_reports(health_report, bn_report, quality_report)
    if failures:
        _header("VALIDATION FAILURES", "!")
        for msg in failures:
            print(f"  [FAIL] {msg}")
        print(f"\n  {len(failures)} validation error(s) found.\n")
        log.error("Phase 4 validation failed: %d error(s).", len(failures))
        return 3

    # ── Master Summary ──────────────────────────────────────────────────────
    _print_master_summary(health_report, bn_report, quality_report, elapsed_total)

    _sep()
    print("  [OK] All Phase 4 Tests Completed Successfully")
    _sep()
    print()

    log.info(
        "Phase 4 test complete in %.3fs — Health=%.1f (%s), Quality=%.1f (%s), "
        "Bottlenecks=%d.",
        elapsed_total,
        health_report.get("health_score", 0),
        health_report.get("health_status", "?"),
        quality_report.get("quality_index", 0),
        quality_report.get("quality_level", "?"),
        bn_report.get("event_count", 0),
    )
    return 0


# ============================================================================

if __name__ == "__main__":
    sys.exit(main())
