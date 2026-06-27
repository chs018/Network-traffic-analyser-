"""
test_phase3.py -- Phase 3 Analytics Integration Test
=====================================================
Network Traffic Analysis and Intrusion Detection System

Validates the Phase 3 analytics engine by loading the Phase 2 output
(data/processed/packets.csv) and running all three analytics modules:

  1. TrafficStatistics   -- Overall traffic insights
  2. ProtocolAnalysis    -- Protocol breakdown and distribution
  3. BandwidthMonitor    -- Bandwidth utilisation and throughput

Expected Console Output
-----------------------
================================
PHASE 3 ANALYTICS REPORT
================================
Total Packets      : <N>
Unique Source IPs  : <N>
Unique Dest IPs    : <N>
Average Packet Size: <F> bytes
...

Exit Codes
----------
    0  All analytics modules passed
    1  packets.csv not found (run Phase 2 first)
    2  Analytics computation error
    3  Unexpected error

Usage
-----
    python test_phase3.py
    python test_phase3.py --csv path/to/packets.csv
    python test_phase3.py --top 15

Author: Network Traffic Analyzer Project
Version: 3.0.0
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

# Force UTF-8 stdout on Windows to handle box-drawing chars gracefully
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )

# -- Ensure project root on sys.path ------------------------------------------
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from utils.config import config
from utils.logger import get_logger
from analysis.traffic_statistics import TrafficStatistics
from analysis.protocol_analysis import ProtocolAnalysis
from analysis.bandwidth_monitor import BandwidthMonitor

log = get_logger("test_phase3")


# ============================================================================
# DISPLAY HELPERS
# ============================================================================

_W = 60   # default print width

def _sep(char: str = "=", width: int = _W) -> None:
    """Print a horizontal separator line."""
    print(char * width)


def _header(title: str, char: str = "=", width: int = _W) -> None:
    """Print a framed section header."""
    print(f"\n{char * width}")
    print(f"  {title}")
    print(f"{char * width}")


def _section(title: str, width: int = _W) -> None:
    """Print a sub-section divider."""
    print(f"\n{'-' * width}")
    print(f"  {title}")
    print(f"{'-' * width}")


def _kv(label: str, value: Any, width: int = 24) -> None:
    """Print a key-value pair with consistent alignment."""
    print(f"  {label:<{width}}: {value}")


def _format_bytes(byte_count: int) -> str:
    """Human-readable byte size."""
    for unit in ["B", "KB", "MB", "GB"]:
        if byte_count < 1024:
            return f"{byte_count:.1f} {unit}"
        byte_count /= 1024
    return f"{byte_count:.1f} TB"


def _bar(fraction: float, width: int = 24) -> str:
    """Render an ASCII progress bar using basic characters."""
    fraction = max(0.0, min(1.0, fraction))
    filled = int(fraction * width)
    return "#" * filled + "." * (width - filled)


# ============================================================================
# SECTION 1 -- TRAFFIC STATISTICS
# ============================================================================

def run_traffic_statistics(csv_path: Path, top_n: int) -> dict[str, Any]:
    """
    Run TrafficStatistics analytics and print a formatted report.

    Args:
        csv_path: Path to packets.csv.
        top_n:    Number of top IPs to display.

    Returns:
        The raw report dictionary.
    """
    _header("SECTION 1 -- TRAFFIC STATISTICS")
    t0 = time.perf_counter()

    ts = TrafficStatistics(top_n=top_n, csv_path=csv_path)
    ts.load_data(source="csv")
    report = ts.to_report_dict()
    elapsed = time.perf_counter() - t0

    # Basic metrics
    _section("Basic Metrics")
    _kv("Total Packets", f"{report['total_packets']:,}")
    _kv("Total Bytes", _format_bytes(report["total_bytes"]))
    _kv("Capture Duration", f"{report['capture_duration_seconds']:.2f} s")
    _kv("Packets / Second", f"{report['packets_per_second']:.2f}")
    _kv("Bytes / Second", f"{report['bytes_per_second']:.2f}")
    _kv("Capture Start", str(report["capture_start"])[:26] or "N/A")
    _kv("Capture End", str(report["capture_end"])[:26] or "N/A")

    # IP insights
    _section("IP Statistics")
    _kv("Unique Source IPs", report["unique_src_ips"])
    _kv("Unique Dest IPs", report["unique_dst_ips"])

    # Packet size distribution
    _section("Packet Size Distribution")
    _kv("Average Size", f"{report['avg_packet_size']} bytes")
    _kv("Min Size", f"{report['min_packet_size']} bytes")
    _kv("Max Size", f"{report['max_packet_size']} bytes")
    _kv("Median Size", f"{report['median_packet_size']} bytes")
    _kv("Std Deviation", f"{report['std_packet_size']} bytes")

    # Top source IPs
    top_src = report.get("top_source_ips", [])
    if top_src:
        _section(f"Top {top_n} Source IPs")
        max_count = top_src[0][1] if top_src else 1
        for ip, count in top_src:
            bar = _bar(count / max(max_count, 1))
            print(f"  {ip:<20} {count:>6,} pkt  {bar}")

    # Top destination IPs
    top_dst = report.get("top_destination_ips", [])
    if top_dst:
        _section(f"Top {top_n} Destination IPs")
        max_count = top_dst[0][1] if top_dst else 1
        for ip, count in top_dst:
            bar = _bar(count / max(max_count, 1))
            print(f"  {ip:<20} {count:>6,} pkt  {bar}")

    # Chart-ready data validation
    bar_data = ts.get_bar_chart_data("top_src_ips")
    pie_data = ts.get_pie_chart_data("protocol_distribution")
    line_data = ts.get_line_chart_data("packet_timeline")
    _section("Visualization Data Shapes")
    _kv("Bar chart labels", len(bar_data["labels"]))
    _kv("Pie chart labels", len(pie_data["labels"]))
    _kv("Line chart points", len(line_data["labels"]))
    _kv("Computed in", f"{elapsed:.3f}s")

    print(f"\n  [OK] Traffic Statistics -- PASSED")
    log.info("TrafficStatistics validation complete in %.3fs.", elapsed)
    return report


# ============================================================================
# SECTION 2 -- PROTOCOL ANALYSIS
# ============================================================================

def run_protocol_analysis(csv_path: Path, top_n: int) -> dict[str, Any]:
    """
    Run ProtocolAnalysis and print a formatted report.

    Args:
        csv_path: Path to packets.csv.
        top_n:    Number of top protocols to display.

    Returns:
        The raw report dictionary.
    """
    _header("SECTION 2 -- PROTOCOL ANALYSIS")
    t0 = time.perf_counter()

    pa = ProtocolAnalysis(top_n=top_n, csv_path=csv_path)
    pa.load_data(source="csv")
    report = pa.to_report_dict()
    elapsed = time.perf_counter() - t0

    # Protocol counts
    _section("Protocol Overview")
    _kv("Total Packets", f"{report['total_packets']:,}")
    _kv("Distinct Protocols", report["total_protocols"])

    # Key percentages
    _section("Key Protocol Percentages")
    key_protos = [
        ("TCP", report["tcp_pct"]),
        ("UDP", report["udp_pct"]),
        ("ICMP", report["icmp_pct"]),
        ("ARP", report["arp_pct"]),
        ("HTTP", report["http_pct"]),
        ("HTTPS", report["https_pct"]),
        ("DNS", report["dns_pct"]),
        ("NTP", report["ntp_pct"]),
        ("MALFORMED", report["malformed_pct"]),
        ("UNKNOWN", report["unknown_pct"]),
    ]
    for proto, pct in key_protos:
        bar = _bar(pct / 100)
        print(f"  {proto:<12} {pct:>6.2f}%  {bar}")

    # Protocol distribution table
    proto_dist = report.get("protocol_distribution", {})
    if proto_dist:
        _section(f"All Protocols (sorted by volume, top {top_n + 5})")
        total = report["total_packets"] or 1
        for proto, count in sorted(proto_dist.items(), key=lambda x: -x[1])[:top_n + 5]:
            pct = count / total * 100
            bar = _bar(pct / 100)
            print(f"  {proto:<22} {count:>6,}  ({pct:5.1f}%)  {bar}")

    # Transport distribution
    transport_dist = report.get("transport_distribution", {})
    if transport_dist:
        _section("Transport Layer Distribution")
        for proto, count in sorted(transport_dist.items(), key=lambda x: -x[1]):
            pct = count / (report["total_packets"] or 1) * 100
            print(f"  {proto:<12} {count:>6,}  ({pct:.1f}%)")

    # Application layer distribution
    app_dist = report.get("application_distribution", {})
    if app_dist:
        _section("Application Layer Distribution (by port)")
        for app, count in sorted(app_dist.items(), key=lambda x: -x[1])[:top_n]:
            print(f"  {app:<16} {count:>6,}")

    # Top protocol ranking
    top_protocols = report.get("top_protocols", [])
    if top_protocols:
        _section("Top Protocol Ranking")
        print(f"  {'Rank':<6} {'Protocol':<22} {'Packets':>8} {'Pct (%)':>8}")
        print(f"  {'-'*6} {'-'*22} {'-'*8} {'-'*8}")
        for p in top_protocols[:top_n]:
            print(
                f"  #{p['rank']:<5} {p['protocol']:<22} {p['packet_count']:>8,} "
                f"{p['percentage']:>7.2f}%"
            )

    # Chart-ready data validation
    bar_data = pa.get_bar_chart_data("protocol_distribution")
    pie_data = pa.get_pie_chart_data("transport_layer")
    line_data = pa.get_line_chart_data()
    _section("Visualization Data Shapes")
    _kv("Bar chart labels", len(bar_data["labels"]))
    _kv("Pie chart labels", len(pie_data["labels"]))
    _kv("Line chart points", len(line_data["labels"]))
    _kv("Computed in", f"{elapsed:.3f}s")

    print(f"\n  [OK] Protocol Analysis -- PASSED")
    log.info("ProtocolAnalysis validation complete in %.3fs.", elapsed)
    return report


# ============================================================================
# SECTION 3 -- BANDWIDTH MONITOR
# ============================================================================

def run_bandwidth_monitor(csv_path: Path, top_n: int) -> dict[str, Any]:
    """
    Run BandwidthMonitor analytics and print a formatted report.

    Args:
        csv_path: Path to packets.csv.
        top_n:    Number of peak intervals to display.

    Returns:
        The raw report dictionary.
    """
    _header("SECTION 3 -- BANDWIDTH MONITOR")
    t0 = time.perf_counter()

    bm = BandwidthMonitor(
        link_speed_bps=1_000_000_000.0,   # 1 Gbps reference
        top_n=top_n,
        csv_path=csv_path,
    )
    bm.load_data(source="csv")
    report = bm.to_report_dict()
    elapsed = time.perf_counter() - t0

    # Aggregate metrics
    _section("Aggregate Metrics")
    _kv("Total Bytes", _format_bytes(report["total_bytes"]))
    _kv("Total Packets", f"{report['total_packets']:,}")
    _kv("Capture Duration", f"{report['capture_duration_seconds']:.2f} s")
    _kv("Avg Bytes/Second", f"{report['avg_bytes_per_second']:.2f} B/s")
    _kv("Peak Bytes/Second", f"{report['peak_bytes_per_second']:.2f} B/s")
    _kv("Avg Packets/Second", f"{report['avg_packets_per_second']:.2f} pps")
    _kv("Peak Packets/Second", f"{report['peak_packets_per_second']:.2f} pps")
    _kv(
        "BW Utilisation",
        f"{report['bandwidth_utilisation_pct']:.4f}% (of 1 Gbps link)",
    )

    # Peak intervals
    top_intervals = report.get("top_intervals", [])
    if top_intervals:
        _section(f"Top {top_n} Busiest Intervals (per minute)")
        print(
            f"  {'Timestamp':<32} {'Bytes':>10} {'Packets':>8} "
            f"{'B/s':>12} {'pps':>8}"
        )
        print(f"  {'-'*32} {'-'*10} {'-'*8} {'-'*12} {'-'*8}")
        for iv in top_intervals:
            ts_short = str(iv["timestamp"])[:26]
            print(
                f"  {ts_short:<32} {iv['bytes']:>10,} {iv['packets']:>8,} "
                f"{iv['bps']:>12.2f} {iv['pps']:>8.2f}"
            )

    # Chart-ready data validation
    bar_data = bm.get_bar_chart_data("bytes_per_minute")
    pie_data = bm.get_pie_chart_data("protocol_bytes")
    line_data = bm.get_line_chart_data("bytes_per_minute")
    _section("Visualization Data Shapes")
    _kv("Bar chart labels", len(bar_data["labels"]))
    _kv("Pie chart labels", len(pie_data["labels"]))
    _kv("Line chart points", len(line_data["labels"]))
    _kv("Computed in", f"{elapsed:.3f}s")

    # Live-capture API smoke test
    _section("Live-Capture API Smoke Test (ring-buffer)")
    bm.reset()
    sample = bm.record(bytes_count=50_000, packet_count=100, interface="eth0")
    _kv("Sample B/s", f"{sample.bytes_per_second:.0f}")
    _kv("Sample pps", f"{sample.packets_per_second:.0f}")
    _kv("Sample util%", f"{sample.utilisation_pct:.4f}%")
    _kv("Current util%", f"{bm.current_utilisation():.4f}%")
    _kv("Average BPS", f"{bm.average_bps():.0f}")

    print(f"\n  [OK] Bandwidth Monitor -- PASSED")
    log.info("BandwidthMonitor validation complete in %.3fs.", elapsed)
    return report


# ============================================================================
# VALIDATION CHECKS
# ============================================================================

def _validate_reports(
    traffic_report: dict[str, Any],
    protocol_report: dict[str, Any],
    bandwidth_report: dict[str, Any],
) -> list[str]:
    """
    Run basic sanity checks on the three report dictionaries.

    Returns:
        List of failure messages. An empty list means all checks passed.
    """
    failures: list[str] = []

    # Traffic checks
    if traffic_report.get("total_packets", 0) <= 0:
        failures.append("TrafficStatistics: total_packets must be > 0")
    if traffic_report.get("avg_packet_size", 0) <= 0:
        failures.append("TrafficStatistics: avg_packet_size must be > 0")
    if not isinstance(traffic_report.get("top_source_ips"), list):
        failures.append("TrafficStatistics: top_source_ips must be a list")

    # Protocol checks
    if protocol_report.get("total_protocols", 0) <= 0:
        failures.append("ProtocolAnalysis: total_protocols must be > 0")
    if not isinstance(protocol_report.get("protocol_distribution"), dict):
        failures.append("ProtocolAnalysis: protocol_distribution must be a dict")

    # Bandwidth checks
    if bandwidth_report.get("total_bytes", 0) <= 0:
        failures.append("BandwidthMonitor: total_bytes must be > 0")
    if bandwidth_report.get("avg_bytes_per_second", 0) < 0:
        failures.append("BandwidthMonitor: avg_bytes_per_second must be >= 0")
    if not isinstance(bandwidth_report.get("top_intervals"), list):
        failures.append("BandwidthMonitor: top_intervals must be a list")

    return failures


# ============================================================================
# MASTER SUMMARY BANNER
# ============================================================================

def _print_master_summary(
    traffic_report: dict[str, Any],
    protocol_report: dict[str, Any],
    bandwidth_report: dict[str, Any],
    elapsed_total: float,
) -> None:
    """Print the final PHASE 3 ANALYTICS REPORT summary banner."""
    # Top protocol by packet count
    proto_dist = traffic_report.get("protocol_distribution", {})
    top_proto = (
        max(proto_dist, key=proto_dist.get)
        if proto_dist
        else "N/A"
    )
    total_pkts = max(traffic_report.get("total_packets", 1), 1)
    top_proto_pct = round(
        proto_dist.get(top_proto, 0) / total_pkts * 100, 1
    )

    # Top source IP
    top_src = traffic_report.get("top_source_ips", [])
    top_src_ip = top_src[0][0] if top_src else "N/A"

    _header("PHASE 3 ANALYTICS REPORT  --  SUMMARY", "=")
    print()
    _kv("Total Packets",       f"{traffic_report.get('total_packets', 0):,}")
    _kv("Unique Source IPs",   traffic_report.get("unique_src_ips", 0))
    _kv("Unique Dest IPs",     traffic_report.get("unique_dst_ips", 0))
    print()
    _kv("Average Packet Size",
        f"{traffic_report.get('avg_packet_size', 0):.1f} bytes")
    _kv("Min / Max Packet",
        f"{traffic_report.get('min_packet_size', 0)} / "
        f"{traffic_report.get('max_packet_size', 0)} bytes")
    print()
    _kv("Top Protocol",        f"{top_proto} ({top_proto_pct:.1f}%)")
    _kv("Total Protocols",     protocol_report.get("total_protocols", 0))
    print()
    _kv("Total Bytes",         _format_bytes(bandwidth_report.get("total_bytes", 0)))
    _kv("Avg Throughput",
        f"{bandwidth_report.get('avg_bytes_per_second', 0):.2f} B/s")
    _kv("Peak Throughput",
        f"{bandwidth_report.get('peak_bytes_per_second', 0):.2f} B/s")
    _kv("BW Utilisation",
        f"{bandwidth_report.get('bandwidth_utilisation_pct', 0):.4f}%")
    print()
    _kv("Top Source IP",       top_src_ip)
    _kv("Total Run Time",      f"{elapsed_total:.3f}s")
    print()


# ============================================================================
# CLI
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Phase 3 Test -- Network Traffic Analytics Engine\n"
            "Validates TrafficStatistics, ProtocolAnalysis, BandwidthMonitor."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python test_phase3.py\n"
            "  python test_phase3.py --csv data/processed/packets.csv\n"
            "  python test_phase3.py --top 15\n"
        ),
    )
    parser.add_argument(
        "--csv", "-c",
        type=str,
        default=None,
        help=(
            "Path to packets.csv (default: data/processed/packets.csv). "
            "Run test_phase2.py first to generate this file."
        ),
    )
    parser.add_argument(
        "--top", "-n",
        type=int,
        default=10,
        help="Number of top-N items in ranked lists (default: 10).",
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Resolve CSV path
    if args.csv:
        csv_path = Path(args.csv)
    else:
        csv_path = config.paths.processed_data_dir / "packets.csv"

    # -- Pre-flight check -----------------------------------------------------
    _header("PHASE 3 ANALYTICS ENGINE -- VALIDATION", "=")
    print(f"\n  CSV Source : {csv_path}")
    print(f"  Top-N      : {args.top}")

    if not csv_path.exists():
        print(
            f"\n  [FAIL] packets.csv not found at: {csv_path}\n"
            "     Run Phase 2 pipeline first:\n"
            "       python test_phase2.py --generate\n"
        )
        log.error("packets.csv not found: %s", csv_path)
        return 1

    config.initialise_directories()
    total_start = time.perf_counter()

    # -- Run all three analytics modules --------------------------------------
    try:
        traffic_report = run_traffic_statistics(csv_path, args.top)
        protocol_report = run_protocol_analysis(csv_path, args.top)
        bandwidth_report = run_bandwidth_monitor(csv_path, args.top)

    except FileNotFoundError as exc:
        print(f"\n  [FAIL] File not found: {exc}\n")
        log.error("FileNotFoundError in analytics: %s", exc)
        return 1

    except Exception as exc:  # noqa: BLE001
        print(f"\n  [FAIL] Analytics error: {exc}\n")
        log.error(
            "Unexpected error in Phase 3 analytics:\n%s", traceback.format_exc()
        )
        return 2

    elapsed_total = time.perf_counter() - total_start

    # -- Validation checks ----------------------------------------------------
    failures = _validate_reports(traffic_report, protocol_report, bandwidth_report)
    if failures:
        _header("VALIDATION FAILURES", "!")
        for msg in failures:
            print(f"  [FAIL] {msg}")
        print(f"\n  {len(failures)} validation error(s) found.\n")
        log.error("Phase 3 validation failed: %d error(s).", len(failures))
        return 2

    # -- Master summary -------------------------------------------------------
    _print_master_summary(
        traffic_report, protocol_report, bandwidth_report, elapsed_total
    )

    _sep()
    print("  [OK] Analytics Completed Successfully")
    _sep()
    print()

    log.info(
        "Phase 3 test complete: %d packets analysed in %.3fs.",
        traffic_report.get("total_packets", 0),
        elapsed_total,
    )
    return 0


# ============================================================================

if __name__ == "__main__":
    sys.exit(main())
