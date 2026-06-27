"""
test_phase2.py — Phase 2 Integration Test Script
=================================================
Network Traffic Analysis and Intrusion Detection System

End-to-end test of the Phase 2 packet ingestion pipeline:

  PCAP File
    ↓  PcapReader
    ↓  PacketParser
    ↓  FeatureExtractor
    ↓  DataFrame
    ↓  SQLite (traffic_logs)
    ↓  CSV Export (data/processed/packets.csv)
    ↓  Summary Statistics

Usage
-----
    # With a real PCAP file:
    python test_phase2.py --pcap data/raw/sample.pcap

    # Auto-generate a synthetic PCAP for testing (requires Scapy):
    python test_phase2.py --generate

    # Quiet mode (no banner):
    python test_phase2.py --pcap data/raw/sample.pcap --quiet

Exit Codes
----------
    0   All pipeline steps succeeded
    1   PCAP file not found or invalid
    2   PyShark / TShark not available
    3   Unexpected pipeline error

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from __future__ import annotations

import argparse
import sys
import time
import traceback
from pathlib import Path
from typing import Optional

# ── Ensure project root is on sys.path ────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ── Phase 1 Infrastructure ────────────────────────────────────────────────────
from utils.config import config
from utils.logger import get_logger

log = get_logger("test_phase2")

# ── Phase 2 Pipeline ──────────────────────────────────────────────────────────
from capture.pcap_reader import PcapReader, validate_synthetic_pcap, TSharkNotFoundError, PcapOpenError, PcapValidationError
from capture.packet_parser import PacketParser, PacketRecord
from capture.feature_extractor import FeatureExtractor
from database.db_manager import DatabaseManager, SessionRecord
from utils.helpers import generate_session_id, utc_now_iso, format_bytes


# ──────────────────────────────────────────────────────────────────────────────
# SYNTHETIC PCAP GENERATOR  (requires Scapy — optional dependency)
# ──────────────────────────────────────────────────────────────────────────────

def generate_synthetic_pcap(output_path: Path, packet_count: int = 500) -> Path:
    """
    Generate a synthetic PCAP file using Scapy for testing purposes.

    Creates a realistic mix of TCP, UDP, ICMP, DNS, and ARP packets
    between fictional IP addresses.

    Args:
        output_path:  Destination .pcap file path.
        packet_count: Number of packets to generate (default 500).

    Returns:
        Path to the generated PCAP file.

    Raises:
        ImportError: If Scapy is not installed.
        RuntimeError: On any Scapy/IO error.
    """
    try:
        from scapy.all import (
            Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR,
            wrpcap, RandShort,
        )
        import random
    except ImportError as exc:
        raise ImportError(
            "Scapy is required for synthetic PCAP generation.\n"
            "Install it: pip install scapy"
        ) from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    log.info("Generating synthetic PCAP: %d packets → %s", packet_count, output_path)

    src_ips = [f"192.168.1.{i}" for i in range(1, 21)]
    dst_ips = [f"10.0.0.{i}" for i in range(1, 11)] + ["8.8.8.8", "1.1.1.1", "93.184.216.34"]

    packets = []
    for i in range(packet_count):
        src = random.choice(src_ips)
        dst = random.choice(dst_ips)
        ptype = random.choices(
            ["tcp", "udp", "icmp", "dns", "arp"],
            weights=[50, 25, 10, 10, 5],
        )[0]

        try:
            if ptype == "tcp":
                pkt = (
                    Ether()
                    / IP(src=src, dst=dst, ttl=random.randint(32, 128))
                    / TCP(
                        sport=int(RandShort()),
                        dport=random.choice([80, 443, 22, 8080, 3306]),
                        flags=random.choice(["S", "SA", "A", "PA", "FA"]),
                    )
                    / (b"X" * random.randint(0, 1400))
                )
            elif ptype == "udp":
                pkt = (
                    Ether()
                    / IP(src=src, dst=dst, ttl=random.randint(32, 128))
                    / UDP(sport=int(RandShort()), dport=random.choice([53, 67, 123, 161]))
                    / (b"Y" * random.randint(0, 512))
                )
            elif ptype == "icmp":
                pkt = (
                    Ether()
                    / IP(src=src, dst=dst, ttl=random.randint(32, 128))
                    / ICMP(type=random.choice([0, 8]))
                )
            elif ptype == "dns":
                pkt = (
                    Ether()
                    / IP(src=src, dst="8.8.8.8", ttl=64)
                    / UDP(sport=int(RandShort()), dport=53)
                    / DNS(rd=1, qd=DNSQR(qname="example.com"))
                )
            else:  # ARP
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=dst, psrc=src)

            packets.append(pkt)

        except Exception as exc:
            log.debug("Skipping packet %d due to Scapy error: %s", i, exc)

    wrpcap(str(output_path), packets)
    log.info("Synthetic PCAP written: %d packets", len(packets))

    # FIX 5: validate the PCAP after creation
    val = validate_synthetic_pcap(output_path)
    if not val["valid"]:
        log.warning(
            "Synthetic PCAP post-creation validation warning: "
            "file=%s exists=%s size=%s bytes packet_count=%s",
            output_path.name, val['exists'], val['size_bytes'], val['packet_count'],
        )
    else:
        log.info(
            "Synthetic PCAP validated: packet_count=%s | size=%s bytes",
            val['packet_count'], val['size_bytes'],
        )
    return output_path


# ──────────────────────────────────────────────────────────────────────────────
# BANNER / DISPLAY HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _banner(text: str, char: str = "=", width: int = 60) -> None:
    """Print a section banner to stdout."""
    print(f"\n{char * width}")
    print(f"  {text}")
    print(f"{char * width}")


def _print_summary(summary: dict, reader_stats: dict, parser_stats: dict,
                   csv_path: Path, db_rows: int, elapsed: float) -> None:
    """Pretty-print the pipeline summary to stdout."""

    _banner("PHASE 2 PIPELINE — RESULTS", "═")

    print(f"\n{'─' * 60}")
    print(f"  {'INGESTION':}")
    print(f"{'─' * 60}")
    print(f"  PCAP File          : {reader_stats['file']}")
    print(f"  Packets Read       : {reader_stats['packets_read']:,}")
    print(f"  Read Errors        : {reader_stats['errors']}")
    print(f"  Parse Successes    : {parser_stats['parsed']:,}")
    print(f"  Parse Errors       : {parser_stats['errors']}")
    print(f"  Processing Time    : {elapsed:.2f}s")

    print(f"\n{'─' * 60}")
    print(f"  TRAFFIC STATISTICS")
    print(f"{'─' * 60}")
    print(f"  Total Packets      : {summary.get('total_packets', 0):,}")
    print(f"  Unique Source IPs  : {summary.get('unique_source_ips', 0):,}")
    print(f"  Unique Dest IPs    : {summary.get('unique_destination_ips', 0):,}")
    print(f"  Avg Packet Size    : {summary.get('avg_packet_size', 0):.1f} bytes")
    print(f"  Max Packet Size    : {summary.get('max_packet_size', 0):,} bytes")
    print(f"  Min Packet Size    : {summary.get('min_packet_size', 0):,} bytes")
    print(f"  Packets with IP    : {summary.get('packets_with_ip', 0):,}")
    print(f"  Packets w/o IP     : {summary.get('packets_without_ip', 0):,}")
    print(f"  Capture Start      : {summary.get('capture_start', 'N/A')}")
    print(f"  Capture End        : {summary.get('capture_end', 'N/A')}")

    proto_dist = summary.get("protocol_distribution", {})
    if proto_dist:
        print(f"\n{'─' * 60}")
        print(f"  PROTOCOL DISTRIBUTION")
        print(f"{'─' * 60}")
        total = sum(proto_dist.values()) or 1
        for proto, cnt in sorted(proto_dist.items(), key=lambda x: -x[1])[:10]:
            bar = "█" * int(cnt / total * 30)
            print(f"  {proto:<12} {cnt:>6,}   {bar}")

    top_src = summary.get("top_10_source_ips", [])
    if top_src:
        print(f"\n{'─' * 60}")
        print(f"  TOP 10 SOURCE IPs")
        print(f"{'─' * 60}")
        for ip, cnt in top_src:
            print(f"  {ip:<20} {cnt:>6,} packets")

    top_dst = summary.get("top_10_destination_ips", [])
    if top_dst:
        print(f"\n{'─' * 60}")
        print(f"  TOP 10 DESTINATION IPs")
        print(f"{'─' * 60}")
        for ip, cnt in top_dst:
            print(f"  {ip:<20} {cnt:>6,} packets")

    print(f"\n{'─' * 60}")
    print(f"  OUTPUT")
    print(f"{'─' * 60}")
    csv_size = csv_path.stat().st_size if csv_path.exists() else 0
    print(f"  CSV Exported       : {csv_path}")
    print(f"  CSV Size           : {format_bytes(csv_size)}")
    print(f"  Database Rows      : {db_rows:,} → traffic_logs")

    print(f"\n{'═' * 60}")
    print(f"  ✅  Phase 2 Pipeline Complete")
    print(f"{'═' * 60}\n")


# ──────────────────────────────────────────────────────────────────────────────
# CORE PIPELINE FUNCTION
# ──────────────────────────────────────────────────────────────────────────────

def run_pipeline(pcap_file: Path, quiet: bool = False) -> int:
    """
    Execute the full Phase 2 ingestion pipeline.

    Steps:
      1. Validate and load PCAP file via PcapReader
      2. Parse each packet into a PacketRecord via PacketParser
      3. Create/update a capture session in the database
      4. Convert records to an enriched DataFrame via FeatureExtractor
      5. Export DataFrame to CSV
      6. Persist DataFrame to SQLite traffic_logs table
      7. Update session statistics
      8. Print summary statistics

    Args:
        pcap_file: Path to the PCAP file.
        quiet:     Suppress console output if True.

    Returns:
        Exit code: 0 on success, 1–3 on failure.
    """
    start_time = time.perf_counter()

    # ── Step 0: Ensure directories and DB are initialised ─────────────────────
    config.initialise_directories()
    db = DatabaseManager()
    db.initialise()

    # ── Step 1: Create a capture session ──────────────────────────────────────
    session_id = generate_session_id()
    session_start = utc_now_iso()

    try:
        session_record = SessionRecord(
            session_id=session_id,
            start_time=session_start,
            interface="pcap_file",
            pcap_file=str(pcap_file),
        )
        db.insert_session(session_record)
        log.info("Capture session created: %s", session_id)
    except Exception as exc:
        log.warning("Could not insert session record: %s", exc)

    # ── Step 2: Load and parse PCAP ───────────────────────────────────────────
    records: list[PacketRecord] = []
    reader_stats: dict = {}
    parser_stats: dict = {}

    try:
        reader = PcapReader(pcap_file)
        parser = PacketParser(session_id=session_id)

        log.info("Starting packet ingestion…")
        packet_iter = reader.iterate_packets()

        for raw_pkt in packet_iter:
            record = parser.parse_packet(raw_pkt)
            if record is not None:
                records.append(record)

        reader_stats = reader.get_stats()
        parser_stats = parser.get_stats()
        reader.close()

    except PcapValidationError as exc:
        log.error("PCAP validation failed: %s", exc)
        return 1
    except PcapOpenError as exc:
        log.error("PCAP open failed: %s", exc)
        return 1
    except TSharkNotFoundError as exc:
        log.error("TShark not found: %s", exc)
        return 2
    except FileNotFoundError as exc:
        log.error("PCAP file not found: %s", exc)
        return 1
    except ValueError as exc:
        log.error("Invalid PCAP file: %s", exc)
        return 1
    except RuntimeError as exc:
        log.error("Runtime error (PyShark/TShark): %s", exc)
        return 2
    except Exception as exc:
        log.error("Unexpected error during ingestion: %s\n%s", exc, traceback.format_exc())
        return 3

    if not records:
        log.warning("No packets were successfully parsed. Aborting pipeline.")
        print("\n⚠️  No packets could be parsed from the PCAP file.")
        print("   Check that TShark/Wireshark is installed and the file is valid.\n")
        return 1

    log.info("Ingestion complete: %d packets parsed.", len(records))

    # ── Step 3: Feature extraction, CSV, and DB persistence ───────────────────
    extractor = FeatureExtractor(
        session_id=session_id,
        db_manager=db,
    )

    try:
        df, summary = extractor.run_pipeline(
            records=records,
            export_csv=True,
            save_db=True,
        )
        csv_path = extractor.csv_output_path
        db_rows = len(df)

    except Exception as exc:
        log.error("Feature extraction pipeline failed: %s\n%s", exc, traceback.format_exc())
        return 3

    # ── Step 4: Update session stats ──────────────────────────────────────────
    elapsed = time.perf_counter() - start_time
    total_bytes = int(df["packet_length"].sum()) if "packet_length" in df.columns else 0

    try:
        db.update_session_stats(
            session_id=session_id,
            total_packets=len(records),
            total_bytes=total_bytes,
            total_alerts=0,
            end_time=utc_now_iso(),
        )
        log.info("Session stats updated.")
    except Exception as exc:
        log.warning("Could not update session stats: %s", exc)

    # ── Step 5: Print results ─────────────────────────────────────────────────
    if not quiet:
        _print_summary(
            summary=summary,
            reader_stats=reader_stats,
            parser_stats=parser_stats,
            csv_path=csv_path,
            db_rows=db_rows,
            elapsed=elapsed,
        )
    else:
        print(f"✅  Phase 2 complete: {len(records):,} packets | "
              f"{elapsed:.2f}s | CSV: {csv_path}")

    db.close()
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Phase 2 Test — Network Traffic Analysis IDS\n"
            "Runs the full PCAP ingestion pipeline."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_phase2.py --generate
  python test_phase2.py --pcap data/raw/sample.pcap
  python test_phase2.py --pcap data/raw/sample.pcap --quiet
        """,
    )
    parser.add_argument(
        "--pcap", "-p",
        type=str,
        default=None,
        help="Path to an existing PCAP file to analyse.",
    )
    parser.add_argument(
        "--generate", "-g",
        action="store_true",
        help="Generate a synthetic PCAP using Scapy and run the pipeline on it.",
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=500,
        help="Number of synthetic packets to generate (default: 500, used with --generate).",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress detailed output (print a one-line summary only).",
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # ── Determine the PCAP file path ──────────────────────────────────────────
    if args.generate:
        synth_path = config.paths.raw_data_dir / "synthetic_test.pcap"
        try:
            pcap_file = generate_synthetic_pcap(synth_path, packet_count=args.count)
        except ImportError as exc:
            print(f"\n❌  {exc}\n")
            return 2
        except Exception as exc:
            print(f"\n❌  Synthetic generation failed: {exc}\n")
            return 3

    elif args.pcap:
        pcap_file = Path(args.pcap)

    else:
        # Auto-detect: look for any .pcap file in data/raw/
        raw_dir = config.paths.raw_data_dir
        raw_dir.mkdir(parents=True, exist_ok=True)
        pcap_candidates = list(raw_dir.glob("*.pcap")) + list(raw_dir.glob("*.pcapng"))

        if pcap_candidates:
            pcap_file = pcap_candidates[0]
            log.info("Auto-detected PCAP: %s", pcap_file)
        else:
            print(
                "\n❌  No PCAP file specified and none found in data/raw/\n\n"
                "Options:\n"
                "  1. Run: python test_phase2.py --generate\n"
                "     (generates a synthetic test PCAP using Scapy)\n\n"
                "  2. Run: python test_phase2.py --pcap /path/to/your/file.pcap\n\n"
                "  3. Place a .pcap file in data/raw/ and re-run.\n"
            )
            return 1

    if not args.quiet:
        _banner(f"PHASE 2 — PACKET INGESTION PIPELINE", "═")
        print(f"  PCAP File  : {pcap_file}")
        print(f"  Output CSV : {config.paths.processed_data_dir / 'packets.csv'}")
        print(f"  Database   : {config.paths.database_path}")
        print()

    return run_pipeline(pcap_file=pcap_file, quiet=args.quiet)


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(main())
