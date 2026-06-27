"""
test_pyshark_compatibility.py — PyShark / asyncio Compatibility Test
=====================================================================
Network Traffic Analysis and Intrusion Detection System

Verifies that the full Python → asyncio → PyShark → TShark chain works
correctly on the current system, with special attention to Python 3.12+
and 3.14 asyncio event loop changes.

Checks performed:
  1. Python version reported
  2. asyncio event loop can be created / set on the main thread
  3. TShark binary is on PATH and returns a version string
  4. PyShark can be imported
  5. A sample PCAP file can be opened via PcapReader (with event loop init)
  6. The first packet can be read from that PCAP

Usage:
    python test_pyshark_compatibility.py
    python test_pyshark_compatibility.py --pcap path/to/file.pcap
    python test_pyshark_compatibility.py --generate   (needs Scapy)

Exit codes:
    0  All checks passed
    1  One or more checks failed (see output for details)

Author: Network Traffic Analyzer Project
Version: 2.1.0
Python: 3.11+
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# ── Ensure project root is on sys.path ────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ──────────────────────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ──────────────────────────────────────────────────────────────────────────────

_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _ok(label: str, detail: str = "") -> None:
    tick = f"{_GREEN}OK{_RESET}"
    detail_str = f"  {_YELLOW}({detail}){_RESET}" if detail else ""
    print(f"  {label:<28} [ {tick} ]{detail_str}")


def _fail(label: str, reason: str = "") -> None:
    cross = f"{_RED}FAIL{_RESET}"
    print(f"  {label:<28} [ {cross} ]  {_RED}{reason}{_RESET}")


def _section(title: str) -> None:
    print(f"\n{_BOLD}{'-' * 60}{_RESET}")
    print(f"{_BOLD}  {title}{_RESET}")
    print(f"{_BOLD}{'-' * 60}{_RESET}")


# ------------------------------------------------------------------------------
# CHECK FUNCTIONS
# ------------------------------------------------------------------------------

def check_python_version() -> bool:
    """Check 1: Python version."""
    _section("CHECK 1 — Python Version")
    version = sys.version.split()[0]
    major, minor = sys.version_info.major, sys.version_info.minor

    if major == 3 and minor >= 9:
        _ok("Python Version", f"{version} (3.9+ supported)")
        if minor >= 12:
            print(f"  {_YELLOW}Note: Python 3.12+ has stricter asyncio event loop rules.")
            print(f"        PcapReader._initialize_event_loop() handles this.{_RESET}")
        return True
    else:
        _fail("Python Version", f"{version} — need 3.9+")
        return False


def check_event_loop() -> bool:
    """Check 2: asyncio event loop can be created on the main thread."""
    _section("CHECK 2 — asyncio Event Loop")

    # Simulate exactly what PcapReader._initialize_event_loop does
    try:
        loop = asyncio.get_running_loop()
        _ok("Running loop found", repr(loop))
        return True
    except RuntimeError:
        pass  # Expected in sync context

    try:
        loop = asyncio.get_event_loop()
        if not loop.is_closed():
            _ok("Existing loop (not running)", repr(loop))
            return True
        print(f"  {_YELLOW}Existing loop is closed — creating new one.{_RESET}")
    except RuntimeError:
        print(f"  {_YELLOW}No loop on thread (Python 3.12+ expected) — creating one.{_RESET}")

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _ok("New event loop created & set", repr(loop))
        return True
    except Exception as exc:
        _fail("Event loop creation", str(exc))
        return False


def check_tshark() -> tuple[bool, str]:
    """Check 3: TShark binary is available on PATH."""
    _section("CHECK 3 — TShark Availability")
    try:
        from capture.pcap_reader import PcapReader, TSharkNotFoundError
        version_line = PcapReader.verify_tshark()
        _ok("TShark on PATH", version_line[:60])
        return True, version_line
    except Exception as exc:
        _fail("TShark", str(exc)[:120])
        return False, ""


def check_pyshark() -> bool:
    """Check 4: PyShark can be imported."""
    _section("CHECK 4 — PyShark Import")
    try:
        import pyshark
        version = getattr(pyshark, "__version__", "unknown")
        _ok("PyShark imported", f"version={version}")
        return True
    except ImportError as exc:
        _fail("PyShark import", str(exc))
        print(f"\n  {_YELLOW}Fix: pip install pyshark{_RESET}")
        return False


def check_pcap_open(pcap_path: Path) -> bool:
    """Check 5: PcapReader can open the file (tests event loop init + PyShark)."""
    _section("CHECK 5 — PCAP File Open")

    if not pcap_path.exists():
        _fail("PCAP exists", f"Not found: {pcap_path}")
        return False

    _ok("PCAP file exists", f"{pcap_path.stat().st_size:,} bytes")

    try:
        from capture.pcap_reader import PcapReader, PcapOpenError, TSharkNotFoundError

        reader = PcapReader(pcap_path)
        reader._initialize_event_loop()   # Explicit call to test the fix
        reader.load_capture()
        _ok("PcapReader opened", pcap_path.name)
        return True, reader  # type: ignore[return-value]

    except Exception as exc:
        _fail("PcapReader open", f"{type(exc).__name__}: {str(exc)[:100]}")
        return False, None  # type: ignore[return-value]


def check_first_packet(reader) -> bool:
    """Check 6: First packet can be read from the open capture."""
    _section("CHECK 6 — First Packet Read")

    if reader is None:
        _fail("First packet", "No open reader (Check 5 failed)")
        return False

    try:
        first = None
        for pkt in reader.iterate_packets():
            first = pkt
            break

        reader.close()

        if first is None:
            _fail("First packet", "Capture is empty (0 packets)")
            return False

        layer = getattr(first, "highest_layer", "unknown")
        length = getattr(first, "length", "?")
        _ok("First packet read", f"layer={layer} | length={length} bytes")
        return True

    except Exception as exc:
        _fail("First packet read", f"{type(exc).__name__}: {str(exc)[:100]}")
        try:
            reader.close()
        except Exception:
            pass
        return False


# ------------------------------------------------------------------------------
# PCAP ACQUISITION
# ------------------------------------------------------------------------------

def _get_or_generate_pcap(pcap_arg: str | None, generate: bool) -> Path | None:
    """Resolve or generate a PCAP file to test against."""
    from utils.config import config

    if pcap_arg:
        return Path(pcap_arg)

    if generate:
        print(f"\n{_YELLOW}Generating synthetic PCAP (50 packets)...{_RESET}")
        try:
            from test_phase2 import generate_synthetic_pcap
            path = generate_synthetic_pcap(
                config.paths.raw_data_dir / "compat_test.pcap",
                packet_count=50,
            )
            print(f"  Generated: {path}")
            return path
        except ImportError as exc:
            print(f"  {_RED}Scapy not available for generation: {exc}{_RESET}")
            return None
        except Exception as exc:
            print(f"  {_RED}Generation failed: {exc}{_RESET}")
            return None

    # Auto-detect any PCAP in data/raw/
    raw_dir = config.paths.raw_data_dir
    raw_dir.mkdir(parents=True, exist_ok=True)
    candidates = sorted(raw_dir.glob("*.pcap")) + sorted(raw_dir.glob("*.pcapng"))

    if candidates:
        print(f"\n{_YELLOW}Auto-detected PCAP: {candidates[0]}{_RESET}")
        return candidates[0]

    return None


# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PyShark / asyncio compatibility test for Python 3.12+/3.14",
    )
    parser.add_argument("--pcap", "-p", default=None, help="Path to a PCAP file to test.")
    parser.add_argument(
        "--generate", "-g",
        action="store_true",
        help="Generate a 50-packet synthetic PCAP using Scapy (requires Scapy).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    print(f"\n{_BOLD}{'=' * 60}{_RESET}")
    print(f"{_BOLD}  PyShark / asyncio Compatibility Test{_RESET}")
    print(f"{_BOLD}  Network Traffic Analysis IDS -- Phase 2{_RESET}")
    print(f"{_BOLD}{'=' * 60}{_RESET}")

    results: dict[str, bool] = {}

    # -- Check 1: Python version ------------------------------------------------
    results["Python Version"] = check_python_version()

    # ── Check 2: asyncio event loop ───────────────────────────────────────────
    results["Event Loop"] = check_event_loop()

    # ── Check 3: TShark ───────────────────────────────────────────────────────
    tshark_ok, _ = check_tshark()
    results["TShark"] = tshark_ok

    # ── Check 4: PyShark ──────────────────────────────────────────────────────
    results["PyShark"] = check_pyshark()

    # ── Get PCAP for checks 5 & 6 ─────────────────────────────────────────────
    _section("PCAP File Acquisition")
    pcap_path = _get_or_generate_pcap(args.pcap, args.generate)

    if pcap_path is None:
        print(
            f"\n  {_YELLOW}No PCAP file available for checks 5 & 6.{_RESET}\n"
            f"  Re-run with  --generate  or  --pcap path/to/file.pcap\n"
        )
        results["PCAP Open"] = False
        results["First Packet Read"] = False
    else:
        # ── Check 5: PCAP open ────────────────────────────────────────────────
        pcap_ok_result = check_pcap_open(pcap_path)
        if isinstance(pcap_ok_result, tuple):
            pcap_ok, reader = pcap_ok_result
        else:
            pcap_ok, reader = pcap_ok_result, None

        results["PCAP Open"] = pcap_ok

        # ── Check 6: First packet ─────────────────────────────────────────────
        results["First Packet Read"] = check_first_packet(reader)

    # ── Summary ───────────────────────────────────────────────────────────────
    _section("COMPATIBILITY SUMMARY")

    all_passed = True
    for check_name, passed in results.items():
        if passed:
            _ok(check_name)
        else:
            _fail(check_name, "see details above")
            all_passed = False

    print()
    if all_passed:
        print(f"  {_GREEN}{_BOLD}Compatibility Test Passed{_RESET}")
        print(f"  {_GREEN}The Phase 2 pipeline is ready to process PCAP files.{_RESET}")
    else:
        failed = [k for k, v in results.items() if not v]
        print(f"  {_RED}{_BOLD}Compatibility Test Failed{_RESET}")
        print(f"  {_RED}Failed checks: {', '.join(failed)}{_RESET}")
        print(
            f"\n  {_YELLOW}Troubleshooting tips:"
            f"\n    - TShark missing?  Install Wireshark and ensure 'tshark' is on PATH."
            f"\n    - Event loop error? This is fixed in pcap_reader v2.1.0."
            f"\n    - PyShark error?   Run: pip install --upgrade pyshark"
            f"\n    - No PCAP file?    Run: python test_pyshark_compatibility.py --generate{_RESET}\n"
        )

    print(f"{'=' * 60}\n")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
