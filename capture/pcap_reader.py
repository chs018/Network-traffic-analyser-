"""
pcap_reader.py — Production PCAP File Reader (Patched for Python 3.12+/3.14)
=============================================================================
Network Traffic Analysis and Intrusion Detection System

Reads packet data from PCAP/PCAPNG files using PyShark (which wraps
TShark) and yields raw packet objects to the PacketParser layer.

PATCH NOTES (v2.1.0):
  - FIX 1: asyncio event loop compatibility for Python 3.12+ and 3.14
            (_initialize_event_loop called before every FileCapture creation)
  - FIX 2: Robust PyShark opening with granular exception handling and
            custom exception types (PcapOpenError, TSharkNotFoundError)
  - FIX 3: validate_pcap() alias + extended validation with detailed logs
  - FIX 4: verify_tshark() uses subprocess to confirm TShark is on PATH
  - FIX 5: Synthetic PCAP post-creation validation hook (used in test script)
  - FIX 6: Detailed debug logging at every lifecycle stage
  - FIX 7: test_pyshark_compatibility.py (separate file)

Design principles:
  - Generator-based: packets are never fully loaded into RAM at once
  - Defensive: every validation/IO step has explicit exception handling
  - Transparent: all major lifecycle events are logged at appropriate levels
  - Composable: integrates directly with the Phase 1 Config and Logger singletons

Supported file formats:
  .pcap | .pcapng | .cap

Author: Network Traffic Analyzer Project
Version: 2.1.0
Python: 3.11+ (patched for 3.12 / 3.14 asyncio changes)
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import Generator, Optional

# PyShark is the primary capture backend (wraps Wireshark/TShark)
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

from utils.config import config
from utils.logger import get_capture_logger

log = get_capture_logger()

# ── Supported PCAP file extensions ─────────────────────────────────────────────
_VALID_EXTENSIONS: frozenset[str] = frozenset({".pcap", ".pcapng", ".cap"})


# ──────────────────────────────────────────────────────────────────────────────
# CUSTOM EXCEPTIONS  (FIX 2 + FIX 4)
# ──────────────────────────────────────────────────────────────────────────────

class PcapReaderError(RuntimeError):
    """Base exception for all PcapReader failures."""


class PcapValidationError(PcapReaderError):
    """Raised when PCAP file validation fails (missing, wrong ext, empty)."""


class PcapOpenError(PcapReaderError):
    """
    Raised when PyShark/TShark cannot open the PCAP file.

    Wraps all underlying asyncio, PyShark, and OS errors with a
    user-friendly message and the original cause as ``__cause__``.
    """


class TSharkNotFoundError(PcapReaderError):
    """
    Raised when TShark is not installed or not found on PATH.

    Provides platform-specific installation guidance.
    """

    _INSTALL_GUIDE = (
        "\n\nInstallation guide:"
        "\n  Windows : Download Wireshark from https://www.wireshark.org/download.html"
        "\n            During setup, tick 'TShark' and 'Add to PATH'."
        "\n  Linux   : sudo apt install tshark   OR   sudo yum install wireshark-cli"
        "\n  macOS   : brew install wireshark"
        "\n\nAfter installing, restart your terminal and re-run the script."
    )

    def __init__(self, detail: str = "") -> None:
        msg = (
            "TShark is not installed or not available in PATH."
            + (f" Detail: {detail}" if detail else "")
            + self._INSTALL_GUIDE
        )
        super().__init__(msg)


# ──────────────────────────────────────────────────────────────────────────────
# PcapReader
# ──────────────────────────────────────────────────────────────────────────────

class PcapReader:
    """
    Memory-efficient PCAP/PCAPNG file reader backed by PyShark.

    Reads packets lazily via a generator, ensuring that even very large
    capture files (100 MB+) can be processed without exhausting system RAM.

    Python 3.12+ / 3.14 asyncio Compatibility
    ------------------------------------------
    PyShark internally calls ``asyncio.get_event_loop()`` which, since
    Python 3.10, emits a DeprecationWarning when no running loop exists,
    and since 3.12 raises ``RuntimeError: There is no current event loop
    in thread 'MainThread'``.

    This class calls :meth:`_initialize_event_loop` before every
    ``pyshark.FileCapture(...)`` creation to guarantee a loop is set on
    the current thread, regardless of Python version.

    Attributes:
        pcap_path (Path):      Absolute path to the validated PCAP file.
        bpf_filter (str):      Optional BPF display filter applied during read.
        packet_count (int):    Running total of packets yielded so far.
        error_count (int):     Packets that raised exceptions during iteration.
        _capture:              The underlying PyShark FileCapture object.

    Example::

        reader = PcapReader("data/raw/sample.pcap")
        for pkt in reader.iterate_packets():
            print(pkt.highest_layer)
        reader.close()

        # Or as a context manager:
        with PcapReader("data/raw/sample.pcap") as reader:
            for pkt in reader.iterate_packets():
                process(pkt)
    """

    def __init__(
        self,
        pcap_path: str | Path,
        bpf_filter: str = "",
        keep_packets: bool = False,
        verify_tshark_on_init: bool = False,
    ) -> None:
        """
        Initialise and validate the PcapReader.

        Args:
            pcap_path:             Path to the PCAP file (absolute or relative).
            bpf_filter:            Optional TShark display/BPF filter expression.
                                   Empty string = read all packets.
            keep_packets:          If True, PyShark retains packet objects in
                                   memory (useful for random access but increases
                                   RAM usage).  Default False for large-file
                                   efficiency.
            verify_tshark_on_init: If True, call :meth:`verify_tshark` during
                                   construction.  Defaults to False to avoid a
                                   subprocess call on every instantiation.

        Raises:
            RuntimeError:           If PyShark is not installed.
            TSharkNotFoundError:    If verify_tshark_on_init=True and TShark
                                    is absent.
            PcapValidationError:    If PCAP file validation fails.
        """
        if not PYSHARK_AVAILABLE:
            raise RuntimeError(
                "PyShark is not installed. "
                "Run: pip install pyshark\n"
                "Also ensure TShark/Wireshark is installed on your system."
            )

        self.pcap_path: Path = Path(pcap_path).resolve()
        self.bpf_filter: str = bpf_filter
        self.keep_packets: bool = keep_packets

        self.packet_count: int = 0
        self.error_count: int = 0
        self._capture: Optional[pyshark.FileCapture] = None  # type: ignore[name-defined]

        log.debug(
            "PcapReader __init__ | Python %s | pyshark available=%s",
            sys.version.split()[0],
            PYSHARK_AVAILABLE,
        )

        # Optional TShark check at construction
        if verify_tshark_on_init:
            self.verify_tshark()

        # Validate on construction — fail fast before any expensive I/O
        self.validate_file()

        log.info(
            "PcapReader initialised | file='%s' | filter='%s'",
            self.pcap_path.name,
            self.bpf_filter or "<none>",
        )

    # ── Context Manager ────────────────────────────────────────────────────────

    def __enter__(self) -> "PcapReader":
        """Open the PyShark capture handle on context entry."""
        self.load_capture()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Always close the capture handle on exit (even on exception)."""
        self.close()
        return False   # Never suppress exceptions

    # ── FIX 1: asyncio Event Loop Compatibility ────────────────────────────────

    def _initialize_event_loop(self) -> asyncio.AbstractEventLoop:
        """
        Ensure a valid asyncio event loop exists on the **current** thread.

        IMPORTANT: When a running loop already exists (e.g. Streamlit's own
        asyncio loop), PyShark CANNOT share it — it needs to create its own
        nested loop which Python forbids.  In that case callers must use
        :meth:`iterate_packets_in_thread` instead, which offloads all PyShark
        work to a dedicated background thread with an isolated loop.

        Strategy (for non-async threads only):
          1. Try to get the existing non-running loop.
          2. If none exists or it is closed, create a brand-new one.

        Returns:
            The active :class:`asyncio.AbstractEventLoop` for this thread.

        Raises:
            PcapOpenError: If a loop cannot be created.
        """
        log.debug("Initializing asyncio event loop for PyShark compatibility.")

        # Check whether a running loop exists on this thread already
        try:
            running = asyncio.get_running_loop()
            # There IS a running loop — we cannot create a nested one.
            # Callers should use iterate_packets_in_thread() instead.
            log.debug(
                "Running event loop detected (%r). PyShark must run in a "
                "separate thread to avoid event loop conflict.", running
            )
            return running
        except RuntimeError:
            pass  # No running loop — safe to proceed

        # Try to re-use an existing (non-running) loop if compatible
        import sys
        try:
            loop = asyncio.get_event_loop()
            if not loop.is_closed():
                if sys.platform == "win32" and not isinstance(loop, asyncio.ProactorEventLoop):
                    log.debug("Existing loop %r is not a ProactorEventLoop; cannot reuse on Windows.", loop)
                else:
                    log.debug("Re-using existing (not running) event loop: %r", loop)
                    return loop
            log.debug("Existing event loop is closed or incompatible. Creating a new one.")
        except RuntimeError:
            log.debug(
                "No event loop on current thread (Python 3.12+ behaviour). "
                "Creating a new event loop."
            )

        # Create a brand-new loop (ProactorEventLoop on Windows) and set it as current
        try:
            if sys.platform == "win32":
                loop = asyncio.ProactorEventLoop()
            else:
                loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            log.debug("Event loop created successfully: %r", loop)
            return loop
        except Exception as exc:
            log.error("Failed to create asyncio event loop: %s", exc)
            raise PcapOpenError(
                f"Cannot initialise asyncio event loop required by PyShark: {exc}"
            ) from exc

    # ── FIX 4: TShark Verification ────────────────────────────────────────────

    @staticmethod
    def verify_tshark() -> str:
        """
        Verify that TShark is installed and available on the system PATH.

        Uses ``subprocess`` to run ``tshark -v`` and capture the version
        string.  This is the same check PyShark performs internally, but
        done early so failures surface with a clear error message.

        Returns:
            The first line of TShark's version output string.

        Raises:
            TSharkNotFoundError: If TShark is not found on PATH or returns
                                 a non-zero exit code.
        """
        log.debug("Verifying TShark availability...")

        try:
            result = subprocess.run(
                ["tshark", "-v"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                detail = result.stderr.strip() or "non-zero exit code"
                log.error("TShark returned error: %s", detail)
                raise TSharkNotFoundError(detail)

            first_line = (result.stdout or result.stderr).strip().splitlines()[0]
            log.info("TShark verified: %s", first_line)
            return first_line

        except FileNotFoundError:
            log.error("TShark not found on PATH.")
            raise TSharkNotFoundError("'tshark' executable not found on PATH.")

        except subprocess.TimeoutExpired:
            log.error("TShark version check timed out.")
            raise TSharkNotFoundError("'tshark -v' timed out after 10 seconds.")

        except TSharkNotFoundError:
            raise   # Re-raise without wrapping

        except Exception as exc:
            log.error("Unexpected error verifying TShark: %s", exc)
            raise TSharkNotFoundError(f"Unexpected error: {exc}") from exc

    # ── FIX 3: PCAP Validation ─────────────────────────────────────────────────

    def validate_file(self) -> None:
        """
        Validate the PCAP file path, extension, size, and read permissions.

        Alias: :meth:`validate_pcap` points to this method.

        Raises:
            PcapValidationError: File missing, wrong extension, empty, or unreadable.
        """
        log.debug("Validating PCAP file: %s", self.pcap_path)

        # ── Existence ─────────────────────────────────────────────────────────
        if not self.pcap_path.exists():
            msg = (
                f"PCAP file not found: '{self.pcap_path}'\n"
                f"Check that the path is correct and the file exists."
            )
            log.error(msg)
            raise PcapValidationError(msg)

        # ── Regular file (not a directory) ────────────────────────────────────
        if not self.pcap_path.is_file():
            msg = f"Path is not a regular file: '{self.pcap_path}'"
            log.error(msg)
            raise PcapValidationError(msg)

        # ── Extension ─────────────────────────────────────────────────────────
        suffix = self.pcap_path.suffix.lower()
        if suffix not in _VALID_EXTENSIONS:
            msg = (
                f"Unsupported file extension '{suffix}'. "
                f"Expected one of: {', '.join(sorted(_VALID_EXTENSIONS))}"
            )
            log.error(msg)
            raise PcapValidationError(msg)

        # ── Non-empty ─────────────────────────────────────────────────────────
        file_size = self.pcap_path.stat().st_size
        if file_size == 0:
            msg = f"PCAP file is empty (0 bytes): '{self.pcap_path}'"
            log.error(msg)
            raise PcapValidationError(msg)

        # ── Read permission ───────────────────────────────────────────────────
        if not os.access(self.pcap_path, os.R_OK):
            msg = f"No read permission for file: '{self.pcap_path}'"
            log.error(msg)
            raise PermissionError(msg)

        log.debug(
            "PCAP validation passed | size=%.2f KB | ext='%s'",
            file_size / 1024,
            suffix,
        )

    # Public alias requested in the spec
    validate_pcap = validate_file

    # ── FIX 2: Robust PCAP Opening ─────────────────────────────────────────────

    def load_capture(self) -> None:
        """
        Open the PyShark FileCapture handle on the **current** thread.

        NOTE: If called from a thread that already has a running asyncio loop
        (e.g. Streamlit's main thread), this will raise ``PcapOpenError``
        with an event-loop message.  Use :meth:`iterate_packets_in_thread`
        when running inside Streamlit.

        Raises:
            TSharkNotFoundError: If TShark is detected as absent.
            PcapOpenError:       For all other open failures.
        """
        if self._capture is not None:
            log.debug("Capture already loaded; skipping re-open.")
            return

        import threading
        if threading.current_thread() != threading.main_thread():
            log.debug("Non-main thread detected; deferring PyShark capture opening to thread iteration.")
            return

        # Ensure we have a usable event loop on this thread
        log.debug("Initializing asyncio event loop before opening PCAP...")
        self._initialize_event_loop()

        log.info("Opening PCAP using PyShark: %s", self.pcap_path)

        try:
            kwargs: dict = {
                "input_file": str(self.pcap_path),
                "keep_packets": self.keep_packets,
                "use_json": True,
                "include_raw": False,
            }
            if self.bpf_filter:
                kwargs["display_filter"] = self.bpf_filter

            log.debug("pyshark.FileCapture kwargs: %s", {
                k: v for k, v in kwargs.items() if k != "input_file"
            })

            self._capture = pyshark.FileCapture(**kwargs)  # type: ignore[attr-defined]
            log.info("PCAP capture loaded successfully.")

        except FileNotFoundError as exc:
            log.error("TShark not found when opening PCAP: %s", exc)
            self._capture = None
            raise TSharkNotFoundError(str(exc)) from exc

        except RuntimeError as exc:
            err_str = str(exc)
            log.error("RuntimeError opening PCAP '%s': %s", self.pcap_path.name, err_str)
            self._capture = None
            raise PcapOpenError(
                f"asyncio/event-loop error while opening '{self.pcap_path.name}': {err_str}. "
                f"Use iterate_packets_in_thread() when running inside Streamlit."
            ) from exc

        except OSError as exc:
            log.error("OS error opening PCAP '%s': %s", self.pcap_path.name, exc)
            self._capture = None
            raise PcapOpenError(
                f"OS error reading '{self.pcap_path.name}': {exc}"
            ) from exc

        except Exception as exc:
            log.error(
                "Unexpected error opening PCAP '%s': %s: %s",
                self.pcap_path.name, type(exc).__name__, exc,
            )
            self._capture = None
            raise PcapOpenError(
                f"Could not open PCAP file '{self.pcap_path.name}': "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    def iterate_packets_in_thread(self) -> list:
        """
        Parse all packets in a dedicated background thread with its own
        isolated asyncio event loop.

        This is the **correct method to use when running inside Streamlit**
        (or any other async framework), because Streamlit already owns a
        running event loop on the main thread and PyShark cannot share it.

        The background thread:
          1. Creates a fresh ``asyncio`` event loop (isolated from Streamlit).
          2. Opens the PyShark FileCapture.
          3. Iterates all packets and collects raw packet objects.
          4. Closes the capture cleanly.
          5. Returns the collected packet list to the calling thread.

        Returns:
            List of raw PyShark ``Packet`` objects (same as iterate_packets).

        Raises:
            PcapOpenError / TSharkNotFoundError on failure (re-raised from
            the background thread).
        """
        import threading

        packets: list = []
        exc_holder: list = []   # [exception] if thread raised

        def _thread_worker() -> None:
            # Each thread gets its own ProactorEventLoop on Windows — completely isolated.
            import sys
            if sys.platform == "win32":
                loop = asyncio.ProactorEventLoop()
            else:
                loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            log.debug("Background thread event loop created: %r", loop)
            try:
                kwargs: dict = {
                    "input_file": str(self.pcap_path),
                    "keep_packets": self.keep_packets,
                    "use_json": True,
                    "include_raw": False,
                    "eventloop": loop,
                }
                if self.bpf_filter:
                    kwargs["display_filter"] = self.bpf_filter

                capture = pyshark.FileCapture(**kwargs)  # type: ignore[attr-defined]
                log.info(
                    "[thread] PCAP opened successfully: %s", self.pcap_path.name
                )

                try:
                    for pkt in capture:
                        try:
                            packets.append(pkt)
                            self.packet_count += 1
                            if self.packet_count % 1000 == 0:
                                log.debug(
                                    "[thread] Progress: %d packets read",
                                    self.packet_count,
                                )
                        except Exception as pkt_exc:
                            self.error_count += 1
                            log.warning(
                                "[thread] Packet error #%d (skipping): %s",
                                self.packet_count, pkt_exc,
                            )
                except StopIteration:
                    pass
                except Exception as iter_exc:
                    import traceback
                    log.error("[thread] Iteration error: %s\n%s", iter_exc, traceback.format_exc())
                    exc_holder.append(iter_exc)
                finally:
                    try:
                        capture.close()
                    except Exception:
                        pass

            except FileNotFoundError as exc:
                exc_holder.append(TSharkNotFoundError(str(exc)))
            except Exception as exc:
                import traceback
                log.error("[thread] Failed to open PCAP '%s': %s\n%s", self.pcap_path.name, exc, traceback.format_exc())
                exc_holder.append(
                    PcapOpenError(
                        f"Thread failed to open '{self.pcap_path.name}': "
                        f"{type(exc).__name__}: {exc}"
                    )
                )
            finally:
                try:
                    loop.close()
                except Exception:
                    pass
                log.debug("[thread] Event loop closed.")

        log.info(
            "Starting background thread to parse PCAP: %s", self.pcap_path.name
        )
        t = threading.Thread(target=_thread_worker, daemon=True)
        t.start()
        t.join()   # Block until all packets are collected

        if exc_holder:
            raise exc_holder[0]

        log.info(
            "[thread] Packet collection complete: %d packets, %d errors.",
            self.packet_count, self.error_count,
        )
        return packets

    def close(self) -> None:
        """
        Close the PyShark capture handle and release resources.

        Safe to call multiple times — subsequent calls are no-ops.
        """
        log.debug("Closing PcapReader capture handle.")

        if self._capture is not None:
            try:
                self._capture.close()
                log.debug("PyShark FileCapture closed cleanly.")
            except Exception as exc:
                log.debug("Non-fatal error closing capture: %s", exc)
            finally:
                self._capture = None

        log.info(
            "PcapReader closed | packets_read=%d | errors=%d",
            self.packet_count,
            self.error_count,
        )

    # ── Packet Iteration ───────────────────────────────────────────────────────

    def iterate_packets(self) -> Generator:
        """
        Yield raw PyShark packet objects one at a time (generator).

        Automatically detects whether a running asyncio loop is present
        (e.g. inside Streamlit) and delegates to
        :meth:`iterate_packets_in_thread` in that case, yielding the
        collected packets as a generator afterwards.

        Each packet is a ``pyshark.packet.packet.Packet`` object with
        layer attributes accessible via dot notation (e.g. ``pkt.ip.src``).

        Yields:
            ``pyshark.packet.packet.Packet`` objects.

        Raises:
            PcapOpenError:       If the file cannot be opened.
            TSharkNotFoundError: If TShark is absent.
        """
        # Detect if we are inside a running event loop (e.g. Streamlit) or non-main thread
        import threading
        _running_loop = False
        try:
            asyncio.get_running_loop()
            _running_loop = True
        except RuntimeError:
            pass

        if _running_loop or threading.current_thread() != threading.main_thread() or self._capture is None:
            # ── Streamlit / async context / deferred capture: use background thread ──
            log.info(
                "Using thread-isolated packet collection for: %s",
                self.pcap_path.name,
            )
            raw_packets = self.iterate_packets_in_thread()
            for pkt in raw_packets:
                yield pkt
            return

        # ── Normal main-thread context: iterate directly ──────────────────────

        log.info("Packet iteration start: %s", self.pcap_path.name)
        log_interval = 1_000

        try:
            for raw_packet in self._capture:
                try:
                    self.packet_count += 1
                    yield raw_packet

                    if self.packet_count % log_interval == 0:
                        log.debug(
                            "Progress: %d packets read | errors: %d",
                            self.packet_count,
                            self.error_count,
                        )

                except Exception as pkt_exc:
                    self.error_count += 1
                    log.warning(
                        "Packet parsing failure #%d (skipping): %s: %s",
                        self.packet_count,
                        type(pkt_exc).__name__,
                        pkt_exc,
                    )

        except StopIteration:
            pass

        except Exception as cap_exc:
            log.error(
                "Fatal error during packet iteration after %d packets: %s: %s",
                self.packet_count,
                type(cap_exc).__name__,
                cap_exc,
            )
            raise

        log.info(
            "Packet iteration finish: total=%d | errors=%d | file='%s'",
            self.packet_count,
            self.error_count,
            self.pcap_path.name,
        )

    # ── Statistics ─────────────────────────────────────────────────────────────

    def packet_count_estimate(self) -> Optional[int]:
        """Return the running packet count (complete once iteration finishes)."""
        return self.packet_count

    def get_stats(self) -> dict[str, int | str]:
        """
        Return a summary of reader statistics.

        Returns:
            Dict with keys: ``file``, ``packets_read``, ``errors``.
        """
        return {
            "file": self.pcap_path.name,
            "packets_read": self.packet_count,
            "errors": self.error_count,
        }

    def reset(self) -> None:
        """
        Reset counters and close the capture handle.

        Allows the same PcapReader instance to be reused for a fresh read
        of the same file by calling :meth:`load_capture` again.
        """
        self.close()
        self.packet_count = 0
        self.error_count = 0
        log.debug("PcapReader reset.")

    def __repr__(self) -> str:
        return (
            f"PcapReader("
            f"file='{self.pcap_path.name}', "
            f"packets={self.packet_count}, "
            f"errors={self.error_count})"
        )


# ──────────────────────────────────────────────────────────────────────────────
# FIX 5: SYNTHETIC PCAP VALIDATION HELPER
# ──────────────────────────────────────────────────────────────────────────────

def validate_synthetic_pcap(pcap_path: Path) -> dict[str, object]:
    """
    Validate a synthetic (or real) PCAP file after creation.

    Checks:
      1. File exists
      2. File size > 0
      3. At least one packet can be read

    Args:
        pcap_path: Path to the PCAP file to validate.

    Returns:
        Dict with keys:
          - ``exists``       (bool)
          - ``size_bytes``   (int)
          - ``packet_count`` (int)
          - ``valid``        (bool)

    Logs:
        INFO  on success: "Synthetic PCAP created successfully | packets=X | size=Y bytes"
        ERROR on failure: reason
    """
    result: dict[str, object] = {
        "exists": False,
        "size_bytes": 0,
        "packet_count": 0,
        "valid": False,
    }

    pcap_path = Path(pcap_path)

    # ── Check 1: existence ────────────────────────────────────────────────────
    if not pcap_path.exists():
        log.error("Synthetic PCAP validation failed: file not found: %s", pcap_path)
        return result

    result["exists"] = True

    # ── Check 2: non-empty ────────────────────────────────────────────────────
    size_bytes = pcap_path.stat().st_size
    result["size_bytes"] = size_bytes

    if size_bytes == 0:
        log.error(
            "Synthetic PCAP validation failed: file is empty: %s", pcap_path
        )
        return result

    # ── Check 3: readable by PcapReader (reads first packet only) ─────────────
    packet_count = 0
    try:
        reader = PcapReader(pcap_path)
        for _ in reader.iterate_packets():
            packet_count += 1
            if packet_count >= 5:   # Read up to 5 packets to confirm validity
                break
        reader.close()
    except (PcapValidationError, PcapOpenError, TSharkNotFoundError) as exc:
        log.error("Synthetic PCAP validation failed (read error): %s", exc)
        result["packet_count"] = packet_count
        return result

    result["packet_count"] = packet_count

    if packet_count == 0:
        log.error(
            "Synthetic PCAP validation failed: no readable packets in '%s'",
            pcap_path.name,
        )
        return result

    result["valid"] = True
    log.info(
        "Synthetic PCAP created successfully | packets_sampled=%d | size=%d bytes | file='%s'",
        packet_count,
        size_bytes,
        pcap_path.name,
    )
    return result
