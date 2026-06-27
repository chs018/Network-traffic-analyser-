"""
logger.py — Centralised Logging Module
========================================
Network Traffic Analysis and Intrusion Detection System

Provides a factory for creating named loggers with:
  - Console handler  (coloured, human-readable)
  - Rotating file handler (structured, machine-parseable)
  - Configurable verbosity levels per handler
  - Thread-safe log emission

All loggers produced by this module follow the hierarchy:
  NetTrafficIDS
  ├── NetTrafficIDS.capture
  ├── NetTrafficIDS.analysis
  ├── NetTrafficIDS.detection
  ├── NetTrafficIDS.ml
  └── NetTrafficIDS.database

Usage:
    from utils.logger import get_logger

    log = get_logger(__name__)
    log.info("Module initialised.")
    log.warning("Threshold exceeded: %d pps", packet_rate)

Author: Network Traffic Analyzer Project
Version: 1.0.0
Python: 3.11+
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

# Import config lazily to avoid circular-import issues during early bootstrap.
# We resolve actual values inside each function rather than at module level.

# ──────────────────────────────────────────────────────────────────────────────
# ANSI COLOUR CODES FOR CONSOLE OUTPUT
# ──────────────────────────────────────────────────────────────────────────────

_RESET = "\033[0m"
_BOLD = "\033[1m"

_LEVEL_COLOURS: dict[str, str] = {
    "DEBUG":    "\033[36m",    # Cyan
    "INFO":     "\033[32m",    # Green
    "WARNING":  "\033[33m",    # Yellow
    "ERROR":    "\033[31m",    # Red
    "CRITICAL": "\033[35m",    # Magenta
}


# ──────────────────────────────────────────────────────────────────────────────
# COLOURED FORMATTER
# ──────────────────────────────────────────────────────────────────────────────

class ColouredFormatter(logging.Formatter):
    """
    Custom formatter that applies ANSI colour codes to the log level name
    when writing to a terminal (TTY). Falls back to plain text in non-TTY
    environments (e.g. file redirects, CI pipelines).
    """

    def __init__(self, fmt: str, datefmt: str, use_colour: bool = True) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)
        self._use_colour = use_colour

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        """
        Format the log record, optionally applying colour to level name.

        Args:
            record: The LogRecord to format.

        Returns:
            The formatted log message string.
        """
        if self._use_colour:
            colour = _LEVEL_COLOURS.get(record.levelname, "")
            record.levelname = (
                f"{colour}{_BOLD}{record.levelname:<8}{_RESET}"
            )
        return super().format(record)


# ──────────────────────────────────────────────────────────────────────────────
# LOGGER REGISTRY  (prevents duplicate handlers on re-import)
# ──────────────────────────────────────────────────────────────────────────────

_CONFIGURED_LOGGERS: set[str] = set()


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def get_logger(
    name: str,
    *,
    console_level: Optional[str] = None,
    file_level: Optional[str] = None,
    log_file: Optional[Path] = None,
) -> logging.Logger:
    """
    Retrieve (or create) a named logger with console and rotating-file handlers.

    The function is idempotent — calling it multiple times with the same
    ``name`` returns the same logger without attaching duplicate handlers.

    Args:
        name:          Logger name; conventionally pass ``__name__``.
        console_level: Override console verbosity (e.g. ``"DEBUG"``).
                       Defaults to ``LoggingConfig.console_level``.
        file_level:    Override file verbosity.
                       Defaults to ``LoggingConfig.file_level``.
        log_file:      Override log file path.
                       Defaults to ``Paths.app_log_path``.

    Returns:
        A configured :class:`logging.Logger` instance.

    Example:
        log = get_logger(__name__)
        log.info("Service started on port %d", port)
    """
    from utils.config import config  # deferred to avoid circular import

    lcfg = config.logging
    paths = config.paths

    # Resolve effective configuration values
    effective_console_level: str = console_level or lcfg.console_level
    effective_file_level: str = file_level or lcfg.file_level
    effective_log_file: Path = log_file or paths.app_log_path

    logger = logging.getLogger(name)

    # Guard: only configure once per logger name
    if name in _CONFIGURED_LOGGERS:
        return logger

    _CONFIGURED_LOGGERS.add(name)

    # Logger itself accepts ALL levels; handlers gate actual output
    logger.setLevel(logging.DEBUG)

    # ── Console Handler ────────────────────────────────────────────────────────
    _attach_console_handler(
        logger=logger,
        level=effective_console_level,
        fmt=lcfg.console_format,
        datefmt=lcfg.date_format,
    )

    # ── Rotating File Handler ─────────────────────────────────────────────────
    _attach_file_handler(
        logger=logger,
        level=effective_file_level,
        log_file=effective_log_file,
        fmt=lcfg.file_format,
        datefmt=lcfg.date_format,
        max_bytes=lcfg.max_bytes,
        backup_count=lcfg.backup_count,
    )

    # Prevent propagation to the root logger to avoid duplicate output
    logger.propagate = False

    return logger


def get_root_logger() -> logging.Logger:
    """
    Return the application root logger (``NetTrafficIDS``).

    Use this to set global verbosity or attach application-wide handlers.

    Returns:
        The root application logger.
    """
    from utils.config import config

    return get_logger(config.logging.root_logger)


def set_global_level(level: str) -> None:
    """
    Dynamically adjust the log level on all handlers of every configured logger.

    Useful for runtime debugging without restarting the application.

    Args:
        level: A valid logging level string (``"DEBUG"``, ``"INFO"``, etc.).

    Raises:
        ValueError: If ``level`` is not a recognised logging level.
    """
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(
            f"Invalid log level: '{level}'. "
            f"Choose from: DEBUG, INFO, WARNING, ERROR, CRITICAL."
        )

    for name in _CONFIGURED_LOGGERS:
        lgr = logging.getLogger(name)
        lgr.setLevel(numeric_level)
        for handler in lgr.handlers:
            handler.setLevel(numeric_level)


def shutdown_logging() -> None:
    """
    Flush and close all handlers on every configured logger.

    Call this during application teardown to ensure no log records are lost.
    """
    for name in _CONFIGURED_LOGGERS:
        lgr = logging.getLogger(name)
        for handler in lgr.handlers[:]:
            handler.flush()
            handler.close()
            lgr.removeHandler(handler)
    _CONFIGURED_LOGGERS.clear()
    logging.shutdown()


# ──────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _attach_console_handler(
    logger: logging.Logger,
    level: str,
    fmt: str,
    datefmt: str,
) -> None:
    """
    Attach a coloured StreamHandler (stdout) to *logger*.

    Args:
        logger:  Target logger.
        level:   Minimum log level for this handler.
        fmt:     Format string.
        datefmt: Date/time format string.
    """
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Detect TTY support for colour
    use_colour = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    formatter = ColouredFormatter(fmt=fmt, datefmt=datefmt, use_colour=use_colour)
    handler.setFormatter(formatter)

    logger.addHandler(handler)


def _attach_file_handler(
    logger: logging.Logger,
    level: str,
    log_file: Path,
    fmt: str,
    datefmt: str,
    max_bytes: int,
    backup_count: int,
) -> None:
    """
    Attach a RotatingFileHandler to *logger*, creating parent directories
    as needed.

    Args:
        logger:       Target logger.
        level:        Minimum log level for this handler.
        log_file:     Absolute path to the log file.
        fmt:          Format string.
        datefmt:      Date/time format string.
        max_bytes:    Maximum log file size before rotation.
        backup_count: Number of rotated files to keep.
    """
    log_file.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.handlers.RotatingFileHandler(
        filename=log_file,
        mode="a",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
        delay=False,
    )
    handler.setLevel(getattr(logging, level.upper(), logging.DEBUG))

    formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)
    handler.setFormatter(formatter)

    logger.addHandler(handler)


# ──────────────────────────────────────────────────────────────────────────────
# SPECIALISED LOGGER ACCESSORS
# ──────────────────────────────────────────────────────────────────────────────

def get_capture_logger() -> logging.Logger:
    """Return the packet-capture sub-logger."""
    from utils.config import config
    return get_logger(
        config.logging.capture_logger,
        log_file=config.paths.capture_log_path,
    )


def get_detection_logger() -> logging.Logger:
    """Return the intrusion-detection sub-logger."""
    from utils.config import config
    return get_logger(
        config.logging.detection_logger,
        log_file=config.paths.detection_log_path,
    )


def get_analysis_logger() -> logging.Logger:
    """Return the traffic-analysis sub-logger."""
    from utils.config import config
    return get_logger(config.logging.analysis_logger)


def get_ml_logger() -> logging.Logger:
    """Return the machine-learning sub-logger."""
    from utils.config import config
    return get_logger(config.logging.ml_logger)


def get_db_logger() -> logging.Logger:
    """Return the database sub-logger."""
    from utils.config import config
    return get_logger(config.logging.db_logger)
