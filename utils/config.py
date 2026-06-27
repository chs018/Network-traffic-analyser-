"""
config.py — Central Configuration Module
=========================================
Network Traffic Analysis and Intrusion Detection System

This module serves as the single source of truth for all project-wide
configuration: directory paths, database settings, logging parameters,
ML model paths, and detection thresholds.

Usage:
    from utils.config import Config, Paths, MLConfig, DetectionThresholds

Author: Network Traffic Analyzer Project
Version: 1.0.0
Python: 3.11+
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

# ──────────────────────────────────────────────────────────────────────────────
# PROJECT ROOT RESOLUTION
# ──────────────────────────────────────────────────────────────────────────────

# Resolve the absolute path to the project root (one level above utils/)
PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parent.parent


# ──────────────────────────────────────────────────────────────────────────────
# PROJECT METADATA
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProjectMeta:
    """Immutable metadata constants for the project."""

    name: str = "Network Traffic Analysis & Intrusion Detection System"
    short_name: str = "NetTrafficIDS"
    version: str = "1.0.0"
    author: str = "Final Year Project"
    description: str = (
        "A real-time network traffic analysis and intrusion detection system "
        "that monitors network activity, detects anomalies, identifies attacks "
        "(DDoS, Port Scanning, Brute Force), and provides an interactive dashboard."
    )
    python_version: str = "3.11+"
    license: str = "MIT"


# ──────────────────────────────────────────────────────────────────────────────
# DIRECTORY & FILE PATHS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Paths:
    """
    Centralised path configuration for all project directories and files.

    All paths are resolved as absolute paths relative to PROJECT_ROOT so the
    project can be run from any working directory.
    """

    # ── Root ──────────────────────────────────────────────────────────────────
    root: Path = field(default_factory=lambda: PROJECT_ROOT)

    # ── Data Directories ──────────────────────────────────────────────────────
    data_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "data")
    raw_data_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "data" / "raw")
    processed_data_dir: Path = field(
        default_factory=lambda: PROJECT_ROOT / "data" / "processed"
    )
    reports_data_dir: Path = field(
        default_factory=lambda: PROJECT_ROOT / "data" / "reports"
    )

    # ── Database ──────────────────────────────────────────────────────────────
    database_dir: Path = field(
        default_factory=lambda: PROJECT_ROOT / "database"
    )
    database_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "database" / "traffic.db"
    )

    # ── ML Models ─────────────────────────────────────────────────────────────
    models_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "models")
    anomaly_model_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "models" / "anomaly_detector.pkl"
    )
    classifier_model_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "models" / "attack_classifier.pkl"
    )
    scaler_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "models" / "feature_scaler.pkl"
    )
    label_encoder_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "models" / "label_encoder.pkl"
    )

    # ── Logs ──────────────────────────────────────────────────────────────────
    logs_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "logs")
    app_log_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "logs" / "app.log"
    )
    capture_log_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "logs" / "capture.log"
    )
    detection_log_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "logs" / "detection.log"
    )

    # ── Reports Output ────────────────────────────────────────────────────────
    reports_output_dir: Path = field(
        default_factory=lambda: PROJECT_ROOT / "reports" / "output"
    )

    def ensure_all(self) -> None:
        """Create all required directories if they do not already exist."""
        directories = [
            self.data_dir,
            self.raw_data_dir,
            self.processed_data_dir,
            self.reports_data_dir,
            self.database_dir,
            self.models_dir,
            self.logs_dir,
            self.reports_output_dir,
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def verify_all(self) -> dict[str, bool]:
        """
        Verify existence of all critical directories.

        Returns:
            dict[str, bool]: Mapping of directory name → exists flag.
        """
        return {
            "data/raw": self.raw_data_dir.exists(),
            "data/processed": self.processed_data_dir.exists(),
            "data/reports": self.reports_data_dir.exists(),
            "database": self.database_dir.exists(),
            "models": self.models_dir.exists(),
            "logs": self.logs_dir.exists(),
            "reports/output": self.reports_output_dir.exists(),
        }


# ──────────────────────────────────────────────────────────────────────────────
# DATABASE CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DatabaseConfig:
    """SQLite database configuration parameters."""

    # SQLite pragmas for performance tuning
    journal_mode: str = "WAL"          # Write-Ahead Logging for concurrency
    synchronous: str = "NORMAL"        # Balance between safety and speed
    cache_size: int = -64_000          # 64 MB page cache (negative = KB)
    foreign_keys: bool = True          # Enforce referential integrity
    timeout: float = 30.0             # Connection timeout in seconds

    # Pagination defaults for queries
    default_page_size: int = 100
    max_page_size: int = 10_000

    # Retention policy
    max_traffic_records: int = 1_000_000   # Auto-prune threshold
    max_alert_records: int = 100_000       # Auto-prune threshold


# ──────────────────────────────────────────────────────────────────────────────
# LOGGING CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LoggingConfig:
    """Logging system configuration."""

    # Severity levels: DEBUG | INFO | WARNING | ERROR | CRITICAL
    console_level: str = "INFO"
    file_level: str = "DEBUG"

    # Rotation settings
    max_bytes: int = 10 * 1024 * 1024   # 10 MB per log file
    backup_count: int = 5               # Keep 5 rotated backups

    # Format strings
    console_format: str = (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_format: str = (
        "%(asctime)s | %(levelname)-8s | %(name)s | "
        "%(filename)s:%(lineno)d | %(funcName)s() | %(message)s"
    )
    date_format: str = "%Y-%m-%d %H:%M:%S"

    # Logger names
    root_logger: str = "NetTrafficIDS"
    capture_logger: str = "NetTrafficIDS.capture"
    analysis_logger: str = "NetTrafficIDS.analysis"
    detection_logger: str = "NetTrafficIDS.detection"
    ml_logger: str = "NetTrafficIDS.ml"
    db_logger: str = "NetTrafficIDS.database"


# ──────────────────────────────────────────────────────────────────────────────
# ML CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MLConfig:
    """
    Machine Learning configuration for future Phase 2 integration.

    All parameters here are placeholders that will be tuned during
    model training and evaluation.
    """

    # ── Isolation Forest (Anomaly Detection) ──────────────────────────────────
    isolation_forest_n_estimators: int = 200
    isolation_forest_contamination: float = 0.05   # Expected 5% anomaly rate
    isolation_forest_max_samples: str = "auto"
    isolation_forest_random_state: int = 42

    # ── Random Forest (Attack Classification) ─────────────────────────────────
    rf_n_estimators: int = 100
    rf_max_depth: int = 15
    rf_min_samples_split: int = 5
    rf_random_state: int = 42
    rf_n_jobs: int = -1                # Use all CPU cores

    # ── Training Configuration ─────────────────────────────────────────────────
    test_size: float = 0.20            # 80/20 train-test split
    validation_size: float = 0.10     # 10% of training for validation
    cv_folds: int = 5                  # K-fold cross-validation
    random_state: int = 42

    # ── Feature Engineering ────────────────────────────────────────────────────
    # Features to be extracted from captured packets (Phase 2)
    numerical_features: tuple[str, ...] = (
        "packet_length",
        "inter_arrival_time",
        "bytes_per_second",
        "packets_per_second",
        "flow_duration",
        "src_port",
        "dst_port",
        "protocol_num",
        "tcp_flags",
        "window_size",
    )
    categorical_features: tuple[str, ...] = (
        "protocol",
        "src_ip_class",
        "dst_ip_class",
    )

    # ── Attack Classes ─────────────────────────────────────────────────────────
    attack_labels: tuple[str, ...] = (
        "BENIGN",
        "DDoS",
        "PortScan",
        "BruteForce",
        "Anomaly",
    )

    # ── Model Performance Thresholds ───────────────────────────────────────────
    min_accuracy: float = 0.90         # Minimum acceptable accuracy
    min_f1_score: float = 0.88        # Minimum acceptable F1 (macro avg)
    min_precision: float = 0.88
    min_recall: float = 0.85


# ──────────────────────────────────────────────────────────────────────────────
# DETECTION THRESHOLDS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DetectionThresholds:
    """
    Rule-based detection thresholds for Phase 1 heuristic detectors.

    These values are intentionally conservative defaults and should be
    calibrated to the specific network environment during deployment.
    """

    # ── DDoS Detection ────────────────────────────────────────────────────────
    ddos_packets_per_second: int = 1_000     # Packets/sec to flag potential DDoS
    ddos_bytes_per_second: int = 10_485_760  # 10 MB/s threshold
    ddos_unique_src_ips: int = 50            # Min unique sources for DDoS
    ddos_time_window_seconds: int = 10       # Analysis window

    # ── Port Scan Detection ───────────────────────────────────────────────────
    portscan_unique_ports: int = 20          # Ports/min to flag port scan
    portscan_time_window_seconds: int = 60   # Analysis window
    portscan_syn_ratio: float = 0.85         # SYN-to-ACK ratio threshold

    # ── Brute Force Detection ─────────────────────────────────────────────────
    bruteforce_failed_attempts: int = 10     # Failed logins before alert
    bruteforce_time_window_seconds: int = 60 # Analysis window
    bruteforce_ssh_port: int = 22
    bruteforce_rdp_port: int = 3389
    bruteforce_ftp_port: int = 21
    bruteforce_http_port: int = 80
    bruteforce_https_port: int = 443

    # ── Bandwidth Bottleneck Detection ────────────────────────────────────────
    bandwidth_high_utilisation: float = 0.80   # 80% utilisation = warning
    bandwidth_critical_utilisation: float = 0.95  # 95% = critical
    bandwidth_sample_interval_seconds: int = 5

    # ── Anomaly Detection Sensitivity ─────────────────────────────────────────
    anomaly_z_score_threshold: float = 3.0    # Z-score for statistical outliers
    anomaly_iqr_multiplier: float = 1.5       # IQR fence multiplier


# ──────────────────────────────────────────────────────────────────────────────
# NETWORK CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class NetworkConfig:
    """Network interface and protocol configuration."""

    # Default capture interface (overridden by user at runtime)
    default_interface: str = "eth0"

    # Capture filter (BPF syntax) — empty = capture everything
    default_bpf_filter: str = ""

    # Packet capture limits
    capture_timeout_seconds: int = 30
    max_packet_buffer: int = 10_000

    # Well-known service ports
    common_ports: tuple[int, ...] = (
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        6379,  # Redis
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
    )

    # Protocol numbers
    protocol_map: dict[int, str] = field(
        default_factory=lambda: {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            41: "IPv6",
            58: "ICMPv6",
            89: "OSPF",
            132: "SCTP",
        }
    )


# ──────────────────────────────────────────────────────────────────────────────
# DASHBOARD / UI CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DashboardConfig:
    """Streamlit dashboard layout and display configuration."""

    page_title: str = "Network Traffic IDS"
    page_icon: str = "🛡️"
    layout: str = "wide"
    initial_sidebar_state: str = "expanded"

    # Auto-refresh interval for live monitoring (seconds)
    refresh_interval_seconds: int = 5

    # Chart defaults
    chart_theme: str = "plotly_dark"
    chart_height: int = 400
    chart_color_benign: str = "#00C851"
    chart_color_warning: str = "#FF8800"
    chart_color_attack: str = "#FF4444"
    chart_color_primary: str = "#1565C0"

    # Table display
    max_rows_displayed: int = 500


# ──────────────────────────────────────────────────────────────────────────────
# UNIFIED CONFIG FACADE
# ──────────────────────────────────────────────────────────────────────────────

class Config:
    """
    Unified configuration facade providing access to all sub-configs.

    This is the primary entry point for consuming configuration throughout
    the application. Each sub-config is instantiated once and cached.

    Example:
        from utils.config import Config

        cfg = Config()
        db_path = cfg.paths.database_path
        threshold = cfg.thresholds.ddos_packets_per_second
    """

    def __init__(self) -> None:
        self.meta: ProjectMeta = ProjectMeta()
        self.paths: Paths = Paths()
        self.database: DatabaseConfig = DatabaseConfig()
        self.logging: LoggingConfig = LoggingConfig()
        self.ml: MLConfig = MLConfig()
        self.thresholds: DetectionThresholds = DetectionThresholds()
        self.network: NetworkConfig = NetworkConfig()
        self.dashboard: DashboardConfig = DashboardConfig()

    def initialise_directories(self) -> None:
        """Ensure all required project directories exist."""
        self.paths.ensure_all()

    def get_env(self, key: str, default: str = "") -> str:
        """
        Retrieve a value from environment variables, falling back to default.

        Args:
            key:     Environment variable name.
            default: Fallback value if variable is not set.

        Returns:
            The environment variable value or the provided default.
        """
        return os.environ.get(key, default)

    def __repr__(self) -> str:
        return (
            f"Config("
            f"project='{self.meta.name}', "
            f"version='{self.meta.version}', "
            f"root='{self.paths.root}'"
            f")"
        )


# ──────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL SINGLETON
# ──────────────────────────────────────────────────────────────────────────────

# A shared singleton for use across the entire application.
# Import and use: `from utils.config import config`
config: Config = Config()
