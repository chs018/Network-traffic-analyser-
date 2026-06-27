"""
pdf_generator.py — PDF Report Generator
=========================================
Network Traffic Analysis and Intrusion Detection System

Generates professional PDF reports from traffic analysis and detection
results using the ``reportlab`` library.

Report sections:
  1. Executive Summary (KPIs and key findings)
  2. Traffic Overview (charts embedded as images)
  3. Protocol Analysis Table
  4. Detected Attacks (timeline and breakdown)
  5. Alert Log (paginated table)
  6. ML Model Performance (Phase 2)
  7. Recommendations

Classes:
    ReportConfig  — Dataclass for report customisation options
    PDFGenerator  — Main report generation class

Phase 1 Status: STUB — class interface and docstrings only.

Author: Network Traffic Analyzer Project
Version: 1.0.0
Python: 3.11+
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.config import config
from utils.helpers import utc_now_iso
from utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class ReportConfig:
    """Customisation options for a generated PDF report."""

    title: str = "Network Traffic Analysis Report"
    author: str = "Network Traffic IDS"
    organisation: str = "Final Year Project"
    include_traffic_overview: bool = True
    include_protocol_table: bool = True
    include_attack_timeline: bool = True
    include_alert_log: bool = True
    include_ml_metrics: bool = False      # Phase 2
    max_alert_rows: int = 100
    page_size: str = "A4"                # "A4" | "LETTER"
    logo_path: Optional[Path] = None


class PDFGenerator:
    """
    Generates PDF analysis reports using ``reportlab``.

    Attributes:
        output_dir (Path): Directory where generated PDFs are saved.
        config (ReportConfig): Report generation options.

    .. note::
        Phase 1 STUB — ``generate()`` writes a placeholder file.
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        report_config: Optional[ReportConfig] = None,
    ) -> None:
        """
        Initialise the PDFGenerator.

        Args:
            output_dir:    Directory for output PDFs.
                           Defaults to ``config.paths.reports_output_dir``.
            report_config: Report customisation options.
        """
        self.output_dir: Path = output_dir or config.paths.reports_output_dir
        self.config: ReportConfig = report_config or ReportConfig()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        log.debug("PDFGenerator initialised (output='%s').", self.output_dir)

    def generate(self, data: dict, filename: Optional[str] = None) -> Path:
        """
        Generate a PDF report from the provided data dict.

        Args:
            data:     Dict containing traffic summary, alerts, and metrics.
            filename: Output filename (auto-generated if None).

        Returns:
            Absolute :class:`Path` to the generated PDF file.

        .. note::
            Phase 1 STUB — creates an empty placeholder file.
        """
        if filename is None:
            timestamp = utc_now_iso().replace(":", "-").replace("+", "")
            filename = f"report_{timestamp}.pdf"

        output_path = self.output_dir / filename
        # Phase 2: build PDF with reportlab here
        output_path.touch()
        log.info("PDF report generated (stub): %s", output_path)
        return output_path
