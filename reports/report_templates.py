"""
report_templates.py — PDF Report Template Definitions
=======================================================
Network Traffic Analysis and Intrusion Detection System

Defines reportlab paragraph styles, table styles, colour palettes,
and page layout constants used by PDFGenerator to produce consistent,
professionally styled PDF reports.

Exports:
    STYLES         — ParagraphStyle registry
    TABLE_STYLE    — Default TableStyle for data tables
    COLOUR_PALETTE — Named colour constants
    PAGE_MARGINS   — Standard page margin tuple

Phase 1 Status: STUB — style definitions and docstrings only.

Author: Network Traffic Analyzer Project
Version: 1.0.0
Python: 3.11+
"""

from __future__ import annotations

# ── Colour Palette ────────────────────────────────────────────────────────────
# Named hex colours used throughout generated reports.
# Defined as simple strings here; converted to reportlab Color objects in Phase 2.

COLOUR_PALETTE: dict[str, str] = {
    "primary":      "#1565C0",   # Deep Blue
    "secondary":    "#0288D1",   # Light Blue
    "accent":       "#00ACC1",   # Cyan
    "success":      "#2E7D32",   # Dark Green
    "warning":      "#F57F17",   # Amber
    "danger":       "#C62828",   # Dark Red
    "critical":     "#6A1B9A",   # Dark Purple
    "text_primary": "#212121",   # Near Black
    "text_muted":   "#757575",   # Grey
    "background":   "#FAFAFA",   # Off White
    "table_header": "#1565C0",   # Deep Blue
    "table_row_alt":"#E3F2FD",   # Light Blue (alternating rows)
}

# ── Page Margins ──────────────────────────────────────────────────────────────
# Margins as (left, right, top, bottom) in points (72 pt = 1 inch).
PAGE_MARGINS: tuple[float, float, float, float] = (72.0, 72.0, 72.0, 72.0)

# ── Paragraph Style Registry ─────────────────────────────────────────────────
# Placeholder dict — Phase 2 will replace with reportlab ParagraphStyle objects.
STYLES: dict[str, dict] = {
    "Title": {
        "fontSize": 24,
        "fontName": "Helvetica-Bold",
        "textColor": COLOUR_PALETTE["primary"],
        "spaceAfter": 20,
    },
    "Heading1": {
        "fontSize": 16,
        "fontName": "Helvetica-Bold",
        "textColor": COLOUR_PALETTE["primary"],
        "spaceAfter": 12,
        "spaceBefore": 20,
    },
    "Heading2": {
        "fontSize": 13,
        "fontName": "Helvetica-Bold",
        "textColor": COLOUR_PALETTE["secondary"],
        "spaceAfter": 8,
        "spaceBefore": 14,
    },
    "Body": {
        "fontSize": 10,
        "fontName": "Helvetica",
        "textColor": COLOUR_PALETTE["text_primary"],
        "leading": 14,
        "spaceAfter": 6,
    },
    "Caption": {
        "fontSize": 8,
        "fontName": "Helvetica-Oblique",
        "textColor": COLOUR_PALETTE["text_muted"],
        "spaceAfter": 4,
    },
    "TableHeader": {
        "fontSize": 9,
        "fontName": "Helvetica-Bold",
        "textColor": "#FFFFFF",
        "alignment": "CENTER",
    },
    "TableCell": {
        "fontSize": 9,
        "fontName": "Helvetica",
        "textColor": COLOUR_PALETTE["text_primary"],
    },
}

# ── Table Style ───────────────────────────────────────────────────────────────
# Placeholder list — Phase 2 replaces with reportlab TableStyle commands.
TABLE_STYLE: list[tuple] = [
    ("BACKGROUND",  (0, 0), (-1, 0),  COLOUR_PALETTE["table_header"]),
    ("TEXTCOLOR",   (0, 0), (-1, 0),  "#FFFFFF"),
    ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
    ("FONTSIZE",    (0, 0), (-1, 0),  9),
    ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
    ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
        [COLOUR_PALETTE["background"], COLOUR_PALETTE["table_row_alt"]]),
    ("GRID",        (0, 0), (-1, -1), 0.5, COLOUR_PALETTE["text_muted"]),
    ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ("RIGHTPADDING",(0, 0), (-1, -1), 6),
    ("TOPPADDING",  (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
]
