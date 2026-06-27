"""
theme.py — Design Tokens & Color Palette
==========================================
Enterprise SOC Dashboard Theme Configuration

Centralised colour palette, typography, spacing, and shadow tokens
used across all dashboard components for visual consistency.

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from __future__ import annotations


# ──────────────────────────────────────────────────────────────────────────────
# COLOUR PALETTE
# ──────────────────────────────────────────────────────────────────────────────

class Colors:
    """Enterprise SOC colour palette."""

    # ── Primary ───────────────────────────────────────────────────────────────
    PRIMARY = "#1565C0"
    PRIMARY_LIGHT = "#1E88E5"
    PRIMARY_DARK = "#0D47A1"

    # ── Semantic ──────────────────────────────────────────────────────────────
    SUCCESS = "#00C851"
    SUCCESS_DARK = "#00A844"
    WARNING = "#FF8800"
    WARNING_DARK = "#E67A00"
    DANGER = "#FF4444"
    DANGER_DARK = "#D32F2F"
    CRITICAL = "#D50000"
    INFO = "#00BCD4"
    INFO_DARK = "#0097A7"

    # ── Severity ──────────────────────────────────────────────────────────────
    SEVERITY_LOW = "#2196F3"
    SEVERITY_MEDIUM = "#FF9800"
    SEVERITY_HIGH = "#FF5722"
    SEVERITY_CRITICAL = "#D50000"

    # ── Backgrounds (Dark Mode) ───────────────────────────────────────────────
    BG_DARK = "#0D1117"
    BG_DARK_SECONDARY = "#161B22"
    BG_DARK_TERTIARY = "#1C2128"
    SURFACE_DARK = "#21262D"
    SURFACE_DARK_HOVER = "#30363D"

    # ── Backgrounds (Light Mode) ──────────────────────────────────────────────
    BG_LIGHT = "#FFFFFF"
    BG_LIGHT_SECONDARY = "#F6F8FA"
    BG_LIGHT_TERTIARY = "#EAEEF2"
    SURFACE_LIGHT = "#FFFFFF"
    SURFACE_LIGHT_HOVER = "#F3F4F6"

    # ── Text (Dark Mode) ──────────────────────────────────────────────────────
    TEXT_DARK_PRIMARY = "#E6EDF3"
    TEXT_DARK_SECONDARY = "#8B949E"
    TEXT_DARK_MUTED = "#6E7681"

    # ── Text (Light Mode) ─────────────────────────────────────────────────────
    TEXT_LIGHT_PRIMARY = "#1F2328"
    TEXT_LIGHT_SECONDARY = "#656D76"
    TEXT_LIGHT_MUTED = "#8B949E"

    # ── Borders ───────────────────────────────────────────────────────────────
    BORDER_DARK = "#30363D"
    BORDER_LIGHT = "#D0D7DE"

    # ── Chart Colours ─────────────────────────────────────────────────────────
    CHART_BENIGN = "#00C851"
    CHART_WARNING = "#FF8800"
    CHART_ATTACK = "#FF4444"
    CHART_PRIMARY = "#1565C0"
    CHART_PALETTE = [
        "#1565C0", "#00C851", "#FF8800", "#FF4444", "#9C27B0",
        "#00BCD4", "#FF9800", "#E91E63", "#3F51B5", "#009688",
    ]


# ──────────────────────────────────────────────────────────────────────────────
# TYPOGRAPHY
# ──────────────────────────────────────────────────────────────────────────────

class Typography:
    """Font family and size tokens."""

    FONT_FAMILY = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    FONT_MONO = "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace"

    # Sizes (px)
    SIZE_XS = "0.75rem"     # 12px
    SIZE_SM = "0.8125rem"   # 13px
    SIZE_BASE = "0.875rem"  # 14px
    SIZE_MD = "1rem"        # 16px
    SIZE_LG = "1.125rem"    # 18px
    SIZE_XL = "1.25rem"     # 20px
    SIZE_2XL = "1.5rem"     # 24px
    SIZE_3XL = "2rem"       # 32px

    # Weights
    WEIGHT_NORMAL = "400"
    WEIGHT_MEDIUM = "500"
    WEIGHT_SEMIBOLD = "600"
    WEIGHT_BOLD = "700"


# ──────────────────────────────────────────────────────────────────────────────
# SPACING & RADIUS
# ──────────────────────────────────────────────────────────────────────────────

class Spacing:
    """Consistent spacing tokens."""

    XS = "4px"
    SM = "8px"
    MD = "12px"
    LG = "16px"
    XL = "24px"
    XXL = "32px"
    XXXL = "48px"


class Radius:
    """Border radius tokens."""

    SM = "6px"
    MD = "8px"
    LG = "12px"
    XL = "16px"
    FULL = "9999px"


# ──────────────────────────────────────────────────────────────────────────────
# SHADOWS
# ──────────────────────────────────────────────────────────────────────────────

class Shadows:
    """Box shadow tokens."""

    SM = "0 1px 2px rgba(0, 0, 0, 0.05)"
    MD = "0 2px 8px rgba(0, 0, 0, 0.08)"
    LG = "0 4px 16px rgba(0, 0, 0, 0.12)"
    XL = "0 8px 32px rgba(0, 0, 0, 0.16)"


# ──────────────────────────────────────────────────────────────────────────────
# SEVERITY MAPPING
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "LOW": Colors.SEVERITY_LOW,
    "MEDIUM": Colors.SEVERITY_MEDIUM,
    "HIGH": Colors.SEVERITY_HIGH,
    "CRITICAL": Colors.SEVERITY_CRITICAL,
}

SEVERITY_BG = {
    "LOW": "rgba(33, 150, 243, 0.15)",
    "MEDIUM": "rgba(255, 152, 0, 0.15)",
    "HIGH": "rgba(255, 87, 34, 0.15)",
    "CRITICAL": "rgba(213, 0, 0, 0.15)",
}

STATUS_COLORS = {
    "healthy": Colors.SUCCESS,
    "connected": Colors.SUCCESS,
    "active": Colors.SUCCESS,
    "loaded": Colors.SUCCESS,
    "ok": Colors.SUCCESS,
    "inactive": Colors.WARNING,
    "not_loaded": Colors.WARNING,
    "warning": Colors.WARNING,
    "error": Colors.DANGER,
    "unhealthy": Colors.DANGER,
    "disconnected": Colors.DANGER,
}


# ──────────────────────────────────────────────────────────────────────────────
# HEALTH SCORE COLOURS
# ──────────────────────────────────────────────────────────────────────────────

def health_color(score: float) -> str:
    """Return colour for a health score (0-100)."""
    if score >= 90:
        return Colors.SUCCESS
    elif score >= 75:
        return "#8BC34A"
    elif score >= 55:
        return Colors.WARNING
    elif score >= 35:
        return "#FF5722"
    else:
        return Colors.CRITICAL


def health_label(score: float) -> str:
    """Return human-readable label for a health score."""
    if score >= 90:
        return "Excellent"
    elif score >= 75:
        return "Good"
    elif score >= 55:
        return "Moderate"
    elif score >= 35:
        return "Poor"
    else:
        return "Critical"


def threat_color(level: str) -> str:
    """Return colour for a threat level string."""
    return SEVERITY_COLORS.get(level.upper(), Colors.TEXT_DARK_SECONDARY)
