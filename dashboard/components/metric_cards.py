"""
metric_cards.py — KPI Metric Card Components
==============================================
Enterprise SOC Dashboard

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

from __future__ import annotations

from typing import Optional

import streamlit as st

from dashboard.theme import Colors


def render_metric_card(
    label: str,
    value: str,
    icon: str = "",
    delta: Optional[str] = None,
    delta_color: str = "neutral",
    help_text: str = "",
    color: Optional[str] = None,
) -> None:
    """
    Render a single KPI metric card.

    Args:
        label: Metric label text.
        value: Formatted metric value.
        icon: Optional emoji icon.
        delta: Optional delta/change text (e.g. "+12%").
        delta_color: "positive", "negative", or "neutral".
        help_text: Optional tooltip text.
        color: Optional accent colour for the value.
    """
    icon_html = f'<div class="metric-icon">{icon}</div>' if icon else ""
    value_style = f'color:{color};' if color else ""
    delta_html = ""
    if delta:
        delta_html = f'<div class="metric-delta {delta_color}">{delta}</div>'
    help_attr = f' title="{help_text}"' if help_text else ""

    st.markdown(
        f'<div class="metric-card"{help_attr}>'
        f'{icon_html}'
        f'<div class="metric-label">{label}</div>'
        f'<div class="metric-value" style="{value_style}">{value}</div>'
        f'{delta_html}'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_metric_row(metrics: list[dict]) -> None:
    """
    Render a row of metric cards.

    Args:
        metrics: List of dicts with keys: label, value, icon, delta, delta_color, color.
    """
    n = len(metrics)
    if n == 0:
        return
    cols = st.columns(n)
    for col, m in zip(cols, metrics):
        with col:
            render_metric_card(
                label=m.get("label", ""),
                value=m.get("value", "0"),
                icon=m.get("icon", ""),
                delta=m.get("delta"),
                delta_color=m.get("delta_color", "neutral"),
                help_text=m.get("help_text", ""),
                color=m.get("color"),
            )


def format_bytes(size_bytes: int) -> str:
    """Format bytes into human-readable string."""
    if size_bytes >= 1_073_741_824:
        return f"{size_bytes / 1_073_741_824:.2f} GB"
    elif size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} B"


def format_bps(bps: float) -> str:
    """Format bits-per-second into human-readable string."""
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    elif bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    elif bps >= 1_000:
        return f"{bps / 1_000:.2f} Kbps"
    return f"{bps:.0f} bps"


def format_pps(pps: float) -> str:
    """Format packets-per-second into human-readable string."""
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.2f} Mpps"
    elif pps >= 1_000:
        return f"{pps / 1_000:.2f} Kpps"
    return f"{pps:.0f} pps"
