"""
status_badges.py — Status Badge Components
============================================
Enterprise SOC Dashboard

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

from __future__ import annotations

import streamlit as st

from dashboard.theme import STATUS_COLORS


def render_status_badge(label: str, status: str, extra: str = "", pulse: bool = False) -> None:
    """
    Render a single status badge (pill) with coloured dot.

    Args:
        label: Badge label (e.g. "Database").
        status: Status string (e.g. "healthy", "error"). Used to pick colour.
        extra: Optional extra text after the badge.
        pulse: Whether to animate the dot with a pulse effect.
    """
    color = STATUS_COLORS.get(status.lower(), "#8B949E")
    extra_html = f' <span style="color:#8B949E;font-size:0.75rem;">{extra}</span>' if extra else ""
    pulse_class = " pulse" if pulse else ""

    st.markdown(
        f'<span class="status-badge{pulse_class}" style="background:{color}15;color:{color};border-color:{color}30;">'
        f'<span class="status-dot" style="background:{color};"></span>'
        f'{status.title()}'
        f'</span>{extra_html}',
        unsafe_allow_html=True,
    )


def render_all_status_badges() -> None:
    """Render all system status badges in a horizontal row."""
    from dashboard.data_loaders import load_system_status
    status = load_system_status()

    cols = st.columns(6)
    badges = [
        ("Database", status.get("database_status", "Unknown")),
        ("Capture", status.get("packet_capture_status", "Unknown")),
        ("Rule Engine", status.get("rule_engine_status", "Unknown")),
        ("ML Model", status.get("ml_model_status", "Unknown").split(" ")[0] if status.get("ml_model_status") else "Unknown"),
        ("Memory", f'{status["memory_mb"]} MB' if status.get("memory_mb") else "N/A"),
        ("CPU", f'{status["cpu_percent"]}%' if status.get("cpu_percent") is not None else "N/A"),
    ]

    for col, (label, stat) in zip(cols, badges):
        with col:
            render_status_badge(label, stat.lower().replace("loaded", "loaded").replace("active", "active"))
