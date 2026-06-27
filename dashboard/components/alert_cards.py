"""
alert_cards.py — Alert Summary Card Components
================================================
Enterprise SOC Dashboard

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

from __future__ import annotations

import streamlit as st

from dashboard.theme import Colors


def render_alert_summary_cards(summary: dict) -> None:
    """
    Render alert summary KPI cards in a row.

    Args:
        summary: Dict with keys: total, critical, high, medium, low.
    """
    total = summary.get("total", 0)
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)

    cols = st.columns(5)
    cards = [
        ("Total Alerts", str(total), "🚨", Colors.PRIMARY),
        ("Critical", str(critical), "🔴", Colors.CRITICAL),
        ("High", str(high), "🟠", Colors.SEVERITY_HIGH),
        ("Medium", str(medium), "🟡", Colors.SEVERITY_MEDIUM),
        ("Low", str(low), "🔵", Colors.SEVERITY_LOW),
    ]

    for col, (label, value, icon, color) in zip(cols, cards):
        with col:
            st.markdown(
                f'<div class="metric-card" style="border-left:3px solid {color};">'
                f'<div class="metric-label">{icon} {label}</div>'
                f'<div class="metric-value" style="color:{color};">{value}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
