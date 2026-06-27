"""
timeline_cards.py — Threat Timeline Components
================================================
Enterprise SOC Dashboard

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from dashboard.theme import SEVERITY_COLORS


def render_timeline_card(row: dict) -> None:
    """
    Render a single threat timeline event card.

    Args:
        row: Dict with keys: timestamp, alert_type, severity, src_ip, dst_ip,
             description (recommendation), and optionally confidence.
    """
    severity = row.get("severity", "MEDIUM").upper()
    sev_color = SEVERITY_COLORS.get(severity, "#8B949E")
    timestamp = row.get("timestamp", "N/A")
    attack = row.get("alert_type", "Unknown")
    src_ip = row.get("src_ip", "?")
    dst_ip = row.get("dst_ip", "?")
    dst_port = row.get("dst_port", "")
    recommendation = row.get("description", "")

    port_html = f':{dst_port}' if dst_port else ""

    st.markdown(
        f'<div class="timeline-card severity-{severity}">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">'
        f'<div>'
        f'<span class="timeline-attack" style="color:{sev_color};">{attack}</span>'
        f' <span class="status-badge" style="background:{sev_color}20;color:{sev_color};font-size:0.7rem;">{severity}</span>'
        f'</div>'
        f'<span class="timeline-timestamp">{timestamp}</span>'
        f'</div>'
        f'<div class="timeline-ips">'
        f'{src_ip} &rarr; {dst_ip}{port_html}'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_timeline(df: pd.DataFrame, max_items: int = 20) -> None:
    """
    Render a threat timeline from a DataFrame of alerts.

    Args:
        df: DataFrame with alert data (columns: timestamp, alert_type, severity,
            src_ip, dst_ip, description, dst_port).
        max_items: Maximum number of timeline cards to render.
    """
    if df.empty:
        st.info("No threat events to display.")
        return

    # Sort newest first
    if "timestamp" in df.columns:
        df = df.sort_values("timestamp", ascending=False)

    for _, row in df.head(max_items).iterrows():
        render_timeline_card(row.to_dict())
