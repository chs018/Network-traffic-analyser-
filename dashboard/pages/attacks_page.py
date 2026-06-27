"""
attacks_page.py — Attack Detection Analytics Page
===================================================
Enterprise SOC Dashboard

Displays attack distribution, detection confidence,
attack trends, and per-attack-type breakdowns.

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from __future__ import annotations

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from dashboard.styles import get_plotly_layout
from dashboard.theme import Colors, SEVERITY_COLORS
from dashboard.data_loaders import (
    load_alerts,
    load_alert_summary,
    load_attack_distribution,
    load_severity_distribution,
    load_alert_trend,
)
from dashboard.components.section_headers import render_section_header
from dashboard.components.metric_cards import render_metric_row
from dashboard.components.chart_containers import (
    render_chart,
    create_donut_chart,
    create_bar_chart,
    create_horizontal_bar_chart,
)
from dashboard.components.alert_cards import render_alert_summary_cards


def render() -> None:
    """Render the Attack Detection Analytics page."""
    # ── Attack Summary ───────────────────────────────────────────────────────
    render_section_header("⚔️", "Attack Overview", "Detected threats and anomalies")
    _render_attack_summary()

    st.markdown("---")

    # ── Attack Distribution ──────────────────────────────────────────────────
    render_section_header("🎯", "Attack Distribution", "By type and severity")
    _render_attack_distribution()

    st.markdown("---")

    # ── Attack Trend ─────────────────────────────────────────────────────────
    render_section_header("📈", "Attack Trend", "Attacks over time")
    _render_attack_trend()

    st.markdown("---")

    # ── Per-Attack Breakdown ─────────────────────────────────────────────────
    render_section_header("📋", "Detailed Attack Breakdown", "Per-attack-type analysis")
    _render_per_attack_breakdown()


def _render_attack_summary() -> None:
    """Render attack summary KPIs."""
    summary = load_alert_summary()
    render_alert_summary_cards(summary)


def _render_attack_distribution() -> None:
    """Render attack distribution charts."""
    layout = get_plotly_layout()

    col1, col2 = st.columns(2)

    with col1:
        attack_df = load_attack_distribution()
        if attack_df.empty:
            st.info("No attack data available.")
        else:
            fig = create_donut_chart(
                labels=attack_df["attack_type"].tolist(),
                values=attack_df["count"].tolist(),
                title="Attacks by Type",
            )
            render_chart(fig, height=400, key="attack_type_donut")

    with col2:
        sev_df = load_severity_distribution()
        if sev_df.empty:
            st.info("No severity data available.")
        else:
            colors = [SEVERITY_COLORS.get(s, "#8B949E") for s in sev_df["severity"]]
            fig = go.Figure(go.Bar(
                x=sev_df["severity"],
                y=sev_df["count"],
                marker_color=colors,
                text=sev_df["count"],
                textposition="auto",
                hovertemplate="%{x}: %{y}<extra></extra>",
            ))
            fig.update_layout(
                title="Alerts by Severity",
                xaxis_title="Severity",
                yaxis_title="Count",
            )
            render_chart(fig, height=400, key="attack_sev_bar")


def _render_attack_trend() -> None:
    """Render attack trend over time."""
    trend_df = load_alert_trend()
    if trend_df.empty:
        st.info("No trend data available.")
        return

    fig = create_bar_chart(
        x=[str(t) for t in trend_df["time_bucket"].tolist()],
        y=trend_df["count"].tolist(),
        title="Alert Volume (5-minute intervals)",
        x_label="Time",
        y_label="Alerts",
        color=Colors.WARNING,
    )
    render_chart(fig, height=350, key="attack_trend")


def _render_per_attack_breakdown() -> None:
    """Render per-attack-type detail tables."""
    summary = load_alert_summary()
    attack_counts = summary.get("attack_counts", {})

    if not attack_counts:
        st.info("No attacks detected yet.")
        return

    for attack_type, count in attack_counts.items():
        with st.expander(f"**{attack_type}** — {count} alerts", expanded=False):
            df = load_alerts(limit=100, alert_type=attack_type)
            if not df.empty:
                display_cols = ["id", "timestamp", "severity", "src_ip", "dst_ip", "description"]
                available = [c for c in display_cols if c in df.columns]
                st.dataframe(
                    df[available].head(25),
                    use_container_width=True,
                    height=min(35 * min(len(df), 25) + 40, 500),
                )
            else:
                st.info("No alerts for this attack type.")
