"""
traffic_page.py — Traffic Analytics Page
==========================================
Enterprise SOC Dashboard

Displays traffic statistics, protocol distribution, bandwidth trends,
top hosts, and packet size distribution.

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from __future__ import annotations

import streamlit as st
import pandas as pd

from dashboard.styles import get_plotly_layout
from dashboard.theme import Colors
from dashboard.data_loaders import (
    load_traffic_summary,
    load_protocol_distribution,
    load_bandwidth_summary,
    load_top_sources,
    load_top_destinations,
    _load_traffic_dataframe,
)
from dashboard.components.section_headers import render_section_header
from dashboard.components.metric_cards import (
    render_metric_row,
    format_bytes,
    format_bps,
    format_pps,
)
from dashboard.components.chart_containers import (
    render_chart,
    create_donut_chart,
    create_horizontal_bar_chart,
    create_line_chart,
)


def render() -> None:
    """Render the Traffic Analytics page."""
    # ── Traffic Overview KPIs ────────────────────────────────────────────────
    render_section_header("📈", "Traffic Overview", "Packet capture statistics")
    _render_traffic_kpis()

    st.markdown("---")

    # ── Protocol Distribution ────────────────────────────────────────────────
    render_section_header("📋", "Protocol Distribution", "Traffic breakdown by protocol")
    _render_protocol_section()

    st.markdown("---")

    # ── Bandwidth Trend ──────────────────────────────────────────────────────
    render_section_header("📡", "Bandwidth Analysis", "Throughput over time")
    _render_bandwidth_section()

    st.markdown("---")

    # ── Top Hosts ────────────────────────────────────────────────────────────
    render_section_header("🖥️", "Top Hosts", "Most active network endpoints")
    _render_top_hosts_section()

    st.markdown("---")

    # ── Packet Size Distribution ─────────────────────────────────────────────
    render_section_header("📦", "Packet Size Distribution", "Size analysis")
    _render_packet_size_distribution()


def _render_traffic_kpis() -> None:
    """Render traffic summary KPI cards."""
    summary = load_traffic_summary()
    bw = load_bandwidth_summary()

    metrics = [
        {
            "label": "Total Packets",
            "value": f"{summary['total_packets']:,}",
            "icon": "📦",
            "color": Colors.PRIMARY,
        },
        {
            "label": "Total Bytes",
            "value": format_bytes(summary["total_bytes"]),
            "icon": "💾",
            "color": Colors.INFO,
        },
        {
            "label": "Packets/sec",
            "value": format_pps(summary["packets_per_second"]),
            "icon": "⚡",
            "color": Colors.PRIMARY_LIGHT,
        },
        {
            "label": "Bytes/sec",
            "value": format_bps(bw.get("current_bps", 0)),
            "icon": "📡",
            "color": Colors.INFO,
        },
    ]
    render_metric_row(metrics)

    metrics2 = [
        {
            "label": "Capture Duration",
            "value": f"{summary['capture_duration']:.1f}s",
            "icon": "⏱️",
        },
        {
            "label": "Avg Packet Size",
            "value": f"{summary['avg_packet_size']:.0f} B",
            "icon": "📏",
        },
        {
            "label": "Unique Src IPs",
            "value": f"{summary['unique_src_ips']}",
            "icon": "🔵",
        },
        {
            "label": "Unique Dst IPs",
            "value": f"{summary['unique_dst_ips']}",
            "icon": "🟣",
        },
    ]
    render_metric_row(metrics2)


def _render_protocol_section() -> None:
    """Render protocol distribution charts."""
    proto_df = load_protocol_distribution()

    col1, col2 = st.columns([1, 1])

    with col1:
        if proto_df.empty:
            st.info("No protocol data available.")
        else:
            fig = create_donut_chart(
                labels=proto_df["protocol"].tolist(),
                values=proto_df["count"].tolist(),
                title="Protocol Breakdown",
            )
            render_chart(fig, height=400, key="traffic_proto_donut")

    with col2:
        if proto_df.empty:
            st.info("No protocol data available.")
        else:
            fig = create_horizontal_bar_chart(
                y=proto_df["protocol"].tolist(),
                x=proto_df["count"].tolist(),
                title="Protocol Counts",
                x_label="Packets",
            )
            render_chart(fig, height=400, key="traffic_proto_bar")


def _render_bandwidth_section() -> None:
    """Render bandwidth analysis."""
    bw = load_bandwidth_summary()

    metrics = [
        {
            "label": "Current Bandwidth",
            "value": format_bps(bw.get("current_bps", 0)),
            "icon": "📡",
            "color": Colors.PRIMARY,
        },
        {
            "label": "Peak Bandwidth",
            "value": format_bps(bw.get("peak_bps", 0)),
            "icon": "🔺",
            "color": Colors.WARNING,
        },
        {
            "label": "Average Bandwidth",
            "value": format_bps(bw.get("avg_bps", 0)),
            "icon": "📊",
            "color": Colors.INFO,
        },
        {
            "label": "Utilisation",
            "value": f"{bw.get('utilisation_pct', 0):.1f}%",
            "icon": "📈",
            "color": Colors.SUCCESS if bw.get("utilisation_pct", 0) < 80 else Colors.WARNING,
        },
    ]
    render_metric_row(metrics)


def _render_top_hosts_section() -> None:
    """Render top source and destination hosts."""
    col1, col2 = st.columns(2)

    with col1:
        src_df = load_top_sources(10)
        if src_df.empty:
            st.info("No source data available.")
        else:
            fig = create_horizontal_bar_chart(
                y=src_df["ip"].tolist(),
                x=src_df["packets"].tolist(),
                title="Top 10 Source Hosts",
                x_label="Packets",
            )
            render_chart(fig, height=400, key="traffic_top_src")

    with col2:
        dst_df = load_top_destinations(10)
        if dst_df.empty:
            st.info("No destination data available.")
        else:
            fig = create_horizontal_bar_chart(
                y=dst_df["ip"].tolist(),
                x=dst_df["packets"].tolist(),
                title="Top 10 Destination Hosts",
                x_label="Packets",
                color=Colors.INFO,
            )
            render_chart(fig, height=400, key="traffic_top_dst")


def _render_packet_size_distribution() -> None:
    """Render packet size histogram."""
    df = _load_traffic_dataframe()
    if df is None or df.empty:
        st.info("No packet data available for size distribution.")
        return

    if "packet_length" not in df.columns:
        st.info("Packet length data not available.")
        return

    import plotly.graph_objects as go
    from dashboard.components.chart_containers import render_chart

    fig = go.Figure(go.Histogram(
        x=df["packet_length"],
        nbinsx=50,
        marker_color=Colors.PRIMARY,
        opacity=0.8,
    ))
    fig.update_layout(
        title="Packet Size Distribution",
        xaxis_title="Packet Size (bytes)",
        yaxis_title="Count",
    )
    render_chart(fig, height=350, key="traffic_pkt_size")
