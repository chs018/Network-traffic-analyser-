"""
home_page.py — Executive Dashboard (Landing Page)
===================================================
Enterprise SOC Dashboard

Displays executive KPIs, health gauges, analytics overview,
threat timeline, and recent alerts — the primary operations view.

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from __future__ import annotations

import streamlit as st

from dashboard.styles import get_plotly_layout
from dashboard.theme import Colors, health_color
from dashboard.data_loaders import (
    load_traffic_summary,
    load_alerts,
    load_alert_summary,
    load_health_report,
    load_quality_report,
    load_bandwidth_summary,
    load_protocol_distribution,
    load_top_sources,
    load_top_destinations,
    load_attack_distribution,
    load_alert_timeline,
    load_alert_trend,
)
from dashboard.components.section_headers import render_section_header
from dashboard.components.metric_cards import (
    render_metric_row,
    format_bytes,
    format_bps,
    format_pps,
)
from dashboard.components.gauge_cards import render_gauge_row
from dashboard.components.chart_containers import (
    render_chart,
    create_donut_chart,
    create_horizontal_bar_chart,
    create_bar_chart,
    create_line_chart,
)
from dashboard.components.timeline_cards import render_timeline
from dashboard.components.data_tables import render_alert_table


def render() -> None:
    """Render the Executive Dashboard page."""
    # ── Pipeline Result Banner (if a run just completed) ─────────────────────
    _maybe_render_pipeline_banner()

    # ── Hero Banner ──────────────────────────────────────────────────────────
    _render_hero_banner()

    # Check if there is any data at all
    traffic = load_traffic_summary()
    if traffic.get("total_packets", 0) == 0:
        _render_empty_state()
        return

    # ── KPI Cards ────────────────────────────────────────────────────────────
    render_section_header("📊", "Key Performance Indicators", "Real-time network metrics")
    _render_kpi_cards()

    st.markdown("---")

    # ── Health Gauges ────────────────────────────────────────────────────────
    render_section_header("⏱️", "Network Health Gauges", "System vital signs")
    _render_health_gauges()

    st.markdown("---")

    # ── Analytics Overview ───────────────────────────────────────────────────
    render_section_header("📈", "Analytics Overview", "Traffic and threat analysis")
    _render_analytics_charts()

    st.markdown("---")

    # ── Threat Timeline ──────────────────────────────────────────────────────
    render_section_header("🕐", "Recent Threat Timeline", "Latest security events")
    _render_threat_timeline()

    st.markdown("---")

    # ── Alert Summary Table ──────────────────────────────────────────────────
    render_section_header("📋", "Latest Alerts", "Most recent security alerts")
    _render_recent_alerts()


def _maybe_render_pipeline_banner() -> None:
    """Show a dismissible banner with the last pipeline run result."""
    result = st.session_state.get("pipeline_result")
    if not result or not result.get("success"):
        return

    # Only show the banner once after a new analysis
    if st.session_state.get("_pipeline_banner_dismissed"):
        return

    sev = result.get("highest_severity", "NONE")
    sev_color = {
        "CRITICAL": "#FF1744", "HIGH": "#FF6D00",
        "MEDIUM": "#FFB300", "LOW": "#2979FF", "NONE": "#00C851",
    }.get(sev, "#00C851")

    col1, col2 = st.columns([8, 1])
    with col1:
        st.markdown(
            f"""
            <div style="background:rgba(0,200,81,0.08);border:1px solid rgba(0,200,81,0.25);
                        border-radius:10px;padding:12px 18px;margin-bottom:12px;
                        display:flex;align-items:center;gap:16px;">
                <span style="font-size:1.4rem;">✅</span>
                <div style="flex:1;">
                    <span style="font-weight:700;color:#E6EDF3;font-size:0.9rem;">
                        Analysis Complete
                    </span>
                    <span style="font-size:0.8rem;color:#8B949E;margin-left:16px;">
                        {result.get('pcap_file','')} &nbsp;|&nbsp;
                        {result.get('packets_processed',0):,} packets &nbsp;|&nbsp;
                        {result.get('alerts_generated',0)} alerts &nbsp;|&nbsp;
                        Threat: <span style="color:{sev_color};font-weight:700;">{sev}</span>
                        &nbsp;|&nbsp; {result.get('elapsed_seconds',0):.1f}s
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        if st.button("✕", key="dismiss_pipeline_banner", help="Dismiss"):
            st.session_state._pipeline_banner_dismissed = True
            st.rerun()


def _render_empty_state() -> None:
    """Render the empty state when no traffic has been analysed yet."""
    st.markdown(
        """
        <div style="text-align:center;padding:72px 20px;
                    background:linear-gradient(135deg,rgba(21,101,192,0.06),rgba(0,188,212,0.04));
                    border-radius:20px;border:1px dashed rgba(21,101,192,0.2);
                    margin-top:24px;margin-bottom:24px;">
            <div style="font-size:4rem;margin-bottom:20px;">🛡️</div>
            <div style="font-size:1.5rem;font-weight:700;color:#E6EDF3;margin-bottom:10px;">
                No Traffic Data Available
            </div>
            <div style="font-size:0.95rem;color:#8B949E;max-width:500px;
                        margin:0 auto 32px auto;line-height:1.7;">
                Upload a PCAP / PCAPng network capture file and run the analysis 
                pipeline to populate the dashboard with real-time security insights.
                Or run Demo Mode to see the system with synthetic data.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        if st.button("📁 Upload PCAP File", type="primary", use_container_width=True, key="home_go_upload"):
            st.session_state.current_page = "upload"
            st.rerun()
    with col2:
        if st.button("🎭 Run Demo Mode", use_container_width=True, key="home_go_demo"):
            st.session_state.current_page = "upload"
            st.session_state._sidebar_trigger_demo = True
            st.rerun()
    with col3:
        if st.button("🤖 View ML Models", use_container_width=True, key="home_go_models"):
            st.session_state.current_page = "models"
            st.rerun()


def _render_hero_banner() -> None:
    """Render the executive dashboard hero banner."""
    alerts = load_alert_summary()
    health = load_health_report()
    summary = load_traffic_summary()

    total_alerts = alerts.get("total", 0)
    critical = alerts.get("critical", 0)
    health_score = health.get("health_score", 0)
    packets = summary.get("total_packets", 0)

    # Determine system status
    if critical > 0:
        status_text = "Threat Detected"
        status_color = "#FF4444"
    elif total_alerts > 0:
        status_text = "Monitoring Active"
        status_color = "#FF8800"
    elif packets > 0:
        status_text = "All Clear"
        status_color = "#00C851"
    else:
        status_text = "Awaiting Traffic"
        status_color = "#8B949E"

    st.markdown(
        f'<div class="hero-banner">'
        f'<div class="hero-title">NetTraffic IDS — Security Operations Center</div>'
        f'<div class="hero-subtitle">'
        f'Network Traffic Analysis & Intrusion Detection System | '
        f'{packets:,} packets analysed | {total_alerts} alerts | '
        f'Health: {health_score:.0f}/100'
        f'</div>'
        f'<div class="hero-status" style="background:{status_color}15;border-color:{status_color}40;color:{status_color};">'
        f'<span class="pulse-dot" style="background:{status_color};"></span>'
        f'{status_text}'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def _render_kpi_cards() -> None:
    """Render the top KPI metric cards."""
    traffic = load_traffic_summary()
    alerts = load_alert_summary()
    health = load_health_report()
    quality = load_quality_report()

    # Row 1: Core metrics
    metrics_row1 = [
        {
            "label": "Total Packets",
            "value": f"{traffic['total_packets']:,}",
            "icon": "📦",
            "color": Colors.PRIMARY,
        },
        {
            "label": "Packets/sec",
            "value": format_pps(traffic["packets_per_second"]),
            "icon": "⚡",
            "color": Colors.INFO,
        },
        {
            "label": "Bandwidth",
            "value": format_bps(traffic["bytes_per_second"] * 8),
            "icon": "📡",
            "color": Colors.PRIMARY_LIGHT,
        },
        {
            "label": "Total Alerts",
            "value": f"{alerts['total']:,}",
            "icon": "🚨",
            "color": Colors.WARNING if alerts["total"] > 0 else Colors.SUCCESS,
        },
        {
            "label": "Critical Alerts",
            "value": f"{alerts['critical']}",
            "icon": "🔴",
            "color": Colors.CRITICAL if alerts["critical"] > 0 else Colors.SUCCESS,
        },
    ]
    render_metric_row(metrics_row1)

    # Row 2: Derived metrics
    metrics_row2 = [
        {
            "label": "Active Hosts",
            "value": f"{traffic['unique_src_ips']}",
            "icon": "🖥️",
            "color": Colors.INFO,
        },
        {
            "label": "Health Score",
            "value": f"{health['health_score']:.0f}",
            "icon": "💚",
            "color": health_color(health["health_score"]),
        },
        {
            "label": "Network Quality",
            "value": f"{quality['quality_index']:.0f}",
            "icon": "📊",
            "color": health_color(quality["quality_index"]),
        },
        {
            "label": "Threat Level",
            "value": _get_threat_level(alerts),
            "icon": "🛡️",
            "color": Colors.CRITICAL if alerts["critical"] > 0 else (
                Colors.SEVERITY_HIGH if alerts["high"] > 0 else Colors.SUCCESS
            ),
        },
    ]
    render_metric_row(metrics_row2)


def _get_threat_level(alerts: dict) -> str:
    """Determine current threat level from alert counts."""
    if alerts.get("critical", 0) > 0:
        return "CRITICAL"
    elif alerts.get("high", 0) > 0:
        return "HIGH"
    elif alerts.get("medium", 0) > 0:
        return "MEDIUM"
    return "LOW"


def _render_health_gauges() -> None:
    """Render the network health gauge row."""
    health = load_health_report()
    quality = load_quality_report()
    bandwidth = load_bandwidth_summary()
    alerts = load_alert_summary()

    # Determine threat numeric value (0-100 scale)
    threat_val = 0
    if alerts["critical"] > 0:
        threat_val = 100
    elif alerts["high"] > 0:
        threat_val = 75
    elif alerts["medium"] > 0:
        threat_val = 50
    elif alerts["low"] > 0:
        threat_val = 25

    gauges = [
        {
            "title": "Health Score",
            "value": health.get("health_score", 0),
            "min_val": 0,
            "max_val": 100,
            "gauge_suffix": "",
            "height": 200,
            "key": "gauge_health",
        },
        {
            "title": "Bandwidth Utilisation",
            "value": bandwidth.get("utilisation_pct", 0),
            "min_val": 0,
            "max_val": 100,
            "gauge_suffix": "%",
            "height": 200,
            "key": "gauge_bw",
        },
        {
            "title": "Network Quality",
            "value": quality.get("quality_index", 0),
            "min_val": 0,
            "max_val": 100,
            "gauge_suffix": "",
            "height": 200,
            "key": "gauge_quality",
        },
        {
            "title": "Threat Level",
            "value": threat_val,
            "min_val": 0,
            "max_val": 100,
            "gauge_suffix": "",
            "height": 200,
            "key": "gauge_threat",
        },
    ]
    render_gauge_row(gauges)


def _render_analytics_charts() -> None:
    """Render the analytics overview charts in a 2x2 grid."""
    layout = get_plotly_layout()

    row1_col1, row1_col2 = st.columns(2)
    with row1_col1:
        _render_protocol_chart(layout)
    with row1_col2:
        _render_attack_distribution_chart(layout)

    row2_col1, row2_col2 = st.columns(2)
    with row2_col1:
        _render_top_sources_chart(layout)
    with row2_col2:
        _render_alert_trend_chart(layout)


def _render_protocol_chart(layout: dict) -> None:
    """Render protocol distribution donut chart."""
    proto_df = load_protocol_distribution()
    if proto_df.empty:
        st.info("No protocol data available.")
        return

    fig = create_donut_chart(
        labels=proto_df["protocol"].tolist(),
        values=proto_df["count"].tolist(),
        title="Protocol Distribution",
    )
    render_chart(fig, height=350, key="chart_proto")


def _render_attack_distribution_chart(layout: dict) -> None:
    """Render attack distribution donut chart."""
    attack_df = load_attack_distribution()
    if attack_df.empty:
        st.info("No attack data available.")
        return

    fig = create_donut_chart(
        labels=attack_df["attack_type"].tolist(),
        values=attack_df["count"].tolist(),
        title="Attack Distribution",
    )
    render_chart(fig, height=350, key="chart_attack_dist")


def _render_top_sources_chart(layout: dict) -> None:
    """Render top source hosts horizontal bar chart."""
    src_df = load_top_sources(10)
    if src_df.empty:
        st.info("No source data available.")
        return

    fig = create_horizontal_bar_chart(
        y=src_df["ip"].tolist(),
        x=src_df["packets"].tolist(),
        title="Top Source Hosts",
        x_label="Packets",
    )
    render_chart(fig, height=350, key="chart_top_src")


def _render_alert_trend_chart(layout: dict) -> None:
    """Render alert trend bar chart."""
    trend_df = load_alert_trend()
    if trend_df.empty:
        st.info("No alert trend data available.")
        return

    fig = create_bar_chart(
        x=[str(t) for t in trend_df["time_bucket"].tolist()],
        y=trend_df["count"].tolist(),
        title="Alert Trend (5-min buckets)",
        x_label="Time",
        y_label="Count",
        color=Colors.WARNING,
    )
    render_chart(fig, height=350, key="chart_alert_trend")


def _render_threat_timeline() -> None:
    """Render the threat timeline."""
    timeline_df = load_alert_timeline()
    render_timeline(timeline_df, max_items=10)


def _render_recent_alerts() -> None:
    """Render the recent alerts table."""
    alerts_df = load_alerts(limit=20)
    render_alert_table(alerts_df, max_rows=20, key="home_alerts")
