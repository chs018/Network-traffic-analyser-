"""
system_page.py — System Status Panel
======================================
Enterprise SOC Dashboard

Displays database status, capture status, rule engine status,
ML model status, configuration, version info, and resource usage.

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from __future__ import annotations

import streamlit as st

from dashboard.styles import get_plotly_layout
from dashboard.theme import Colors, STATUS_COLORS
from dashboard.data_loaders import load_system_status
from dashboard.components.section_headers import render_section_header
from dashboard.components.status_badges import render_status_badge
from dashboard.components.metric_cards import render_metric_row


def render() -> None:
    """Render the System Status page."""
    status = load_system_status()
    layout = get_plotly_layout()
    text_color = layout.get("font", {}).get("color", "#E6EDF3")

    # ── System Overview ──────────────────────────────────────────────────────
    render_section_header("🖥️", "System Status", "Infrastructure health")
    _render_system_overview(status, text_color)

    st.markdown("---")

    # ── Component Status ─────────────────────────────────────────────────────
    render_section_header("🔧", "Component Status", "All subsystems")
    _render_component_status(status, text_color)

    st.markdown("---")

    # ── Resource Usage ───────────────────────────────────────────────────────
    render_section_header("📊", "Resource Usage", "Memory, CPU, and Disk")
    _render_resource_usage(status, text_color)
    _render_live_system_gauges()

    st.markdown("---")

    # ── Database Management ──────────────────────────────────────────────────
    render_section_header("🗄️", "Database Management", "Inspect and maintain the traffic database")
    _render_db_management()

    st.markdown("---")

    # ── Configuration ────────────────────────────────────────────────────────
    render_section_header("⚙️", "Configuration", "Current settings")
    _render_configuration(status, text_color)

    st.markdown("---")

    # ── Application Log Viewer ───────────────────────────────────────────────
    render_section_header("📜", "Application Log", "Last 100 log lines (newest first)")
    _render_log_viewer()


def _render_system_overview(status: dict, text_color: str) -> None:
    """Render system overview KPI cards."""
    metrics = [
        {
            "label": "Database",
            "value": status.get("database_status", "Unknown"),
            "icon": "🗄️",
            "color": STATUS_COLORS.get(status.get("database_status", "").lower(), Colors.TEXT_DARK_SECONDARY),
        },
        {
            "label": "Traffic Records",
            "value": f"{status.get('database_records', 0):,}",
            "icon": "📦",
            "color": Colors.PRIMARY,
        },
        {
            "label": "Database Size",
            "value": status.get("database_size", "0 KB"),
            "icon": "💾",
            "color": Colors.INFO,
        },
        {
            "label": "App Uptime",
            "value": status.get("app_uptime", "0s"),
            "icon": "⏱️",
            "color": Colors.SUCCESS,
        },
    ]
    render_metric_row(metrics)


def _render_component_status(status: dict, text_color: str) -> None:
    """Render component status grid."""
    components = [
        ("Database", status.get("database_status", "Unknown").lower(), "SQLite connection"),
        ("Packet Capture", status.get("packet_capture_status", "Unknown").lower(), "PCAP reader"),
        ("Rule Engine", status.get("rule_engine_status", "Unknown").lower(), "IDS detection"),
        ("ML Model", status.get("ml_model_status", "Unknown").split(" ")[0].lower(), "Anomaly/classifier"),
    ]

    cols = st.columns(4)
    for col, (name, stat, desc) in zip(cols, components):
        with col:
            st.markdown(
                f'<div class="info-card">'
                f'<div class="info-label">{name}</div>'
                f'<div style="margin:8px 0;">',
                unsafe_allow_html=True,
            )
            render_status_badge(name, stat)
            st.markdown(
                f'</div>'
                f'<div style="font-size:0.75rem;color:#8B949E;">{desc}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )


def _render_resource_usage(status: dict, text_color: str) -> None:
    """Render memory and CPU usage."""
    mem = status.get("memory_mb")
    cpu = status.get("cpu_percent")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            f'<div class="info-card">'
            f'<div class="info-label">Memory Usage</div>'
            f'<div class="info-value" style="color:{Colors.PRIMARY};">'
            f'{mem} MB</div>' if mem else
            f'<div class="info-card">'
            f'<div class="info-label">Memory Usage</div>'
            f'<div class="info-value" style="color:#8B949E;">N/A</div>',
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        color = Colors.SUCCESS if cpu and cpu < 50 else (Colors.WARNING if cpu and cpu < 80 else Colors.DANGER)
        st.markdown(
            f'<div class="info-card">'
            f'<div class="info-label">CPU Usage</div>'
            f'<div class="info-value" style="color:{color};">'
            f'{cpu}%</div>' if cpu else
            f'<div class="info-card">'
            f'<div class="info-label">CPU Usage</div>'
            f'<div class="info-value" style="color:#8B949E;">N/A</div>',
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with col3:
        st.markdown(
            f'<div class="info-card">'
            f'<div class="info-label">Python Version</div>'
            f'<div class="info-value" style="color:{Colors.INFO};">'
            f'{status.get("python_version", "N/A")}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


def _render_configuration(status: dict, text_color: str) -> None:
    """Render current configuration details."""
    from utils.config import config

    with st.expander("Application Configuration", expanded=False):
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**General**")
            st.markdown(f"- App Name: `{config.meta.name}`")
            st.markdown(f"- Version: `{config.meta.version}`")
            st.markdown(f"- Python: `{status.get('python_version', 'N/A')}`")

        with col2:
            st.markdown("**Dashboard**")
            st.markdown(f"- Refresh Interval: `{config.dashboard.refresh_interval_seconds}s`")
            st.markdown(f"- Chart Theme: `{config.dashboard.chart_theme}`")
            st.markdown(f"- Layout: `{config.dashboard.layout}`")

    with st.expander("Detection Thresholds", expanded=False):
        from utils.config import config
        t = config.thresholds
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**DDoS Detection**")
            st.markdown(f"- Packets/sec threshold: `{t.ddos_packets_per_second}`")
            st.markdown(f"- Unique source IPs: `{t.ddos_unique_src_ips}`")
        with col2:
            st.markdown("**Port Scan Detection**")
            st.markdown(f"- Unique ports: `{t.portscan_unique_ports}`")
            st.markdown(f"- Time window: `{t.portscan_time_window_seconds}s`")


# ── NEW SECTIONS ──────────────────────────────────────────────────────────────

def _render_live_system_gauges() -> None:
    """Render real-time CPU, RAM, and disk gauges using psutil."""
    try:
        import psutil
        import os
    except ImportError:
        st.info("Install `psutil` for live system gauges: `pip install psutil`")
        return

    try:
        cpu_pct = psutil.cpu_percent(interval=0.3)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage(".")

        cpu_color = (
            Colors.SUCCESS if cpu_pct < 50
            else Colors.WARNING if cpu_pct < 80
            else Colors.DANGER
        )
        ram_pct = ram.percent
        ram_color = (
            Colors.SUCCESS if ram_pct < 60
            else Colors.WARNING if ram_pct < 85
            else Colors.DANGER
        )
        disk_pct = disk.percent
        disk_color = (
            Colors.SUCCESS if disk_pct < 70
            else Colors.WARNING if disk_pct < 90
            else Colors.DANGER
        )

        st.markdown("**Live Resource Gauges**")
        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown(
                f"""
                <div class="gauge-card">
                    <div style="font-size:0.7rem;color:#8B949E;text-transform:uppercase;
                                letter-spacing:0.08em;margin-bottom:8px;">CPU</div>
                    <div style="font-size:1.8rem;font-weight:800;color:{cpu_color};">
                        {cpu_pct:.1f}%
                    </div>
                    <div style="background:rgba(255,255,255,0.07);height:6px;
                                border-radius:3px;margin-top:8px;">
                        <div style="background:{cpu_color};width:{cpu_pct:.1f}%;
                                    height:6px;border-radius:3px;"></div>
                    </div>
                    <div style="font-size:0.7rem;color:#8B949E;margin-top:6px;">
                        {psutil.cpu_count()} cores
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col2:
            ram_used_gb = ram.used / (1024**3)
            ram_total_gb = ram.total / (1024**3)
            st.markdown(
                f"""
                <div class="gauge-card">
                    <div style="font-size:0.7rem;color:#8B949E;text-transform:uppercase;
                                letter-spacing:0.08em;margin-bottom:8px;">RAM</div>
                    <div style="font-size:1.8rem;font-weight:800;color:{ram_color};">
                        {ram_pct:.1f}%
                    </div>
                    <div style="background:rgba(255,255,255,0.07);height:6px;
                                border-radius:3px;margin-top:8px;">
                        <div style="background:{ram_color};width:{ram_pct:.1f}%;
                                    height:6px;border-radius:3px;"></div>
                    </div>
                    <div style="font-size:0.7rem;color:#8B949E;margin-top:6px;">
                        {ram_used_gb:.1f} / {ram_total_gb:.1f} GB
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col3:
            disk_free_gb = disk.free / (1024**3)
            disk_total_gb = disk.total / (1024**3)
            st.markdown(
                f"""
                <div class="gauge-card">
                    <div style="font-size:0.7rem;color:#8B949E;text-transform:uppercase;
                                letter-spacing:0.08em;margin-bottom:8px;">DISK</div>
                    <div style="font-size:1.8rem;font-weight:800;color:{disk_color};">
                        {disk_pct:.1f}%
                    </div>
                    <div style="background:rgba(255,255,255,0.07);height:6px;
                                border-radius:3px;margin-top:8px;">
                        <div style="background:{disk_color};width:{disk_pct:.1f}%;
                                    height:6px;border-radius:3px;"></div>
                    </div>
                    <div style="font-size:0.7rem;color:#8B949E;margin-top:6px;">
                        {disk_free_gb:.1f} GB free / {disk_total_gb:.1f} GB total
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    except Exception as e:
        st.warning(f"Live gauges error: {e}")


def _render_db_management() -> None:
    """Render database inspection and management controls."""
    from dashboard.data_loaders import _get_db

    try:
        db = _get_db()
        health = db.health_check()

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Traffic Records", f"{health.get('traffic_records', 0):,}")
        with col2:
            st.metric("Total Alerts", f"{health.get('total_alerts', 0):,}")
        with col3:
            size = health.get('db_size_bytes', 0)
            st.metric("DB Size", f"{size/1024:.1f} KB" if size < 1_048_576 else f"{size/1_048_576:.1f} MB")

        st.markdown("")
        col_a, col_b, col_c = st.columns(3)

        with col_a:
            if st.button(
                "🗑️ Clear Traffic Records",
                use_container_width=True,
                key="btn_clear_traffic",
                help="Delete all traffic_logs records (keeps alerts)",
            ):
                try:
                    if hasattr(db, "clear_traffic_records"):
                        db.clear_traffic_records()
                    else:
                        with db._conn() as conn:
                            conn.execute("DELETE FROM traffic_logs")
                    from dashboard.data_loaders import invalidate_all_caches
                    invalidate_all_caches()
                    st.success("✅ Traffic records cleared.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error: {e}")

        with col_b:
            if st.button(
                "🗑️ Clear All Alerts",
                use_container_width=True,
                key="btn_clear_alerts",
                help="Delete all alert records",
            ):
                try:
                    if hasattr(db, "clear_alerts"):
                        db.clear_alerts()
                    else:
                        with db._conn() as conn:
                            conn.execute("DELETE FROM alerts")
                    from dashboard.data_loaders import invalidate_all_caches
                    invalidate_all_caches()
                    st.success("✅ Alerts cleared.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error: {e}")

        with col_c:
            if st.button(
                "🔧 Vacuum DB",
                use_container_width=True,
                key="btn_vacuum_db",
                help="Run SQLite VACUUM to reclaim disk space",
            ):
                try:
                    import sqlite3
                    from utils.config import config
                    db_path = config.paths.database_path
                    with sqlite3.connect(str(db_path)) as conn:
                        conn.execute("VACUUM")
                    st.success("✅ Database vacuumed successfully.")
                except Exception as e:
                    st.error(f"Vacuum error: {e}")

    except Exception as e:
        st.warning(f"Database management unavailable: {e}")


def _render_log_viewer() -> None:
    """Render the application log viewer."""
    from dashboard.data_loaders import load_recent_log_lines

    lines = load_recent_log_lines(n=100)

    col1, col2 = st.columns([4, 1])
    with col2:
        if st.button("🔄 Refresh Logs", use_container_width=True, key="btn_refresh_logs"):
            st.rerun()

    if not lines:
        st.info("No log lines available.")
        return

    # Color-code by log level
    colored_lines = []
    for line in lines[:50]:  # show top 50
        if "ERROR" in line or "CRITICAL" in line:
            color = "#FF4444"
        elif "WARNING" in line:
            color = "#FFB300"
        elif "INFO" in line:
            color = "#8B949E"
        else:
            color = "#6E7681"
        escaped = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        colored_lines.append(f'<span style="color:{color};">{escaped}</span>')

    log_html = "<br/>".join(colored_lines)
    st.markdown(
        f"""
        <div style="background:#0D1117;border:1px solid rgba(255,255,255,0.08);
                    border-radius:10px;padding:16px;font-family:monospace;
                    font-size:0.72rem;line-height:1.8;max-height:400px;
                    overflow-y:auto;">
            {log_html}
        </div>
        """,
        unsafe_allow_html=True,
    )

