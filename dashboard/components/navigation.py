"""
navigation.py — Left Sidebar Navigation Component
===================================================
Enterprise SOC Dashboard

Always-visible left sidebar with:
  - Branding header
  - PCAP upload widget with start/stop/demo controls
  - Live pipeline status bar
  - Navigation menu (9 pages)
  - Quick actions (refresh, export, reset, DB clear)
  - Footer

Author: Network Traffic Analyzer Project
Version: 7.5.0
"""

from __future__ import annotations

import time
from datetime import datetime

import streamlit as st

from dashboard.theme import Colors, health_color, health_label, threat_color
from dashboard.styles import get_plotly_layout


# Navigation menu: (icon, label, page_key)
NAV_ITEMS = [
    ("📊", "Dashboard",       "home"),
    ("📁", "Upload & Analyse","upload"),
    ("📈", "Traffic",         "traffic"),
    ("⚔️", "Attacks",         "attacks"),
    ("🚨", "Alerts",          "alerts"),
    ("🔬", "Packet Explorer", "packets"),
    ("📋", "Reports",         "reports"),
    ("🤖", "ML Models",       "models"),
    ("🖥️", "System",          "system"),
]


def render_sidebar() -> str:
    """
    Render the left navigation sidebar and return the selected page key.

    Returns:
        The selected page key string (e.g. "home", "upload", "traffic", …).
    """
    with st.sidebar:
        # ── Logo & Branding ──────────────────────────────────────────────────
        st.markdown(
            '<div style="text-align:center;padding:16px 12px;margin-bottom:8px;'
            'background:linear-gradient(135deg,rgba(21,101,192,0.2),rgba(0,188,212,0.1));'
            'border-radius:12px;border:1px solid rgba(21,101,192,0.2);">'
            '<div style="font-size:2.2rem;margin-bottom:4px;">🛡️</div>'
            '<div style="font-size:1.15rem;font-weight:700;color:#E6EDF3;'
            'letter-spacing:-0.02em;">NetTraffic IDS</div>'
            '<div style="font-size:0.65rem;color:#8B949E;margin-top:4px;'
            'letter-spacing:0.05em;">ENTERPRISE SOC</div>'
            '<div style="margin-top:8px;">'
            '<span style="display:inline-block;padding:2px 8px;border-radius:9999px;'
            'background:rgba(0,200,81,0.15);color:#00C851;font-size:0.6rem;'
            'font-weight:600;border:1px solid rgba(0,200,81,0.3);">'
            f'v{config_version()}</span>'
            '</div>'
            '</div>',
            unsafe_allow_html=True,
        )

        st.markdown("---")

        # ── Live Clock ───────────────────────────────────────────────────────
        _render_live_clock()

        st.markdown("---")

        # ── Upload PCAP Section ──────────────────────────────────────────────
        _render_upload_section()

        st.markdown("---")

        # ── Pipeline Status Bar ──────────────────────────────────────────────
        _render_pipeline_status()

        st.markdown("---")

        # ── Network Status ───────────────────────────────────────────────────
        _render_network_status()

        st.markdown("---")

        # ── Navigation Menu ──────────────────────────────────────────────────
        selected = _render_nav_menu()

        st.markdown("---")

        # ── Quick Actions ────────────────────────────────────────────────────
        _render_actions()

        st.markdown("---")

        # ── Footer ───────────────────────────────────────────────────────────
        _render_footer()

    return selected


def _render_live_clock() -> None:
    """Render a live-updating clock in the sidebar."""
    clock_placeholder = st.empty()
    now = datetime.now()
    clock_placeholder.markdown(
        f'<div class="live-clock">'
        f'🕐 {now.strftime("%H:%M:%S")}<br/>'
        f'<span style="font-size:0.7rem;">{now.strftime("%d %b %Y")}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )


def _render_upload_section() -> None:
    """Render the sidebar upload widget and pipeline controls."""
    st.markdown(
        '<div style="font-size:0.7rem;color:#8B949E;text-transform:uppercase;'
        'letter-spacing:0.08em;margin-bottom:8px;font-weight:600;">📁 Quick Upload</div>',
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Upload PCAP",
        type=["pcap", "pcapng", "cap"],
        label_visibility="collapsed",
        key="sidebar_pcap_uploader",
    )

    if uploaded_file is not None:
        from pathlib import Path
        raw_dir = Path("data") / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        save_path = raw_dir / uploaded_file.name
        with open(save_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        st.session_state.current_file = str(save_path)
        st.session_state.current_file_name = uploaded_file.name
        st.success(f"✅ {uploaded_file.name}")

    # Controls row
    running = st.session_state.get("pipeline_running", False)
    col1, col2 = st.columns(2)

    with col1:
        has_file = bool(st.session_state.get("current_file"))
        if st.button(
            "▶ Run" if not running else "⏳ Running…",
            use_container_width=True,
            disabled=(running or not has_file),
            key="sidebar_btn_run",
            type="primary" if has_file and not running else "secondary",
        ):
            _run_pipeline_from_sidebar()

    with col2:
        if st.button(
            "🎭 Demo",
            use_container_width=True,
            disabled=running,
            key="sidebar_btn_demo",
            help="Run with synthetic demo data",
        ):
            _run_demo_from_sidebar()

    # Stop button
    if running:
        if st.button("⏹ Stop Pipeline", use_container_width=True, key="sidebar_btn_stop"):
            st.session_state["_stop_pipeline"] = True
            st.warning("Stop requested…")


def _run_pipeline_from_sidebar() -> None:
    """Navigate to upload page and trigger run."""
    st.session_state.current_page = "upload"
    st.session_state._sidebar_trigger_run = True
    st.rerun()


def _run_demo_from_sidebar() -> None:
    """Navigate to upload page and trigger demo."""
    st.session_state.current_page = "upload"
    st.session_state._sidebar_trigger_demo = True
    st.rerun()


def _render_pipeline_status() -> None:
    """Render live pipeline status in the sidebar."""
    running = st.session_state.get("pipeline_running", False)
    phase = st.session_state.get("pipeline_phase", "Idle")
    progress = st.session_state.get("pipeline_progress", 0.0)
    packets = st.session_state.get("pipeline_packets_done", 0)
    elapsed = st.session_state.get("pipeline_elapsed", 0.0)
    current_file = st.session_state.get("current_file_name", "")
    analysis_done = st.session_state.get("analysis_complete", False)

    if running:
        status_color = "#F59E0B"   # amber — running
        status_label = "ANALYSING"
        dot_anim = "animation:pulse 1s infinite;"
    elif analysis_done:
        status_color = "#00C851"   # green — done
        status_label = "COMPLETE"
        dot_anim = ""
    else:
        status_color = "#6E7681"   # grey — idle
        status_label = "IDLE"
        dot_anim = ""

    file_display = current_file[:20] + "…" if len(current_file) > 20 else (current_file or "No file")

    st.markdown(
        f"""
        <div style="font-size:0.7rem;color:#8B949E;text-transform:uppercase;
                    letter-spacing:0.08em;margin-bottom:8px;font-weight:600;">
            Pipeline Status
        </div>
        <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);
                    border-radius:8px;padding:10px 12px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
                <span style="width:8px;height:8px;border-radius:50%;
                             background:{status_color};display:inline-block;{dot_anim}
                             box-shadow:0 0 5px {status_color}60;"></span>
                <span style="font-size:0.7rem;font-weight:700;color:{status_color};">
                    {status_label}
                </span>
            </div>
            <div style="font-size:0.7rem;color:#8B949E;line-height:1.8;">
                📎 File: <span style="color:#E6EDF3;">{file_display}</span><br/>
                ⚙️ Phase: <span style="color:#E6EDF3;">{phase[:30]}</span><br/>
                📦 Packets: <span style="color:#E6EDF3;">{packets:,}</span><br/>
                ⏱️ Elapsed: <span style="color:#E6EDF3;">{elapsed:.1f}s</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if running:
        st.progress(progress)


def _render_network_status() -> None:
    """Render current network status indicators."""
    from dashboard.data_loaders import load_health_report, load_alert_summary

    layout = get_plotly_layout()
    text_color = layout.get("font", {}).get("color", "#E6EDF3")

    health = load_health_report()
    alerts = load_alert_summary()

    health_score = health.get("health_score", 0)
    h_color = health_color(health_score)
    h_label = health_label(health_score)

    # Determine threat level from alerts
    if alerts.get("critical", 0) > 0:
        threat_lvl = "CRITICAL"
    elif alerts.get("high", 0) > 0:
        threat_lvl = "HIGH"
    elif alerts.get("medium", 0) > 0:
        threat_lvl = "MEDIUM"
    else:
        threat_lvl = "LOW"
    t_color = threat_color(threat_lvl)

    st.markdown(
        f'<div style="margin-bottom:8px;">'
        f'<div style="font-size:0.65rem;color:#8B949E;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;font-weight:600;">Network Status</div>'
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;padding:6px 8px;background:rgba(255,255,255,0.03);border-radius:6px;">'
        f'<span style="width:8px;height:8px;border-radius:50%;background:{h_color};display:inline-block;animation:pulse 2s infinite;box-shadow:0 0 6px {h_color}60;"></span>'
        f'<span style="font-size:0.78rem;color:{text_color};">Health: <strong>{h_label}</strong> ({health_score:.0f})</span>'
        f'</div>'
        f'<div style="display:flex;align-items:center;gap:8px;padding:6px 8px;background:rgba(255,255,255,0.03);border-radius:6px;">'
        f'<span style="width:8px;height:8px;border-radius:50%;background:{t_color};display:inline-block;animation:pulse 2s infinite;box-shadow:0 0 6px {t_color}60;"></span>'
        f'<span style="font-size:0.78rem;color:{text_color};">Threat: <strong>{threat_lvl}</strong></span>'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def _render_nav_menu() -> str:
    """Render the navigation menu and return selected page key."""
    from dashboard.theme import Colors as C

    layout = get_plotly_layout()
    text_color = layout.get("font", {}).get("color", "#E6EDF3")

    # Use session state to track selected page
    if "current_page" not in st.session_state:
        st.session_state.current_page = "home"

    current = st.session_state.current_page

    st.markdown(
        f'<div style="font-size:0.7rem;color:#8B949E;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px;padding-left:4px;">Navigation</div>',
        unsafe_allow_html=True,
    )

    for icon, label, key in NAV_ITEMS:
        is_active = key == current

        if st.button(
            f"{icon}  {label}",
            key=f"nav_{key}",
            use_container_width=True,
            type="primary" if is_active else "secondary",
        ):
            st.session_state.current_page = key
            st.rerun()

    return current


def _render_actions() -> None:
    """Render action buttons (refresh, export, reset, DB clear)."""
    st.markdown(
        f'<div style="font-size:0.7rem;color:#8B949E;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px;padding-left:4px;">Actions</div>',
        unsafe_allow_html=True,
    )

    # Theme toggle
    current_theme = st.session_state.get("theme", "dark")
    theme_label = "☀️ Light" if current_theme == "dark" else "🌙 Dark"
    if st.button(theme_label, use_container_width=True, key="theme_toggle"):
        st.session_state.theme = "light" if current_theme == "dark" else "dark"
        st.rerun()

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Refresh", use_container_width=True, key="action_refresh"):
            try:
                from dashboard.data_loaders import invalidate_all_caches
                invalidate_all_caches()
            except Exception:
                pass
            st.rerun()
    with col2:
        if st.button("📥 Export", use_container_width=True, key="action_export"):
            _trigger_export()

    col3, col4 = st.columns(2)
    with col3:
        if st.button(
            "🗑️ Reset",
            use_container_width=True,
            key="action_reset",
            help="Clear all session state and pipeline results",
        ):
            _reset_dashboard()
    with col4:
        if st.button(
            "🔃 Reload ML",
            use_container_width=True,
            key="action_reload_ml",
            help="Force ML models to reload from disk",
        ):
            _reload_ml_models()

    # Export downloads (if available)
    if st.session_state.get("export_csv"):
        st.download_button(
            "📥 Download CSV",
            data=st.session_state.export_csv,
            file_name="alerts_export.csv",
            mime="text/csv",
            use_container_width=True,
            key="sidebar_dl_csv",
        )
    if st.session_state.get("export_json"):
        st.download_button(
            "📥 Download JSON",
            data=st.session_state.export_json,
            file_name="alerts_export.json",
            mime="application/json",
            use_container_width=True,
            key="sidebar_dl_json",
        )


def _trigger_export() -> None:
    """Handle export button click — generate downloadable data."""
    from dashboard.data_loaders import load_alerts
    df = load_alerts(limit=10000)
    if not df.empty:
        st.session_state.export_csv = df.to_csv(index=False)
        st.session_state.export_json = df.to_json(orient="records", indent=2)
        st.success("Export ready!")
    else:
        st.info("No alerts to export yet.")


def _reset_dashboard() -> None:
    """Reset all pipeline state and session data."""
    keys_to_clear = [
        "pipeline_running", "pipeline_phase", "pipeline_progress",
        "pipeline_packets_done", "pipeline_elapsed", "pipeline_error",
        "pipeline_result", "analysis_complete", "current_file",
        "current_file_name", "demo_mode_active", "export_csv", "export_json",
    ]
    for k in keys_to_clear:
        st.session_state.pop(k, None)
    try:
        from dashboard.data_loaders import invalidate_all_caches
        invalidate_all_caches()
    except Exception:
        pass
    st.success("✅ Dashboard reset.")
    st.rerun()


def _reload_ml_models() -> None:
    """Force ML model cache clear."""
    try:
        from dashboard.data_loaders import load_ml_model_info
        load_ml_model_info.clear()
        st.success("✅ ML model cache cleared. Models will reload on next run.")
    except Exception as e:
        st.info(f"Reload: {e}")


def _render_footer() -> None:
    """Render sidebar footer."""
    st.markdown(
        '<div style="text-align:center;padding:12px 8px;margin-top:8px;'
        'background:rgba(255,255,255,0.02);border-radius:8px;border:1px solid rgba(255,255,255,0.05);">'
        '<div style="font-size:0.6rem;color:#6E7681;line-height:1.6;">'
        '<span style="color:#8B949E;">Final Year Project</span><br/>'
        'Network Traffic Analysis &amp; IDS<br/>'
        '<span style="display:inline-block;margin-top:4px;padding:2px 6px;border-radius:4px;'
        'background:rgba(21,101,192,0.1);color:#1565C0;font-size:0.55rem;">'
        'Python 3.11+ | Streamlit | SQLite</span>'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )


def config_version() -> str:
    """Get app version from config."""
    try:
        from utils.config import config
        return config.meta.version
    except Exception:
        return "1.0.0"
