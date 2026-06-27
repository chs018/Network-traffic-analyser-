"""
app.py — Dashboard Orchestrator
=================================
Enterprise SOC Dashboard

Main orchestrator that handles page routing, theme toggling,
and the auto-refresh timer. Delegates rendering to individual
page modules.

Author: Network Traffic Analyzer Project
Version: 7.5.0
Python: 3.11+
"""

from __future__ import annotations

import sys
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

# ── Ensure project root is on sys.path ────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.styles import inject_global_css
from dashboard.theme import Colors
from dashboard.components.navigation import render_sidebar
from dashboard.pipeline import init_pipeline_state


def render_dashboard() -> None:
    """
    Main entry point for the enterprise SOC dashboard.

    Called by the root app.py after page configuration.
    Handles:
      - Theme initialisation
      - Pipeline state initialisation
      - Global CSS injection
      - Sidebar navigation
      - Page routing
      - Auto-refresh timer
    """
    # ── Theme & State Initialisation ──────────────────────────────────────────
    _init_theme()
    init_pipeline_state()

    # ── Global CSS ────────────────────────────────────────────────────────────
    inject_global_css()

    # ── Sidebar Navigation ────────────────────────────────────────────────────
    selected_page = render_sidebar()

    # ── Page Routing ──────────────────────────────────────────────────────────
    _route_page(selected_page)

    # ── Auto-Refresh Timer ────────────────────────────────────────────────────
    _auto_refresh()


def _init_theme() -> None:
    """Initialise theme from session state or default to dark."""
    if "theme" not in st.session_state:
        st.session_state.theme = "dark"


def _route_page(page: str) -> None:
    """Route to the selected page module."""
    if page == "home":
        from dashboard.pages.home_page import render
        render()
    elif page == "upload":
        from dashboard.pages.upload_page import render
        render()
    elif page == "traffic":
        from dashboard.pages.traffic_page import render
        render()
    elif page == "attacks":
        from dashboard.pages.attacks_page import render
        render()
    elif page == "alerts":
        from dashboard.pages.alerts_page import render
        render()
    elif page == "packets":
        from dashboard.pages.packets_page import render
        render()
    elif page == "reports":
        from dashboard.pages.reports_page import render
        render()
    elif page == "models":
        from dashboard.pages.models_page import render
        render()
    elif page == "system":
        from dashboard.pages.system_page import render
        render()
    else:
        st.error(f"Unknown page: {page}")


def _auto_refresh() -> None:
    """
    Auto-refresh the app every N seconds (configurable).
    Skips refresh if the pipeline is actively running to avoid interrupting it.
    """
    from utils.config import config
    interval = config.dashboard.refresh_interval_seconds

    # Don't auto-refresh during pipeline execution
    if st.session_state.get("pipeline_running", False):
        st.markdown(
            '<div class="refresh-indicator">⏳ Analysis running…</div>',
            unsafe_allow_html=True,
        )
        return

    if "last_refresh" not in st.session_state:
        st.session_state.last_refresh = time.time()

    elapsed = time.time() - st.session_state.last_refresh
    if elapsed >= interval:
        st.session_state.last_refresh = time.time()
        st.rerun()

    # Show refresh indicator
    remaining = max(0, interval - elapsed)
    st.markdown(
        f'<div class="refresh-indicator">'
        f'🔄 Next refresh in {remaining:.0f}s'
        f'</div>',
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    from app import main
    main()

