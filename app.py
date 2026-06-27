"""
app.py — Application Entry Point
=================================
Network Traffic Analysis and Intrusion Detection System

This is the Streamlit application entry point. Run with:

    streamlit run app.py

Responsibilities:
  - Configure the Streamlit page layout and theme
  - Initialise all project directories
  - Initialise the SQLite database (create tables if needed)
  - Delegate to the Enterprise SOC Dashboard orchestrator

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# ── Ensure project root is on sys.path ────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Project Imports ───────────────────────────────────────────────────────────
from utils.config import config
from utils.logger import get_logger

log = get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# STREAMLIT PAGE CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

def _configure_page() -> None:
    """Apply Streamlit page-level settings from DashboardConfig."""
    dcfg = config.dashboard
    st.set_page_config(
        page_title=dcfg.page_title,
        page_icon=dcfg.page_icon,
        layout=dcfg.layout,
        initial_sidebar_state=dcfg.initial_sidebar_state,
        menu_items={
            "Get Help": None,
            "Report a bug": None,
            "About": (
                f"**{config.meta.name}**\n\n"
                f"{config.meta.description}\n\n"
                f"Version: {config.meta.version}"
            ),
        },
    )


# ──────────────────────────────────────────────────────────────────────────────
# INITIALISATION HELPERS
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_resource(show_spinner="Initialising project directories…")
def _init_directories() -> dict[str, bool]:
    """Create all required project directories (cached)."""
    log.info("Initialising project directories.")
    config.initialise_directories()
    status = config.paths.verify_all()
    log.info("Directory status: %s", status)
    return status


@st.cache_resource(show_spinner="Connecting to database…")
def _init_database():
    """Initialise the SQLite database and return (DatabaseManager, health_dict)."""
    from database.db_manager import DatabaseManager

    log.info("Initialising database.")
    db = DatabaseManager()
    db.initialise()
    health = db.health_check()
    log.info("Database health: %s", health)
    return db, health


# ──────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Application main function.

    Configures the page, initialises infrastructure, then delegates
    to the Enterprise SOC Dashboard orchestrator.
    """
    _configure_page()

    # ── Initialise Infrastructure ─────────────────────────────────────────────
    dir_status = _init_directories()

    try:
        db_manager, db_health = _init_database()
    except Exception as exc:
        log.error("Database initialisation failed: %s", exc)
        db_health = {"status": "unhealthy", "error": str(exc)}
        db_manager = None

    # ── Store init results in session state for dashboard access ──────────────
    st.session_state.dir_status = dir_status
    st.session_state.db_health = db_health

    # ── Delegate to Enterprise SOC Dashboard ──────────────────────────────────
    from dashboard.app import render_dashboard
    render_dashboard()


# ──────────────────────────────────────────────────────────────────────────────
# GUARD
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
