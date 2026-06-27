"""
dashboard/__init__.py — Enterprise SOC Dashboard Package
=========================================================
Network Traffic Analysis and Intrusion Detection System

Enterprise-grade Security Operations Center dashboard built
with Streamlit. Pure presentation layer — all computations
come from backend modules (Phases 1-6).

Modules:
    app             — Dashboard orchestrator and page routing
    styles          — Global CSS injection (dark + light themes)
    theme           — Design tokens, colour palette, typography
    data_loaders    — Cached data access layer
    components      — Reusable UI components
    pages           — Individual page implementations

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

__all__ = [
    "app",
    "styles",
    "theme",
    "data_loaders",
    "components",
    "pages",
]
