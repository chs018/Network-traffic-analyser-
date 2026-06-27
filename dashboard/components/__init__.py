"""
components/__init__.py — Reusable UI Components
=================================================
Enterprise SOC Dashboard

Exports all reusable Streamlit components for consistent usage
across dashboard pages.

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from dashboard.components.section_headers import render_section_header
from dashboard.components.status_badges import render_status_badge, render_all_status_badges
from dashboard.components.metric_cards import render_metric_card, render_metric_row
from dashboard.components.gauge_cards import render_gauge_card, render_gauge_row
from dashboard.components.chart_containers import render_chart
from dashboard.components.data_tables import render_alert_table
from dashboard.components.timeline_cards import render_timeline, render_timeline_card
from dashboard.components.navigation import render_sidebar
from dashboard.components.alert_cards import render_alert_summary_cards

__all__ = [
    "render_section_header",
    "render_status_badge",
    "render_all_status_badges",
    "render_metric_card",
    "render_metric_row",
    "render_gauge_card",
    "render_gauge_row",
    "render_chart",
    "render_alert_table",
    "render_timeline",
    "render_timeline_card",
    "render_sidebar",
    "render_alert_summary_cards",
]
