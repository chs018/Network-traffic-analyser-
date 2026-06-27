"""
pages/__init__.py — Dashboard Pages
=====================================
Enterprise SOC Dashboard

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

from dashboard.pages import home_page
from dashboard.pages import traffic_page
from dashboard.pages import attacks_page
from dashboard.pages import alerts_page
from dashboard.pages import system_page

__all__ = [
    "home_page",
    "traffic_page",
    "attacks_page",
    "alerts_page",
    "system_page",
]
