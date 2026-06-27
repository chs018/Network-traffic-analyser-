"""
styles.py — Global CSS Injection
=================================
Enterprise SOC Dashboard Stylesheet

Injects global CSS for dark and light themes via st.markdown().
All components inherit these base styles for visual consistency.

Author: Network Traffic Analyzer Project
Version: 2.0.0
Python: 3.11+
"""

from __future__ import annotations

import base64
from pathlib import Path

import streamlit as st

from dashboard.theme import Colors, Typography, Spacing, Radius, Shadows


def _get_bg_base64() -> str:
    """Load background image as base64 string."""
    bg_path = Path(__file__).parent.parent / "assets" / "bg-circuit.png"
    if bg_path.exists():
        with open(bg_path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    return ""


_BG_BASE64 = _get_bg_base64()
_BG_STYLE = (
    f'background: linear-gradient(rgba(13,17,23,0.82), rgba(13,17,23,0.82)), '
    f'url("data:image/png;base64,{_BG_BASE64}") !important; '
    f'background-size: cover !important; background-position: center !important; '
    f'background-attachment: fixed !important; background-repeat: no-repeat !important; '
    f'background-color: {Colors.BG_DARK} !important;'
    if _BG_BASE64
    else ""
)
_BG_STYLE_LIGHT = (
    f'background: linear-gradient(rgba(255,255,255,0.88), rgba(255,255,255,0.88)), '
    f'url("data:image/png;base64,{_BG_BASE64}") !important; '
    f'background-size: cover !important; background-position: center !important; '
    f'background-attachment: fixed !important; background-repeat: no-repeat !important; '
    f'background-color: {Colors.BG_LIGHT} !important;'
    if _BG_BASE64
    else ""
)


# ──────────────────────────────────────────────────────────────────────────────
# DARK MODE CSS
# ──────────────────────────────────────────────────────────────────────────────

DARK_CSS = f"""
<style>
/* ── Reset & Base ────────────────────────────────────────────────────────── */
.stApp, section.main .block-container, section[data-testid="stMain"] {{
    background-color: {Colors.BG_DARK} !important;
    {_BG_STYLE}
    color: {Colors.TEXT_DARK_PRIMARY};
    font-family: {Typography.FONT_FAMILY};
}}

/* ── Animations ──────────────────────────────────────────────────────────── */
@keyframes fadeInUp {{
    from {{ opacity: 0; transform: translateY(12px); }}
    to {{ opacity: 1; transform: translateY(0); }}
}}
@keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.5; }}
}}
@keyframes glow {{
    0%, 100% {{ box-shadow: 0 0 5px rgba(21,101,192,0.3); }}
    50% {{ box-shadow: 0 0 20px rgba(21,101,192,0.6); }}
}}
@keyframes slideIn {{
    from {{ opacity: 0; transform: translateX(-8px); }}
    to {{ opacity: 1; transform: translateX(0); }}
}}
@keyframes shimmer {{
    0% {{ background-position: -200% 0; }}
    100% {{ background-position: 200% 0; }}
}}

/* ── Sidebar ─────────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, {Colors.BG_DARK_SECONDARY} 0%, #0a0e14 100%) !important;
    border-right: 1px solid {Colors.BORDER_DARK};
}}

section[data-testid="stSidebar"] .stRadio label,
section[data-testid="stSidebar"] .stSelectbox label {{
    color: {Colors.TEXT_DARK_SECONDARY};
}}

section[data-testid="stSidebar"] .stButton > button {{
    border: 1px solid {Colors.BORDER_DARK};
    background: {Colors.SURFACE_DARK};
    color: {Colors.TEXT_DARK_PRIMARY};
    transition: all 0.2s ease;
}}

section[data-testid="stSidebar"] .stButton > button:hover {{
    border-color: {Colors.PRIMARY};
    background: rgba(21,101,192,0.15);
}}

section[data-testid="stSidebar"] .stButton > button[data-testid="stBaseButton-primary"] {{
    background: linear-gradient(135deg, {Colors.PRIMARY}, {Colors.PRIMARY_DARK});
    border: none;
    color: #fff;
}}

/* ── Headers ─────────────────────────────────────────────────────────────── */
h1, h2, h3, h4, h5, h6 {{
    color: {Colors.TEXT_DARK_PRIMARY};
    font-family: {Typography.FONT_FAMILY};
    font-weight: {Typography.WEIGHT_SEMIBOLD};
    letter-spacing: -0.01em;
}}

/* ── Hero Banner ─────────────────────────────────────────────────────────── */
.hero-banner {{
    background: linear-gradient(135deg, rgba(21,101,192,0.25) 0%, rgba(0,188,212,0.15) 50%, rgba(0,200,81,0.1) 100%);
    border: 1px solid rgba(21,101,192,0.3);
    border-radius: {Radius.XL};
    padding: {Spacing.XXL} {Spacing.XL};
    margin-bottom: {Spacing.XL};
    position: relative;
    overflow: hidden;
    animation: fadeInUp 0.5s ease-out;
}}

.hero-banner::before {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, {Colors.PRIMARY}, {Colors.INFO}, {Colors.SUCCESS});
}}

.hero-banner .hero-title {{
    font-size: {Typography.SIZE_2XL};
    font-weight: {Typography.WEIGHT_BOLD};
    color: {Colors.TEXT_DARK_PRIMARY};
    margin: 0 0 {Spacing.SM} 0;
}}

.hero-banner .hero-subtitle {{
    font-size: {Typography.SIZE_BASE};
    color: {Colors.TEXT_DARK_SECONDARY};
    margin: 0;
}}

.hero-banner .hero-status {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-top: {Spacing.MD};
    padding: 4px 12px;
    background: rgba(0,200,81,0.15);
    border: 1px solid rgba(0,200,81,0.3);
    border-radius: {Radius.FULL};
    font-size: {Typography.SIZE_XS};
    color: {Colors.SUCCESS};
    font-weight: {Typography.WEIGHT_MEDIUM};
}}

.hero-banner .hero-status .pulse-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: {Colors.SUCCESS};
    animation: pulse 2s infinite;
}}

/* ── Metric Cards ────────────────────────────────────────────────────────── */
.metric-card {{
    background: {Colors.SURFACE_DARK};
    border: 1px solid {Colors.BORDER_DARK};
    border-top: 3px solid {Colors.PRIMARY};
    border-radius: {Radius.LG};
    padding: {Spacing.XL} {Spacing.LG};
    box-shadow: {Shadows.MD};
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    height: 100%;
    position: relative;
    overflow: hidden;
    animation: fadeInUp 0.4s ease-out;
}}

.metric-card::after {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(135deg, transparent 60%, rgba(21,101,192,0.03));
    pointer-events: none;
}}

.metric-card:hover {{
    border-color: {Colors.PRIMARY_LIGHT};
    box-shadow: 0 8px 32px rgba(21,101,192,0.2);
    transform: translateY(-2px);
}}

.metric-card .metric-icon {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: {Radius.MD};
    background: rgba(21,101,192,0.12);
    font-size: 1.2rem;
    margin-bottom: {Spacing.SM};
}}

.metric-card .metric-value {{
    font-size: {Typography.SIZE_2XL};
    font-weight: {Typography.WEIGHT_BOLD};
    color: {Colors.TEXT_DARK_PRIMARY};
    line-height: 1.2;
    margin: {Spacing.SM} 0;
}}

.metric-card .metric-label {{
    font-size: {Typography.SIZE_XS};
    font-weight: {Typography.WEIGHT_MEDIUM};
    color: {Colors.TEXT_DARK_SECONDARY};
    text-transform: uppercase;
    letter-spacing: 0.08em;
}}

.metric-card .metric-delta {{
    font-size: {Typography.SIZE_SM};
    font-weight: {Typography.WEIGHT_MEDIUM};
    margin-top: {Spacing.XS};
}}

.metric-delta.positive {{ color: {Colors.SUCCESS}; }}
.metric-delta.negative {{ color: {Colors.DANGER}; }}
.metric-delta.neutral {{ color: {Colors.TEXT_DARK_MUTED}; }}

/* ── Gauge Cards ─────────────────────────────────────────────────────────── */
.gauge-card {{
    background: {Colors.SURFACE_DARK};
    border: 1px solid {Colors.BORDER_DARK};
    border-radius: {Radius.LG};
    padding: {Spacing.LG};
    box-shadow: {Shadows.MD};
    text-align: center;
    height: 100%;
    transition: all 0.3s ease;
    animation: fadeInUp 0.5s ease-out;
}}

.gauge-card:hover {{
    box-shadow: 0 4px 20px rgba(21,101,192,0.15);
    border-color: rgba(21,101,192,0.3);
}}

/* ── Section Headers ─────────────────────────────────────────────────────── */
.section-header {{
    display: flex;
    align-items: center;
    gap: {Spacing.SM};
    margin: {Spacing.XL} 0 {Spacing.LG} 0;
    padding-bottom: {Spacing.SM};
    border-bottom: 2px solid transparent;
    border-image: linear-gradient(90deg, {Colors.PRIMARY}, transparent) 1;
    animation: fadeInUp 0.3s ease-out;
}}

.section-header .section-icon {{
    font-size: {Typography.SIZE_LG};
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: {Radius.MD};
    background: rgba(21,101,192,0.12);
}}

.section-header .section-title {{
    font-size: {Typography.SIZE_MD};
    font-weight: {Typography.WEIGHT_SEMIBOLD};
    color: {Colors.TEXT_DARK_PRIMARY};
    margin: 0;
}}

.section-header .section-subtitle {{
    font-size: {Typography.SIZE_SM};
    color: {Colors.TEXT_DARK_SECONDARY};
    margin: 0;
}}

/* ── Status Badges ───────────────────────────────────────────────────────── */
.status-badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: {Radius.FULL};
    font-size: {Typography.SIZE_XS};
    font-weight: {Typography.WEIGHT_MEDIUM};
    line-height: 1.4;
    white-space: nowrap;
    border: 1px solid transparent;
}}

.status-badge .status-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}}

.status-badge.pulse .status-dot {{
    animation: pulse 2s infinite;
}}

/* ── Alert Row Styling ───────────────────────────────────────────────────── */
.alert-row-critical {{
    background-color: rgba(213, 0, 0, 0.08) !important;
    border-left: 3px solid {Colors.CRITICAL};
}}
.alert-row-high {{
    background-color: rgba(255, 87, 34, 0.08) !important;
    border-left: 3px solid {Colors.SEVERITY_HIGH};
}}
.alert-row-medium {{
    background-color: rgba(255, 152, 0, 0.06) !important;
    border-left: 3px solid {Colors.SEVERITY_MEDIUM};
}}
.alert-row-low {{
    background-color: rgba(33, 150, 243, 0.06) !important;
    border-left: 3px solid {Colors.SEVERITY_LOW};
}}

/* ── Timeline Cards ──────────────────────────────────────────────────────── */
.timeline-card {{
    background: {Colors.SURFACE_DARK};
    border: 1px solid {Colors.BORDER_DARK};
    border-radius: {Radius.MD};
    padding: {Spacing.MD} {Spacing.LG};
    margin-bottom: {Spacing.SM};
    border-left: 4px solid {Colors.PRIMARY};
    transition: all 0.25s ease;
    animation: slideIn 0.3s ease-out;
    position: relative;
}}

.timeline-card::before {{
    content: '';
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 4px;
    border-radius: 4px 0 0 4px;
}}

.timeline-card:hover {{
    border-left-color: {Colors.PRIMARY_LIGHT};
    background: {Colors.SURFACE_DARK_HOVER};
    transform: translateX(4px);
    box-shadow: {Shadows.MD};
}}

.timeline-card.severity-CRITICAL {{ border-left-color: {Colors.CRITICAL}; }}
.timeline-card.severity-HIGH {{ border-left-color: {Colors.SEVERITY_HIGH}; }}
.timeline-card.severity-MEDIUM {{ border-left-color: {Colors.SEVERITY_MEDIUM}; }}
.timeline-card.severity-LOW {{ border-left-color: {Colors.SEVERITY_LOW}; }}

.timeline-timestamp {{
    font-size: {Typography.SIZE_XS};
    color: {Colors.TEXT_DARK_MUTED};
    font-family: {Typography.FONT_MONO};
}}

.timeline-attack {{
    font-weight: {Typography.WEIGHT_SEMIBOLD};
    color: {Colors.TEXT_DARK_PRIMARY};
}}

.timeline-ips {{
    font-family: {Typography.FONT_MONO};
    font-size: {Typography.SIZE_SM};
    color: {Colors.TEXT_DARK_SECONDARY};
    background: rgba(255,255,255,0.04);
    padding: 2px 8px;
    border-radius: {Radius.SM};
    display: inline-block;
    margin-top: 4px;
}}

/* ── Chart Containers ────────────────────────────────────────────────────── */
.chart-container {{
    background: {Colors.SURFACE_DARK};
    border: 1px solid {Colors.BORDER_DARK};
    border-radius: {Radius.LG};
    padding: {Spacing.LG};
    box-shadow: {Shadows.SM};
    height: 100%;
    transition: all 0.3s ease;
    animation: fadeInUp 0.5s ease-out;
}}

.chart-container:hover {{
    box-shadow: {Shadows.MD};
    border-color: rgba(21,101,192,0.2);
}}

.chart-container .chart-title {{
    font-size: {Typography.SIZE_BASE};
    font-weight: {Typography.WEIGHT_SEMIBOLD};
    color: {Colors.TEXT_DARK_PRIMARY};
    margin-bottom: {Spacing.MD};
    padding-bottom: {Spacing.SM};
    border-bottom: 1px solid {Colors.BORDER_DARK};
}}

/* ── Dividers ────────────────────────────────────────────────────────────── */
hr {{
    border: none;
    border-top: 1px solid {Colors.BORDER_DARK};
    margin: {Spacing.LG} 0;
    opacity: 0.6;
}}

/* ── Data Tables ─────────────────────────────────────────────────────────── */
.stDataFrame {{
    border-radius: {Radius.MD};
    overflow: hidden;
    border: 1px solid {Colors.BORDER_DARK};
}}

/* ── Scrollbar ───────────────────────────────────────────────────────────── */
::-webkit-scrollbar {{
    width: 6px;
    height: 6px;
}}
::-webkit-scrollbar-track {{
    background: transparent;
}}
::-webkit-scrollbar-thumb {{
    background: {Colors.SURFACE_DARK_HOVER};
    border-radius: {Radius.FULL};
}}
::-webkit-scrollbar-thumb:hover {{
    background: {Colors.TEXT_DARK_MUTED};
}}

/* ── Buttons ─────────────────────────────────────────────────────────────── */
.stButton > button {{
    border-radius: {Radius.MD};
    font-weight: {Typography.WEIGHT_MEDIUM};
    transition: all 0.2s ease;
    border: 1px solid {Colors.BORDER_DARK};
}}

.stButton > button:hover {{
    transform: translateY(-1px);
    box-shadow: {Shadows.SM};
}}

/* ── Expander ────────────────────────────────────────────────────────────── */
.streamlit-expanderHeader {{
    font-weight: {Typography.WEIGHT_SEMIBOLD};
    color: {Colors.TEXT_DARK_PRIMARY};
    border: 1px solid {Colors.BORDER_DARK};
    border-radius: {Radius.MD};
}}

/* ── Tabs ────────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab"] {{
    font-weight: {Typography.WEIGHT_MEDIUM};
    color: {Colors.TEXT_DARK_SECONDARY};
    border-radius: {Radius.MD} {Radius.MD} 0 0;
}}

.stTabs [aria-selected="true"] {{
    color: {Colors.PRIMARY_LIGHT};
    border-bottom-color: {Colors.PRIMARY_LIGHT};
}}

/* ── Info Cards (System Status) ──────────────────────────────────────────── */
.info-card {{
    background: {Colors.SURFACE_DARK};
    border: 1px solid {Colors.BORDER_DARK};
    border-radius: {Radius.LG};
    padding: {Spacing.LG};
    height: 100%;
    transition: all 0.3s ease;
    animation: fadeInUp 0.4s ease-out;
}}

.info-card:hover {{
    border-color: rgba(21,101,192,0.3);
    box-shadow: {Shadows.MD};
}}

.info-card .info-label {{
    font-size: {Typography.SIZE_XS};
    color: {Colors.TEXT_DARK_SECONDARY};
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: {Spacing.XS};
}}

.info-card .info-value {{
    font-size: {Typography.SIZE_LG};
    font-weight: {Typography.WEIGHT_BOLD};
    color: {Colors.TEXT_DARK_PRIMARY};
}}

/* ── Live Clock ──────────────────────────────────────────────────────────── */
.live-clock {{
    font-family: {Typography.FONT_MONO};
    font-size: {Typography.SIZE_SM};
    color: {Colors.TEXT_DARK_SECONDARY};
    text-align: center;
    padding: {Spacing.SM};
    background: rgba(255,255,255,0.03);
    border-radius: {Radius.MD};
    border: 1px solid {Colors.BORDER_DARK};
}}

/* ── Bottom Status Bar ───────────────────────────────────────────────────── */
.status-bar {{
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    z-index: 9999;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 20px;
    background: rgba(22,27,34,0.95);
    backdrop-filter: blur(8px);
    border-top: 1px solid {Colors.BORDER_DARK};
    font-size: 0.7rem;
    color: {Colors.TEXT_DARK_MUTED};
}}

.status-bar .status-item {{
    display: flex;
    align-items: center;
    gap: 6px;
}}

.status-bar .status-dot {{
    width: 6px;
    height: 6px;
    border-radius: 50%;
    animation: pulse 2s infinite;
}}

/* ── Refresh Indicator ───────────────────────────────────────────────────── */
.refresh-indicator {{
    position: fixed;
    bottom: 36px;
    right: 12px;
    z-index: 9999;
    font-size: 0.65rem;
    color: {Colors.TEXT_DARK_MUTED};
    background: rgba(22,27,34,0.85);
    backdrop-filter: blur(4px);
    padding: 4px 10px;
    border-radius: {Radius.FULL};
    border: 1px solid {Colors.BORDER_DARK};
}}
</style>
"""


# ──────────────────────────────────────────────────────────────────────────────
# LIGHT MODE CSS
# ──────────────────────────────────────────────────────────────────────────────

LIGHT_CSS = f"""
<style>
/* ── Reset & Base ────────────────────────────────────────────────────────── */
.stApp, section.main .block-container, section[data-testid="stMain"] {{
    background-color: {Colors.BG_LIGHT} !important;
    {_BG_STYLE_LIGHT}
    color: {Colors.TEXT_LIGHT_PRIMARY};
    font-family: {Typography.FONT_FAMILY};
}}

/* ── Animations ──────────────────────────────────────────────────────────── */
@keyframes fadeInUp {{
    from {{ opacity: 0; transform: translateY(12px); }}
    to {{ opacity: 1; transform: translateY(0); }}
}}
@keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.5; }}
}}

/* ── Sidebar ─────────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, {Colors.BG_LIGHT_SECONDARY} 0%, #f0f2f5 100%) !important;
    border-right: 1px solid {Colors.BORDER_LIGHT};
}}

section[data-testid="stSidebar"] .stButton > button {{
    border: 1px solid {Colors.BORDER_LIGHT};
    background: {Colors.SURFACE_LIGHT};
    color: {Colors.TEXT_LIGHT_PRIMARY};
}}

section[data-testid="stSidebar"] .stButton > button:hover {{
    border-color: {Colors.PRIMARY};
    background: rgba(21,101,192,0.08);
}}

section[data-testid="stSidebar"] .stButton > button[data-testid="stBaseButton-primary"] {{
    background: linear-gradient(135deg, {Colors.PRIMARY}, {Colors.PRIMARY_DARK});
    border: none;
    color: #fff;
}}

/* ── Headers ─────────────────────────────────────────────────────────────── */
h1, h2, h3, h4, h5, h6 {{
    color: {Colors.TEXT_LIGHT_PRIMARY};
    font-family: {Typography.FONT_FAMILY};
    font-weight: {Typography.WEIGHT_SEMIBOLD};
    letter-spacing: -0.01em;
}}

/* ── Hero Banner ─────────────────────────────────────────────────────────── */
.hero-banner {{
    background: linear-gradient(135deg, rgba(21,101,192,0.08) 0%, rgba(0,188,212,0.06) 50%, rgba(0,200,81,0.04) 100%);
    border: 1px solid rgba(21,101,192,0.15);
    border-radius: {Radius.XL};
    padding: {Spacing.XXL} {Spacing.XL};
    margin-bottom: {Spacing.XL};
    position: relative;
    overflow: hidden;
    animation: fadeInUp 0.5s ease-out;
}}

.hero-banner::before {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, {Colors.PRIMARY}, {Colors.INFO}, {Colors.SUCCESS});
}}

.hero-banner .hero-title {{
    font-size: {Typography.SIZE_2XL};
    font-weight: {Typography.WEIGHT_BOLD};
    color: {Colors.TEXT_LIGHT_PRIMARY};
    margin: 0 0 {Spacing.SM} 0;
}}

.hero-banner .hero-subtitle {{
    font-size: {Typography.SIZE_BASE};
    color: {Colors.TEXT_LIGHT_SECONDARY};
    margin: 0;
}}

.hero-banner .hero-status {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-top: {Spacing.MD};
    padding: 4px 12px;
    background: rgba(0,200,81,0.1);
    border: 1px solid rgba(0,200,81,0.2);
    border-radius: {Radius.FULL};
    font-size: {Typography.SIZE_XS};
    color: {Colors.SUCCESS_DARK};
    font-weight: {Typography.WEIGHT_MEDIUM};
}}

.hero-banner .hero-status .pulse-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: {Colors.SUCCESS};
    animation: pulse 2s infinite;
}}

/* ── Metric Cards ────────────────────────────────────────────────────────── */
.metric-card {{
    background: {Colors.SURFACE_LIGHT};
    border: 1px solid {Colors.BORDER_LIGHT};
    border-top: 3px solid {Colors.PRIMARY};
    border-radius: {Radius.LG};
    padding: {Spacing.XL} {Spacing.LG};
    box-shadow: {Shadows.SM};
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    height: 100%;
    position: relative;
    overflow: hidden;
    animation: fadeInUp 0.4s ease-out;
}}

.metric-card::after {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(135deg, transparent 60%, rgba(21,101,192,0.02));
    pointer-events: none;
}}

.metric-card:hover {{
    border-color: {Colors.PRIMARY};
    box-shadow: 0 4px 16px rgba(21,101,192,0.12);
    transform: translateY(-2px);
}}

.metric-card .metric-icon {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: {Radius.MD};
    background: rgba(21,101,192,0.08);
    font-size: 1.2rem;
    margin-bottom: {Spacing.SM};
}}

.metric-card .metric-value {{
    font-size: {Typography.SIZE_2XL};
    font-weight: {Typography.WEIGHT_BOLD};
    color: {Colors.TEXT_LIGHT_PRIMARY};
    line-height: 1.2;
    margin: {Spacing.SM} 0;
}}

.metric-card .metric-label {{
    font-size: {Typography.SIZE_XS};
    font-weight: {Typography.WEIGHT_MEDIUM};
    color: {Colors.TEXT_LIGHT_SECONDARY};
    text-transform: uppercase;
    letter-spacing: 0.08em;
}}

.metric-card .metric-delta {{
    font-size: {Typography.SIZE_SM};
    font-weight: {Typography.WEIGHT_MEDIUM};
    margin-top: {Spacing.XS};
}}

.metric-delta.positive {{ color: {Colors.SUCCESS_DARK}; }}
.metric-delta.negative {{ color: {Colors.DANGER}; }}
.metric-delta.neutral {{ color: {Colors.TEXT_LIGHT_MUTED}; }}

/* ── Gauge Cards ─────────────────────────────────────────────────────────── */
.gauge-card {{
    background: {Colors.SURFACE_LIGHT};
    border: 1px solid {Colors.BORDER_LIGHT};
    border-radius: {Radius.LG};
    padding: {Spacing.LG};
    box-shadow: {Shadows.SM};
    text-align: center;
    height: 100%;
    transition: all 0.3s ease;
    animation: fadeInUp 0.5s ease-out;
}}

.gauge-card:hover {{
    box-shadow: {Shadows.MD};
    border-color: rgba(21,101,192,0.2);
}}

/* ── Section Headers ─────────────────────────────────────────────────────── */
.section-header {{
    display: flex;
    align-items: center;
    gap: {Spacing.SM};
    margin: {Spacing.XL} 0 {Spacing.LG} 0;
    padding-bottom: {Spacing.SM};
    border-bottom: 2px solid transparent;
    border-image: linear-gradient(90deg, {Colors.PRIMARY}, transparent) 1;
    animation: fadeInUp 0.3s ease-out;
}}

.section-header .section-icon {{
    font-size: {Typography.SIZE_LG};
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: {Radius.MD};
    background: rgba(21,101,192,0.08);
}}

.section-header .section-title {{
    font-size: {Typography.SIZE_MD};
    font-weight: {Typography.WEIGHT_SEMIBOLD};
    color: {Colors.TEXT_LIGHT_PRIMARY};
    margin: 0;
}}

.section-header .section-subtitle {{
    font-size: {Typography.SIZE_SM};
    color: {Colors.TEXT_LIGHT_SECONDARY};
    margin: 0;
}}

/* ── Status Badges ───────────────────────────────────────────────────────── */
.status-badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: {Radius.FULL};
    font-size: {Typography.SIZE_XS};
    font-weight: {Typography.WEIGHT_MEDIUM};
    line-height: 1.4;
    white-space: nowrap;
    border: 1px solid transparent;
}}

.status-badge .status-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}}

.status-badge.pulse .status-dot {{
    animation: pulse 2s infinite;
}}

/* ── Alert Row Styling ───────────────────────────────────────────────────── */
.alert-row-critical {{
    background-color: rgba(213, 0, 0, 0.06) !important;
    border-left: 3px solid {Colors.CRITICAL};
}}
.alert-row-high {{
    background-color: rgba(255, 87, 34, 0.06) !important;
    border-left: 3px solid {Colors.SEVERITY_HIGH};
}}
.alert-row-medium {{
    background-color: rgba(255, 152, 0, 0.04) !important;
    border-left: 3px solid {Colors.SEVERITY_MEDIUM};
}}
.alert-row-low {{
    background-color: rgba(33, 150, 243, 0.04) !important;
    border-left: 3px solid {Colors.SEVERITY_LOW};
}}

/* ── Timeline Cards ──────────────────────────────────────────────────────── */
.timeline-card {{
    background: {Colors.SURFACE_LIGHT};
    border: 1px solid {Colors.BORDER_LIGHT};
    border-radius: {Radius.MD};
    padding: {Spacing.MD} {Spacing.LG};
    margin-bottom: {Spacing.SM};
    border-left: 4px solid {Colors.PRIMARY};
    transition: all 0.25s ease;
    animation: fadeInUp 0.3s ease-out;
}}

.timeline-card:hover {{
    border-left-color: {Colors.PRIMARY_DARK};
    background: {Colors.SURFACE_LIGHT_HOVER};
    transform: translateX(4px);
    box-shadow: {Shadows.SM};
}}

.timeline-card.severity-CRITICAL {{ border-left-color: {Colors.CRITICAL}; }}
.timeline-card.severity-HIGH {{ border-left-color: {Colors.SEVERITY_HIGH}; }}
.timeline-card.severity-MEDIUM {{ border-left-color: {Colors.SEVERITY_MEDIUM}; }}
.timeline-card.severity-LOW {{ border-left-color: {Colors.SEVERITY_LOW}; }}

.timeline-timestamp {{
    font-size: {Typography.SIZE_XS};
    color: {Colors.TEXT_LIGHT_MUTED};
    font-family: {Typography.FONT_MONO};
}}

.timeline-attack {{
    font-weight: {Typography.WEIGHT_SEMIBOLD};
    color: {Colors.TEXT_LIGHT_PRIMARY};
}}

.timeline-ips {{
    font-family: {Typography.FONT_MONO};
    font-size: {Typography.SIZE_SM};
    color: {Colors.TEXT_LIGHT_SECONDARY};
    background: rgba(0,0,0,0.04);
    padding: 2px 8px;
    border-radius: {Radius.SM};
    display: inline-block;
    margin-top: 4px;
}}

/* ── Chart Containers ────────────────────────────────────────────────────── */
.chart-container {{
    background: {Colors.SURFACE_LIGHT};
    border: 1px solid {Colors.BORDER_LIGHT};
    border-radius: {Radius.LG};
    padding: {Spacing.LG};
    box-shadow: {Shadows.SM};
    height: 100%;
    transition: all 0.3s ease;
    animation: fadeInUp 0.5s ease-out;
}}

.chart-container:hover {{
    box-shadow: {Shadows.MD};
    border-color: rgba(21,101,192,0.2);
}}

.chart-container .chart-title {{
    font-size: {Typography.SIZE_BASE};
    font-weight: {Typography.WEIGHT_SEMIBOLD};
    color: {Colors.TEXT_LIGHT_PRIMARY};
    margin-bottom: {Spacing.MD};
    padding-bottom: {Spacing.SM};
    border-bottom: 1px solid {Colors.BORDER_LIGHT};
}}

/* ── Dividers ────────────────────────────────────────────────────────────── */
hr {{
    border: none;
    border-top: 1px solid {Colors.BORDER_LIGHT};
    margin: {Spacing.LG} 0;
    opacity: 0.6;
}}

/* ── Data Tables ─────────────────────────────────────────────────────────── */
.stDataFrame {{
    border-radius: {Radius.MD};
    overflow: hidden;
    border: 1px solid {Colors.BORDER_LIGHT};
}}

/* ── Scrollbar ───────────────────────────────────────────────────────────── */
::-webkit-scrollbar {{
    width: 6px;
    height: 6px;
}}
::-webkit-scrollbar-track {{
    background: transparent;
}}
::-webkit-scrollbar-thumb {{
    background: {Colors.BORDER_LIGHT};
    border-radius: {Radius.FULL};
}}

/* ── Buttons ─────────────────────────────────────────────────────────────── */
.stButton > button {{
    border-radius: {Radius.MD};
    font-weight: {Typography.WEIGHT_MEDIUM};
    transition: all 0.2s ease;
    border: 1px solid {Colors.BORDER_LIGHT};
}}

.stButton > button:hover {{
    transform: translateY(-1px);
    box-shadow: {Shadows.SM};
}}

/* ── Expander ────────────────────────────────────────────────────────────── */
.streamlit-expanderHeader {{
    font-weight: {Typography.WEIGHT_SEMIBOLD};
    color: {Colors.TEXT_LIGHT_PRIMARY};
    border: 1px solid {Colors.BORDER_LIGHT};
    border-radius: {Radius.MD};
}}

/* ── Tabs ────────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab"] {{
    font-weight: {Typography.WEIGHT_MEDIUM};
    color: {Colors.TEXT_LIGHT_SECONDARY};
    border-radius: {Radius.MD} {Radius.MD} 0 0;
}}

.stTabs [aria-selected="true"] {{
    color: {Colors.PRIMARY};
    border-bottom-color: {Colors.PRIMARY};
}}

/* ── Info Cards (System Status) ──────────────────────────────────────────── */
.info-card {{
    background: {Colors.SURFACE_LIGHT};
    border: 1px solid {Colors.BORDER_LIGHT};
    border-radius: {Radius.LG};
    padding: {Spacing.LG};
    height: 100%;
    transition: all 0.3s ease;
    animation: fadeInUp 0.4s ease-out;
}}

.info-card:hover {{
    border-color: rgba(21,101,192,0.3);
    box-shadow: {Shadows.SM};
}}

.info-card .info-label {{
    font-size: {Typography.SIZE_XS};
    color: {Colors.TEXT_LIGHT_SECONDARY};
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: {Spacing.XS};
}}

.info-card .info-value {{
    font-size: {Typography.SIZE_LG};
    font-weight: {Typography.WEIGHT_BOLD};
    color: {Colors.TEXT_LIGHT_PRIMARY};
}}

/* ── Live Clock ──────────────────────────────────────────────────────────── */
.live-clock {{
    font-family: {Typography.FONT_MONO};
    font-size: {Typography.SIZE_SM};
    color: {Colors.TEXT_LIGHT_SECONDARY};
    text-align: center;
    padding: {Spacing.SM};
    background: rgba(0,0,0,0.03);
    border-radius: {Radius.MD};
    border: 1px solid {Colors.BORDER_LIGHT};
}}

/* ── Bottom Status Bar ───────────────────────────────────────────────────── */
.status-bar {{
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    z-index: 9999;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 20px;
    background: rgba(255,255,255,0.95);
    backdrop-filter: blur(8px);
    border-top: 1px solid {Colors.BORDER_LIGHT};
    font-size: 0.7rem;
    color: {Colors.TEXT_LIGHT_MUTED};
}}

.status-bar .status-item {{
    display: flex;
    align-items: center;
    gap: 6px;
}}

.status-bar .status-dot {{
    width: 6px;
    height: 6px;
    border-radius: 50%;
    animation: pulse 2s infinite;
}}

/* ── Refresh Indicator ───────────────────────────────────────────────────── */
.refresh-indicator {{
    position: fixed;
    bottom: 36px;
    right: 12px;
    z-index: 9999;
    font-size: 0.65rem;
    color: {Colors.TEXT_LIGHT_MUTED};
    background: rgba(255,255,255,0.85);
    backdrop-filter: blur(4px);
    padding: 4px 10px;
    border-radius: {Radius.FULL};
    border: 1px solid {Colors.BORDER_LIGHT};
}}
</style>
"""


# ──────────────────────────────────────────────────────────────────────────────
# PLOTLY CHART THEME
# ──────────────────────────────────────────────────────────────────────────────

PLOTLY_DARK_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#E6EDF3", family=Typography.FONT_FAMILY, size=12),
    xaxis=dict(gridcolor="#21262D", zerolinecolor="#30363D"),
    yaxis=dict(gridcolor="#21262D", zerolinecolor="#30363D"),
    margin=dict(l=40, r=20, t=50, b=40),
    hoverlabel=dict(
        bgcolor="#21262D",
        font_size=12,
        font_family=Typography.FONT_MONO,
        font_color="#E6EDF3",
    ),
    legend=dict(
        bgcolor="rgba(0,0,0,0)",
        font=dict(color="#8B949E"),
    ),
)

PLOTLY_LIGHT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#1F2328", family=Typography.FONT_FAMILY, size=12),
    xaxis=dict(gridcolor="#EAEEF2", zerolinecolor="#D0D7DE"),
    yaxis=dict(gridcolor="#EAEEF2", zerolinecolor="#D0D7DE"),
    margin=dict(l=40, r=20, t=50, b=40),
    hoverlabel=dict(
        bgcolor="#FFFFFF",
        font_size=12,
        font_family=Typography.FONT_MONO,
        font_color="#1F2328",
    ),
    legend=dict(
        bgcolor="rgba(0,0,0,0)",
        font=dict(color="#656D76"),
    ),
)


# ──────────────────────────────────────────────────────────────────────────────
# INJECTION FUNCTION
# ──────────────────────────────────────────────────────────────────────────────

def inject_global_css() -> None:
    """Inject the appropriate theme CSS into the Streamlit app."""
    theme = st.session_state.get("theme", "dark")
    css = DARK_CSS if theme == "dark" else LIGHT_CSS
    st.markdown(css, unsafe_allow_html=True)


def get_plotly_layout() -> dict:
    """Return the Plotly layout dict for the current theme."""
    theme = st.session_state.get("theme", "dark")
    return PLOTLY_DARK_LAYOUT if theme == "dark" else PLOTLY_LIGHT_LAYOUT
