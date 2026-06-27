"""
gauge_cards.py — Plotly Gauge Chart Components
================================================
Enterprise SOC Dashboard

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

from __future__ import annotations

import streamlit as st
import plotly.graph_objects as go

from dashboard.styles import get_plotly_layout
from dashboard.theme import Colors, health_color


def render_gauge_card(
    title: str,
    value: float,
    min_val: float = 0,
    max_val: float = 100,
    gauge_suffix: str = "",
    height: int = 200,
    key: str = "",
) -> None:
    """
    Render a single Plotly gauge chart in a card container.

    Args:
        title: Gauge title displayed above the chart.
        value: Current value to display.
        min_val: Minimum gauge value.
        max_val: Maximum gauge value.
        gauge_suffix: Suffix for the number (e.g. "%").
        height: Chart height in pixels.
        key: Unique key for Streamlit.
    """
    color = health_color(value) if max_val == 100 else Colors.PRIMARY

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        number={"suffix": gauge_suffix, "font": {"size": 28}},
        gauge={
            "axis": {"range": [min_val, max_val], "tickwidth": 1},
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [min_val, min_val + (max_val - min_val) * 0.3], "color": "rgba(255,68,68,0.1)"},
                {"range": [min_val + (max_val - min_val) * 0.3, min_val + (max_val - min_val) * 0.6], "color": "rgba(255,136,0,0.1)"},
                {"range": [min_val + (max_val - min_val) * 0.6, max_val], "color": "rgba(0,200,81,0.1)"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.8,
                "value": value,
            },
        },
    ))

    layout = get_plotly_layout()
    fig.update_layout(
        height=height,
        margin=dict(l=20, r=20, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color=layout.get("font", {}).get("color", "#E6EDF3")),
    )

    st.markdown(f'<div class="gauge-card">', unsafe_allow_html=True)
    st.markdown(
        f'<div style="text-align:center;font-size:0.875rem;font-weight:600;'
        f'color:{layout.get("font", {}).get("color", "#E6EDF3")};'
        f'margin-bottom:4px;">{title}</div>',
        unsafe_allow_html=True,
    )
    st.plotly_chart(fig, use_container_width=True, key=key)
    st.markdown("</div>", unsafe_allow_html=True)


def render_gauge_row(gauges: list[dict], cols_per_row: int = 4) -> None:
    """
    Render a row of gauge cards.

    Args:
        gauges: List of dicts with keys: title, value, min_val, max_val, gauge_suffix.
        cols_per_row: Number of columns per row.
    """
    if not gauges:
        return

    for i in range(0, len(gauges), cols_per_row):
        row_gauges = gauges[i:i + cols_per_row]
        cols = st.columns(len(row_gauges))
        for col, g in zip(cols, row_gauges):
            with col:
                render_gauge_card(
                    title=g.get("title", ""),
                    value=g.get("value", 0),
                    min_val=g.get("min_val", 0),
                    max_val=g.get("max_val", 100),
                    gauge_suffix=g.get("gauge_suffix", ""),
                    height=g.get("height", 200),
                    key=g.get("key", f"gauge_{i}"),
                )
