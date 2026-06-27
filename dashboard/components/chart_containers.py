"""
chart_containers.py — Plotly Chart Wrapper Component
=====================================================
Enterprise SOC Dashboard

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

from __future__ import annotations

from typing import Optional

import streamlit as st
import plotly.graph_objects as go

from dashboard.styles import get_plotly_layout
from dashboard.theme import Colors


def render_chart(
    fig: go.Figure,
    title: str = "",
    height: int = 400,
    key: str = "",
    use_container_width: bool = True,
) -> None:
    """
    Render a Plotly figure inside a styled chart container.

    Args:
        fig: Plotly Figure object.
        title: Optional chart title displayed above the chart.
        height: Chart height in pixels.
        key: Unique Streamlit key.
        use_container_width: Whether to use full container width.
    """
    layout = get_plotly_layout()

    # Apply consistent layout defaults
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            color=layout.get("font", {}).get("color", "#E6EDF3"),
            family=layout.get("font", {}).get("family", "sans-serif"),
            size=12,
        ),
        margin=dict(l=40, r=20, t=30, b=40),
        hoverlabel=dict(
            bgcolor=layout.get("hoverlabel", {}).get("bgcolor", "#21262D"),
            font_size=12,
            font_color=layout.get("hoverlabel", {}).get("font_color", "#E6EDF3"),
        ),
    )

    # Style axes
    for axis in ["xaxis", "yaxis"]:
        axis_defaults = layout.get(axis, {})
        fig.update_layout(**{
            axis: dict(
                gridcolor=axis_defaults.get("gridcolor", "#21262D"),
                zerolinecolor=axis_defaults.get("zerolinecolor", "#30363D"),
                showgrid=True,
            ),
        })

    if title:
        st.markdown(
            f'<div class="chart-container">'
            f'<div class="chart-title">{title}</div>',
            unsafe_allow_html=True,
        )
    
    st.plotly_chart(
        fig,
        use_container_width=use_container_width,
        key=key,
        config={
            "displayModeBar": True,
            "displaylogo": False,
            "modeBarButtonsToRemove": ["lasso2d", "select2d"],
            "toImageButtonOptions": {
                "format": "png",
                "filename": f"{title or 'chart'}",
                "height": height,
                "width": 1200,
                "scale": 2,
            },
        },
    )

    if title:
        st.markdown("</div>", unsafe_allow_html=True)


def create_bar_chart(
    x: list,
    y: list,
    title: str = "",
    x_label: str = "",
    y_label: str = "",
    color: str = Colors.PRIMARY,
    orientation: str = "v",
) -> go.Figure:
    """Create a styled bar chart."""
    fig = go.Figure(go.Bar(
        x=x, y=y,
        orientation=orientation,
        marker_color=color,
        hovertemplate="%{x}<br>%{y}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text=title, x=0.01, font=dict(size=14)),
        xaxis_title=x_label,
        yaxis_title=y_label,
    )
    return fig


def create_line_chart(
    x: list,
    y: list,
    title: str = "",
    x_label: str = "",
    y_label: str = "",
    color: str = Colors.PRIMARY,
    fill: bool = False,
) -> go.Figure:
    """Create a styled line/area chart."""
    fig = go.Figure(go.Scatter(
        x=x, y=y,
        mode="lines",
        line=dict(color=color, width=2),
        fill="tozeroy" if fill else None,
        fillcolor=f"{color}20" if fill else None,
        hovertemplate="%{x}<br>%{y}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text=title, x=0.01, font=dict(size=14)),
        xaxis_title=x_label,
        yaxis_title=y_label,
    )
    return fig


def create_donut_chart(
    labels: list,
    values: list,
    title: str = "",
    colors: list[str] | None = None,
) -> go.Figure:
    """Create a styled donut/pie chart."""
    from dashboard.theme import Colors as C
    palette = colors or C.CHART_PALETTE

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=palette[:len(labels)], line=dict(color="rgba(0,0,0,0)", width=2)),
        textinfo="label+percent",
        textposition="outside",
        textfont=dict(size=11),
        hovertemplate="%{label}: %{value}<br>%{percent}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text=title, x=0.01, font=dict(size=14)),
        showlegend=False,
    )
    return fig


def create_horizontal_bar_chart(
    y: list,
    x: list,
    title: str = "",
    x_label: str = "",
    y_label: str = "",
    color: str = Colors.PRIMARY,
) -> go.Figure:
    """Create a styled horizontal bar chart (good for top-N lists)."""
    fig = go.Figure(go.Bar(
        x=x, y=y,
        orientation="h",
        marker_color=color,
        hovertemplate="%{y}: %{x}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text=title, x=0.01, font=dict(size=14)),
        xaxis_title=x_label,
        yaxis_title=y_label,
        yaxis=dict(autorange="reversed"),
    )
    return fig
