"""
section_headers.py — Reusable Section Header Component
=======================================================
Enterprise SOC Dashboard

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

from __future__ import annotations

import streamlit as st


def render_section_header(
    icon: str,
    title: str,
    subtitle: str = "",
    help_text: str = "",
) -> None:
    """Render a consistent section header with icon, title, and divider."""
    sub_html = f'<span class="section-subtitle">{subtitle}</span>' if subtitle else ""
    help_attr = f' title="{help_text}"' if help_text else ""

    st.markdown(
        f'<div class="section-header"{help_attr}>'
        f'<span class="section-icon">{icon}</span>'
        f'<div>'
        f'<div class="section-title">{title}</div>'
        f'{sub_html}'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
