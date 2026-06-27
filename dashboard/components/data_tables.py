"""
data_tables.py — Alert Data Table Component
=============================================
Enterprise SOC Dashboard

Renders professional alert tables with search, filter, sort,
pagination, and colour-coded rows using st.dataframe.

Author: Network Traffic Analyzer Project
Version: 2.0.0
"""

from __future__ import annotations

from typing import Optional

import pandas as pd
import streamlit as st

from dashboard.theme import SEVERITY_COLORS, SEVERITY_BG


def render_alert_table(
    df: pd.DataFrame,
    max_rows: int = 100,
    key: str = "alert_table",
) -> None:
    """
    Render a professional alert data table with severity colour coding.

    Args:
        df: DataFrame with alert data (should contain: id, timestamp, severity,
            alert_type, src_ip, dst_ip, description columns).
        max_rows: Maximum rows to display.
        key: Unique Streamlit key.
    """
    if df.empty:
        st.info("No alerts to display.")
        return

    # Select and rename columns for display
    display_cols = []
    col_mapping = {
        "id": "ID",
        "timestamp": "Time",
        "severity": "Severity",
        "alert_type": "Attack",
        "src_ip": "Source IP",
        "dst_ip": "Dest IP",
        "dst_port": "Port",
        "protocol": "Protocol",
        "description": "Recommendation",
    }

    for col, label in col_mapping.items():
        if col in df.columns:
            display_cols.append(col)

    display_df = df[display_cols].copy()

    # Rename columns
    rename_map = {col: col_mapping[col] for col in display_cols}
    display_df = display_df.rename(columns=rename_map)

    # Limit rows
    display_df = display_df.head(max_rows)

    # Apply severity colouring via Styler
    if "Severity" in display_df.columns:
        def _color_severity(row):
            sev = str(row.get("Severity", "")).upper()
            bg = SEVERITY_BG.get(sev, "transparent")
            return [f"background-color: {bg}"] * len(row)

        styled = display_df.style.apply(_color_severity, axis=1)
        st.dataframe(
            styled,
            use_container_width=True,
            height=min(35 * len(display_df) + 40, 600),
            key=key,
        )
    else:
        st.dataframe(
            display_df,
            use_container_width=True,
            height=min(35 * len(display_df) + 40, 600),
            key=key,
        )

    # Export buttons
    col1, col2, _ = st.columns([1, 1, 4])
    with col1:
        csv = display_df.to_csv(index=False)
        st.download_button(
            label="Export CSV",
            data=csv,
            file_name="alerts.csv",
            mime="text/csv",
            key=f"{key}_csv",
        )
    with col2:
        json_data = display_df.to_json(orient="records", indent=2)
        st.download_button(
            label="Export JSON",
            data=json_data,
            file_name="alerts.json",
            mime="application/json",
            key=f"{key}_json",
        )
