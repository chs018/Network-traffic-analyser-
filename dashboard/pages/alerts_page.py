"""
alerts_page.py — Alert Center Page
====================================
Enterprise SOC Dashboard

Professional alert management with:
  - Alert summary KPI cards
  - Severity/type filters
  - Paginated alert table with clickable rows
  - Full alert detail panel (evidence, recommendation, confidence)
  - Severity distribution chart
  - CSV/JSON export

Author: Network Traffic Analyzer Project
Version: 7.5.0
Python: 3.11+
"""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from dashboard.components.alert_cards import render_alert_summary_cards
from dashboard.components.chart_containers import render_chart
from dashboard.components.data_tables import render_alert_table
from dashboard.components.section_headers import render_section_header
from dashboard.data_loaders import load_alert_summary, load_alerts
from dashboard.styles import get_plotly_layout
from dashboard.theme import Colors, SEVERITY_COLORS


def render() -> None:
    """Render the Alert Center page."""
    # ── Alert Summary KPIs ───────────────────────────────────────────────────
    render_section_header("🚨", "Alert Center", "Security event management")
    summary = load_alert_summary()
    render_alert_summary_cards(summary)

    st.markdown("---")

    # ── Alert Browser ────────────────────────────────────────────────────────
    render_section_header("🔍", "Alert Browser", "Search, filter, and inspect alerts")
    _render_alert_browser()


def _render_alert_browser() -> None:
    """Render the alert browser with filters, table, and detail panel."""
    col1, col2, col3, col4 = st.columns([2, 2, 2, 2])

    with col1:
        severity_filter = st.selectbox(
            "Severity",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0,
            key="alert_sev_filter",
        )

    with col2:
        attack_types = list(load_alert_summary().get("attack_counts", {}).keys())
        attack_filter = st.selectbox(
            "Attack Type",
            options=["All"] + attack_types,
            index=0,
            key="alert_type_filter",
        )

    with col3:
        max_rows = st.selectbox(
            "Max Rows",
            options=[25, 50, 100, 200, 500],
            index=1,
            key="alert_max_rows",
        )

    with col4:
        st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
        if st.button("🔄 Refresh Alerts", use_container_width=True, key="btn_refresh_alerts"):
            load_alerts.clear()
            load_alert_summary.clear()
            st.rerun()

    # Load filtered data
    sev = None if severity_filter == "All" else severity_filter
    atype = None if attack_filter == "All" else attack_filter

    df = load_alerts(limit=max_rows, severity=sev, alert_type=atype)

    if df.empty:
        _render_no_alerts_state()
        return

    # ── Data Table ────────────────────────────────────────────────────────────
    render_alert_table(df, max_rows=max_rows, key="alerts_page_table")

    # ── Alert Detail Inspector ────────────────────────────────────────────────
    st.markdown("---")
    render_section_header("🔎", "Alert Detail Inspector", "Select an alert row to inspect")
    _render_alert_detail_panel(df)

    # ── Export ────────────────────────────────────────────────────────────────
    st.markdown("---")
    render_section_header("📥", "Export Alerts", "Download filtered alert data")
    _render_export_section(df)

    # ── Severity Chart ────────────────────────────────────────────────────────
    st.markdown("---")
    render_section_header("📊", "Severity Distribution", "Alert severity breakdown")
    _render_severity_chart()


def _render_alert_detail_panel(df: pd.DataFrame) -> None:
    """
    Render an expandable detail panel for a selected alert.
    The user selects a row index to inspect the full alert record.
    """
    if df.empty:
        st.info("No alerts to inspect.")
        return

    max_idx = len(df) - 1

    col1, col2 = st.columns([1, 3])
    with col1:
        row_idx = st.number_input(
            "Alert row (0-based index)",
            min_value=0,
            max_value=max_idx,
            value=0,
            step=1,
            key="alert_detail_idx",
        )

    row = df.iloc[int(row_idx)]

    with st.expander(
        f"🚨 Alert Detail — Row {int(row_idx)}: {row.get('alert_type', '—')}",
        expanded=True,
    ):
        _render_single_alert_detail(row)


def _render_single_alert_detail(row: pd.Series) -> None:
    """Render the full detail view for a single alert."""
    # Severity color
    sev = str(row.get("severity", "LOW")).upper()
    sev_color = SEVERITY_COLORS.get(sev, "#8B949E")
    confidence = row.get("confidence", 0)
    if isinstance(confidence, float):
        conf_pct = f"{confidence:.0%}"
    else:
        conf_pct = str(confidence)

    # ── Top Row: Alert ID + Severity Badge ────────────────────────────────────
    st.markdown(
        f"""
        <div style="display:flex;align-items:center;gap:16px;
                    padding:12px 16px;background:rgba(255,255,255,0.03);
                    border-radius:8px;margin-bottom:12px;
                    border-left:4px solid {sev_color};">
            <span style="font-size:1.4rem;">🚨</span>
            <div style="flex:1;">
                <div style="font-weight:700;font-size:1rem;color:#E6EDF3;">
                    {row.get('alert_type', '—')}
                </div>
                <div style="font-size:0.75rem;color:#8B949E;font-family:monospace;">
                    ID: {row.get('alert_id', row.get('id', '—'))}
                </div>
            </div>
            <span style="padding:4px 14px;border-radius:999px;font-weight:700;
                         font-size:0.8rem;color:{sev_color};
                         background:{sev_color}1A;border:1px solid {sev_color}50;">
                {sev}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Detail Columns ────────────────────────────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**📡 Network Details**")
        _detail_row("Source IP", row.get("src_ip", row.get("source_ip", "—")))
        _detail_row("Destination IP", row.get("dst_ip", row.get("destination_ip", "—")))
        _detail_row("Protocol", row.get("protocol", "—"))
        _detail_row("Port", row.get("dst_port", row.get("port", "—")))
        _detail_row("Timestamp", str(row.get("timestamp", "—"))[:19].replace("T", " "))

    with col2:
        st.markdown("**🔍 Detection Details**")
        _detail_row("Detector", row.get("detector_name", row.get("detector", "—")))
        _detail_row("Confidence", conf_pct)
        _detail_row("Severity", sev)
        _detail_row("Rule / Method", row.get("rule", "—"))

        # Confidence bar
        conf_val = float(confidence) if isinstance(confidence, (int, float)) else 0.0
        _render_confidence_bar(conf_val, sev_color)

    # ── Description ───────────────────────────────────────────────────────────
    description = row.get("description", row.get("raw_evidence", ""))
    if description and str(description) not in ("nan", "None", ""):
        st.markdown("**📝 Description**")
        st.markdown(
            f"""
            <div style="background:rgba(255,255,255,0.03);border-radius:8px;
                        padding:12px 14px;border:1px solid rgba(255,255,255,0.08);
                        font-size:0.83rem;color:#C9D1D9;line-height:1.6;">
                {description}
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Evidence ──────────────────────────────────────────────────────────────
    evidence_raw = row.get("evidence", row.get("raw_evidence", ""))
    if evidence_raw and str(evidence_raw) not in ("nan", "None", "{}"):
        st.markdown("**🧩 Evidence**")
        try:
            if isinstance(evidence_raw, str):
                evidence = json.loads(evidence_raw)
            else:
                evidence = evidence_raw
            if isinstance(evidence, dict):
                for k, v in evidence.items():
                    _detail_row(
                        k.replace("_", " ").title(),
                        str(v)[:120],
                    )
            else:
                st.code(str(evidence_raw), language="json")
        except Exception:
            st.code(str(evidence_raw)[:500])

    # ── Recommendation ────────────────────────────────────────────────────────
    rec = row.get("recommendation", "")
    if rec and str(rec) not in ("nan", "None", ""):
        st.markdown("**💡 Recommendation**")
        st.info(str(rec))

    # ── Raw Record ────────────────────────────────────────────────────────────
    with st.expander("📄 Full Raw Record (JSON)", expanded=False):
        st.json(row.dropna().to_dict())


def _render_confidence_bar(confidence: float, color: str) -> None:
    """Render a visual confidence bar."""
    pct = max(0.0, min(1.0, confidence))
    st.markdown(
        f"""
        <div style="margin-top:8px;">
            <div style="font-size:0.72rem;color:#8B949E;margin-bottom:4px;">
                Confidence: {pct:.0%}
            </div>
            <div style="background:rgba(255,255,255,0.08);border-radius:4px;height:6px;">
                <div style="background:{color};width:{pct*100:.1f}%;height:6px;
                             border-radius:4px;transition:width 0.5s ease;"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _detail_row(label: str, value) -> None:
    """Render a label-value detail row."""
    st.markdown(
        f"""
        <div style="display:flex;justify-content:space-between;align-items:center;
                    padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.05);">
            <span style="color:#8B949E;font-size:0.8rem;">{label}</span>
            <span style="color:#E6EDF3;font-family:monospace;font-size:0.8rem;
                         font-weight:500;max-width:65%;text-align:right;
                         word-break:break-all;">{value}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_export_section(df: pd.DataFrame) -> None:
    """Render CSV/JSON export buttons."""
    col1, col2 = st.columns(2)

    with col1:
        if st.button("📊 Generate CSV Export", use_container_width=True, key="btn_gen_alert_csv"):
            st.download_button(
                "📥 Download Alerts (CSV)",
                data=df.to_csv(index=False),
                file_name="alerts_export.csv",
                mime="text/csv",
                key="dl_alert_csv",
                use_container_width=True,
            )

    with col2:
        if st.button("📋 Generate JSON Export", use_container_width=True, key="btn_gen_alert_json"):
            st.download_button(
                "📥 Download Alerts (JSON)",
                data=df.to_json(orient="records", indent=2),
                file_name="alerts_export.json",
                mime="application/json",
                key="dl_alert_json",
                use_container_width=True,
            )


def _render_severity_chart() -> None:
    """Render the severity distribution donut chart."""
    import plotly.graph_objects as go

    summary = load_alert_summary()
    sev_dist = summary.get("severity_dist", {})
    if not sev_dist:
        st.caption("No alert data to chart.")
        return

    labels = list(sev_dist.keys())
    values = list(sev_dist.values())
    colors = [SEVERITY_COLORS.get(s, "#8B949E") for s in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.5,
        marker=dict(colors=colors, line=dict(color="rgba(0,0,0,0)", width=2)),
        textinfo="label+percent",
        textposition="outside",
    ))
    fig.update_layout(
        title="Severity Breakdown",
        showlegend=False,
        height=300,
    )
    render_chart(fig, height=300, key="alerts_sev_dist")


def _render_no_alerts_state() -> None:
    """Show a friendly empty state when no alerts match the filters."""
    st.markdown(
        """
        <div style="text-align:center;padding:48px 20px;
                    background:rgba(255,255,255,0.02);border-radius:12px;
                    border:1px dashed rgba(255,255,255,0.07);margin-top:16px;">
            <div style="font-size:2.5rem;margin-bottom:12px;">✅</div>
            <div style="font-size:1.1rem;font-weight:600;color:#E6EDF3;margin-bottom:6px;">
                No Alerts Found
            </div>
            <div style="font-size:0.85rem;color:#8B949E;">
                No alerts match the current filters, or no analysis has been run yet.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📁 Upload & Analyse", type="primary", key="btn_upload_from_alerts"):
            st.session_state.current_page = "upload"
            st.rerun()
    with col2:
        if st.button("🎭 Run Demo", key="btn_demo_from_alerts"):
            st.session_state.current_page = "upload"
            st.rerun()
