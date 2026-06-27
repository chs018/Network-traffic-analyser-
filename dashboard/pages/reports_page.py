"""
reports_page.py — Report Generation & Downloads
=================================================
Enterprise SOC Dashboard

One-click generation of professional analysis reports in multiple formats.
All reports are built from the current database contents and available
for immediate download.

Report Types:
  - Traffic Summary Report  (CSV + JSON)
  - Security Alerts Report  (CSV + JSON)
  - Protocol Analysis Report (JSON)
  - Executive Summary        (JSON + plain text)
  - Combined Full Report     (JSON)

Author: Network Traffic Analyzer Project
Version: 7.5.0
Python: 3.11+
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import streamlit as st

from dashboard.components.section_headers import render_section_header
from dashboard.data_loaders import (
    load_alert_summary,
    load_alerts,
    load_bandwidth_summary,
    load_health_report,
    load_protocol_distribution,
    load_traffic_summary,
)
from dashboard.theme import Colors


# ──────────────────────────────────────────────────────────────────────────────
# MAIN RENDER
# ──────────────────────────────────────────────────────────────────────────────

def render() -> None:
    """Render the Reports & Downloads page."""
    _render_header()

    # Check if there is data
    traffic = load_traffic_summary()
    if traffic.get("total_packets", 0) == 0:
        _render_empty_state()
        return

    render_section_header("📋", "Available Reports", "Click Generate then Download")

    _render_traffic_report_card(traffic)
    st.markdown("")
    _render_alerts_report_card()
    st.markdown("")
    _render_protocol_report_card()
    st.markdown("")
    _render_executive_summary_card(traffic)
    st.markdown("")
    _render_combined_report_card(traffic)


# ──────────────────────────────────────────────────────────────────────────────
# PAGE HEADER
# ──────────────────────────────────────────────────────────────────────────────

def _render_header() -> None:
    st.markdown(
        """
        <div class="hero-banner">
            <div class="hero-title">📋 Reports & Downloads</div>
            <div class="hero-subtitle">
                Generate and download professional analysis reports in CSV or JSON format.
                All reports are built from the current database contents.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# REPORT CARDS
# ──────────────────────────────────────────────────────────────────────────────

def _report_card_header(icon: str, title: str, description: str) -> None:
    """Render a report card header section."""
    st.markdown(
        f"""
        <div style="background:rgba(21,101,192,0.06);border:1px solid rgba(21,101,192,0.15);
                    border-radius:12px;padding:16px 20px;margin-bottom:12px;">
            <div style="display:flex;align-items:center;gap:12px;">
                <span style="font-size:1.6rem;">{icon}</span>
                <div>
                    <div style="font-weight:700;color:#E6EDF3;font-size:1rem;">{title}</div>
                    <div style="font-size:0.78rem;color:#8B949E;margin-top:2px;">{description}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_traffic_report_card(traffic: dict) -> None:
    """Traffic Summary Report card."""
    with st.expander("📈 Traffic Summary Report", expanded=False):
        _report_card_header(
            "📈",
            "Traffic Summary Report",
            "Total packets, bytes, PPS, BPS, top IPs, packet size statistics.",
        )
        col1, col2 = st.columns(2)
        with col1:
            if st.button("⚡ Generate CSV", key="gen_traffic_csv", use_container_width=True):
                csv = _build_traffic_csv(traffic)
                st.download_button(
                    "📥 Download Traffic Report (CSV)",
                    data=csv,
                    file_name=_report_filename("traffic_summary", "csv"),
                    mime="text/csv",
                    key="dl_traffic_csv",
                    use_container_width=True,
                )
        with col2:
            if st.button("⚡ Generate JSON", key="gen_traffic_json", use_container_width=True):
                js = json.dumps(traffic, indent=2, default=str)
                st.download_button(
                    "📥 Download Traffic Report (JSON)",
                    data=js,
                    file_name=_report_filename("traffic_summary", "json"),
                    mime="application/json",
                    key="dl_traffic_json",
                    use_container_width=True,
                )

        # Preview
        st.caption("**Preview**")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Packets", f"{traffic.get('total_packets', 0):,}")
        with col2:
            total_mb = traffic.get("total_bytes", 0) / 1_048_576
            st.metric("Total Data", f"{total_mb:.2f} MB")
        with col3:
            st.metric("Unique Source IPs", traffic.get("unique_src_ips", 0))


def _render_alerts_report_card() -> None:
    """Security Alerts Report card."""
    with st.expander("🚨 Security Alerts Report", expanded=False):
        _report_card_header(
            "🚨",
            "Security Alerts Report",
            "All detected alerts with severity, confidence, source/destination IPs, and evidence.",
        )
        df_alerts = load_alerts(limit=50000)
        alert_summary = load_alert_summary()

        col1, col2 = st.columns(2)
        with col1:
            if st.button("⚡ Generate CSV", key="gen_alerts_csv", use_container_width=True):
                if not df_alerts.empty:
                    st.download_button(
                        "📥 Download Alerts Report (CSV)",
                        data=df_alerts.to_csv(index=False),
                        file_name=_report_filename("security_alerts", "csv"),
                        mime="text/csv",
                        key="dl_alerts_csv",
                        use_container_width=True,
                    )
                else:
                    st.info("No alerts found.")
        with col2:
            if st.button("⚡ Generate JSON", key="gen_alerts_json", use_container_width=True):
                payload = {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "summary": alert_summary,
                    "alerts": df_alerts.to_dict(orient="records") if not df_alerts.empty else [],
                }
                st.download_button(
                    "📥 Download Alerts Report (JSON)",
                    data=json.dumps(payload, indent=2, default=str),
                    file_name=_report_filename("security_alerts", "json"),
                    mime="application/json",
                    key="dl_alerts_json",
                    use_container_width=True,
                )

        # Preview
        st.caption("**Alert Summary**")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total", alert_summary.get("total", 0))
        with col2:
            st.metric("🔴 Critical", alert_summary.get("critical", 0))
        with col3:
            st.metric("🟠 High", alert_summary.get("high", 0))
        with col4:
            st.metric("🟡 Medium", alert_summary.get("medium", 0))


def _render_protocol_report_card() -> None:
    """Protocol Analysis Report card."""
    with st.expander("📡 Protocol Analysis Report", expanded=False):
        _report_card_header(
            "📡",
            "Protocol Analysis Report",
            "Protocol distribution, bandwidth utilisation, and health metrics.",
        )
        proto_df = load_protocol_distribution()
        bw = load_bandwidth_summary()
        health = load_health_report()

        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "protocol_distribution": proto_df.to_dict(orient="records") if not proto_df.empty else [],
            "bandwidth": bw,
            "health": health,
        }

        col1, col2 = st.columns(2)
        with col1:
            if st.button("⚡ Generate CSV", key="gen_proto_csv", use_container_width=True):
                if not proto_df.empty:
                    st.download_button(
                        "📥 Download Protocol Report (CSV)",
                        data=proto_df.to_csv(index=False),
                        file_name=_report_filename("protocol_analysis", "csv"),
                        mime="text/csv",
                        key="dl_proto_csv",
                        use_container_width=True,
                    )
                else:
                    st.info("No protocol data available.")
        with col2:
            if st.button("⚡ Generate JSON", key="gen_proto_json", use_container_width=True):
                st.download_button(
                    "📥 Download Protocol Report (JSON)",
                    data=json.dumps(payload, indent=2, default=str),
                    file_name=_report_filename("protocol_analysis", "json"),
                    mime="application/json",
                    key="dl_proto_json",
                    use_container_width=True,
                )

        # Preview top protocols
        if not proto_df.empty:
            st.caption("**Top 5 Protocols**")
            st.dataframe(proto_df.head(5), use_container_width=True, hide_index=True)


def _render_executive_summary_card(traffic: dict) -> None:
    """Executive Summary Report card."""
    with st.expander("📊 Executive Summary", expanded=False):
        _report_card_header(
            "📊",
            "Executive Summary",
            "High-level summary suitable for management presentation.",
        )
        alert_summary = load_alert_summary()
        health = load_health_report()

        summary = _build_executive_summary(traffic, alert_summary, health)

        col1, col2 = st.columns(2)
        with col1:
            if st.button("⚡ Generate Text", key="gen_exec_txt", use_container_width=True):
                txt = _format_executive_txt(summary)
                st.download_button(
                    "📥 Download Executive Summary (TXT)",
                    data=txt,
                    file_name=_report_filename("executive_summary", "txt"),
                    mime="text/plain",
                    key="dl_exec_txt",
                    use_container_width=True,
                )
        with col2:
            if st.button("⚡ Generate JSON", key="gen_exec_json", use_container_width=True):
                st.download_button(
                    "📥 Download Executive Summary (JSON)",
                    data=json.dumps(summary, indent=2, default=str),
                    file_name=_report_filename("executive_summary", "json"),
                    mime="application/json",
                    key="dl_exec_json",
                    use_container_width=True,
                )

        # Preview
        st.markdown(f"""
        **Generated:** {summary['generated_at'][:19].replace('T', ' ')}  
        **Health Score:** {summary['health_score']}/100  
        **Total Alerts:** {summary['total_alerts']}  
        **Threat Level:** {summary['overall_threat_level']}  
        """)


def _render_combined_report_card(traffic: dict) -> None:
    """Full Combined Report card."""
    with st.expander("📦 Full Combined Report", expanded=False):
        _report_card_header(
            "📦",
            "Full Combined Report",
            "All sections combined — traffic, alerts, protocols, health, and ML results.",
        )
        if st.button("⚡ Generate Full Report (JSON)", key="gen_full_json", use_container_width=True):
            alert_summary = load_alert_summary()
            health = load_health_report()
            bw = load_bandwidth_summary()
            proto_df = load_protocol_distribution()
            df_alerts = load_alerts(limit=50000)

            combined = {
                "report_type": "full_combined",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "traffic_summary": traffic,
                "alert_summary": alert_summary,
                "alerts": df_alerts.to_dict(orient="records") if not df_alerts.empty else [],
                "protocol_distribution": proto_df.to_dict(orient="records") if not proto_df.empty else [],
                "bandwidth": bw,
                "health": health,
                "executive_summary": _build_executive_summary(traffic, alert_summary, health),
            }

            st.download_button(
                "📥 Download Full Report (JSON)",
                data=json.dumps(combined, indent=2, default=str),
                file_name=_report_filename("full_report", "json"),
                mime="application/json",
                key="dl_full_json",
                use_container_width=True,
            )
            st.success("✅ Full report ready for download.")


# ──────────────────────────────────────────────────────────────────────────────
# REPORT BUILDERS
# ──────────────────────────────────────────────────────────────────────────────

def _build_traffic_csv(traffic: dict) -> str:
    """Build a CSV string for the traffic summary."""
    import io, csv as _csv
    buf = io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["Metric", "Value"])
    for k, v in traffic.items():
        if not isinstance(v, (list, dict)):
            w.writerow([k, v])
    # Top source IPs
    for ip, count in (traffic.get("top_src_ips") or []):
        w.writerow([f"top_src_ip:{ip}", count])
    for ip, count in (traffic.get("top_dst_ips") or []):
        w.writerow([f"top_dst_ip:{ip}", count])
    return buf.getvalue()


def _build_executive_summary(
    traffic: dict, alert_summary: dict, health: dict
) -> dict:
    """Build a structured executive summary dict."""
    total_alerts = alert_summary.get("total", 0)
    critical = alert_summary.get("critical", 0)
    high = alert_summary.get("high", 0)

    if critical > 0:
        threat = "CRITICAL"
    elif high > 0:
        threat = "HIGH"
    elif total_alerts > 0:
        threat = "MEDIUM"
    else:
        threat = "LOW"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_threat_level": threat,
        "health_score": health.get("health_score", 0),
        "health_status": health.get("status", "Unknown"),
        "total_packets": traffic.get("total_packets", 0),
        "total_bytes": traffic.get("total_bytes", 0),
        "capture_duration_s": traffic.get("capture_duration", 0),
        "unique_src_ips": traffic.get("unique_src_ips", 0),
        "unique_dst_ips": traffic.get("unique_dst_ips", 0),
        "total_alerts": total_alerts,
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": alert_summary.get("medium", 0),
        "low_alerts": alert_summary.get("low", 0),
        "recommendations": health.get("recommendations", []),
    }


def _format_executive_txt(summary: dict) -> str:
    """Format executive summary as plain text."""
    lines = [
        "=" * 60,
        "NETWORK TRAFFIC ANALYSIS — EXECUTIVE SUMMARY",
        "=" * 60,
        f"Generated: {summary['generated_at'][:19].replace('T', ' ')} UTC",
        "",
        "OVERALL THREAT LEVEL: " + summary["overall_threat_level"],
        "HEALTH SCORE: " + str(summary["health_score"]) + "/100",
        "HEALTH STATUS: " + str(summary["health_status"]),
        "",
        "TRAFFIC STATISTICS",
        "-" * 40,
        f"  Total Packets  : {summary['total_packets']:,}",
        f"  Total Data     : {summary['total_bytes'] / 1_048_576:.2f} MB",
        f"  Capture Window : {summary['capture_duration_s']:.1f} seconds",
        f"  Unique Sources : {summary['unique_src_ips']}",
        f"  Unique Dests   : {summary['unique_dst_ips']}",
        "",
        "SECURITY ALERTS",
        "-" * 40,
        f"  Total Alerts   : {summary['total_alerts']}",
        f"  Critical       : {summary['critical_alerts']}",
        f"  High           : {summary['high_alerts']}",
        f"  Medium         : {summary['medium_alerts']}",
        f"  Low            : {summary['low_alerts']}",
        "",
        "RECOMMENDATIONS",
        "-" * 40,
    ]
    for r in summary.get("recommendations", []):
        lines.append(f"  • {r}")
    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def _report_filename(report_type: str, extension: str) -> str:
    """Generate a timestamped report filename."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"netids_{report_type}_{ts}.{extension}"


# ──────────────────────────────────────────────────────────────────────────────
# EMPTY STATE
# ──────────────────────────────────────────────────────────────────────────────

def _render_empty_state() -> None:
    st.markdown(
        """
        <div style="text-align:center;padding:60px 20px;
                    background:rgba(255,255,255,0.02);border-radius:16px;
                    border:1px dashed rgba(255,255,255,0.08);margin-top:32px;">
            <div style="font-size:3rem;margin-bottom:16px;">📋</div>
            <div style="font-size:1.2rem;font-weight:600;color:#E6EDF3;margin-bottom:8px;">
                No Data Available
            </div>
            <div style="font-size:0.9rem;color:#8B949E;max-width:400px;margin:0 auto 24px auto;">
                Run an analysis pipeline first to generate reports.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("📁 Upload & Analyse", type="primary", key="btn_go_upload_reports"):
        st.session_state.current_page = "upload"
        st.rerun()
