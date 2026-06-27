"""
packets_page.py — Packet Explorer
====================================
Enterprise SOC Dashboard

Browse, search, and inspect individual packets captured from PCAP files.
Provides paginated access to all traffic records with full filter controls.

Author: Network Traffic Analyzer Project
Version: 7.5.0
Python: 3.11+
"""

from __future__ import annotations

from typing import Optional

import pandas as pd
import streamlit as st

from dashboard.components.section_headers import render_section_header
from dashboard.data_loaders import load_packets_page, load_traffic_summary
from dashboard.theme import Colors


# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

PAGE_SIZE = 100

PROTOCOL_OPTIONS = [
    "All", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS",
    "ARP", "FTP", "SSH", "SMTP", "TLS",
]

DISPLAY_COLS = [
    "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "packet_length", "ttl", "tcp_flags", "timestamp",
]

COL_LABELS = {
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "src_port": "Src Port",
    "dst_port": "Dst Port",
    "protocol": "Protocol",
    "packet_length": "Length (B)",
    "ttl": "TTL",
    "tcp_flags": "TCP Flags",
    "timestamp": "Timestamp",
}


# ──────────────────────────────────────────────────────────────────────────────
# MAIN RENDER
# ──────────────────────────────────────────────────────────────────────────────

def render() -> None:
    """Render the Packet Explorer page."""
    _render_header()

    # Check if data exists
    traffic_summary = load_traffic_summary()
    total_packets = traffic_summary.get("total_packets", 0)

    if total_packets == 0:
        _render_empty_state()
        return

    # ── Filters ───────────────────────────────────────────────────────────────
    render_section_header("🔍", "Search & Filter", "Filter packets by IP, protocol, or size")
    filters = _render_filters()

    st.markdown("---")

    # ── Packet Table ──────────────────────────────────────────────────────────
    render_section_header("📋", "Packet Table", f"Browsing up to {total_packets:,} captured packets")
    _render_packet_table(filters, total_packets)


# ──────────────────────────────────────────────────────────────────────────────
# HEADER
# ──────────────────────────────────────────────────────────────────────────────

def _render_header() -> None:
    st.markdown(
        """
        <div class="hero-banner">
            <div class="hero-title">🔬 Packet Explorer</div>
            <div class="hero-subtitle">
                Browse, filter, and inspect every packet captured from your PCAP files.
                Search by IP address, protocol, port, or packet size.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# FILTERS
# ──────────────────────────────────────────────────────────────────────────────

def _render_filters() -> dict:
    """Render filter controls and return filter dict."""
    col1, col2, col3 = st.columns(3)
    col4, col5, col6 = st.columns(3)

    with col1:
        src_ip = st.text_input(
            "Source IP",
            placeholder="e.g. 192.168.1.1",
            key="pkt_filter_src_ip",
        )
    with col2:
        dst_ip = st.text_input(
            "Destination IP",
            placeholder="e.g. 8.8.8.8",
            key="pkt_filter_dst_ip",
        )
    with col3:
        protocol = st.selectbox(
            "Protocol",
            PROTOCOL_OPTIONS,
            key="pkt_filter_proto",
        )
    with col4:
        min_len = st.number_input(
            "Min Length (bytes)",
            min_value=0,
            max_value=65535,
            value=0,
            step=1,
            key="pkt_filter_min_len",
        )
    with col5:
        max_len = st.number_input(
            "Max Length (bytes)",
            min_value=0,
            max_value=65535,
            value=65535,
            step=1,
            key="pkt_filter_max_len",
        )
    with col6:
        page = st.number_input(
            "Page",
            min_value=1,
            value=1,
            step=1,
            key="pkt_page",
        )

    if st.button("🔄 Clear Filters", key="btn_clear_pkt_filters"):
        for k in ["pkt_filter_src_ip", "pkt_filter_dst_ip"]:
            st.session_state.pop(k, None)
        st.rerun()

    return {
        "src_ip": src_ip or None,
        "dst_ip": dst_ip or None,
        "protocol": protocol,
        "min_len": int(min_len) if min_len > 0 else None,
        "max_len": int(max_len) if max_len < 65535 else None,
        "page": int(page),
    }


# ──────────────────────────────────────────────────────────────────────────────
# PACKET TABLE
# ──────────────────────────────────────────────────────────────────────────────

def _render_packet_table(filters: dict, total: int) -> None:
    """Load and display the paginated packet table."""
    df, total_records = load_packets_page(
        page=filters["page"],
        page_size=PAGE_SIZE,
        src_ip_filter=filters.get("src_ip"),
        dst_ip_filter=filters.get("dst_ip"),
        protocol_filter=filters.get("protocol") if filters.get("protocol") != "All" else None,
        min_length=filters.get("min_len"),
        max_length=filters.get("max_len"),
    )

    if df.empty:
        st.info("📭 No packets match the current filters.")
        return

    # Select and rename columns that exist
    available = [c for c in DISPLAY_COLS if c in df.columns]
    df_display = df[available].copy()
    df_display = df_display.rename(columns={c: COL_LABELS.get(c, c) for c in available})

    # Format timestamp
    if "Timestamp" in df_display.columns:
        df_display["Timestamp"] = pd.to_datetime(
            df_display["Timestamp"], errors="coerce"
        ).dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")

    # Pagination info
    total_pages = max(1, (total_records + PAGE_SIZE - 1) // PAGE_SIZE)
    st.caption(
        f"Showing page **{filters['page']}** of **{total_pages}** &nbsp;|&nbsp; "
        f"**{len(df_display)}** packets &nbsp;|&nbsp; "
        f"**{total_records:,}** total records"
    )

    # Display table
    st.dataframe(
        df_display,
        use_container_width=True,
        height=450,
        column_config={
            "Length (B)": st.column_config.NumberColumn(format="%d B"),
            "Src Port": st.column_config.NumberColumn(format="%d"),
            "Dst Port": st.column_config.NumberColumn(format="%d"),
        },
    )

    # Inline packet detail expander
    render_section_header("🔎", "Packet Detail Inspector", "Select a packet row to inspect")
    _render_packet_detail(df)

    # Export
    csv = df_display.to_csv(index=False)
    st.download_button(
        label="📥 Export Page as CSV",
        data=csv,
        file_name=f"packets_page_{filters['page']}.csv",
        mime="text/csv",
        key="download_pkt_csv",
    )


# ──────────────────────────────────────────────────────────────────────────────
# PACKET DETAIL
# ──────────────────────────────────────────────────────────────────────────────

def _render_packet_detail(df: pd.DataFrame) -> None:
    """Render an expandable detail panel for a selected packet."""
    if df.empty:
        return

    max_idx = len(df) - 1
    pkt_idx = st.number_input(
        "Packet row index (0-based)",
        min_value=0,
        max_value=max_idx,
        value=0,
        step=1,
        key="pkt_detail_idx",
    )

    if 0 <= pkt_idx <= max_idx:
        row = df.iloc[int(pkt_idx)]
        with st.expander(f"📦 Packet #{int(pkt_idx)} Detail", expanded=True):
            _render_packet_row_detail(row)


def _render_packet_row_detail(row: pd.Series) -> None:
    """Render detailed information for a single packet."""
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**🔗 Network Layer**")
        _metric_row("Source IP", row.get("src_ip", "—"))
        _metric_row("Destination IP", row.get("dst_ip", "—"))
        _metric_row("Protocol", row.get("protocol", "—"))
        _metric_row("TTL", row.get("ttl", "—"))
        _metric_row("IP Version", row.get("ip_version", "4"))

    with col2:
        st.markdown("**🔌 Transport Layer**")
        _metric_row("Source Port", row.get("src_port", "—"))
        _metric_row("Destination Port", row.get("dst_port", "—"))
        _metric_row("Packet Length", f"{row.get('packet_length', 0)} bytes")
        _metric_row("Payload Size", f"{row.get('payload_size', 0)} bytes")
        _metric_row("TCP Flags", row.get("tcp_flags", "—"))

    st.markdown("**⏰ Timing**")
    _metric_row("Timestamp", str(row.get("timestamp", "—")))

    # Show all columns as JSON
    with st.expander("📄 Raw Record (all fields)"):
        st.json(row.dropna().to_dict())


def _metric_row(label: str, value) -> None:
    """Render a key-value metric row."""
    st.markdown(
        f"""
        <div style="display:flex;justify-content:space-between;padding:4px 0;
                    border-bottom:1px solid rgba(255,255,255,0.05);">
            <span style="color:#8B949E;font-size:0.82rem;">{label}</span>
            <span style="color:#E6EDF3;font-family:monospace;font-size:0.82rem;
                         font-weight:600;">{value}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# EMPTY STATE
# ──────────────────────────────────────────────────────────────────────────────

def _render_empty_state() -> None:
    """Render empty state when no packets have been captured yet."""
    st.markdown(
        """
        <div style="text-align:center;padding:60px 20px;
                    background:rgba(255,255,255,0.02);border-radius:16px;
                    border:1px dashed rgba(255,255,255,0.08);margin-top:32px;">
            <div style="font-size:3rem;margin-bottom:16px;">📭</div>
            <div style="font-size:1.2rem;font-weight:600;color:#E6EDF3;margin-bottom:8px;">
                No Packets Captured Yet
            </div>
            <div style="font-size:0.9rem;color:#8B949E;max-width:400px;margin:0 auto 24px auto;">
                Upload a PCAP file and run the analysis pipeline to populate
                the packet database.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("📁 Go to Upload Page", type="primary", key="btn_go_upload_empty"):
        st.session_state.current_page = "upload"
        st.rerun()
