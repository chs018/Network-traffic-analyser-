"""
upload_page.py — PCAP Upload & Analysis Page
==============================================
Enterprise SOC Dashboard

Provides the primary entry point for network traffic analysis:
  - Drag-and-drop PCAP file upload
  - Real-time pipeline progress via st.status()
  - Step-by-step progress reporting
  - Demo mode for demonstration without a real PCAP file
  - Analysis result summary after completion

Author: Network Traffic Analyzer Project
Version: 7.5.0
Python: 3.11+
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import streamlit as st

from dashboard.components.section_headers import render_section_header
from dashboard.pipeline import PipelineOrchestrator, init_pipeline_state
from dashboard.theme import Colors


def render() -> None:
    """Render the Upload & Analyse page."""
    init_pipeline_state()

    _render_page_header()

    # Show last analysis result banner at top if available
    result = st.session_state.get("pipeline_result")
    if result and result.get("success"):
        _render_result_banner(result)
        st.markdown("---")

    # ── Upload Section ───────────────────────────────────────────────────────
    render_section_header("📁", "Upload PCAP File", "Drag & drop or click to browse")
    uploaded_file = _render_upload_widget()

    st.markdown("---")

    # ── Controls ─────────────────────────────────────────────────────────────
    render_section_header("🎮", "Analysis Controls", "Start, stop, or run demo")
    _render_controls(uploaded_file)

    # ── Progress Display ─────────────────────────────────────────────────────
    if st.session_state.get("pipeline_running"):
        st.markdown("---")
        render_section_header("⚙️", "Pipeline Status", "Live progress tracking")
        _render_running_state()


def _render_page_header() -> None:
    """Render the page hero banner."""
    st.markdown(
        """
        <div class="hero-banner">
            <div class="hero-title">📁 Upload & Analyse</div>
            <div class="hero-subtitle">
                Upload a PCAP / PCAPng network capture file to run the full 
                analysis pipeline — traffic statistics, protocol analysis, 
                rule-based intrusion detection, and ML anomaly detection.
            </div>
            <div class="hero-status">
                <span class="pulse-dot"></span>
                End-to-End Analysis Pipeline
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_upload_widget() -> Optional[object]:
    """Render the file upload widget and return the uploaded file object."""
    st.markdown(
        """
        <style>
        .upload-zone {
            border: 2px dashed rgba(21,101,192,0.4);
            border-radius: 12px;
            padding: 32px;
            text-align: center;
            background: rgba(21,101,192,0.04);
            margin-bottom: 16px;
            transition: all 0.3s ease;
        }
        .upload-zone:hover {
            border-color: rgba(21,101,192,0.7);
            background: rgba(21,101,192,0.08);
        }
        .upload-hint {
            font-size: 0.8rem;
            color: #8B949E;
            margin-top: 8px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Drag & drop your PCAP file here, or click to browse",
        type=["pcap", "pcapng", "cap"],
        accept_multiple_files=False,
        label_visibility="collapsed",
        key="pcap_uploader",
    )

    if uploaded_file is not None:
        # Save to data/raw directory
        raw_dir = Path("data") / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        save_path = raw_dir / uploaded_file.name

        with open(save_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        st.session_state.current_file = str(save_path)
        st.session_state.current_file_name = uploaded_file.name

        # Show file info
        size_kb = uploaded_file.size / 1024
        size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.2f} MB"

        st.markdown(
            f"""
            <div style="background:rgba(0,200,81,0.08);border:1px solid rgba(0,200,81,0.25);
                        border-radius:10px;padding:16px;margin-top:8px;">
                <div style="display:flex;align-items:center;gap:12px;">
                    <span style="font-size:1.5rem;">✅</span>
                    <div>
                        <div style="font-weight:600;color:#E6EDF3;">{uploaded_file.name}</div>
                        <div style="font-size:0.78rem;color:#8B949E;">
                            Size: <strong>{size_str}</strong> &nbsp;|&nbsp;
                            Type: <strong>{uploaded_file.type or "pcap"}</strong> &nbsp;|&nbsp;
                            Ready to analyse
                        </div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div class="upload-hint">
                Supported formats: .pcap, .pcapng, .cap
                &nbsp;|&nbsp; Requires TShark / Wireshark installed
            </div>
            """,
            unsafe_allow_html=True,
        )

    return uploaded_file


def _render_controls(uploaded_file) -> None:
    """Render Start / Stop / Demo controls."""
    running = st.session_state.get("pipeline_running", False)

    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        start_disabled = running or (
            uploaded_file is None
            and not st.session_state.get("current_file")
        )
        if st.button(
            "▶  Start Analysis",
            use_container_width=True,
            disabled=start_disabled,
            key="btn_start_analysis",
            type="primary",
        ):
            _run_pipeline()

    with col2:
        if st.button(
            "⏹  Stop",
            use_container_width=True,
            disabled=not running,
            key="btn_stop_analysis",
        ):
            st.session_state["_stop_pipeline"] = True
            st.warning("⏹ Stop requested — pipeline will halt after the current step.")

    with col3:
        if st.button(
            "🎭  Demo Mode",
            use_container_width=True,
            disabled=running,
            key="btn_demo_mode",
            help="Generate synthetic traffic data and run the full pipeline",
        ):
            _run_demo()

    # Current file indicator
    current = st.session_state.get("current_file_name", "")
    if current:
        st.markdown(
            f"""
            <div style="margin-top:12px;padding:8px 12px;border-radius:8px;
                        background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);
                        font-size:0.8rem;color:#8B949E;">
                📎 Selected: <strong style="color:#E6EDF3;">{current}</strong>
            </div>
            """,
            unsafe_allow_html=True,
        )


def _run_pipeline() -> None:
    """Execute the analysis pipeline for the uploaded PCAP file."""
    file_path = st.session_state.get("current_file", "")
    if not file_path:
        st.error("Please upload a PCAP file first.")
        return

    pcap_path = Path(file_path)
    if not pcap_path.exists():
        st.error(f"File not found: {file_path}")
        return

    orch = PipelineOrchestrator()

    with st.status("🔄 Running analysis pipeline…", expanded=True) as status:
        progress = st.progress(0.0)
        result = orch.run(
            pcap_path=pcap_path,
            status_container=status,
            progress_bar=progress,
        )

    if result.success:
        st.success(
            f"✅ Analysis complete in **{result.elapsed_seconds:.1f}s** — "
            f"**{result.packets_processed:,}** packets, "
            f"**{result.alerts_generated}** alerts detected."
        )
        st.session_state.current_page = "home"
        time.sleep(1.5)
        st.rerun()
    else:
        st.error(f"❌ Pipeline failed: {result.error_message}")


def _run_demo() -> None:
    """Execute the analysis pipeline in demo mode."""
    orch = PipelineOrchestrator()

    with st.status("🎭 Generating demo data and running pipeline…", expanded=True) as status:
        progress = st.progress(0.0)
        result = orch.run_demo(
            status_container=status,
            progress_bar=progress,
        )

    if result.success:
        st.success(
            f"🎭 Demo complete in **{result.elapsed_seconds:.1f}s** — "
            f"**{result.packets_processed:,}** synthetic packets, "
            f"**{result.alerts_generated}** alerts."
        )
        st.session_state.current_file_name = "demo_synthetic_traffic.pcap"
        st.session_state.current_page = "home"
        time.sleep(1.5)
        st.rerun()
    else:
        st.error(f"❌ Demo failed: {result.error_message}")


def _render_running_state() -> None:
    """Show the live pipeline progress while running."""
    phase = st.session_state.get("pipeline_phase", "Running…")
    progress = st.session_state.get("pipeline_progress", 0.0)
    packets = st.session_state.get("pipeline_packets_done", 0)
    elapsed = st.session_state.get("pipeline_elapsed", 0.0)

    st.progress(progress)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Phase", phase)
    with col2:
        st.metric("Packets Processed", f"{packets:,}")
    with col3:
        st.metric("Elapsed", f"{elapsed:.1f}s")


def _render_result_banner(result: dict) -> None:
    """Show a summary banner from the last completed run."""
    sev = result.get("highest_severity", "NONE")
    sev_color = {
        "CRITICAL": Colors.CRITICAL,
        "HIGH": Colors.SEVERITY_HIGH,
        "MEDIUM": Colors.SEVERITY_MEDIUM,
        "LOW": Colors.SEVERITY_LOW,
        "NONE": Colors.SUCCESS,
    }.get(sev, Colors.SUCCESS)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📦 Packets", f"{result.get('packets_processed', 0):,}")
    with col2:
        st.metric("🚨 Alerts", result.get("alerts_generated", 0))
    with col3:
        st.metric("🤖 ML Anomalies", result.get("ml_anomalies", 0))
    with col4:
        st.metric("⚡ Duration", f"{result.get('elapsed_seconds', 0):.1f}s")

    st.markdown(
        f"""
        <div style="background:rgba(21,101,192,0.08);border:1px solid rgba(21,101,192,0.2);
                    border-radius:10px;padding:12px 16px;margin-top:8px;">
            <span style="font-size:0.8rem;color:#8B949E;">
                Last analysis: <strong style="color:#E6EDF3;">{result.get('pcap_file','')}</strong>
                &nbsp;|&nbsp; Threat level: 
                <strong style="color:{sev_color};">{sev}</strong>
                &nbsp;|&nbsp; Run ID: <code style="font-size:0.75rem;">{result.get('run_id','')}</code>
                &nbsp;|&nbsp; Completed: {result.get('completed_at','')[:19].replace('T',' ')}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )
