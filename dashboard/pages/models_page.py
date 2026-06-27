"""
models_page.py — ML Model Manager
====================================
Enterprise SOC Dashboard

Displays all trained ML models with metadata, performance metrics,
and management actions (reload, enable/disable).

Author: Network Traffic Analyzer Project
Version: 7.5.0
Python: 3.11+
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from dashboard.components.section_headers import render_section_header
from dashboard.data_loaders import load_ml_model_info
from dashboard.theme import Colors


# Model type → emoji map
_TYPE_ICONS = {
    "anomaly": "🔍",
    "classifier": "🎯",
    "preprocessor": "⚙️",
    "unknown": "🤖",
}

_TYPE_COLORS = {
    "anomaly":      "#00BCD4",
    "classifier":   "#4CAF50",
    "preprocessor": "#FF9800",
    "unknown":      "#9E9E9E",
}


def render() -> None:
    """Render the ML Model Manager page."""
    _render_header()

    models = load_ml_model_info()

    render_section_header("🤖", "Registered Models", f"{len(models)} model(s) on disk")

    if not models:
        _render_empty_state()
        return

    # ── Model Cards ───────────────────────────────────────────────────────────
    for idx, model in enumerate(models):
        _render_model_card(model, idx)
        st.markdown("")

    st.markdown("---")
    render_section_header("⚡", "Management Actions", "Model lifecycle operations")
    _render_management_actions(models)


def _render_header() -> None:
    st.markdown(
        """
        <div class="hero-banner">
            <div class="hero-title">🤖 ML Model Manager</div>
            <div class="hero-subtitle">
                View all trained ML models, their performance metrics, and status.
                Models are used automatically during the analysis pipeline for 
                anomaly detection and attack classification.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_model_card(model: dict, idx: int = 0) -> None:
    """Render a card for a single ML model."""
    mtype = model.get("model_type", "unknown").lower()
    icon = _TYPE_ICONS.get(mtype, "🤖")
    color = _TYPE_COLORS.get(mtype, "#9E9E9E")
    is_active = model.get("is_active", True)
    name = model.get("model_name", model.get("model_key", "Unknown"))
    status_dot = "🟢" if is_active else "🔴"

    with st.expander(f"{icon} {name}  {status_dot}", expanded=False):
        col1, col2, col3 = st.columns([2, 2, 1])

        with col1:
            st.markdown(f"""
            <div style="margin-bottom:12px;">
                <span style="font-size:0.7rem;color:{color};text-transform:uppercase;
                             letter-spacing:0.1em;font-weight:600;
                             background:rgba(0,0,0,0.2);padding:2px 8px;border-radius:999px;
                             border:1px solid {color}40;">
                    {model.get('model_type', 'unknown').upper()}
                </span>
            </div>
            """, unsafe_allow_html=True)

            _kv_row("Model Key", model.get("model_key", "—"))
            _kv_row("Version", f"v{model.get('version', 1)}")
            _kv_row("Status", "Active ✅" if is_active else "Inactive ⛔")
            _kv_row("Trained At", str(model.get("trained_at", "—"))[:19].replace("T", " "))

        with col2:
            # Performance metrics
            st.markdown("**📊 Performance Metrics**")
            accuracy = model.get("accuracy", 0.0)
            f1 = model.get("f1_score", 0.0)
            precision = model.get("precision", 0.0)
            recall = model.get("recall", 0.0)
            n_samples = model.get("n_samples", 0)
            n_features = model.get("n_features", 0)

            if accuracy > 0:
                _kv_row("Accuracy", f"{accuracy:.2%}")
                _kv_row("F1 Score", f"{f1:.4f}")
                _kv_row("Precision", f"{precision:.4f}")
                _kv_row("Recall", f"{recall:.4f}")
                _kv_row("Training Samples", f"{n_samples:,}")
                _kv_row("Feature Count", f"{n_features}")
            else:
                st.caption("Metrics not available (model was loaded from file, not trained in this session).")

            if model.get("notes"):
                _kv_row("Notes", model.get("notes", ""))

        with col3:
            st.markdown("**Actions**")
            file_path = model.get("file_path", "")
            if file_path and Path(file_path).exists():
                size_kb = Path(file_path).stat().st_size / 1024
                st.caption(f"📁 {size_kb:.1f} KB")
                st.caption("✅ File exists")
            else:
                st.caption("⚠️ File not found")

            if st.button(
                "🔄 Reload",
                key=f"reload_{model.get('model_key', 'unknown')}_{idx}",
                use_container_width=True,
                help="Force reload this model from disk",
            ):
                _reload_model(model.get("model_key", ""))


def _render_management_actions(models: list) -> None:
    """Render global model management buttons."""
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button(
            "🔄 Reload All Models",
            use_container_width=True,
            key="btn_reload_all",
            help="Force all models to reload from disk on next pipeline run",
        ):
            try:
                from ml.model_manager import ModelManager
                mm = ModelManager()
                mm.reload_all()
                st.success("✅ All models reloaded.")
            except Exception as e:
                st.info(f"ℹ️ Model reload: {e}")

    with col2:
        if st.button(
            "🔍 Verify Model Files",
            use_container_width=True,
            key="btn_verify_models",
            help="Check that all model files exist and are readable",
        ):
            _verify_model_files(models)

    with col3:
        if st.button(
            "📊 Refresh Model Registry",
            use_container_width=True,
            key="btn_refresh_registry",
            help="Refresh model info from ModelManager",
        ):
            load_ml_model_info.clear()
            st.success("✅ Model registry refreshed.")
            st.rerun()

    # Display pipeline ML summary
    st.markdown("---")
    render_section_header("📈", "ML Pipeline Summary", "Statistics from last analysis run")
    _render_ml_pipeline_summary()


def _reload_model(model_key: str) -> None:
    """Attempt to reload a specific model."""
    try:
        from ml.model_manager import ModelManager
        mm = ModelManager()
        if hasattr(mm, "reload"):
            mm.reload(model_key)
        st.success(f"✅ Model '{model_key}' reloaded.")
        load_ml_model_info.clear()
    except Exception as e:
        st.info(f"ℹ️ Could not reload model '{model_key}': {e}")


def _verify_model_files(models: list) -> None:
    """Verify that all model files exist."""
    all_ok = True
    for m in models:
        fp = m.get("file_path", "")
        if fp:
            exists = Path(fp).exists()
            if exists:
                size = Path(fp).stat().st_size
                st.success(f"✅ {m.get('model_name', fp)} — {size / 1024:.1f} KB")
            else:
                st.error(f"❌ {m.get('model_name', fp)} — File not found: {fp}")
                all_ok = False
        else:
            st.warning(f"⚠️ {m.get('model_name', 'Unknown')} — No file path recorded")
    if all_ok:
        st.success("✅ All model files verified successfully.")


def _render_ml_pipeline_summary() -> None:
    """Show ML results from the last pipeline run (if available)."""
    result = st.session_state.get("pipeline_result")
    if not result:
        st.info("Run the analysis pipeline to see ML inference results here.")
        return

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔍 Anomalies Detected", result.get("ml_anomalies", 0))
    with col2:
        st.metric("🎯 Attacks Classified", result.get("ml_attacks", 0))
    with col3:
        st.metric("📦 Packets Analysed", f"{result.get('packets_processed', 0):,}")
    with col4:
        st.metric("⚡ Pipeline Duration", f"{result.get('elapsed_seconds', 0):.1f}s")


def _kv_row(label: str, value) -> None:
    """Render a key-value detail row."""
    st.markdown(
        f"""
        <div style="display:flex;justify-content:space-between;align-items:center;
                    padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.05);">
            <span style="color:#8B949E;font-size:0.8rem;">{label}</span>
            <span style="color:#E6EDF3;font-family:monospace;font-size:0.8rem;
                         font-weight:500;">{value}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_empty_state() -> None:
    """Render empty state when no models are found."""
    from utils.config import config
    models_dir = getattr(config.paths, "models_dir", Path("models"))

    st.markdown(
        f"""
        <div style="text-align:center;padding:60px 20px;
                    background:rgba(255,255,255,0.02);border-radius:16px;
                    border:1px dashed rgba(255,255,255,0.08);margin-top:32px;">
            <div style="font-size:3rem;margin-bottom:16px;">🤖</div>
            <div style="font-size:1.2rem;font-weight:600;color:#E6EDF3;margin-bottom:8px;">
                No Models Found
            </div>
            <div style="font-size:0.9rem;color:#8B949E;max-width:480px;margin:0 auto;">
                Expected model files in: <code>{models_dir}</code><br/>
                Models needed: <code>isolation_forest.pkl</code>,
                <code>random_forest.pkl</code>, <code>xgboost.pkl</code>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
