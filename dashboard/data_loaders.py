"""
data_loaders.py — Cached Data Access Layer
============================================
Enterprise SOC Dashboard

All data access goes through cached functions that call existing backend
modules. Prevents duplicate database queries and re-computation.

Author: Network Traffic Analyzer Project
Version: 7.5.0
Python: 3.11+
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Optional

import pandas as pd
import streamlit as st

from utils.config import config
from utils.logger import get_logger

log = get_logger(__name__)

# TTL for cached data (seconds)
CACHE_TTL = 5


def invalidate_all_caches() -> None:
    """
    Clear ALL st.cache_data and st.cache_resource caches.
    Call after the analysis pipeline completes so the dashboard
    picks up fresh data on the next render.
    """
    try:
        _get_traffic_stats.clear()
    except Exception:
        pass
    try:
        _get_protocol_analysis.clear()
    except Exception:
        pass
    try:
        _get_bandwidth_monitor.clear()
    except Exception:
        pass
    try:
        load_traffic_summary.clear()
    except Exception:
        pass
    try:
        _load_traffic_dataframe.clear()
    except Exception:
        pass
    try:
        load_protocol_distribution.clear()
    except Exception:
        pass
    try:
        load_bandwidth_summary.clear()
    except Exception:
        pass
    try:
        load_health_report.clear()
    except Exception:
        pass
    try:
        load_quality_report.clear()
    except Exception:
        pass
    try:
        load_alerts.clear()
    except Exception:
        pass
    try:
        load_alert_summary.clear()
    except Exception:
        pass
    try:
        load_alert_timeline.clear()
    except Exception:
        pass
    try:
        load_alert_trend.clear()
    except Exception:
        pass
    try:
        load_system_status.clear()
    except Exception:
        pass
    try:
        load_top_sources.clear()
    except Exception:
        pass
    try:
        load_top_destinations.clear()
    except Exception:
        pass
    try:
        load_attack_distribution.clear()
    except Exception:
        pass
    try:
        load_severity_distribution.clear()
    except Exception:
        pass
    try:
        load_packets_page.clear()
    except Exception:
        pass
    log.debug("All dashboard caches invalidated.")


# ──────────────────────────────────────────────────────────────────────────────
# DATABASE ACCESS
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_resource(show_spinner=False)
def _get_db():
    """Return the cached DatabaseManager singleton."""
    from database.db_manager import DatabaseManager
    db = DatabaseManager()
    db.initialise()
    return db


# ──────────────────────────────────────────────────────────────────────────────
# LOADED ANALYSIS ENGINES (shared across loaders)
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_resource(show_spinner=False)
def _get_traffic_stats():
    """Return a loaded TrafficStatistics instance."""
    from analysis.traffic_statistics import TrafficStatistics
    ts = TrafficStatistics()
    db = _get_db()
    try:
        ts.load_data(source="db", db_manager=db)
    except Exception:
        pass
    return ts


@st.cache_resource(show_spinner=False)
def _get_protocol_analysis():
    """Return a loaded ProtocolAnalysis instance."""
    from analysis.protocol_analysis import ProtocolAnalysis
    pa = ProtocolAnalysis()
    db = _get_db()
    try:
        pa.load_data(source="db", db_manager=db)
    except Exception:
        pass
    return pa


@st.cache_resource(show_spinner=False)
def _get_bandwidth_monitor():
    """Return a loaded BandwidthMonitor instance."""
    from analysis.bandwidth_monitor import BandwidthMonitor
    bm = BandwidthMonitor()
    db = _get_db()
    try:
        bm.load_data(source="db", db_manager=db)
    except Exception:
        pass
    return bm


# ──────────────────────────────────────────────────────────────────────────────
# TRAFFIC DATA
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_traffic_summary() -> dict[str, Any]:
    """Load traffic statistics summary from the backend."""
    try:
        ts = _get_traffic_stats()
        summary = ts.generate_summary()
        return {
            "total_packets": summary.basic.total_packets,
            "total_bytes": summary.basic.total_bytes,
            "packets_per_second": summary.basic.packets_per_second,
            "bytes_per_second": summary.basic.bytes_per_second,
            "capture_duration": summary.basic.capture_duration_seconds,
            "capture_start": summary.basic.capture_start,
            "capture_end": summary.basic.capture_end,
            "unique_src_ips": summary.ip.unique_src_ips,
            "unique_dst_ips": summary.ip.unique_dst_ips,
            "top_src_ips": summary.ip.top_src_ips,
            "top_dst_ips": summary.ip.top_dst_ips,
            "avg_packet_size": summary.packets.avg_packet_size,
            "max_packet_size": summary.packets.max_packet_size,
            "min_packet_size": summary.packets.min_packet_size,
        }
    except Exception as e:
        log.debug("Traffic summary load failed: %s", e)
        return _empty_traffic_summary()


@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def _load_traffic_dataframe() -> Optional[pd.DataFrame]:
    """Load traffic records from DB as a DataFrame."""
    db = _get_db()
    count = db.get_traffic_count()
    if count == 0:
        return None
    rows = db.fetch_recent_traffic(limit=min(count, 10000))
    if not rows:
        return None
    return pd.DataFrame(rows)


def _empty_traffic_summary() -> dict[str, Any]:
    """Return empty traffic summary when no data is available."""
    return {
        "total_packets": 0,
        "total_bytes": 0,
        "packets_per_second": 0.0,
        "bytes_per_second": 0.0,
        "capture_duration": 0.0,
        "capture_start": "",
        "capture_end": "",
        "unique_src_ips": 0,
        "unique_dst_ips": 0,
        "top_src_ips": [],
        "top_dst_ips": [],
        "avg_packet_size": 0.0,
        "max_packet_size": 0,
        "min_packet_size": 0,
    }


# ──────────────────────────────────────────────────────────────────────────────
# PROTOCOL DATA
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_protocol_distribution() -> pd.DataFrame:
    """Load protocol distribution as a DataFrame for charting."""
    try:
        pa = _get_protocol_analysis()
        report = pa.generate_protocol_report()
        if not report.all_protocols:
            return pd.DataFrame(columns=["protocol", "count", "percentage"])
        rows = [
            {"protocol": e.protocol, "count": e.packet_count, "percentage": e.percentage}
            for e in report.all_protocols
        ]
        return pd.DataFrame(rows)
    except Exception as e:
        log.debug("Protocol distribution load failed: %s", e)
        return pd.DataFrame(columns=["protocol", "count", "percentage"])


# ──────────────────────────────────────────────────────────────────────────────
# BANDWIDTH DATA
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_bandwidth_summary() -> dict[str, Any]:
    """Load bandwidth monitoring summary."""
    try:
        bm = _get_bandwidth_monitor()
        report = bm.generate_bandwidth_report()
        # Extract utilisation if available, else default to 0
        util_pct = 0.0
        if hasattr(report, "utilisation_percent"):
            util_pct = report.utilisation_percent
        elif hasattr(report, "intervals") and report.intervals:
            # Try to compute from metrics
            if hasattr(report, "metrics"):
                util_pct = getattr(report.metrics, "utilisation_percent", 0)
        return {
            "current_bps": getattr(report, "current_bps", 0) or 0,
            "peak_bps": getattr(report, "peak_bps", 0) or 0,
            "avg_bps": getattr(report, "avg_bps", 0) or 0,
            "utilisation_pct": util_pct,
        }
    except Exception as e:
        log.debug("Bandwidth summary load failed: %s", e)
        return {"current_bps": 0, "peak_bps": 0, "avg_bps": 0, "utilisation_pct": 0}


# ──────────────────────────────────────────────────────────────────────────────
# HEALTH & QUALITY DATA
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_health_report() -> dict[str, Any]:
    """Load network health report."""
    try:
        from analysis.health_monitor import NetworkHealthMonitor
        hm = NetworkHealthMonitor()
        ts = _get_traffic_stats()
        pa = _get_protocol_analysis()
        bm = _get_bandwidth_monitor()
        report = hm.generate_health_report(
            traffic_stats=ts,
            protocol_analysis=pa,
            bandwidth_monitor=bm,
        )
        return {
            "health_score": report.health_score,
            "status": report.status,
            "components": [
                {"name": c.name, "score": c.score, "weight": c.weight}
                for c in report.components
            ] if hasattr(report, "components") else [],
            "issues": report.issues if hasattr(report, "issues") else [],
            "recommendations": report.recommendations if hasattr(report, "recommendations") else [],
        }
    except Exception as e:
        log.debug("Health report load failed: %s", e)
        return {"health_score": 0, "status": "Error", "components": [], "issues": []}


@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_quality_report() -> dict[str, Any]:
    """Load network quality report."""
    try:
        from analysis.network_quality import NetworkQualityAnalyzer
        nq = NetworkQualityAnalyzer()
        ts = _get_traffic_stats()
        pa = _get_protocol_analysis()
        bm = _get_bandwidth_monitor()
        report = nq.generate_quality_report(
            traffic_stats=ts,
            protocol_analysis=pa,
            bandwidth_monitor=bm,
        )
        return {
            "quality_index": report.quality_index,
            "quality": report.quality,
            "dimensions": [
                {"name": d.name, "score": d.score, "quality": d.quality}
                for d in report.dimensions
            ] if hasattr(report, "dimensions") else [],
        }
    except Exception as e:
        log.debug("Quality report load failed: %s", e)
        return {"quality_index": 0, "quality": "Error", "dimensions": []}


# ──────────────────────────────────────────────────────────────────────────────
# ALERT DATA
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_alerts(
    limit: int = 100,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
) -> pd.DataFrame:
    """Load alerts from database as a DataFrame."""
    db = _get_db()
    rows = db.fetch_alerts(limit=limit, severity=severity, alert_type=alert_type)
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_alert_summary() -> dict[str, Any]:
    """Load alert summary statistics."""
    db = _get_db()
    all_alerts = db.fetch_alerts(limit=10000)
    if not all_alerts:
        return {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "attack_counts": {}, "severity_dist": {},
        }
    df = pd.DataFrame(all_alerts)
    severity_counts = df["severity"].value_counts().to_dict() if "severity" in df.columns else {}
    attack_counts = df["alert_type"].value_counts().to_dict() if "alert_type" in df.columns else {}
    return {
        "total": len(df),
        "critical": severity_counts.get("CRITICAL", 0),
        "high": severity_counts.get("HIGH", 0),
        "medium": severity_counts.get("MEDIUM", 0),
        "low": severity_counts.get("LOW", 0),
        "attack_counts": attack_counts,
        "severity_dist": severity_counts,
    }


@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_alert_timeline() -> pd.DataFrame:
    """Load recent alerts ordered by timestamp (newest first) for timeline."""
    db = _get_db()
    rows = db.fetch_alerts(limit=50)
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        df = df.sort_values("timestamp", ascending=False)
    return df


# ──────────────────────────────────────────────────────────────────────────────
# SYSTEM STATUS
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_system_status() -> dict[str, Any]:
    """Load system status information."""
    import sys
    import os

    status = {
        "database_status": "Disconnected",
        "database_records": 0,
        "database_size": "0 KB",
        "packet_capture_status": "Inactive",
        "rule_engine_status": "Active",
        "ml_model_status": "Not Loaded",
        "app_version": config.meta.version,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "app_uptime": _get_uptime(),
    }

    # Database
    try:
        db = _get_db()
        health = db.health_check()
        status["database_status"] = health.get("status", "unknown").title()
        status["database_records"] = health.get("traffic_records", 0)
        status["total_alerts"] = health.get("total_alerts", 0)
        size_bytes = health.get("db_size_bytes", 0)
        if size_bytes > 1_048_576:
            status["database_size"] = f"{size_bytes / 1_048_576:.1f} MB"
        elif size_bytes > 1024:
            status["database_size"] = f"{size_bytes / 1024:.1f} KB"
        else:
            status["database_size"] = f"{size_bytes} B"
    except Exception:
        pass

    # Memory & CPU (optional)
    try:
        import psutil
        process = psutil.Process(os.getpid())
        mem = process.memory_info()
        status["memory_mb"] = round(mem.rss / 1_048_576, 1)
        status["cpu_percent"] = process.cpu_percent(interval=0.1)
    except ImportError:
        status["memory_mb"] = None
        status["cpu_percent"] = None

    # ML models
    try:
        from pathlib import Path
        models_dir = config.paths.models_dir if hasattr(config.paths, "models_dir") else Path("models")
        if models_dir.exists():
            model_files = list(models_dir.glob("*.joblib")) + list(models_dir.glob("*.pkl"))
            if model_files:
                status["ml_model_status"] = f"Loaded ({len(model_files)} models)"
    except Exception:
        pass

    return status


def _get_uptime() -> str:
    """Calculate application uptime from session state."""
    if "app_start_time" not in st.session_state:
        st.session_state.app_start_time = time.time()
    elapsed = time.time() - st.session_state.app_start_time
    hours = int(elapsed // 3600)
    minutes = int((elapsed % 3600) // 60)
    seconds = int(elapsed % 60)
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


# ──────────────────────────────────────────────────────────────────────────────
# CHART-READY DATA HELPERS
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_top_sources(n: int = 10) -> pd.DataFrame:
    """Load top N source IPs by packet count."""
    summary = load_traffic_summary()
    top = summary.get("top_src_ips", [])
    if not top:
        return pd.DataFrame(columns=["ip", "packets"])
    rows = [{"ip": ip, "packets": count} for ip, count in top[:n]]
    return pd.DataFrame(rows)


@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_top_destinations(n: int = 10) -> pd.DataFrame:
    """Load top N destination IPs by packet count."""
    summary = load_traffic_summary()
    top = summary.get("top_dst_ips", [])
    if not top:
        return pd.DataFrame(columns=["ip", "packets"])
    rows = [{"ip": ip, "packets": count} for ip, count in top[:n]]
    return pd.DataFrame(rows)


@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_attack_distribution() -> pd.DataFrame:
    """Load attack type distribution for pie/donut chart."""
    summary = load_alert_summary()
    counts = summary.get("attack_counts", {})
    if not counts:
        return pd.DataFrame(columns=["attack_type", "count"])
    rows = [{"attack_type": k, "count": v} for k, v in counts.items()]
    return pd.DataFrame(rows).sort_values("count", ascending=False)


@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_severity_distribution() -> pd.DataFrame:
    """Load severity distribution for charting."""
    summary = load_alert_summary()
    dist = summary.get("severity_dist", {})
    if not dist:
        return pd.DataFrame(columns=["severity", "count"])
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    rows = [{"severity": s, "count": dist.get(s, 0)} for s in order]
    return pd.DataFrame(rows)


@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_alert_trend() -> pd.DataFrame:
    """Load alert trend grouped by time bucket for bar chart."""
    df = load_alerts(limit=10000)
    if df.empty or "timestamp" not in df.columns:
        return pd.DataFrame(columns=["time_bucket", "count"])
    try:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["time_bucket"] = df["timestamp"].dt.floor("5min")
        trend = df.groupby("time_bucket").size().reset_index(name="count")
        return trend.sort_values("time_bucket")
    except Exception:
        return pd.DataFrame(columns=["time_bucket", "count"])


# ──────────────────────────────────────────────────────────────────────────────
# PACKET EXPLORER DATA
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def load_packets_page(
    page: int = 1,
    page_size: int = 100,
    src_ip_filter: Optional[str] = None,
    dst_ip_filter: Optional[str] = None,
    protocol_filter: Optional[str] = None,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
) -> tuple[pd.DataFrame, int]:
    """
    Load a paginated page of traffic records for the Packet Explorer.

    Returns:
        (DataFrame of packets, total_record_count)
    """
    db = _get_db()
    try:
        total = db.get_traffic_count()
        offset = (page - 1) * page_size
        rows = db.fetch_recent_traffic(limit=page_size + offset)
        if not rows:
            return pd.DataFrame(), 0

        df = pd.DataFrame(rows) if isinstance(rows[0], dict) else _dataclass_list_to_df(rows)

        # Apply filters
        if src_ip_filter and "src_ip" in df.columns:
            df = df[df["src_ip"].astype(str).str.contains(src_ip_filter, case=False, na=False)]
        if dst_ip_filter and "dst_ip" in df.columns:
            df = df[df["dst_ip"].astype(str).str.contains(dst_ip_filter, case=False, na=False)]
        if protocol_filter and protocol_filter != "All" and "protocol" in df.columns:
            df = df[df["protocol"].astype(str).str.upper() == protocol_filter.upper()]
        if min_length is not None and "packet_length" in df.columns:
            df = df[pd.to_numeric(df["packet_length"], errors="coerce").fillna(0) >= min_length]
        if max_length is not None and "packet_length" in df.columns:
            df = df[pd.to_numeric(df["packet_length"], errors="coerce").fillna(0) <= max_length]

        # Return the requested page slice
        df = df.iloc[offset:offset + page_size].reset_index(drop=True)
        return df, total
    except Exception as e:
        log.debug("load_packets_page error: %s", e)
        return pd.DataFrame(), 0


def _dataclass_list_to_df(rows: list) -> pd.DataFrame:
    """Convert a list of dataclasses or namedtuples to DataFrame."""
    try:
        from dataclasses import asdict
        return pd.DataFrame([asdict(r) for r in rows])
    except Exception:
        try:
            return pd.DataFrame([vars(r) for r in rows])
        except Exception:
            return pd.DataFrame()


# ──────────────────────────────────────────────────────────────────────────────
# ML MODEL INFO
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=30, show_spinner=False)
def load_ml_model_info() -> list[dict[str, Any]]:
    """
    Load metadata for all available ML models from the ModelManager registry.

    Returns:
        List of dicts with model metadata.
    """
    try:
        from ml.model_manager import ModelManager
        mm = ModelManager()
        models = mm.list_models()
        result = []
        for m in models:
            result.append({
                "model_key": m.model_key,
                "model_name": m.model_name,
                "model_type": m.model_type,
                "version": m.version,
                "is_active": m.is_active,
                "trained_at": m.trained_at,
                "accuracy": m.accuracy,
                "f1_score": m.f1_score,
                "precision": m.precision,
                "recall": m.recall,
                "n_samples": m.n_samples,
                "n_features": m.n_features,
                "file_path": m.file_path,
                "notes": m.notes,
            })
        return result
    except Exception as e:
        log.debug("load_ml_model_info error: %s", e)
        # Fallback: scan models directory for .pkl files
        result = []
        try:
            models_dir = config.paths.models_dir
            canonical = {
                "isolation_forest.pkl": ("isolation_forest", "Isolation Forest", "anomaly"),
                "random_forest.pkl": ("random_forest", "Random Forest", "classifier"),
                "xgboost.pkl": ("xgboost", "XGBoost", "classifier"),
                "preprocessor_scaler.pkl": ("preprocessor", "Preprocessor Scaler", "preprocessor"),
                "label_encoder.pkl": ("label_encoder", "Label Encoder", "preprocessor"),
            }
            for fname, (key, name, mtype) in canonical.items():
                fpath = models_dir / fname
                if fpath.exists():
                    stat = fpath.stat()
                    import datetime as _dt
                    result.append({
                        "model_key": key,
                        "model_name": name,
                        "model_type": mtype,
                        "version": 1,
                        "is_active": True,
                        "trained_at": _dt.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "accuracy": 0.0,
                        "f1_score": 0.0,
                        "precision": 0.0,
                        "recall": 0.0,
                        "n_samples": 0,
                        "n_features": 0,
                        "file_path": str(fpath),
                        "notes": f"File size: {stat.st_size / 1024:.1f} KB",
                    })
        except Exception:
            pass
        return result


# ──────────────────────────────────────────────────────────────────────────────
# SYSTEM LOG VIEWER
# ──────────────────────────────────────────────────────────────────────────────

def load_recent_log_lines(n: int = 100) -> list[str]:
    """
    Load the last N lines from the application log file.

    Returns:
        List of log line strings (newest first).
    """
    try:
        log_path = config.paths.app_log_path
        if not log_path.exists():
            return ["Log file not found."]
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return [l.rstrip() for l in lines[-n:]][::-1]
    except Exception as e:
        return [f"Could not read log file: {e}"]
