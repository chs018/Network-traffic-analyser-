"""
pipeline.py — End-to-End Analysis Pipeline Orchestrator
=========================================================
Network Traffic Analysis and Intrusion Detection System

The PipelineOrchestrator is the central integration engine that connects
every backend module into a single, cohesive workflow:

  PCAP File → Validate → Parse → Extract Features → Traffic Stats →
  Protocol Analysis → Bandwidth Monitor → Health Report →
  Rule Engine (4 detectors) → ML Inference → Alert Ingestion →
  Cache Invalidation → Dashboard Refresh

Progress is reported via st.session_state keys and a real-time
st.status() container, making the UI feel responsive throughout.

Author: Network Traffic Analyzer Project
Version: 7.5.0
Python: 3.11+
"""

from __future__ import annotations

import time
import uuid
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import streamlit as st

from utils.config import config
from utils.logger import get_logger

log = get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# PIPELINE RESULT DATACLASS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PipelineResult:
    """Summary of a completed pipeline run."""

    success: bool = False
    run_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    pcap_file: str = ""
    packets_processed: int = 0
    records_inserted: int = 0
    alerts_generated: int = 0
    ml_anomalies: int = 0
    ml_attacks: int = 0
    elapsed_seconds: float = 0.0
    highest_severity: str = "NONE"
    error_message: str = ""
    completed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    step_results: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "run_id": self.run_id,
            "pcap_file": self.pcap_file,
            "packets_processed": self.packets_processed,
            "records_inserted": self.records_inserted,
            "alerts_generated": self.alerts_generated,
            "ml_anomalies": self.ml_anomalies,
            "ml_attacks": self.ml_attacks,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "highest_severity": self.highest_severity,
            "error_message": self.error_message,
            "completed_at": self.completed_at,
        }


# ──────────────────────────────────────────────────────────────────────────────
# PIPELINE ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────

class PipelineOrchestrator:
    """
    End-to-end analysis pipeline that integrates all 7 phases.

    Usage (inside Streamlit):
        orch = PipelineOrchestrator()
        result = orch.run(pcap_path=Path("data/raw/capture.pcap"),
                          status_container=st.status("Running..."))
    """

    # Step names in order
    STEPS = [
        "validate",
        "parse",
        "extract",
        "traffic_stats",
        "protocol_analysis",
        "bandwidth_monitor",
        "health_report",
        "rule_engine",
        "ml_inference",
        "persist_alerts",
        "invalidate_caches",
    ]

    STEP_LABELS = {
        "validate":          "🔍 Validating PCAP file",
        "parse":             "📦 Parsing packets",
        "extract":           "⚙️  Extracting features",
        "traffic_stats":     "📊 Computing traffic statistics",
        "protocol_analysis": "📋 Analysing protocols",
        "bandwidth_monitor": "📡 Monitoring bandwidth",
        "health_report":     "🏥 Generating health report",
        "rule_engine":       "🔎 Running rule-based detection",
        "ml_inference":      "🤖 Running ML inference",
        "persist_alerts":    "💾 Persisting alerts",
        "invalidate_caches": "🔄 Refreshing dashboard",
    }

    def __init__(self) -> None:
        self._stop_requested = False

    def stop(self) -> None:
        """Request the pipeline to stop at the next safe checkpoint."""
        self._stop_requested = True

    # ── Main Entry Point ──────────────────────────────────────────────────────

    def run(
        self,
        pcap_path: Path,
        status_container=None,
        progress_bar=None,
    ) -> PipelineResult:
        """
        Execute the full analysis pipeline synchronously.

        Args:
            pcap_path:        Path to the .pcap / .pcapng file.
            status_container: Optional st.status() container for live updates.
            progress_bar:     Optional st.progress() element.

        Returns:
            PipelineResult with summary of the completed run.
        """
        self._stop_requested = False
        result = PipelineResult(pcap_file=pcap_path.name)
        t_start = time.perf_counter()

        # Session state tracking
        _set_state("pipeline_running", True)
        _set_state("pipeline_phase", "Starting…")
        _set_state("pipeline_progress", 0.0)
        _set_state("pipeline_error", None)
        _set_state("pipeline_result", None)

        log.info("Pipeline started for: %s", pcap_path)

        try:
            # ── Step 1: Validate ──────────────────────────────────────────────
            if not self._update_step("validate", 1, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            pcap_valid, packet_count_estimate = self._step_validate(pcap_path)
            if not pcap_valid:
                return self._abort(result, f"Invalid PCAP file: {pcap_path.name}", t_start)

            result.step_results["validate"] = {"ok": True, "estimated_packets": packet_count_estimate}

            # ── Step 2: Parse ─────────────────────────────────────────────────
            if not self._update_step("parse", 2, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            packet_records = self._step_parse(pcap_path, status_container)
            result.packets_processed = len(packet_records)
            _set_state("pipeline_packets_done", result.packets_processed)
            result.step_results["parse"] = {"packets": result.packets_processed}
            log.info("Pipeline: parsed %d packet records.", result.packets_processed)

            if result.packets_processed == 0:
                return self._abort(result, "No packets were parsed from the PCAP file.", t_start)

            # ── Step 3: Extract Features ──────────────────────────────────────
            if not self._update_step("extract", 3, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            df_traffic, records_inserted = self._step_extract(packet_records, status_container)
            result.records_inserted = records_inserted
            result.step_results["extract"] = {"records_inserted": records_inserted}

            # ── Step 4: Traffic Statistics ────────────────────────────────────
            if not self._update_step("traffic_stats", 4, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            traffic_stats = self._step_traffic_stats()
            result.step_results["traffic_stats"] = {"ok": traffic_stats is not None}

            # ── Step 5: Protocol Analysis ─────────────────────────────────────
            if not self._update_step("protocol_analysis", 5, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            protocol_analysis = self._step_protocol_analysis()
            result.step_results["protocol_analysis"] = {"ok": protocol_analysis is not None}

            # ── Step 6: Bandwidth Monitor ─────────────────────────────────────
            if not self._update_step("bandwidth_monitor", 6, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            bandwidth_monitor = self._step_bandwidth_monitor()
            result.step_results["bandwidth_monitor"] = {"ok": bandwidth_monitor is not None}

            # ── Step 7: Health Report ─────────────────────────────────────────
            if not self._update_step("health_report", 7, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            health_report = self._step_health_report(traffic_stats, protocol_analysis, bandwidth_monitor)
            result.step_results["health_report"] = {
                "health_score": getattr(health_report, "health_score", 0)
            }

            # ── Step 8: Rule Engine ───────────────────────────────────────────
            if not self._update_step("rule_engine", 8, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            rule_alerts = self._step_rule_engine(
                df_traffic, traffic_stats, protocol_analysis, bandwidth_monitor, health_report
            )
            result.step_results["rule_engine"] = {"alerts": len(rule_alerts)}
            log.info("Pipeline: rule engine produced %d alerts.", len(rule_alerts))

            # ── Step 9: ML Inference ──────────────────────────────────────────
            if not self._update_step("ml_inference", 9, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            ml_alerts, ml_anomalies, ml_attacks = self._step_ml_inference(df_traffic)
            result.ml_anomalies = ml_anomalies
            result.ml_attacks = ml_attacks
            result.step_results["ml_inference"] = {
                "anomalies": ml_anomalies,
                "attacks": ml_attacks,
                "alerts": len(ml_alerts),
            }
            log.info("Pipeline: ML inference — %d anomalies, %d attacks.", ml_anomalies, ml_attacks)

            # ── Step 10: Persist Alerts ───────────────────────────────────────
            if not self._update_step("persist_alerts", 10, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            all_alerts = rule_alerts + ml_alerts
            stored_count = self._step_persist_alerts(all_alerts)
            result.alerts_generated = stored_count

            # Determine highest severity
            if all_alerts:
                try:
                    from detection.rule_engine import RuleEngine
                    engine = RuleEngine()
                    result.highest_severity = engine.get_highest_severity(all_alerts)
                except Exception:
                    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
                    result.highest_severity = max(
                        (a.severity for a in all_alerts),
                        key=lambda s: sev_order.get(s, 0),
                        default="NONE",
                    )

            # ── Step 11: Invalidate Caches ────────────────────────────────────
            if not self._update_step("invalidate_caches", 11, status_container, progress_bar):
                return self._abort(result, "Stopped by user", t_start)

            self._step_invalidate_caches()

            # ── Done ──────────────────────────────────────────────────────────
            result.elapsed_seconds = time.perf_counter() - t_start
            result.success = True

            _set_state("pipeline_running", False)
            _set_state("pipeline_progress", 1.0)
            _set_state("pipeline_phase", "Complete ✅")
            _set_state("pipeline_result", result.to_dict())
            _set_state("analysis_complete", True)
            _set_state("pipeline_elapsed", result.elapsed_seconds)

            if status_container:
                try:
                    status_container.update(label="✅ Analysis complete!", state="complete", expanded=False)
                except Exception:
                    pass

            if progress_bar:
                try:
                    progress_bar.progress(1.0)
                except Exception:
                    pass

            log.info(
                "Pipeline complete in %.2fs: %d packets, %d alerts (highest: %s).",
                result.elapsed_seconds, result.packets_processed,
                result.alerts_generated, result.highest_severity,
            )
            return result

        except Exception as exc:
            tb = traceback.format_exc()
            log.error("Pipeline error: %s\n%s", exc, tb)
            return self._abort(result, str(exc), t_start)

    # ── Demo Mode ─────────────────────────────────────────────────────────────

    def run_demo(self, status_container=None, progress_bar=None) -> PipelineResult:
        """
        Generate synthetic traffic data and run the full pipeline.

        Used when no PCAP file is available (demo mode).
        Injects synthetic packet records directly into the database.
        """
        log.info("Pipeline: running in DEMO mode.")

        result = PipelineResult(pcap_file="demo_synthetic_traffic.pcap")
        t_start = time.perf_counter()

        _set_state("pipeline_running", True)
        _set_state("pipeline_phase", "Generating demo data…")
        _set_state("pipeline_progress", 0.0)
        _set_state("pipeline_error", None)
        _set_state("pipeline_result", None)

        try:
            if status_container:
                try:
                    status_container.write("🎭 Generating synthetic network traffic data…")
                except Exception:
                    pass

            # Generate synthetic data
            df_traffic, records_inserted = self._generate_demo_data()
            result.packets_processed = records_inserted
            result.records_inserted = records_inserted
            _set_state("pipeline_packets_done", records_inserted)

            if progress_bar:
                try:
                    progress_bar.progress(0.3)
                except Exception:
                    pass

            # Run analysis on synthetic data
            traffic_stats = self._step_traffic_stats()
            protocol_analysis = self._step_protocol_analysis()
            bandwidth_monitor = self._step_bandwidth_monitor()
            health_report = self._step_health_report(traffic_stats, protocol_analysis, bandwidth_monitor)

            if progress_bar:
                try:
                    progress_bar.progress(0.6)
                except Exception:
                    pass

            rule_alerts = self._step_rule_engine(
                df_traffic, traffic_stats, protocol_analysis, bandwidth_monitor, health_report
            )
            ml_alerts, ml_anomalies, ml_attacks = self._step_ml_inference(df_traffic)

            if progress_bar:
                try:
                    progress_bar.progress(0.85)
                except Exception:
                    pass

            all_alerts = rule_alerts + ml_alerts
            stored_count = self._step_persist_alerts(all_alerts)
            result.alerts_generated = stored_count
            result.ml_anomalies = ml_anomalies
            result.ml_attacks = ml_attacks

            self._step_invalidate_caches()

            result.elapsed_seconds = time.perf_counter() - t_start
            result.success = True

            _set_state("pipeline_running", False)
            _set_state("pipeline_progress", 1.0)
            _set_state("pipeline_phase", "Demo complete ✅")
            _set_state("pipeline_result", result.to_dict())
            _set_state("analysis_complete", True)
            _set_state("pipeline_elapsed", result.elapsed_seconds)
            _set_state("demo_mode_active", True)

            if status_container:
                try:
                    status_container.update(label="✅ Demo complete!", state="complete", expanded=False)
                except Exception:
                    pass

            if progress_bar:
                try:
                    progress_bar.progress(1.0)
                except Exception:
                    pass

            log.info("Demo pipeline complete in %.2fs.", result.elapsed_seconds)
            return result

        except Exception as exc:
            tb = traceback.format_exc()
            log.error("Demo pipeline error: %s\n%s", exc, tb)
            return self._abort(result, str(exc), t_start)

    # ── Step Implementations ──────────────────────────────────────────────────

    def _step_validate(self, pcap_path: Path) -> tuple[bool, int]:
        """Validate the PCAP file exists and is readable."""
        if not pcap_path.exists():
            return False, 0
        if pcap_path.stat().st_size < 24:  # PCAP global header is 24 bytes
            return False, 0
        # Rough packet count estimate from file size
        size_kb = pcap_path.stat().st_size / 1024
        estimate = max(1, int(size_kb / 0.1))  # ~100 bytes/packet average
        return True, estimate

    def _step_parse(self, pcap_path: Path, status_container=None) -> list:
        """Parse PCAP using PcapReader + PacketParser."""
        from capture.pcap_reader import PcapReader
        from capture.packet_parser import PacketParser

        records = []
        reader = PcapReader(pcap_path)
        parser = PacketParser()

        try:
            for pkt in reader.iterate_packets():
                if self._stop_requested:
                    break
                try:
                    record = parser.parse_packet(pkt)
                    if record is not None:
                        records.append(record)
                        if len(records) % 1000 == 0:
                            _set_state("pipeline_packets_done", len(records))
                            if status_container:
                                try:
                                    status_container.write(f"  Parsed {len(records):,} packets…")
                                except Exception:
                                    pass
                except Exception as pkt_exc:
                    log.debug("Packet parse error (skipping): %s", pkt_exc)
        except Exception as exc:
            log.warning("PcapReader error: %s — will try fallback.", exc)
        finally:
            reader.close()

        return records

    def _step_extract(self, packet_records: list, status_container=None) -> tuple:
        """Extract features and persist to database."""
        from capture.feature_extractor import FeatureExtractor
        import pandas as pd

        fe = FeatureExtractor()
        db = _get_db()

        try:
            # Use feature extractor's pipeline
            if hasattr(fe, "run_pipeline"):
                result = fe.run_pipeline(packet_records)
                if hasattr(result, "traffic_records"):
                    records_inserted = len(result.traffic_records)
                elif hasattr(result, "records_inserted"):
                    records_inserted = result.records_inserted
                else:
                    records_inserted = len(packet_records)
            else:
                # Manual extraction fallback
                records_inserted = 0
                from database.db_manager import TrafficRecord
                from utils.helpers import utc_now_iso
                for pr in packet_records:
                    try:
                        tr = TrafficRecord(
                            timestamp=getattr(pr, "timestamp", utc_now_iso()),
                            src_ip=getattr(pr, "src_ip", "0.0.0.0"),
                            dst_ip=getattr(pr, "dst_ip", "0.0.0.0"),
                            src_port=getattr(pr, "src_port", 0),
                            dst_port=getattr(pr, "dst_port", 0),
                            protocol=getattr(pr, "protocol", "UNKNOWN"),
                            packet_length=getattr(pr, "packet_length", 0),
                            ttl=getattr(pr, "ttl", 0),
                            tcp_flags=str(getattr(pr, "tcp_flags", "")),
                            payload_size=getattr(pr, "payload_size", 0),
                        )
                        db.insert_traffic_record(tr)
                        records_inserted += 1
                    except Exception:
                        pass

        except Exception as exc:
            log.warning("Feature extraction error: %s — will fall back to direct insertion.", exc)
            records_inserted = self._fallback_insert(packet_records, db)

        # Build DataFrame from DB for downstream steps
        try:
            rows = db.fetch_recent_traffic(limit=min(records_inserted + 1000, 50000))
            df_traffic = _rows_to_df(rows) if rows else None
        except Exception:
            df_traffic = None

        if df_traffic is None:
            import pandas as pd
            df_traffic = pd.DataFrame()

        return df_traffic, records_inserted

    def _fallback_insert(self, packet_records: list, db) -> int:
        """Direct DB insertion fallback when feature extractor fails."""
        from utils.helpers import utc_now_iso
        count = 0
        for pr in packet_records:
            try:
                from database.db_manager import TrafficRecord
                tr = TrafficRecord(
                    timestamp=getattr(pr, "timestamp", utc_now_iso()),
                    src_ip=getattr(pr, "src_ip", "0.0.0.0"),
                    dst_ip=getattr(pr, "dst_ip", "0.0.0.0"),
                    src_port=getattr(pr, "src_port", 0),
                    dst_port=getattr(pr, "dst_port", 0),
                    protocol=getattr(pr, "protocol", "UNKNOWN"),
                    packet_length=getattr(pr, "packet_length", 0),
                    ttl=getattr(pr, "ttl", 0),
                    tcp_flags=str(getattr(pr, "tcp_flags", "")),
                    payload_size=getattr(pr, "payload_size", 0),
                )
                db.insert_traffic_record(tr)
                count += 1
            except Exception:
                pass
        return count

    def _step_traffic_stats(self):
        """Reload traffic statistics from DB."""
        try:
            from analysis.traffic_statistics import TrafficStatistics
            ts = TrafficStatistics()
            db = _get_db()
            ts.load_data(source="db", db_manager=db)
            return ts
        except Exception as exc:
            log.warning("Traffic stats step error: %s", exc)
            return None

    def _step_protocol_analysis(self):
        """Reload protocol analysis from DB."""
        try:
            from analysis.protocol_analysis import ProtocolAnalysis
            pa = ProtocolAnalysis()
            db = _get_db()
            pa.load_data(source="db", db_manager=db)
            return pa
        except Exception as exc:
            log.warning("Protocol analysis step error: %s", exc)
            return None

    def _step_bandwidth_monitor(self):
        """Reload bandwidth monitor from DB."""
        try:
            from analysis.bandwidth_monitor import BandwidthMonitor
            bm = BandwidthMonitor()
            db = _get_db()
            bm.load_data(source="db", db_manager=db)
            return bm
        except Exception as exc:
            log.warning("Bandwidth monitor step error: %s", exc)
            return None

    def _step_health_report(self, traffic_stats, protocol_analysis, bandwidth_monitor):
        """Generate network health report."""
        try:
            from analysis.health_monitor import NetworkHealthMonitor
            hm = NetworkHealthMonitor()
            report = hm.generate_health_report(
                traffic_stats=traffic_stats,
                protocol_analysis=protocol_analysis,
                bandwidth_monitor=bandwidth_monitor,
            )
            return report
        except Exception as exc:
            log.warning("Health report step error: %s", exc)
            return None

    def _step_rule_engine(
        self, df_traffic, traffic_stats, protocol_analysis, bandwidth_monitor, health_report
    ) -> list:
        """Run all four rule-based detectors via the RuleEngine."""
        import pandas as pd
        if df_traffic is None or (isinstance(df_traffic, pd.DataFrame) and df_traffic.empty):
            return []

        try:
            from detection.rule_engine import RuleEngine
            from detection.ddos_detector import DDoSDetector
            from detection.portscan_detector import PortScanDetector
            from detection.bruteforce_detector import BruteForceDetector
            from detection.synflood_detector import SYNFloodDetector

            db = _get_db()
            engine = RuleEngine(db_manager=db, dedup_window_seconds=60)
            engine.register(DDoSDetector())
            engine.register(PortScanDetector())
            engine.register(BruteForceDetector())
            engine.register(SYNFloodDetector())

            alerts = engine.run_detection(
                df=df_traffic,
                traffic_stats=traffic_stats,
                protocol_analysis=protocol_analysis,
                bandwidth_monitor=bandwidth_monitor,
                health_report=health_report,
            )
            return alerts
        except ImportError as e:
            log.warning("Rule engine import error: %s", e)
            return self._rule_engine_fallback(df_traffic)
        except Exception as exc:
            log.warning("Rule engine step error: %s", exc)
            return []

    def _rule_engine_fallback(self, df_traffic) -> list:
        """Try detectors individually if the full engine fails."""
        alerts = []
        import pandas as pd
        if df_traffic is None or (isinstance(df_traffic, pd.DataFrame) and df_traffic.empty):
            return []

        detector_classes = []
        for cls_name, mod_name in [
            ("DDoSDetector", "detection.ddos_detector"),
            ("PortScanDetector", "detection.portscan_detector"),
            ("BruteForceDetector", "detection.bruteforce_detector"),
            ("SYNFloodDetector", "detection.synflood_detector"),
        ]:
            try:
                import importlib
                mod = importlib.import_module(mod_name)
                cls = getattr(mod, cls_name)
                detector = cls()
                new_alerts = detector.detect(df=df_traffic)
                alerts.extend(new_alerts)
            except Exception as e:
                log.debug("Fallback detector %s error: %s", cls_name, e)

        return alerts

    def _step_ml_inference(self, df_traffic) -> tuple[list, int, int]:
        """Run ML anomaly detection and attack classification."""
        import pandas as pd
        if df_traffic is None or (isinstance(df_traffic, pd.DataFrame) and df_traffic.empty):
            return [], 0, 0

        ml_alerts = []
        ml_anomalies = 0
        ml_attacks = 0

        try:
            from ml.feature_engineering import FeatureEngineer
            from ml.anomaly_detector import AnomalyDetector
            from ml.attack_classifier import AttackClassifier
            from detection.rule_engine import SecurityAlert
            from utils.helpers import utc_now_iso
            import numpy as np
            import uuid as _uuid

            # Feature engineering
            fe = FeatureEngineer()
            df_features = fe.transform(df_traffic)
            if df_features.empty:
                return [], 0, 0

            X = df_features.values.astype(np.float32)

            # ── Anomaly Detection (Isolation Forest) ─────────────────────────
            ad = AnomalyDetector()
            ad_loaded = ad.load()

            # Fallback: try alternative path
            if not ad_loaded:
                alt_path = config.paths.models_dir / "isolation_forest.pkl"
                if alt_path.exists():
                    ad.model_path = alt_path
                    ad_loaded = ad.load(alt_path)

            if ad_loaded:
                try:
                    preds = ad.predict(X)
                    anomaly_mask = preds == -1
                    ml_anomalies = int(anomaly_mask.sum())

                    if ml_anomalies > 0:
                        # Create one summary alert per significant anomaly cluster
                        anomaly_rows = df_traffic[anomaly_mask] if len(anomaly_mask) == len(df_traffic) else df_traffic.head(ml_anomalies)
                        src_ip = "MULTIPLE"
                        if "src_ip" in anomaly_rows.columns:
                            top_src = anomaly_rows["src_ip"].value_counts()
                            if not top_src.empty:
                                src_ip = str(top_src.index[0])

                        severity = "HIGH" if ml_anomalies > 50 else "MEDIUM" if ml_anomalies > 10 else "LOW"
                        alert = SecurityAlert(
                            alert_id=str(_uuid.uuid4()),
                            attack_type="ML-AnomalyDetected",
                            severity=severity,
                            confidence=min(0.95, 0.6 + ml_anomalies / max(len(df_traffic), 1)),
                            source_ip=src_ip,
                            destination_ip="MULTIPLE",
                            timestamp=utc_now_iso(),
                            evidence={
                                "anomaly_count": ml_anomalies,
                                "total_packets": len(df_traffic),
                                "anomaly_rate": round(ml_anomalies / max(len(df_traffic), 1), 4),
                                "model": "IsolationForest",
                            },
                            recommendation=(
                                f"ML model flagged {ml_anomalies} packets as anomalous "
                                f"({ml_anomalies/max(len(df_traffic),1):.1%} of total). "
                                "Investigate the source IPs and payload patterns."
                            ),
                            detector_name="IsolationForest (ML)",
                            description=f"Isolation Forest detected {ml_anomalies} anomalous packets.",
                        )
                        ml_alerts.append(alert)
                except Exception as e:
                    log.debug("Anomaly inference error: %s", e)

            # ── Attack Classification (Random Forest / XGBoost) ───────────────
            clf = AttackClassifier()
            clf_loaded = clf.load()

            if not clf_loaded:
                alt_path = config.paths.models_dir / "random_forest.pkl"
                if alt_path.exists():
                    clf_loaded = clf.load(alt_path)

            if clf_loaded:
                try:
                    # Subsample for speed (max 5000 rows)
                    X_sample = X[:5000] if len(X) > 5000 else X
                    results = clf.classify_batch(X_sample)
                    attack_results = [r for r in results if r.is_attack]
                    ml_attacks = len(attack_results)

                    if ml_attacks > 0:
                        # Group by predicted label
                        from collections import Counter
                        attack_types = Counter(r.predicted_label for r in attack_results)

                        for attack_label, count in attack_types.most_common(3):
                            top_conf = max(
                                (r.confidence for r in attack_results
                                 if r.predicted_label == attack_label),
                                default=0.6,
                            )
                            severity = "HIGH" if count > 20 else "MEDIUM" if count > 5 else "LOW"
                            alert = SecurityAlert(
                                alert_id=str(_uuid.uuid4()),
                                attack_type=f"ML-{attack_label}",
                                severity=severity,
                                confidence=top_conf,
                                source_ip="MULTIPLE",
                                destination_ip="MULTIPLE",
                                timestamp=utc_now_iso(),
                                evidence={
                                    "predicted_class": attack_label,
                                    "count": count,
                                    "confidence": round(top_conf, 4),
                                    "model": results[0].model_name if results else "Unknown",
                                },
                                recommendation=(
                                    f"ML classifier identified {count} packets as {attack_label}. "
                                    "Review source IPs and apply appropriate firewall rules."
                                ),
                                detector_name=f"AttackClassifier (ML)",
                                description=f"ML classified {count} packets as {attack_label}.",
                            )
                            ml_alerts.append(alert)
                except Exception as e:
                    log.debug("Classification inference error: %s", e)

        except Exception as exc:
            log.warning("ML inference step error: %s", exc)

        return ml_alerts, ml_anomalies, ml_attacks

    def _step_persist_alerts(self, all_alerts: list) -> int:
        """Persist all alerts to database via AlertManager."""
        if not all_alerts:
            return 0
        try:
            from detection.alert_manager import AlertManager
            db = _get_db()
            am = AlertManager(db_manager=db)
            stored = am.ingest(all_alerts)
            return stored
        except Exception as exc:
            log.warning("Alert persistence step error: %s", exc)
            # Try direct DB insertion as fallback
            db = _get_db()
            count = 0
            for alert in all_alerts:
                try:
                    record = alert.to_alert_record()
                    db.insert_alert(record)
                    count += 1
                except Exception:
                    pass
            return count

    def _step_invalidate_caches(self) -> None:
        """Clear all st.cache_data caches so dashboard picks up fresh data."""
        try:
            from dashboard.data_loaders import invalidate_all_caches
            invalidate_all_caches()
        except Exception as exc:
            log.warning("Cache invalidation error: %s — trying st.cache_data.clear()", exc)
            try:
                st.cache_data.clear()
            except Exception:
                pass

    def _generate_demo_data(self) -> tuple:
        """Generate synthetic network traffic and inject into DB."""
        import pandas as pd
        import numpy as np
        import random
        from database.db_manager import TrafficRecord
        from utils.helpers import utc_now_iso
        from datetime import datetime, timedelta, timezone

        db = _get_db()
        n_packets = 5000
        now = datetime.now(timezone.utc)
        records_inserted = 0
        rows = []

        protocols = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS"]
        ips_normal = [f"192.168.1.{i}" for i in range(1, 51)]
        ips_attack = ["10.0.0.1", "10.0.0.2", "172.16.0.99"]

        rng = random.Random(42)
        np_rng = np.random.RandomState(42)

        for i in range(n_packets):
            ts = (now - timedelta(seconds=n_packets - i)).isoformat()
            is_attack_pkt = rng.random() < 0.08  # 8% attack traffic

            if is_attack_pkt:
                src = rng.choice(ips_attack)
                dst = rng.choice(ips_normal[:10])
                proto = rng.choice(["TCP", "UDP"])
                pkt_len = int(np_rng.exponential(1400))
                dst_port = rng.choice([22, 80, 443, 8080, 3389])
                ttl = rng.randint(32, 64)
            else:
                src = rng.choice(ips_normal)
                dst = rng.choice(ips_normal + ["8.8.8.8", "1.1.1.1"])
                proto = rng.choice(protocols)
                pkt_len = rng.randint(64, 1500)
                dst_port = rng.choice([80, 443, 53, 22, 8080])
                ttl = rng.randint(64, 128)

            try:
                tr = TrafficRecord(
                    timestamp=ts,
                    src_ip=src,
                    dst_ip=dst,
                    src_port=rng.randint(1024, 65535),
                    dst_port=dst_port,
                    protocol=proto,
                    packet_length=pkt_len,
                    ttl=ttl,
                    tcp_flags="0x02" if proto == "TCP" else "0",
                    payload_size=max(0, pkt_len - 40),
                )
                db.insert_traffic_record(tr)
                records_inserted += 1
                rows.append({
                    "src_ip": src, "dst_ip": dst,
                    "src_port": rng.randint(1024, 65535),
                    "dst_port": dst_port,
                    "protocol": proto,
                    "packet_length": pkt_len,
                    "ttl": ttl,
                    "timestamp": ts,
                })
            except Exception:
                pass

        df = pd.DataFrame(rows) if rows else pd.DataFrame()
        return df, records_inserted

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _update_step(
        self,
        step_name: str,
        step_index: int,
        status_container,
        progress_bar,
    ) -> bool:
        """Update session state and UI containers. Returns False if stop requested."""
        if self._stop_requested:
            return False

        label = self.STEP_LABELS.get(step_name, step_name)
        progress = (step_index - 1) / len(self.STEPS)

        _set_state("pipeline_phase", label)
        _set_state("pipeline_progress", progress)

        if status_container:
            try:
                status_container.write(f"**{label}**")
            except Exception:
                pass

        if progress_bar:
            try:
                progress_bar.progress(progress)
            except Exception:
                pass

        log.info("Pipeline step [%d/%d]: %s", step_index, len(self.STEPS), label)
        return True

    def _abort(self, result: PipelineResult, message: str, t_start: float) -> PipelineResult:
        """Mark pipeline as failed and update session state."""
        result.success = False
        result.error_message = message
        result.elapsed_seconds = time.perf_counter() - t_start

        _set_state("pipeline_running", False)
        _set_state("pipeline_phase", "Failed ❌")
        _set_state("pipeline_error", message)
        _set_state("pipeline_result", result.to_dict())

        log.error("Pipeline aborted: %s", message)
        return result


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _set_state(key: str, value: Any) -> None:
    """Safely set a session state key."""
    try:
        st.session_state[key] = value
    except Exception:
        pass


def _get_db():
    """Get or create the DatabaseManager singleton."""
    try:
        from dashboard.data_loaders import _get_db as loader_get_db
        return loader_get_db()
    except Exception:
        from database.db_manager import DatabaseManager
        db = DatabaseManager()
        db.initialise()
        return db


def _rows_to_df(rows: list):
    """Convert list of dicts/objects to DataFrame."""
    import pandas as pd
    if not rows:
        return pd.DataFrame()
    if isinstance(rows[0], dict):
        return pd.DataFrame(rows)
    # Convert dataclass/namedtuple
    try:
        from dataclasses import asdict
        return pd.DataFrame([asdict(r) for r in rows])
    except Exception:
        return pd.DataFrame([vars(r) for r in rows])


def init_pipeline_state() -> None:
    """Initialize all pipeline-related session state keys if not present."""
    defaults = {
        "pipeline_running": False,
        "pipeline_phase": "Idle",
        "pipeline_progress": 0.0,
        "pipeline_packets_done": 0,
        "pipeline_elapsed": 0.0,
        "pipeline_error": None,
        "pipeline_result": None,
        "analysis_complete": False,
        "current_file": "",
        "demo_mode_active": False,
        "selected_alert_id": None,
        "selected_packet_id": None,
        "filters": {},
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default
