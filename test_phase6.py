"""
test_phase6.py — Phase 6 Machine Learning Engine Validation
============================================================
Network Traffic Analysis and Intrusion Detection System

Validates the Phase 6 ML engine by running the complete workflow:

  1.  Load packets.csv → build ML dataset (DatasetBuilder)
  2.  Generate features (FeatureEngineer)
  3.  Preprocess and split (DataPreprocessor)
  4.  Train Isolation Forest (AnomalyDetector)
  5.  Train Random Forest + XGBoost (AttackClassifier)
  6.  Evaluate both models (ModelEvaluator)
  7.  Save all models (ModelManager)
  8.  Reload models from disk
  9.  Run batch inference (classify_batch / score_batch)
  10. Compare ML predictions with Phase 5 Rule Engine alerts
  11. Validate chart-ready visualization methods
  12. Print MACHINE LEARNING REPORT banner

Expected Output:
=====================================
MACHINE LEARNING REPORT
=====================================
Dataset Size     : 1000
Features         : XX
...
=====================================

Exit Codes:
    0  All tests passed
    1  packets.csv not found
    2  Training / evaluation error
    3  Validation failures

Usage:
    python test_phase6.py
    python test_phase6.py --csv data/processed/packets.csv --no-xgboost
    python test_phase6.py --no-db --no-save

Author: Network Traffic Analyzer Project
Version: 6.0.0
Python: 3.11+
"""

from __future__ import annotations

import argparse
import io
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Optional

# ── UTF-8 on Windows ──────────────────────────────────────────────────────────
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )

# ── Project root on path ──────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from utils.config import config
from utils.logger import get_logger

log = get_logger("test_phase6")

_W = 55   # Banner width


# ══════════════════════════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _sep(char: str = "=", w: int = _W) -> None:
    print(char * w)

def _header(title: str, char: str = "=") -> None:
    print(f"\n{'=' * _W}\n  {title}\n{'=' * _W}")

def _section(title: str) -> None:
    print(f"\n{'-' * _W}\n  {title}\n{'-' * _W}")

def _kv(label: str, value: Any, w: int = 22) -> None:
    print(f"  {label:<{w}}: {value}")

def _ok(msg: str) -> None:
    print(f"  [OK]   {msg}")

def _fail(msg: str) -> None:
    print(f"  [FAIL] {msg}")

def _info(msg: str) -> None:
    print(f"  [INFO] {msg}")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — DATASET BUILDING
# ══════════════════════════════════════════════════════════════════════════════

def build_dataset(
    csv_path: Path,
) -> dict[str, Any]:
    """
    Build ML dataset from packets.csv.

    Returns:
        Dict with X, y, feature_names, label_encoder, class_names.
    """
    from ml.dataset_builder import DatasetBuilder

    _header("STEP 1 — DATASET BUILDING")
    t0 = time.perf_counter()
    builder = DatasetBuilder(csv_path=csv_path)
    X, y, feature_names, label_encoder = builder.build()
    elapsed = time.perf_counter() - t0

    class_names = list(label_encoder.classes_)
    dist = builder.class_distribution(y)

    _kv("CSV path", csv_path)
    _kv("Total samples", f"{len(X):,}")
    _kv("Features", len(feature_names))
    _kv("Classes", class_names)
    _kv("Build time", f"{elapsed:.3f}s")
    _section("Class Distribution")
    for cls, cnt in sorted(dist.items(), key=lambda x: -x[1]):
        pct = cnt / len(y) * 100
        print(f"  {cls:<15} : {cnt:>4} ({pct:.1f}%)")

    return {
        "X": X,
        "y": y,
        "feature_names": feature_names,
        "label_encoder": label_encoder,
        "class_names": class_names,
        "builder": builder,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — PREPROCESSING
# ══════════════════════════════════════════════════════════════════════════════

def preprocess_dataset(
    X, y, feature_names: list[str]
) -> dict[str, Any]:
    """Apply preprocessing and split into train/test."""
    from ml.preprocessing import DataPreprocessor, PreprocessConfig

    _header("STEP 2 — PREPROCESSING & SPLIT")
    t0 = time.perf_counter()
    preprocessor = DataPreprocessor(cfg=PreprocessConfig(test_size=0.20))
    X_train, X_test, y_train, y_test = preprocessor.fit_transform_split(
        X, y, feature_names=feature_names
    )
    elapsed = time.perf_counter() - t0

    _kv("X_train shape", X_train.shape)
    _kv("X_test shape", X_test.shape)
    _kv("Selected features", len(preprocessor.feature_names))
    _kv("Preprocessing time", f"{elapsed:.3f}s")
    _ok("Preprocessing complete.")

    return {
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "preprocessor": preprocessor,
        "feature_names_selected": preprocessor.feature_names,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — ANOMALY MODEL TRAINING
# ══════════════════════════════════════════════════════════════════════════════

def train_anomaly(
    X_train, X_test, y_test, y,
    label_encoder,
    feature_names: list[str],
    save_model: bool,
    db_manager: Optional[Any],
) -> dict[str, Any]:
    """Train and evaluate the Isolation Forest model."""
    from ml.train_anomaly_model import train_anomaly_model
    from ml.anomaly_detector import AnomalyDetector

    _header("STEP 3 — ANOMALY MODEL (ISOLATION FOREST)")
    t0 = time.perf_counter()

    result = train_anomaly_model(
        contamination=0.05,
        n_estimators=100,   # Reduced for speed in test
        save_model=save_model,
        db_manager=db_manager,
    )
    elapsed = time.perf_counter() - t0

    metrics = result["metrics"]
    _kv("Training samples", f"{metrics.get('n_train_samples', 0):,}")
    _kv("Test samples", f"{metrics.get('n_test_samples', 0):,}")
    _kv("Anomaly rate", f"{metrics.get('anomaly_rate', 0):.2%}")
    _kv("Accuracy", f"{metrics.get('accuracy', 0):.4f}")
    _kv("F1 (macro)", f"{metrics.get('f1_macro', 0):.4f}")
    _kv("ROC-AUC", f"{metrics.get('roc_auc', 0):.4f}")
    _kv("Train time", f"{elapsed:.3f}s")
    _ok("Isolation Forest trained successfully.")

    return result


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — CLASSIFIER TRAINING
# ══════════════════════════════════════════════════════════════════════════════

def train_attack_classifier(
    save_model: bool,
    prefer_xgboost: bool,
    db_manager: Optional[Any],
) -> dict[str, Any]:
    """Train and evaluate the attack classifier."""
    from ml.train_classifier import train_classifier

    _header("STEP 4 — ATTACK CLASSIFIER (RF / XGBoost)")
    t0 = time.perf_counter()

    result = train_classifier(
        prefer_xgboost=prefer_xgboost,
        save_model=save_model,
        db_manager=db_manager,
        run_cv=True,
    )
    elapsed = time.perf_counter() - t0

    metrics = result["metrics"]
    clf = result["model"]
    _kv("Backend", clf._clf.model_name)
    _kv("Classes", result["class_names"])
    _kv("Training samples", f"{metrics.get('n_train_samples', 0):,}")
    _kv("Test samples", f"{metrics.get('n_test_samples', 0):,}")
    _kv("Features", metrics.get("n_features", 0))
    _kv("Accuracy", f"{metrics.get('accuracy', 0):.4f}")
    _kv("Precision (macro)", f"{metrics.get('precision_macro', 0):.4f}")
    _kv("Recall (macro)", f"{metrics.get('recall_macro', 0):.4f}")
    _kv("F1 (macro)", f"{metrics.get('f1_macro', 0):.4f}")
    _kv("ROC-AUC", f"{metrics.get('roc_auc', 0):.4f}")
    if metrics.get("cv_mean"):
        _kv("CV F1 (5-fold)", f"{metrics.get('cv_mean', 0):.4f} ± {metrics.get('cv_std', 0):.4f}")
    _kv("Train time", f"{elapsed:.3f}s")

    _section("Per-Class F1")
    for cls, f1 in sorted(metrics.get("per_class_f1", {}).items()):
        print(f"  {cls:<15} : {f1:.4f}")

    _ok("Attack Classifier trained successfully.")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — MODEL RELOAD & INFERENCE
# ══════════════════════════════════════════════════════════════════════════════

def test_reload_and_inference(
    classifier_result: dict[str, Any],
    anomaly_result: dict[str, Any],
) -> dict[str, Any]:
    """Reload models from disk and run batch inference."""
    from ml.model_manager import ModelManager
    from ml.anomaly_detector import AnomalyDetector
    from ml.attack_classifier import AttackClassifier

    _header("STEP 5 — MODEL RELOAD & INFERENCE")

    mm = ModelManager()

    # ── Reload Anomaly Model ───────────────────────────────────────────────
    anomaly_detector = AnomalyDetector()
    loaded_anomaly = anomaly_detector.load()
    _kv("Anomaly model loaded", loaded_anomaly)

    # ── Reload Classifier ──────────────────────────────────────────────────
    clf = AttackClassifier(
        label_encoder=classifier_result["label_encoder"]
    )
    loaded_clf = clf.load()
    _kv("Classifier loaded", loaded_clf)

    # ── Batch Inference on test set ────────────────────────────────────────
    X_test = classifier_result["X_test"]
    y_test = classifier_result["y_test"]
    class_names = classifier_result["class_names"]

    t0 = time.perf_counter()
    if loaded_clf:
        batch_results = clf.classify_batch(X_test)
        clf_elapsed = time.perf_counter() - t0
        attack_predictions = sum(1 for r in batch_results if r.is_attack)
        _kv("Batch size", len(batch_results))
        _kv("Attack predictions", attack_predictions)
        _kv("Benign predictions", len(batch_results) - attack_predictions)
        _kv("Avg confidence", f"{sum(r.confidence for r in batch_results) / len(batch_results):.4f}")
        _kv("Inference time", f"{clf_elapsed:.3f}s")
        _ok("Batch classification inference successful.")
    else:
        _info("Classifier not loaded from disk — skipping batch inference.")
        batch_results = []
        attack_predictions = 0

    # ── Anomaly Batch Scoring ──────────────────────────────────────────────
    anomaly_scores: Any = None
    if loaded_anomaly and len(X_test) > 0:
        t0 = time.perf_counter()
        anomaly_scores = anomaly_detector.score_batch(X_test)
        anom_elapsed = time.perf_counter() - t0
        n_anomalies = int((anomaly_detector.predict(X_test) == -1).sum())
        _kv("Anomalies detected", n_anomalies)
        _kv("Score range", f"[{anomaly_scores.min():.4f}, {anomaly_scores.max():.4f}]")
        _kv("Anomaly score time", f"{anom_elapsed:.3f}s")
        _ok("Anomaly batch scoring successful.")
    else:
        _info("Anomaly model not available — skipping batch scoring.")

    return {
        "batch_results": batch_results,
        "attack_predictions": attack_predictions,
        "anomaly_scores": anomaly_scores,
        "anomaly_detector_loaded": loaded_anomaly,
        "classifier_loaded": loaded_clf,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — COMPARE ML vs RULE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def compare_ml_vs_rules(
    batch_results: list,
    csv_path: Path,
) -> dict[str, Any]:
    """
    Compare ML classifier predictions with Phase 5 rule-engine alerts.

    Args:
        batch_results: List of ClassificationResult from ML inference.
        csv_path:      Path to packets.csv for rule engine.

    Returns:
        Comparison statistics.
    """
    from analysis.traffic_statistics import TrafficStatistics
    from analysis.protocol_analysis import ProtocolAnalysis
    from analysis.bandwidth_monitor import BandwidthMonitor
    from detection.rule_engine import RuleEngine
    from detection.ddos_detector import DDoSDetector
    from detection.portscan_detector import PortScanDetector
    from detection.bruteforce_detector import BruteForceDetector
    from detection.synflood_detector import SYNFloodDetector

    _header("STEP 6 — ML vs RULE ENGINE COMPARISON")
    t0 = time.perf_counter()

    # ── Rule Engine ────────────────────────────────────────────────────────
    ts = TrafficStatistics(csv_path=csv_path)
    ts.load_data(source="csv")
    pa = ProtocolAnalysis(csv_path=csv_path)
    pa.load_data(source="csv")
    bm = BandwidthMonitor(csv_path=csv_path)
    bm.load_data(source="csv")

    engine = RuleEngine(dedup_window_seconds=0)
    cfg_overrides = {
        "ddos_packets_per_second": 5,
        "portscan_unique_ports": 5,
        "bruteforce_failed_attempts": 3,
        "synflood_syn_per_second": 5.0,
    }
    engine.register(DDoSDetector(enabled=True, cfg_overrides=cfg_overrides))
    engine.register(SYNFloodDetector(enabled=True, cfg_overrides=cfg_overrides))
    engine.register(PortScanDetector(enabled=True, cfg_overrides=cfg_overrides))
    engine.register(BruteForceDetector(enabled=True, cfg_overrides=cfg_overrides))

    df = ts.get_dataframe()
    rule_alerts = engine.run_detection(
        df=df,
        traffic_stats=ts,
        protocol_analysis=pa,
        bandwidth_monitor=bm,
    )
    elapsed = time.perf_counter() - t0

    # ── ML attack count ─────────────────────────────────────────────────────
    ml_attack_count = sum(1 for r in batch_results if r.is_attack)
    rule_alert_count = len(rule_alerts)

    _section("Comparison Results")
    _kv("Packets analysed", f"{len(df):,}")
    _kv("Rule engine alerts", rule_alert_count)
    _kv("ML attack predictions", ml_attack_count)
    _kv("Rule engine time", f"{elapsed:.3f}s")

    _section("Rule Engine Alert Types")
    from collections import Counter
    type_counts = Counter(a.attack_type for a in rule_alerts)
    for atype, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {atype:<25} : {cnt}")

    _section("ML Prediction Distribution")
    if batch_results:
        from collections import Counter as _Counter
        pred_dist = _Counter(r.predicted_label for r in batch_results)
        for cls, cnt in sorted(pred_dist.items(), key=lambda x: -x[1]):
            print(f"  {cls:<15} : {cnt:>4} ({cnt / len(batch_results) * 100:.1f}%)")

    _ok("ML vs Rule Engine comparison complete.")

    return {
        "rule_alerts": rule_alerts,
        "rule_alert_count": rule_alert_count,
        "ml_attack_count": ml_attack_count,
        "type_counts": dict(type_counts),
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — VISUALIZATION DATA VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def validate_viz_data(
    classifier_result: dict[str, Any],
) -> list[str]:
    """Validate chart-ready output methods from ModelEvaluator."""
    from ml.metrics import ModelEvaluator

    _header("STEP 7 — VISUALIZATION DATA VALIDATION")
    failures: list[str] = []
    evaluator = ModelEvaluator()
    metrics_result = classifier_result.get("metrics_result")

    if metrics_result is None:
        _info("No metrics_result available — skipping viz validation.")
        return failures

    # get_confusion_matrix_data()
    try:
        cm_data = evaluator.get_confusion_matrix_data(metrics_result)
        if "z" not in cm_data or "x" not in cm_data:
            failures.append("get_confusion_matrix_data(): missing 'z' or 'x'.")
        _kv("Confusion matrix shape", f"{len(cm_data['z'])} × {len(cm_data['z'][0]) if cm_data['z'] else 0}")
    except Exception as exc:
        failures.append(f"get_confusion_matrix_data() raised: {exc}")

    # get_feature_importance_data()
    try:
        fi_data = evaluator.get_feature_importance_data(metrics_result, top_n=10)
        if "features" not in fi_data or "importances" not in fi_data:
            failures.append("get_feature_importance_data(): missing keys.")
        _kv("Feature importance entries", len(fi_data.get("features", [])))
    except Exception as exc:
        failures.append(f"get_feature_importance_data() raised: {exc}")

    # get_prediction_distribution()
    try:
        pd_data = evaluator.get_prediction_distribution(metrics_result)
        if "labels" not in pd_data or "values" not in pd_data:
            failures.append("get_prediction_distribution(): missing keys.")
        _kv("Prediction distribution", pd_data.get("labels", []))
    except Exception as exc:
        failures.append(f"get_prediction_distribution() raised: {exc}")

    # get_probability_distribution()
    try:
        import numpy as np
        y_proba = classifier_result["model"].predict_proba(
            classifier_result["X_test"][:10]
        ) if classifier_result["model"].is_loaded else np.zeros((10, 5))
        prob_data = evaluator.get_probability_distribution(
            y_proba,
            classifier_result["class_names"],
        )
        if "labels" not in prob_data:
            failures.append("get_probability_distribution(): missing 'labels'.")
        _kv("Prob. distribution labels", prob_data.get("labels", []))
    except Exception as exc:
        failures.append(f"get_probability_distribution() raised: {exc}")

    if not failures:
        _ok("All 4 visualization methods returned valid data.")
    return failures


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — MODEL MANAGER VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def validate_model_manager(save_model: bool) -> list[str]:
    """Validate ModelManager registry, listing, and metadata methods."""
    from ml.model_manager import ModelManager

    _header("STEP 8 — MODEL MANAGER VALIDATION")
    failures: list[str] = []
    mm = ModelManager()

    # list_models()
    try:
        models = mm.list_models()
        _kv("Registered models", len(models))
        for m in models:
            status = "active" if m.is_active else "inactive"
            print(f"  {m.model_name:<35} v{m.version} [{status}]")
    except Exception as exc:
        failures.append(f"list_models() raised: {exc}")

    # get_metadata_dict()
    try:
        meta = mm.get_metadata_dict()
        if not isinstance(meta, dict):
            failures.append("get_metadata_dict(): expected dict.")
        _kv("Metadata keys", list(meta.keys()))
    except Exception as exc:
        failures.append(f"get_metadata_dict() raised: {exc}")

    # exists()
    try:
        for key in ("isolation_forest", "random_forest"):
            exists = mm.exists(key)
            icon = "[OK]" if exists else "[--]"
            print(f"  {icon} {key}.pkl exists: {exists}")
    except Exception as exc:
        failures.append(f"exists() raised: {exc}")

    if not failures:
        _ok("ModelManager validation passed.")
    return failures


# ══════════════════════════════════════════════════════════════════════════════
# VALIDATION CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def _run_validation_checks(
    dataset_result: dict[str, Any],
    pre_result: dict[str, Any],
    anomaly_result: dict[str, Any],
    clf_result: dict[str, Any],
    inference_result: dict[str, Any],
) -> list[str]:
    """Run sanity checks across all Phase 6 components."""
    import numpy as np
    failures: list[str] = []

    # Dataset checks
    X = dataset_result["X"]
    y = dataset_result["y"]
    if X.shape[0] == 0:
        failures.append("Dataset X is empty.")
    if len(X.shape) != 2:
        failures.append(f"Dataset X must be 2-D, got shape {X.shape}.")
    if len(y) != len(X):
        failures.append(f"y length ({len(y)}) != X rows ({len(X)}).")
    if len(dataset_result["feature_names"]) == 0:
        failures.append("No feature names generated.")
    if len(dataset_result["class_names"]) == 0:
        failures.append("No class names generated.")

    # Preprocessing checks
    X_train = pre_result["X_train"]
    X_test = pre_result["X_test"]
    if X_train.dtype != np.float32:
        # Acceptable: just check it's a float type
        if not np.issubdtype(X_train.dtype, np.floating):
            failures.append(f"X_train dtype must be float, got {X_train.dtype}.")
    if np.isnan(X_train).any():
        failures.append("X_train contains NaN values.")
    if np.isnan(X_test).any():
        failures.append("X_test contains NaN values.")

    # Anomaly model checks
    anom_model = anomaly_result.get("model")
    if anom_model is None or not anom_model.is_loaded:
        failures.append("AnomalyDetector not trained / loaded.")
    anom_metrics = anomaly_result.get("metrics", {})
    if not (0.0 <= anom_metrics.get("anomaly_rate", -1.0) <= 1.0):
        failures.append(
            f"anomaly_rate out of range: {anom_metrics.get('anomaly_rate')}"
        )

    # Classifier checks
    clf_metrics = clf_result.get("metrics", {})
    clf_model = clf_result.get("model")
    if clf_model is None or not clf_model.is_loaded:
        failures.append("AttackClassifier not trained / loaded.")
    if not (0.0 <= clf_metrics.get("accuracy", -1.0) <= 1.0):
        failures.append(f"accuracy out of range: {clf_metrics.get('accuracy')}")
    if not clf_metrics.get("class_names") and not clf_result.get("class_names"):
        failures.append("class_names missing from classifier result.")

    # Inference checks
    batch = inference_result.get("batch_results", [])
    from ml.attack_classifier import ClassificationResult
    for r in batch[:5]:   # Spot-check first 5
        if not isinstance(r, ClassificationResult):
            failures.append(f"Batch result is not ClassificationResult: {type(r)}")
            break
        if r.predicted_label == "":
            failures.append("Empty predicted_label in ClassificationResult.")
        if not (0.0 <= r.confidence <= 1.0):
            failures.append(f"Confidence {r.confidence} out of [0,1].")

    return failures


# ══════════════════════════════════════════════════════════════════════════════
# FINAL ML REPORT BANNER
# ══════════════════════════════════════════════════════════════════════════════

def print_ml_report(
    dataset_result: dict[str, Any],
    pre_result: dict[str, Any],
    anomaly_result: dict[str, Any],
    clf_result: dict[str, Any],
    inference_result: dict[str, Any],
    comparison_result: dict[str, Any],
    total_elapsed: float,
) -> None:
    """Print the MACHINE LEARNING REPORT banner."""
    anom_metrics = anomaly_result.get("metrics", {})
    clf_metrics = clf_result.get("metrics", {})

    print()
    _sep("=")
    print("  MACHINE LEARNING REPORT")
    _sep("=")
    print()
    _kv("Dataset Size", f"{len(dataset_result['X']):,}")
    _kv("Features", len(dataset_result["feature_names"]))
    _kv("Classes", dataset_result["class_names"])
    print()
    _kv("Training Samples", f"{anom_metrics.get('n_train_samples', 0):,}")
    _kv("Test Samples", f"{anom_metrics.get('n_test_samples', 0):,}")
    print()
    _sep("-")
    print("  ISOLATION FOREST (Anomaly Detection)")
    _sep("-")
    _kv("Anomaly Rate", f"{anom_metrics.get('anomaly_rate', 0):.2%}")
    _kv("Accuracy", f"{anom_metrics.get('accuracy', 0):.4f}")
    _kv("F1 (macro)", f"{anom_metrics.get('f1_macro', 0):.4f}")
    _kv("ROC-AUC", f"{anom_metrics.get('roc_auc', 0):.4f}")
    print()
    _sep("-")
    print(f"  {clf_metrics.get('model_name', 'CLASSIFIER')} (Attack Classification)")
    _sep("-")
    _kv("Accuracy", f"{clf_metrics.get('accuracy', 0):.4f}")
    _kv("Precision", f"{clf_metrics.get('precision_macro', 0):.4f}")
    _kv("Recall", f"{clf_metrics.get('recall_macro', 0):.4f}")
    _kv("F1 (macro)", f"{clf_metrics.get('f1_macro', 0):.4f}")
    _kv("ROC-AUC", f"{clf_metrics.get('roc_auc', 0):.4f}")
    if clf_metrics.get("cv_mean"):
        _kv("CV F1 (5-fold)", f"{clf_metrics.get('cv_mean', 0):.4f} ± {clf_metrics.get('cv_std', 0):.4f}")
    print()
    _sep("-")
    print("  INFERENCE")
    _sep("-")
    _kv("Rule Engine Alerts", comparison_result.get("rule_alert_count", 0))
    _kv("ML Attack Predictions", inference_result.get("attack_predictions", 0))
    _kv("Anomaly Model Loaded", inference_result.get("anomaly_detector_loaded", False))
    _kv("Classifier Loaded", inference_result.get("classifier_loaded", False))
    print()
    _kv("Total Pipeline Time", f"{total_elapsed:.3f}s")
    print()
    _sep("=")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Phase 6 Test — ML-Based Intrusion Detection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--csv", type=str, default=None)
    parser.add_argument("--no-xgboost", action="store_true",
                        help="Force Random Forest backend.")
    parser.add_argument("--no-save", action="store_true",
                        help="Skip model persistence.")
    parser.add_argument("--no-db", action="store_true",
                        help="Skip database persistence.")
    return parser.parse_args()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    """Main entry point. Returns exit code."""
    args = parse_args()
    total_start = time.perf_counter()

    # ── Resolve CSV ────────────────────────────────────────────────────────
    csv_path = Path(args.csv) if args.csv else (
        config.paths.processed_data_dir / "packets.csv"
    )

    _header("PHASE 6 ML ENGINE VALIDATION", "=")
    print(f"\n  CSV Source : {csv_path}")
    print(f"  XGBoost    : {'disabled' if args.no_xgboost else 'enabled (if available)'}")
    print(f"  Save Models: {'no' if args.no_save else 'yes'}")

    if not csv_path.exists():
        print(f"\n  [FAIL] packets.csv not found: {csv_path}")
        print("     Run Phase 2 first: python test_phase2.py --generate\n")
        return 1

    config.initialise_directories()

    # ── DB ─────────────────────────────────────────────────────────────────
    db_manager = None
    if not args.no_db:
        try:
            from database.db_manager import DatabaseManager
            db_manager = DatabaseManager()
            db_manager.initialise()
        except Exception as exc:
            log.warning("Could not initialise database: %s", exc)

    try:
        # ── Phase 6 Pipeline ───────────────────────────────────────────────
        dataset_result = build_dataset(csv_path)

        pre_result = preprocess_dataset(
            dataset_result["X"],
            dataset_result["y"],
            dataset_result["feature_names"],
        )

        anomaly_result = train_anomaly(
            X_train=pre_result["X_train"],
            X_test=pre_result["X_test"],
            y_test=pre_result["y_test"],
            y=dataset_result["y"],
            label_encoder=dataset_result["label_encoder"],
            feature_names=pre_result["feature_names_selected"],
            save_model=not args.no_save,
            db_manager=db_manager,
        )

        clf_result = train_attack_classifier(
            save_model=not args.no_save,
            prefer_xgboost=not args.no_xgboost,
            db_manager=db_manager,
        )

        inference_result = test_reload_and_inference(
            classifier_result=clf_result,
            anomaly_result=anomaly_result,
        )

        comparison_result = compare_ml_vs_rules(
            batch_results=inference_result.get("batch_results", []),
            csv_path=csv_path,
        )

        viz_failures = validate_viz_data(clf_result)
        mm_failures = validate_model_manager(save_model=not args.no_save)
        core_failures = _run_validation_checks(
            dataset_result, pre_result, anomaly_result,
            clf_result, inference_result,
        )

    except FileNotFoundError as exc:
        print(f"\n  [FAIL] File not found: {exc}\n")
        return 1
    except Exception as exc:
        print(f"\n  [FAIL] Runtime error: {exc}\n")
        log.error("Phase 6 error:\n%s", traceback.format_exc())
        return 2

    total_elapsed = time.perf_counter() - total_start

    # ── Final report banner ────────────────────────────────────────────────
    print_ml_report(
        dataset_result, pre_result, anomaly_result,
        clf_result, inference_result, comparison_result, total_elapsed,
    )

    # ── Model Manager Summary ──────────────────────────────────────────────
    _section("Saved Models Summary")
    from ml.model_manager import ModelManager
    mm = ModelManager()
    for info in mm.list_models():
        status = "ACTIVE" if info.is_active else "      "
        print(f"  [{status}] {info.model_name:<35} acc={info.accuracy:.4f} f1={info.f1_score:.4f}")

    # ── All Failures ───────────────────────────────────────────────────────
    all_failures = viz_failures + mm_failures + core_failures
    if all_failures:
        _header("VALIDATION FAILURES", "!")
        for msg in all_failures:
            _fail(msg)
        print(f"\n  {len(all_failures)} validation error(s) found.\n")
        log.error("Phase 6 validation: %d failure(s).", len(all_failures))
        return 3

    # ── Sign-off ───────────────────────────────────────────────────────────
    print()
    _sep()
    print("  [OK] All Phase 6 Tests Completed Successfully")
    _sep()
    print()

    log.info(
        "Phase 6 test complete in %.3fs. "
        "Dataset=%d, Features=%d, Acc=%.4f, F1=%.4f.",
        total_elapsed,
        len(dataset_result["X"]),
        len(dataset_result["feature_names"]),
        clf_result.get("metrics", {}).get("accuracy", 0.0),
        clf_result.get("metrics", {}).get("f1_macro", 0.0),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
