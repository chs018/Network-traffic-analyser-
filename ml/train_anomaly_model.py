"""
train_anomaly_model.py — Isolation Forest Training Pipeline
============================================================
Network Traffic Analysis and Intrusion Detection System

Orchestrates the complete Isolation Forest training lifecycle:
  1. Load packets.csv via DatasetBuilder (balanced synthetic labels)
  2. Apply feature engineering (FeatureEngineer)
  3. Preprocess features (DataPreprocessor)
  4. Train AnomalyDetector on BENIGN samples (unsupervised — proper IDS approach)
  5. Evaluate on held-out test set using non-BENIGN samples as ground-truth anomalies
  6. Save model via AnomalyDetector.save() and ModelManager
  7. Log metrics to database

The Isolation Forest is trained on BENIGN-only samples so it learns the
distribution of normal traffic. During evaluation, non-BENIGN samples serve
as ground-truth anomalies, which produces meaningful accuracy metrics.

Entry Points:
    train_anomaly_model()  — Full training pipeline
    main()                 — CLI entry point

Author: Network Traffic Analyzer Project
Version: 6.1.0
Python: 3.11+
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, Optional

import numpy as np

from utils.config import config
from utils.logger import get_ml_logger

log = get_ml_logger()


# ──────────────────────────────────────────────────────────────────────────────
# TRAINING PIPELINE
# ──────────────────────────────────────────────────────────────────────────────

def train_anomaly_model(
    csv_path: Optional[Path] = None,
    contamination: float = 0.05,
    n_estimators: int = 200,
    save_model: bool = True,
    db_manager: Optional[Any] = None,
) -> dict[str, Any]:
    """
    Full Isolation Forest training pipeline.

    The Isolation Forest is trained exclusively on BENIGN-labelled samples
    (semi-supervised approach). This ensures the model learns normal traffic
    patterns and can flag genuine anomalies at inference time.

    Args:
        csv_path:      Path to packets.csv. Defaults to config.paths.
        contamination: Expected anomaly fraction for the Isolation Forest
                       offset calibration (0.001–0.499).
        n_estimators:  Number of trees in the forest.
        save_model:    If True, persist model to disk.
        db_manager:    Optional DatabaseManager for metadata persistence.

    Returns:
        Dict with keys: model, metrics, feature_names, preprocessor,
                        X_test, y_test, y_test_binary, label_encoder.
    """
    from ml.dataset_builder import DatasetBuilder
    from ml.preprocessing import DataPreprocessor, PreprocessConfig
    from ml.anomaly_detector import AnomalyDetector
    from ml.model_manager import ModelManager
    from ml.metrics import ModelMetricsResult

    csv_path = csv_path or config.paths.processed_data_dir / "packets.csv"
    log.info("train_anomaly_model(): CSV=%s", csv_path)
    t0 = time.perf_counter()

    # ── Step 1: Build balanced dataset ────────────────────────────────────
    builder = DatasetBuilder(csv_path=csv_path)
    X, y, feature_names, label_encoder = builder.build()
    class_names = list(label_encoder.classes_)
    log.info(
        "Dataset: X=%s, classes=%s, distribution=%s.",
        X.shape, class_names, builder.class_distribution(y),
    )

    # ── Step 2: Identify BENIGN index ─────────────────────────────────────
    benign_idx = (
        list(label_encoder.classes_).index("BENIGN")
        if "BENIGN" in label_encoder.classes_
        else 0
    )

    # ── Step 3: Preprocess ────────────────────────────────────────────────
    preprocessor = DataPreprocessor(cfg=PreprocessConfig(test_size=0.20))
    X_scaled, y_proc = preprocessor.fit_transform(X, y, feature_names=feature_names)
    X_train_full, X_test, y_train_full, y_test = preprocessor.train_test_split(
        X_scaled, y_proc
    )

    # ── Step 4: Extract BENIGN-only training samples ───────────────────────
    # Train Isolation Forest on normal traffic only → learns normal distribution
    benign_mask_train = (y_train_full == benign_idx)
    X_train_benign = X_train_full[benign_mask_train]

    if len(X_train_benign) < 10:
        # Fallback: use all training data if not enough BENIGN samples
        log.warning(
            "train_anomaly_model(): Only %d BENIGN training samples — "
            "falling back to full training set.", len(X_train_benign)
        )
        X_train_benign = X_train_full

    log.info(
        "Anomaly model: training on %d BENIGN samples (out of %d total).",
        len(X_train_benign), len(X_train_full),
    )

    # ── Step 5: Build binary ground-truth for evaluation ──────────────────
    # For the test set: BENIGN=0 (normal), everything else=1 (anomaly)
    y_test_binary = (y_test != benign_idx).astype(int)
    log.info(
        "Evaluation: %d test samples (%d anomalies, %d normal).",
        len(y_test), int(y_test_binary.sum()), int((y_test_binary == 0).sum()),
    )

    # ── Step 6: Train ─────────────────────────────────────────────────────
    detector = AnomalyDetector(
        contamination=contamination,
        n_estimators=n_estimators,
        random_state=config.ml.random_state,
    )
    detector.train(
        X_train_benign,
        feature_names=preprocessor.feature_names,
        contamination=contamination,
    )

    # ── Step 7: Evaluate ──────────────────────────────────────────────────
    # Pass y_test_binary only if we have both positive and negative samples
    eval_labels = (
        y_test_binary
        if y_test_binary.sum() > 0 and (y_test_binary == 0).sum() > 0
        else None
    )
    metrics_dict = detector.evaluate(
        X_test=X_test,
        y_test_binary=eval_labels,
        feature_names=preprocessor.feature_names,
    )
    elapsed = time.perf_counter() - t0
    metrics_dict["training_time_seconds"] = round(elapsed, 3)
    metrics_dict["n_train_samples"] = len(X_train_benign)
    metrics_dict["n_test_samples"] = len(X_test)
    metrics_dict["n_features"] = X_train_benign.shape[1]

    log.info(
        "AnomalyDetector metrics: anomaly_rate=%.4f, acc=%.4f, f1=%.4f, auc=%.4f.",
        metrics_dict.get("anomaly_rate", 0.0),
        metrics_dict.get("accuracy", 0.0),
        metrics_dict.get("f1_macro", 0.0),
        metrics_dict.get("roc_auc", 0.0),
    )

    # ── Step 8: Persist ───────────────────────────────────────────────────
    if save_model:
        config.initialise_directories()

        # Save via AnomalyDetector (canonical path)
        detector.save()

        # Save via ModelManager (versioned + DB + registry)
        mm = ModelManager(db_manager=db_manager)
        mr = ModelMetricsResult(
            model_name="IsolationForest",
            model_type="anomaly",
            anomaly_rate=metrics_dict.get("anomaly_rate", 0.0),
            accuracy=metrics_dict.get("accuracy", 0.0),
            f1_macro=metrics_dict.get("f1_macro", 0.0),
            precision_macro=metrics_dict.get("precision_macro", 0.0),
            recall_macro=metrics_dict.get("recall_macro", 0.0),
            roc_auc=metrics_dict.get("roc_auc", 0.0),
            n_samples=len(X_train_benign),
            n_features=X_train_benign.shape[1],
        )
        mm.save(
            model=detector.model,
            model_key="isolation_forest",
            metrics=mr,
            feature_names=preprocessor.feature_names,
            hyperparameters={
                "contamination": contamination,
                "n_estimators": n_estimators,
                "trained_on": "BENIGN_only",
            },
        )

        # Save preprocessor artifacts
        preprocessor.save()
        log.info("AnomalyDetector: all artifacts saved.")

    return {
        "model": detector,
        "metrics": metrics_dict,
        "feature_names": preprocessor.feature_names,
        "preprocessor": preprocessor,
        "X_test": X_test,
        "y_test": y_test,
        "y_test_binary": y_test_binary,
        "label_encoder": label_encoder,
    }


# ──────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest Anomaly Detection Model",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--csv", type=str, default=None,
                        help="Path to packets.csv.")
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="Expected anomaly fraction (default: 0.05).")
    parser.add_argument("--n-estimators", type=int, default=200,
                        help="Number of trees (default: 200).")
    parser.add_argument("--no-save", action="store_true",
                        help="Skip model persistence.")
    return parser.parse_args()


def main() -> int:
    """CLI main — train and save the anomaly model."""
    args = parse_args()
    csv_path = Path(args.csv) if args.csv else None

    result = train_anomaly_model(
        csv_path=csv_path,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        save_model=not args.no_save,
    )

    metrics = result["metrics"]
    print("\n" + "=" * 50)
    print("  ANOMALY MODEL TRAINING COMPLETE")
    print("=" * 50)
    print(f"  Training Samples  : {metrics.get('n_train_samples', 0):,}")
    print(f"  Test Samples      : {metrics.get('n_test_samples', 0):,}")
    print(f"  Features          : {metrics.get('n_features', 0)}")
    print(f"  Anomaly Rate      : {metrics.get('anomaly_rate', 0):.2%}")
    print(f"  Accuracy          : {metrics.get('accuracy', 0):.4f}")
    print(f"  F1 (macro)        : {metrics.get('f1_macro', 0):.4f}")
    print(f"  ROC-AUC           : {metrics.get('roc_auc', 0):.4f}")
    print(f"  Training Time     : {metrics.get('training_time_seconds', 0):.3f}s")
    print("=" * 50)
    return 0


if __name__ == "__main__":
    sys.exit(main())
