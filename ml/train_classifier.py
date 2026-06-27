"""
train_classifier.py — Attack Classifier Training Pipeline
=========================================================
Network Traffic Analysis and Intrusion Detection System

Orchestrates the full Random Forest / XGBoost classifier training lifecycle:
  1. Load packets.csv via DatasetBuilder (generates synthetic labels)
  2. Apply feature engineering (FeatureEngineer)
  3. Preprocess features (DataPreprocessor)
  4. Train AttackClassifier (RF or XGBoost)
  5. Run K-fold cross-validation
  6. Evaluate on held-out test set
  7. Save model, preprocessor, and label encoder via ModelManager
  8. Log metadata to database

Entry Points:
    train_classifier()  — Full training pipeline, returns result dict
    main()              — CLI entry point

Author: Network Traffic Analyzer Project
Version: 6.0.0
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

def train_classifier(
    csv_path: Optional[Path] = None,
    prefer_xgboost: bool = True,
    save_model: bool = True,
    db_manager: Optional[Any] = None,
    run_cv: bool = True,
) -> dict[str, Any]:
    """
    Full attack classifier training pipeline.

    Args:
        csv_path:       Path to packets.csv. Defaults to config paths.
        prefer_xgboost: Try XGBoost first; fall back to Random Forest.
        save_model:     If True, persist model and artefacts to disk.
        db_manager:     Optional DatabaseManager for metadata persistence.
        run_cv:         If True, run K-fold cross-validation.

    Returns:
        Dict with keys: model, metrics, feature_names, preprocessor,
                        class_names, label_encoder, X_test, y_test.
    """
    from ml.dataset_builder import DatasetBuilder, LabelConfig
    from ml.preprocessing import DataPreprocessor, PreprocessConfig
    from ml.attack_classifier import AttackClassifier
    from ml.model_manager import ModelManager
    from ml.metrics import ModelEvaluator, ModelMetricsResult

    csv_path = csv_path or config.paths.processed_data_dir / "packets.csv"
    log.info("train_classifier(): CSV=%s, prefer_xgb=%s.", csv_path, prefer_xgboost)
    t0 = time.perf_counter()

    # ── Step 1: Build dataset ──────────────────────────────────────────────
    builder = DatasetBuilder(csv_path=csv_path)
    X, y, feature_names, label_encoder = builder.build()
    class_names = list(label_encoder.classes_)
    log.info(
        "Dataset: X=%s, classes=%s, distribution=%s.",
        X.shape, class_names,
        builder.class_distribution(y),
    )

    # ── Step 2: Preprocess and split ───────────────────────────────────────
    preprocessor = DataPreprocessor(cfg=PreprocessConfig(test_size=0.20))
    X_train, X_test, y_train, y_test = preprocessor.fit_transform_split(
        X, y, feature_names=feature_names
    )
    feature_names_selected = preprocessor.feature_names
    log.info(
        "Preprocessing: train=%d, test=%d, features=%d.",
        len(X_train), len(X_test), len(feature_names_selected),
    )

    # ── Step 3: Train classifier ───────────────────────────────────────────
    clf = AttackClassifier(
        prefer_xgboost=prefer_xgboost,
        label_encoder=label_encoder,
    )
    clf.train(
        X_train=X_train,
        y_train=y_train,
        feature_names=feature_names_selected,
        class_names=class_names,
        label_encoder=label_encoder,
    )
    log.info("Classifier trained: %s.", clf._clf.model_name)

    # ── Step 4: Evaluate ───────────────────────────────────────────────────
    evaluator = ModelEvaluator(cv_folds=config.ml.cv_folds)
    eval_result = evaluator.evaluate_classifier(
        model=clf.model,
        X_test=X_test,
        y_test=y_test,
        X_train=X_train if run_cv else None,
        y_train=y_train if run_cv else None,
        class_names=class_names,
        feature_names=feature_names_selected,
        model_name=clf._clf.model_name,
    )
    metrics_dict = eval_result.to_dict()
    elapsed = time.perf_counter() - t0
    metrics_dict["training_time_seconds"] = round(elapsed, 3)
    metrics_dict["n_train_samples"] = len(X_train)
    metrics_dict["n_test_samples"] = len(X_test)
    metrics_dict["n_features"] = len(feature_names_selected)

    log.info(
        "Classifier metrics: acc=%.4f, f1=%.4f, auc=%.4f, cv=%.4f±%.4f.",
        eval_result.accuracy,
        eval_result.f1_macro,
        eval_result.roc_auc,
        eval_result.cv_mean,
        eval_result.cv_std,
    )

    # ── Step 5: Persist ────────────────────────────────────────────────────
    if save_model:
        config.initialise_directories()

        # Save classifier
        clf.save()

        # Save via ModelManager (versioned + DB + registry)
        mm = ModelManager(db_manager=db_manager)
        model_key = "xgboost" if "XGB" in clf._clf.model_name else "random_forest"
        mm.save(
            model=clf.model,
            model_key=model_key,
            metrics=eval_result,
            feature_names=feature_names_selected,
            class_names=class_names,
            hyperparameters=getattr(clf.model, "get_params", lambda: {})(),
        )

        # Save preprocessor
        preprocessor.save()

        log.info("Classifier: all artefacts saved.")

    return {
        "model": clf,
        "metrics": metrics_dict,
        "metrics_result": eval_result,
        "feature_names": feature_names_selected,
        "class_names": class_names,
        "label_encoder": label_encoder,
        "preprocessor": preprocessor,
        "X_test": X_test,
        "y_test": y_test,
        "X_train": X_train,
        "y_train": y_train,
    }


# ──────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train Random Forest / XGBoost Attack Classifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--csv", type=str, default=None,
                        help="Path to packets.csv.")
    parser.add_argument("--no-xgboost", action="store_true",
                        help="Force Random Forest (skip XGBoost).")
    parser.add_argument("--no-cv", action="store_true",
                        help="Skip cross-validation.")
    parser.add_argument("--no-save", action="store_true",
                        help="Skip model persistence.")
    return parser.parse_args()


def main() -> int:
    """CLI main — train and save the attack classifier."""
    args = parse_args()
    csv_path = Path(args.csv) if args.csv else None

    result = train_classifier(
        csv_path=csv_path,
        prefer_xgboost=not args.no_xgboost,
        save_model=not args.no_save,
        run_cv=not args.no_cv,
    )

    metrics = result["metrics"]
    print("\n" + "=" * 52)
    print("  CLASSIFIER TRAINING COMPLETE")
    print("=" * 52)
    print(f"  Model             : {metrics.get('model_name', 'N/A')}")
    print(f"  Classes           : {result['class_names']}")
    print(f"  Training Samples  : {metrics.get('n_train_samples', 0):,}")
    print(f"  Test Samples      : {metrics.get('n_test_samples', 0):,}")
    print(f"  Features          : {metrics.get('n_features', 0)}")
    print()
    print(f"  Accuracy          : {metrics.get('accuracy', 0):.4f}")
    print(f"  Precision (macro) : {metrics.get('precision_macro', 0):.4f}")
    print(f"  Recall (macro)    : {metrics.get('recall_macro', 0):.4f}")
    print(f"  F1 (macro)        : {metrics.get('f1_macro', 0):.4f}")
    print(f"  ROC-AUC           : {metrics.get('roc_auc', 0):.4f}")
    if metrics.get("cv_mean"):
        print(f"  CV F1 (5-fold)    : {metrics.get('cv_mean', 0):.4f} ± {metrics.get('cv_std', 0):.4f}")
    print(f"  Training Time     : {metrics.get('training_time_seconds', 0):.3f}s")
    print("=" * 52)
    return 0


if __name__ == "__main__":
    sys.exit(main())
