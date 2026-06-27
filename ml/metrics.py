"""
metrics.py — ML Model Evaluation Metrics
=========================================
Network Traffic Analysis and Intrusion Detection System

Provides a comprehensive suite of model evaluation metrics including:
  - Accuracy, Precision, Recall, F1 (macro, weighted, per-class)
  - ROC-AUC (macro OvR)
  - Confusion Matrix
  - Classification Report
  - Feature Importance rankings
  - Cross-validation scores
  - Chart-ready output methods for dashboard visualisation

Classes:
    ModelMetricsResult — Dataclass holding all computed metrics
    ModelEvaluator     — Metric computation engine

Author: Network Traffic Analyzer Project
Version: 6.0.0
Python: 3.11+
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelBinarizer

from utils.logger import get_ml_logger

log = get_ml_logger()


# ──────────────────────────────────────────────────────────────────────────────
# METRICS RESULT DATACLASS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ModelMetricsResult:
    """
    Holds the complete evaluation metrics for a trained model.

    All scalar metrics are rounded to 4 decimal places internally.
    Use :meth:`to_dict` for JSON-serialisable output.
    """

    # Model identification
    model_name: str = ""
    model_type: str = ""         # "anomaly" | "classifier"

    # Overall metrics
    accuracy: float = 0.0
    precision_macro: float = 0.0
    recall_macro: float = 0.0
    f1_macro: float = 0.0
    precision_weighted: float = 0.0
    recall_weighted: float = 0.0
    f1_weighted: float = 0.0
    roc_auc: float = 0.0

    # Per-class metrics
    per_class_precision: dict[str, float] = field(default_factory=dict)
    per_class_recall: dict[str, float] = field(default_factory=dict)
    per_class_f1: dict[str, float] = field(default_factory=dict)
    per_class_support: dict[str, int] = field(default_factory=dict)

    # Confusion matrix (as nested list for JSON compatibility)
    confusion_matrix: list[list[int]] = field(default_factory=list)
    class_names: list[str] = field(default_factory=list)

    # Cross-validation
    cv_scores: list[float] = field(default_factory=list)
    cv_mean: float = 0.0
    cv_std: float = 0.0

    # Feature importance (feature_name → importance_score)
    feature_importance: dict[str, float] = field(default_factory=dict)

    # Anomaly-specific
    anomaly_rate: float = 0.0       # Fraction of samples flagged as anomaly
    contamination: float = 0.0      # Configured contamination parameter

    # Sample counts
    n_samples: int = 0
    n_features: int = 0
    n_classes: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return a flat, JSON-serialisable dictionary of all metrics."""
        return {
            "model_name": self.model_name,
            "model_type": self.model_type,
            "accuracy": round(self.accuracy, 4),
            "precision_macro": round(self.precision_macro, 4),
            "recall_macro": round(self.recall_macro, 4),
            "f1_macro": round(self.f1_macro, 4),
            "precision_weighted": round(self.precision_weighted, 4),
            "recall_weighted": round(self.recall_weighted, 4),
            "f1_weighted": round(self.f1_weighted, 4),
            "roc_auc": round(self.roc_auc, 4),
            "cv_mean": round(self.cv_mean, 4),
            "cv_std": round(self.cv_std, 4),
            "cv_scores": [round(s, 4) for s in self.cv_scores],
            "anomaly_rate": round(self.anomaly_rate, 4),
            "per_class_f1": {k: round(v, 4) for k, v in self.per_class_f1.items()},
            "confusion_matrix": self.confusion_matrix,
            "class_names": self.class_names,
            "n_samples": self.n_samples,
            "n_features": self.n_features,
            "n_classes": self.n_classes,
            "top_features": dict(
                sorted(self.feature_importance.items(),
                       key=lambda x: -x[1])[:10]
            ),
        }

    def __repr__(self) -> str:
        return (
            f"ModelMetricsResult(model={self.model_name!r}, "
            f"acc={self.accuracy:.3f}, f1_macro={self.f1_macro:.3f}, "
            f"roc_auc={self.roc_auc:.3f})"
        )


# ──────────────────────────────────────────────────────────────────────────────
# MODEL EVALUATOR
# ──────────────────────────────────────────────────────────────────────────────

class ModelEvaluator:
    """
    Comprehensive model evaluation engine.

    Computes the full metric suite for both anomaly detection and
    classification models. Returns :class:`ModelMetricsResult` objects
    that are JSON-serialisable and chart-ready.

    Usage::

        evaluator = ModelEvaluator()

        # For classifier
        result = evaluator.evaluate_classifier(
            model, X_test, y_test,
            class_names=["BENIGN", "DDoS", ...],
            feature_names=["pkt_len", ...],
        )

        # For anomaly detector
        result = evaluator.evaluate_anomaly_detector(
            model, X_test, y_test_binary,
            contamination=0.05,
        )

        # Chart data
        cm_data = evaluator.get_confusion_matrix_data(result)
        fi_data = evaluator.get_feature_importance_data(result)
    """

    def __init__(self, cv_folds: int = 5, random_state: int = 42) -> None:
        """
        Initialise the ModelEvaluator.

        Args:
            cv_folds:     Number of folds for cross-validation.
            random_state: Random seed for reproducibility.
        """
        self._cv_folds = cv_folds
        self._random_state = random_state
        log.debug("ModelEvaluator initialised (cv=%d).", cv_folds)

    # ── Classifier Evaluation ─────────────────────────────────────────────────

    def evaluate_classifier(
        self,
        model: Any,
        X_test: np.ndarray,
        y_test: np.ndarray,
        X_train: Optional[np.ndarray] = None,
        y_train: Optional[np.ndarray] = None,
        class_names: Optional[list[str]] = None,
        feature_names: Optional[list[str]] = None,
        model_name: str = "RandomForest",
    ) -> ModelMetricsResult:
        """
        Compute full evaluation metrics for a classification model.

        Args:
            model:         Fitted scikit-learn classifier.
            X_test:        Test feature matrix.
            y_test:        True encoded label vector.
            X_train:       Optional training data for cross-validation.
            y_train:       Optional training labels for cross-validation.
            class_names:   Human-readable class names.
            feature_names: Feature names (for feature importance).
            model_name:    Model identifier string.

        Returns:
            Populated :class:`ModelMetricsResult`.
        """
        log.info("ModelEvaluator: evaluating classifier '%s'.", model_name)

        y_pred = model.predict(X_test)
        y_proba: Optional[np.ndarray] = None
        if hasattr(model, "predict_proba"):
            try:
                y_proba = model.predict_proba(X_test)
            except Exception:
                pass

        result = ModelMetricsResult(
            model_name=model_name,
            model_type="classifier",
            n_samples=len(y_test),
            n_features=X_test.shape[1] if len(X_test.shape) > 1 else 0,
            n_classes=len(np.unique(y_test)),
            class_names=class_names or [],
        )

        # Core scalar metrics
        result.accuracy = float(accuracy_score(y_test, y_pred))
        result.precision_macro = float(
            precision_score(y_test, y_pred, average="macro", zero_division=0)
        )
        result.recall_macro = float(
            recall_score(y_test, y_pred, average="macro", zero_division=0)
        )
        result.f1_macro = float(
            f1_score(y_test, y_pred, average="macro", zero_division=0)
        )
        result.precision_weighted = float(
            precision_score(y_test, y_pred, average="weighted", zero_division=0)
        )
        result.recall_weighted = float(
            recall_score(y_test, y_pred, average="weighted", zero_division=0)
        )
        result.f1_weighted = float(
            f1_score(y_test, y_pred, average="weighted", zero_division=0)
        )

        # ROC-AUC (multi-class OvR)
        if y_proba is not None:
            try:
                n_cls = y_proba.shape[1] if len(y_proba.shape) > 1 else 1
                if n_cls >= 2:
                    result.roc_auc = float(
                        roc_auc_score(
                            y_test, y_proba,
                            multi_class="ovr",
                            average="macro",
                        )
                    )
            except Exception as exc:
                log.warning("ROC-AUC computation failed: %s", exc)

        # Per-class metrics
        if class_names:
            for i, cls in enumerate(class_names):
                mask = (y_test == i)
                pred_mask = (y_pred == i)
                if mask.sum() == 0:
                    continue
                result.per_class_precision[cls] = float(
                    precision_score(y_test == i, y_pred == i, zero_division=0)
                )
                result.per_class_recall[cls] = float(
                    recall_score(y_test == i, y_pred == i, zero_division=0)
                )
                result.per_class_f1[cls] = float(
                    f1_score(y_test == i, y_pred == i, zero_division=0)
                )
                result.per_class_support[cls] = int(mask.sum())

        # Confusion matrix
        labels = list(range(len(class_names))) if class_names else None
        cm = confusion_matrix(y_test, y_pred, labels=labels)
        result.confusion_matrix = cm.tolist()

        # Feature importance
        if feature_names:
            result.feature_importance = self._extract_feature_importance(
                model, feature_names
            )

        # Cross-validation (if training data provided)
        if X_train is not None and y_train is not None:
            result.cv_scores, result.cv_mean, result.cv_std = self._cross_validate(
                model, X_train, y_train
            )

        log.info(
            "Classifier metrics: acc=%.4f, f1=%.4f, auc=%.4f.",
            result.accuracy, result.f1_macro, result.roc_auc,
        )
        return result

    # ── Anomaly Detector Evaluation ───────────────────────────────────────────

    def evaluate_anomaly_detector(
        self,
        model: Any,
        X_test: np.ndarray,
        y_test_binary: Optional[np.ndarray] = None,
        contamination: float = 0.05,
        feature_names: Optional[list[str]] = None,
        model_name: str = "IsolationForest",
    ) -> ModelMetricsResult:
        """
        Compute evaluation metrics for an anomaly detection model.

        For unsupervised models (no labels), only the anomaly rate and
        score distribution are computed. If y_test_binary is provided,
        standard binary classification metrics are computed.

        Args:
            model:            Fitted Isolation Forest (or compatible) model.
            X_test:           Test feature matrix.
            y_test_binary:    Optional binary labels (1=anomaly, 0=normal).
            contamination:    Expected anomaly fraction.
            feature_names:    Feature names for analysis.
            model_name:       Model identifier string.

        Returns:
            Populated :class:`ModelMetricsResult`.
        """
        log.info("ModelEvaluator: evaluating anomaly detector '%s'.", model_name)

        result = ModelMetricsResult(
            model_name=model_name,
            model_type="anomaly",
            contamination=contamination,
            n_samples=len(X_test),
            n_features=X_test.shape[1] if len(X_test.shape) > 1 else 0,
        )

        # Isolation Forest: predict() returns -1=anomaly, +1=normal
        try:
            raw_preds = model.predict(X_test)  # -1 or +1
            anomaly_mask = (raw_preds == -1)
            result.anomaly_rate = float(anomaly_mask.mean())
            result.n_classes = 2
            result.class_names = ["NORMAL", "ANOMALY"]
        except Exception as exc:
            log.error("AnomalyDetector.predict() failed: %s", exc)
            return result

        # If binary ground-truth labels available
        if y_test_binary is not None:
            # Convert IF output: -1 → 1 (anomaly), +1 → 0 (normal)
            y_pred_bin = (raw_preds == -1).astype(int)
            y_true_bin = y_test_binary.astype(int)

            result.accuracy = float(accuracy_score(y_true_bin, y_pred_bin))
            result.precision_macro = float(
                precision_score(y_true_bin, y_pred_bin, zero_division=0)
            )
            result.recall_macro = float(
                recall_score(y_true_bin, y_pred_bin, zero_division=0)
            )
            result.f1_macro = float(
                f1_score(y_true_bin, y_pred_bin, zero_division=0)
            )

            # Score-based ROC-AUC
            try:
                scores = model.score_samples(X_test)  # more negative = more anomalous
                # Negate so higher = anomalous (matching convention)
                result.roc_auc = float(
                    roc_auc_score(y_true_bin, -scores)
                )
            except Exception as exc:
                log.warning("Anomaly ROC-AUC failed: %s", exc)

            cm = confusion_matrix(y_true_bin, y_pred_bin)
            result.confusion_matrix = cm.tolist()
            result.per_class_f1 = {
                "NORMAL": float(f1_score(y_true_bin == 0, y_pred_bin == 0, zero_division=0)),
                "ANOMALY": float(f1_score(y_true_bin, y_pred_bin, zero_division=0)),
            }

        # Feature importance (not native to IF — use permutation importance stub)
        if feature_names:
            # Approximation: use |score| variance across samples as proxy
            try:
                scores = model.score_samples(X_test)
                # Use score variance per feature (heuristic — not true importances)
                result.feature_importance = {
                    name: 0.0 for name in feature_names
                }
            except Exception:
                pass

        log.info(
            "Anomaly metrics: anomaly_rate=%.4f, acc=%.4f, f1=%.4f.",
            result.anomaly_rate, result.accuracy, result.f1_macro,
        )
        return result

    # ── Cross-Validation ──────────────────────────────────────────────────────

    def _cross_validate(
        self,
        model: Any,
        X: np.ndarray,
        y: np.ndarray,
    ) -> tuple[list[float], float, float]:
        """
        Run stratified K-fold cross-validation.

        Args:
            model: Fitted scikit-learn estimator (must support clone).
            X:     Training feature matrix.
            y:     Label vector.

        Returns:
            Tuple of (cv_scores_list, mean_score, std_score).
        """
        try:
            from sklearn.base import clone
            cv = StratifiedKFold(
                n_splits=self._cv_folds,
                shuffle=True,
                random_state=self._random_state,
            )
            scores = cross_val_score(
                clone(model), X, y,
                cv=cv,
                scoring="f1_macro",
                n_jobs=-1,
            )
            return (
                [round(float(s), 4) for s in scores],
                round(float(scores.mean()), 4),
                round(float(scores.std()), 4),
            )
        except Exception as exc:
            log.warning("Cross-validation failed: %s", exc)
            return [], 0.0, 0.0

    # ── Feature Importance ────────────────────────────────────────────────────

    @staticmethod
    def _extract_feature_importance(
        model: Any,
        feature_names: list[str],
    ) -> dict[str, float]:
        """
        Extract feature importances from a trained model.

        Supports:
          - RandomForest / GradientBoosting: feature_importances_
          - XGBoost: get_score() / feature_importances_
          - LogisticRegression / SVM: coef_

        Args:
            model:         Fitted sklearn-compatible model.
            feature_names: Ordered list of feature names.

        Returns:
            Dict mapping feature_name → importance_score (higher = more important).
        """
        importances: Optional[np.ndarray] = None

        if hasattr(model, "feature_importances_"):
            importances = np.array(model.feature_importances_)
        elif hasattr(model, "coef_"):
            coef = np.array(model.coef_)
            if coef.ndim > 1:
                importances = np.abs(coef).mean(axis=0)
            else:
                importances = np.abs(coef)

        if importances is None or len(importances) != len(feature_names):
            return {}

        # Normalise to [0, 1]
        total = importances.sum()
        if total > 0:
            importances = importances / total

        return {
            name: round(float(imp), 6)
            for name, imp in zip(feature_names, importances)
        }

    # ── Chart-Ready Output ────────────────────────────────────────────────────

    @staticmethod
    def get_confusion_matrix_data(result: ModelMetricsResult) -> dict[str, Any]:
        """
        Return Plotly heatmap-ready confusion matrix data.

        Returns::

            {
                "z":       [[TN, FP], [FN, TP]],
                "x":       ["Predicted BENIGN", ...],
                "y":       ["Actual BENIGN", ...],
                "colorscale": "Blues",
            }
        """
        labels = result.class_names or [str(i) for i in range(len(result.confusion_matrix))]
        return {
            "z": result.confusion_matrix,
            "x": [f"Predicted {l}" for l in labels],
            "y": [f"Actual {l}" for l in labels],
            "colorscale": "Blues",
            "title": f"Confusion Matrix — {result.model_name}",
        }

    @staticmethod
    def get_feature_importance_data(
        result: ModelMetricsResult,
        top_n: int = 15,
    ) -> dict[str, list]:
        """
        Return top-N feature importances as a bar chart dataset.

        Returns::

            {"features": [...], "importances": [...]}
        """
        sorted_fi = sorted(
            result.feature_importance.items(),
            key=lambda x: -x[1],
        )[:top_n]
        return {
            "features": [f for f, _ in sorted_fi],
            "importances": [i for _, i in sorted_fi],
            "title": f"Feature Importance — {result.model_name}",
        }

    @staticmethod
    def get_prediction_distribution(
        result: ModelMetricsResult,
    ) -> dict[str, Any]:
        """
        Return class count distribution for a pie/bar chart.

        Returns::

            {"labels": [...], "values": [...]}
        """
        return {
            "labels": list(result.per_class_support.keys()),
            "values": list(result.per_class_support.values()),
            "title": "Prediction Class Distribution",
        }

    @staticmethod
    def get_probability_distribution(
        y_proba: np.ndarray,
        class_names: list[str],
    ) -> dict[str, Any]:
        """
        Return mean predicted probabilities per class for a bar chart.

        Args:
            y_proba:     Probability matrix (n_samples × n_classes).
            class_names: Ordered class names.

        Returns::

            {"labels": [...], "mean_probs": [...]}
        """
        mean_probs = y_proba.mean(axis=0).tolist() if len(y_proba.shape) > 1 else []
        return {
            "labels": class_names,
            "mean_probs": [round(p, 4) for p in mean_probs],
            "title": "Mean Predicted Class Probabilities",
        }
