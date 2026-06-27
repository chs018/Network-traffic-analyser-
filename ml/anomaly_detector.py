"""
anomaly_detector.py — Isolation Forest Anomaly Detection
=========================================================
Network Traffic Analysis and Intrusion Detection System

Fully implements the Phase 1 AnomalyDetector stub using a trained
Isolation Forest model for online and batch network traffic anomaly detection.

The anomaly detector assigns each record:
  - A continuous anomaly score (lower = more anomalous)
  - A binary label: "ANOMALY" | "NORMAL"
  - A confidence value (0.0–1.0)

Integration with Phase 5 Rule Engine:
  Flagged records are enriched with anomaly_score and passed alongside
  rule-based SecurityAlert objects for combined analysis.

Classes:
    AnomalyResult   — Dataclass for a single anomaly scoring result
    AnomalyDetector — Isolation Forest inference wrapper (Phase 6 — fully implemented)

Author: Network Traffic Analyzer Project
Version: 6.0.0
Python: 3.11+
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd

from utils.config import config
from utils.helpers import utc_now_iso
from utils.logger import get_ml_logger

log = get_ml_logger()


# ──────────────────────────────────────────────────────────────────────────────
# ANOMALY RESULT DATACLASS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AnomalyResult:
    """
    Holds the output of an anomaly scoring operation.

    Attributes:
        score:      Raw Isolation Forest score (more negative = more anomalous).
        label:      "ANOMALY" or "NORMAL".
        confidence: Confidence in the label (0.0–1.0).
        is_anomaly: Convenience flag (True if label == "ANOMALY").
        timestamp:  ISO-8601 timestamp of the scoring.
    """

    score: float
    label: str
    confidence: float
    is_anomaly: bool = False
    timestamp: str = field(default_factory=utc_now_iso)
    inference_time_ms: float = 0.0
    supporting_features: dict[str, float] = field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# ANOMALY DETECTOR
# ──────────────────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Online anomaly detector backed by a trained Isolation Forest.

    Provides:
      - train()        — Fit Isolation Forest on unlabelled feature matrix
      - predict()      — Predict -1 (anomaly) / +1 (normal) for batch
      - predict_proba()— Return calibrated anomaly probabilities
      - score()        — Per-sample anomaly score (continuous)
      - score_batch()  — Batch anomaly scoring
      - classify()     — Convert score → binary label
      - evaluate()     — Compute binary classification metrics on labelled data
      - save()         — Persist trained model via ModelManager
      - load()         — Lazy-load model from disk

    Attributes:
        model:           Fitted IsolationForest instance (None if not loaded).
        is_loaded (bool): True after train() or load() succeeds.
        scored_count (int): Total records scored since initialisation.
        threshold (float): Score threshold for anomaly classification.
    """

    LABEL_ANOMALY: str = "ANOMALY"
    LABEL_NORMAL: str  = "NORMAL"

    def __init__(
        self,
        model_path: Optional[Path] = None,
        threshold: float = 0.0,
        contamination: float = 0.05,
        n_estimators: int = 200,
        random_state: int = 42,
    ) -> None:
        """
        Initialise the AnomalyDetector.

        Args:
            model_path:    Path to a serialised IsolationForest. Defaults to
                           ``config.paths.anomaly_model_path``.
            threshold:     Score threshold below which a sample is ANOMALY.
                           Isolation Forest raw scores are typically in (−0.5, 0.5).
                           Default 0.0 uses the sign of the score.
            contamination: Expected fraction of anomalies (for IF training).
            n_estimators:  Number of trees in the Isolation Forest.
            random_state:  Random seed for reproducibility.
        """
        self.model_path: Path = model_path or config.paths.anomaly_model_path
        self.threshold = threshold
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self.model: Optional[Any] = None
        self.is_loaded: bool = False
        self.scored_count: int = 0
        self._n_features: int = 0
        self._feature_names: list[str] = []
        self._train_score_mean: float = 0.0
        self._train_score_std: float = 1.0

        log.debug(
            "AnomalyDetector initialised (contamination=%.3f, n_estimators=%d).",
            contamination, n_estimators,
        )

    # ── Training ──────────────────────────────────────────────────────────────

    def train(
        self,
        X_train: np.ndarray,
        feature_names: Optional[list[str]] = None,
        contamination: Optional[float] = None,
    ) -> "AnomalyDetector":
        """
        Fit an Isolation Forest on unlabelled training data.

        Args:
            X_train:       Training feature matrix (n_samples × n_features).
            feature_names: Optional feature name list.
            contamination: Override contamination parameter.

        Returns:
            self (for method chaining).
        """
        from sklearn.ensemble import IsolationForest

        cont = contamination if contamination is not None else self.contamination
        cont = max(0.001, min(0.499, cont))  # sklearn range constraint

        log.info(
            "AnomalyDetector.train(): fitting on X=%s, contamination=%.3f.",
            X_train.shape, cont,
        )
        t0 = time.perf_counter()

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=cont,
            max_samples="auto",
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_train)

        # Compute training score statistics for confidence calibration
        train_scores = self.model.score_samples(X_train)
        self._train_score_mean = float(train_scores.mean())
        self._train_score_std = max(float(train_scores.std()), 1e-9)

        elapsed = time.perf_counter() - t0
        self._n_features = X_train.shape[1]
        self._feature_names = feature_names or []
        self.is_loaded = True

        log.info(
            "AnomalyDetector: trained in %.3fs. "
            "Score μ=%.4f, σ=%.4f.",
            elapsed, self._train_score_mean, self._train_score_std,
        )
        return self

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly labels for a batch.

        Args:
            X: Feature matrix (n_samples × n_features).

        Returns:
            1-D int array: -1 for anomaly, +1 for normal.
        """
        if not self.is_loaded or self.model is None:
            return np.ones(len(X), dtype=int)  # Default: all normal
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Return calibrated anomaly probabilities.

        Uses a sigmoid calibration on the raw Isolation Forest scores
        to produce probabilities in [0, 1] where 1 = certainly anomalous.

        Args:
            X: Feature matrix (n_samples × n_features).

        Returns:
            2-D float array (n_samples × 2): columns = [P(normal), P(anomaly)].
        """
        if not self.is_loaded or self.model is None:
            normal = np.ones((len(X), 2), dtype=np.float32)
            normal[:, 0] = 1.0
            normal[:, 1] = 0.0
            return normal

        raw_scores = self.model.score_samples(X)
        # Negate: more negative raw score → more anomalous → higher proba
        z = -(raw_scores - self._train_score_mean) / self._train_score_std
        proba_anomaly = 1.0 / (1.0 + np.exp(-z))           # sigmoid
        proba_normal = 1.0 - proba_anomaly
        return np.column_stack([proba_normal, proba_anomaly]).astype(np.float32)

    def score(self, feature_vector: np.ndarray) -> float:
        """
        Compute an anomaly score for a single feature vector.

        Args:
            feature_vector: 1-D float32 array of length n_features.

        Returns:
            Anomaly score. More negative = more anomalous.
            Returns 0.0 if the model is not loaded.
        """
        if not self.is_loaded or self.model is None:
            return 0.0
        self.scored_count += 1
        return float(
            self.model.score_samples(feature_vector.reshape(1, -1))[0]
        )

    def score_batch(self, X: np.ndarray) -> np.ndarray:
        """
        Score a batch of feature vectors.

        Args:
            X: Feature matrix (n_samples × n_features).

        Returns:
            1-D float32 array of anomaly scores, shape (n_samples,).
        """
        if not self.is_loaded or self.model is None or X.shape[0] == 0:
            return np.zeros(X.shape[0] if len(X.shape) > 0 else 0, dtype=np.float32)
        self.scored_count += X.shape[0]
        return self.model.score_samples(X).astype(np.float32)

    def score_record(
        self,
        feature_vector: np.ndarray,
        feature_names: Optional[list[str]] = None,
    ) -> AnomalyResult:
        """
        Score a single record and return a rich AnomalyResult.

        Args:
            feature_vector: 1-D float32 feature array.
            feature_names:  Optional feature name list for evidence.

        Returns:
            :class:`AnomalyResult` with score, label, confidence, and evidence.
        """
        t0 = time.perf_counter()
        raw_score = self.score(feature_vector)
        label = self.classify(raw_score)
        proba = self.predict_proba(feature_vector.reshape(1, -1))[0]
        confidence = float(proba[1]) if label == self.LABEL_ANOMALY else float(proba[0])
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Top contributing features (absolute value of normalised feature)
        supporting: dict[str, float] = {}
        if feature_names and len(feature_names) == len(feature_vector):
            ranked = sorted(
                zip(feature_names, np.abs(feature_vector)),
                key=lambda x: -x[1],
            )[:5]
            supporting = {k: round(float(v), 4) for k, v in ranked}

        return AnomalyResult(
            score=round(raw_score, 6),
            label=label,
            confidence=round(confidence, 4),
            is_anomaly=(label == self.LABEL_ANOMALY),
            inference_time_ms=round(elapsed_ms, 3),
            supporting_features=supporting,
        )

    def classify(self, score: float, threshold: Optional[float] = None) -> str:
        """
        Convert a raw anomaly score to a binary label.

        Args:
            score:     Anomaly score from :meth:`score`.
            threshold: Override classification threshold.

        Returns:
            "ANOMALY" or "NORMAL".
        """
        t = threshold if threshold is not None else self.threshold
        # For Isolation Forest: score_samples returns negative → more anomalous
        # IF.predict uses the offset internally; here we use raw score
        if self.is_loaded and self.model is not None:
            # Use the model's own decision function for consistency
            return (
                self.LABEL_ANOMALY
                if score < self.model.offset_  # type: ignore[union-attr]
                else self.LABEL_NORMAL
            )
        return self.LABEL_ANOMALY if score < t else self.LABEL_NORMAL

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test_binary: Optional[np.ndarray] = None,
        feature_names: Optional[list[str]] = None,
    ) -> dict:
        """
        Evaluate the trained model on test data.

        Args:
            X_test:          Test feature matrix.
            y_test_binary:   Optional binary labels (1=anomaly, 0=normal).
            feature_names:   Feature names for the evaluator.

        Returns:
            Dictionary of metrics (from :class:`ModelEvaluator`).
        """
        from ml.metrics import ModelEvaluator
        evaluator = ModelEvaluator()
        result = evaluator.evaluate_anomaly_detector(
            model=self.model,
            X_test=X_test,
            y_test_binary=y_test_binary,
            contamination=self.contamination,
            feature_names=feature_names or self._feature_names,
            model_name="IsolationForest",
        )
        return result.to_dict()

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> None:
        """
        Persist the fitted model to disk.

        Args:
            path: Override save path (defaults to config.paths.anomaly_model_path).
        """
        if not self.is_loaded or self.model is None:
            log.warning("AnomalyDetector.save(): model not trained yet.")
            return

        save_path = path or self.model_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        import joblib
        joblib.dump(
            {
                "model": self.model,
                "threshold": self.threshold,
                "contamination": self.contamination,
                "n_features": self._n_features,
                "feature_names": self._feature_names,
                "train_score_mean": self._train_score_mean,
                "train_score_std": self._train_score_std,
            },
            save_path, compress=3,
        )
        log.info("AnomalyDetector: saved to %s.", save_path)

    def load(self, path: Optional[Path] = None) -> bool:
        """
        Load a serialised model from disk.

        Args:
            path: Override load path (defaults to config.paths.anomaly_model_path).

        Returns:
            True if successfully loaded; False otherwise.
        """
        load_path = path or self.model_path
        if not load_path.exists():
            log.warning("AnomalyDetector.load(): file not found: %s", load_path)
            return False

        try:
            import joblib
            data = joblib.load(load_path)
            # Support both raw model and dict format
            if isinstance(data, dict):
                self.model = data["model"]
                self.threshold = data.get("threshold", self.threshold)
                self.contamination = data.get("contamination", self.contamination)
                self._n_features = data.get("n_features", 0)
                self._feature_names = data.get("feature_names", [])
                self._train_score_mean = data.get("train_score_mean", 0.0)
                self._train_score_std = data.get("train_score_std", 1.0)
            else:
                self.model = data
            self.is_loaded = True
            log.info("AnomalyDetector: loaded from %s.", load_path)
            return True
        except Exception as exc:
            log.error("AnomalyDetector.load() failed: %s", exc)
            return False

    def __repr__(self) -> str:
        return (
            f"AnomalyDetector("
            f"is_loaded={self.is_loaded}, "
            f"scored_count={self.scored_count}, "
            f"contamination={self.contamination})"
        )
