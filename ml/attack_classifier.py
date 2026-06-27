"""
attack_classifier.py — Multi-Class Attack Classifier
=====================================================
Network Traffic Analysis and Intrusion Detection System

Implements a production-quality multi-class attack classifier supporting:
  - Model 1 (default): Random Forest Classifier
  - Model 2 (optional): XGBoost Classifier (if available)

Both models share a common :class:`BaseClassifier` interface, allowing
transparent swapping without changing downstream code.

Predicted Classes (matching config.ml.attack_labels):
  BENIGN | DDoS | PortScan | BruteForce | SYNFlood

The classifier integrates with the Phase 5 Rule Engine — ML predictions
supplement rule-based alerts with probability distributions and
confidence scores.

Classes:
    ClassificationResult — Dataclass holding a single classification output
    BaseClassifier       — Abstract classifier interface
    RandomForestClassifier — Random Forest implementation
    XGBoostClassifier    — XGBoost implementation (optional)
    AttackClassifier     — Unified facade that auto-selects best model

Author: Network Traffic Analyzer Project
Version: 6.0.0
Python: 3.11+
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from utils.config import config
from utils.logger import get_ml_logger

log = get_ml_logger()


# ──────────────────────────────────────────────────────────────────────────────
# CLASSIFICATION RESULT DATACLASS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ClassificationResult:
    """
    Holds the output of a single network traffic record classification.

    Attributes:
        predicted_label:  Predicted attack class string.
        predicted_index:  Encoded integer index of the predicted class.
        confidence:       Probability of the predicted class (0.0–1.0).
        class_probs:      Full probability distribution across all classes.
        inference_time_ms: Time taken for this inference in milliseconds.
        model_name:       Name of the model that made this prediction.
        supporting_features: Top-5 feature contributions (feature_name → value).
    """

    predicted_label: str
    predicted_index: int = 0
    confidence: float = 1.0
    class_probs: dict[str, float] = field(default_factory=dict)
    inference_time_ms: float = 0.0
    model_name: str = "Unknown"
    supporting_features: dict[str, float] = field(default_factory=dict)

    @property
    def is_attack(self) -> bool:
        """True if the predicted class is not BENIGN."""
        return self.predicted_label.upper() not in ("BENIGN", "NORMAL", "UNKNOWN")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict."""
        return {
            "predicted_label": self.predicted_label,
            "predicted_index": self.predicted_index,
            "confidence": round(self.confidence, 4),
            "class_probs": {k: round(v, 4) for k, v in self.class_probs.items()},
            "inference_time_ms": round(self.inference_time_ms, 3),
            "model_name": self.model_name,
            "is_attack": self.is_attack,
        }


# ──────────────────────────────────────────────────────────────────────────────
# BASE CLASSIFIER INTERFACE
# ──────────────────────────────────────────────────────────────────────────────

class BaseClassifier(abc.ABC):
    """
    Abstract base class for all attack classifiers.

    Defines the contract that all classifier implementations must satisfy,
    enabling transparent swapping of Random Forest ↔ XGBoost without
    changing downstream code.
    """

    @abc.abstractmethod
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: Optional[list[str]] = None,
        class_names: Optional[list[str]] = None,
    ) -> "BaseClassifier":
        """Fit the classifier on training data. Returns self."""
        ...

    @abc.abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict integer class labels for a batch."""
        ...

    @abc.abstractmethod
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class probability matrix (n_samples × n_classes)."""
        ...

    @abc.abstractmethod
    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        feature_names: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Compute and return a metrics dictionary."""
        ...

    @property
    @abc.abstractmethod
    def is_loaded(self) -> bool:
        """True if the model is trained / loaded from disk."""
        ...

    @property
    @abc.abstractmethod
    def model_name(self) -> str:
        """Human-readable model name."""
        ...


# ──────────────────────────────────────────────────────────────────────────────
# RANDOM FOREST CLASSIFIER
# ──────────────────────────────────────────────────────────────────────────────

class RandomForestClassifierModel(BaseClassifier):
    """
    Multi-class attack classifier backed by scikit-learn RandomForestClassifier.

    Automatically tunes n_estimators and max_depth from config.
    """

    def __init__(
        self,
        n_estimators: int = 300,
        max_depth: Optional[int] = 20,
        min_samples_split: int = 2,
        min_samples_leaf: int = 1,
        random_state: int = 42,
        n_jobs: int = -1,
    ) -> None:
        from sklearn.ensemble import RandomForestClassifier as _RFC
        self._model = _RFC(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            random_state=random_state,
            n_jobs=n_jobs,
            class_weight="balanced",   # Handle any residual imbalance
        )
        self._is_loaded: bool = False
        self._feature_names: list[str] = []
        self._class_names: list[str] = []
        log.debug("RandomForestClassifierModel initialised.")

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def model_name(self) -> str:
        return "RandomForestClassifier"

    @property
    def model(self) -> Any:
        return self._model

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: Optional[list[str]] = None,
        class_names: Optional[list[str]] = None,
    ) -> "RandomForestClassifierModel":
        """
        Fit the Random Forest on training data.

        Args:
            X_train:       Training feature matrix.
            y_train:       Encoded integer label vector.
            feature_names: Optional feature names for importance extraction.
            class_names:   Optional class name list.

        Returns:
            self (for method chaining).
        """
        log.info(
            "RandomForestClassifier.train(): X=%s, classes=%d.",
            X_train.shape, len(np.unique(y_train)),
        )
        t0 = time.perf_counter()
        self._model.fit(X_train, y_train)
        elapsed = time.perf_counter() - t0
        self._feature_names = feature_names or []
        self._class_names = class_names or []
        self._is_loaded = True
        log.info("RandomForestClassifier: trained in %.3fs.", elapsed)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict integer class indices."""
        if not self._is_loaded:
            return np.zeros(len(X), dtype=int)
        return self._model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class probability matrix (n_samples × n_classes)."""
        if not self._is_loaded:
            n = len(X)
            n_cls = max(len(self._class_names), 2)
            result = np.zeros((n, n_cls), dtype=np.float32)
            result[:, 0] = 1.0
            return result
        return self._model.predict_proba(X).astype(np.float32)

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        feature_names: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Compute full classification metrics."""
        from ml.metrics import ModelEvaluator
        evaluator = ModelEvaluator()
        result = evaluator.evaluate_classifier(
            model=self._model,
            X_test=X_test,
            y_test=y_test,
            class_names=self._class_names,
            feature_names=feature_names or self._feature_names,
            model_name=self.model_name,
        )
        return result.to_dict()


# ──────────────────────────────────────────────────────────────────────────────
# XGBOOST CLASSIFIER (OPTIONAL)
# ──────────────────────────────────────────────────────────────────────────────

class XGBoostClassifierModel(BaseClassifier):
    """
    Multi-class attack classifier backed by XGBoost.

    Falls back gracefully if xgboost is not installed — callers should
    check ``is_available()`` before instantiating.
    """

    @staticmethod
    def is_available() -> bool:
        """Return True if xgboost is importable."""
        try:
            import xgboost  # noqa: F401
            return True
        except ImportError:
            return False

    def __init__(
        self,
        n_estimators: int = 300,
        max_depth: int = 8,
        learning_rate: float = 0.05,
        subsample: float = 0.8,
        colsample_bytree: float = 0.8,
        random_state: int = 42,
        n_jobs: int = -1,
        use_gpu: bool = False,
    ) -> None:
        if not self.is_available():
            raise ImportError(
                "xgboost is not installed. Install it with: pip install xgboost"
            )
        import xgboost as xgb
        self._model = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            subsample=subsample,
            colsample_bytree=colsample_bytree,
            random_state=random_state,
            n_jobs=n_jobs,
            eval_metric="mlogloss",
            verbosity=0,
            use_label_encoder=False,
        )
        self._is_loaded: bool = False
        self._feature_names: list[str] = []
        self._class_names: list[str] = []
        log.debug("XGBoostClassifierModel initialised.")

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def model_name(self) -> str:
        return "XGBoostClassifier"

    @property
    def model(self) -> Any:
        return self._model

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: Optional[list[str]] = None,
        class_names: Optional[list[str]] = None,
    ) -> "XGBoostClassifierModel":
        log.info(
            "XGBoostClassifier.train(): X=%s, classes=%d.",
            X_train.shape, len(np.unique(y_train)),
        )
        t0 = time.perf_counter()
        self._model.fit(X_train, y_train)
        elapsed = time.perf_counter() - t0
        self._feature_names = feature_names or []
        self._class_names = class_names or []
        self._is_loaded = True
        log.info("XGBoostClassifier: trained in %.3fs.", elapsed)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self._is_loaded:
            return np.zeros(len(X), dtype=int)
        return self._model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self._is_loaded:
            n = len(X)
            n_cls = max(len(self._class_names), 2)
            result = np.zeros((n, n_cls), dtype=np.float32)
            result[:, 0] = 1.0
            return result
        return self._model.predict_proba(X).astype(np.float32)

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        feature_names: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        from ml.metrics import ModelEvaluator
        evaluator = ModelEvaluator()
        result = evaluator.evaluate_classifier(
            model=self._model,
            X_test=X_test,
            y_test=y_test,
            class_names=self._class_names,
            feature_names=feature_names or self._feature_names,
            model_name=self.model_name,
        )
        return result.to_dict()


# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CLASSIFIER FACADE
# ──────────────────────────────────────────────────────────────────────────────

class AttackClassifier:
    """
    Unified multi-class attack classification facade.

    Wraps either a Random Forest or XGBoost classifier behind a single
    consistent API. XGBoost is used automatically when available and
    when ``prefer_xgboost=True`` (default).

    The classifier performs:
      - Single-record classification → :class:`ClassificationResult`
      - Batch classification
      - Confidence-scored probability distribution across all attack classes
      - Evidence-based supporting feature extraction

    Attributes:
        model:            The underlying :class:`BaseClassifier` instance.
        label_encoder:    Fitted LabelEncoder for label ↔ index conversion.
        is_loaded (bool): True after train() or load() succeeds.
        classified_count: Total records classified since initialisation.

    Usage::

        clf = AttackClassifier(prefer_xgboost=True)
        clf.train(X_train, y_train, feature_names=names, class_names=classes)
        clf.save()

        result = clf.classify(feature_vector)
        print(result.predicted_label, result.confidence)
    """

    def __init__(
        self,
        prefer_xgboost: bool = True,
        model_path: Optional[Path] = None,
        label_encoder: Optional[LabelEncoder] = None,
        feature_names: Optional[list[str]] = None,
    ) -> None:
        """
        Initialise the AttackClassifier.

        Args:
            prefer_xgboost: Use XGBoost if available; else Random Forest.
            model_path:     Path for model persistence.
            label_encoder:  Pre-fitted LabelEncoder.
            feature_names:  Feature names for the classifier.
        """
        self.model_path: Path = model_path or config.paths.classifier_model_path
        self.label_encoder: LabelEncoder = label_encoder or LabelEncoder()
        self._feature_names: list[str] = feature_names or []
        self._classes: list[str] = list(config.ml.attack_labels)
        self.classified_count: int = 0

        # Select backend
        if prefer_xgboost and XGBoostClassifierModel.is_available():
            self._clf: BaseClassifier = XGBoostClassifierModel(
                n_estimators=300,
                max_depth=8,
                learning_rate=0.05,
                random_state=config.ml.rf_random_state,
            )
            log.info("AttackClassifier: using XGBoost backend.")
        else:
            self._clf = RandomForestClassifierModel(
                n_estimators=300,
                max_depth=20,
                min_samples_split=2,
                random_state=config.ml.rf_random_state,
                n_jobs=config.ml.rf_n_jobs,
            )
            log.info("AttackClassifier: using RandomForest backend.")

        log.debug("AttackClassifier initialised (%s).", self._clf.model_name)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_loaded(self) -> bool:
        return self._clf.is_loaded

    @property
    def model(self) -> Any:
        """Return the underlying sklearn/XGBoost model object."""
        return getattr(self._clf, "_model", None)

    # ── Training ──────────────────────────────────────────────────────────────

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Return class probability matrix (n_samples × n_classes).

        Args:
            X: Feature matrix (n_samples × n_features).

        Returns:
            Float32 array (n_samples × n_classes).
        """
        return self._clf.predict_proba(X)

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: Optional[list[str]] = None,
        class_names: Optional[list[str]] = None,
        label_encoder: Optional[LabelEncoder] = None,
    ) -> "AttackClassifier":
        """
        Fit the classifier on training data.

        Args:
            X_train:       Feature matrix.
            y_train:       Encoded integer label vector.
            feature_names: Feature names (for importance extraction).
            class_names:   Human-readable class names.
            label_encoder: Fitted LabelEncoder (for label ↔ index mapping).

        Returns:
            self (for method chaining).
        """
        if feature_names:
            self._feature_names = feature_names
        if class_names:
            self._classes = class_names
        if label_encoder:
            self.label_encoder = label_encoder

        self._clf.train(
            X_train, y_train,
            feature_names=self._feature_names,
            class_names=self._classes,
        )
        return self

    # ── Inference ─────────────────────────────────────────────────────────────

    def classify(
        self,
        feature_vector: np.ndarray,
        feature_names: Optional[list[str]] = None,
    ) -> ClassificationResult:
        """
        Classify a single traffic record feature vector.

        Args:
            feature_vector: 1-D float32 array of length n_features.
            feature_names:  Optional feature names for evidence extraction.

        Returns:
            :class:`ClassificationResult` with predicted label, confidence,
            and full class probability distribution.
        """
        t0 = time.perf_counter()

        if not self._clf.is_loaded:
            return ClassificationResult(
                predicted_label="BENIGN",
                confidence=1.0,
                class_probs={cls: 0.0 for cls in self._classes},
                model_name=self._clf.model_name,
            )

        X = feature_vector.reshape(1, -1)
        pred_idx = int(self._clf.predict(X)[0])
        proba = self._clf.predict_proba(X)[0]

        # Decode label
        try:
            pred_label = self.label_encoder.inverse_transform([pred_idx])[0]
        except Exception:
            pred_label = self._classes[pred_idx] if pred_idx < len(self._classes) else "UNKNOWN"

        # Build class probability dict
        class_probs: dict[str, float] = {}
        for i, name in enumerate(self._classes):
            if i < len(proba):
                class_probs[name] = round(float(proba[i]), 4)

        confidence = float(proba[pred_idx]) if pred_idx < len(proba) else 0.0
        elapsed_ms = (time.perf_counter() - t0) * 1000
        self.classified_count += 1

        # Top feature evidence
        names = feature_names or self._feature_names
        supporting: dict[str, float] = {}
        if names and len(names) == len(feature_vector):
            ranked = sorted(
                zip(names, np.abs(feature_vector)),
                key=lambda x: -x[1],
            )[:5]
            supporting = {k: round(float(v), 4) for k, v in ranked}

        return ClassificationResult(
            predicted_label=str(pred_label),
            predicted_index=pred_idx,
            confidence=round(confidence, 4),
            class_probs=class_probs,
            inference_time_ms=round(elapsed_ms, 3),
            model_name=self._clf.model_name,
            supporting_features=supporting,
        )

    def classify_batch(
        self,
        X: np.ndarray,
        feature_names: Optional[list[str]] = None,
    ) -> list[ClassificationResult]:
        """
        Classify a batch of feature vectors.

        Args:
            X:             Feature matrix (n_samples × n_features).
            feature_names: Optional feature names.

        Returns:
            List of :class:`ClassificationResult` instances.
        """
        if not self._clf.is_loaded or len(X) == 0:
            return [
                ClassificationResult(
                    predicted_label="BENIGN",
                    confidence=1.0,
                    model_name=self._clf.model_name,
                )
                for _ in range(len(X))
            ]

        t0 = time.perf_counter()
        preds = self._clf.predict(X)
        probas = self._clf.predict_proba(X)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        per_record_ms = elapsed_ms / max(len(X), 1)

        results: list[ClassificationResult] = []
        for i, (pred_idx, proba) in enumerate(zip(preds, probas)):
            pred_idx = int(pred_idx)
            try:
                pred_label = self.label_encoder.inverse_transform([pred_idx])[0]
            except Exception:
                pred_label = (
                    self._classes[pred_idx]
                    if pred_idx < len(self._classes)
                    else "UNKNOWN"
                )

            class_probs = {
                name: round(float(proba[j]), 4)
                for j, name in enumerate(self._classes)
                if j < len(proba)
            }
            confidence = float(proba[pred_idx]) if pred_idx < len(proba) else 0.0

            results.append(ClassificationResult(
                predicted_label=str(pred_label),
                predicted_index=pred_idx,
                confidence=round(confidence, 4),
                class_probs=class_probs,
                inference_time_ms=round(per_record_ms, 3),
                model_name=self._clf.model_name,
            ))

        self.classified_count += len(results)
        return results

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        X_train: Optional[np.ndarray] = None,
        y_train: Optional[np.ndarray] = None,
        feature_names: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """
        Compute full evaluation metrics.

        Args:
            X_test:   Test feature matrix.
            y_test:   True integer label vector.
            X_train:  Training data for cross-validation (optional).
            y_train:  Training labels for cross-validation (optional).
            feature_names: Feature names.

        Returns:
            JSON-serialisable metrics dictionary.
        """
        from ml.metrics import ModelEvaluator
        evaluator = ModelEvaluator()
        result = evaluator.evaluate_classifier(
            model=self.model,
            X_test=X_test,
            y_test=y_test,
            X_train=X_train,
            y_train=y_train,
            class_names=self._classes,
            feature_names=feature_names or self._feature_names,
            model_name=self._clf.model_name,
        )
        return result.to_dict()

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> None:
        """
        Persist the fitted classifier to disk.

        Args:
            path: Override save path.
        """
        if not self._clf.is_loaded:
            log.warning("AttackClassifier.save(): model not trained yet.")
            return
        import joblib
        save_path = path or self.model_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "label_encoder": self.label_encoder,
                "feature_names": self._feature_names,
                "class_names": self._classes,
                "backend": self._clf.model_name,
            },
            save_path, compress=3,
        )
        log.info("AttackClassifier: saved to %s.", save_path)

    def load(self, path: Optional[Path] = None) -> bool:
        """
        Load a serialised classifier from disk.

        Args:
            path: Override load path.

        Returns:
            True if successfully loaded; False otherwise.
        """
        import joblib
        load_path = path or self.model_path
        if not load_path.exists():
            log.warning("AttackClassifier.load(): file not found: %s", load_path)
            return False

        try:
            data = joblib.load(load_path)
            if isinstance(data, dict):
                raw_model = data["model"]
                self.label_encoder = data.get("label_encoder", self.label_encoder)
                self._feature_names = data.get("feature_names", [])
                self._classes = data.get("class_names", self._classes)
                backend = data.get("backend", "")
            else:
                raw_model = data

            # Wrap raw model in appropriate backend
            backend_name = getattr(raw_model, "__class__", type(raw_model)).__name__
            if "XGB" in backend_name and XGBoostClassifierModel.is_available():
                self._clf = XGBoostClassifierModel()
                self._clf._model = raw_model
                self._clf._is_loaded = True
                self._clf._feature_names = self._feature_names
                self._clf._class_names = self._classes
            else:
                self._clf = RandomForestClassifierModel()
                self._clf._model = raw_model
                self._clf._is_loaded = True
                self._clf._feature_names = self._feature_names
                self._clf._class_names = self._classes

            log.info("AttackClassifier: loaded from %s (%s).", load_path, backend_name)
            return True
        except Exception as exc:
            log.error("AttackClassifier.load() failed: %s", exc)
            return False

    def __repr__(self) -> str:
        return (
            f"AttackClassifier("
            f"backend={self._clf.model_name}, "
            f"is_loaded={self.is_loaded}, "
            f"classified={self.classified_count})"
        )
