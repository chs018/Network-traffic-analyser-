"""
model_manager.py — ML Model Lifecycle Manager
===============================================
Network Traffic Analysis and Intrusion Detection System

Manages the complete lifecycle of trained ML models:
  - Save / load models with joblib serialisation
  - Model versioning (incremental v1, v2, v3 ...)
  - Lazy loading (load on first use)
  - Model existence checks
  - Metadata persistence to database and JSON
  - Active model promotion and registry

Model File Layout (models/ directory):
  isolation_forest.pkl     — Current active anomaly model
  random_forest.pkl        — Current active classifier
  preprocessor_scaler.pkl  — Fitted StandardScaler
  label_encoder.pkl        — Fitted LabelEncoder
  metadata.json            — Registry of all models and their metrics

Classes:
    ModelInfo     — Metadata dataclass for a single model version
    ModelManager  — Lifecycle manager (save / load / version / metadata)

Author: Network Traffic Analyzer Project
Version: 6.0.0
Python: 3.11+
"""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import joblib

from database.db_manager import DatabaseManager, ModelMetadata
from utils.config import config
from utils.helpers import utc_now_iso
from utils.logger import get_ml_logger

log = get_ml_logger()


# ──────────────────────────────────────────────────────────────────────────────
# MODEL INFO DATACLASS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ModelInfo:
    """
    Metadata for a single trained model version.

    Stored in the metadata.json registry and optionally in the database.
    """

    model_key: str          # Canonical key: "isolation_forest" | "random_forest"
    model_name: str         # Human-readable: "IsolationForest_v3"
    model_type: str         # "anomaly" | "classifier"
    file_path: str          # Absolute path to .pkl file
    trained_at: str         # ISO-8601 training timestamp
    version: int = 1        # Auto-incremented version
    is_active: bool = False  # True for currently deployed model
    accuracy: float = 0.0
    f1_score: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    roc_auc: float = 0.0
    n_samples: int = 0
    n_features: int = 0
    feature_names: list[str] = field(default_factory=list)
    class_names: list[str] = field(default_factory=list)
    hyperparameters: dict[str, Any] = field(default_factory=dict)
    notes: str = ""


# ──────────────────────────────────────────────────────────────────────────────
# MODEL MANAGER
# ──────────────────────────────────────────────────────────────────────────────

class ModelManager:
    """
    Manages the complete lifecycle of Phase 6 ML models.

    Provides:
      - save()       — Serialise a fitted model with versioning
      - load()       — Lazy-load a model from disk (caches in memory)
      - exists()     — Check if a model file is present
      - promote()    — Mark a version as the active production model
      - register()   — Record model metadata in JSON and database
      - list_models()— Return all registered model versions

    All loaded models are cached in ``_model_cache`` to avoid repeated
    disk I/O during inference.

    Usage::

        mm = ModelManager(db_manager=db)
        mm.save(fitted_rf, "random_forest", metrics=result)
        mm.save(fitted_if, "isolation_forest", metrics=result)

        rf = mm.load("random_forest")
        if_model = mm.load("isolation_forest")
    """

    # Canonical file names for active models
    _CANONICAL_NAMES: dict[str, str] = {
        "isolation_forest":  "isolation_forest.pkl",
        "random_forest":     "random_forest.pkl",
        "xgboost":           "xgboost.pkl",
        "preprocessor":      "preprocessor_scaler.pkl",
        "label_encoder":     "label_encoder.pkl",
    }

    def __init__(
        self,
        models_dir: Optional[Path] = None,
        db_manager: Optional[DatabaseManager] = None,
    ) -> None:
        """
        Initialise the ModelManager.

        Args:
            models_dir: Directory to store model files (defaults to models/).
            db_manager: Optional DatabaseManager for metadata persistence.
        """
        self._dir: Path = models_dir or config.paths.models_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._db: Optional[DatabaseManager] = db_manager
        self._metadata_path: Path = self._dir / "metadata.json"
        self._model_cache: dict[str, Any] = {}
        self._registry: dict[str, list[ModelInfo]] = self._load_registry()
        log.debug("ModelManager initialised. Models dir: %s", self._dir)

    # ── Save ──────────────────────────────────────────────────────────────────

    def save(
        self,
        model: Any,
        model_key: str,
        metrics: Optional[Any] = None,       # ModelMetricsResult
        feature_names: Optional[list[str]] = None,
        class_names: Optional[list[str]] = None,
        hyperparameters: Optional[dict[str, Any]] = None,
        notes: str = "",
    ) -> ModelInfo:
        """
        Serialise a trained model to disk and register its metadata.

        The model is saved to both a versioned file and the canonical
        active file (e.g., ``random_forest.pkl``).

        Args:
            model:            Fitted scikit-learn / XGBoost estimator.
            model_key:        Canonical model key (e.g. "random_forest").
            metrics:          Optional :class:`ModelMetricsResult` for storing metrics.
            feature_names:    List of feature names used during training.
            class_names:      List of class names.
            hyperparameters:  Dict of model hyperparameters.
            notes:            Optional analyst notes.

        Returns:
            :class:`ModelInfo` with the registered metadata.
        """
        if not model_key:
            raise ValueError("model_key must be a non-empty string.")

        # Determine version
        existing = self._registry.get(model_key, [])
        version = max((m.version for m in existing), default=0) + 1

        # Determine file name
        canonical_name = self._CANONICAL_NAMES.get(model_key, f"{model_key}.pkl")
        versioned_name = f"{model_key}_v{version}.pkl"

        canonical_path = self._dir / canonical_name
        versioned_path = self._dir / versioned_name

        # Save canonical (overwrite active)
        joblib.dump(model, canonical_path, compress=3)
        # Save versioned backup
        shutil.copy2(canonical_path, versioned_path)

        # Determine model type
        model_type = "anomaly" if "forest" in type(model).__name__.lower() and \
            "isolation" in type(model).__name__.lower() else "classifier"
        if "isolation" in model_key.lower():
            model_type = "anomaly"
        elif model_key in ("random_forest", "xgboost"):
            model_type = "classifier"

        # Build ModelInfo
        info = ModelInfo(
            model_key=model_key,
            model_name=f"{model_key.replace('_', ' ').title()}_v{version}",
            model_type=model_type,
            file_path=str(canonical_path.resolve()),
            trained_at=utc_now_iso(),
            version=version,
            is_active=True,
            feature_names=feature_names or [],
            class_names=class_names or [],
            hyperparameters=hyperparameters or self._extract_params(model),
            notes=notes,
        )

        # Populate metrics fields
        if metrics is not None:
            info.accuracy = getattr(metrics, "accuracy", 0.0)
            info.f1_score = getattr(metrics, "f1_macro", 0.0)
            info.precision = getattr(metrics, "precision_macro", 0.0)
            info.recall = getattr(metrics, "recall_macro", 0.0)
            info.roc_auc = getattr(metrics, "roc_auc", 0.0)
            info.n_samples = getattr(metrics, "n_samples", 0)
            info.n_features = getattr(metrics, "n_features", 0)

        # Deactivate previous versions
        for prev in self._registry.get(model_key, []):
            prev.is_active = False

        if model_key not in self._registry:
            self._registry[model_key] = []
        self._registry[model_key].append(info)

        # Update cache
        self._model_cache[model_key] = model

        # Persist registry
        self._save_registry()

        # Persist to DB
        if self._db:
            self._persist_to_db(info)

        log.info(
            "ModelManager: saved '%s' v%d → %s (acc=%.4f, f1=%.4f).",
            model_key, version, canonical_path.name,
            info.accuracy, info.f1_score,
        )
        return info

    # ── Load ──────────────────────────────────────────────────────────────────

    def load(self, model_key: str, force_reload: bool = False) -> Optional[Any]:
        """
        Load a model from disk with lazy caching.

        Args:
            model_key:    Canonical model key (e.g. "random_forest").
            force_reload: If True, bypass cache and reload from disk.

        Returns:
            Loaded model object, or None if the file does not exist.
        """
        if not force_reload and model_key in self._model_cache:
            log.debug("ModelManager: '%s' served from cache.", model_key)
            return self._model_cache[model_key]

        canonical_name = self._CANONICAL_NAMES.get(model_key, f"{model_key}.pkl")
        path = self._dir / canonical_name

        if not path.exists():
            log.warning("ModelManager: model file not found: %s", path)
            return None

        try:
            model = joblib.load(path)
            self._model_cache[model_key] = model
            log.info("ModelManager: loaded '%s' from %s.", model_key, path.name)
            return model
        except Exception as exc:
            log.error("ModelManager: failed to load '%s': %s", model_key, exc)
            return None

    # ── Existence ─────────────────────────────────────────────────────────────

    def exists(self, model_key: str) -> bool:
        """
        Check whether a canonical model file exists on disk.

        Args:
            model_key: Model key string.

        Returns:
            True if the .pkl file exists; False otherwise.
        """
        canonical_name = self._CANONICAL_NAMES.get(model_key, f"{model_key}.pkl")
        return (self._dir / canonical_name).exists()

    # ── Promote ───────────────────────────────────────────────────────────────

    def promote(self, model_key: str, version: int) -> bool:
        """
        Promote a specific model version to be the active production model.

        Copies the versioned file to the canonical name and updates the registry.

        Args:
            model_key: Canonical model key.
            version:   Version number to promote.

        Returns:
            True if successful; False if version not found.
        """
        versions = self._registry.get(model_key, [])
        target = next((v for v in versions if v.version == version), None)
        if not target:
            log.warning("ModelManager.promote(): v%d not found for '%s'.", version, model_key)
            return False

        versioned_path = self._dir / f"{model_key}_v{version}.pkl"
        if not versioned_path.exists():
            log.warning("ModelManager.promote(): file not found: %s", versioned_path)
            return False

        canonical_name = self._CANONICAL_NAMES.get(model_key, f"{model_key}.pkl")
        canonical_path = self._dir / canonical_name
        shutil.copy2(versioned_path, canonical_path)

        # Update active flags
        for v in versions:
            v.is_active = (v.version == version)

        self._model_cache.pop(model_key, None)   # Invalidate cache
        self._save_registry()
        log.info("ModelManager: promoted '%s' v%d to active.", model_key, version)
        return True

    # ── Registry & Listing ────────────────────────────────────────────────────

    def list_models(self) -> list[ModelInfo]:
        """Return all registered model versions across all model keys."""
        return [info for versions in self._registry.values() for info in versions]

    def get_active(self, model_key: str) -> Optional[ModelInfo]:
        """Return the currently active ModelInfo for the given key."""
        for info in self._registry.get(model_key, []):
            if info.is_active:
                return info
        return None

    def get_metadata_dict(self) -> dict[str, Any]:
        """Return the full registry as a JSON-serialisable dict."""
        result: dict[str, Any] = {}
        for key, versions in self._registry.items():
            result[key] = [asdict(v) for v in versions]
        return result

    def clear_cache(self) -> None:
        """Clear the in-memory model cache."""
        self._model_cache.clear()
        log.debug("ModelManager: cache cleared.")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load_registry(self) -> dict[str, list[ModelInfo]]:
        """Load the model registry from metadata.json."""
        if not self._metadata_path.exists():
            return {}
        try:
            with open(self._metadata_path) as f:
                raw = json.load(f)
            registry: dict[str, list[ModelInfo]] = {}
            for key, versions in raw.items():
                registry[key] = [ModelInfo(**v) for v in versions]
            return registry
        except Exception as exc:
            log.warning("ModelManager: could not load registry: %s", exc)
            return {}

    def _save_registry(self) -> None:
        """Persist the in-memory registry to metadata.json."""
        try:
            with open(self._metadata_path, "w") as f:
                json.dump(self.get_metadata_dict(), f, indent=2, default=str)
        except Exception as exc:
            log.error("ModelManager: failed to save registry: %s", exc)

    def _persist_to_db(self, info: ModelInfo) -> None:
        """Write ModelInfo to the database model_metadata table."""
        try:
            import json as _json
            record = ModelMetadata(
                model_name=info.model_name,
                model_type=info.model_type,
                model_path=info.file_path,
                trained_at=info.trained_at,
                accuracy=info.accuracy,
                f1_score=info.f1_score,
                precision=info.precision,
                recall=info.recall,
                training_samples=info.n_samples,
                feature_names=_json.dumps(info.feature_names),
                is_active=info.is_active,
                notes=info.notes or "",
            )
            self._db.insert_model_metadata(record)  # type: ignore[union-attr]
            log.debug("ModelManager: persisted '%s' metadata to DB.", info.model_name)
        except Exception as exc:
            log.warning("ModelManager: DB persistence failed: %s", exc)

    @staticmethod
    def _extract_params(model: Any) -> dict[str, Any]:
        """Extract hyperparameters from a scikit-learn compatible estimator."""
        try:
            params = model.get_params()
            # Filter to JSON-serialisable scalar values
            return {
                k: v for k, v in params.items()
                if isinstance(v, (int, float, str, bool, type(None)))
            }
        except Exception:
            return {}

    def __repr__(self) -> str:
        keys = list(self._registry.keys())
        return f"ModelManager(models={keys}, cached={list(self._model_cache.keys())})"
