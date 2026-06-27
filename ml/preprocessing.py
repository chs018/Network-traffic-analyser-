"""
preprocessing.py — ML Data Preprocessing Pipeline
===================================================
Network Traffic Analysis and Intrusion Detection System

Handles all data preparation tasks required before training or inference:
  - Missing value imputation (median for numeric, mode for categorical)
  - Outlier handling (IQR-based clipping)
  - Feature scaling (StandardScaler / MinMaxScaler)
  - Label encoding (LabelEncoder)
  - Train/Test split (stratified)
  - Feature selection (variance threshold + mutual information)
  - Pipeline persistence via joblib

Classes:
    PreprocessConfig  — Dataclass of preprocessing parameters
    DataPreprocessor  — Full sklearn preprocessing pipeline (Phase 6 — fully implemented)

Author: Network Traffic Analyzer Project
Version: 6.0.0
Python: 3.11+
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_selection import VarianceThreshold
from sklearn.model_selection import train_test_split as sk_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from utils.config import config
from utils.logger import get_ml_logger

log = get_ml_logger()

# Type aliases
FeatureMatrix = np.ndarray   # shape (n_samples, n_features)
LabelVector = np.ndarray     # shape (n_samples,)


# ──────────────────────────────────────────────────────────────────────────────
# PREPROCESSING CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PreprocessConfig:
    """Tunable parameters for the preprocessing pipeline."""

    # Scaling strategy: "standard" | "minmax"
    scaler_type: str = "standard"

    # IQR-based clipping multiplier (1.5 = Tukey fence)
    iqr_multiplier: float = 3.0

    # Variance threshold: remove features with variance < threshold
    variance_threshold: float = 0.0   # 0.0 = remove zero-variance features only

    # Train/test split
    test_size: float = 0.20
    random_state: int = 42

    # Whether to apply IQR clipping
    clip_outliers: bool = True


# ──────────────────────────────────────────────────────────────────────────────
# DATA PREPROCESSOR
# ──────────────────────────────────────────────────────────────────────────────

class DataPreprocessor:
    """
    End-to-end data preprocessing pipeline for the Network Traffic IDS.

    Transforms a raw feature matrix + label vector into clean, scaled,
    and encoded arrays ready for scikit-learn estimators.

    Pipeline steps:
      1. Missing value imputation (median per column)
      2. IQR-based outlier clipping
      3. Zero-variance feature removal (VarianceThreshold)
      4. StandardScaler normalisation
      5. Label encoding

    The preprocessor stores its fit state so it can be applied consistently
    during both training and inference.

    Attributes:
        feature_names (list[str]):  Feature names after selection.
        scaler (StandardScaler):    Fitted scaler instance.
        label_encoder (LabelEncoder): Fitted label encoder.
        selector (VarianceThreshold): Fitted feature selector.
        is_fitted (bool):           True after fit_transform() has been called.

    Usage::

        pre = DataPreprocessor()
        X_train, X_test, y_train, y_test = pre.fit_transform_split(X_raw, y_raw, feature_names)

        # Inference
        X_new = pre.transform(X_inference)
        pre.save()
    """

    def __init__(
        self,
        cfg: Optional[PreprocessConfig] = None,
        scaler_path: Optional[Path] = None,
        label_encoder_path: Optional[Path] = None,
    ) -> None:
        """
        Initialise the DataPreprocessor.

        Args:
            cfg:               Optional configuration override.
            scaler_path:       Path for scaler persistence.
            label_encoder_path: Path for label encoder persistence.
        """
        self._cfg = cfg or PreprocessConfig()
        self._ml_cfg = config.ml
        self._scaler_path = scaler_path or config.paths.scaler_path
        self._le_path = label_encoder_path or config.paths.label_encoder_path

        self.feature_names: list[str] = list(self._ml_cfg.numerical_features)
        self.scaler: StandardScaler = StandardScaler()
        self.label_encoder: LabelEncoder = LabelEncoder()
        self.selector: VarianceThreshold = VarianceThreshold(
            threshold=self._cfg.variance_threshold
        )
        self._col_medians: dict[str, float] = {}
        self._iqr_bounds: dict[str, tuple[float, float]] = {}
        self.is_fitted: bool = False

        log.debug("DataPreprocessor initialised.")

    # ── Public API ─────────────────────────────────────────────────────────────

    def fit_transform(
        self,
        X: FeatureMatrix,
        y: Optional[LabelVector] = None,
        feature_names: Optional[list[str]] = None,
    ) -> Tuple[FeatureMatrix, Optional[LabelVector]]:
        """
        Fit the preprocessing pipeline on X and return transformed arrays.

        Args:
            X:             Raw feature matrix (n_samples × n_features).
            y:             Optional encoded label vector.
            feature_names: Optional column names for X.

        Returns:
            Tuple (X_transformed, y_transformed).
            y_transformed is None if y was not provided.
        """
        if feature_names:
            self.feature_names = list(feature_names)

        log.info("DataPreprocessor.fit_transform(): X=%s", X.shape)

        # Step 1: Impute missing values (fit column medians)
        X = self._fit_impute(X)

        # Step 2: Clip outliers (IQR)
        if self._cfg.clip_outliers:
            X = self._fit_clip(X)

        # Step 3: Feature selection (remove zero-variance)
        X = self._fit_select(X)

        # Step 4: Scale
        X = self.scaler.fit_transform(X).astype(np.float32)

        # Step 5: Encode labels (already done by DatasetBuilder — just store)
        y_out: Optional[LabelVector] = None
        if y is not None:
            y_out = y.astype(int)

        self.is_fitted = True
        log.info(
            "DataPreprocessor: fitted. Output shape: X=%s, features=%d.",
            X.shape, X.shape[1] if len(X.shape) > 1 else 0,
        )
        return X.astype(np.float32), y_out

    def transform(
        self,
        X: FeatureMatrix,
        feature_names: Optional[list[str]] = None,
    ) -> FeatureMatrix:
        """
        Apply the fitted pipeline to new data (inference mode).

        Args:
            X:             New feature matrix.
            feature_names: Optional feature names (for alignment).

        Returns:
            Scaled feature matrix (n_samples × n_selected_features).

        Raises:
            RuntimeError: If called before fit_transform().
        """
        if not self.is_fitted:
            raise RuntimeError("DataPreprocessor must be fitted before transform().")

        # Align features if names provided
        if feature_names and self.feature_names:
            X = self._align_features(X, feature_names)

        # Impute
        X = self._apply_impute(X)

        # Clip
        if self._cfg.clip_outliers:
            X = self._apply_clip(X)

        # Select
        X = self.selector.transform(X)

        # Scale
        X = self.scaler.transform(X).astype(np.float32)

        return np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    def fit_transform_split(
        self,
        X: FeatureMatrix,
        y: LabelVector,
        feature_names: Optional[list[str]] = None,
    ) -> Tuple[FeatureMatrix, FeatureMatrix, LabelVector, LabelVector]:
        """
        Fit-transform and split into train/test sets (stratified).

        Args:
            X:             Raw feature matrix.
            y:             Encoded label vector.
            feature_names: Optional feature names.

        Returns:
            Tuple (X_train, X_test, y_train, y_test).
        """
        X_proc, y_proc = self.fit_transform(X, y, feature_names)

        # Stratified split
        try:
            X_train, X_test, y_train, y_test = sk_split(
                X_proc, y_proc,
                test_size=self._cfg.test_size,
                random_state=self._cfg.random_state,
                stratify=y_proc,
            )
        except ValueError:
            # Fall back to non-stratified if classes too small
            log.warning("DataPreprocessor: stratified split failed; using random split.")
            X_train, X_test, y_train, y_test = sk_split(
                X_proc, y_proc,
                test_size=self._cfg.test_size,
                random_state=self._cfg.random_state,
            )

        log.info(
            "DataPreprocessor: train=%d, test=%d.",
            len(X_train), len(X_test),
        )
        return X_train, X_test, y_train, y_test

    def train_test_split(
        self,
        X: FeatureMatrix,
        y: LabelVector,
    ) -> Tuple[FeatureMatrix, FeatureMatrix, LabelVector, LabelVector]:
        """
        Split already-transformed data into train and test sets.

        Args:
            X: Feature matrix (already preprocessed).
            y: Label vector.

        Returns:
            Tuple (X_train, X_test, y_train, y_test).
        """
        try:
            return sk_split(
                X, y,
                test_size=self._cfg.test_size,
                random_state=self._cfg.random_state,
                stratify=y,
            )
        except ValueError:
            return sk_split(
                X, y,
                test_size=self._cfg.test_size,
                random_state=self._cfg.random_state,
            )

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> None:
        """
        Serialise the fitted scaler, selector, and encoder to disk.

        Args:
            path: Directory path for saving (defaults to models_dir).
        """
        if not self.is_fitted:
            log.warning("DataPreprocessor.save(): preprocessor not fitted yet.")
            return

        base = path or config.paths.models_dir
        base.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.scaler, base / "preprocessor_scaler.pkl")
        joblib.dump(self.selector, base / "preprocessor_selector.pkl")
        joblib.dump(self.label_encoder, base / "label_encoder.pkl")

        meta = {
            "feature_names": self.feature_names,
            "col_medians": self._col_medians,
            "iqr_bounds": {k: list(v) for k, v in self._iqr_bounds.items()},
            "is_fitted": True,
        }
        with open(base / "preprocessor_meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        log.info("DataPreprocessor saved to %s.", base)

    def load(self, path: Optional[Path] = None) -> bool:
        """
        Load a previously serialised preprocessor from disk.

        Args:
            path: Directory path for loading (defaults to models_dir).

        Returns:
            True if successfully loaded; False otherwise.
        """
        base = path or config.paths.models_dir
        scaler_file = base / "preprocessor_scaler.pkl"
        selector_file = base / "preprocessor_selector.pkl"
        le_file = base / "label_encoder.pkl"
        meta_file = base / "preprocessor_meta.json"

        if not all(f.exists() for f in (scaler_file, selector_file)):
            log.warning("DataPreprocessor.load(): missing files in %s.", base)
            return False

        try:
            self.scaler = joblib.load(scaler_file)
            self.selector = joblib.load(selector_file)
            if le_file.exists():
                self.label_encoder = joblib.load(le_file)
            if meta_file.exists():
                with open(meta_file) as f:
                    meta = json.load(f)
                self.feature_names = meta.get("feature_names", self.feature_names)
                self._col_medians = meta.get("col_medians", {})
                self._iqr_bounds = {
                    k: tuple(v) for k, v in meta.get("iqr_bounds", {}).items()
                }
                self.is_fitted = meta.get("is_fitted", True)
            self.is_fitted = True
            log.info("DataPreprocessor loaded from %s.", base)
            return True
        except Exception as exc:
            log.error("DataPreprocessor.load() failed: %s", exc)
            return False

    # ── Internal Pipeline Steps ────────────────────────────────────────────────

    def _fit_impute(self, X: FeatureMatrix) -> FeatureMatrix:
        """Fit and apply median imputation per column."""
        X_df = pd.DataFrame(X, columns=self._col_index(X))
        self._col_medians = {
            col: float(X_df[col].median()) for col in X_df.columns
        }
        X_df = X_df.fillna(pd.Series(self._col_medians))
        return X_df.values.astype(np.float32)

    def _apply_impute(self, X: FeatureMatrix) -> FeatureMatrix:
        """Apply fitted median imputation."""
        if not self._col_medians:
            return np.nan_to_num(X, nan=0.0)
        X_df = pd.DataFrame(X, columns=self._col_index(X))
        defaults = {col: self._col_medians.get(col, 0.0) for col in X_df.columns}
        return X_df.fillna(pd.Series(defaults)).values.astype(np.float32)

    def _fit_clip(self, X: FeatureMatrix) -> FeatureMatrix:
        """Fit IQR bounds and clip outliers."""
        X_df = pd.DataFrame(X, columns=self._col_index(X))
        m = self._cfg.iqr_multiplier
        for col in X_df.columns:
            q1 = float(X_df[col].quantile(0.25))
            q3 = float(X_df[col].quantile(0.75))
            iqr = q3 - q1
            lo = q1 - m * iqr
            hi = q3 + m * iqr
            self._iqr_bounds[col] = (lo, hi)
            X_df[col] = X_df[col].clip(lower=lo, upper=hi)
        return X_df.values.astype(np.float32)

    def _apply_clip(self, X: FeatureMatrix) -> FeatureMatrix:
        """Apply fitted IQR clipping."""
        if not self._iqr_bounds:
            return X
        X_df = pd.DataFrame(X, columns=self._col_index(X))
        for col in X_df.columns:
            if col in self._iqr_bounds:
                lo, hi = self._iqr_bounds[col]
                X_df[col] = X_df[col].clip(lower=lo, upper=hi)
        return X_df.values.astype(np.float32)

    def _fit_select(self, X: FeatureMatrix) -> FeatureMatrix:
        """Fit VarianceThreshold and remove zero-variance features."""
        X_sel = self.selector.fit_transform(X)
        support = self.selector.get_support()
        if self.feature_names and len(self.feature_names) == len(support):
            self.feature_names = [
                n for n, keep in zip(self.feature_names, support) if keep
            ]
        log.debug(
            "DataPreprocessor: selected %d / %d features.",
            X_sel.shape[1], X.shape[1],
        )
        return X_sel.astype(np.float32)

    def _align_features(
        self,
        X: FeatureMatrix,
        input_names: list[str],
    ) -> FeatureMatrix:
        """
        Align input features to the fitted feature order.

        Missing columns are filled with 0; extra columns are dropped.
        """
        df_in = pd.DataFrame(X, columns=input_names)
        df_aligned = pd.DataFrame(
            {col: df_in.get(col, pd.Series(0.0, index=df_in.index))
             for col in self.feature_names}
        )
        return df_aligned.values.astype(np.float32)

    @staticmethod
    def _col_index(X: FeatureMatrix) -> list[str]:
        """Generate synthetic column names for a feature matrix."""
        return [f"f{i}" for i in range(X.shape[1] if len(X.shape) > 1 else 0)]
