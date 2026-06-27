"""
ml/__init__.py
==============
Network Traffic Analysis and Intrusion Detection System

Machine Learning Package — Phase 6 (fully implemented).

Provides a production-quality ML-based IDS pipeline that operates alongside
(not as a replacement for) the Phase 5 Rule Engine.

Architecture:
  DatasetBuilder   → Constructs labelled ML datasets from packets.csv
  FeatureEngineer  → Derives 50+ statistical features from raw packets
  DataPreprocessor → Scales, imputes, and splits feature matrices
  AnomalyDetector  → Isolation Forest for unknown anomaly detection
  AttackClassifier → Random Forest / XGBoost for multi-class classification
  ModelManager     → Save / load / version all trained models
  ModelEvaluator   → Comprehensive metrics (acc/F1/AUC/CV/confusion matrix)

Training Pipelines:
  train_anomaly_model()  — Train Isolation Forest
  train_classifier()     — Train RF / XGBoost classifier

Modules:
    feature_engineering — Feature derivation engine
    dataset_builder     — ML dataset construction
    preprocessing       — Data preprocessing pipeline
    anomaly_detector    — Isolation Forest anomaly detection
    attack_classifier   — Random Forest / XGBoost attack classification
    model_manager       — Model lifecycle management
    metrics             — Model evaluation metric suite
    train_anomaly_model — Anomaly model training pipeline
    train_classifier    — Attack classifier training pipeline

Author: Network Traffic Analyzer Project
Version: 6.0.0
"""

from ml.preprocessing import DataPreprocessor
from ml.feature_engineering import FeatureEngineer, FeatureConfig
from ml.dataset_builder import DatasetBuilder, LabelConfig
from ml.anomaly_detector import AnomalyDetector, AnomalyResult
from ml.attack_classifier import (
    AttackClassifier,
    ClassificationResult,
    BaseClassifier,
    RandomForestClassifierModel,
    XGBoostClassifierModel,
)
from ml.model_manager import ModelManager, ModelInfo
from ml.metrics import ModelEvaluator, ModelMetricsResult
from ml.train_anomaly_model import train_anomaly_model
from ml.train_classifier import train_classifier

__all__ = [
    # Preprocessing
    "DataPreprocessor",
    # Feature Engineering
    "FeatureEngineer",
    "FeatureConfig",
    # Dataset
    "DatasetBuilder",
    "LabelConfig",
    # Anomaly Detection
    "AnomalyDetector",
    "AnomalyResult",
    # Attack Classification
    "AttackClassifier",
    "ClassificationResult",
    "BaseClassifier",
    "RandomForestClassifierModel",
    "XGBoostClassifierModel",
    # Model Management
    "ModelManager",
    "ModelInfo",
    # Metrics
    "ModelEvaluator",
    "ModelMetricsResult",
    # Training Pipelines
    "train_anomaly_model",
    "train_classifier",
]
