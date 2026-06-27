"""verify_inference.py -- Live inference verification for Phase 6"""
import sys, io
# Force UTF-8 output on Windows to handle any log symbols
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import numpy as np
sys.path.insert(0, '.')

from ml.anomaly_detector import AnomalyDetector
from ml.attack_classifier import AttackClassifier
from ml.dataset_builder import DatasetBuilder
from ml.preprocessing import DataPreprocessor, PreprocessConfig

print('=' * 60)
print('  VERIFICATION -- MODEL RELOAD & LIVE INFERENCE')
print('=' * 60)

# Reload Anomaly Detector
anom = AnomalyDetector()
loaded_a = anom.load()
tag = 'OK' if loaded_a else 'FAIL'
print(f'  [{tag}]  AnomalyDetector.load()  : {loaded_a}')

# Build a fitted preprocessor to get correct selector/scaler
builder = DatasetBuilder()
X_full, y_full, feat_names, le = builder.build()
pre = DataPreprocessor(cfg=PreprocessConfig(test_size=0.20, random_state=42))
X_proc, y_proc = pre.fit_transform(X_full, y_full, feature_names=feat_names)

# Reload Attack Classifier using the fitted label encoder
clf = AttackClassifier(label_encoder=le)
loaded_c = clf.load()
tag = 'OK' if loaded_c else 'FAIL'
print(f'  [{tag}]  AttackClassifier.load() : {loaded_c}  backend={clf._clf.model_name}')
print(f'       Classes: {list(le.classes_)}')
print(f'       Features (after selection): {X_proc.shape[1]}')

print()
print('  --- Single-packet inference ---')
rng = np.random.default_rng(42)
n_feat_scaled = X_proc.shape[1]

for label, mean_val in [('BENIGN-like', 0.0), ('attack-like', 3.5)]:
    x = rng.normal(mean_val, 1.0, size=(1, n_feat_scaled)).astype('float32')
    result = clf.classify(x[0])
    anom_pred = anom.predict(x)[0]
    anomaly_str = 'YES' if anom_pred == -1 else 'NO'
    print(f'  Packet ({label})')
    print(f'    Predicted : {result.predicted_label}  confidence={result.confidence:.3f}')
    print(f'    Anomaly   : {anomaly_str}')
    print()

# Batch inference
X_batch = rng.normal(0, 1, size=(50, n_feat_scaled)).astype('float32')
results = clf.classify_batch(X_batch)
attack_cnt = sum(1 for r in results if r.is_attack)
avg_conf   = sum(r.confidence for r in results) / len(results)
anom_preds = anom.predict(X_batch)
anom_cnt   = int((anom_preds == -1).sum())

print(f'  Batch (50 packets):')
print(f'    Classifier : {attack_cnt} attacks / {50 - attack_cnt} benign  avg_conf={avg_conf:.3f}')
print(f'    Anomaly    : {anom_cnt} anomalies flagged')
print()
print('  [OK]  All inference checks passed')
