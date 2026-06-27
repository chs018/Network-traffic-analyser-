"""verify_metrics.py -- ML metrics and performance verification for Phase 6"""
import sys, io, numpy as np
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, '.')

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
)

print('=' * 60)
print('  VERIFICATION -- ML METRICS (>90% TARGETS)')
print('=' * 60)

from ml.dataset_builder import DatasetBuilder
from ml.preprocessing import DataPreprocessor, PreprocessConfig
from ml.attack_classifier import AttackClassifier

# --- Build balanced dataset ---
builder = DatasetBuilder()
X, y, feat_names, le = builder.build()
dist = builder.class_distribution(y)
print(f'  Dataset         : {X.shape[0]} samples, {X.shape[1]} features')
print(f'  Classes         : {list(le.classes_)}')
print(f'  Distribution    : {dict(dist)}')
print()

# --- Preprocess & split ---
pre = DataPreprocessor(cfg=PreprocessConfig(test_size=0.20, random_state=42))
X_train, X_test, y_train, y_test = pre.fit_transform_split(X, y, feature_names=feat_names)
print(f'  Train/Test      : {len(X_train)}/{len(X_test)}')
print(f'  Features after  : {X_train.shape[1]}')
print()

# --- Train fresh Random Forest classifier ---
clf = AttackClassifier(label_encoder=le, prefer_xgboost=False)
clf.train(X_train, y_train)

# --- Predict directly using the internal model ---
y_pred = clf._clf.predict(X_test)
y_proba = clf._clf.predict_proba(X_test)

# --- Compute metrics ---
acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
rec  = recall_score(y_test, y_pred, average='macro', zero_division=0)
f1   = f1_score(y_test, y_pred, average='macro', zero_division=0)
try:
    auc = roc_auc_score(
        y_test, y_proba,
        multi_class='ovr', average='macro', labels=sorted(np.unique(y_test))
    )
except Exception:
    auc = 0.0

# --- Per-class F1 ---
per_class_f1 = f1_score(y_test, y_pred, average=None, zero_division=0)
class_names  = list(le.classes_)

# --- Print report ---
print('  ATTACK CLASSIFIER METRICS')
print(f'  {"Metric":<24} {"Value":>8}  {"Target":>8}  {"Pass?":>6}')
print('  ' + '-' * 54)
for name, val, tgt in [
    ('Accuracy',          acc,  0.90),
    ('Precision (macro)', prec, 0.90),
    ('Recall (macro)',    rec,  0.90),
    ('F1 (macro)',        f1,   0.90),
    ('ROC-AUC',           auc,  0.95),
]:
    icon = 'PASS' if val >= tgt else 'FAIL'
    print(f'  {name:<24} {val:>8.4f}  {tgt:>8.2f}  [{icon}]')

print()
print('  Per-class F1:')
all_class_pass = True
for cls, score in zip(class_names, per_class_f1):
    bar = '#' * int(score * 30)
    icon = 'OK' if score >= 0.90 else 'LO'
    if score < 0.90:
        all_class_pass = False
    print(f'  [{icon}]  {cls:<12} {score:.4f}  |{bar}')

# --- Full sklearn report ---
print()
print('  Sklearn classification_report:')
report = classification_report(
    y_test, y_pred,
    target_names=class_names,
    zero_division=0,
)
for line in report.splitlines():
    print(f'    {line}')

# --- Final verdict ---
all_pass = acc >= 0.90 and prec >= 0.90 and rec >= 0.90 and f1 >= 0.90
print()
print('  ' + '=' * 54)
result_str = 'ALL TARGETS MET  (exit 0)' if all_pass else 'SOME TARGETS MISSED  (exit 1)'
print(f'  RESULT: {result_str}')
print('  ' + '=' * 54)
sys.exit(0 if all_pass else 1)
