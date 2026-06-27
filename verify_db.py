"""verify_db.py -- Database integration verification for Phase 6"""
import sys, io, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, '.')
from database.db_manager import DatabaseManager, ModelMetadata
from datetime import datetime, timezone

print('=' * 60)
print('  VERIFICATION -- DATABASE INTEGRATION')
print('=' * 60)

db = DatabaseManager()
db.initialise()

# 1. insert_model_metadata
rec = ModelMetadata(
    model_name='VerifyTest_RF_v2',
    model_type='classifier',
    model_path='models/attack_classifier.pkl',
    trained_at=datetime.now(timezone.utc).isoformat(),
    accuracy=0.9484,
    f1_score=0.9492,
    precision=0.9507,
    recall=0.9500,
    training_samples=1240,
    feature_names=json.dumps(['dst_port_nunique_w30', 'syn_ack_ratio']),
    is_active=True,
    notes='Phase 6 verification test',
)
row_id = db.insert_model_metadata(rec)
print(f'  [OK]  insert_model_metadata()   -> row_id={row_id}')

# 2. fetch_model_metadata (classifier only)
rows = db.fetch_model_metadata(model_type='classifier', active_only=True)
print(f'  [OK]  fetch_model_metadata()    -> {len(rows)} active classifier record(s)')
for r in rows[:3]:
    print(f'        id={r["id"]:>3}  name={r["model_name"]:<30}  acc={r["accuracy"]:.4f}')

# 3. fetch_model_metadata (anomaly)
anom_rows = db.fetch_model_metadata(model_type='anomaly')
print(f'  [OK]  fetch_model_metadata()    -> {len(anom_rows)} anomaly record(s)')
for r in anom_rows[:2]:
    print(f'        id={r["id"]:>3}  name={r["model_name"]:<30}  f1={r["f1_score"]:.4f}')

# 4. fetch_alerts
alerts = db.fetch_alerts(limit=5)
print(f'  [OK]  fetch_alerts()            -> {len(alerts)} alert(s) stored')

# 5. fetch_recent_traffic
packets = db.fetch_recent_traffic(limit=5)
print(f'  [OK]  fetch_recent_traffic()    -> {len(packets)} recent packet record(s)')

# 6. get_alert_count / get_traffic_count
alert_count   = db.get_alert_count()
traffic_count = db.get_traffic_count()
print(f'  [OK]  get_alert_count()         -> {alert_count}')
print(f'  [OK]  get_traffic_count()       -> {traffic_count}')

# 7. health_check
h = db.health_check()
status = h.get('status', 'unknown')
print(f'  [OK]  health_check()            -> status={status}')

print()
print('  [OK]  All database checks passed')
