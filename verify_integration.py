import sys
import ast
sys.path.insert(0, '.')

errors = []
checks = [
    ('dashboard/pipeline.py', None),
    ('dashboard/data_loaders.py', None),
    ('dashboard/app.py', None),
    ('dashboard/components/navigation.py', None),
    ('dashboard/pages/upload_page.py', None),
    ('dashboard/pages/packets_page.py', None),
    ('dashboard/pages/reports_page.py', None),
    ('dashboard/pages/models_page.py', None),
    ('dashboard/pages/alerts_page.py', None),
    ('dashboard/pages/home_page.py', None),
    ('dashboard/pages/system_page.py', None),
    ('dashboard/styles.py', None),
]

for path, _ in checks:
    try:
        with open(path, encoding='utf-8') as f:
            src = f.read()
        ast.parse(src)
        print(f'[OK] {path}')
    except SyntaxError as e:
        errors.append(f'[FAIL] {path}: SyntaxError at line {e.lineno}: {e.msg}')
    except Exception as e:
        errors.append(f'[FAIL] {path}: {e}')

# Test critical imports
imports = [
    ('dashboard.pipeline', 'PipelineOrchestrator'),
    ('dashboard.data_loaders', 'invalidate_all_caches'),
]
for mod, attr in imports:
    try:
        m = __import__(mod, fromlist=[attr])
        getattr(m, attr)
        print(f'[OK] import {mod}.{attr}')
    except Exception as e:
        errors.append(f'[FAIL] import {mod}.{attr}: {e}')

if errors:
    print()
    print('=== ERRORS ===')
    for e in errors:
        print(e)
    sys.exit(1)
else:
    print()
    print('All checks passed!')
