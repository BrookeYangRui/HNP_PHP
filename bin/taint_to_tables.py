#!/usr/bin/env python3
import csv
from pathlib import Path
from collections import defaultdict
import re

ROOT = Path(__file__).resolve().parents[1]
IN_CSV = ROOT / 'reports' / 'csv' / 'taint_findings.csv'
OUT_DIR = ROOT / 'reports' / 'csv'
OUT_DIR.mkdir(parents=True, exist_ok=True)

API_RE = re.compile(r'([A-Za-z_:>]+)\(')

WHITELIST = {
    'url','route','redirect','wp_redirect','base_url','site_url','url::to',
    'Url::to','RedirectResponse','AbstractController::redirect','UrlGenerator::generate'
}

# read findings
rows = []
if not IN_CSV.exists():
    print(f"No taint findings: {IN_CSV} not found. Run bin/run_taint_scan.py first.")
    raise SystemExit(0)

with open(IN_CSV, 'r', encoding='utf-8') as f:
    r = csv.DictReader(f)
    for row in r:
        rows.append(row)

# aggregate
agg = defaultdict(lambda: defaultdict(int))  # fw -> api -> count
per_fw_api_files = defaultdict(lambda: defaultdict(set))
for r in rows:
    fw = r['Framework']
    code = r['Code'] or ''
    m = API_RE.search(code)
    api = m.group(1) if m else ''
    api_norm = api.strip().lstrip('>')
    if '::' in api_norm and api_norm.lower() != 'url::to':
        api_norm = api_norm.split('::')[-1]
    if api_norm and (api_norm in WHITELIST or api in WHITELIST):
        agg[fw][api] += 1
        per_fw_api_files[fw][api].add(f"{r['File']}:{r['Line']}")

# write summary
out_summary = OUT_DIR / 'taint_api_summary.csv'
with open(out_summary, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    w.writerow(['Framework','API','Findings','Examples'])
    for fw in sorted(agg.keys()):
        for api, cnt in sorted(agg[fw].items(), key=lambda x: -x[1]):
            examples = list(per_fw_api_files[fw][api])[:3]
            w.writerow([fw, api, cnt, ' | '.join(examples)])

print(f"✅ Wrote {out_summary}")
