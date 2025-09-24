#!/usr/bin/env python3
import json, subprocess, sys, shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / 'php-hnp-scanner-pro' / 'rules' / 'php-hnp-taint.yml'
TARGETS = ROOT / 'framework_sources'
OUT = ROOT / 'reports'
(OUT / 'csv').mkdir(parents=True, exist_ok=True)
(OUT / 'yaml').mkdir(parents=True, exist_ok=True)

FRAMEWORKS = ['laravel','symfony','wordpress','codeigniter','yii2']

def semgrep_bin() -> str:
    sys_semgrep = shutil.which('semgrep')
    if sys_semgrep:
        return sys_semgrep
    venv_semgrep = ROOT / 'php-hnp-scanner-pro' / '.venv' / 'bin' / 'semgrep'
    if venv_semgrep.exists():
        return str(venv_semgrep)
    raise FileNotFoundError('semgrep not found. Install with: cd php-hnp-scanner-pro && source .venv/bin/activate && pip install semgrep')

def run_one(framework: str):
    target = TARGETS / framework
    if not target.exists():
        print(f"skip {framework}: not found")
        return []
    cmd = [semgrep_bin(),'scan','--config',str(RULES),'--json','--include','*.php',str(target)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode not in (0,1):
        print(f"semgrep failed for {framework}: {p.stderr[:200]}")
        return []
    data = json.loads(p.stdout)
    rows = []
    for r in data.get('results', []):
        rows.append({
            'framework': framework.title(),
            'check_id': r.get('check_id',''),
            'message': r.get('extra',{}).get('message',''),
            'path': r.get('path',''),
            'start_line': r.get('start',{}).get('line',''),
            'code': r.get('extra',{}).get('lines','').strip()
        })
    (OUT / 'yaml' / f'taint_{framework}.json').write_text(json.dumps(data, indent=2), encoding='utf-8')
    return rows

def write_csv(rows):
    import csv
    csv_path = OUT / 'csv' / 'taint_findings.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Framework','Check','Message','File','Line','Code'])
        for r in rows:
            w.writerow([r['framework'], r['check_id'], r['message'], r['path'], r['start_line'], r['code']])
    print(f"✅ Taint findings written to {csv_path}")

def main():
    args = sys.argv[1:]
    if args:
        fw = args[0].lower()
        rows = run_one(fw)
        write_csv(rows)
        return
    all_rows = []
    for fw in FRAMEWORKS:
        all_rows.extend(run_one(fw))
    write_csv(all_rows)

if __name__ == '__main__':
    main()
