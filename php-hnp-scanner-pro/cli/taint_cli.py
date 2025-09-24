#!/usr/bin/env python3
"""
Interactive taint-tracking CLI (Semgrep taint mode)
1) Scan from list (CSV with framework name + path)
2) Scan local web frameworks in framework_sources/
"""
import sys, csv
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / 'bin' / 'run_taint_scan.py'
FRAMEWORKS = ['Laravel','Symfony','WordPress','CodeIgniter','Yii2']

def pick_mode() -> int:
    print('Choose mode:')
    print('  1) Scan from list (CSV: name,path)')
    print('  2) Scan local webframework (framework_sources/*)')
    while True:
        s = input('Enter 1 or 2: ').strip()
        if s in ('1','2'): return int(s)
        print('Invalid input.')

def scan_from_list():
    p = input('Enter CSV path (name,path): ').strip()
    csv_path = Path(p)
    if not csv_path.exists():
        print('File not found.'); return
    with open(csv_path, 'r', encoding='utf-8') as f:
        r = csv.reader(f)
        rows = list(r)
    for name, path in rows:
        print(f'==> Scanning {name} at {path}')
        # temporarily symlink to framework_sources/name
        target_dir = ROOT / 'framework_sources' / name.lower()
        target_dir.parent.mkdir(parents=True, exist_ok=True)
        if not target_dir.exists():
            try:
                target_dir.symlink_to(Path(path))
            except Exception:
                pass
        subprocess.run([str(RUNNER), name.lower()])

def scan_local():
    print('Select framework:')
    for i, fw in enumerate(FRAMEWORKS, start=1):
        print(f'  {i}. {fw}')
    while True:
        s = input('Enter number: ').strip()
        if s.isdigit() and 1 <= int(s) <= len(FRAMEWORKS):
            fw = FRAMEWORKS[int(s)-1].lower()
            subprocess.run([str(RUNNER), fw])
            return
        print('Invalid input.')

def main():
    m = pick_mode()
    if m == 1:
        scan_from_list()
    else:
        scan_local()

if __name__ == '__main__':
    main()
