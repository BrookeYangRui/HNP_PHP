#!/usr/bin/env python3
"""
Framework Flow Scanner (Interactive)
- Lets user choose a PHP web framework to analyze
- Defines Sources (where Host can enter), Sinks (developer-facing APIs), Guards (validations/configs)
- Performs lightweight static pattern scan to map potential flows: Source -> (Processing/Guards) -> Sink
- Outputs terminal summary and saves JSON/YAML report into reports/
"""
import os
import sys
import json
import yaml
import re
from pathlib import Path
from datetime import datetime
from typing import Tuple

ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_SOURCES_DIR = ROOT / 'framework_sources'
REPORTS_DIR = ROOT / 'reports'
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
(REPORTS_DIR / 'yaml').mkdir(parents=True, exist_ok=True)
(REPORTS_DIR / 'csv').mkdir(parents=True, exist_ok=True)
(REPORTS_DIR / 'html').mkdir(parents=True, exist_ok=True)

FRAMEWORKS = [
    ('Laravel', FRAMEWORK_SOURCES_DIR / 'laravel'),
    ('Symfony', FRAMEWORK_SOURCES_DIR / 'symfony'),
    ('WordPress', FRAMEWORK_SOURCES_DIR / 'wordpress'),
    ('CodeIgniter', FRAMEWORK_SOURCES_DIR / 'codeigniter'),
    ('Yii2', FRAMEWORK_SOURCES_DIR / 'yii2'),
]

# Definitions: sources, sinks (developer APIs), guards (validation/config) per framework
DEFS = {
    'Laravel': {
        'sources': [r"\$_SERVER\['HTTP_HOST'\]", r"request\(\)->getHost\("],
        'sinks': [r"url\(", r"route\(", r"asset\(", r"redirect\(", r"->to\("],
        'guards': [r"URL::forceRootUrl\(", r"TrustProxies", r"TrustHosts", r"APP_URL"],
    },
    'Symfony': {
        'sources': [r"\$_SERVER\['HTTP_HOST'\]", r"->getHost\("],
        'sinks': [r"->generateUrl\(", r"UrlGenerator->generate\(", r"new RedirectResponse\("],
        'guards': [r"trusted_hosts", r"setTrustedProxies", r"setTrustedHosts"],
    },
    'WordPress': {
        'sources': [r"\$_SERVER\['HTTP_HOST'\]"],
        'sinks': [r"home_url\(", r"site_url\(", r"wp_redirect\("],
        'guards': [r"WP_HOME", r"WP_SITEURL"],
    },
    'CodeIgniter': {
        'sources': [r"\$_SERVER\['HTTP_HOST'\]", r"\$this->input->server\(\'HTTP_HOST\'\)"],
        'sinks': [r"base_url\(", r"site_url\(", r"redirect\("],
        'guards': [r"\$config\['base_url'\]", r"config\('base_url'\)"],
    },
    'Yii2': {
        'sources': [r"\$_SERVER\['HTTP_HOST'\]"],
        'sinks': [r"Url::to\(", r"->redirect\("],
        'guards': [r"baseUrl", r"hostInfo"],
    },
}

SCAN_GLOBS = [
    '**/src/**/*.php', '**/app/**/*.php', '**/core/**/*.php', '**/includes/**/*.php',
    '**/config/**/*.php', '**/*.php',
]

class FlowScanner:
    def __init__(self, name: str, path: Path):
        self.name = name
        self.path = path
        self.defs = DEFS.get(name, {})
        self.results = {
            'framework': name,
            'timestamp': datetime.now().isoformat(),
            'sources': [],
            'sinks': [],
            'guards': [],
            'flows': [],  # pairs of (source_file,line) -> (sink_file,line) with optional guard hits in between (file,line)
            'notes': [],
        }

    def _grep(self, pattern: str):
        regex = re.compile(pattern)
        hits = []
        for g in SCAN_GLOBS:
            for f in self.path.glob(g):
                if not f.is_file() or f.suffix != '.php':
                    continue
                try:
                    txt = f.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    continue
                for m in regex.finditer(txt):
                    line = txt[:m.start()].count('\n') + 1
                    lines = txt.splitlines()
                    snippet = lines[line-1][:200] if 0 <= line-1 < len(lines) else ''
                    hits.append({'file': str(f.relative_to(self.path)), 'line': line, 'snippet': snippet})
        return hits

    def scan(self):
        # sources
        for p in self.defs.get('sources', []):
            self.results['sources'].extend(self._grep(p))
        # sinks
        for p in self.defs.get('sinks', []):
            self.results['sinks'].extend(self._grep(p))
        # guards
        for p in self.defs.get('guards', []):
            self.results['guards'].extend(self._grep(p))

        # naive flow pairing with fallbacks
        sources_by_dir = {}
        for s in self.results['sources']:
            d = str(Path(s['file']).parent)
            sources_by_dir.setdefault(d, []).append(s)
        guards_by_dir = {}
        for g in self.results['guards']:
            d = str(Path(g['file']).parent)
            guards_by_dir.setdefault(d, []).append(g)

        global_sources = self.results['sources'][:]
        for sink in self.results['sinks']:
            d = str(Path(sink['file']).parent)
            candidate_sources = sources_by_dir.get(d, [])
            candidate_guards = guards_by_dir.get(d, [])

            if candidate_sources:
                src_list = candidate_sources[:3]
            elif global_sources:
                src_list = global_sources[:3]
            else:
                src_list = [None]

            for src in src_list:
                flow = {
                    'source': src if src else {'file': '', 'line': '', 'snippet': ''},
                    'sink': sink,
                    'guards': candidate_guards[:3]
                }
                self.results['flows'].append(flow)

        # notes for config-dependent risk
        if self.name in ('Laravel', 'WordPress', 'CodeIgniter', 'Yii2'):
            self.results['notes'].append('Configuration-dependent: ensure base URL / trusted hosts / proxies are pinned.')
        if self.name == 'Symfony':
            self.results['notes'].append('Ensure trusted_hosts and trusted_proxies are set to avoid proxy-based HNP.')
        return self.results


def pick_framework() -> Tuple[str, Path]:
    print("请选择要扫描的PHP框架：")
    for i, (name, path) in enumerate(FRAMEWORKS, start=1):
        print(f"  {i}. {name}  ({'存在' if path.exists() else '未下载'})")
    while True:
        choice = input("输入数字选择：").strip()
        if not choice.isdigit():
            print("请输入有效数字。")
            continue
        idx = int(choice)
        if 1 <= idx <= len(FRAMEWORKS):
            return FRAMEWORKS[idx-1]
        print("超出范围，请重新输入。")


def save_reports(framework: str, data: dict):
    base = f"flow_{framework.lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    json_path = REPORTS_DIR / 'yaml' / f"{base}.json"
    yaml_path = REPORTS_DIR / 'yaml' / f"{base}.yaml"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    with open(yaml_path, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)
    return json_path, yaml_path


def print_summary(res: dict):
    print("\n=== 扫描摘要 ===")
    print(f"框架: {res['framework']}")
    print(f"Sources: {len(res['sources'])}  Sinks: {len(res['sinks'])}  Guards: {len(res['guards'])}")
    print(f"可能的流(示例): {len(res['flows'])}")
    for i, flow in enumerate(res['flows'][:5], start=1):
        s = flow['source']; k = flow['sink']; gs = flow['guards']
        print(f" {i}) {s['file']}:{s['line']}  ->  {k['file']}:{k['line']}  | Guards: {len(gs)}")
    if res['notes']:
        print("备注:")
        for n in res['notes']:
            print(f" - {n}")


def main():
    if not FRAMEWORK_SOURCES_DIR.exists():
        print(f"未找到框架源码目录: {FRAMEWORK_SOURCES_DIR}")
        sys.exit(1)
    name, path = pick_framework()
    if not path.exists():
        print(f"所选框架尚未下载: {path}")
        sys.exit(1)
    scanner = FlowScanner(name, path)
    res = scanner.scan()
    print_summary(res)
    j, y = save_reports(name, res)
    print(f"\n报告已保存: {j}\n          {y}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n已取消。")
