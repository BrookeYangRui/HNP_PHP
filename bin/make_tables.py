#!/usr/bin/env python3
"""
Aggregate flow_*.(json|yaml) and produce English reports:
- reports/csv/flow_summary.csv
- reports/csv/flow_top_sinks.csv
- reports/csv/flow_matrix.csv
- reports/csv/flow_high_risk.csv (Guards_Hit==0 and Sink_API in whitelist)
- reports/csv/flow_api_risk.csv (concise per-framework API risk table)
- reports/csv/flow_api_risk_detailed.csv (detailed: canonical API, aliases, category, description)
- reports/latex/flow_tables.tex
- reports/html/flow_report.md / flow_api_risk.md
- reports/html/flow_report.html
"""
import json, yaml, glob, csv
from pathlib import Path
from collections import Counter, defaultdict
import re, statistics

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / 'reports' / 'yaml'
CSV_DIR = ROOT / 'reports' / 'csv'
TEX_DIR = ROOT / 'reports' / 'latex'
HTML_DIR = ROOT / 'reports' / 'html'
CSV_DIR.mkdir(parents=True, exist_ok=True)
TEX_DIR.mkdir(parents=True, exist_ok=True)
HTML_DIR.mkdir(parents=True, exist_ok=True)

API_NAME_RE = re.compile(r'([A-Za-z_:>]+)\(')

# Canonical API map per framework (normalized -> canonical + meta)
CANONICAL = {
    'Laravel': {
        'url':              {'canonical':'url()',              'category':'URL Generation', 'desc':'Build absolute/relative URL; affected by Host if APP_URL is not pinned'},
        'route':            {'canonical':'route()',            'category':'URL Generation', 'desc':'Generate URL by route name'},
        'redirect':         {'canonical':'redirect()',         'category':'Redirect',       'desc':'Issue HTTP redirect; affected by Host/proxy'},
        'asset':            {'canonical':'asset()',            'category':'URL Generation', 'desc':'Generate asset URL'},
    },
    'Symfony': {
        'generateurl':      {'canonical':'UrlGenerator::generate()', 'category':'URL Generation', 'desc':'Generate URL by route (requires trusted_hosts/proxies)'},
        'redirect':         {'canonical':'AbstractController::redirect()', 'category':'Redirect', 'desc':'Controller redirect'},
        'redirectresponse': {'canonical':'RedirectResponse',   'category':'Redirect',       'desc':'Construct redirect response'},
    },
    'WordPress': {
        'wp_redirect':      {'canonical':'wp_redirect()',      'category':'Redirect',       'desc':'WP redirect; recommend setting WP_HOME/WP_SITEURL'},
        'home_url':         {'canonical':'home_url()',         'category':'URL Generation', 'desc':'Homepage URL'},
        'site_url':         {'canonical':'site_url()',         'category':'URL Generation', 'desc':'Site URL'},
        'get_home_url':     {'canonical':'get_home_url()',     'category':'URL Generation', 'desc':'Get homepage URL'},
        'get_site_url':     {'canonical':'get_site_url()',     'category':'URL Generation', 'desc':'Get site URL'},
        'admin_url':        {'canonical':'admin_url()',        'category':'URL Generation', 'desc':'Admin URL'},
    },
    'CodeIgniter': {
        'base_url':         {'canonical':'base_url()',         'category':'URL Generation', 'desc':'Base URL (must set $config[base_url])'},
        'site_url':         {'canonical':'site_url()',         'category':'URL Generation', 'desc':'Site URL'},
        'redirect':         {'canonical':'redirect()',         'category':'Redirect',       'desc':'HTTP redirect'},
    },
    'Yii2': {
        'url::to':          {'canonical':'Url::to()',          'category':'URL Generation', 'desc':'Generate URL by route (recommend setting hostInfo/baseUrl)'},
        'redirect':         {'canonical':'Response::redirect()', 'category':'Redirect',     'desc':'Response redirect'},
    },
}

# Whitelist derived from canonical keys
APIS_WHITELIST = set()
for fw, items in CANONICAL.items():
    for k in items.keys():
        APIS_WHITELIST.add(k)

RECS = {
    'Laravel': 'Pin APP_URL and configure TrustProxies/TrustHosts (or URL::forceRootUrl)',
    'Symfony': 'Configure trusted_hosts and trusted_proxies',
    'WordPress': 'Define WP_HOME and WP_SITEURL',
    'CodeIgniter': 'Set $config[base_url] to avoid dynamic Host',
    'Yii2': 'Configure request->hostInfo and UrlManager baseUrl'
}

def normalize_api(raw: str) -> str:
    if not raw:
        return ''
    s = raw.strip().lstrip('>')
    if '::' in s and s.lower() != 'url::to':
        s = s.split('::')[-1]
    return s.lower()

# Load all flow reports
records = []
flows_all = []
for p in sorted(list(SRC_DIR.glob('flow_*.json')) + list(SRC_DIR.glob('flow_*.yaml'))):
    try:
        data = json.load(open(p, 'r', encoding='utf-8')) if p.suffix == '.json' else yaml.safe_load(open(p, 'r', encoding='utf-8'))
        framework = data.get('framework', 'unknown')
        sources = data.get('sources', [])
        sinks = data.get('sinks', [])
        guards = data.get('guards', [])
        flows = data.get('flows', [])
        guard_hits = sum(len(f.get('guards', [])) for f in flows)
        guard_hit_rate = round(guard_hits / max(1, len(flows)), 3)
        src_sink_ratio = round(len(sources) / max(1, len(sinks)), 3)
        state = 'N/A'
        enh_json = ROOT / 'data' / 'enhanced_framework_analysis_results.json'
        if enh_json.exists():
            try:
                enh = json.load(open(enh_json, 'r', encoding='utf-8'))
                if framework in enh and 'security_state' in enh[framework]:
                    state = enh[framework]['security_state']['state']
            except Exception:
                pass
        records.append({
            'framework': framework,
            'file': p.name,
            'sources': len(sources),
            'sinks': len(sinks),
            'guards': len(guards),
            'flows': len(flows),
            'guard_hit_rate': guard_hit_rate,
            'src_sink_ratio': src_sink_ratio,
            'state': state,
        })
        for f in flows:
            s = f.get('source', {})
            k = f.get('sink', {})
            gs = f.get('guards', [])
            api = ''
            snippet = k.get('snippet', '')
            m = API_NAME_RE.search(snippet)
            if m:
                api = m.group(1)
            flows_all.append([
                framework,
                s.get('file', ''), s.get('line', ''), s.get('snippet', ''),
                k.get('file', ''), k.get('line', ''), k.get('snippet', ''),
                len(gs), '; '.join(sorted({g.get('file','') for g in gs})), api
            ])
    except Exception:
        continue

# Summary per framework (latest wins)
latest = {}
for r in records:
    latest[r['framework']] = r

summary_rows = [['Framework', 'Sources', 'Sinks', 'Guards', 'Flows', 'Guard_Hit_Rate', 'Src/Sink', 'Security_State', 'Report_File']]
for fw in sorted(latest.keys()):
    r = latest[fw]
    summary_rows.append([fw, r['sources'], r['sinks'], r['guards'], r['flows'], r['guard_hit_rate'], r['src_sink_ratio'], r['state'], r['file']])

with open(CSV_DIR / 'flow_summary.csv', 'w', newline='', encoding='utf-8') as f:
    csv.writer(f).writerows(summary_rows)

# Top sinks (unfiltered)
sink_counter = Counter()
for row in flows_all:
    sink_counter[(row[0], row[4])] += 1
sink_rows = [['Framework', 'Sink_File', 'Count']]
for (fw, file), cnt in sink_counter.most_common(50):
    sink_rows.append([fw, file, cnt])
with open(CSV_DIR / 'flow_top_sinks.csv', 'w', newline='', encoding='utf-8') as f:
    csv.writer(f).writerows(sink_rows)

# Flow matrix (unfiltered)
matrix_header = ['Framework','Source_File','Source_Line','Source_Snippet','Sink_File','Sink_Line','Sink_Snippet','Guards_Hit','Guards_Files','Sink_API']
with open(CSV_DIR / 'flow_matrix.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f); writer.writerow(matrix_header); writer.writerows(flows_all)

# High-risk filtered CSV (whitelist)
high_risk = []
for row in flows_all:
    fw = row[0]
    api_raw = (row[9] or '')
    api_norm = normalize_api(api_raw)
    if fw == 'Symfony' and api_norm == 'redirectresponse':
        api_norm = 'redirectresponse'
    if row[7] == 0 and api_norm in APIS_WHITELIST:
        high_risk.append(row)
with open(CSV_DIR / 'flow_high_risk.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f); writer.writerow(matrix_header); writer.writerows(high_risk)

# Concise per-framework API risk table (whitelist + normalized + description)
api_map = defaultdict(lambda: defaultdict(lambda: {'total':0,'unguarded':0,'guarded':0,'aliases':set(),'meta':{}}))
for row in flows_all:
    fw, guards_hit, api_raw = row[0], row[7], (row[9] or '').strip()
    api_norm = normalize_api(api_raw)
    if fw in CANONICAL and api_norm in CANONICAL[fw]:
        meta = CANONICAL[fw][api_norm]
    else:
        continue
    api_map[fw][api_norm]['total'] += 1
    api_map[fw][api_norm]['aliases'].add(api_raw or api_norm)
    api_map[fw][api_norm]['meta'] = meta
    if guards_hit and guards_hit > 0:
        api_map[fw][api_norm]['guarded'] += 1
    else:
        api_map[fw][api_norm]['unguarded'] += 1

api_rows = [['Framework','Canonical_API','Aliases','Category','Description','Total','Unguarded','Guarded','Protected_Rate','Security_State','Recommendation']]
for fw in sorted(api_map.keys()):
    for api_norm, stats in sorted(api_map[fw].items(), key=lambda x: (-x[1]['unguarded'], -x[1]['total'])):
        total = stats['total']; unguarded = stats['unguarded']; guarded = stats['guarded']
        rate = f"{(guarded/total*100):.1f}%" if total else '0.0%'
        meta = stats['meta']
        aliases = ', '.join(sorted(stats['aliases']))
        api_rows.append([
            fw,
            meta['canonical'],
            aliases,
            meta['category'],
            meta['desc'],
            total,
            unguarded,
            guarded,
            rate,
            latest.get(fw,{}).get('state','N/A'),
            RECS.get(fw,'')
        ])

with open(CSV_DIR / 'flow_api_risk.csv', 'w', newline='', encoding='utf-8') as f:
    csv.writer(f).writerows([[h for h in ['Framework','API','Total','Unguarded','Guarded','Protected_Rate','Security_State','Recommendation']]] + [
        [r[0], r[1], r[5], r[6], r[7], r[8], r[9], r[10]] for r in api_rows[1:]
    ])

with open(CSV_DIR / 'flow_api_risk_detailed.csv', 'w', newline='', encoding='utf-8') as f:
    csv.writer(f).writerows(api_rows)

# LaTeX API risk table (subset)
tex = []
tex.append('\\documentclass{article}')
tex.append('\\usepackage{booktabs}')
tex.append('\\usepackage{geometry}')
tex.append('\\geometry{margin=1in}')
tex.append('\\begin{document}')
tex.append('\\section*{API Risk Table (Concise)}')
tex.append('\\begin{table}[h]')
tex.append('\\centering')
tex.append('\\begin{tabular}{l l r r r l l}')
tex.append('\\toprule')
tex.append('Framework & API & Total & Unguarded & Guarded & Protected Rate & State\\\\')
tex.append('\\midrule')
for r in api_rows[1:40]:
    fw, canon, aliases, cat, desc, total, unguarded, guarded, rate, state, _ = r
    api_esc = canon.replace('_', '\\_')
    tex.append(f"{fw} & {api_esc} & {total} & {unguarded} & {guarded} & {rate} & {state}\\\\")
tex.append('\\bottomrule')
tex.append('\\end{tabular}')
tex.append('\\end{table}')
tex.append('\\end{document}')
(TEX_DIR / 'flow_tables.tex').write_text('\n'.join(tex), encoding='utf-8')

# Markdown pointer (English)
total_flows = len(flows_all)
hr_flows = len(high_risk)
avg_guard = statistics.mean([r[7] for r in flows_all]) if flows_all else 0
md = []
md.append('# PHP Framework HNP Flow Report (Canonical APIs)')
md.append('')
md.append(f'- Total flows: {total_flows}')
md.append(f'- High-risk flows (no guards & risky API): {len(high_risk)}')
md.append(f'- Average guards per flow: {avg_guard:.2f}')
md.append('')
md.append('## CSVs')
md.append('- reports/csv/flow_api_risk.csv (concise)')
md.append('- reports/csv/flow_api_risk_detailed.csv (detailed with aliases/category/description)')
(HTML_DIR / 'flow_api_risk.md').write_text('\n'.join(md), encoding='utf-8')

print('✅ Generated (EN):')
print(' -', CSV_DIR / 'flow_api_risk.csv')
print(' -', CSV_DIR / 'flow_api_risk_detailed.csv')
print(' -', CSV_DIR / 'flow_high_risk.csv')
