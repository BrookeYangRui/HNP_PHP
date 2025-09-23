#!/usr/bin/env python3
import argparse, json, os, re, subprocess, sys, shutil, csv
from pathlib import Path
from typing import Dict, Any, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
OUTDIR = ROOT / "out"
RULES = ROOT / "rules" / "php-hnp.yml"
ADAPTERS_DIR = ROOT / "adapters"

SUSPICIOUS_PATH_HINTS = [
    "password", "reset", "verify", "token", "activation",
    "login", "register", "callback", "oauth", "sso"
]

def run(cmd: List[str], cwd: Path=None) -> Tuple[int, str, str]:
    proc = subprocess.Popen(cmd, cwd=str(cwd) if cwd else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()
    return proc.returncode, out, err

def detect_framework(project: Path) -> str:
    # best-effort heuristics
    if (project / "artisan").exists() or (project / "bootstrap" / "app.php").exists():
        return "laravel"
    if (project / "wp-includes" / "version.php").exists() or (project / "wp-config.php").exists():
        return "wordpress"
    if (project / "bin" / "console").exists() and (project / "config").exists():
        return "symfony"
    if (project / "bin" / "cake.php").exists() or (project / "config" / "app.php").exists():
        return "cakephp"
    if (project / "vendor" / "yiisoft" / "yii2").exists() or (project / "config" / "web.php").exists():
        return "yii2"
    if (project / "system" / "CodeIgniter.php").exists() or (project / "app" / "Config" / "App.php").exists() or (project / "application" / "config" / "config.php").exists():
        return "codeigniter"
    return "unknown"

def load_adapter(framework: str):
    sys.path.insert(0, str(ADAPTERS_DIR))
    try:
        if framework == "laravel":
            import adapter_laravel as ad; return ad
        if framework == "symfony":
            import adapter_symfony as ad; return ad
        if framework == "wordpress":
            import adapter_wordpress as ad; return ad
        if framework == "cakephp":
            import adapter_cakephp as ad; return ad
        if framework == "yii2":
            import adapter_yii2 as ad; return ad
        if framework == "codeigniter":
            import adapter_codeigniter as ad; return ad
    except Exception as e:
        print(f"[adapter] load failed: {e}", file=sys.stderr)
    return None

def semgrep_scan(project: Path) -> Dict[str, Any]:
    if shutil.which("semgrep") is None:
        print("[!] semgrep not found in PATH; skipping semgrep scan", file=sys.stderr)
        return {"results": [], "errors": ["semgrep missing"]}
    OUTDIR.mkdir(parents=True, exist_ok=True)
    out_json = OUTDIR / "semgrep.json"
    cmd = [
        "semgrep", "scan",
        "--config", str(RULES),
        "--json", "--quiet",
        "-o", str(out_json),
        "--timeout", "240",
        "--include", "**/*.php",
        "--include", "**/*.blade.php",
        "--include", "**/*.twig",
        "--exclude", "vendor/**",
        "--exclude", "node_modules/**",
        str(project)
    ]
    code, out, err = run(cmd)
    if code != 0 and not (OUTDIR / "semgrep.json").exists():
        print(f"[semgrep] exit={code} stderr={err[:300]}", file=sys.stderr)
        return {"results": [], "errors": ["semgrep failed"]}
    try:
        return json.loads((OUTDIR / "semgrep.json").read_text(encoding="utf-8"))
    except Exception:
        return {"results": [], "errors": ["failed to parse semgrep output"]}

def ctx_default(framework: str) -> Dict[str, Any]:
    return {
        "framework": framework,
        "pinned_base_url": None,
        "trusted_proxies": None,
        "trusted_hosts": None,
        "proxy_host_trusted": False,
        "proxy_proto_trusted": False
    }

def score_finding(f: Dict[str, Any], ctx: Dict[str, Any]) -> str:
    path = (f.get("path") or "").lower()
    msg  = (f.get("extra", {}).get("message") or "").lower()
    sink = (f.get("extra", {}).get("metavars", {}).get("$SINK", {}).get("abstract_content") or "").lower()

    base = "MEDIUM"
    if any(k in msg for k in ["redirect", "location", "mail", "wp_mail"]) or "header(" in msg:
        base = "HIGH"
    if any(k in path for k in SUSPICIOUS_PATH_HINTS) or any(k in msg for k in SUSPICIOUS_PATH_HINTS):
        # sensitive workflows (reset, verify, oauth, login)
        base = "HIGH"

    # Config escalation
    if ctx.get("proxy_host_trusted") and base == "HIGH":
        return "CRITICAL"
    if (ctx.get("pinned_base_url") in (None, "", False)) and base == "HIGH":
        return "HIGH"
    return base

def build_evidence(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Make a very simple source->sink map per file location
    evid = {"edges": []}
    for r in results:
        extra = r.get("extra", {})
        dataflow = extra.get("dataflow_trace", [])
        if dataflow:
            path = r.get("path")
            chain = [f"{x.get('file','?')}:{x.get('line','?')}:{x.get('code','')[:80]}" for x in dataflow]
            evid["edges"].append({"path": path, "trace": chain})
    return evid

def write_sarif(findings, ctx, path):
    sarif = {
      "version": "2.1.0",
      "runs": [{
        "tool": {"driver": {"name": "php-hnp-scanner", "informationUri": "https://example.local"}},
        "results": []
      }]
    }
    for f in findings:
      sarif["runs"][0]["results"].append({
        "level": {"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note"}.get(f.get("score","LOW"),"note"),
        "message": {"text": f.get("extra",{}).get("message","HNP")},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": f.get("path","?")},
            "region": {"startLine": f.get("start",{}).get("line",1)}
          }
        }]
      })
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")

def suggest_pocs(findings, ctx):
    pocs = []
    for f in findings:
        if f.get("score") in ("HIGH","CRITICAL"):
            file = f.get("path","?")
            line = f.get("start",{}).get("line","?")
            pocs.append({
              "file": file, "line": line,
              "curl_xfh": 'curl -H "X-Forwarded-Host: attacker.tld" https://TARGET/...',
              "curl_dual_host": 'printf "GET / HTTP/1.1\r\nHost: legit.tld\r\nHost: attacker.tld\r\n\r\n" | nc TARGET 80'
            })
    return pocs

def write_csv(findings: List[Dict[str, Any]], ctx: Dict[str, Any], csv_path: Path):
    with csv_path.open("w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["severity","file","line","message","framework","pinned_base","trusted_proxies","trusted_hosts"])
        for f in findings:
            line = f.get("start",{}).get("line","?")
            w.writerow([f.get("score"), f.get("path"), line, f.get("extra",{}).get("message",""),
                        ctx["framework"], ctx.get("pinned_base_url"), ctx.get("trusted_proxies"), ctx.get("trusted_hosts")])

def render_report(findings: List[Dict[str, Any]], ctx: Dict[str, Any]) -> str:
    lines = []
    lines.append("# HNP Scan Report\n")
    lines.append("## Environment signals\n")
    lines.append(f"- Framework: **{ctx['framework']}**\n")
    lines.append(f"- Pinned base URL: **{ctx.get('pinned_base_url') or 'NOT PINNED'}**\n")
    lines.append(f"- Trusted proxies: **{ctx.get('trusted_proxies') or 'not configured'}**\n")
    lines.append(f"- Trusted hosts: **{ctx.get('trusted_hosts') or 'not configured'}**\n")
    if ctx.get("proxy_host_trusted"):
        lines.append(f"- ⚠️ `X-Forwarded-Host` **trusted** → HNP risk escalates.\n")
    if not findings:
        lines.append("\n## Findings\n_None._\n")
        return "\n".join(lines)

    lines.append("\n## Findings\n")
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        score = f.get("score", "LOW")
        path = f.get("path", "?")
        start = f.get("start", {}); line = start.get("line", "?")
        msg = f.get("extra", {}).get("message", "")
        lines.append(f"### {i}. [{score}] {path}:{line}\n")
        lines.append(f"- Semgrep severity: **{sev}**\n")
        lines.append(f"- Message: {msg}\n")
        code = f.get("extra", {}).get("lines", "")
        if code: lines.append("\n```php\n" + code.strip() + "\n```\n")
        # simple autofix suggestions by framework
        lines.append("- Suggested fix:\n")
        fw = ctx.get("framework")
        if fw == "laravel":
            lines.append("  - Set APP_URL; restrict TrustProxies (no HEADER_X_FORWARDED_HOST); define TrustHosts whitelist.\n")
        elif fw == "symfony":
            lines.append("  - Set router.default_uri; avoid '*' in trusted_proxies; only trust x-forwarded-proto.\n")
        elif fw == "wordpress":
            lines.append("  - Define WP_HOME/WP_SITEURL; verify allowed_redirect_hosts whitelist.\n")
        elif fw == "cakephp":
            lines.append("  - Configure Router::fullBaseUrl with constant origin.\n")
        elif fw == "yii2":
            lines.append("  - Configure urlManager.hostInfo; avoid deriving host from request headers.\n")
        elif fw == "codeigniter":
            lines.append("  - Set base_url in config; avoid trusting X-Forwarded-Host.\n")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description="PHP Host Name Pollution scanner (PRO)")
    ap.add_argument("project", help="Path to PHP project root")
    ap.add_argument("--min-score", default="LOW", choices=["LOW","MEDIUM","HIGH","CRITICAL"],
                    help="Filter results below this score")
    ap.add_argument("--emit-sarif", action="store_true", help="Emit SARIF to out/hnp.sarif")
    ap.add_argument("--allow-host", action="append", default=[],
                    help="Whitelist host pattern (regex); flows to these are downgraded")
    args = ap.parse_args()
    project = Path(args.project).resolve()
    if not project.exists():
        print(f"Project not found: {project}", file=sys.stderr); sys.exit(2)

    framework = detect_framework(project)
    adapter = load_adapter(framework)
    ctx = ctx_default(framework)

    if adapter:
        try:
            ctx.update(adapter.collect_context(project))
        except Exception as e:
            print(f"[adapter] collect_context error: {e}", file=sys.stderr)

    semgrep_out = semgrep_scan(project)
    results = semgrep_out.get("results", [])
    findings = []
    order = {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}
    for r in results:
        f = {
            "path": r.get("path"),
            "start": r.get("start"),
            "end": r.get("end"),
            "extra": r.get("extra", {}),
            "severity": r.get("extra", {}).get("severity", "INFO"),
        }
        f["score"] = score_finding(f, ctx)
        # allow-host 降级
        msg_blob = (f["extra"].get("message") or "") + " " + (f["extra"].get("lines") or "")
        for pat in args.allow_host:
            try:
                if re.search(pat, msg_blob):
                    f["score"] = "LOW"
            except re.error:
                pass
        if order[f["score"]] >= order[args.min_score]:
            findings.append(f)

    OUTDIR.mkdir(parents=True, exist_ok=True)
    (OUTDIR / "hnp-findings.json").write_text(json.dumps({"context": ctx, "findings": findings}, indent=2), encoding="utf-8")
    evidence = build_evidence(results)
    (OUTDIR / "hnp-evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (OUTDIR / "hnp-report.md").write_text(render_report(findings, ctx), encoding="utf-8")
    write_csv(findings, ctx, OUTDIR / "hnp-summary.csv")
    if args.emit_sarif:
        write_sarif(findings, ctx, OUTDIR / "hnp.sarif")
    pocs = suggest_pocs(findings, ctx)
    (OUTDIR / "hnp-poc.json").write_text(json.dumps(pocs, indent=2), encoding="utf-8")
    print(f"[ok] Wrote {OUTDIR/'hnp-findings.json'}, {OUTDIR/'hnp-evidence.json'}, {OUTDIR/'hnp-report.md'}, {OUTDIR/'hnp-summary.csv'}")
    print(f"[ok] Extra outputs: {OUTDIR/'hnp-poc.json'}" + (" and hnp.sarif" if args.emit_sarif else ""))

if __name__ == "__main__":
    main()
