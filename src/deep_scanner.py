#!/usr/bin/env python3
"""
HNP Deep Scanner - Integration with php-hnp-scanner-pro for deep taint analysis
"""
import argparse
import json
import os
import subprocess
import sys
from typing import Dict, Any

import yaml

PROJECT_ROOT = "/home/rui/HNP_PHP"
FRAMEWORK_DIR = os.path.join(PROJECT_ROOT, "frameworks")
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports", "framework_analysis", "json")
CSV_DIR = os.path.join(PROJECT_ROOT, "reports", "framework_analysis", "csv")
METADATA_FILE = os.path.join(PROJECT_ROOT, "config", "framework_config.yaml")
PHP_SCANNER_DIR = os.path.join(PROJECT_ROOT, "src")


def ensure_dirs() -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)
    os.makedirs(CSV_DIR, exist_ok=True)


def load_metadata() -> Dict[str, Any]:
    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def check_php_scanner() -> bool:
    if not os.path.exists(PHP_SCANNER_DIR):
        print(f"❌ php-hnp-scanner-pro directory not found: {PHP_SCANNER_DIR}")
        return False
    composer_json = os.path.join(PHP_SCANNER_DIR, "composer.json")
    if not os.path.exists(composer_json):
        print(f"❌ composer.json not found: {composer_json}")
        return False
    return True


def run_php_scanner(framework_path: str, framework_name: str) -> Dict[str, Any]:
    """Use external taint adapter only (Plan C)."""
    try:
        from external_taint import run_framework_scan
    except Exception as e:
        return {"error": f"External adapter not available: {e}"}
    try:
        return run_framework_scan(framework_path, framework_name)
    except Exception as e:
        return {"error": f"External scan failed: {e}"}


def analyze_taint_flows(scan_result: Dict[str, Any], framework_name: str) -> Dict[str, Any]:
    if "error" in scan_result:
        return scan_result
    flows = scan_result.get("flows", [])
    sources = scan_result.get("sources", [])
    sinks = scan_result.get("sinks", [])
    states = {"Safe": 0, "Risk": 0, "Partial": 0, "Protected": 0}
    for flow in flows:
        has_guard = flow.get("has_guard", False)
        has_validation = flow.get("has_validation", False)
        if has_guard and has_validation:
            states["Protected"] += 1
        elif has_guard or has_validation:
            states["Partial"] += 1
        else:
            states["Risk"] += 1
    if not flows:
        states["Safe"] = 1
    # Provide simple filtering-ready structure per sink type
    flows_by_sink = {}
    for f in flows:
        st = f.get("sink_type", "unknown")
        flows_by_sink.setdefault(st, []).append(f)

    return {
        "framework": framework_name,
        "total_flows": len(flows),
        "total_sources": len(sources),
        "total_sinks": len(sinks),
        "security_states": states,
        "flows": flows,
        "sources": sources,
        "sinks": sinks,
        "flows_by_sink": flows_by_sink,
    }


def update_csv_reports(analysis: Dict[str, Any]) -> None:
    if "error" in analysis:
        print(f"❌ Skipping CSV update: {analysis['error']}")
        return
    framework = analysis["framework"]
    detailed_path = os.path.join(CSV_DIR, "flow_api_risk_detailed.csv")
    # 以 sink Type聚合（支持后续筛选）
    by_sink = {}
    for f in analysis.get("flows", []):
        st = f.get("sink_type", "unknown")
        by_sink.setdefault(st, {"total": 0, "risk": 0, "guarded": 0})
        by_sink[st]["total"] += 1
        if not f.get("has_guard") and not f.get("has_validation"):
            by_sink[st]["risk"] += 1
        else:
            by_sink[st]["guarded"] += 1
    import csv as _csv
    for sink_type, agg in by_sink.items():
        total = agg["total"]
        risk = agg["risk"]
        guarded = agg["guarded"]
        rate = (guarded / total) if total > 0 else 1.0
        if total == 0:
            security_state = "Safe"
        elif risk == 0 or rate >= 0.8:
            security_state = "Protected"
        elif rate >= 0.3:
            security_state = "Partial"
        else:
            security_state = "Risk"
        with open(detailed_path, "a", encoding="utf-8", newline="") as f:
            w = _csv.writer(f)
            w.writerow([
                framework,
                sink_type,
                "",
                "sink",
                "Deep taint analysis (interprocedural)",
                total,
                risk,
                guarded,
                f"{rate:.2f}",
                security_state,
                "Configure guards/validation",
            ])


def main():
    ensure_dirs()
    parser = argparse.ArgumentParser(description="Integrate with php-hnp-scanner-pro for deep taint analysis")
    parser.add_argument("--framework", required=True, help="framework name (e.g., laravel, symfony)")
    parser.add_argument("--dry-run", action="store_true", help="Check environment only, don't run scan")
    args = parser.parse_args()

    framework_name = args.framework
    framework_path = os.path.join(FRAMEWORK_DIR, framework_name)
    if not os.path.exists(framework_path):
        print(f"❌ Framework directory not found: {framework_path}")
        sys.exit(1)

    if args.dry_run:
        ok = check_php_scanner()
        print(f"✅ Environment check: {ok}")
        sys.exit(0 if ok else 1)

    print(f"🔍 Starting deep scan: {framework_name}")
    scan_result = run_php_scanner(framework_path, framework_name)
    if "error" in scan_result:
        print(f"❌ Scan failed: {scan_result['error']}")
        sys.exit(1)
    analysis = analyze_taint_flows(scan_result, framework_name)
    update_csv_reports(analysis)
    report_path = os.path.join(REPORT_DIR, f"{framework_name}_deep_analysis.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(analysis, f, ensure_ascii=False, indent=2)
    print(f"✅ Deep scan completed: {framework_name}")
    print(f"   Total flows: {analysis['total_flows']}")
    print(f"   Security states: {analysis['security_states']}")


if __name__ == "__main__":
    main()
