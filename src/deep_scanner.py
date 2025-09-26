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
ANALYSIS_DIR = os.path.join(PROJECT_ROOT, "reports", "framework_analysis")
METADATA_FILE = os.path.join(PROJECT_ROOT, "config", "framework_config.yaml")
PHP_SCANNER_DIR = os.path.join(PROJECT_ROOT, "src")


def ensure_dirs(framework_name: str) -> None:
    """Ensure framework-specific directories exist."""
    framework_analysis_dir = os.path.join(ANALYSIS_DIR, framework_name)
    os.makedirs(framework_analysis_dir, exist_ok=True)
    return framework_analysis_dir


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


def update_csv_reports(analysis: Dict[str, Any], framework_dir: str) -> None:
    if "error" in analysis:
        print(f"❌ Skipping CSV update: {analysis['error']}")
        return
    
    framework = analysis["framework"]
    
    # Write framework-specific CSV in framework directory
    csv_path = os.path.join(framework_dir, f"{framework}_api_flows.csv")
    import csv as _csv
    
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = _csv.writer(f)
        writer.writerow([
            "source_file", "sink_file", "sink_line", "sink_symbol", 
            "scenario", "has_guard", "has_validation"
        ])
        
        for flow in analysis.get("flows", []):
            sink_symbol = flow.get("sink_symbol", "")
            impact = analysis.get("api_impact_analysis", {}).get(sink_symbol, {})
            scenario = impact.get("scenario", "Unknown impact")
            
            writer.writerow([
                flow.get("source_file", ""),
                flow.get("sink_file", ""),
                flow.get("sink_line", ""),
                sink_symbol,
                scenario,
                flow.get("has_guard", False),
                flow.get("has_validation", False)
            ])
    
    print(f"📊 CSV report saved: {csv_path}")


def main():
    parser = argparse.ArgumentParser(description="Integrate with php-hnp-scanner-pro for deep taint analysis")
    parser.add_argument("--framework", required=True, help="framework name (e.g., laravel, symfony)")
    parser.add_argument("--dry-run", action="store_true", help="Check environment only, don't run scan")
    args = parser.parse_args()

    framework_name = args.framework
    framework_path = os.path.join(FRAMEWORK_DIR, framework_name)
    if not os.path.exists(framework_path):
        print(f"❌ Framework directory not found: {framework_path}")
        sys.exit(1)

    # Create framework-specific directory
    framework_dir = ensure_dirs(framework_name)

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
    update_csv_reports(analysis, framework_dir)
    
    # Write framework-specific JSON in framework directory
    report_path = os.path.join(framework_dir, f"{framework_name}_api_flows.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(analysis, f, ensure_ascii=False, indent=2)
    
    # Generate optimized analysis files
    try:
        from analysis_generator import generate_all_analysis_files
        generated_files = generate_all_analysis_files(analysis, framework_dir)
        print(f"📊 Generated {len(generated_files)} optimized analysis files")
    except Exception as e:
        print(f"⚠️  Failed to generate optimized files: {e}")
    
    print(f"✅ Deep scan completed: {framework_name}")
    print(f"   Total flows: {analysis.get('total_flows', 0)}")
    print(f"   Unique symbols: {len(analysis.get('unique_symbols', []))}")
    print(f"   JSON report: {report_path}")
    print(f"   CSV report: {os.path.join(framework_dir, f'{framework_name}_api_flows.csv')}")
    print(f"   Framework directory: {framework_dir}")


if __name__ == "__main__":
    main()
