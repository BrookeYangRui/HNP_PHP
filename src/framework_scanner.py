#!/usr/bin/env python3
"""
HNP Framework Scanner - Lightweight source→sink pattern scanner for PHP frameworks
"""
import argparse
import csv
import json
import os
from typing import Dict, Any, List, Tuple

import yaml


PROJECT_ROOT = "/home/rui/HNP_PHP"
FRAMEWORK_DIR = os.path.join(PROJECT_ROOT, "frameworks")
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports", "framework")
CSV_DIR = os.path.join(PROJECT_ROOT, "reports", "csv")
METADATA_FILE = os.path.join(PROJECT_ROOT, "config", "framework_config.yaml")


def ensure_dirs() -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)
    os.makedirs(CSV_DIR, exist_ok=True)


def load_metadata() -> Dict[str, Any]:
    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def read_text_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def find_matches_in_dir(root: str, patterns: List[str], exts: Tuple[str, ...]) -> int:
    total = 0
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            if not name.lower().endswith(exts):
                continue
            content = read_text_file(os.path.join(dirpath, name))
            for p in patterns:
                if p in content:
                    total += content.count(p)
    return total


def compute_security_state(total: int, unguarded: int, guarded: int) -> str:
    if total == 0:
        return "Safe"
    if guarded == 0:
        return "Risk"
    rate = guarded / max(total, 1)
    if rate >= 0.8:
        return "Protected"
    return "Partial"


def scan_framework(fw_key: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    fw_meta = metadata["frameworks"][fw_key]
    fw_path = os.path.join(FRAMEWORK_DIR, fw_key if fw_key != "codeigniter" else "codeigniter")
    if fw_key == "laravel":
        fw_path = os.path.join(FRAMEWORK_DIR, "laravel")
    elif fw_key == "symfony":
        fw_path = os.path.join(FRAMEWORK_DIR, "symfony")
    elif fw_key == "cakephp":
        fw_path = os.path.join(FRAMEWORK_DIR, "cakephp")
    elif fw_key == "yii":
        fw_path = os.path.join(FRAMEWORK_DIR, "yii")
    elif fw_key == "slim":
        fw_path = os.path.join(FRAMEWORK_DIR, "slim")
    elif fw_key == "laminas":
        fw_path = os.path.join(FRAMEWORK_DIR, "laminas")
    elif fw_key == "phalcon":
        fw_path = os.path.join(FRAMEWORK_DIR, "phalcon")
    elif fw_key == "codeigniter":
        fw_path = os.path.join(FRAMEWORK_DIR, "codeigniter")

    result = {
        "framework": fw_key,
        "sinks": [],
        "sources_total": 0,
    }

    # 简易 sources 计数
    source_patterns = []
    for s in fw_meta.get("sources", []):
        source_patterns.extend(s.get("patterns", []))
    result["sources_total"] = find_matches_in_dir(fw_path, source_patterns, (".php", ".phtml", ".twig", ".blade.php", ".php.dist", ".yaml", ".yml"))

    # 校验配置命中（作为 guard 的粗略代理）
    validation_paths = fw_meta.get("validations", [])
    guard_hits = 0
    for v in validation_paths:
        for cpath in v.get("config_paths", []):
            # 支持简单通配 * 仅在末尾目录层级
            if "*" in cpath:
                base = cpath.split("*")[0].rstrip("/")
                cfg_dir = os.path.join(fw_path, os.path.dirname(base))
                if os.path.isdir(cfg_dir):
                    guard_hits += 1
            else:
                if os.path.exists(os.path.join(fw_path, cpath)):
                    guard_hits += 1

    # 按 sink 统计
    for sink in fw_meta.get("sinks", []):
        patterns = sink.get("patterns", [])
        total = find_matches_in_dir(fw_path, patterns, (".php", ".phtml", ".twig", ".blade.php"))
        # 粗略估计：若存在相关验证配置文件则认为部分被保护
        guarded = min(total, guard_hits)
        unguarded = max(total - guarded, 0)
        state = compute_security_state(total, unguarded, guarded)
        result["sinks"].append({
            "name": sink.get("name", "unknown"),
            "patterns": patterns,
            "total": total,
            "guarded": guarded,
            "unguarded": unguarded,
            "security_state": state,
        })

    return result


def write_reports(fw_key: str, scan: Dict[str, Any]) -> None:
    # 更新单框架 YAML/JSON
    ypath = os.path.join(REPORT_DIR, f"{fw_key}_report.yaml")
    jpath = os.path.join(REPORT_DIR, f"{fw_key}_report.json")
    with open(ypath, "w", encoding="utf-8") as fy:
        yaml.safe_dump(scan, fy, sort_keys=False, allow_unicode=True)
    with open(jpath, "w", encoding="utf-8") as fj:
        json.dump(scan, fj, ensure_ascii=False, indent=2)

    # 追加写入详细 CSV
    detailed_path = os.path.join(CSV_DIR, "flow_api_risk_detailed.csv")
    header = [
        "Framework",
        "Canonical_API",
        "Aliases",
        "Category",
        "Description",
        "Total",
        "Unguarded",
        "Guarded",
        "Protected_Rate",
        "Security_State",
        "Recommendation",
    ]
    file_exists = os.path.exists(detailed_path)
    with open(detailed_path, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(header)
        for s in scan["sinks"]:
            total = s["total"]
            guarded = s["guarded"]
            rate = (guarded / total) if total else 1.0
            writer.writerow([
                fw_key,
                s["name"],
                "|".join(s.get("patterns", [])),
                "sink",
                "Auto scan",
                total,
                s["unguarded"],
                guarded,
                f"{rate:.2f}",
                s["security_state"],
                "Configure validation/guards",
            ])

    # 汇总 CSV
    summary_path = os.path.join(CSV_DIR, "flow_summary.csv")
    sum_header = ["Framework", "Sources", "Sinks", "Risk", "Partial", "Protected", "Safe"]
    counts = {"Risk": 0, "Partial": 0, "Protected": 0, "Safe": 0}
    for s in scan["sinks"]:
        counts[s["security_state"]] = counts.get(s["security_state"], 0) + 1
    with open(summary_path, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not os.path.exists(summary_path) or os.path.getsize(summary_path) == 0:
            writer.writerow(sum_header)
        writer.writerow([
            fw_key,
            scan["sources_total"],
            len(scan["sinks"]),
            counts.get("Risk", 0),
            counts.get("Partial", 0),
            counts.get("Protected", 0),
            counts.get("Safe", 0),
        ])


def main():
    ensure_dirs()
    parser = argparse.ArgumentParser(description="Lightweight framework source→sink scanner")
    parser.add_argument("--framework", nargs="+", required=True, help="framework keys, e.g., laravel symfony yii")
    args = parser.parse_args()

    metadata = load_metadata()
    for fw_key in args.framework:
        if fw_key not in metadata.get("frameworks", {}):
            print(f"Skipping unknown framework: {fw_key}")
            continue
        scan = scan_framework(fw_key, metadata)
        write_reports(fw_key, scan)
        print(f"✅ Scan completed: {fw_key}")


if __name__ == "__main__":
    main()


