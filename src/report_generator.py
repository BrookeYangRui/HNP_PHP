#!/usr/bin/env python3
import argparse
import csv
import json
import os
from typing import Dict, Any

import yaml

PROJECT_ROOT = "/home/rui/HNP_PHP"
FRAMEWORK_DIR = os.path.join(PROJECT_ROOT, "frameworks")
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports", "framework")
METADATA_FILE = os.path.join(PROJECT_ROOT, "tools", "framework_metadata.yaml")


def ensure_dirs() -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)


def load_metadata() -> Dict[str, Any]:
    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def init_framework_report(framework_key: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    fw = metadata["frameworks"].get(framework_key, {})
    return {
        "framework": framework_key,
        "sources": fw.get("sources", []),
        "sinks": fw.get("sinks", []),
        "validations": fw.get("validations", []),
        "summary": {
            "total_sources": len(fw.get("sources", [])),
            "total_sinks": len(fw.get("sinks", [])),
            "security_state": "Unknown",
        },
    }


def write_yaml_json(framework_key: str, report: Dict[str, Any]) -> None:
    ypath = os.path.join(REPORT_DIR, f"{framework_key}_report.yaml")
    jpath = os.path.join(REPORT_DIR, f"{framework_key}_report.json")
    with open(ypath, "w", encoding="utf-8") as fy:
        yaml.safe_dump(report, fy, sort_keys=False, allow_unicode=True)
    with open(jpath, "w", encoding="utf-8") as fj:
        json.dump(report, fj, ensure_ascii=False, indent=2)


def append_csv_matrix(framework_key: str, report: Dict[str, Any]) -> None:
    # 生成 flow_api_risk_detailed.csv 所需列的占位行
    detailed_path = os.path.join(PROJECT_ROOT, "reports", "csv", "flow_api_risk_detailed.csv")
    os.makedirs(os.path.dirname(detailed_path), exist_ok=True)

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

        # 简化占位：对每个 sink 生成一行
        for sink in report.get("sinks", []):
            writer.writerow(
                [
                    framework_key,
                    sink.get("name", "unknown"),
                    "|".join(sink.get("patterns", [])),
                    "sink",
                    "Auto-generated placeholder",
                    0,
                    0,
                    0,
                    0.0,
                    "Unknown",
                    "Review configuration and guards",
                ]
            )


def main():
    ensure_dirs()
    parser = argparse.ArgumentParser(description="Generate framework report templates")
    parser.add_argument("--framework", required=True, help="framework key, e.g., laravel/symfony/yii ...")
    args = parser.parse_args()

    metadata = load_metadata()
    fw_key = args.framework
    if fw_key not in metadata.get("frameworks", {}):
        raise SystemExit(f"Unknown framework key: {fw_key}")

    report = init_framework_report(fw_key, metadata)
    write_yaml_json(fw_key, report)
    append_csv_matrix(fw_key, report)
    print(f"✅ 生成报告模板完成: {fw_key}")


if __name__ == "__main__":
    main()


