#!/usr/bin/env python3
"""
Merge individual JSON reports into unified files
"""
import json
import os
import time
from typing import Dict, Any, List

PROJECT_ROOT = "/home/rui/HNP_PHP"
APPLICATION_JSON_DIR = os.path.join(PROJECT_ROOT, "reports", "application_analysis", "json")
FRAMEWORK_JSON_DIR = os.path.join(PROJECT_ROOT, "reports", "framework_analysis", "json")


def merge_application_reports() -> None:
    """Merge all application analysis JSON files into one unified file"""
    print("🔄 Merging application analysis reports...")
    
    unified_data = {
        "metadata": {
            "total_projects": 0,
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_version": "1.0"
        },
        "projects": []
    }
    
    # Find all individual JSON files
    json_files = [f for f in os.listdir(APPLICATION_JSON_DIR) if f.endswith('_analysis.json')]
    
    for json_file in json_files:
        file_path = os.path.join(APPLICATION_JSON_DIR, json_file)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                analysis_data = json.load(f)
                unified_data["projects"].append(analysis_data)
                print(f"   ✅ Added: {analysis_data.get('repository', 'Unknown')}")
        except Exception as e:
            print(f"   ❌ Error reading {json_file}: {e}")
    
    # Update metadata
    unified_data["metadata"]["total_projects"] = len(unified_data["projects"])
    
    # Save unified file
    unified_file = os.path.join(APPLICATION_JSON_DIR, "unified_analysis_results.json")
    with open(unified_file, "w", encoding="utf-8") as f:
        json.dump(unified_data, f, ensure_ascii=False, indent=2)
    
    print(f"📊 Merged {len(unified_data['projects'])} application reports into {unified_file}")


def merge_framework_reports() -> None:
    """Merge all framework analysis JSON files into one unified file"""
    print("🔄 Merging framework analysis reports...")
    
    unified_data = {
        "metadata": {
            "total_frameworks": 0,
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_version": "1.0"
        },
        "frameworks": {}
    }
    
    # Find all individual JSON files (excluding deep analysis and unified files)
    json_files = [f for f in os.listdir(FRAMEWORK_JSON_DIR) 
                  if f.endswith('_report.json') and not f.startswith('unified')]
    
    for json_file in json_files:
        file_path = os.path.join(FRAMEWORK_JSON_DIR, json_file)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                analysis_data = json.load(f)
                # Extract framework name from filename
                framework_name = json_file.replace('_report.json', '')
                unified_data["frameworks"][framework_name] = analysis_data
                print(f"   ✅ Added: {framework_name}")
        except Exception as e:
            print(f"   ❌ Error reading {json_file}: {e}")
    
    # Update metadata
    unified_data["metadata"]["total_frameworks"] = len(unified_data["frameworks"])
    
    # Save unified file
    unified_file = os.path.join(FRAMEWORK_JSON_DIR, "unified_framework_analysis.json")
    with open(unified_file, "w", encoding="utf-8") as f:
        json.dump(unified_data, f, ensure_ascii=False, indent=2)
    
    print(f"📊 Merged {len(unified_data['frameworks'])} framework reports into {unified_file}")


def main():
    """Main function to merge all JSON reports"""
    print("🚀 Starting JSON report merging process...")
    
    # Ensure directories exist
    os.makedirs(APPLICATION_JSON_DIR, exist_ok=True)
    os.makedirs(FRAMEWORK_JSON_DIR, exist_ok=True)
    
    # Merge application reports
    merge_application_reports()
    
    # Merge framework reports
    merge_framework_reports()
    
    print("✅ JSON report merging completed!")


if __name__ == "__main__":
    main()
