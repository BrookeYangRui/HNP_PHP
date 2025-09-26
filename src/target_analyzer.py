#!/usr/bin/env python3
"""
Target Analyzer - Download and analyze vulnerable PHP projects from target list
"""
import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from typing import Dict, Any, List, Tuple

import yaml


PROJECT_ROOT = "/home/rui/HNP_PHP"
TARGET_LIST_FILE = os.path.join(PROJECT_ROOT, "target-list", "defense_result_php.csv")
TARGET_DIR = os.path.join(PROJECT_ROOT, "targets")
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports", "application_analysis", "json")
CSV_DIR = os.path.join(PROJECT_ROOT, "reports", "application_analysis", "csv")
PROGRESS_FILE = os.path.join(PROJECT_ROOT, "progress.json")


def ensure_dirs() -> None:
    os.makedirs(TARGET_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)
    os.makedirs(CSV_DIR, exist_ok=True)


def load_target_list() -> List[Dict[str, str]]:
    """Load target list from CSV file"""
    targets = []
    with open(TARGET_LIST_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            targets.append({
                "index": row["Index"],
                "repository": row["Repository"],
                "url": row["URL"],
                "stars": row["Stars"],
                "year": row["Year"],
                "matched_function": row["Matched Function"]
            })
    return targets


def git_clone_project(repo_url: str, target_dir: str) -> bool:
    """Clone a project repository"""
    try:
        if not shutil.which("git"):
            print("❌ git not installed")
            return False
        
        # Remove existing directory if exists
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
        
        print(f"📥 Cloning {repo_url}...")
        result = subprocess.run([
            "git", "clone", "--depth", "1", "--single-branch", repo_url, target_dir
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"❌ Clone failed: {result.stderr}")
            return False
        
        return True
    except subprocess.TimeoutExpired:
        print("❌ Clone timeout")
        return False
    except Exception as e:
        print(f"❌ Clone error: {e}")
        return False


def analyze_project(project_dir: str, target_info: Dict[str, str]) -> Dict[str, Any]:
    """Analyze a single project for HNP vulnerabilities"""
    analysis = {
        "repository": target_info["repository"],
        "url": target_info["url"],
        "stars": target_info["stars"],
        "year": target_info["year"],
        "matched_function": target_info["matched_function"],
        "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "files_analyzed": 0,
        "vulnerabilities_found": 0,
        "vulnerability_details": [],
        "vulnerability_scenarios": [],
        "framework_detected": None,
        "security_state": "Unknown",
        "taint_tracking_detected": False,
        "taint_tracking_evidence": []
    }
    
    # Detect framework
    framework = detect_framework(project_dir)
    analysis["framework_detected"] = framework
    
    # Count PHP files
    php_files = count_php_files(project_dir)
    analysis["files_analyzed"] = php_files
    
    # Run external taint scan (Plan C)
    try:
        from external_taint import run_app_scan
        taint_res = run_app_scan(project_dir)
    except Exception as e:
        taint_res = {"error": f"External adapter error: {e}"}

    # Normalize into analysis fields
    if "error" not in taint_res:
        flows = taint_res.get("flows", [])
        analysis["vulnerabilities_found"] = len(flows)
        analysis["vulnerability_details"] = flows
        analysis["vulnerability_scenarios"] = flows  # keep same structure for unified json
        analysis["taint_tracking_detected"] = len(flows) > 0
        analysis["taint_tracking_evidence"] = taint_res.get("sinks", [])
    else:
        analysis["taint_tracking_detected"] = False
        analysis["taint_tracking_evidence"] = [taint_res]
    
    # Determine security state
    if analysis["vulnerabilities_found"] == 0:
        analysis["security_state"] = "Safe"
    elif analysis["vulnerabilities_found"] > 10:
        analysis["security_state"] = "High Risk"
    elif analysis["vulnerabilities_found"] > 5:
        analysis["security_state"] = "Medium Risk"
    else:
        analysis["security_state"] = "Low Risk"
    
    return analysis


def detect_framework(project_dir: str) -> str:
    """Detect which PHP framework is used"""
    framework_indicators = {
        "Laravel": ["artisan", "composer.json", "app/Http"],
        "Symfony": ["symfony", "src/", "config/packages"],
        "CodeIgniter": ["system/core", "application/", "index.php"],
        "CakePHP": ["app/", "lib/Cake", "config/core.php"],
        "Yii": ["framework/", "protected/", "yii.php"],
        "WordPress": ["wp-config.php", "wp-includes/", "wp-admin/"],
        "ThinkPHP": ["ThinkPHP/", "Application/", "index.php"],
        "Zend": ["library/Zend", "application/", "public/"],
        "Slim": ["vendor/slim", "src/", "public/"],
        "Phalcon": ["app/", "public/", "config/"]
    }
    
    for framework, indicators in framework_indicators.items():
        for indicator in indicators:
            if os.path.exists(os.path.join(project_dir, indicator)):
                return framework
    
    return "Unknown"


def count_php_files(project_dir: str) -> int:
    """Count PHP files in the project"""
    count = 0
    for root, dirs, files in os.walk(project_dir):
        # Skip vendor, node_modules, .git directories
        dirs[:] = [d for d in dirs if d not in ['.git', 'vendor', 'node_modules', 'cache', 'logs']]
        for file in files:
            if file.endswith(('.php', '.phtml')):
                count += 1
    return count


def scan_hnp_patterns_with_scenarios(project_dir: str, matched_function: str) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Scan for HNP vulnerability patterns and analyze scenarios"""
    vulnerabilities = []
    scenarios = []
    
    # Extract vulnerability type from matched function
    vuln_type = matched_function.split('_')[-1] if '_' in matched_function else "unknown"
    
    # Common HNP patterns
    patterns = {
        "https": ["https://", "HTTPS://", "https://$_SERVER", "https://$HTTP_HOST"],
        "http": ["http://", "HTTP://", "http://$_SERVER", "http://$HTTP_HOST"],
        "server_name": ["$_SERVER['SERVER_NAME']", "$_SERVER[\"SERVER_NAME\"]", "SERVER_NAME"],
        "http_host": ["$_SERVER['HTTP_HOST']", "$_SERVER[\"HTTP_HOST\"]", "HTTP_HOST"]
    }
    
    search_patterns = patterns.get(vuln_type, patterns["http"])
    
    for root, dirs, files in os.walk(project_dir):
        # Skip vendor, node_modules, .git directories
        dirs[:] = [d for d in dirs if d not in ['.git', 'vendor', 'node_modules', 'cache', 'logs']]
        
        for file in files:
            if file.endswith(('.php', '.phtml')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        lines = content.split('\n')
                        
                        for i, line in enumerate(lines, 1):
                            for pattern in search_patterns:
                                if pattern in line:
                                    # Basic vulnerability record
                                    vuln = {
                                        "file": os.path.relpath(file_path, project_dir),
                                        "line": i,
                                        "pattern": pattern,
                                        "snippet": line.strip()[:100]
                                    }
                                    vulnerabilities.append(vuln)
                                    
                                    # Analyze vulnerability scenario
                                    scenario = analyze_vulnerability_scenario(lines, i, pattern, vuln_type)
                                    if scenario:
                                        scenarios.append(scenario)
                                        
                except Exception:
                    continue
    
    return vulnerabilities, scenarios


def analyze_vulnerability_scenario(lines: List[str], line_num: int, pattern: str, vuln_type: str) -> Dict[str, str]:
    """Analyze the context around a vulnerability to determine the scenario"""
    scenario = {
        "file": "",
        "line": line_num,
        "pattern": pattern,
        "scenario_type": "Unknown",
        "context": "",
        "risk_level": "Medium",
        "description": ""
    }
    
    # Get context (5 lines before and after)
    start = max(0, line_num - 6)
    end = min(len(lines), line_num + 5)
    context_lines = lines[start:end]
    context = "\n".join([f"{start + i + 1:3d}: {line}" for i, line in enumerate(context_lines)])
    
    scenario["context"] = context
    
    # Analyze scenario based on context
    line_content = lines[line_num - 1].lower()
    
    # URL Generation scenarios
    if any(keyword in line_content for keyword in ["url", "link", "href", "src", "redirect"]):
        scenario["scenario_type"] = "URL Generation"
        scenario["description"] = "Host header used in URL generation without validation"
        scenario["risk_level"] = "High"
    
    # Authentication scenarios
    elif any(keyword in line_content for keyword in ["login", "auth", "session", "token", "oauth"]):
        scenario["scenario_type"] = "Authentication Bypass"
        scenario["description"] = "Host header used in authentication logic"
        scenario["risk_level"] = "Critical"
    
    # Cache scenarios
    elif any(keyword in line_content for keyword in ["cache", "memcache", "redis", "session"]):
        scenario["scenario_type"] = "Cache Poisoning"
        scenario["description"] = "Host header used in cache key generation"
        scenario["risk_level"] = "High"
    
    # Email scenarios
    elif any(keyword in line_content for keyword in ["mail", "email", "smtp", "send"]):
        scenario["scenario_type"] = "Email Spoofing"
        scenario["description"] = "Host header used in email generation"
        scenario["risk_level"] = "Medium"
    
    # API scenarios
    elif any(keyword in line_content for keyword in ["api", "endpoint", "request", "response"]):
        scenario["scenario_type"] = "API Manipulation"
        scenario["description"] = "Host header used in API responses"
        scenario["risk_level"] = "Medium"
    
    # Configuration scenarios
    elif any(keyword in line_content for keyword in ["config", "setting", "env", "define"]):
        scenario["scenario_type"] = "Configuration Injection"
        scenario["description"] = "Host header used in configuration"
        scenario["risk_level"] = "High"
    
    # Default scenario
    else:
        scenario["scenario_type"] = "General HNP"
        scenario["description"] = f"Host header used in {vuln_type} context without validation"
        scenario["risk_level"] = "Medium"
    
    return scenario


def detect_taint_tracking(project_dir: str) -> List[Dict[str, str]]:
    """Detect if the project uses real taint tracking mechanisms"""
    taint_evidence = []
    
    # Look for taint tracking indicators
    taint_indicators = [
        # Static analysis tools
        "psalm", "phpstan", "phan", "phpcs", "phpcbf",
        # Security scanners
        "semgrep", "sonarqube", "snyk", "veracode",
        # Custom taint tracking
        "taint", "sanitize", "validate", "escape",
        # Framework security features
        "csrf", "xss", "sql_injection", "input_validation"
    ]
    
    # Check composer.json for security tools
    composer_file = os.path.join(project_dir, "composer.json")
    if os.path.exists(composer_file):
        try:
            with open(composer_file, "r", encoding="utf-8") as f:
                content = f.read().lower()
                for indicator in taint_indicators:
                    if indicator in content:
                        taint_evidence.append({
                            "type": "composer_dependency",
                            "file": "composer.json",
                            "evidence": f"Found {indicator} in composer.json",
                            "confidence": "High"
                        })
        except Exception:
            pass
    
    # Check for configuration files
    config_files = [
        "psalm.xml", "phpstan.neon", "phan.php", ".phpcs.xml",
        "semgrep.yml", "sonar-project.properties", ".snyk"
    ]
    
    for config_file in config_files:
        config_path = os.path.join(project_dir, config_file)
        if os.path.exists(config_path):
            taint_evidence.append({
                "type": "config_file",
                "file": config_file,
                "evidence": f"Found {config_file} configuration",
                "confidence": "High"
            })
    
    # Check for security-related code patterns
    security_patterns = [
        "filter_var", "htmlspecialchars", "mysqli_real_escape_string",
        "PDO::quote", "addslashes", "strip_tags", "preg_replace"
    ]
    
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in ['.git', 'vendor', 'node_modules']]
        
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for pattern in security_patterns:
                            if pattern in content:
                                taint_evidence.append({
                                    "type": "security_function",
                                    "file": os.path.relpath(file_path, project_dir),
                                    "evidence": f"Found {pattern} usage",
                                    "confidence": "Medium"
                                })
                except Exception:
                    continue
    
    return taint_evidence


def save_analysis_report(analysis: Dict[str, Any]) -> None:
    """Save analysis report to unified JSON file"""
    unified_report_file = os.path.join(REPORT_DIR, "unified_analysis_results.json")
    
    # Load existing data or create new structure
    if os.path.exists(unified_report_file):
        try:
            with open(unified_report_file, "r", encoding="utf-8") as f:
                unified_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            unified_data = {
                "metadata": {
                    "total_projects": 0,
                    "last_updated": "",
                    "analysis_version": "1.0"
                },
                "projects": []
            }
    else:
        unified_data = {
            "metadata": {
                "total_projects": 0,
                "last_updated": "",
                "analysis_version": "1.0"
            },
            "projects": []
        }
    
    # Check if project already exists and update or add
    repo_name = analysis["repository"]
    existing_project = None
    for i, project in enumerate(unified_data["projects"]):
        if project["repository"] == repo_name:
            existing_project = i
            break
    
    if existing_project is not None:
        # Update existing project
        unified_data["projects"][existing_project] = analysis
    else:
        # Add new project
        unified_data["projects"].append(analysis)
    
    # Update metadata
    unified_data["metadata"]["total_projects"] = len(unified_data["projects"])
    unified_data["metadata"]["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Save unified report
    with open(unified_report_file, "w", encoding="utf-8") as f:
        json.dump(unified_data, f, ensure_ascii=False, indent=2)


def update_target_csv(analysis: Dict[str, Any]) -> None:
    """Update target analysis CSV file"""
    csv_file = os.path.join(CSV_DIR, "target_analysis_results.csv")
    
    # Check if file exists to determine if we need headers
    file_exists = os.path.exists(csv_file)
    
    with open(csv_file, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        
        if not file_exists:
            writer.writerow([
                "Repository", "URL", "Stars", "Year", "Framework", 
                "Files_Analyzed", "Vulnerabilities_Found", "Security_State",
                "Matched_Function", "Analysis_Time", "Taint_Tracking_Detected",
                "Vulnerability_Scenarios", "Top_Scenario_Type", "Top_Risk_Level"
            ])
        
        # Get top scenario type and risk level
        scenarios = analysis.get("vulnerability_scenarios", [])
        top_scenario = "None"
        top_risk = "Unknown"
        if scenarios:
            scenario_types = [s.get("scenario_type", "Unknown") for s in scenarios]
            risk_levels = [s.get("risk_level", "Unknown") for s in scenarios]
            top_scenario = max(set(scenario_types), key=scenario_types.count)
            top_risk = max(set(risk_levels), key=risk_levels.count)
        
        writer.writerow([
            analysis["repository"],
            analysis["url"],
            analysis["stars"],
            analysis["year"],
            analysis["framework_detected"],
            analysis["files_analyzed"],
            analysis["vulnerabilities_found"],
            analysis["security_state"],
            analysis["matched_function"],
            analysis["analysis_time"],
            analysis["taint_tracking_detected"],
            len(scenarios),
            top_scenario,
            top_risk
        ])


def cleanup_project(project_dir: str) -> None:
    """Remove the downloaded project directory"""
    try:
        if os.path.exists(project_dir):
            shutil.rmtree(project_dir)
            print(f"🗑️  Cleaned up {project_dir}")
    except Exception as e:
        print(f"❌ Cleanup failed: {e}")


def save_progress(completed_indices: List[int], total_targets: int, analysis_stats: Dict[str, Any] = None) -> None:
    """Save progress to JSON file with statistics"""
    progress = {
        "completed_indices": completed_indices,
        "total_targets": total_targets,
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "progress_percentage": (len(completed_indices) / total_targets) * 100,
        "statistics": analysis_stats or {
            "total_analyzed": 0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0,
            "safe_count": 0,
            "taint_tracking_detected_count": 0,
            "frameworks": {},
            "scenario_types": {},
            "vulnerability_totals": 0,
            "files_analyzed_total": 0
        }
    }
    
    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump(progress, f, indent=2)


def load_progress() -> Tuple[List[int], Dict[str, Any]]:
    """Load progress from JSON file"""
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
                progress = json.load(f)
                return progress.get("completed_indices", []), progress.get("statistics", {})
        except Exception:
            return [], {}
    return [], {}


def check_duplicate_analysis(repository: str) -> bool:
    """Check if repository has already been analyzed"""
    csv_file = os.path.join(CSV_DIR, "target_analysis_results.csv")
    if not os.path.exists(csv_file):
        return False
    
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            content = f.read()
            return repository in content
    except Exception:
        return False


def update_statistics(analysis: Dict[str, Any], current_stats: Dict[str, Any]) -> Dict[str, Any]:
    """Update analysis statistics"""
    stats = current_stats.copy()
    
    # Initialize nested dictionaries if they don't exist
    if "frameworks" not in stats:
        stats["frameworks"] = {}
    if "scenario_types" not in stats:
        stats["scenario_types"] = {}
    
    # Basic counts
    stats["total_analyzed"] = stats.get("total_analyzed", 0) + 1
    stats["vulnerability_totals"] = stats.get("vulnerability_totals", 0) + analysis["vulnerabilities_found"]
    stats["files_analyzed_total"] = stats.get("files_analyzed_total", 0) + analysis["files_analyzed"]
    
    # Security state counts
    security_state = analysis["security_state"]
    if security_state == "High Risk":
        stats["high_risk_count"] = stats.get("high_risk_count", 0) + 1
    elif security_state == "Medium Risk":
        stats["medium_risk_count"] = stats.get("medium_risk_count", 0) + 1
    elif security_state == "Low Risk":
        stats["low_risk_count"] = stats.get("low_risk_count", 0) + 1
    elif security_state == "Safe":
        stats["safe_count"] = stats.get("safe_count", 0) + 1
    
    # Taint tracking count
    if analysis["taint_tracking_detected"]:
        stats["taint_tracking_detected_count"] = stats.get("taint_tracking_detected_count", 0) + 1
    
    # Framework counts
    framework = analysis["framework_detected"]
    if framework:
        stats["frameworks"][framework] = stats["frameworks"].get(framework, 0) + 1
    
    # Scenario type counts
    scenarios = analysis.get("vulnerability_scenarios", [])
    for scenario in scenarios:
        scenario_type = scenario.get("scenario_type", "Unknown")
        stats["scenario_types"][scenario_type] = stats["scenario_types"].get(scenario_type, 0) + 1
    
    return stats


def analyze_single_target(target_info: Dict[str, str], keep_files: bool = False, current_stats: Dict[str, Any] = None) -> Tuple[bool, Dict[str, Any]]:
    """Analyze a single target project"""
    repo_name = target_info["repository"].replace("/", "_")
    project_dir = os.path.join(TARGET_DIR, repo_name)
    
    # Check for duplicates
    if check_duplicate_analysis(target_info["repository"]):
        print(f"⏭️  Skipping {target_info['repository']} (already analyzed)")
        return True, current_stats or {}
    
    print(f"\n🔍 Analyzing: {target_info['repository']}")
    print(f"   URL: {target_info['url']}")
    print(f"   Stars: {target_info['stars']}, Year: {target_info['year']}")
    print(f"   Vulnerability: {target_info['matched_function']}")
    
    # Clone project
    if not git_clone_project(target_info["url"], project_dir):
        return False, current_stats or {}
    
    # Analyze project
    analysis = analyze_project(project_dir, target_info)
    
    # Save results
    save_analysis_report(analysis)
    update_target_csv(analysis)
    
    # Update statistics
    updated_stats = update_statistics(analysis, current_stats or {})
    
    # Print summary
    print(f"   Framework: {analysis['framework_detected']}")
    print(f"   Files analyzed: {analysis['files_analyzed']}")
    print(f"   Vulnerabilities found: {analysis['vulnerabilities_found']}")
    print(f"   Security state: {analysis['security_state']}")
    print(f"   Taint tracking: {'Yes' if analysis['taint_tracking_detected'] else 'No'}")
    
    # Print vulnerability scenarios
    scenarios = analysis.get("vulnerability_scenarios", [])
    if scenarios:
        scenario_types = [s.get("scenario_type", "Unknown") for s in scenarios]
        top_scenario = max(set(scenario_types), key=scenario_types.count)
        print(f"   Top scenario: {top_scenario}")
    
    # Cleanup
    if not keep_files:
        cleanup_project(project_dir)
    
    return True, updated_stats


def main():
    ensure_dirs()
    
    parser = argparse.ArgumentParser(description="Analyze vulnerable PHP projects from target list")
    parser.add_argument("--start", type=int, default=0, help="Start index (0-based)")
    parser.add_argument("--count", type=int, default=10, help="Number of projects to analyze")
    parser.add_argument("--keep", action="store_true", help="Keep downloaded files (don't cleanup)")
    parser.add_argument("--single", type=int, help="Analyze single project by index")
    parser.add_argument("--resume", action="store_true", help="Resume from last progress")
    parser.add_argument("--clear-progress", action="store_true", help="Clear progress and start fresh")
    args = parser.parse_args()
    
    # Load target list
    targets = load_target_list()
    print(f"📋 Loaded {len(targets)} targets from {TARGET_LIST_FILE}")
    
    # Handle progress
    completed_indices = []
    analysis_stats = {}
    if args.clear_progress and os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)
        print("🗑️  Cleared progress file")
    elif args.resume:
        completed_indices, analysis_stats = load_progress()
        print(f"📈 Resuming from progress: {len(completed_indices)}/{len(targets)} completed")
        if analysis_stats:
            print(f"📊 Current statistics:")
            print(f"   Total analyzed: {analysis_stats.get('total_analyzed', 0)}")
            print(f"   High risk: {analysis_stats.get('high_risk_count', 0)}")
            print(f"   Medium risk: {analysis_stats.get('medium_risk_count', 0)}")
            print(f"   Low risk: {analysis_stats.get('low_risk_count', 0)}")
            print(f"   Safe: {analysis_stats.get('safe_count', 0)}")
            print(f"   Taint tracking detected: {analysis_stats.get('taint_tracking_detected_count', 0)}")
    
    if args.single is not None:
        # Analyze single project
        if 0 <= args.single < len(targets):
            success, updated_stats = analyze_single_target(targets[args.single], args.keep, analysis_stats)
            # Update progress
            if success and args.single not in completed_indices:
                completed_indices.append(args.single)
                save_progress(completed_indices, len(targets), updated_stats)
        else:
            print(f"❌ Invalid index: {args.single}")
            sys.exit(1)
    else:
        # Analyze multiple projects
        if args.resume:
            # Skip already completed projects
            remaining_indices = [i for i in range(len(targets)) if i not in completed_indices]
            if not remaining_indices:
                print("✅ All projects already completed!")
                return
            
            start_idx = remaining_indices[0]
            end_idx = min(start_idx + args.count, len(targets))
        else:
            start_idx = args.start
            end_idx = min(start_idx + args.count, len(targets))
        
        print(f"🎯 Analyzing projects {start_idx} to {end_idx-1}")
        
        success_count = 0
        for i in range(start_idx, end_idx):
            if i in completed_indices:
                print(f"⏭️  Skipping {targets[i]['repository']} (already completed)")
                continue
                
            target = targets[i]
            success, updated_stats = analyze_single_target(target, args.keep, analysis_stats)
            if success:
                success_count += 1
                completed_indices.append(i)
                analysis_stats = updated_stats
                save_progress(completed_indices, len(targets), analysis_stats)
            
            # Small delay to avoid overwhelming GitHub
            time.sleep(1)
        
        print(f"\n✅ Analysis completed: {success_count}/{end_idx-start_idx} projects analyzed successfully")
        print(f"📊 Total progress: {len(completed_indices)}/{len(targets)} projects completed")
        
        # Print final statistics
        if analysis_stats:
            print(f"\n📈 Analysis Statistics:")
            print(f"   Total analyzed: {analysis_stats.get('total_analyzed', 0)}")
            print(f"   High risk: {analysis_stats.get('high_risk_count', 0)}")
            print(f"   Medium risk: {analysis_stats.get('medium_risk_count', 0)}")
            print(f"   Low risk: {analysis_stats.get('low_risk_count', 0)}")
            print(f"   Safe: {analysis_stats.get('safe_count', 0)}")
            print(f"   Taint tracking detected: {analysis_stats.get('taint_tracking_detected_count', 0)}")
            print(f"   Total vulnerabilities found: {analysis_stats.get('vulnerability_totals', 0)}")
            print(f"   Total files analyzed: {analysis_stats.get('files_analyzed_total', 0)}")
            
            # Framework breakdown
            frameworks = analysis_stats.get('frameworks', {})
            if frameworks:
                print(f"   Framework breakdown:")
                for fw, count in sorted(frameworks.items(), key=lambda x: x[1], reverse=True):
                    print(f"     {fw}: {count}")
            
            # Scenario breakdown
            scenarios = analysis_stats.get('scenario_types', {})
            if scenarios:
                print(f"   Scenario breakdown:")
                for scenario, count in sorted(scenarios.items(), key=lambda x: x[1], reverse=True):
                    print(f"     {scenario}: {count}")


if __name__ == "__main__":
    main()
