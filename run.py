#!/usr/bin/env python3
"""
HNP PHP Analysis System - Unified Runner
Simple interface for all analysis tasks
"""
import argparse
import os
import sys
import subprocess
from typing import List

PROJECT_ROOT = "/home/rui/HNP_PHP"
SRC_DIR = os.path.join(PROJECT_ROOT, "src")


def run_command(cmd: List[str], description: str) -> bool:
    """Run a command and return success status"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, cwd=PROJECT_ROOT, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e.stderr}")
        return False


def check_framework_exists(framework: str) -> bool:
    """Check if framework is already downloaded"""
    framework_dir = os.path.join(PROJECT_ROOT, "frameworks", framework)
    return os.path.exists(framework_dir) and os.path.isdir(framework_dir)


def download_frameworks(frameworks: List[str]) -> None:
    """Download specified frameworks (skip if already exists)"""
    for fw in frameworks:
        if check_framework_exists(fw):
            print(f"⏭️  {fw} already exists, skipping download")
            continue
            
        fw_map = {
            "laravel": 1, "symfony": 2, "codeigniter": 3, 
            "cakephp": 4, "yii": 5, "slim": 6, "laminas": 7, "phalcon": 8
        }
        if fw.lower() in fw_map:
            cmd = ["python3", "src/framework_cli.py", "--download", str(fw_map[fw.lower()])]
            run_command(cmd, f"Downloading {fw}")


def analyze_frameworks(frameworks: List[str]) -> None:
    """Analyze frameworks for HNP vulnerabilities"""
    if not frameworks:
        frameworks = ["laravel", "symfony", "codeigniter", "cakephp", "yii"]
    
    # Generate reports
    cmd = ["python3", "src/report_generator.py", "--framework"] + frameworks
    run_command(cmd, "Generating framework reports")
    
    # Scan for vulnerabilities
    cmd = ["python3", "src/framework_scanner.py", "--framework"] + frameworks
    run_command(cmd, "Scanning framework vulnerabilities")
    
    # Generate charts
    cmd = ["python3", "src/chart_generator.py"]
    run_command(cmd, "Generating charts and tables")


def analyze_applications(start: int = 0, count: int = 10, resume: bool = False) -> None:
    """Analyze vulnerable applications"""
    cmd = ["python3", "src/target_analyzer.py"]
    
    if resume:
        cmd.extend(["--resume", "--count", str(count)])
    else:
        cmd.extend(["--start", str(start), "--count", str(count)])
    
    run_command(cmd, f"Analyzing applications {start} to {start + count - 1}")


def show_results() -> None:
    """Show analysis results"""
    print("\n📊 Analysis Results:")
    
    # Framework results
    framework_json = os.path.join(PROJECT_ROOT, "reports", "framework_analysis", "json", "unified_framework_analysis.json")
    if os.path.exists(framework_json):
        print(f"✅ Framework analysis: {framework_json}")
    
    # Application results
    app_json = os.path.join(PROJECT_ROOT, "reports", "application_analysis", "json", "unified_analysis_results.json")
    if os.path.exists(app_json):
        print(f"✅ Application analysis: {app_json}")
    
    # Progress
    progress_file = os.path.join(PROJECT_ROOT, "progress.json")
    if os.path.exists(progress_file):
        print(f"✅ Progress tracking: {progress_file}")
    
    # CSV summaries
    csv_files = [
        "reports/framework_analysis/csv/flow_summary.csv",
        "reports/application_analysis/csv/target_analysis_results.csv"
    ]
    
    for csv_file in csv_files:
        full_path = os.path.join(PROJECT_ROOT, csv_file)
        if os.path.exists(full_path):
            print(f"✅ CSV report: {csv_file}")


def interactive_menu():
    """Interactive menu for analysis selection"""
    print("\n🎯 HNP PHP Analysis System")
    print("=" * 40)
    print("1. Framework Analysis (Web Frameworks)")
    print("2. Application Analysis (Vulnerable Projects)")
    print("3. Show Results")
    print("4. Exit")
    print("=" * 40)
    
    while True:
        try:
            choice = input("\nSelect analysis type (1-4): ").strip()
            
            if choice == "1":
                framework_analysis_menu()
                break
            elif choice == "2":
                application_analysis_menu()
                break
            elif choice == "3":
                show_results()
                break
            elif choice == "4":
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please select 1-4.")
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break


def framework_analysis_menu():
    """Framework analysis submenu"""
    print("\n🔧 Framework Analysis")
    print("=" * 30)
    print("Available frameworks:")
    
    frameworks = ["laravel", "symfony", "codeigniter", "cakephp", "yii"]
    for i, fw in enumerate(frameworks, 1):
        status = "✅ Downloaded" if check_framework_exists(fw) else "❌ Not downloaded"
        print(f"{i}. {fw.capitalize()} - {status}")
    
    print("6. All frameworks")
    print("7. Back to main menu")
    
    while True:
        try:
            choice = input("\nSelect framework (1-7): ").strip()
            
            if choice in ["1", "2", "3", "4", "5"]:
                fw_index = int(choice) - 1
                selected_fw = frameworks[fw_index]
                print(f"\n🚀 Analyzing {selected_fw}...")
                download_frameworks([selected_fw])
                analyze_frameworks([selected_fw])
                break
            elif choice == "6":
                print("\n🚀 Analyzing all frameworks...")
                download_frameworks(frameworks)
                analyze_frameworks(frameworks)
                break
            elif choice == "7":
                interactive_menu()
                break
            else:
                print("❌ Invalid choice. Please select 1-7.")
        except (ValueError, IndexError):
            print("❌ Invalid choice. Please select 1-7.")
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break


def application_analysis_menu():
    """Application analysis submenu"""
    print("\n📱 Application Analysis")
    print("=" * 30)
    print("1. Analyze single project")
    print("2. Analyze multiple projects")
    print("3. Resume previous analysis")
    print("4. Back to main menu")
    
    while True:
        try:
            choice = input("\nSelect option (1-4): ").strip()
            
            if choice == "1":
                index = int(input("Enter project index (0-146): "))
                print(f"\n🚀 Analyzing project {index}...")
                analyze_applications(start=index, count=1)
                break
            elif choice == "2":
                count = int(input("How many projects to analyze? (default: 10): ") or "10")
                print(f"\n🚀 Analyzing {count} projects...")
                analyze_applications(count=count)
                break
            elif choice == "3":
                print("\n🚀 Resuming analysis...")
                analyze_applications(resume=True)
                break
            elif choice == "4":
                interactive_menu()
                break
            else:
                print("❌ Invalid choice. Please select 1-4.")
        except ValueError:
            print("❌ Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break


def main():
    parser = argparse.ArgumentParser(description="HNP PHP Analysis System - Unified Runner")
    
    # Main commands
    parser.add_argument("--download", nargs="+", help="Download frameworks (laravel, symfony, codeigniter, cakephp, yii)")
    parser.add_argument("--analyze-frameworks", nargs="*", help="Analyze frameworks (default: all main frameworks)")
    parser.add_argument("--analyze-apps", type=int, nargs="?", const=10, help="Analyze applications (default: 10)")
    parser.add_argument("--resume", action="store_true", help="Resume application analysis")
    parser.add_argument("--results", action="store_true", help="Show analysis results")
    parser.add_argument("--all", action="store_true", help="Run complete analysis (download + analyze frameworks + analyze apps)")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    
    args = parser.parse_args()
    
    # If no arguments or interactive mode, show interactive menu
    if not any([args.download, args.analyze_frameworks, args.analyze_apps, args.resume, args.results, args.all]) or args.interactive:
        interactive_menu()
        return
    
    if args.download:
        download_frameworks(args.download)
    
    if args.analyze_frameworks is not None:
        analyze_frameworks(args.analyze_frameworks)
    
    if args.analyze_apps is not None:
        analyze_applications(count=args.analyze_apps, resume=args.resume)
    
    if args.resume and args.analyze_apps is None:
        analyze_applications(resume=True)
    
    if args.results:
        show_results()
    
    if args.all:
        print("🚀 Running complete analysis...")
        download_frameworks(["laravel", "symfony", "codeigniter", "cakephp", "yii"])
        analyze_frameworks()
        analyze_applications(count=20)
        show_results()


if __name__ == "__main__":
    main()
