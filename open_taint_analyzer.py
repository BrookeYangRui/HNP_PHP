#!/usr/bin/env python3
"""
Open Taint Tracking Analyzer for HNP Detection
Comprehensive open-ended static analysis of PHP frameworks
"""

import os
import sys
import json
import csv
import subprocess
import time
import argparse
from datetime import datetime
from pathlib import Path

class OpenTaintAnalyzer:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.frameworks_dir = self.project_root / "frameworks"
        self.results_dir = self.project_root / "results"
        
        # Ensure results directory exists
        self.results_dir.mkdir(exist_ok=True)
        
        # Available frameworks
        self.frameworks = {
            "1": {"name": "Laravel", "path": "laravel", "description": "Laravel Framework"},
            "2": {"name": "Symfony", "path": "symfony", "description": "Symfony Framework"},
            "3": {"name": "WordPress", "path": "wordpress", "description": "WordPress CMS"},
            "4": {"name": "CodeIgniter", "path": "codeigniter", "description": "CodeIgniter Framework"},
            "5": {"name": "CakePHP", "path": "cakephp", "description": "CakePHP Framework"},
            "6": {"name": "Yii2", "path": "yii", "description": "Yii2 Framework"},
            "7": {"name": "All Frameworks", "path": ".", "description": "Analyze all available frameworks"}
        }
    
    def show_menu(self):
        """Display the interactive menu"""
        print("\n" + "="*60)
        print("Open Taint Tracking Analyzer")
        print("="*60)
        print("Select a framework to analyze:")
        print()
        
        for key, framework in self.frameworks.items():
            status = "Available" if self.is_framework_available(framework["path"]) else "Not found"
            print(f"  {key}. {framework['name']} - {framework['description']} [{status}]")
        
        print()
        print("  0. Exit")
        print("="*60)
    
    def is_framework_available(self, framework_path):
        """Check if framework is available"""
        if framework_path == ".":
            return any(self.frameworks_dir.iterdir())
        else:
            return (self.frameworks_dir / framework_path).exists()
    
    def get_framework_results_dir(self, framework_name):
        """Get or create framework-specific results directory"""
        if isinstance(framework_name, str):
            framework_results_dir = self.results_dir / framework_name.lower()
        else:
            framework_results_dir = self.results_dir / str(framework_name).lower()
        framework_results_dir.mkdir(exist_ok=True)
        return framework_results_dir
    
    def get_user_choice(self):
        """Get user's framework choice"""
        while True:
            try:
                choice = input("\nEnter your choice (0-7): ").strip()
                if choice == "0":
                    return None
                elif choice in self.frameworks:
                    return choice
                else:
            print("Invalid choice. Please select 0-7.")
            except KeyboardInterrupt:
                return None
    
    def analyze_framework(self, choice):
        """Main analysis function"""
        framework = self.frameworks[choice]
        framework_name = framework["name"]
        framework_path = framework["path"]
        
        print(f"\nStarting Open Taint Tracking analysis of {framework_name}...")
        print(f"Target path: {self.frameworks_dir / framework_path}")
        
        return self.run_open_analysis(framework_path, framework_name)
    
    def run_open_analysis(self, framework_path, framework_name):
        """Run open-ended taint tracking analysis"""
        print(f"\nRunning Open Taint Tracking Analysis...")
        
        # Phase 1: Open Semgrep Discovery
        print(f"\nPhase 1: Open Taint Source Discovery")
        print("-" * 50)
        discovery_file = self.run_open_semgrep_discovery(framework_path, framework_name)
        if not discovery_file:
            print("Open analysis failed at discovery phase")
            return False
        
        # Phase 2: Open Taint Flow Analysis
        print(f"\nPhase 2: Open Taint Flow Analysis")
        print("-" * 50)
        flow_analysis = self.analyze_open_taint_flow(discovery_file, framework_name)
        if not flow_analysis:
            print("Open analysis failed at flow analysis phase")
            return False
        
        # Phase 3: Open Security Analysis
        print(f"\nPhase 3: Open Security Analysis")
        print("-" * 50)
        security_analysis = self.analyze_open_security(discovery_file, framework_name)
        if not security_analysis:
            print("Open analysis failed at security analysis phase")
            return False
        
        # Phase 4: Generate Open Reports
        print(f"\nPhase 4: Generate Open Reports")
        print("-" * 50)
        open_reports = self.generate_open_reports(discovery_file, flow_analysis, security_analysis, framework_name)
        if not open_reports:
            print("Open analysis failed at report generation phase")
            return False
        
        # Display open results
        self.display_open_results(open_reports, framework_name)
        return True
    
    def run_open_semgrep_discovery(self, framework_path, framework_name):
        """Run open-ended Semgrep discovery"""
        print(f"Running open Semgrep discovery on {framework_name}...")
        
        target_path = self.frameworks_dir / framework_path
        if not target_path.exists():
            print(f"Framework path not found: {target_path}")
            return None
        
        # Use open exploration rule
        rule_file = self.project_root / "rules" / "discovery" / "open-host-exploration.yml"
        if not rule_file.exists():
            print(f"Open exploration rule not found: {rule_file}")
            return None
        
        results_dir = self.results_dir / framework_name.lower()
        results_dir.mkdir(exist_ok=True)
        
        discovery_file = results_dir / "open_discovery.json"
        
        cmd = [
            "semgrep",
            "--config", str(rule_file),
            "--json",
            "--no-git-ignore",
            str(target_path)
        ]
        
        start_time = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            discovery_time = time.time() - start_time
            
            if result.returncode == 0:
                discovery_file.write_text(result.stdout)
                print(f"Open discovery completed. Results saved to {discovery_file}")
                print(f"Took {discovery_time:.2f}s")
                return discovery_file
            else:
                print(f"Open discovery failed: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            print("Open discovery timed out")
            return None
        except Exception as e:
            print(f"Error running open discovery: {e}")
            return None
    
    def analyze_open_taint_flow(self, discovery_file, framework_name):
        """Analyze open taint flow patterns"""
        print(f"Analyzing open taint flow patterns...")
        
        try:
            with open(discovery_file, 'r') as f:
                discovery_data = json.load(f)
            
            findings = discovery_data.get('results', [])
            print(f"Found {len(findings)} taint propagation points")
            
            # Analyze usage patterns
            patterns = {
                'Direct_Return': 0,
                'URL_Construction': 0,
                'Header_Setting': 0,
                'Configuration': 0,
                'Validation': 0,
                'String_Operations': 0,
                'Object_Properties': 0,
                'Other': 0
            }
            
            for finding in findings:
                try:
                    file_path = finding.get('path', '')
                    line_num = finding.get('start', {}).get('line', 0)
                    
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_lines = f.readlines()
                    
                    if line_num <= len(file_lines):
                        code_line = file_lines[line_num - 1].strip()
                        
                        # Classify usage patterns
                        if 'return' in code_line and ('getHost' in code_line or 'getHttpHost' in code_line):
                            patterns['Direct_Return'] += 1
                        elif 'url' in code_line.lower() or 'http' in code_line or 'Url' in code_line:
                            patterns['URL_Construction'] += 1
                        elif 'header' in code_line.lower():
                            patterns['Header_Setting'] += 1
                        elif 'config' in code_line.lower() or 'setting' in code_line.lower():
                            patterns['Configuration'] += 1
                        elif 'preg_match' in code_line or 'validate' in code_line.lower():
                            patterns['Validation'] += 1
                        elif 'trim' in code_line or 'str_' in code_line or 'Str::' in code_line:
                            patterns['String_Operations'] += 1
                        elif '->' in code_line and ('=' in code_line or '[' in code_line):
                            patterns['Object_Properties'] += 1
                        else:
                            patterns['Other'] += 1
                            
                except:
                    patterns['Other'] += 1
            
            print(f"Open taint usage patterns identified:")
            for pattern, count in patterns.items():
                if count > 0:
                    percentage = (count / len(findings)) * 100
                    print(f"   - {pattern}: {count} ({percentage:.1f}%)")
            
            return {
                'findings': findings,
                'patterns': patterns,
                'total_findings': len(findings)
            }
            
        except Exception as e:
            print(f"Error analyzing taint flow: {e}")
            return None
    
    def analyze_open_security(self, discovery_file, framework_name):
        """Analyze open security patterns"""
        print(f"Analyzing open security patterns...")
        
        try:
            with open(discovery_file, 'r') as f:
                discovery_data = json.load(f)
            
            findings = discovery_data.get('results', [])
            
            security_analysis = {
                'Explicit_Validation': [],
                'No_Explicit_Validation': [],
                'Context_Dependent': []
            }
            
            for finding in findings:
                try:
                    file_path = finding.get('path', '')
                    line_num = finding.get('start', {}).get('line', 0)
                    
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_lines = f.readlines()
                    
                    # Get broader context
                    context_start = max(0, line_num - 5)
                    context_end = min(len(file_lines), line_num + 5)
                    context = ' '.join(file_lines[context_start:context_end])
                    current_line = file_lines[line_num - 1].strip() if line_num <= len(file_lines) else ''
                    
                    # More comprehensive validation detection
                    validation_keywords = [
                        'preg_match', 'filter_var', 'validate', 'sanitize', 'whitelist', 
                        'blacklist', 'allowed', 'trusted', 'secure', 'check', 'verify', 
                        'confirm', 'ensure', 'guard', 'isValid', 'isAllowed'
                    ]
                    
                    # Risk usage detection
                    risk_keywords = [
                        'echo', 'print', 'header(', 'setcookie', 'redirect', 'location:',
                        'url(', 'href', 'src=', 'action=', 'window.location'
                    ]
                    
                    has_validation = any(keyword in context.lower() for keyword in validation_keywords)
                    has_risk_usage = any(keyword in current_line.lower() for keyword in risk_keywords)
                    
                    analysis_item = {
                        'file': file_path.split('/')[-1],
                        'line': line_num,
                        'code': current_line,
                        'context': context,
                        'has_validation': has_validation,
                        'has_risk_usage': has_risk_usage
                    }
                    
                    if has_validation:
                        security_analysis['Explicit_Validation'].append(analysis_item)
                    elif has_risk_usage:
                        security_analysis['No_Explicit_Validation'].append(analysis_item)
                    else:
                        security_analysis['Context_Dependent'].append(analysis_item)
                        
                except:
                    pass
            
            print(f"Open security analysis results:")
            print(f"   - Explicit validation: {len(security_analysis['Explicit_Validation'])} points")
            print(f"   - No explicit validation: {len(security_analysis['No_Explicit_Validation'])} points")
            print(f"   - Context-dependent: {len(security_analysis['Context_Dependent'])} points")
            
            return security_analysis
            
        except Exception as e:
            print(f"Error analyzing security: {e}")
            return None
    
    def generate_open_reports(self, discovery_file, flow_analysis, security_analysis, framework_name):
        """Generate open analysis reports"""
        print(f"Generating open analysis reports...")
        
        try:
            results_dir = self.results_dir / framework_name.lower()
            
            # Generate open CSV data
            open_csv_file = results_dir / "open_taint_data.csv"
            with open(open_csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'File', 'Line', 'Column', 'Code_Snippet', 'Usage_Pattern', 
                    'Has_Explicit_Validation', 'Has_Risk_Usage', 'Context_Notes'
                ])
                
                for finding in flow_analysis['findings']:
                    file_path = finding.get('path', '')
                    file_name = file_path.split('/')[-1] if '/' in file_path else file_path
                    line_num = finding.get('start', {}).get('line', 0)
                    col_num = finding.get('start', {}).get('col', 0)
                    
                    # Get code snippet
                    code_snippet = 'N/A'
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            file_lines = f.readlines()
                        if line_num <= len(file_lines):
                            code_snippet = file_lines[line_num - 1].strip()
                    except:
                        pass
                    
                    # Determine usage pattern
                    usage_pattern = 'Other'
                    if 'return' in code_snippet and ('getHost' in code_snippet or 'getHttpHost' in code_snippet):
                        usage_pattern = 'Direct_Return'
                    elif 'url' in code_snippet.lower() or 'http' in code_snippet or 'Url' in code_snippet:
                        usage_pattern = 'URL_Construction'
                    elif 'header' in code_snippet.lower():
                        usage_pattern = 'Header_Setting'
                    elif 'config' in code_snippet.lower():
                        usage_pattern = 'Configuration'
                    elif 'preg_match' in code_snippet or 'validate' in code_snippet.lower():
                        usage_pattern = 'Validation'
                    elif 'trim' in code_snippet or 'str_' in code_snippet or 'Str::' in code_snippet:
                        usage_pattern = 'String_Operations'
                    elif '->' in code_snippet and ('=' in code_snippet or '[' in code_snippet):
                        usage_pattern = 'Object_Properties'
                    
                    # Security check status
                    has_validation = any(item['file'] == file_name and item['line'] == line_num 
                                       for item in security_analysis['Explicit_Validation'])
                    has_risk = any(item['file'] == file_name and item['line'] == line_num 
                                  for item in security_analysis['No_Explicit_Validation'])
                    
                    context_notes = 'Standard usage'
                    if usage_pattern == 'URL_Construction':
                        context_notes = 'URL building context'
                    elif usage_pattern == 'Direct_Return':
                        context_notes = 'Direct data return'
                    elif usage_pattern == 'Validation':
                        context_notes = 'Validation context'
                    elif usage_pattern == 'String_Operations':
                        context_notes = 'String manipulation'
                    
                    writer.writerow([
                        file_name,
                        line_num,
                        col_num,
                        code_snippet,
                        usage_pattern,
                        has_validation,
                        has_risk,
                        context_notes
                    ])
            
            print(f"Open CSV data generated: {open_csv_file}")
            
            # Generate open summary
            open_summary = {
                'analysis_type': 'Open Taint Tracking',
                'framework': framework_name,
                'total_findings': flow_analysis['total_findings'],
                'usage_patterns': flow_analysis['patterns'],
                'security_analysis': {
                    'explicit_validation': len(security_analysis['Explicit_Validation']),
                    'no_explicit_validation': len(security_analysis['No_Explicit_Validation']),
                    'context_dependent': len(security_analysis['Context_Dependent'])
                },
                'files': list(set(f.get('path', '').split('/')[-1] for f in flow_analysis['findings']))
            }
            
            summary_file = results_dir / "open_analysis_summary.json"
            with open(summary_file, 'w') as f:
                json.dump(open_summary, f, indent=2)
            
            print(f"Open summary generated: {summary_file}")
            
            return {
                'csv_file': open_csv_file,
                'summary_file': summary_file,
                'discovery_file': discovery_file
            }
            
        except Exception as e:
            print(f"Error generating open reports: {e}")
            return None
    
    def display_open_results(self, open_reports, framework_name):
        """Display open analysis results"""
        print(f"\n" + "="*60)
        print(f"OPEN TAINT TRACKING RESULTS FOR {framework_name.upper()}")
        print("="*60)
        
        try:
            with open(open_reports['summary_file'], 'r') as f:
                summary = json.load(f)
            
            print(f"Total Taint Points: {summary['total_findings']}")
            print(f"Files Analyzed: {len(summary['files'])}")
            print(f"Analysis Type: {summary['analysis_type']}")
            
            print(f"\nUsage Pattern Distribution:")
            for pattern, count in summary['usage_patterns'].items():
                if count > 0:
                    percentage = (count / summary['total_findings']) * 100
                    print(f"  - {pattern}: {count} ({percentage:.1f}%)")
            
            print(f"\nSecurity Analysis:")
            print(f"  - Explicit validation: {summary['security_analysis']['explicit_validation']} points")
            print(f"  - No explicit validation: {summary['security_analysis']['no_explicit_validation']} points")
            print(f"  - Context-dependent: {summary['security_analysis']['context_dependent']} points")
            
            print(f"\nFiles Analyzed:")
            for file_name in summary['files'][:10]:  # Show first 10 files
                print(f"  - {file_name}")
            if len(summary['files']) > 10:
                print(f"  ... and {len(summary['files']) - 10} more files")
            
            print(f"\nDetailed Reports:")
            print(f"  - CSV Report: {open_reports['csv_file']}")
            print(f"  - Summary Report: {open_reports['summary_file']}")
            print(f"  - Raw Discovery: {open_reports['discovery_file']}")
            
            print(f"\nAll results saved to: results/{framework_name.lower()}/")
            print("="*60)
            
        except Exception as e:
            print(f"Error reading open results: {e}")
    
    def run(self):
        """Main interactive loop"""
        print("Welcome to Open Taint Tracking Analyzer!")
        print("This tool performs comprehensive open-ended analysis of Host Header usage in PHP frameworks.")
        
        while True:
            self.show_menu()
            choice = self.get_user_choice()
            
            if choice is None:
                print("\nGoodbye!")
                break
            
            try:
                success = self.analyze_framework(choice)
                if success:
                    print(f"\nOpen Taint Tracking analysis completed! Check the 'results/' directory for detailed results.")
                else:
                    print(f"\nAnalysis failed. Please check the error messages above.")
                
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                print(f"\nUnexpected error: {e}")
                input("\nPress Enter to continue...")

def main():
    parser = argparse.ArgumentParser(description="Open Taint Tracking Analyzer")
    parser.add_argument("--framework", help="Directly analyze a specific framework (1-7)")
    args = parser.parse_args()
    
    analyzer = OpenTaintAnalyzer()
    
    if args.framework:
        # Direct analysis mode
        if args.framework in analyzer.frameworks:
            analyzer.analyze_framework(args.framework)
        else:
            print(f"Invalid framework choice: {args.framework}")
            print("Valid choices: 1-7")
    else:
        # Interactive mode
        analyzer.run()

if __name__ == "__main__":
    main()
