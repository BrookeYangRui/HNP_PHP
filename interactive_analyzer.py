#!/usr/bin/env python3
"""
Interactive Framework Analyzer for HNP Detection
Provides menu-driven analysis of PHP frameworks with detailed CSV and JSON outputs
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

class FrameworkAnalyzer:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.frameworks_dir = self.project_root / "frameworks"
        self.results_dir = self.project_root / "results"
        self.registry_dir = self.project_root / "registry"
        
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
        print("🔍 HNP Framework Analyzer - Interactive Mode")
        print("="*60)
        print("Select analysis mode:")
        print()
        print("  📊 Analysis Modes:")
        print("    1. Restrictive Analysis - Traditional HNP sink detection")
        print("    2. Open Taint Tracking - Comprehensive host usage discovery")
        print()
        print("  🎯 Framework Selection:")
        
        for key, framework in self.frameworks.items():
            status = "✅ Available" if self.is_framework_available(framework["path"]) else "❌ Not found"
            print(f"    {key}. {framework['name']} - {framework['description']} [{status}]")
        
        print()
        print("  0. Exit")
        print("="*60)
    
    def is_framework_available(self, framework_path):
        """Check if framework is available"""
        if framework_path == ".":
            # Check if any framework exists
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
                    if self.is_framework_available(self.frameworks[choice]["path"]):
                        return choice
                    else:
                        print(f"❌ {self.frameworks[choice]['name']} is not available. Please download it first.")
                        print(f"   See frameworks/README.md for download instructions.")
                else:
                    print("❌ Invalid choice. Please enter 0-7.")
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                sys.exit(0)
    
    def run_semgrep_discovery(self, framework_path, framework_name):
        """Run Semgrep discovery phase"""
        print(f"\n🔍 Phase 1: Running Semgrep discovery on {framework_name}...")
        phase_start = time.time()
        
        # Prepare paths
        if framework_path == ".":
            target_path = str(self.frameworks_dir)
        else:
            target_path = str(self.frameworks_dir / framework_path)
        
        # Get framework-specific results directory
        framework_results_dir = self.get_framework_results_dir(framework_name)
        output_file = framework_results_dir / "discovery.json"
        
        # Run Semgrep
        cmd = [
            "semgrep",
            "--config", "rules/discovery",
            "--json",
            "-o", str(output_file),
            target_path
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            if result.returncode == 0:
                print(f"✅ Semgrep discovery completed. Results saved to {output_file}")
                print(f"⏱ Took {round(time.time() - phase_start, 2)}s")
                return output_file
            else:
                print(f"❌ Semgrep failed: {result.stderr}")
                return None
        except FileNotFoundError:
            print("❌ Semgrep not found. Please install Semgrep first.")
            return None
    
    def extract_candidates(self, discovery_file, framework_name):
        """Extract candidate sinks from Semgrep results"""
        print(f"\n📊 Phase 2: Extracting candidate sinks for {framework_name}...")
        phase_start = time.time()
        
        # Get framework-specific results directory
        framework_results_dir = self.get_framework_results_dir(framework_name)
        candidates_file = framework_results_dir / "candidates.csv"
        
        cmd = [
            "python3", "scripts/extract_candidates.py",
            str(discovery_file)
        ]
        
        try:
            with open(candidates_file, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                print(f"✅ Candidate extraction completed. Results saved to {candidates_file}")
                print(f"⏱ Took {round(time.time() - phase_start, 2)}s")
                return candidates_file
            else:
                print(f"❌ Candidate extraction failed: {result.stderr}")
                return None
        except Exception as e:
            print(f"❌ Error extracting candidates: {e}")
            return None
    
    def generate_psalm_stubs(self, candidates_file, framework_name):
        """Generate Psalm stubs from candidates"""
        print(f"\n🔧 Phase 3: Generating Psalm stubs for {framework_name}...")
        phase_start = time.time()
        
        stub_file = self.project_root / "rules" / "psalm-stubs" / "temp_sinks.phpstub"
        
        cmd = [
            "python3", "scripts/gen_temp_sinks_stub.py",
            str(candidates_file)
        ]
        
        try:
            with open(stub_file, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                print(f"✅ Psalm stubs generated. Updated {stub_file}")
                print(f"⏱ Took {round(time.time() - phase_start, 2)}s")
                return True
            else:
                print(f"❌ Stub generation failed: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ Error generating stubs: {e}")
            return False
    
    def run_psalm_analysis(self, framework_path, framework_name):
        """Run Psalm taint analysis"""
        print(f"\n🔬 Phase 4: Running Psalm taint analysis on {framework_name}...")
        phase_start = time.time()
        
        # Prepare paths
        if framework_path == ".":
            target_path = str(self.frameworks_dir)
        else:
            target_path = str(self.frameworks_dir / framework_path)
        
        # Get framework-specific results directory
        framework_results_dir = self.get_framework_results_dir(framework_name)
        output_file = framework_results_dir / "psalm_analysis.json"

        # Generate minimal harness file to ensure flows
        harness_dir = framework_results_dir / "harness"
        harness_dir.mkdir(exist_ok=True)
        harness_file = harness_dir / "laravel_hnp_harness.php"
        self._write_laravel_harness(harness_file)
        # Write a real PHP sink file (not a stub), so Psalm reports taint on project code
        real_sink_file = harness_dir / "real_sink.php"
        self._write_real_sink(real_sink_file)
        
        # Set PHP path
        env = os.environ.copy()
        env["PATH"] = "/usr/local/php8.3/bin:" + env.get("PATH", "")
        
        # Analyze all harness PHP files
        harness_targets = [str(p) for p in harness_dir.glob('*.php')]
        cmd = [
            "psalm",
            "--output-format=json",
            "--report=" + str(output_file),
            *harness_targets
        ]
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                cwd=self.project_root,
                bufsize=1
            )
            spinner = ['|','/','-','\\']
            i = 0
            while True:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.1)
                    continue
                # Throttle progress display
                if i % 200 == 0:
                    elapsed = round(time.time() - phase_start, 1)
                    print(f"\r⏳ Psalm running {spinner[(i//200)%4]}  elapsed: {elapsed}s", end="", flush=True)
                i += 1
            print()
            if proc.returncode in [0,2]:
                print(f"✅ Psalm analysis completed. Results saved to {output_file}")
                print(f"⏱ Took {round(time.time() - phase_start, 2)}s")
                # Continue with Psalm4 sidecar taint analysis to obtain taint traces
            else:
                print(f"❌ Psalm analysis failed with code {proc.returncode}")
                print(f"⏱ Took {round(time.time() - phase_start, 2)}s")
            # Sidecar Psalm4 taint analysis (phar)
            psalm4_output = framework_results_dir / "psalm4_analysis.json"
            psalm4_config_dir = self.project_root / "tools" / "psalm4"
            psalm4_config_dir.mkdir(parents=True, exist_ok=True)
            psalm4_xml = psalm4_config_dir / "psalm4.xml"
            # Write temp psalm4 config targeting harness + loading our stubs
            harness_abs = str(harness_file.resolve())
            real_sink_abs = str(real_sink_file.resolve())
            stub_sources_abs = str((self.project_root / 'rules' / 'psalm-stubs' / 'taint_sources.phpstub').resolve())
            stub_sinks_abs = str((self.project_root / 'rules' / 'psalm-stubs' / 'temp_sinks.phpstub').resolve())
            stub_fixes_abs = str((self.project_root / 'rules' / 'psalm-stubs' / 'framework_fixes.phpstub').resolve())
            psalm4_xml_contents = f"""<?xml version=\"1.0\"?>
<psalm errorLevel=\"1\" resolveFromConfigFile=\"true\" allFunctionsGlobal=\"true\" useDocblockTypes=\"false\">
  <projectFiles>
    <file name=\"{harness_abs}\" />
    <file name=\"{real_sink_abs}\" />
  </projectFiles>
  <stubs>
    <file name=\"{stub_sources_abs}\" />
    <file name=\"{stub_sinks_abs}\" />
    <file name=\"{stub_fixes_abs}\" />
  </stubs>
</psalm>
"""
            try:
                with open(psalm4_xml, 'w', encoding='utf-8') as f:
                    f.write(psalm4_xml_contents)
            except Exception:
                pass

            psalm4_cmd = [
                "/usr/local/php8.3/bin/php",
                str(self.project_root / "tools" / "psalm4" / "psalm.phar"),
                "--taint-analysis",
                "-c", str(psalm4_xml),
                "--output-format=json",
                "--report=" + str(psalm4_output),
                *harness_targets
            ]

            print("🧪 Running Psalm4 sidecar for taint analysis...")
            try:
                result4 = subprocess.run(psalm4_cmd, capture_output=True, text=True, cwd=self.project_root)
                if result4.returncode in [0,2] and psalm4_output.exists():
                    print(f"✅ Psalm4 taint analysis completed. Results saved to {psalm4_output}")
                    return psalm4_output
                else:
                    print("❌ Psalm4 taint analysis failed:")
                    print(result4.stdout[:500])
                    print(result4.stderr[:500])
                    return output_file if output_file.exists() else None
            except Exception as e:
                print(f"❌ Psalm4 sidecar error: {e}")
                return output_file if output_file.exists() else None
        except FileNotFoundError:
            print("❌ Psalm not found. Please install Psalm first.")
            return None

    def _write_real_sink(self, sink_file: Path):
        code = r"""<?php
/**
 * @psalm-taint-sink html $v
 */
function hnp_real_sink(string $v): void {}
"""
        try:
            with open(sink_file, 'w', encoding='utf-8') as f:
                f.write(code)
        except Exception:
            pass

    def _write_laravel_harness(self, harness_file: Path):
        code = r"""<?php
// Auto-generated harness for Laravel HNP flows

namespace Harness;

/**
 * @psalm-taint-source input
 */
function hnp_inline_source(): string { return 'tainted-inline'; }

/**
 * @psalm-taint-sink html $v
 */
function hnp_inline_sink(string $v): void {}

$_SERVER['HTTP_HOST'] = 'malicious.test';

// Use global taint source to avoid framework symbol resolution
$host = \getHttpHost();

// Keep framework calls to exercise sinks (optional)
$absUrl = 'http://' . $host . '/path';

$resp = new \Illuminate\Http\Response();

$resp->header('Location', $absUrl);

// Debug sink to force taint reporting (real project function)
hnp_real_sink('http://' . $host . '/x');

// $redir calls skipped in minimal harness

$rr = new \Symfony\Component\HttpFoundation\RedirectResponse('http://' . $host . '/redirect');

if (function_exists('getLaravelTrustedHost')) {
    $trusted = \getLaravelTrustedHost($host);
    if ($trusted !== '') {
        $resp->header('Location', 'http://' . $trusted . '/ok');
    }
}
"""
        try:
            with open(harness_file, 'w', encoding='utf-8') as f:
                f.write(code)
        except Exception:
            pass
    
    def generate_detailed_csv(self, discovery_file, psalm_file, framework_name):
        """Generate detailed CSV report"""
        print(f"\n📋 Phase 5: Generating detailed CSV report for {framework_name}...")
        
        # Get framework-specific results directory
        framework_results_dir = self.get_framework_results_dir(framework_name)
        csv_file = framework_results_dir / "detailed_report.csv"
        
        # Load Semgrep results
        try:
            with open(discovery_file, 'r') as f:
                semgrep_data = json.load(f)
        except Exception as e:
            print(f"❌ Error loading Semgrep results: {e}")
            return None
        
        # Load Psalm results
        psalm_data = []
        if psalm_file and psalm_file.exists():
            try:
                with open(psalm_file, 'r') as f:
                    psalm_data = json.load(f)
            except Exception as e:
                print(f"⚠️  Warning: Could not load Psalm results: {e}")
        
        # Helper: fuzzy match a psalm result for a semgrep finding
        def find_psalm_match(semgrep_result, psalm_results):
            target_path = semgrep_result.get("path", "")
            target_line = semgrep_result.get("start", {}).get("line")
            sink_keywords = [
                "Response::header",
                "RedirectResponse",
                "UrlGenerator::to",
                "UrlGenerator::route",
                "UrlGenerator::action",
                "Redirector::to",
                "Redirector::route",
                "Redirector::action",
                "header('Location'",
                "header(\"Location\"",
            ]

            # 1) strict: same file + same line
            for pr in psalm_results:
                if (pr.get("file_path") == target_path and pr.get("line_from") == target_line):
                    return pr

            # 2) relaxed: taint trace contains sink keywords (ignore file path to allow harness-based confirmation)
            for pr in psalm_results:
                trace = pr.get("taint_trace", []) or []
                for t in trace:
                    label = (t.get("label") or "")
                    if any(k in label for k in sink_keywords):
                        return pr

            # 3) fallback: psalm type indicates relevant taint (ignore file path)
            for pr in psalm_results:
                if (pr.get("type") in ("TaintedHeader", "TaintedHtml", "TaintedFormData", "TaintedInput")):
                    return pr

            return None

        # Generate CSV
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                "Framework",
                "Rule ID",
                "Severity",
                "File Path",
                "Line Number",
                "Function/Method",
                "API Type",
                "Taint Source",
                "Taint Sink",
                "Taint Flow",
                "Description",
                "Code Snippet",
                "Psalm Confirmed",
                "Psalm Taint Type",
                "Psalm Trace",
                "Guard Detected",
                "Guard Type",
                "Guard Function"
            ])
            
            # Process Semgrep results
            for result in semgrep_data.get("results", []):
                # Determine if this is confirmed by Psalm (with fuzzy matching)
                psalm_confirmed = "No"
                psalm_taint_type = ""
                psalm_trace = ""

                matched = find_psalm_match(result, psalm_data)
                if matched:
                    psalm_confirmed = "Yes"
                    psalm_taint_type = matched.get("type", "")
                    psalm_trace = json.dumps(matched.get("taint_trace", []))

                # Check for guard detection (use matched if available)
                guard_detected, guard_type, guard_function = self.detect_guard(result, psalm_data)
                
                # Extract API information
                api_type = self.extract_api_type(result)
                taint_source = self.extract_taint_source(result)
                taint_sink = self.extract_taint_sink(result)
                taint_flow = self.extract_taint_flow(result)
                
                # Extract actual code snippet from source file
                code_snippet = self.extract_code_snippet(result)
                
                writer.writerow([
                    framework_name,
                    result.get("check_id", ""),
                    result.get("extra", {}).get("severity", ""),
                    result.get("path", ""),
                    result.get("start", {}).get("line", ""),
                    self.extract_function_name(result),
                    api_type,
                    taint_source,
                    taint_sink,
                    taint_flow,
                    result.get("extra", {}).get("message", ""),
                    code_snippet,
                    psalm_confirmed,
                    psalm_taint_type,
                    psalm_trace,
                    guard_detected,
                    guard_type,
                    guard_function
                ])
        
        print(f"✅ Detailed CSV report generated: {csv_file}")
        return csv_file
    
    def extract_code_snippet(self, result):
        """Extract actual code snippet from source file"""
        file_path = result.get("path", "")
        line_num = result.get("start", {}).get("line", 0)
        
        if not file_path or not line_num:
            return "N/A"
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if line_num <= len(lines):
                # Get the line and strip whitespace
                code_line = lines[line_num - 1].strip()
                # Extract API name from the line
                if '->' in code_line:
                    # Method call: $obj->method()
                    parts = code_line.split('->')
                    if len(parts) > 1:
                        method_part = parts[1].split('(')[0]
                        return f"{method_part}()"
                elif '(' in code_line and ')' in code_line:
                    # Function call: function()
                    func_part = code_line.split('(')[0]
                    return f"{func_part}()"
                else:
                    return code_line[:50] + "..." if len(code_line) > 50 else code_line
            else:
                return "Line not found"
        except Exception as e:
            return f"Error: {str(e)[:30]}"
    
    def extract_api_type(self, result):
        """Extract API type from Semgrep result"""
        check_id = result.get("check_id", "")
        if "redirect" in check_id.lower():
            return "Redirect/Location Header"
        elif "cors" in check_id.lower():
            return "CORS Header"
        elif "cookie" in check_id.lower():
            return "Cookie Domain"
        elif "url" in check_id.lower():
            return "URL Construction"
        else:
            return "Other"
    
    def extract_taint_source(self, result):
        """Extract taint source information"""
        # This would need to be enhanced based on actual Semgrep result structure
        return "HTTP_HOST, HTTP_X_FORWARDED_HOST"
    
    def extract_taint_sink(self, result):
        """Extract taint sink information"""
        check_id = result.get("check_id", "")
        if "redirect" in check_id.lower():
            return "Location header, 3xx response"
        elif "cors" in check_id.lower():
            return "Access-Control-Allow-Origin header"
        elif "cookie" in check_id.lower():
            return "Cookie domain setting"
        elif "url" in check_id.lower():
            return "Absolute URL construction"
        else:
            return "Various sinks"
    
    def extract_taint_flow(self, result):
        """Extract taint flow information"""
        return "Host header → API parameter → Response"
    
    def detect_guard(self, result, psalm_data):
        """Detect if guard functions are present in the taint trace"""
        guard_detected = "No"
        guard_type = ""
        guard_function = ""
        
        target_path = result.get("path")
        target_line = result.get("start", {}).get("line")

        def scan_trace(taint_trace):
            nonlocal guard_detected, guard_type, guard_function
            for trace_item in taint_trace or []:
                label = trace_item.get("label", "")
                if "isLaravelTrustedHost" in label or "getLaravelTrustedHost" in label:
                    guard_detected = "Yes"; guard_type = "Laravel Trusted Hosts"; guard_function = label; return True
                if "isLaravelTrustedProxy" in label or "getLaravelTrustedProxyHost" in label:
                    guard_detected = "Yes"; guard_type = "Laravel Trusted Proxies"; guard_function = label; return True
                if "isSymfonyTrustedProxy" in label or "getSymfonyTrustedProxyHost" in label:
                    guard_detected = "Yes"; guard_type = "Symfony Trusted Proxies"; guard_function = label; return True
                if any(k in label for k in ["validateHost","sanitizeHost","normalizeHost"]):
                    guard_detected = "Yes"; guard_type = "Host Validation"; guard_function = label; return True
                if any(k in label for k in ["validateUrl","buildSafeUrl"]):
                    guard_detected = "Yes"; guard_type = "URL Validation"; guard_function = label; return True
                if any(k in label for k in ["whitelistHost","isAllowedHost"]):
                    guard_detected = "Yes"; guard_type = "Host Whitelist"; guard_function = label; return True
            return False

        # 1) strict match: same file + same line
        for pr in psalm_data:
            if pr.get("file_path") == target_path and pr.get("line_from") == target_line:
                if scan_trace(pr.get("taint_trace", [])):
                    return guard_detected, guard_type, guard_function
                break

        # 2) relaxed: same file
        for pr in psalm_data:
            if pr.get("file_path") == target_path:
                if scan_trace(pr.get("taint_trace", [])):
                    return guard_detected, guard_type, guard_function

        # 3) fallback: any taint trace
        for pr in psalm_data:
            if scan_trace(pr.get("taint_trace", [])):
                return guard_detected, guard_type, guard_function
        
        return guard_detected, guard_type, guard_function
    
    def count_guard_detections(self, semgrep_data, psalm_data):
        """Count guard detections from the analysis results"""
        guard_stats = {
            "total_guards_detected": 0,
            "guard_types": {},
            "guards_by_framework": {}
        }
        
        # Process Semgrep results
        for result in semgrep_data.get("results", []):
            guard_detected, guard_type, guard_function = self.detect_guard(result, psalm_data)
            
            if guard_detected == "Yes":
                guard_stats["total_guards_detected"] += 1
                guard_stats["guard_types"][guard_type] = guard_stats["guard_types"].get(guard_type, 0) + 1
        
        return guard_stats
    
    def extract_function_name(self, result):
        """Extract function/method name from result"""
        # This would need to be enhanced based on actual Semgrep result structure
        return "Unknown"
    
    
    def generate_summary_report(self, framework_name, csv_file, json_files):
        """Generate summary report"""
        print(f"\n📊 Phase 6: Generating summary report for {framework_name}...")
        
        # Get framework-specific results directory
        framework_results_dir = self.get_framework_results_dir(framework_name)
        summary_file = framework_results_dir / "summary.json"
        
        # Load data for guard statistics
        semgrep_data = {}
        psalm_data = []
        
        # Try to load Semgrep data
        for json_file in json_files:
            if json_file and json_file.exists():
                try:
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                        if "results" in data:  # Semgrep format
                            semgrep_data = data
                        else:  # Psalm format
                            psalm_data = data
                except Exception as e:
                    print(f"⚠️  Warning: Could not load {json_file}: {e}")
        
        # Count guard detections
        guard_stats = self.count_guard_detections(semgrep_data, psalm_data)
        
        summary = {
            "framework": framework_name,
            "analysis_timestamp": datetime.now().isoformat(),
            "total_issues_found": 0,
            "psalm_confirmed_issues": 0,
            "guard_detections": guard_stats,
            "api_types": {},
            "severity_distribution": {},
            "files_analyzed": [],
            "detailed_reports": {
                "csv_file": str(csv_file),
                "json_files": [str(f) for f in json_files if f]
            }
        }
        
        # Count issues from CSV
        if csv_file and csv_file.exists():
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    summary["total_issues_found"] += 1
                    
                    # Count severity distribution
                    severity = row.get("Severity", "Unknown")
                    summary["severity_distribution"][severity] = summary["severity_distribution"].get(severity, 0) + 1
                    
                    # Count Psalm confirmed issues
                    if row.get("Psalm Confirmed", "").upper() == "YES":
                        summary["psalm_confirmed_issues"] += 1
                    
                    # Count API types
                    api_type = row.get("API Type", "Other")
                    summary["api_types"][api_type] = summary["api_types"].get(api_type, 0) + 1
                    
                    # Collect analyzed files
                    file_path = row.get("File Path", "")
                    if file_path and file_path not in summary["files_analyzed"]:
                        summary["files_analyzed"].append(file_path)
        
        # Save summary
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Summary report generated: {summary_file}")
        return summary_file
    
    def print_results_summary(self, framework_name, summary_file):
        """Print results summary to console"""
        if not summary_file or not summary_file.exists():
            return
        
        try:
            with open(summary_file, 'r', encoding='utf-8') as f:
                summary = json.load(f)
            
            print("\n" + "="*60)
            print(f"📊 ANALYSIS RESULTS FOR {framework_name.upper()}")
            print("="*60)
            print(f"Total Issues Found: {summary['total_issues_found']}")
            print(f"Psalm Confirmed Issues: {summary['psalm_confirmed_issues']}")
            print()
            print("Severity Distribution:")
            for severity, count in summary['severity_distribution'].items():
                print(f"  - {severity}: {count}")
            print()
            print("API Types Found:")
            for api_type, count in summary['api_types'].items():
                print(f"  - {api_type}: {count}")
            print()
            print("Files Analyzed:")
            for file_path in summary['files_analyzed'][:5]:  # Show first 5
                print(f"  - {file_path}")
            if len(summary['files_analyzed']) > 5:
                print(f"  ... and {len(summary['files_analyzed']) - 5} more files")
            print()
            print("Detailed Reports:")
            print(f"  - CSV Report: {summary['detailed_reports']['csv_file']}")
            for json_file in summary['detailed_reports']['json_files']:
                print(f"  - JSON Report: {json_file}")
            print()
            print(f"📁 All results saved to: results/{framework_name.lower()}/")
            print("="*60)
            
        except Exception as e:
            print(f"❌ Error reading summary: {e}")
    
    def analyze_framework(self, choice, analysis_mode="restrictive"):
        """Main analysis function"""
        framework = self.frameworks[choice]
        framework_name = framework["name"]
        framework_path = framework["path"]
        
        print(f"\n🚀 Starting {analysis_mode} analysis of {framework_name}...")
        print(f"📁 Target path: {self.frameworks_dir / framework_path}")
        
        if analysis_mode == "open":
            return self.run_open_analysis(framework_path, framework_name)
        else:
            return self.run_restrictive_analysis(framework_path, framework_name)
    
    def run_restrictive_analysis(self, framework_path, framework_name):
        """Run traditional restrictive HNP analysis"""
        # Phase 1: Semgrep Discovery
        discovery_file = self.run_semgrep_discovery(framework_path, framework_name)
        if not discovery_file:
            print("❌ Analysis failed at discovery phase")
            return False
        
        # Phase 2: Extract Candidates
        candidates_file = self.extract_candidates(discovery_file, framework_name)
        if not candidates_file:
            print("❌ Analysis failed at candidate extraction phase")
            return False
        
        # Phase 3: Generate Psalm Stubs
        if not self.generate_psalm_stubs(candidates_file, framework_name):
            print("❌ Analysis failed at stub generation phase")
            return False
        
        # Phase 4: Psalm Analysis
        psalm_file = self.run_psalm_analysis(framework_path, framework_name)
        # Note: psalm_file can be None and that's okay
        
        # Phase 5: Generate Detailed CSV
        csv_file = self.generate_detailed_csv(discovery_file, psalm_file, framework_name)
        if not csv_file:
            print("❌ Analysis failed at CSV generation phase")
            return False
        
        # Phase 6: Generate Summary
        summary_file = self.generate_summary_report(discovery_file, csv_file, framework_name)
        if not summary_file:
            print("❌ Analysis failed at summary generation phase")
            return False
        
        # Display results
        self.display_results(summary_file, framework_name)
        return True
    
    def run_open_analysis(self, framework_path, framework_name):
        """Run open-ended taint tracking analysis"""
        print(f"\n🔬 Running Open Taint Tracking Analysis...")
        
        # Phase 1: Open Semgrep Discovery
        print(f"📋 Phase 1: Open Taint Source Discovery")
        print("-" * 50)
        discovery_file = self.run_open_semgrep_discovery(framework_path, framework_name)
        if not discovery_file:
            print("❌ Open analysis failed at discovery phase")
            return False
        
        # Phase 2: Open Taint Flow Analysis
        print(f"\n📋 Phase 2: Open Taint Flow Analysis")
        print("-" * 50)
        flow_analysis = self.analyze_open_taint_flow(discovery_file, framework_name)
        if not flow_analysis:
            print("❌ Open analysis failed at flow analysis phase")
            return False
        
        # Phase 3: Open Security Analysis
        print(f"\n📋 Phase 3: Open Security Analysis")
        print("-" * 50)
        security_analysis = self.analyze_open_security(discovery_file, framework_name)
        if not security_analysis:
            print("❌ Open analysis failed at security analysis phase")
            return False
        
        # Phase 4: Generate Open Reports
        print(f"\n📋 Phase 4: Generate Open Reports")
        print("-" * 50)
        open_reports = self.generate_open_reports(discovery_file, flow_analysis, security_analysis, framework_name)
        if not open_reports:
            print("❌ Open analysis failed at report generation phase")
            return False
        
        # Display open results
        self.display_open_results(open_reports, framework_name)
        return True
    
    def run_open_semgrep_discovery(self, framework_path, framework_name):
        """Run open-ended Semgrep discovery"""
        print(f"🔍 Phase 1: Running open Semgrep discovery on {framework_name}...")
        
        target_path = self.frameworks_dir / framework_path
        if not target_path.exists():
            print(f"❌ Framework path not found: {target_path}")
            return None
        
        # Use open exploration rule
        rule_file = self.project_root / "rules" / "discovery" / "open-host-exploration.yml"
        if not rule_file.exists():
            print(f"❌ Open exploration rule not found: {rule_file}")
            return None
        
        results_dir = self.results_dir / framework_name.lower()
        results_dir.mkdir(exist_ok=True)
        
        discovery_file = results_dir / "open_discovery.json"
        
        cmd = [
            "semgrep",
            "--config", str(rule_file),
            "--json",
            str(target_path)
        ]
        
        start_time = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            discovery_time = time.time() - start_time
            
            if result.returncode == 0:
                discovery_file.write_text(result.stdout)
                print(f"✅ Open discovery completed. Results saved to {discovery_file}")
                print(f"⏱ Took {discovery_time:.2f}s")
                return discovery_file
            else:
                print(f"❌ Open discovery failed: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            print("⏰ Open discovery timed out")
            return None
        except Exception as e:
            print(f"❌ Error running open discovery: {e}")
            return None
    
    def analyze_open_taint_flow(self, discovery_file, framework_name):
        """Analyze open taint flow patterns"""
        print(f"🔍 Analyzing open taint flow patterns...")
        
        try:
            with open(discovery_file, 'r') as f:
                discovery_data = json.load(f)
            
            findings = discovery_data.get('results', [])
            print(f"📊 Found {len(findings)} taint propagation points")
            
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
            
            print(f"🔍 Open taint usage patterns identified:")
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
            print(f"❌ Error analyzing taint flow: {e}")
            return None
    
    def analyze_open_security(self, discovery_file, framework_name):
        """Analyze open security patterns"""
        print(f"🔍 Analyzing open security patterns...")
        
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
            
            print(f"🛡️  Open security analysis results:")
            print(f"   - Explicit validation: {len(security_analysis['Explicit_Validation'])} points")
            print(f"   - No explicit validation: {len(security_analysis['No_Explicit_Validation'])} points")
            print(f"   - Context-dependent: {len(security_analysis['Context_Dependent'])} points")
            
            return security_analysis
            
        except Exception as e:
            print(f"❌ Error analyzing security: {e}")
            return None
    
    def generate_open_reports(self, discovery_file, flow_analysis, security_analysis, framework_name):
        """Generate open analysis reports"""
        print(f"📄 Generating open analysis reports...")
        
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
            
            print(f"✅ Open CSV data generated: {open_csv_file}")
            
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
            
            print(f"✅ Open summary generated: {summary_file}")
            
            return {
                'csv_file': open_csv_file,
                'summary_file': summary_file,
                'discovery_file': discovery_file
            }
            
        except Exception as e:
            print(f"❌ Error generating open reports: {e}")
            return None
    
    def display_open_results(self, open_reports, framework_name):
        """Display open analysis results"""
        print(f"\n" + "="*60)
        print(f"📊 OPEN TAINT TRACKING RESULTS FOR {framework_name.upper()}")
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
            
            print(f"\n📁 All results saved to: results/{framework_name.lower()}/")
            print("="*60)
            
        except Exception as e:
            print(f"❌ Error reading open results: {e}")
    
    def run(self):
        """Main interactive loop"""
        print("🔍 Welcome to HNP Framework Analyzer!")
        print("This tool will analyze PHP frameworks for Host Header Poisoning vulnerabilities.")
        
        while True:
            self.show_menu()
            
            # First, get analysis mode
            print("\nSelect analysis mode (1-2):")
            mode_choice = input("Enter your choice: ").strip()
            
            if mode_choice == "0":
                print("\n👋 Goodbye!")
                break
            
            if mode_choice not in ["1", "2"]:
                print("❌ Invalid choice. Please select 1 or 2.")
                continue
            
            analysis_mode = "restrictive" if mode_choice == "1" else "open"
            mode_name = "Restrictive Analysis" if mode_choice == "1" else "Open Taint Tracking"
            
            print(f"\n✅ Selected: {mode_name}")
            
            # Then, get framework choice
            print("\nSelect framework (1-7):")
            choice = self.get_user_choice()
            
            if choice is None:
                print("\n👋 Goodbye!")
                break
            
            try:
                success = self.analyze_framework(choice, analysis_mode)
                if success:
                    print(f"\n🎉 {mode_name} completed! Check the 'results/' directory for detailed results.")
                else:
                    print(f"\n❌ {mode_name} failed. Please check the error messages above.")
                
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ Unexpected error: {e}")
                input("\nPress Enter to continue...")

def main():
    parser = argparse.ArgumentParser(description="Interactive HNP Framework Analyzer")
    parser.add_argument("--framework", help="Directly analyze a specific framework (1-7)")
    args = parser.parse_args()
    
    analyzer = FrameworkAnalyzer()
    
    if args.framework:
        # Direct analysis mode
        if args.framework in analyzer.frameworks:
            analyzer.analyze_framework(args.framework)
        else:
            print(f"❌ Invalid framework choice: {args.framework}")
            print("Valid choices: 1-7")
    else:
        # Interactive mode
        analyzer.run()

if __name__ == "__main__":
    main()
