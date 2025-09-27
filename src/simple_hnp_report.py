#!/usr/bin/env python3
"""
Simple HNP Report Generator - Generate only the information developers really need
"""
import json
import os
import csv
from typing import Dict, List, Any
from collections import defaultdict
import re


def generate_simple_hnp_report(framework_name: str, analysis_dir: str) -> None:
    """Generate simple HNP risk report"""
    
    # Try to load analysis data from file first
    json_file = os.path.join(analysis_dir, f"{framework_name}_api_flows.json")
    data = None
    
    if os.path.exists(json_file):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"⚠️  Error reading analysis file: {e}")
            data = None
    
    # If no data file, run the scanner directly
    if not data or "error" in data:
        print(f"🔄 Running fresh analysis for {framework_name}...")
        try:
            from external_taint import run_framework_scan
            framework_root = f"/home/rui/HNP_PHP/frameworks/{framework_name}"
            if os.path.exists(framework_root):
                data = run_framework_scan(framework_root, framework_name)
                # Save the analysis data for debugging
                json_file = os.path.join(analysis_dir, f"{framework_name}_api_flows.json")
                with open(json_file, 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"💾 Analysis data saved: {json_file}")
            else:
                print(f"❌ Framework directory not found: {framework_root}")
                return
        except Exception as e:
            print(f"❌ Error running analysis: {e}")
            return
    
    if "error" in data:
        print(f"❌ Analysis data error: {data['error']}")
        return
    
    # Analyze HNP risks
    risk_analysis = analyze_hnp_risks(data)
    
    # Generate simple reports
    generate_simple_markdown_report(framework_name, risk_analysis, analysis_dir)
    generate_simple_csv_report(framework_name, risk_analysis, analysis_dir)
    
    print(f"✅ Generated simple HNP report: {framework_name}")


def analyze_hnp_risks(data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze HNP risks"""
    
    flows = data.get("flows", [])
    api_impact_analysis = data.get("api_impact_analysis", {})
    
    # Group by API function
    api_flows = defaultdict(list)
    for flow in flows:
        sink_symbol = flow.get("sink_symbol", "")
        if sink_symbol:
            api_flows[sink_symbol].append(flow)
    
    # Analyze risk for each API
    risky_apis = []
    
    for api, flows_list in api_flows.items():
        usage_count = len(flows_list)
        has_guard = any(flow.get("has_guard", False) for flow in flows_list)
        has_validation = any(flow.get("has_validation", False) for flow in flows_list)
        is_protected = has_guard or has_validation
        
        # Get risk scenario
        impact_info = api_impact_analysis.get(api, {})
        scenario = impact_info.get("scenario", "Unknown impact")
        
        # If scenario is "Unknown impact", intelligently determine based on API name
        if scenario == "Unknown impact - requires manual analysis" or scenario == "Unknown impact":
            scenario = _get_risk_scenario(api)
        
        # Only focus on risky APIs
        if _is_risky_api(api) and not is_protected:
            risky_apis.append({
                "api": api,
                "usage_count": usage_count,
                "scenario": scenario,
                "sample_files": list(set([flow.get("sink_file", "") for flow in flows_list[:3]]))
            })
    
    # Sort by usage frequency
    risky_apis.sort(key=lambda x: x["usage_count"], reverse=True)
    
    high_risk_count = len([api for api in risky_apis if _is_high_risk_api(api["api"])])
    medium_risk_count = len([api for api in risky_apis if _is_medium_risk_api(api["api"])])
    
    # Get framework category
    framework_name = data.get("framework", "Unknown")
    category = _get_framework_category(high_risk_count, len(api_flows), framework_name)

    return {
        "framework": framework_name,
        "total_flows": len(flows),
        "total_apis": len(api_flows),
        "risky_apis": risky_apis,
        "category": category,
        "summary": {
            "high_risk_count": high_risk_count,
            "medium_risk_count": medium_risk_count,
            "total_risky": len(risky_apis)
        }
    }


def _is_risky_api(api_name: str) -> bool:
    """Check if API has HNP risk"""
    # Exclude obviously safe APIs
    safe_patterns = [
        r'^_', r'^__',  # Private methods
        r'^if$', r'^else$', r'^for$', r'^while$', r'^foreach$',  # Control flow
        r'^array$', r'^count$', r'^strlen$', r'^strpos$',  # Basic PHP
        r'^isset$', r'^empty$', r'^is_null$',  # PHP checks
        r'^next$', r'^handle$',  # Common internal methods
        r'^array_filter$', r'^array_slice$', r'^trim$', r'^ltrim$',  # Basic PHP functions
        r'^preg_match$', r'^is_string$', r'^function$',  # Basic PHP functions
    ]
    
    # Check if it's obviously safe
    if any(re.search(pattern, api_name, re.IGNORECASE) for pattern in safe_patterns):
        return False
    
    # Include APIs that could potentially be risky
    return True


def _is_high_risk_api(api_name: str) -> bool:
    """Check if API is high risk"""
    high_risk_patterns = [
        r'url$', r'route$', r'redirect$', r'link$', r'to$', r'generate$',
        r'login$', r'logout$', r'auth$', r'admin$', r'home$', r'site$',
        r'parse_url$', r'sanitize_url$', r'esc_url$', r'wp_.*_url$',
        r'get_.*_url$', r'network_.*_url$', r'self_.*_url$'
    ]
    return any(re.search(pattern, api_name, re.IGNORECASE) for pattern in high_risk_patterns)


def _is_medium_risk_api(api_name: str) -> bool:
    """Check if API is medium risk"""
    medium_risk_patterns = [
        r'view$', r'render$', r'template$', r'blade$', r'twig$',
        r'mail$', r'email$', r'notification$', r'send$',
        r'header$', r'cookie$', r'response$', r'json$', r'api$'
    ]
    return any(re.search(pattern, api_name, re.IGNORECASE) for pattern in medium_risk_patterns)


def _get_framework_category(high_risk_count: int, total_apis: int, framework_name: str) -> str:
    """Get framework category based on high risk API count and characteristics"""
    if high_risk_count >= 200:
        return "大量高风险API"
    elif high_risk_count >= 5:
        return "多个高风险API"
    elif high_risk_count >= 1:
        if framework_name.lower() == "symfony":
            return "主要测试相关"
        else:
            return "少量高风险API"
    else:
        return "无高风险API"


def _get_risk_scenario(api_name: str) -> str:
    """Infer risk scenario based on API name"""
    if any(keyword in api_name.lower() for keyword in ['url', 'route', 'link', 'redirect']):
        return "URL generation/redirect - Host header affects generated URLs"
    elif any(keyword in api_name.lower() for keyword in ['login', 'logout', 'auth', 'admin']):
        return "Authentication related - Host header affects authentication flow"
    elif any(keyword in api_name.lower() for keyword in ['mail', 'email', 'notification']):
        return "Email/notification - Host header affects email content"
    elif any(keyword in api_name.lower() for keyword in ['view', 'render', 'template']):
        return "Template rendering - Host header affects template output"
    elif any(keyword in api_name.lower() for keyword in ['header', 'response', 'json']):
        return "Response handling - Host header affects response content"
    else:
        return "Requires manual analysis for specific impact"


def generate_simple_markdown_report(framework_name: str, risk_analysis: Dict[str, Any], analysis_dir: str) -> None:
    """Generate simple Markdown report"""
    
    summary = risk_analysis["summary"]
    risky_apis = risk_analysis["risky_apis"]
    
    content = f"""# {framework_name.upper()} Framework HNP Risk Report

## 🚨 Risk Overview

- **Total Taint Flows**: {risk_analysis['total_flows']}
- **Total API Count**: {risk_analysis['total_apis']}
- **Risky APIs**: {summary['total_risky']}
  - 🔴 High Risk APIs: {summary['high_risk_count']}
  - 🟡 Medium Risk APIs: {summary['medium_risk_count']}
- **Framework Category**: {risk_analysis.get('category', 'Unknown')}

---

## ⚠️ APIs with HNP Risk (Unprotected)

"""
    
    if not risky_apis:
        content += "✅ **Good News**: No obvious HNP risk APIs found\n"
    else:
        for api in risky_apis[:20]:  # Show only top 20
            risk_level = "🔴 High Risk API" if _is_high_risk_api(api["api"]) else "🟡 Medium Risk API"
            content += f"""### {api['api']}() - {risk_level}
- **Usage Count**: {api['usage_count']}
- **Risk Scenario**: {api['scenario']}
- **Sample Files**: {', '.join(api['sample_files'][:2])}

"""
    
    content += f"""## 🛡️ Protection Recommendations

### Required Protection Measures:
1. **Trusted Proxy Configuration**: Configure framework's trusted proxy settings
2. **Host Validation**: Validate Host header against allowed list
3. **URL Generation Protection**: Use absolute URLs instead of relative URLs

### Configuration Examples:
```php
// {framework_name.upper()}
// Configure appropriate trusted proxy and host validation based on framework type
```

---
*Report Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
    
    # Save report
    report_file = os.path.join(analysis_dir, f"{framework_name}_HNP_RISK_REPORT.md")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(content)
    
    print(f"📄 Simple report generated: {report_file}")


def generate_simple_csv_report(framework_name: str, risk_analysis: Dict[str, Any], analysis_dir: str) -> None:
    """Generate simple CSV report"""
    
    csv_file = os.path.join(analysis_dir, f"{framework_name}_HNP_RISK_SUMMARY.csv")
    
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "API Function", "Risk Level", "Usage Count", "Risk Scenario", "Sample Files", "Developer Recommendation"
        ])
        
        for api in risk_analysis["risky_apis"]:
            risk_level = "HIGH" if _is_high_risk_api(api["api"]) else "MEDIUM"
            suggestion = "Must configure trusted proxy and host validation" if risk_level == "HIGH" else "Recommend configuring protection"
            
            writer.writerow([
                api["api"],
                risk_level,
                api["usage_count"],
                api["scenario"],
                "; ".join(api["sample_files"][:2]),
                suggestion
            ])
    
    print(f"📊 CSV report generated: {csv_file}")


def main():
    """Generate simple report for specified framework"""
    import sys
    
    if len(sys.argv) > 1:
        framework_name = sys.argv[1]
        analysis_dir = f"/home/rui/HNP_PHP/reports/framework_analysis/{framework_name}"
        generate_simple_hnp_report(framework_name, analysis_dir)
    else:
        print("Usage: python3 src/simple_hnp_report.py <framework_name>")
        print("Example: python3 src/simple_hnp_report.py laravel")


if __name__ == "__main__":
    main()
