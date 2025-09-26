#!/usr/bin/env python3
"""
Analysis Generator - Creates optimized analysis files for framework scan results
"""
import json
import os
import csv
from datetime import datetime
from typing import Dict, Any, List


def generate_analysis_summary(analysis: Dict[str, Any], framework_dir: str) -> str:
    """Generate simplified analysis summary in Markdown format."""
    framework = analysis.get("framework", "Unknown")
    api_impact = analysis.get("api_impact_analysis", {})
    
    # Get functions with scenarios
    functions_with_scenarios = []
    for symbol, impact in api_impact.items():
        scenario = impact.get("scenario", "Unknown impact")
        if scenario != "Unknown impact - requires manual analysis":
            functions_with_scenarios.append((symbol, scenario))
    
    content = f"""# {framework.title()} Framework HNP Analysis

## Summary

**Framework**: {framework.title()}  
**Total Flows**: {analysis.get('total_flows', 0)}  
**Source Files**: {analysis.get('total_sources', 0)}  
**Functions Found**: {len(analysis.get('unique_symbols', []))}  

## Functions with Host Header Impact

"""
    
    for func, scenario in functions_with_scenarios[:10]:  # Top 10 functions
        content += f"""### {func}
- **Scenario**: {scenario}

"""
    
    content += f"""## Analysis Method

Open-source taint flow analysis: Host header sources → Function calls → Impact assessment"""
    
    file_path = os.path.join(framework_dir, f"{framework}_analysis_summary.md")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
    
    return file_path


def generate_flow_details(analysis: Dict[str, Any], framework_dir: str) -> str:
    """Generate simplified flow analysis in JSON format."""
    framework = analysis.get("framework", "Unknown")
    flows = analysis.get("flows", [])
    api_impact = analysis.get("api_impact_analysis", {})
    
    # Create flows with scenarios
    flows_with_scenarios = []
    for i, flow in enumerate(flows):
        sink_symbol = flow.get("sink_symbol", "")
        impact_info = api_impact.get(sink_symbol, {})
        scenario = impact_info.get("scenario", "Unknown impact")
        
        if scenario != "Unknown impact - requires manual analysis":
            flows_with_scenarios.append({
                "flow_id": f"flow_{i+1:03d}",
                "source_file": flow.get("source_file", ""),
                "sink_function": sink_symbol,
                "sink_line": flow.get("sink_line", 0),
                "scenario": scenario
            })
    
    detailed_analysis = {
        "framework": framework.title(),
        "summary": {
            "total_flows": analysis.get("total_flows", 0),
            "total_sources": analysis.get("total_sources", 0),
            "functions_found": len(analysis.get("unique_symbols", [])),
            "flows_with_scenarios": len(flows_with_scenarios)
        },
        "flows": flows_with_scenarios[:20],  # Limit to top 20
        "functions": [
            {
                "function": symbol,
                "scenario": api_impact.get(symbol, {}).get("scenario", "Unknown impact")
            }
            for symbol in analysis.get("unique_symbols", [])[:20]  # Limit to top 20
        ]
    }
    
    file_path = os.path.join(framework_dir, f"{framework}_flow_details.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(detailed_analysis, f, ensure_ascii=False, indent=2)
    
    return file_path


def generate_flow_matrix(analysis: Dict[str, Any], framework_dir: str) -> str:
    """Generate simplified flow matrix in CSV format."""
    framework = analysis.get("framework", "Unknown")
    flows = analysis.get("flows", [])
    api_impact = analysis.get("api_impact_analysis", {})
    
    file_path = os.path.join(framework_dir, f"{framework}_flow_matrix.csv")
    
    with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow([
            "Flow_ID", "Source_File", "Sink_Function", "Sink_Line", "Scenario"
        ])
        
        # Write flows (limit to top 50)
        for i, flow in enumerate(flows[:50]):
            sink_symbol = flow.get("sink_symbol", "")
            impact_info = api_impact.get(sink_symbol, {})
            scenario = impact_info.get("scenario", "Unknown impact")
            
            writer.writerow([
                f"flow_{i+1:03d}",
                flow.get("source_file", ""),
                sink_symbol,
                flow.get("sink_line", ""),
                scenario
            ])
    
    return file_path


def generate_visual_flow(analysis: Dict[str, Any], framework_dir: str) -> str:
    """Generate simplified visual flow diagram in HTML format."""
    framework = analysis.get("framework", "Unknown")
    api_impact = analysis.get("api_impact_analysis", {})
    
    # Get functions with scenarios
    functions_with_scenarios = []
    for symbol, impact in api_impact.items():
        scenario = impact.get("scenario", "Unknown impact")
        if scenario != "Unknown impact - requires manual analysis":
            functions_with_scenarios.append((symbol, scenario))
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{framework.title()} HNP Analysis</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
        }}
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #3498db;
        }}
        .stat-number {{
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }}
        .stat-label {{
            color: #7f8c8d;
            font-size: 14px;
            margin-top: 5px;
        }}
        .function-list {{
            margin: 20px 0;
        }}
        .function-item {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #28a745;
        }}
        .function-name {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }}
        .function-scenario {{
            color: #6c757d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 {framework.title()} HNP Analysis</h1>
        
        <div class="summary-stats">
            <div class="stat-card">
                <div class="stat-number">{analysis.get('total_flows', 0)}</div>
                <div class="stat-label">Total Flows</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{analysis.get('total_sources', 0)}</div>
                <div class="stat-label">Source Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(analysis.get('unique_symbols', []))}</div>
                <div class="stat-label">Functions Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(functions_with_scenarios)}</div>
                <div class="stat-label">With Scenarios</div>
            </div>
        </div>

        <h2>Functions with Host Header Impact</h2>
        <div class="function-list">"""
    
    for func, scenario in functions_with_scenarios[:15]:  # Show top 15
        html_content += f"""
            <div class="function-item">
                <div class="function-name">{func}</div>
                <div class="function-scenario">{scenario}</div>
            </div>"""
    
    html_content += f"""
        </div>

        <div style="margin-top: 30px; padding: 20px; background: #e3f2fd; border-radius: 8px;">
            <h3>Analysis Method</h3>
            <p>Open-source taint flow analysis: Host header sources → Function calls → Impact assessment</p>
        </div>
    </div>
</body>
</html>"""
    
    file_path = os.path.join(framework_dir, f"{framework}_visual_flow.html")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return file_path


def generate_all_analysis_files(analysis: Dict[str, Any], framework_dir: str) -> List[str]:
    """Generate all optimized analysis files."""
    generated_files = []
    
    # Generate all analysis files
    generated_files.append(generate_analysis_summary(analysis, framework_dir))
    generated_files.append(generate_flow_details(analysis, framework_dir))
    generated_files.append(generate_flow_matrix(analysis, framework_dir))
    generated_files.append(generate_visual_flow(analysis, framework_dir))
    
    return generated_files


if __name__ == "__main__":
    # This can be used as a standalone script
    import sys
    if len(sys.argv) != 3:
        print("Usage: python analysis_generator.py <framework_json_file> <output_dir>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    output_dir = sys.argv[2]
    
    with open(json_file, "r", encoding="utf-8") as f:
        analysis = json.load(f)
    
    generated = generate_all_analysis_files(analysis, output_dir)
    print(f"Generated {len(generated)} analysis files:")
    for file_path in generated:
        print(f"  - {file_path}")

