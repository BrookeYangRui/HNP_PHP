# Reports Directory Structure

This directory contains analysis reports organized by analysis type:

## 📁 Directory Structure

```
reports/
├── framework_analysis/          # Framework-level analysis results
│   ├── csv/                    # CSV reports for frameworks
│   │   ├── flow_api_risk.csv
│   │   ├── flow_api_risk_detailed.csv
│   │   ├── flow_high_risk.csv
│   │   ├── flow_matrix.csv
│   │   ├── flow_summary.csv
│   │   └── flow_top_sinks.csv
│   ├── json/                   # JSON reports for frameworks
│   │   ├── {framework}_report.json
│   │   └── {framework}_deep_analysis.json
│   ├── yaml/                   # YAML reports for frameworks
│   │   └── {framework}_report.yaml
│   ├── tex/                    # LaTeX tables for academic papers
│   │   └── framework_api_risk_table.tex
│   └── figures/                # Charts and visualizations
│
└── application_analysis/        # Application-level analysis results
    ├── csv/                    # CSV reports for applications
    │   └── target_analysis_results.csv
    ├── json/                   # JSON reports for applications
    │   └── {repository}_analysis.json
    ├── tex/                    # LaTeX tables for applications
    └── figures/                # Charts for applications
```

## 🔍 Analysis Types

### Framework Analysis
- **Purpose**: Analyze PHP web frameworks for HNP vulnerabilities
- **Scope**: Laravel, Symfony, CodeIgniter, CakePHP, Yii
- **Output**: Source/sink patterns, security states, configuration checks
- **Tools**: `framework_scanner.py`, `deep_scanner.py`, `report_generator.py`

### Application Analysis  
- **Purpose**: Analyze individual vulnerable PHP applications
- **Scope**: 147 projects from target list
- **Output**: Vulnerability scenarios, taint tracking detection, risk assessment
- **Tools**: `target_analyzer.py`

## 📊 Report Formats

- **CSV**: Tabular data for statistical analysis
- **JSON**: 
  - **Individual**: `{project}_analysis.json` - Single project/framework reports
  - **Unified**: `unified_analysis_results.json` - All projects in one file
  - **Unified**: `unified_framework_analysis.json` - All frameworks in one file
- **YAML**: Human-readable configuration and metadata
- **LaTeX**: Academic paper-ready tables and figures

### Unified JSON Structure

**Application Analysis (`unified_analysis_results.json`):**
```json
{
  "metadata": {
    "total_projects": 7,
    "last_updated": "2025-09-24 22:12:38",
    "analysis_version": "1.0"
  },
  "projects": [
    {
      "repository": "project/repo",
      "url": "https://github.com/project/repo",
      "framework_detected": "Laravel",
      "vulnerabilities_found": 5,
      "security_state": "Medium Risk",
      "vulnerability_scenarios": [...],
      "taint_tracking_detected": true
    }
  ]
}
```

**Framework Analysis (`unified_framework_analysis.json`):**
```json
{
  "metadata": {
    "total_frameworks": 5,
    "last_updated": "2025-09-24 22:12:31",
    "analysis_version": "1.0"
  },
  "frameworks": {
    "laravel": {
      "framework": "laravel",
      "sources": [...],
      "sinks": [...],
      "security_state": "Risk"
    }
  }
}
```

## 🚀 Usage

### Framework Analysis
```bash
# Generate framework reports
python3 src/report_generator.py --framework laravel symfony

# Scan frameworks for vulnerabilities
python3 src/framework_scanner.py --framework laravel symfony

# Deep taint analysis
python3 src/deep_scanner.py --framework laravel

# Generate charts and tables
python3 src/chart_generator.py
```

### Application Analysis
```bash
# Analyze single application
python3 src/target_analyzer.py --single 0

# Batch analysis with resume
python3 src/target_analyzer.py --resume --count 10

# Clear progress and start fresh
python3 src/target_analyzer.py --clear-progress
```

### JSON Report Management
```bash
# Merge existing individual JSON files into unified files
python3 src/merge_json_reports.py

# View unified application analysis
cat reports/application_analysis/json/unified_analysis_results.json

# View unified framework analysis
cat reports/framework_analysis/json/unified_framework_analysis.json
```

## 📈 Progress Tracking

- **progress.json**: Contains analysis progress and statistics
- **Duplicate Detection**: Automatically skips already analyzed projects
- **Resume Support**: Continue analysis from where it left off
