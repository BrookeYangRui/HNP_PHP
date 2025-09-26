# HNP PHP Analysis System

A unified system for analyzing PHP web frameworks and applications for Host Header Poisoning (HNP) vulnerabilities using open-source taint flow analysis.

## 🚀 Quick Start

### Interactive Mode (Recommended)
```bash
# Start interactive menu
python3 run.py
# or
python3 run.py --interactive
```

### One-Command Analysis
```bash
# Run complete analysis (download frameworks + analyze + generate reports)
python3 run.py --all
```

### Step-by-Step Analysis
```bash
# 1. Download frameworks (skips if already downloaded)
python3 run.py --download laravel symfony codeigniter

# 2. Analyze frameworks
python3 run.py --analyze-frameworks

# 3. Analyze applications
python3 run.py --analyze-apps 20

# 4. Show results
python3 run.py --results
```

## 📋 Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `--interactive` | Interactive menu | `python3 run.py --interactive` |
| `--download` | Download frameworks (skips existing) | `python3 run.py --download laravel symfony` |
| `--analyze-frameworks` | Analyze frameworks | `python3 run.py --analyze-frameworks` |
| `--analyze-apps` | Analyze applications | `python3 run.py --analyze-apps 10` |
| `--resume` | Resume analysis | `python3 run.py --resume` |
| `--results` | Show results | `python3 run.py --results` |
| `--all` | Complete analysis | `python3 run.py --all` |

## 🎯 Common Use Cases

### Research Paper Data
```bash
# Generate all data for academic paper
python3 run.py --all
```

### Framework Comparison
```bash
# Download and analyze main frameworks
python3 run.py --download laravel symfony codeigniter cakephp yii
python3 run.py --analyze-frameworks
```

### Application Vulnerability Study
```bash
# Analyze 50 vulnerable applications
python3 run.py --analyze-apps 50
```

### Resume Interrupted Analysis
```bash
# Continue from where you left off
python3 run.py --resume
```

## 📊 Output Files

All results are saved in the `reports/` directory:

- **Framework Analysis**: `reports/framework_analysis/{framework}/` - Per-framework analysis
- **CSV Reports**: `reports/framework_analysis/{framework}/*.csv` - Tabular data
- **JSON Reports**: `reports/framework_analysis/{framework}/*.json` - Structured data
- **HTML Reports**: `reports/framework_analysis/{framework}/*.html` - Visual analysis

## 🔍 Understanding Results

### Analysis Output
- **Total Flows**: Number of taint flows discovered
- **Source Files**: Files containing host header sources
- **Functions Found**: Unique functions that may be affected by host headers
- **Scenarios**: How host headers influence function behavior

### Impact Scenarios
- **URL Generation**: Host header influences generated URLs
- **Redirects**: Host header affects redirect destinations
- **Response Headers**: Host header affects response headers
- **Template Rendering**: Host header influences template output
- **Cache Operations**: Host header affects cache behavior
- **Email/Notifications**: Host header influences email content

## 🛠️ Prerequisites

- Python 3.7+
- Git
- PHP 7.4+ (optional, for deep analysis)
- Required packages: `pip install pyyaml pandas matplotlib seaborn`

## 📁 Project Structure

```
HNP_PHP/
├── run.py                 # 🎯 Main entry point
├── src/                   # Core analysis scripts (external taint engines)
├── config/                # Configuration files
├── reports/               # Analysis results
├── frameworks/            # Downloaded framework source
└── docs/                  # Documentation
```

## 🚀 That's It!

The system is designed to be simple and unified. Just run `python3 run.py` for interactive mode or `python3 run.py --all` for complete analysis!

### Interactive Menu Features
- **Framework Analysis**: Choose specific frameworks or analyze all
- **Application Analysis**: Single project, batch analysis, or resume
- **Smart Downloads**: Automatically skips already downloaded frameworks
- **Progress Tracking**: Resume interrupted analysis
- **Results Viewing**: Quick access to all analysis results