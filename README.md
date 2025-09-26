# HNP PHP Analysis System

A unified system for analyzing PHP web frameworks and applications for Host Header Injection (HNP) vulnerabilities.

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

- **Unified JSON**: `reports/*/json/unified_*.json` - All results in one file
- **CSV Reports**: `reports/*/csv/*.csv` - Tabular data
- **Progress**: `progress.json` - Analysis progress and statistics

## 🔍 Understanding Results

### Security States
- **Safe**: No vulnerabilities found
- **Low Risk**: 1-5 vulnerabilities
- **Medium Risk**: 6-10 vulnerabilities
- **High Risk**: 10+ vulnerabilities

### Vulnerability Scenarios
- **URL Generation**: Host header in URL construction
- **Authentication Bypass**: Host header in auth logic
- **Cache Poisoning**: Host header in cache keys
- **Email Spoofing**: Host header in email generation
- **API Manipulation**: Host header in API responses
- **Configuration Injection**: Host header in configuration

## 🛠️ Prerequisites

- Python 3.7+
- Git
- PHP 7.4+ (optional, for deep analysis)
- Required packages: `pip install pyyaml pandas matplotlib seaborn`

## 📁 Project Structure

```
HNP_PHP/
├── run.py                 # 🎯 Main entry point
├── src/                   # Core analysis scripts (Plan C external taint only)
├── config/                # Configuration files
├── target-list/           # 147 vulnerable projects
├── reports/               # Analysis results
└── frameworks/            # Downloaded framework source
```

## 🚀 That's It!

The system is designed to be simple and unified. Just run `python3 run.py` for interactive mode or `python3 run.py --all` for complete analysis!

### Interactive Menu Features
- **Framework Analysis**: Choose specific frameworks or analyze all
- **Application Analysis**: Single project, batch analysis, or resume
- **Smart Downloads**: Automatically skips already downloaded frameworks
- **Progress Tracking**: Resume interrupted analysis
- **Results Viewing**: Quick access to all analysis results