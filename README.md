# HNP_PHP - Host Header Poisoning Static Analysis System

A two-stage static analysis system for detecting Host Header Poisoning (HNP) vulnerabilities in PHP applications using Semgrep and Psalm.

## 🎯 Overview

This system implements a **discovery → verification** pipeline for finding HNP sinks:

1. **Discovery Mode**: Uses generic semantic rules in Semgrep to identify potential HNP sinks
2. **Verification Mode**: Uses Psalm's taint analysis to verify complete taint chains

## ✨ Key Features

- ✅ **Generic semantic sink discovery** (not hardcoded function names)
- ✅ **True taint tracking** with Psalm
- ✅ **Multi-framework support** (Laravel, Symfony, WordPress, CodeIgniter, Yii2)
- ✅ **Sanitizer detection** and validation
- ✅ **Progressive registry building**
- ✅ **Academic-ready documentation**

## 🚀 Quick Start

### Interactive Mode (Recommended)
```bash
# 1. Setup frameworks (first time only)
./setup_frameworks.sh

# 2. Run interactive analyzer
./run_interactive.sh

# 3. Select framework to analyze (1-6)
# 4. View detailed CSV and JSON results in out/ directory
```

### Command Line Mode
```bash
# 1. Setup frameworks (see frameworks/README.md)
# 2. Run the complete analysis pipeline
./run_discovery_verification.sh

# Or run individual steps
semgrep --config rules/discovery --json -o out/discover.json .
python3 scripts/extract_candidates.py out/discover.json > out/candidate_sinks.csv
psalm --taint-analysis --output-format=json --report=out/psalm_verify.json
```

### Direct Framework Analysis
```bash
# Analyze specific framework directly
python3 interactive_analyzer.py --framework 1  # Laravel
python3 interactive_analyzer.py --framework 2  # Symfony
python3 interactive_analyzer.py --framework 3  # WordPress
python3 interactive_analyzer.py --framework 4  # CodeIgniter
python3 interactive_analyzer.py --framework 5  # CakePHP
python3 interactive_analyzer.py --framework 6  # Yii2
```

## 📁 Project Structure

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for detailed directory layout.

```
HNP_PHP/
├── rules/discovery/          # Semgrep discovery rules
├── rules/psalm-stubs/        # Psalm taint analysis stubs  
├── scripts/                  # Automation scripts
├── frameworks/               # Framework source code (user-provided)
├── out/                      # Analysis outputs
└── registry/                 # Confirmed sinks registry
```

## 🔧 Requirements

- **PHP**: 8.1+ (tested with 8.3.16)
- **Psalm**: 6.13+ (with taint analysis support)
- **Semgrep**: 1.82+
- **Python**: 3.10+

## 📚 Documentation

- [Quick Start Guide](QUICK_START.md) - Interactive analyzer usage
- [Interactive Guide](INTERACTIVE_GUIDE.md) - Detailed interactive mode guide
- [Project Structure](PROJECT_STRUCTURE.md) - Detailed directory layout
- [Frameworks Setup](frameworks/README.md) - How to download frameworks
- [System Summary](SYSTEM_SUMMARY.md) - Complete system overview

## 🎓 Academic Use

This project is designed for academic research on Host Header Poisoning detection. See documentation for citation guidelines.

## 📄 License

Academic research project - see LICENSE file for details.