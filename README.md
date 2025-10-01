# Open Taint Tracking Analyzer

A comprehensive open-ended static analysis tool for discovering Host Header usage patterns in PHP frameworks.

## 🎯 Overview

This tool performs **Open Taint Tracking** analysis to discover all Host Header usage patterns in PHP frameworks without any sink restrictions. It provides comprehensive insights into how host data flows through the codebase.

## 🔬 Analysis Method

- **Open-ended Taint Tracking**: No sink restrictions, let taint flow freely
- **Comprehensive Discovery**: Find all host usage patterns, not just security issues
- **Pattern Classification**: Categorize usage into 8 different types
- **Security Analysis**: Identify validation, risk usage, and context-dependent cases

## 📊 Results (Laravel Example)

- **33 taint propagation points** discovered
- **12 files** analyzed
- **6 usage patterns** identified:
  - URL Construction: 15 (45.5%)
  - Other: 9 (27.3%)
  - Direct Return: 4 (12.1%)
  - Object Properties: 3 (9.1%)
  - Validation: 1 (3.0%)
  - String Operations: 1 (3.0%)
- **Security Analysis**:
  - Explicit validation: 4 points
  - No explicit validation: 10 points
  - Context-dependent: 19 points

## 🚀 Usage

### Interactive Mode
```bash
python3 open_taint_analyzer.py
```

### Direct Analysis
```bash
python3 open_taint_analyzer.py --framework 1
```

### Available Frameworks
1. Laravel
2. Symfony
3. WordPress
4. CodeIgniter
5. CakePHP
6. Yii2
7. All Frameworks

## 📁 Project Structure

```
├── open_taint_analyzer.py          # Main analysis tool
├── rules/
│   ├── discovery/
│   │   └── open-host-exploration.yml  # Open exploration rule
│   └── psalm-stubs/
│       ├── taint_sources.phpstub      # Taint sources
│       └── open_exploration.phpstub   # Open exploration stubs
├── frameworks/                      # Framework source code
└── results/                         # Analysis results
    └── [framework]/
        ├── open_discovery.json       # Raw discovery data
        ├── open_taint_data.csv       # Structured analysis data
        └── open_analysis_summary.json # Analysis summary
```

## 📄 Generated Reports

- **open_discovery.json**: Raw Semgrep discovery results
- **open_taint_data.csv**: Structured analysis data with usage patterns
- **open_analysis_summary.json**: Analysis summary with statistics

## 🎯 Key Features

- **No Sink Restrictions**: Discovers all host usage patterns
- **Pattern Classification**: 8 different usage pattern types
- **Security Analysis**: Validation and risk assessment
- **Comprehensive Coverage**: 175% more findings than restrictive methods
- **Framework Support**: Laravel, Symfony, WordPress, CodeIgniter, CakePHP, Yii2

## 🔍 Analysis Types

1. **Direct_Return**: Direct return of host data
2. **URL_Construction**: Host data used in URL building
3. **Header_Setting**: Host data in HTTP headers
4. **Configuration**: Host data in configuration
5. **Validation**: Host data in validation logic
6. **String_Operations**: Host data in string manipulation
7. **Object_Properties**: Host data assigned to object properties
8. **Other**: Other usage patterns

## 📈 Benefits

- **Comprehensive Discovery**: Find all host usage points
- **Research Foundation**: Understanding of framework behavior
- **Security Insights**: Identify validation and risk patterns
- **Academic Value**: Objective analysis without subjective risk assessments

## 🛠️ Requirements

- Python 3.6+
- Semgrep
- PHP frameworks in `frameworks/` directory

## 📊 Example Output

```
📊 OPEN TAINT TRACKING RESULTS FOR LARAVEL
============================================================
Total Taint Points: 33
Files Analyzed: 12
Analysis Type: Open Taint Tracking

Usage Pattern Distribution:
  - URL_Construction: 15 (45.5%)
  - Other: 9 (27.3%)
  - Direct_Return: 4 (12.1%)
  - Object_Properties: 3 (9.1%)
  - Validation: 1 (3.0%)
  - String_Operations: 1 (3.0%)

Security Analysis:
  - Explicit validation: 4 points
  - No explicit validation: 10 points
  - Context-dependent: 19 points
```

---

*This tool provides comprehensive open-ended analysis of Host Header usage in PHP frameworks, enabling researchers and developers to understand data flow patterns and security implications.*