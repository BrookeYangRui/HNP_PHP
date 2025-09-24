# HNP PHP Scanner

A comprehensive Host Header Poisoning (HNP) vulnerability scanner for PHP web frameworks. This tool performs both framework-level and application-level analysis to identify HNP vulnerabilities in PHP applications.

## Overview

HNP (Host Header Poisoning) is a security vulnerability where malicious host headers can be used to:
- Generate malicious URLs
- Bypass authentication
- Perform cache poisoning attacks
- Conduct phishing attacks

This scanner analyzes PHP frameworks and applications to identify:
- **Sources**: Entry points where host headers are processed
- **Sinks**: Dangerous APIs that use host information
- **Security States**: Risk levels (Safe, Risk, Partial, Protected)
- **Configuration Issues**: Missing or incorrect security configurations

## Project Structure

```
HNP_PHP/
├── src/                          # Core scripts
│   ├── framework_cli.py          # Framework download manager
│   ├── framework_scanner.py      # Lightweight pattern scanner
│   ├── deep_scanner.py           # Deep taint analysis
│   ├── report_generator.py       # Report generation
│   ├── chart_generator.py        # Chart and table generation
│   └── php_scanner.php           # PHP scanner implementation
├── config/                       # Configuration files
│   ├── framework_config.yaml     # Framework metadata
│   └── php_scanner_composer.json # PHP dependencies
├── frameworks/                   # Downloaded framework source code
├── reports/                      # Generated reports
│   ├── framework/               # Framework-level reports
│   ├── csv/                     # CSV data exports
│   ├── figures/                 # Generated charts
│   └── tex/                     # LaTeX tables
└── docs/                        # Documentation
```

## Quick Start

### 1. Download Frameworks

```bash
# List available frameworks
python3 src/framework_cli.py --list

# Download specific framework
python3 src/framework_cli.py --download 1  # Laravel

# Interactive download
python3 src/framework_cli.py --interactive
```

### 2. Run Framework-Level Scan

```bash
# Lightweight pattern scan
python3 src/framework_scanner.py --framework laravel symfony codeigniter

# Deep taint analysis
python3 src/deep_scanner.py --framework laravel
```

### 3. Generate Reports

```bash
# Generate individual framework reports
python3 src/report_generator.py --framework laravel

# Generate charts and LaTeX tables
python3 src/chart_generator.py
```

## Supported Frameworks

| ID | Framework | Repository | Status |
|----|-----------|------------|--------|
| 1  | Laravel   | laravel/laravel | ✅ |
| 2  | Symfony   | symfony/symfony-demo | ✅ |
| 3  | CodeIgniter | codeigniter4/CodeIgniter4 | ✅ |
| 4  | CakePHP   | cakephp/app | ✅ |
| 5  | Yii       | yiisoft/yii2-app-basic | ✅ |
| 6  | Slim      | slimphp/Slim-Skeleton | ⏳ |
| 7  | Laminas   | laminas/laminas-mvc-skeleton | ⏳ |
| 8  | Phalcon   | phalcon/cphalcon | ⏳ |

## Security States

The scanner categorizes findings into four security states:

- **Safe**: No vulnerabilities or complete protection
- **Risk**: Unprotected dangerous flows
- **Partial**: Some protection (guard OR validation)
- **Protected**: Complete protection (guard AND validation)

## Output Formats

### CSV Reports
- `flow_api_risk_detailed.csv`: Detailed API risk analysis
- `flow_summary.csv`: Framework summary statistics

### JSON/YAML Reports
- Individual framework analysis reports
- Deep taint analysis results

### LaTeX Tables
- IEEE S&P style tables for academic papers
- Publication-ready formatting

## Configuration

Edit `config/framework_config.yaml` to:
- Add new frameworks
- Modify source/sink patterns
- Update validation rules
- Customize security checks

## Requirements

- Python 3.8+
- PHP 7.4+ (for deep scanning)
- Git (for framework downloads)
- PyYAML (for configuration)

## Usage Examples

### Complete Framework Analysis

```bash
# Download all frameworks
for i in {1..5}; do python3 src/framework_cli.py --download $i; done

# Run comprehensive scan
python3 src/framework_scanner.py --framework laravel symfony codeigniter cakephp yii

# Generate deep analysis
for fw in laravel symfony codeigniter cakephp yii; do
    python3 src/deep_scanner.py --framework $fw
done

# Create final reports
python3 src/chart_generator.py
```

### Application-Level Analysis

```bash
# Scan specific application
python3 src/deep_scanner.py --framework laravel --target /path/to/app

# Generate application report
python3 src/report_generator.py --framework laravel --app-specific
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add framework support in `config/framework_config.yaml`
4. Test with existing frameworks
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Citation

If you use this tool in academic research, please cite:

```bibtex
@software{hnp_php_scanner,
  title={HNP PHP Scanner: Host Header Poisoning Vulnerability Detection},
  author={Your Name},
  year={2024},
  url={https://github.com/your-repo/hnp-php-scanner}
}
```
