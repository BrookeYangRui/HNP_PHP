# PHP Host Name Pollution (HNP) Scanner

A comprehensive static analysis tool for detecting Host Name Pollution vulnerabilities in PHP applications.

## Overview

Host Name Pollution (HNP) is a security vulnerability where applications trust the `Host` header from HTTP requests without proper validation, allowing attackers to redirect users to malicious domains or perform cache poisoning attacks.

## Features

- **Static Analysis**: Uses Semgrep for pattern-based vulnerability detection
- **Framework Support**: Includes adapters for Laravel, Symfony, WordPress, CakePHP, CodeIgniter, and Yii2
- **Sink Analysis**: Categorizes vulnerabilities by sink type (redirect, email, output, etc.)
- **Risk Assessment**: Assigns risk levels (LOW, MEDIUM, HIGH, CRITICAL) based on exploit scenarios
- **Batch Scanning**: Supports scanning multiple repositories from CSV input
- **Detailed Reporting**: Generates comprehensive CSV reports with source code context

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd php-hnp-scanner-pro
```

2. Set up Python virtual environment:
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac
```

3. Install dependencies:
```bash
pip install semgrep
```

## Usage

### Single Project Scan

```bash
python cli/hnp_scan.py /path/to/php/project
```

### Batch Scan from CSV

```bash
python hnp_scanner.py
```

The scanner will read from `defense_result_php.csv` and generate results in `hnp_scan_results.csv`.

### CLI Options

```bash
python cli/hnp_scan.py [target] [options]

Options:
  --rules RULES_FILE     Custom rules file (default: rules/php-hnp.yml)
  --min-score SCORE      Minimum risk score to report (LOW/MEDIUM/HIGH/CRITICAL)
  --emit-sarif          Generate SARIF output
  --allow-host HOST     Whitelist specific hosts
```

## Rules

The scanner uses Semgrep rules defined in `rules/php-hnp.yml` to detect:

- `$_SERVER['HTTP_HOST']` usage
- `$_SERVER['HTTP_X_FORWARDED_HOST']` usage  
- `$_SERVER['SERVER_NAME']` usage
- URL construction patterns
- Redirect vulnerabilities
- Email injection points

## Sink Types

The scanner categorizes findings by sink type:

- **Redirect_Sink**: `header()` redirects (HIGH risk)
- **Email_Sink**: `mail()`, PHPMailer, SwiftMailer (HIGH risk)
- **Output_Sink**: `echo`, `print` statements (MEDIUM risk)
- **File_Inclusion_Sink**: `include`, `require` (CRITICAL risk)
- **Database_Sink**: SQL query functions (HIGH risk)
- **URL_Construction_Sink**: URL building (MEDIUM risk)
- **File_Operation_Sink**: File operations (HIGH risk)
- **Configuration_Sink**: Config modifications (MEDIUM risk)
- **Logging_Sink**: Log functions (LOW risk)

## Framework Adapters

Framework-specific adapters analyze configuration files to:

- Detect URL pinning (e.g., `APP_URL` in Laravel)
- Identify trusted proxies and hosts
- Reduce false positives
- Escalate risk based on environment context

Supported frameworks:
- Laravel (`adapters/adapter_laravel.py`)
- Symfony (`adapters/adapter_symfony.py`)
- WordPress (`adapters/adapter_wordpress.py`)
- CakePHP (`adapters/adapter_cakephp.py`)
- CodeIgniter (`adapters/adapter_codeigniter.py`)
- Yii2 (`adapters/adapter_yii2.py`)

## Output Format

The scanner generates CSV reports with the following columns:

- **Basic Info**: Index, Repository, URL, Stars, Year, Expected_Vuln_Type
- **Detection Results**: Has_HNP_Issue, Total_Findings, File_Path, Line_Number
- **Analysis**: Problem_Type, Sink_Type, Sink_Function
- **Risk Assessment**: Exploit_Scenario, Risk_Level
- **Source Code**: Source_Code, Context
- **Status**: success/timeout/error

## Test Fixtures

The `tests/fixtures/` directory contains minimal reproduction test cases for each supported framework:

- `vuln.php`: Vulnerable examples
- `safe.php`: Secure implementations

## CI/CD Integration

GitHub Actions workflow (`.github/workflows/hnp.yml`) provides:

- Automated scanning on pull requests
- SARIF output for GitHub Code Scanning
- Risk-based filtering
- Framework-specific analysis

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new rules
4. Submit a pull request

## License

This project is licensed under the MIT License.

## Security

If you discover a security vulnerability, please report it responsibly through the security contact information in the repository.
