#!/bin/bash

# Interactive HNP Framework Analyzer Launcher
# This script sets up the environment and launches the interactive analyzer

echo "🔍 HNP Framework Analyzer - Interactive Mode"
echo "=============================================="

# Set PHP 8.3 environment
export PATH="/usr/local/php8.3/bin:$PATH"

# Verify environment
echo "🔧 Checking environment..."
echo "PHP version: $(php --version | head -1)"
echo "Psalm version: $(psalm --version 2>/dev/null || echo 'Not found')"
echo "Semgrep version: $(semgrep --version 2>/dev/null || echo 'Not found')"
echo "Python version: $(python3 --version)"
echo ""

# Check if frameworks directory exists
if [ ! -d "frameworks" ]; then
    echo "❌ Frameworks directory not found!"
    echo "Please create the frameworks directory and download frameworks first."
    echo "See frameworks/README.md for instructions."
    exit 1
fi

# Check if any frameworks are available
if [ -z "$(ls -A frameworks 2>/dev/null)" ]; then
    echo "⚠️  No frameworks found in frameworks/ directory"
    echo "Please download frameworks first. See frameworks/README.md for instructions."
    echo ""
    echo "Quick setup examples:"
    echo "  cd frameworks"
    echo "  composer create-project laravel/laravel:^10.0 laravel"
    echo "  composer create-project symfony/skeleton:^6.0 symfony"
    echo ""
    read -p "Do you want to continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Launch the interactive analyzer
echo "🚀 Launching interactive analyzer..."
echo ""
python3 interactive_analyzer.py
