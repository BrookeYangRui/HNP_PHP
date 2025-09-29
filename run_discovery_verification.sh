#!/bin/bash

# HNP Sink Discovery and Verification Pipeline
# This script implements the two-stage discovery→verification process

set -e

# Configuration
PROJECT_ROOT="/home/rui/HNP_PHP"
RULES_DIR="$PROJECT_ROOT/rules/discovery"
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
OUT_DIR="$PROJECT_ROOT/out"
REGISTRY_DIR="$PROJECT_ROOT/registry"
PSALM_STUBS_DIR="$PROJECT_ROOT/rules/psalm-stubs"

# Ensure output directory exists
mkdir -p "$OUT_DIR"

# Set PATH to use PHP 8.3
export PATH="/usr/local/php8.3/bin:$PATH"

echo "=== HNP Sink Discovery and Verification Pipeline ==="
echo "Project root: $PROJECT_ROOT"
echo "PHP version: $(php --version | head -1)"
echo "Psalm version: $(psalm --version)"
echo "Semgrep version: $(semgrep --version)"
echo ""

# Stage 1: Discovery Mode - Semgrep
echo "=== Stage 1: Discovery Mode ==="
echo "Running Semgrep discovery rules..."

if [ ! -d "$RULES_DIR" ]; then
    echo "Error: Rules directory not found: $RULES_DIR"
    exit 1
fi

# Run Semgrep discovery
semgrep --config "$RULES_DIR" --json -o "$OUT_DIR/discover.json" "$PROJECT_ROOT/frameworks" || {
    echo "Warning: Semgrep discovery completed with issues"
}

if [ ! -f "$OUT_DIR/discover.json" ]; then
    echo "Error: Semgrep discovery failed to produce results"
    exit 1
fi

echo "Discovery results saved to: $OUT_DIR/discover.json"

# Extract candidate sinks
echo "Extracting candidate sinks..."
python3 "$SCRIPTS_DIR/extract_candidates.py" "$OUT_DIR/discover.json" > "$OUT_DIR/candidate_sinks.csv" || {
    echo "Error: Failed to extract candidates"
    exit 1
}

echo "Candidate sinks saved to: $OUT_DIR/candidate_sinks.csv"

# Generate temporary Psalm sink stubs
echo "Generating temporary Psalm sink stubs..."
python3 "$SCRIPTS_DIR/gen_temp_sinks_stub.py" "$OUT_DIR/candidate_sinks.csv" > "$PSALM_STUBS_DIR/temp_sinks.phpstub" || {
    echo "Error: Failed to generate Psalm stubs"
    exit 1
}

echo "Temporary stubs generated: $PSALM_STUBS_DIR/temp_sinks.phpstub"

# Filter candidates for Psalm verification
echo "Filtering candidates for verification..."
python3 "$SCRIPTS_DIR/filter_candidates.py" "$OUT_DIR/discover.json" > "$OUT_DIR/candidates.txt" || {
    echo "Warning: Failed to filter candidates, using all files"
    find "$PROJECT_ROOT/frameworks" -name "*.php" | head -100 > "$OUT_DIR/candidates.txt"
}

echo "Candidate files for verification: $OUT_DIR/candidates.txt"

# Stage 2: Verification Mode - Psalm
echo ""
echo "=== Stage 2: Verification Mode ==="
echo "Running Psalm taint analysis..."

# Run Psalm with taint analysis
psalm --taint-analysis --output-format=json --report="$OUT_DIR/psalm_verify.json" $(cat "$OUT_DIR/candidates.txt") || {
    echo "Warning: Psalm verification completed with issues"
}

if [ ! -f "$OUT_DIR/psalm_verify.json" ]; then
    echo "Error: Psalm verification failed to produce results"
    exit 1
fi

echo "Verification results saved to: $OUT_DIR/psalm_verify.json"

# Update registry with confirmed sinks
echo "Updating registry with confirmed sinks..."
python3 "$SCRIPTS_DIR/update_registry.py" "$OUT_DIR/psalm_verify.json" "$REGISTRY_DIR/hnp-sinks.yml" || {
    echo "Error: Failed to update registry"
    exit 1
}

echo "Registry updated: $REGISTRY_DIR/hnp-sinks.yml"

# Generate summary report
echo ""
echo "=== Summary Report ==="
echo "Discovery results: $OUT_DIR/discover.json"
echo "Candidate sinks: $OUT_DIR/candidate_sinks.csv"
echo "Verification results: $OUT_DIR/psalm_verify.json"
echo "Updated registry: $REGISTRY_DIR/hnp-sinks.yml"

# Show candidate count
if [ -f "$OUT_DIR/candidate_sinks.csv" ]; then
    CANDIDATE_COUNT=$(tail -n +2 "$OUT_DIR/candidate_sinks.csv" | wc -l)
    echo "Total candidates found: $CANDIDATE_COUNT"
fi

# Show registry stats
if [ -f "$REGISTRY_DIR/hnp-sinks.yml" ]; then
    echo "Registry contents:"
    grep -A 20 "verified_sinks:" "$REGISTRY_DIR/hnp-sinks.yml" || echo "No verified sinks yet"
fi

echo ""
echo "=== Pipeline Complete ==="
echo "Check the output files for detailed results."
echo "Run this script again to discover new sinks as frameworks are added."
