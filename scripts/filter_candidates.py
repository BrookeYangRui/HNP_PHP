#!/usr/bin/env python3
"""
Filter candidate files for Psalm verification.
"""
import json
import sys
from typing import Set

def filter_candidate_files(discover_json_path: str) -> Set[str]:
    """Extract unique file paths from Semgrep discovery results."""
    candidate_files = set()
    
    try:
        with open(discover_json_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {discover_json_path} not found", file=sys.stderr)
        return set()
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        return set()
    
    for result in data.get('results', []):
        file_path = result.get('path', '')
        if file_path and file_path.endswith('.php'):
            candidate_files.add(file_path)
    
    return candidate_files

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 filter_candidates.py <discover.json>", file=sys.stderr)
        sys.exit(1)
    
    discover_json_path = sys.argv[1]
    candidate_files = filter_candidate_files(discover_json_path)
    
    # Output file paths, one per line
    for file_path in sorted(candidate_files):
        print(file_path)

if __name__ == "__main__":
    main()
