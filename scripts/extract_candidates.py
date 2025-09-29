#!/usr/bin/env python3
"""
Extract candidate sinks from Semgrep discovery results.
"""
import json
import sys
import csv
from typing import Dict, List, Any

def extract_candidate_sinks(discover_json_path: str) -> List[Dict[str, Any]]:
    """Extract candidate sink signatures from Semgrep discovery results."""
    candidates = []
    
    try:
        with open(discover_json_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {discover_json_path} not found", file=sys.stderr)
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        return []
    
    for result in data.get('results', []):
        rule_id = result.get('check_id', '')
        file_path = result.get('path', '')
        line_number = result.get('start', {}).get('line', 0)
        message = result.get('message', '')
        
        # Extract metavariables for sink signature
        metavars = result.get('extra', {}).get('metavars', {})
        
        # Score the candidate based on rule type and context
        score = 0
        sink_type = "unknown"
        
        if "redirect" in rule_id:
            score += 3
            sink_type = "redirect"
        elif "cors" in rule_id:
            score += 2
            sink_type = "cors"
        elif "cookie" in rule_id:
            score += 2
            sink_type = "cookie"
        elif "absurl" in rule_id:
            score += 1
            sink_type = "absurl"
        
        # Extract method/function name if available
        method_name = ""
        if '$M' in metavars:
            method_name = metavars['$M'].get('abstract_content', '')
        
        # Extract header name if available
        header_name = ""
        if '$H' in metavars:
            header_name = metavars['$H'].get('abstract_content', '')
        
        # Extract class/object info
        class_name = ""
        if '$RESP' in metavars:
            class_name = metavars['$RESP'].get('abstract_content', '')
        elif '$OBJ' in metavars:
            class_name = metavars['$OBJ'].get('abstract_content', '')
        
        candidate = {
            'rule_id': rule_id,
            'file_path': file_path,
            'line_number': line_number,
            'message': message,
            'sink_type': sink_type,
            'score': score,
            'method_name': method_name,
            'header_name': header_name,
            'class_name': class_name,
            'metavars': metavars
        }
        
        candidates.append(candidate)
    
    return candidates

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 extract_candidates.py <discover.json>", file=sys.stderr)
        sys.exit(1)
    
    discover_json_path = sys.argv[1]
    candidates = extract_candidate_sinks(discover_json_path)
    
    # Sort by score (highest first)
    candidates.sort(key=lambda x: x['score'], reverse=True)
    
    # Output as CSV
    if candidates:
        fieldnames = ['rule_id', 'file_path', 'line_number', 'sink_type', 'score', 
                     'method_name', 'header_name', 'class_name', 'message']
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        
        for candidate in candidates:
            writer.writerow({k: candidate[k] for k in fieldnames})
    else:
        print("No candidates found", file=sys.stderr)

if __name__ == "__main__":
    main()
