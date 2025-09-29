#!/usr/bin/env python3
"""
Update the HNP sinks registry based on Psalm verification results.
"""
import json
import sys
import yaml
from typing import Dict, List, Any
from pathlib import Path

def load_existing_registry(registry_path: str) -> Dict[str, Any]:
    """Load existing registry or create new one."""
    if Path(registry_path).exists():
        try:
            with open(registry_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: Could not load existing registry: {e}", file=sys.stderr)
    
    return {
        'version': '1.0',
        'description': 'HNP (Host Header Poisoning) Sink Registry',
        'sinks': {}
    }

def parse_psalm_results(psalm_json_path: str) -> List[Dict[str, Any]]:
    """Parse Psalm verification results."""
    try:
        with open(psalm_json_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {psalm_json_path} not found", file=sys.stderr)
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing Psalm JSON: {e}", file=sys.stderr)
        return []
    
    confirmed_sinks = []
    
    # Look for taint analysis results
    for issue in data.get('issues', []):
        if issue.get('type') == 'TaintedInput':
            # Extract sink information from the issue
            sink_info = {
                'file': issue.get('file_name', ''),
                'line': issue.get('line_from', 0),
                'sink_type': 'unknown',
                'method': '',
                'class': '',
                'confidence': 'medium'
            }
            
            # Try to extract method/class from the issue message
            message = issue.get('message', '')
            if 'withHeader' in message:
                sink_info['sink_type'] = 'redirect'
                sink_info['method'] = 'withHeader'
            elif 'set' in message and 'Header' in message:
                sink_info['sink_type'] = 'redirect'
                sink_info['method'] = 'setHeader'
            elif 'Domain' in message:
                sink_info['sink_type'] = 'cookie'
                sink_info['method'] = 'setDomain'
            
            confirmed_sinks.append(sink_info)
    
    return confirmed_sinks

def update_registry(registry: Dict[str, Any], confirmed_sinks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Update registry with confirmed sinks."""
    for sink in confirmed_sinks:
        sink_type = sink['sink_type']
        method = sink['method']
        class_name = sink['class']
        
        # Create sink key
        if class_name:
            sink_key = f"{class_name}::{method}"
        else:
            sink_key = method
        
        # Add to registry
        if sink_type not in registry['sinks']:
            registry['sinks'][sink_type] = {}
        
        registry['sinks'][sink_type][sink_key] = {
            'method': method,
            'class': class_name,
            'file': sink['file'],
            'line': sink['line'],
            'confidence': sink['confidence'],
            'verified_date': '2025-09-28',
            'description': f"Verified {sink_type} sink"
        }
    
    return registry

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 update_registry.py <psalm_verify.json> <hnp-registry.yml>", file=sys.stderr)
        sys.exit(1)
    
    psalm_json_path = sys.argv[1]
    registry_path = sys.argv[2]
    
    # Load existing registry
    registry = load_existing_registry(registry_path)
    
    # Parse Psalm results
    confirmed_sinks = parse_psalm_results(psalm_json_path)
    
    if not confirmed_sinks:
        print("No confirmed sinks found in Psalm results", file=sys.stderr)
        sys.exit(0)
    
    # Update registry
    registry = update_registry(registry, confirmed_sinks)
    
    # Save updated registry
    try:
        with open(registry_path, 'w') as f:
            yaml.dump(registry, f, default_flow_style=False, sort_keys=True)
        print(f"Updated registry with {len(confirmed_sinks)} confirmed sinks", file=sys.stderr)
    except Exception as e:
        print(f"Error saving registry: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
