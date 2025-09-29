#!/usr/bin/env python3
"""
Generate temporary Psalm sink stubs from candidate sinks.
"""
import csv
import sys
import re
from typing import List, Dict, Any

def generate_psalm_stub(candidates: List[Dict[str, Any]]) -> str:
    """Generate Psalm stub content for candidate sinks."""
    stub_content = "<?php\n"
    stub_content += "// Auto-generated temporary sink stubs\n"
    stub_content += "// Generated from candidate sink discovery\n\n"
    
    # Group candidates by class/method for deduplication
    seen_signatures = set()
    
    for candidate in candidates:
        if int(candidate['score']) < 1:  # Skip low-scoring candidates
            continue
            
        method_name = candidate['method_name']
        class_name = candidate['class_name']
        header_name = candidate['header_name']
        sink_type = candidate['sink_type']
        
        # Generate signature based on sink type
        if sink_type == "redirect" and method_name and header_name:
            if header_name.lower() in ['"location"', "'location'", 'location']:
                signature = f"{class_name}::{method_name}"
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    stub_content += generate_redirect_stub(class_name, method_name)
        
        elif sink_type == "cors" and method_name and header_name:
            if "access-control-allow-origin" in header_name.lower():
                signature = f"{class_name}::{method_name}"
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    stub_content += generate_cors_stub(class_name, method_name)
        
        elif sink_type == "cookie" and method_name:
            if "domain" in method_name.lower():
                signature = f"{class_name}::{method_name}"
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    stub_content += generate_cookie_stub(class_name, method_name)
    
    return stub_content

def generate_redirect_stub(class_name: str, method_name: str) -> str:
    """Generate stub for redirect-related methods."""
    # Extract namespace from class name if present
    if '\\' in class_name:
        namespace = '\\'.join(class_name.split('\\')[:-1])
        class_short = class_name.split('\\')[-1]
        stub = f"namespace {namespace};\n"
    else:
        class_short = class_name
        stub = ""
    
    stub += f"class {class_short} {{\n"
    stub += f"    /**\n"
    stub += f"     * @psalm-taint-sink html $value\n"
    stub += f"     */\n"
    stub += f"    public function {method_name}(string $name, string $value, ...): self {{}}\n"
    stub += f"}}\n\n"
    
    return stub

def generate_cors_stub(class_name: str, method_name: str) -> str:
    """Generate stub for CORS-related methods."""
    if '\\' in class_name:
        namespace = '\\'.join(class_name.split('\\')[:-1])
        class_short = class_name.split('\\')[-1]
        stub = f"namespace {namespace};\n"
    else:
        class_short = class_name
        stub = ""
    
    stub += f"class {class_short} {{\n"
    stub += f"    /**\n"
    stub += f"     * @psalm-taint-sink html $value\n"
    stub += f"     */\n"
    stub += f"    public function {method_name}(string $name, string $value, ...): self {{}}\n"
    stub += f"}}\n\n"
    
    return stub

def generate_cookie_stub(class_name: str, method_name: str) -> str:
    """Generate stub for cookie domain methods."""
    if '\\' in class_name:
        namespace = '\\'.join(class_name.split('\\')[:-1])
        class_short = class_name.split('\\')[-1]
        stub = f"namespace {namespace};\n"
    else:
        class_short = class_name
        stub = ""
    
    stub += f"class {class_short} {{\n"
    stub += f"    /**\n"
    stub += f"     * @psalm-taint-sink html $domain\n"
    stub += f"     */\n"
    stub += f"    public function {method_name}(string $domain, ...): self {{}}\n"
    stub += f"}}\n\n"
    
    return stub

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 gen_temp_sinks_stub.py <candidate_sinks.csv>", file=sys.stderr)
        sys.exit(1)
    
    csv_path = sys.argv[1]
    
    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            candidates = list(reader)
    except FileNotFoundError:
        print(f"Error: {csv_path} not found", file=sys.stderr)
        sys.exit(1)
    
    stub_content = generate_psalm_stub(candidates)
    print(stub_content)

if __name__ == "__main__":
    main()
