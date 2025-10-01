#!/usr/bin/env python3
"""
Generate temporary Psalm sink stubs from candidate sinks.
"""
import csv
import sys
import re
from typing import List, Dict, Any

def generate_psalm_stub(candidates: List[Dict[str, Any]]) -> str:
    """Generate Psalm stub content for candidate sinks.
    Policy change: treat ALL candidate function calls as sinks.
    If class_name present => method sink; otherwise => global function sink.
    Unknown params => mark first three params ($a,$b,$c) as taint-sink.
    """
    stub_content = "<?php\n"
    stub_content += "// Auto-generated temporary sink stubs\n"
    stub_content += "// Generated from candidate sink discovery\n\n"
    
    # Group candidates by class/method for deduplication
    seen_signatures = set()
    
    for candidate in candidates:
        try:
            method_name = (candidate.get('method_name') or '').strip()
            class_name = (candidate.get('class_name') or '').strip()
            func_name = (candidate.get('function_name') or '').strip()
        except Exception:
            continue

        # Prefer function_name when class is empty
        if class_name and method_name:
            signature = f"{class_name}::{method_name}"
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            stub_content += generate_generic_method_sink(class_name, method_name)
        elif func_name:
            signature = func_name
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            stub_content += generate_generic_function_sink(func_name)
        elif method_name:  # method without class (fallback to global func)
            signature = method_name
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            stub_content += generate_generic_function_sink(method_name)
    
    # Always append framework-specific critical sinks (Laravel/Symfony)
    stub_content += generate_fixed_framework_sinks()
    return stub_content

def generate_redirect_stub(class_name: str, method_name: str) -> str:
    """(Deprecated) Kept for compatibility; not used after policy change."""
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
    """(Deprecated) Kept for compatibility; not used after policy change."""
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
    """(Deprecated) Kept for compatibility; not used after policy change."""
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

def generate_generic_method_sink(class_name: str, method_name: str) -> str:
    if '\\' in class_name:
        namespace = '\\'.join(class_name.split('\\')[:-1])
        class_short = class_name.split('\\')[-1]
        stub = f"namespace {namespace};\n"
    else:
        class_short = class_name
        stub = ""

    stub += f"class {class_short} {{\n"
    stub += f"    /**\n"
    stub += f"     * @psalm-taint-sink html $a\n"
    stub += f"     * @psalm-taint-sink html $b\n"
    stub += f"     * @psalm-taint-sink html $c\n"
    stub += f"     */\n"
    stub += f"    public function {method_name}($a = null, $b = null, $c = null) {{}}\n"
    stub += f"}}\n\n"
    return stub

def generate_generic_function_sink(function_name: str) -> str:
    stub = ""
    # global namespace function
    stub += f"/**\n"
    stub += f" * @psalm-taint-sink html $a\n"
    stub += f" * @psalm-taint-sink html $b\n"
    stub += f" * @psalm-taint-sink html $c\n"
    stub += f" */\n"
    stub += f"function {function_name}($a = null, $b = null, $c = null) {{}}\n\n"
    return stub

def generate_fixed_framework_sinks() -> str:
    """Append explicit sinks for Laravel/Symfony redirect/url APIs and header()."""
    parts: List[str] = []
    # Illuminate\\Http\\Response::header
    parts.append("namespace Illuminate\\Http;\n")
    parts.append("class Response {\n")
    parts.append("    /**\n")
    parts.append("     * @psalm-taint-sink html $name\n")
    parts.append("     * @psalm-taint-sink html $value\n")
    parts.append("     */\n")
    parts.append("    public function header($name = null, $value = null, $replace = true) {}\n")
    parts.append("}\n\n")

    # Symfony\\Component\\HttpFoundation\\RedirectResponse::__construct
    parts.append("namespace Symfony\\Component\\HttpFoundation;\n")
    parts.append("class RedirectResponse {\n")
    parts.append("    /**\n")
    parts.append("     * @psalm-taint-sink html $url\n")
    parts.append("     */\n")
    parts.append("    public function __construct($url = '', $status = 302, $headers = []) {}\n")
    parts.append("}\n\n")

    # Illuminate Routing UrlGenerator and Redirector
    parts.append("namespace Illuminate\\Routing;\n")
    parts.append("class UrlGenerator {\n")
    parts.append("    /** @psalm-taint-sink html $a */ public function to($a = null, $b = null, $c = null) {}\n")
    parts.append("    /** @psalm-taint-sink html $a */ public function route($a = null, $b = null, $c = null) {}\n")
    parts.append("    /** @psalm-taint-sink html $a */ public function action($a = null, $b = null, $c = null) {}\n")
    parts.append("}\n\n")
    parts.append("class Redirector {\n")
    parts.append("    /** @psalm-taint-sink html $a */ public function to($a = null, $b = null, $c = null) {}\n")
    parts.append("    /** @psalm-taint-sink html $a */ public function route($a = null, $b = null, $c = null) {}\n")
    parts.append("    /** @psalm-taint-sink html $a */ public function action($a = null, $b = null, $c = null) {}\n")
    parts.append("}\n\n")

    # Global header() sink
    parts.append("namespace {\n")
    parts.append("/**\n")
    parts.append(" * @psalm-taint-sink html $a\n")
    parts.append(" * @psalm-taint-sink html $b\n")
    parts.append(" */\n")
    parts.append("function header($a = null, $b = null, $c = null) {}\n")
    parts.append("}\n\n")

    return "".join(parts)

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
