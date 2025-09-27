#!/usr/bin/env python3
"""
External Taint Adapter (Plan C): Integrate Semgrep/Psalm/CodeQL and normalize flows

Behavior
- Prefer Semgrep taint (fast to set up); optionally use Psalm taint if config exists
- Normalize results into flows/sources/sinks compatible with our reports
- Graceful error messages if tools are missing; no internal heuristic scanning here

Notes
- This adapter does not ship rulepacks; it expects environment to provide configs
- For Semgrep you can pass custom configs via SEMGREP_RULES env or project files
"""
import json
import os
import shlex
import subprocess
from typing import Dict, Any, List
import re
import yaml
import sys
import time


def _run_cmd(cmd: List[str], cwd: str, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)


def _semgrep_available() -> bool:
    try:
        subprocess.run(["semgrep", "--version"], check=True, capture_output=True)
        return True
    except Exception:
        return False


def _psalm_available() -> bool:
    try:
        subprocess.run(["vendor/bin/psalm", "-v"], check=True, capture_output=True)
        return True
    except Exception:
        return False


def _normalize_semgrep(json_data: Dict[str, Any], project_root: str) -> Dict[str, Any]:
    flows: List[Dict[str, Any]] = []
    sources: List[Dict[str, Any]] = []
    sinks: List[Dict[str, Any]] = []

    for res in json_data.get("results", []):
        check_id = res.get("check_id", "")
        path = res.get("path", "")
        start = res.get("start", {})
        line = start.get("line", 1)
        message = res.get("message", "")

        # Open result: sources and sinks are both potential flows
        if "source" in check_id.lower():
            # This is a source
            sources.append({"type": "host_name", "file": os.path.relpath(path, project_root), "line": line})
            # Create flow from this source to any potential sink
            flows.append({
                "source_type": "host_name",
                "sink_type": "open_sink",  # Generic sink type for open analysis
                "path": [os.path.relpath(path, project_root)],
                "has_guard": False,
                "has_validation": False,
                "message": message,
            })
        else:
            # This is a potential sink (open result)
            sink_type = "open_sink"
            sinks.append({"type": sink_type, "file": os.path.relpath(path, project_root), "line": line})
            # Create flow from unknown source to this sink
            flows.append({
                "source_type": "host_name",  # Assume host header source
                "sink_type": sink_type,
                "path": [os.path.relpath(path, project_root)],
                "has_guard": False,
                "has_validation": False,
                "message": message,
            })

    flows_by_sink: Dict[str, List[Dict[str, Any]]] = {}
    for f in flows:
        st = f.get("sink_type", "unknown")
        flows_by_sink.setdefault(st, []).append(f)

    return {
        "flows": flows,
        "sources": sources,
        "sinks": sinks,
        "flows_by_sink": flows_by_sink,
    }


def _normalize_psalm(json_data: Dict[str, Any], project_root: str) -> Dict[str, Any]:
    flows: List[Dict[str, Any]] = []
    sources: List[Dict[str, Any]] = []
    sinks: List[Dict[str, Any]] = []

    # Psalm JSON format varies; we look for taint traces in data[issues]
    for issue in json_data.get("issues", []):
        file_name = issue.get("file_name") or issue.get("file_path") or ""
        snippet = (issue.get("message") or "").lower()
        line = issue.get("line_from") or 1
        if not file_name:
            continue
        if "redirect" in snippet:
            sink_type = "redirect"
        elif "render" in snippet or "template" in snippet or "twig" in snippet or "blade" in snippet:
            sink_type = "template_render"
        elif "url" in snippet or "route" in snippet:
            sink_type = "url_generation"
        else:
            sink_type = "unknown"
        sinks.append({"type": sink_type, "file": os.path.relpath(file_name, project_root), "line": line})
        flows.append({
            "source_type": "unknown",
            "sink_type": sink_type,
            "path": [os.path.relpath(file_name, project_root)],
            "has_guard": False,
            "has_validation": False,
        })

    flows_by_sink: Dict[str, List[Dict[str, Any]]] = {}
    for f in flows:
        st = f.get("sink_type", "unknown")
        flows_by_sink.setdefault(st, []).append(f)

    return {
        "flows": flows,
        "sources": sources,
        "sinks": sinks,
        "flows_by_sink": flows_by_sink,
    }


def _load_fw_meta() -> Dict[str, Any]:
    root = os.path.dirname(os.path.dirname(__file__))
    cfg = os.path.join(root, "config", "framework_config.yaml")
    if not os.path.exists(cfg):
        return {}
    try:
        with open(cfg, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _detect_repo_guard(framework_name: str, project_root: str, fw_meta: Dict[str, Any]) -> bool:
    # 1) config_paths existence as guard proxy
    try:
        meta_fw = fw_meta.get("frameworks", {}).get(framework_name, {})
        validations = meta_fw.get("validations", [])
        for v in validations:
            for cpath in v.get("config_paths", []):
                if "*" in cpath:
                    base = cpath.split("*")[0].rstrip("/")
                    dirpath = os.path.join(project_root, os.path.dirname(base))
                    if os.path.isdir(dirpath):
                        return True
                else:
                    if os.path.exists(os.path.join(project_root, cpath)):
                        return True
    except Exception:
        pass

    # 2) generic guard API patterns in repo
    guard_patterns = [
        r"trusted[_-]?proxies",
        r"trusted[_-]?hosts",
        r"forceRootUrl",
        r"setTrustedProxies",
        r"setTrustedHosts",
        r"baseUrl",
        r"hostInfo",
        r"FILTER_VALIDATE_DOMAIN",
        r"preg_match\s*\(.*(allowed|trusted).*host",
    ]
    try:
        rx = re.compile("|".join(guard_patterns), re.IGNORECASE)
        for dirpath, dirnames, filenames in os.walk(project_root):
            dirnames[:] = [d for d in dirnames if d not in [".git", "vendor", "node_modules"]]
            for fn in filenames:
                if not fn.endswith((".php", ".yaml", ".yml", ".php.dist")):
                    continue
                fpath = os.path.join(dirpath, fn)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        if rx.search(f.read()):
                            return True
                except Exception:
                    continue
    except Exception:
        pass
    return False


def _annotate_flows_with_sources_and_guards(framework_name: str, project_root: str, normalized: Dict[str, Any]) -> Dict[str, Any]:
    fw_meta = _load_fw_meta()
    repo_has_guard = _detect_repo_guard(framework_name, project_root, fw_meta)

    # Source annotation: mark as host_name if framework declares sources
    if fw_meta.get("frameworks", {}).get(framework_name, {}).get("sources"):
        for f in normalized.get("flows", []):
            if f.get("source_type") == "unknown":
                f["source_type"] = "host_name"

    # Validation near sink: quick proximity scan
    nearby_patterns = re.compile(r"(trusted|validate|FILTER_VALIDATE|forceRootUrl|setTrusted|hostInfo|baseUrl)", re.IGNORECASE)
    for f in normalized.get("flows", []):
        # repo-level guard
        if repo_has_guard:
            f["has_guard"] = True
        # file-level validation hint
        try:
            sink_file = f.get("path", [None])[0]
            if sink_file:
                abs_path = os.path.join(project_root, sink_file)
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as h:
                    lines = h.read().splitlines()
                # naive: search whole file
                text = "\n".join(lines)
                if nearby_patterns.search(text):
                    f["has_validation"] = True
        except Exception:
            continue

    # rebuild flows_by_sink
    flows_by_sink: Dict[str, List[Dict[str, Any]]] = {}
    for f in normalized.get("flows", []):
        st = f.get("sink_type", "unknown")
        flows_by_sink.setdefault(st, []).append(f)
    normalized["flows_by_sink"] = flows_by_sink
    return normalized


def _semgrep_scan(framework_root: str) -> Dict[str, Any]:
    """Try semgrep with local rules first, then auto."""
    local_rule = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "semgrep_hnp.yaml")
    if os.path.exists(local_rule):
        cmd = ["semgrep", "--config", local_rule, "--quiet", "--json"]
        proc = _run_cmd(cmd, cwd=framework_root)
        if proc.returncode == 0:
            try:
                data = json.loads(proc.stdout or "{}")
                return _normalize_semgrep(data, framework_root)
            except json.JSONDecodeError:
                return {"error": "Semgrep returned non-JSON output"}
    # fallback to auto
    cmd = ["semgrep", "--config", "auto", "--quiet", "--json"]
    proc = _run_cmd(cmd, cwd=framework_root)
    if proc.returncode == 0:
        try:
            data = json.loads(proc.stdout or "{}")
            return _normalize_semgrep(data, framework_root)
        except json.JSONDecodeError:
            return {"error": "Semgrep returned non-JSON output"}
    return {"error": f"Semgrep failed: code {proc.returncode}"}


def run_framework_scan(framework_root: str, framework_name: str) -> Dict[str, Any]:
    """Open-only mode for frameworks: any function/method call is a potential sink.

    This aligns with research/exploration needs: discover extra functions beyond curated lists.
    """
    return run_framework_open_scan(framework_root, framework_name)


def run_framework_open_scan(framework_root: str, framework_name: str) -> Dict[str, Any]:
    """Open-mode: build complete flows from sources to API sinks, one flow per source-sink path."""
    fw_meta = _load_fw_meta()
    meta_fw = fw_meta.get("frameworks", {}).get(framework_name, {})
    source_patterns = []
    for s in meta_fw.get("sources", []):
        for p in s.get("patterns", []):
            try:
                source_patterns.append(re.compile(re.escape(p.replace("(", "").rstrip("(")), re.IGNORECASE))
            except re.error:
                continue

    if not source_patterns:
        # Comprehensive host indicators based on framework analysis
        source_patterns = [
            # PHP global variables
            re.compile(r"HTTP_HOST|SERVER_NAME", re.IGNORECASE),
            
            # Symfony/Laravel Request methods
            re.compile(r"getHost\s*\(", re.IGNORECASE),
            re.compile(r"getHttpHost\s*\(", re.IGNORECASE),
            re.compile(r"getServerName\s*\(", re.IGNORECASE),
            re.compile(r"getSchemeAndHttpHost\s*\(", re.IGNORECASE),
            re.compile(r"getUri\s*\(", re.IGNORECASE),
            re.compile(r"getRequestUri\s*\(", re.IGNORECASE),
            
            # Symfony RequestContext
            re.compile(r"RequestContext.*getHost", re.IGNORECASE),
            re.compile(r"getHost.*RequestContext", re.IGNORECASE),
            
            # URL Generation methods
            re.compile(r"UrlGenerator.*generate", re.IGNORECASE),
            re.compile(r"generate.*UrlGenerator", re.IGNORECASE),
            re.compile(r"Router.*generate", re.IGNORECASE),
            re.compile(r"generate.*Router", re.IGNORECASE),
            
            # Redirect and Response methods
            re.compile(r"RedirectResponse", re.IGNORECASE),
            re.compile(r"redirect.*Response", re.IGNORECASE),
            
            # Proxy headers
            re.compile(r"X-Forwarded-Host", re.IGNORECASE),
            re.compile(r"FORWARDED_HOST", re.IGNORECASE),
            re.compile(r"getTrustedProxies", re.IGNORECASE),
            re.compile(r"setTrustedProxies", re.IGNORECASE),
            
            # Laravel specific
            re.compile(r"fullUrl\s*\(", re.IGNORECASE),
            re.compile(r"url\s*\(", re.IGNORECASE),
            re.compile(r"route\s*\(", re.IGNORECASE),
            re.compile(r"action\s*\(", re.IGNORECASE),
            
            # CodeIgniter specific
            re.compile(r"get_server\s*\(", re.IGNORECASE),
            re.compile(r"server\s*\(", re.IGNORECASE),
            re.compile(r"input\s*\(.*server", re.IGNORECASE),
            re.compile(r"getServer\s*\(", re.IGNORECASE),
            re.compile(r"service\s*\(.*request.*getServer", re.IGNORECASE),
            re.compile(r"getServer\s*\(.*HTTP_HOST", re.IGNORECASE),
            
            # CakePHP specific
            re.compile(r"getHost\s*\(", re.IGNORECASE),
            re.compile(r"host\s*\(", re.IGNORECASE),
            re.compile(r"env\s*\(.*HTTP_HOST", re.IGNORECASE),
            
            # Yii specific
            re.compile(r"getHostInfo\s*\(", re.IGNORECASE),
            re.compile(r"getHostName\s*\(", re.IGNORECASE),
            re.compile(r"getServerName\s*\(", re.IGNORECASE),
            re.compile(r"getServerPort\s*\(", re.IGNORECASE),
            
            # WordPress specific
            re.compile(r"wp_guess_url\s*\(", re.IGNORECASE),
            re.compile(r"get_site_url\s*\(", re.IGNORECASE),
            re.compile(r"get_home_url\s*\(", re.IGNORECASE),
            re.compile(r"site_url\s*\(", re.IGNORECASE),
            re.compile(r"home_url\s*\(", re.IGNORECASE),
            re.compile(r"wp_login_url\s*\(", re.IGNORECASE),
            re.compile(r"wp_lostpassword_url\s*\(", re.IGNORECASE),
            re.compile(r"wp_registration_url\s*\(", re.IGNORECASE),
            re.compile(r"wp_logout_url\s*\(", re.IGNORECASE),
            re.compile(r"wp_mail\s*\(", re.IGNORECASE),
            re.compile(r"wp_safe_redirect\s*\(", re.IGNORECASE),
            re.compile(r"network_site_url\s*\(", re.IGNORECASE),
            re.compile(r"wp_validate_redirect\s*\(", re.IGNORECASE),
            re.compile(r"allowed_redirect_hosts", re.IGNORECASE),
            
            # Generic URL generation patterns
            re.compile(r"generateUrl\s*\(", re.IGNORECASE),
            re.compile(r"buildUrl\s*\(", re.IGNORECASE),
            re.compile(r"createUrl\s*\(", re.IGNORECASE),
            re.compile(r"makeUrl\s*\(", re.IGNORECASE),
            re.compile(r"constructUrl\s*\(", re.IGNORECASE),
            
            # Generic redirect patterns
            re.compile(r"redirect\s*\(", re.IGNORECASE),
            re.compile(r"forward\s*\(", re.IGNORECASE),
            re.compile(r"goto\s*\(", re.IGNORECASE),
            re.compile(r"location\s*:", re.IGNORECASE),
            
            # Generic mail/notification patterns
            re.compile(r"sendMail\s*\(", re.IGNORECASE),
            re.compile(r"mail\s*\(", re.IGNORECASE),
            re.compile(r"sendEmail\s*\(", re.IGNORECASE),
            re.compile(r"notify\s*\(", re.IGNORECASE),
            re.compile(r"notification\s*\(", re.IGNORECASE),
            
            # Generic configuration patterns
            re.compile(r"getConfig\s*\(", re.IGNORECASE),
            re.compile(r"getSetting\s*\(", re.IGNORECASE),
            re.compile(r"getOption\s*\(", re.IGNORECASE),
            re.compile(r"getParameter\s*\(", re.IGNORECASE),
        ]

    call_patterns = [
        re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(") ,
        re.compile(r"->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(") ,
        re.compile(r"::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(") ,
    ]

    # Collect target files first for progress
    target_files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(framework_root):
        # Skip common non-source directories
        dirnames[:] = [d for d in dirnames if d not in [".git", "vendor", "node_modules", "tests", "test", "spec", "docs", "documentation"]]
        
        # Include all PHP files in framework root and common source directories
        if (framework_root in dirpath or 
            any(core in dirpath for core in ["src/", "app/", "config/", "system/", "application/", "lib/", "library/", "core/", "framework/", "includes/", "wp-includes/", "wp-admin/"])):
            for fn in filenames:
                if fn.endswith((".php", ".blade.php", ".phtml")):
                    target_files.append(os.path.join(dirpath, fn))

    total = len(target_files)
    processed = 0
    last_print = 0.0
    repo_has_source = False
    

    # Build complete flows: source -> [intermediate calls] -> API sink
    complete_flows: List[Dict[str, Any]] = []
    api_sinks: List[Dict[str, Any]] = []
    all_sources: List[Dict[str, Any]] = []

    for fpath in target_files:
        processed += 1
        now = time.time()
        if now - last_print > 0.1:
            pct = (processed / total * 100.0) if total else 100.0
            sys.stdout.write(f"\r[Open Scan] {processed}/{total} ({pct:5.1f}%) : {os.path.relpath(fpath, framework_root):.120}")
            sys.stdout.flush()
            last_print = now

        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        rel = os.path.relpath(fpath, framework_root)
        lines = content.splitlines()
        
        # Check if file contains sources
        has_source = any(rx.search(content) for rx in source_patterns)
        if has_source:
            repo_has_source = True
            # Find the actual line with the source
            source_line = 1
            for i, line in enumerate(lines, start=1):
                if any(rx.search(line) for rx in source_patterns):
                    source_line = i
                    break
            all_sources.append({
                "type": "host_name",
                "file": rel,
                "line": source_line,
            })

        # Extract all function calls in this file
        file_calls = []
        for i, line in enumerate(lines, start=1):
            for rx in call_patterns:
                for m in rx.finditer(line):
                    callee = m.group(1)
                    file_calls.append({
                        "symbol": callee,
                        "line": i,
                        "file": rel
                    })

        # If file has sources, create flows to ALL function calls in this file (open mode)
        if has_source and file_calls:
            # No filtering - all calls are potential sinks in open mode
            for call in file_calls:
                # Skip obvious internal/private methods but keep everything else
                if not _is_obviously_internal(call["symbol"]):
                    api_sinks.append({
                        "type": "open_sink",
                        "file": call["file"],
                        "line": call["line"],
                        "symbol": call["symbol"]
                    })

                    complete_flows.append({
                        "source_type": "host_name",
                        "sink_type": "open_sink",
                        "source_file": rel,
                        "sink_file": call["file"],
                        "sink_line": call["line"],
                        "sink_symbol": call["symbol"],
                        "flow_path": [rel],  # Simplified: source file -> sink file
                        "has_guard": False,
                        "has_validation": False,
                    })

    # finalize progress line
    sys.stdout.write("\n")
    sys.stdout.flush()

    if not repo_has_source:
        return {"error": "No host sources detected; open-mode produced no flows"}

    # Get unique symbols and filter for developer APIs only
    all_symbols = sorted({s.get("symbol") for s in api_sinks if s.get("symbol")})
    developer_apis = _filter_developer_apis(all_symbols, framework_name)
    
    # Analyze impact for developer APIs only
    api_impact_analysis = _analyze_api_impact(developer_apis, framework_name)
    
    return {
        "framework": framework_name,
        "total_flows": len(complete_flows),
        "total_sources": len(all_sources),
        "total_sinks": len(api_sinks),
        "unique_symbols": developer_apis,
        "api_impact_analysis": api_impact_analysis,
        "flows": complete_flows,
        "sources": all_sources,
        "sinks": api_sinks,  # Keep sinks for compatibility
    }


def _is_obviously_internal(symbol: str) -> bool:
    """Check if a symbol is obviously internal (very basic filtering only)."""
    # Only exclude the most obvious internal patterns
    obvious_internal = [
        r'^__',  # Magic methods
        r'^set[A-Z]', r'^get[A-Z]', r'^is[A-Z]', r'^has[A-Z]',  # Basic getters/setters
        r'Test$', r'Mock$', r'Stub$', r'Fake$',  # Test utilities
        r'^serialize', r'^unserialize',  # Serialization
    ]
    
    return any(re.search(pattern, symbol, re.IGNORECASE) for pattern in obvious_internal)


def _is_developer_api(symbol: str, framework_name: str) -> bool:
    """Check if a symbol is a developer-facing API that could cause HNP issues."""
    # Exclude basic PHP functions and internal framework functions
    exclude_patterns = [
        r'^_', r'^__',  # Private methods
        r'^if$', r'^else$', r'^for$', r'^while$', r'^foreach$',  # Control flow
        r'^array$', r'^count$', r'^strlen$', r'^strpos$', r'^str_starts_with$',  # Basic PHP
        r'^isset$', r'^empty$', r'^is_null$', r'^is_ssl$',  # PHP checks
        r'^add_filter$', r'^add_action$', r'^apply_filters$',  # WordPress hooks
        r'^WP_Error$', r'^is_wp_error$',  # WordPress error handling
        r'^force_ssl_admin$', r'^set_url_scheme$',  # Internal functions
        r'^login_header$',  # WordPress internal
    ]
    
    # Check exclusions first
    if any(re.search(pattern, symbol, re.IGNORECASE) for pattern in exclude_patterns):
        return False
    
    # HNP-risk developer APIs
    hnp_risk_patterns = [
        # High HNP risk - URL generation
        r'url$', r'route$', r'redirect$', r'link$', r'to$', r'generate$',
        # WordPress specific URL functions
        r'^wp_.*_url$', r'^get_.*_url$', r'^site_url$', r'^home_url$',
        # High HNP risk - Authentication
        r'^wp_login$', r'^wp_logout$', r'^login$', r'^logout$', r'^auth$',
        # High HNP risk - Redirects
        r'^wp_safe_redirect$', r'^redirect$', r'^forward$',
        # Medium HNP risk - Email/notifications
        r'^wp_mail$', r'^mail$', r'^send.*mail$', r'^notify$',
        # Medium HNP risk - Response headers
        r'^header$', r'^cookie$', r'^setcookie$', r'^response$',
        # Medium HNP risk - Template rendering
        r'^view$', r'^render$', r'^template$', r'^blade$', r'^twig$',
        # Medium HNP risk - API responses
        r'^json$', r'^api$', r'^toJson$',
    ]
    
    return any(re.search(pattern, symbol, re.IGNORECASE) for pattern in hnp_risk_patterns)


def _filter_developer_apis(symbols: List[str], framework_name: str) -> List[str]:
    """Filter symbols to only include developer-facing APIs that could cause HNP issues."""
    # Exclude basic PHP functions and internal framework functions
    exclude_patterns = [
        # Basic PHP functions
        r'^if$', r'^else$', r'^for$', r'^while$', r'^foreach$', r'^elseif$',
        r'^array$', r'^count$', r'^strlen$', r'^strpos$', r'^str_starts_with$',
        r'^isset$', r'^empty$', r'^is_null$', r'^is_ssl$', r'^sprintf$',
        r'^add$', r'^get_option$', r'^esc_attr$', r'^apply_filters$',
        # Private methods
        r'^_', r'^__',
        # WordPress internal functions
        r'^add_filter$', r'^add_action$', r'^WP_Error$', r'^is_wp_error$',
        r'^force_ssl_admin$', r'^set_url_scheme$', r'^login_header$',
    ]
    
    # Filter symbols using the improved _is_developer_api function
    developer_apis = []
    for symbol in symbols:
        if not any(re.search(pattern, symbol, re.IGNORECASE) for pattern in exclude_patterns):
            if _is_developer_api(symbol, framework_name):
                developer_apis.append(symbol)
    
    return sorted(developer_apis)


def _analyze_api_impact(apis: List[str], framework_name: str) -> Dict[str, Dict[str, Any]]:
    """Analyze potential HNP impact for each developer API."""
    impact_analysis = {}
    
    # Impact categories and their scenarios
    impact_patterns = {
        "url_generation": {
            "patterns": ["url", "route", "link", "href", "to", "generate"],
            "scenario": "URL generation - host header influences generated URLs",
            "examples": ["url()", "route()", "to()", "generate()"]
        },
        "redirect": {
            "patterns": ["redirect", "forward", "goto"],
            "scenario": "Redirects - host header affects redirect destinations",
            "examples": ["redirect()", "redirectToRoute()", "redirectToAction()"]
        },
        "template_render": {
            "patterns": ["view", "render", "template", "blade", "twig"],
            "scenario": "Template rendering - host header influences template output",
            "examples": ["view()", "render()", "renderView()"]
        },
        "response_headers": {
            "patterns": ["header", "cookie", "setcookie", "response"],
            "scenario": "Response headers - host header affects response headers",
            "examples": ["header()", "cookie()", "setcookie()"]
        },
        "email_notification": {
            "patterns": ["mail", "email", "notification", "send"],
            "scenario": "Email/notifications - host header influences email content",
            "examples": ["mail()", "sendMail()", "notification()"]
        },
        "json_response": {
            "patterns": ["json", "api", "response"],
            "scenario": "JSON responses - host header affects API responses",
            "examples": ["json()", "toJson()", "jsonResponse()"]
        },
        "file_download": {
            "patterns": ["download", "file", "stream", "attachment"],
            "scenario": "File operations - host header influences file handling",
            "examples": ["download()", "streamDownload()", "file()"]
        },
        "cache_operations": {
            "patterns": ["cache", "store", "session"],
            "scenario": "Cache/session - host header affects cache behavior",
            "examples": ["cache()", "session()", "store()"]
        }
    }
    
    for api in apis:
        api_lower = api.lower()
        matched_categories = []
        
        for category, info in impact_patterns.items():
            if any(pattern in api_lower for pattern in info["patterns"]):
                matched_categories.append({
                    "category": category,
                    "scenario": info["scenario"],
                    "examples": info["examples"]
                })
        
        if matched_categories:
            impact_analysis[api] = {
                "categories": matched_categories,
                "scenario": matched_categories[0]["scenario"],  # Use first match
                "potential_impact": _get_potential_impact(matched_categories)
            }
        else:
            impact_analysis[api] = {
                "categories": [],
                "scenario": "Unknown impact - requires manual analysis",
                "potential_impact": ["Review API usage for host header dependencies"]
            }
    
    return impact_analysis


def _get_potential_impact(categories: List[Dict[str, Any]]) -> List[str]:
    """Get potential impact scenarios based on categories."""
    impacts = set()
    for category in categories:
        cat = category["category"]
        if cat == "url_generation":
            impacts.update(["URL manipulation", "Cache poisoning"])
        elif cat == "redirect":
            impacts.update(["Redirect manipulation"])
        elif cat == "template_render":
            impacts.update(["Template injection", "Cache poisoning"])
        elif cat == "response_headers":
            impacts.update(["Header manipulation", "Cache poisoning"])
        elif cat == "email_notification":
            impacts.update(["Email content manipulation"])
        elif cat == "json_response":
            impacts.update(["API response manipulation"])
        elif cat == "file_download":
            impacts.update(["File operation manipulation"])
        elif cat == "cache_operations":
            impacts.update(["Cache behavior manipulation"])
    return list(impacts)


def run_app_scan(project_root: str) -> Dict[str, Any]:
    """Run external engines on an application repo and normalize output."""
    # Reuse the same adapters; different roots
    if _semgrep_available():
        cmd = ["semgrep", "--config", "auto", "--quiet", "--json", "--no-rewrite"]
        proc = _run_cmd(cmd, cwd=project_root)
        if proc.returncode == 0:
            try:
                data = json.loads(proc.stdout or "{}")
                return _normalize_semgrep(data, project_root)
            except json.JSONDecodeError:
                return {"error": "Semgrep returned non-JSON output"}

    if _psalm_available():
        cmd = shlex.split("vendor/bin/psalm --taint-analysis --output-format=json --no-progress")
        proc = _run_cmd(cmd, cwd=project_root)
        if proc.returncode == 0:
            try:
                data = json.loads(proc.stdout or "{}")
                return _normalize_psalm(data, project_root)
            except json.JSONDecodeError:
                return {"error": "Psalm returned non-JSON output"}

    return {"error": "No external taint engine available (install Semgrep or Psalm)"}


