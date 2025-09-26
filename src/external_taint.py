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
    """Open-mode fallback: treat any function/method call as potential sink and emit flows from host sources."""
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
        # generic host indicators (more permissive)
        source_patterns = [
            re.compile(r"HTTP_HOST|SERVER_NAME", re.IGNORECASE),
            re.compile(r"getHost\s*\(", re.IGNORECASE),
            re.compile(r"getHttpHost\s*\(", re.IGNORECASE),
            re.compile(r"getServerName\s*\(", re.IGNORECASE),
        ]

    call_patterns = [
        re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(") ,
        re.compile(r"->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(") ,
        re.compile(r"::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(") ,
    ]

    flows: List[Dict[str, Any]] = []
    sources: List[Dict[str, Any]] = []
    sinks: List[Dict[str, Any]] = []

    # Collect target files first for progress (limit to core directories for speed)
    target_files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(framework_root):
        dirnames[:] = [d for d in dirnames if d not in [".git", "vendor", "node_modules", "tests"]]
        # Focus on core framework code only
        if any(core in dirpath for core in ["src/Illuminate", "src/Symfony", "app/", "config/"]) or framework_root in dirpath:
            for fn in filenames:
                if fn.endswith((".php", ".blade.php", ".phtml")):
                    target_files.append(os.path.join(dirpath, fn))

    total = len(target_files)
    processed = 0
    last_print = 0.0
    repo_has_source = False

    for fpath in target_files:
        processed += 1
        # throttle progress output to ~10/s
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

        # detect source presence in repo
        if any(rx.search(content) for rx in source_patterns):
            repo_has_source = True
            sources.append({
                "type": "host_name",
                "file": os.path.relpath(fpath, framework_root),
                "line": 1,
            })

        rel = os.path.relpath(fpath, framework_root)
        lines = content.splitlines()
        for i, line in enumerate(lines, start=1):
            for rx in call_patterns:
                for m in rx.finditer(line):
                    callee = m.group(1)
                    sinks.append({"type": "open_sink", "file": rel, "line": i, "symbol": callee})
                    flows.append({
                        "source_type": "host_name",
                        "sink_type": "open_sink",
                        "path": [rel],
                        "has_guard": False,
                        "has_validation": False,
                        "symbol": callee,
                    })

    # finalize progress line
    sys.stdout.write("\n")
    sys.stdout.flush()

    if not repo_has_source:
        return {"error": "No host sources detected; open-mode produced no flows"}

    # Build unique sink symbols
    unique_symbols = sorted({s.get("symbol") for s in sinks if s.get("symbol")})

    # Filter for developer-facing APIs only
    developer_apis = _filter_developer_apis(unique_symbols, framework_name)
    
    # Diff against known curated APIs if available
    extras: List[str] = []
    try:
        root = os.path.dirname(os.path.dirname(__file__))
        known_file = os.path.join(root, "config", "known_framework_apis.yaml")
        known = {}
        if os.path.exists(known_file):
            with open(known_file, "r", encoding="utf-8") as f:
                known = yaml.safe_load(f) or {}
        known_list = set(known.get("frameworks", {}).get(framework_name, {}).get("known_sinks", []))
        extras = sorted([sym for sym in developer_apis if sym not in known_list])
    except Exception:
        extras = []

    normalized = {
        "flows": flows,
        "sources": sources,
        "sinks": sinks,
        "unique_sink_symbols": unique_symbols,
        "developer_apis": developer_apis,
        "discovered_extra_symbols": extras,
    }
    return _annotate_flows_with_sources_and_guards(framework_name, framework_root, normalized)


def _filter_developer_apis(symbols: List[str], framework_name: str) -> List[str]:
    """Filter symbols to only include developer-facing APIs."""
    # Common internal/private patterns to exclude
    exclude_patterns = [
        # Private/protected methods
        r"^_", r"^__", r"^set[A-Z]", r"^get[A-Z]", r"^is[A-Z]", r"^has[A-Z]",
        # Internal framework methods
        r"^create[A-Z]", r"^build[A-Z]", r"^make[A-Z]", r"^resolve[A-Z]",
        r"^handle[A-Z]", r"^process[A-Z]", r"^execute[A-Z]", r"^run[A-Z]",
        # Test/development utilities
        r"Test$", r"Mock$", r"Stub$", r"Fake$", r"Debug$", r"Log$",
        # Configuration/internal
        r"Config$", r"Service$", r"Provider$", r"Manager$", r"Factory$",
        r"Builder$", r"Compiler$", r"Parser$", r"Validator$", r"Sanitizer$",
        # Low-level operations
        r"^serialize", r"^unserialize", r"^encode", r"^decode",
        r"^hash", r"^encrypt", r"^decrypt", r"^sign", r"^verify",
    ]
    
    # Framework-specific exclusions
    if framework_name.lower() == "laravel":
        exclude_patterns.extend([
            r"^boot", r"^register", r"^bind", r"^singleton", r"^instance",
            r"^resolve", r"^make", r"^create", r"^build", r"^handle",
            r"^dispatch", r"^fire", r"^listen", r"^observe", r"^macro",
        ])
    elif framework_name.lower() == "symfony":
        exclude_patterns.extend([
            r"^configure", r"^load", r"^process", r"^compile", r"^build",
            r"^resolve", r"^create", r"^make", r"^handle", r"^dispatch",
        ])
    
    # Filter symbols
    developer_apis = []
    for symbol in symbols:
        if not any(re.search(pattern, symbol, re.IGNORECASE) for pattern in exclude_patterns):
            # Keep common developer APIs
            if any(pattern in symbol.lower() for pattern in [
                "url", "route", "redirect", "view", "render", "response", 
                "json", "xml", "html", "text", "download", "stream",
                "header", "cookie", "session", "cache", "mail", "notification"
            ]):
                developer_apis.append(symbol)
    
    return sorted(developer_apis)


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


