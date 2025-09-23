from pathlib import Path
import re, yaml

def collect_context(project: Path) -> dict:
    ctx = {"pinned_base_url": None, "trusted_proxies": None, "trusted_hosts": None, "proxy_host_trusted": False, "proxy_proto_trusted": False}
    fw = project / "config" / "packages" / "framework.yaml"
    if fw.exists():
        txt = fw.read_text(encoding="utf-8", errors="ignore")
        try:
            data = yaml.safe_load(txt)
        except Exception:
            data = {}
        router = (data or {}).get("framework", {}).get("router", {})
        if isinstance(router, dict) and router.get("default_uri"):
            ctx["pinned_base_url"] = router["default_uri"]
        # fallback regex when yaml parse not reliable
        if not ctx["pinned_base_url"]:
            m = re.search(r"default_uri:\s*([^\s#]+)", txt)
            if m:
                ctx["pinned_base_url"] = m.group(1)

        tp = (data or {}).get("framework", {}).get("trusted_proxies")
        if not tp and "trusted_proxies:" in txt:
            tp = True
        if tp:
            if re.search(r"trusted_proxies:\s*['\"]?\*['\"]?|0\.0\.0\.0/0", txt):
                ctx["trusted_proxies"] = "ALL (DANGER)"
            else:
                ctx["trusted_proxies"] = "configured"

        th = (data or {}).get("framework", {}).get("trusted_hosts")
        if not th and "trusted_hosts:" in txt:
            th = True
        if th:
            if re.search(r"trusted_hosts:\s*\[\s*['\"]\.\*['\"]", txt):
                ctx["trusted_hosts"] = "wildcard (DANGER)"
            else:
                ctx["trusted_hosts"] = "configured"

        headers = (data or {}).get("framework", {}).get("trusted_headers")
        if headers:
            val = str(headers).lower()
            if "x-forwarded-host" in val: ctx["proxy_host_trusted"] = True
            if "x-forwarded-proto" in val: ctx["proxy_proto_trusted"] = True
        else:
            if re.search(r"trusted_headers:.*x-forwarded-host", txt, flags=re.I|re.S):
                ctx["proxy_host_trusted"] = True
            if re.search(r"trusted_headers:.*x-forwarded-proto", txt, flags=re.I|re.S):
                ctx["proxy_proto_trusted"] = True
    return ctx
