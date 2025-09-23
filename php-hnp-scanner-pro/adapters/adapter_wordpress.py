from pathlib import Path
import re

def collect_context(project: Path) -> dict:
    ctx = {"pinned_base_url": None, "trusted_proxies": None, "trusted_hosts": None, "proxy_host_trusted": False, "proxy_proto_trusted": False}
    wp = project / "wp-config.php"
    if wp.exists():
        txt = wp.read_text(encoding="utf-8", errors="ignore")
        if "define('WP_HOME'" in txt or 'define("WP_HOME"' in txt:
            ctx["pinned_base_url"] = "WP_HOME"
        elif "define('WP_SITEURL'" in txt or 'define("WP_SITEURL"' in txt:
            ctx["pinned_base_url"] = "WP_SITEURL"
    # allowed_redirect_hosts filter present?
    any_filter = False
    for f in project.rglob("*.php"):
        try:
            t = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if "allowed_redirect_hosts" in t:
            any_filter = True
            break
    if any_filter:
        ctx["trusted_hosts"] = "allowed_redirect_hosts (custom)"
    return ctx
