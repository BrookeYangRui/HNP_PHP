from pathlib import Path

def collect_context(project: Path) -> dict:
    ctx = {"pinned_base_url": None, "trusted_proxies": None, "trusted_hosts": None, "proxy_host_trusted": False, "proxy_proto_trusted": False}
    web = project / "config" / "web.php"
    if web.exists():
        txt = web.read_text(encoding="utf-8", errors="ignore")
        if "urlManager" in txt and "hostInfo" in txt:
            ctx["pinned_base_url"] = "urlManager.hostInfo"
    return ctx
