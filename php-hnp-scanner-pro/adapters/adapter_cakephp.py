from pathlib import Path

def collect_context(project: Path) -> dict:
    ctx = {"pinned_base_url": None, "trusted_proxies": None, "trusted_hosts": None, "proxy_host_trusted": False, "proxy_proto_trusted": False}
    app = project / "config" / "app.php"
    if app.exists():
        txt = app.read_text(encoding="utf-8", errors="ignore")
        if "fullBaseUrl" in txt:
            ctx["pinned_base_url"] = "App.fullBaseUrl"
    return ctx
