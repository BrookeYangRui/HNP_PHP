from pathlib import Path

def collect_context(project: Path) -> dict:
    ctx = {"pinned_base_url": None, "trusted_proxies": None, "trusted_hosts": None, "proxy_host_trusted": False, "proxy_proto_trusted": False}
    ci3 = project / "application" / "config" / "config.php"
    ci4 = project / "app" / "Config" / "App.php"
    for f in [ci3, ci4]:
        if f.exists():
            txt = f.read_text(encoding="utf-8", errors="ignore")
            if "base_url" in txt or "$baseURL" in txt:
                ctx["pinned_base_url"] = "base_url"
    return ctx
