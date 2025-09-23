from pathlib import Path
import re

def _read_env(p: Path) -> dict:
    env = {}
    try:
        for line in (p / ".env").read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line or line.strip().startswith("#"): continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    except Exception:
        pass
    return env

def collect_context(project: Path) -> dict:
    ctx = {"pinned_base_url": None, "trusted_proxies": None, "trusted_hosts": None, "proxy_host_trusted": False, "proxy_proto_trusted": False}
    env = _read_env(project)
    if "APP_URL" in env and env["APP_URL"]:
        ctx["pinned_base_url"] = env["APP_URL"]

    # URL::forceRootUrl()
    for f in [project / "app" / "Providers", project / "app"]:
        if f.exists():
            for php in f.rglob("*.php"):
                try:
                    txt = php.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                if "URL::forceRootUrl(" in txt:
                    ctx["pinned_base_url"] = "URL::forceRootUrl(...)"

    # TrustProxies heuristics
    trust = project / "app" / "Http" / "Middleware" / "TrustProxies.php"
    if trust.exists():
        txt = trust.read_text(encoding="utf-8", errors="ignore")
        if "protected $proxies = '*'" in txt.replace(" ", ""):
            ctx["trusted_proxies"] = "ALL (DANGER)"
        elif "protected $proxies" in txt:
            ctx["trusted_proxies"] = "custom"
        # headers bitmask checks
        if "HEADER_X_FORWARDED_HOST" in txt:
            ctx["proxy_host_trusted"] = True
        if "HEADER_X_FORWARDED_PROTO" in txt:
            ctx["proxy_proto_trusted"] = True

    # TrustHosts middleware
    trust_hosts = project / "app" / "Http" / "Middleware" / "TrustHosts.php"
    if trust_hosts.exists():
        txt = trust_hosts.read_text(encoding="utf-8", errors="ignore")
        if "return [" in txt and "*" in txt:
            ctx["trusted_hosts"] = "wildcard (DANGER)"
        else:
            ctx["trusted_hosts"] = "configured"
    return ctx
