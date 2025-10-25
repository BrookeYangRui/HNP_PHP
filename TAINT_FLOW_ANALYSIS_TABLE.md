# Taint Flow Analysis Results

Based on actual framework source code Taint Tracking analysis, discovered **70 functions** with **57 developer-usable functions** having HNP risks.

## Analysis Statistics

- **Total Functions**: 70
- **Developer Usable Functions**: 57
- **Analyzed Frameworks**: WordPress, Laravel, Symfony, CodeIgniter, CakePHP, Yii2

## Detailed Analysis Table

| Framework | Typical HNP Sinks (High-Risk Functions/Helpers) | Why Risky (Root Cause) | Fix/Mitigation (Core Approach) |
|-----------|--------------------------------------------------|------------------------|--------------------------------|
| **WordPress** | `remove_query_arg()` / `set_url_scheme()` / `esc_url()` / `wp_redirect()` / `wp_safe_redirect()` / `add_query_arg()` / `home_url()` / `is_ssl()` / `wp_login_form()` / `wp_login_url()` | Unfixed `WP_HOME` & `WP_SITEURL` → base URL from Host; `$_SERVER['HTTP_HOST']` directly used for URL construction; email (password reset) becomes exploitable surface | Fix `WP_HOME/SITEURL` in `wp-config.php`; limit `allowed_redirect_hosts`; proxy header sanitization; validate Host header |
| **Laravel** | `url()` / `getHost()` / `getSchemeAndHttpHost()` / `getScheme()` / `root()` / `fullUrl()` / `redirect()` / `getHttpHost()` / `setPreviousUrl()` | Absolute URL construction trusts `Host` / `X-Forwarded-Host` by default; unfixed `APP_URL` → poisoned; Request object directly exposes Host info | Fix `APP_URL` in `.env`; configure `TrustProxies` correctly; use configured domain for absolute URLs; validate Host header |
| **Symfony** | `getHost()` / `getSchemeAndHttpHost()` / `getScheme()` / `getHostRegex()` / `evaluate()` | RequestContext uses request-derived Host; no trusted proxies/headers set → injection; route matching depends on Host | Set `trusted_proxies` & `trusted_headers`; lock `RequestContext` base domain; validate Host regex |
| **CodeIgniter 4** | `base_url()` / `site_url()` / `current_url()` / `redirect()->to()` | `Config\App::$baseURL` empty → auto-infer from Host; URL generation depends on request Host | Fix `baseURL`; avoid deriving Host from request; limit headers in proxy environment |
| **CakePHP 4** | `Router::url(..., true)` / `$this->Url->build(...['fullBase'=>true])` / `$this->Html->link(...['fullBase'=>true])` / `redirect()` | `fullBase` uses request Host; `App.fullBaseUrl` not set → poisoned | Configure `App.fullBaseUrl`; use configured domain for external links |
| **Yii 2** | `Url::to(..., true)` / `UrlManager::createAbsoluteUrl()` / `Url::home(true)` / `Response::redirect()` / `Request::getHostInfo()` | `trustedHosts` not set → `X-Forwarded-Host` effective; absolute URL concatenation polluted | Configure `request.trustedHosts`; fix domain; base absolute URLs on configuration |

## Key Findings

### 1. Most Dangerous Functions (by instance count)
- **`remove_query_arg`** - 16 flows, 16 developer usable
- **`getHost`** - 13 flows, 13 developer usable  
- **`url`** - 12 flows, 12 developer usable
- **`redirect`** - 9 flows, 9 developer usable
- **`getSchemeAndHttpHost`** - 7 flows, 7 developer usable

### 2. Cross-Framework Common Risks
- **`getHost()`** used in both Laravel and Symfony
- **`getSchemeAndHttpHost()`** used for URL construction in multiple frameworks
- **`url()`** function is a major risk point across multiple frameworks

### 3. WordPress-Specific Risks
- **`remove_query_arg()`** - most frequently used function (16 instances)
- **`set_url_scheme()`** - directly uses `$_SERVER['HTTP_HOST']` for URL construction
- **`esc_url()`** - outputs to HTML, potentially exploitable

## Fix Recommendations

### General Fix Approaches
1. **Fix Base URL** - Set fixed domain in configuration files
2. **Validate Host Header** - Check if Host header is in allowed list
3. **Configure Proxy Trust** - Correctly set trusted proxies and headers
4. **Use Configured Domain** - Use configured domain for absolute URLs instead of request Host

### Framework-Specific Fixes
- **WordPress**: Set `WP_HOME` and `WP_SITEURL`
- **Laravel**: Configure `APP_URL` and `TrustProxies`
- **Symfony**: Set `trusted_proxies` and `trusted_headers`
- **CodeIgniter**: Fix `baseURL` configuration
- **CakePHP**: Set `App.fullBaseUrl`
- **Yii2**: Configure `request.trustedHosts`

## Data Source

This analysis is based on actual Taint Tracking analysis of 6 mainstream PHP framework source codes, using Open Taint Tracking method to trace Host header data flow, discovering 57 developer-usable functions out of 70 functions with HNP risks.

---

*Generated: 2024*  
*Analysis Method: Open Taint Tracking*  
*Analysis Tools: Semgrep + PHP-Parser*
