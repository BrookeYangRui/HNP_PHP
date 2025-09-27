# YII Framework HNP Risk Report

## 🚨 Risk Overview

- **Total Taint Flows**: 1329
- **Total API Count**: 228
- **Risky APIs**: 213
  - 🔴 High Risk APIs: 10
  - 🟡 Medium Risk APIs: 5
- **Framework Category**: 多个高风险API

---

## ⚠️ APIs with HNP Risk (Unprotected)

### get() - 🟡 Medium Risk API
- **Usage Count**: 51
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Response.php, framework/web/UrlManager.php

### createUrl() - 🔴 High Risk API
- **Usage Count**: 37
- **Risk Scenario**: URL generation - host header influences generated URLs
- **Sample Files**: framework/web/UrlManager.php

### elseif() - 🟡 Medium Risk API
- **Usage Count**: 29
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Response.php

### to() - 🔴 High Risk API
- **Usage Count**: 26
- **Risk Scenario**: URL generation - host header influences generated URLs
- **Sample Files**: framework/web/Response.php

### substr() - 🟡 Medium Risk API
- **Usage Count**: 22
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/UrlManager.php

### toRoute() - 🔴 High Risk API
- **Usage Count**: 22
- **Risk Scenario**: URL generation - host header influences generated URLs
- **Sample Files**: framework/web/UrlManager.php

### has() - 🟡 Medium Risk API
- **Usage Count**: 22
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Request.php

### set() - 🟡 Medium Risk API
- **Usage Count**: 20
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Response.php

### InvalidConfigException() - 🟡 Medium Risk API
- **Usage Count**: 18
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Response.php

### createObject() - 🟡 Medium Risk API
- **Usage Count**: 18
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Response.php, framework/web/UrlManager.php

### stdout() - 🟡 Medium Risk API
- **Usage Count**: 14
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/console/controllers/ServeController.php

### send() - 🟡 Medium Risk API
- **Usage Count**: 14
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Response.php

### is_array() - 🟡 Medium Risk API
- **Usage Count**: 14
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Response.php

### str_replace() - 🟡 Medium Risk API
- **Usage Count**: 11
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Response.php

### strncmp() - 🟡 Medium Risk API
- **Usage Count**: 11
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Response.php, framework/web/UrlManager.php

### createAbsoluteUrl() - 🔴 High Risk API
- **Usage Count**: 11
- **Risk Scenario**: URL generation - host header influences generated URLs
- **Sample Files**: framework/web/UrlManager.php

### in_array() - 🟡 Medium Risk API
- **Usage Count**: 10
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Response.php

### add() - 🟡 Medium Risk API
- **Usage Count**: 10
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/Request.php, framework/web/Response.php

### parseRequest() - 🟡 Medium Risk API
- **Usage Count**: 9
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/web/UrlManager.php

### ensureScheme() - 🟡 Medium Risk API
- **Usage Count**: 9
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: framework/helpers/BaseUrl.php, framework/web/UrlManager.php

## 🛡️ Protection Recommendations

### Required Protection Measures:
1. **Trusted Proxy Configuration**: Configure framework's trusted proxy settings
2. **Host Validation**: Validate Host header against allowed list
3. **URL Generation Protection**: Use absolute URLs instead of relative URLs

### Configuration Examples:
```php
// YII
// Configure appropriate trusted proxy and host validation based on framework type
```

---
*Report Generated: 2025-09-27 19:16:14*
