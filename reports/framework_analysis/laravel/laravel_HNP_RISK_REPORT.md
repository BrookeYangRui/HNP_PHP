# LARAVEL Framework HNP Risk Report

## 🚨 Risk Overview

- **Total Taint Flows**: 74
- **Total API Count**: 31
- **Risky APIs**: 17
  - 🔴 High Risk APIs: 0
  - 🟡 Medium Risk APIs: 1
- **Framework Category**: 无高风险API

---

## ⚠️ APIs with HNP Risk (Unprotected)

### get() - 🟡 Medium Risk API
- **Usage Count**: 6
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Http/Middleware/HandleCors.php

### matchToKeys() - 🟡 Medium Risk API
- **Usage Count**: 5
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/RouteParameterBinder.php

### varyHeader() - 🟡 Medium Risk API
- **Usage Count**: 4
- **Risk Scenario**: Response handling - Host header affects response content
- **Sample Files**: src/Illuminate/Http/Middleware/HandleCors.php

### bindPathParameters() - 🟡 Medium Risk API
- **Usage Count**: 3
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/RouteParameterBinder.php

### bindHostParameters() - 🟡 Medium Risk API
- **Usage Count**: 3
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/RouteParameterBinder.php

### replaceDefaults() - 🟡 Medium Risk API
- **Usage Count**: 3
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/RouteParameterBinder.php

### handlePreflightRequest() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Http/Middleware/HandleCors.php

### addActualRequestHeaders() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Response handling - Host header affects response content
- **Sample Files**: src/Illuminate/Http/Middleware/HandleCors.php

### fullUrlIs() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: URL generation/redirect - Host header affects generated URLs
- **Sample Files**: src/Illuminate/Http/Middleware/HandleCors.php

### is() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Http/Middleware/HandleCors.php

### decodedPath() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/RouteParameterBinder.php

### parameterNames() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/RouteParameterBinder.php

### parameters() - 🟡 Medium Risk API
- **Usage Count**: 1
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/RouteParameterBinder.php

### array_merge() - 🟡 Medium Risk API
- **Usage Count**: 1
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/RouteParameterBinder.php

### array_intersect_key() - 🟡 Medium Risk API
- **Usage Count**: 1
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/RouteParameterBinder.php

### array_flip() - 🟡 Medium Risk API
- **Usage Count**: 1
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/RouteParameterBinder.php

### matches() - 🟡 Medium Risk API
- **Usage Count**: 1
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: src/Illuminate/Routing/Matching/HostValidator.php

## 🛡️ Protection Recommendations

### Required Protection Measures:
1. **Trusted Proxy Configuration**: Configure framework's trusted proxy settings
2. **Host Validation**: Validate Host header against allowed list
3. **URL Generation Protection**: Use absolute URLs instead of relative URLs

### Configuration Examples:
```php
// LARAVEL
// Configure appropriate trusted proxy and host validation based on framework type
```

---
*Report Generated: 2025-09-27 19:24:02*
