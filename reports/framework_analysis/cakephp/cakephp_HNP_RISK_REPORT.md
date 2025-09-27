# CAKEPHP Framework HNP Risk Report

## 🚨 Risk Overview

- **Total Taint Flows**: 168
- **Total API Count**: 45
- **Risky APIs**: 43
  - 🔴 High Risk APIs: 1
  - 🟡 Medium Risk APIs: 1
- **Framework Category**: 少量高风险API

---

## ⚠️ APIs with HNP Risk (Unprotected)

### env() - 🟡 Medium Risk API
- **Usage Count**: 20
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### useLocaleParser() - 🟡 Medium Risk API
- **Usage Count**: 17
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### build() - 🟡 Medium Risk API
- **Usage Count**: 16
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### read() - 🟡 Medium Risk API
- **Usage Count**: 14
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### consume() - 🟡 Medium Risk API
- **Usage Count**: 12
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### write() - 🟡 Medium Risk API
- **Usage Count**: 10
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### rules() - 🟡 Medium Risk API
- **Usage Count**: 6
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### load() - 🟡 Medium Risk API
- **Usage Count**: 4
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### register() - 🟡 Medium Risk API
- **Usage Count**: 4
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### check() - 🟡 Medium Risk API
- **Usage Count**: 4
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### addDetector() - 🟡 Medium Risk API
- **Usage Count**: 4
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### CakePHP() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### Copyright() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### file_exists() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### parse() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### putenv() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### toEnv() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### toServer() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### config() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

### unset() - 🟡 Medium Risk API
- **Usage Count**: 2
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: config/bootstrap.php

## 🛡️ Protection Recommendations

### Required Protection Measures:
1. **Trusted Proxy Configuration**: Configure framework's trusted proxy settings
2. **Host Validation**: Validate Host header against allowed list
3. **URL Generation Protection**: Use absolute URLs instead of relative URLs

### Configuration Examples:
```php
// CAKEPHP
// Configure appropriate trusted proxy and host validation based on framework type
```

---
*Report Generated: 2025-09-27 19:29:28*
