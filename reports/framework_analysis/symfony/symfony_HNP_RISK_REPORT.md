# SYMFONY Framework HNP Risk Report

## 🚨 Risk Overview

- **Total Taint Flows**: 1867
- **Total API Count**: 182
- **Risky APIs**: 178
  - 🔴 High Risk APIs: 1
  - 🟡 Medium Risk APIs: 2
- **Framework Category**: 主要测试相关

---

## ⚠️ APIs with HNP Risk (Unprotected)

### assertEquals() - 🟡 Medium Risk API
- **Usage Count**: 648
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### set() - 🟡 Medium Risk API
- **Usage Count**: 214
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### create() - 🟡 Medium Risk API
- **Usage Count**: 122
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### initialize() - 🟡 Medium Risk API
- **Usage Count**: 112
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### assertSame() - 🟡 Medium Risk API
- **Usage Count**: 110
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### Request() - 🟡 Medium Risk API
- **Usage Count**: 90
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### assertFalse() - 🟡 Medium Risk API
- **Usage Count**: 78
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### assertTrue() - 🟡 Medium Risk API
- **Usage Count**: 54
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### all() - 🟡 Medium Risk API
- **Usage Count**: 40
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: RequestMatcher/ExpressionRequestMatcher.php, Tests/RequestTest.php

### get() - 🟡 Medium Risk API
- **Usage Count**: 40
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### duplicate() - 🟡 Medium Risk API
- **Usage Count**: 24
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### assertNull() - 🟡 Medium Risk API
- **Usage Count**: 18
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### expectException() - 🟡 Medium Risk API
- **Usage Count**: 12
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### fromGlobals() - 🟡 Medium Risk API
- **Usage Count**: 10
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### assertInstanceOf() - 🟡 Medium Risk API
- **Usage Count**: 10
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### overrideGlobals() - 🟡 Medium Risk API
- **Usage Count**: 10
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### remove() - 🟡 Medium Risk API
- **Usage Count**: 10
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### toArray() - 🟡 Medium Risk API
- **Usage Count**: 8
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### createFromGlobals() - 🟡 Medium Risk API
- **Usage Count**: 8
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

### assertStringContainsString() - 🟡 Medium Risk API
- **Usage Count**: 8
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: Tests/RequestTest.php

## 🛡️ Protection Recommendations

### Required Protection Measures:
1. **Trusted Proxy Configuration**: Configure framework's trusted proxy settings
2. **Host Validation**: Validate Host header against allowed list
3. **URL Generation Protection**: Use absolute URLs instead of relative URLs

### Configuration Examples:
```php
// SYMFONY
// Configure appropriate trusted proxy and host validation based on framework type
```

---
*Report Generated: 2025-09-27 19:26:20*
