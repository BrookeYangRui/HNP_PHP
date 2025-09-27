# WORDPRESS Framework HNP Risk Report

## 🚨 Risk Overview

- **Total Taint Flows**: 62271
- **Total API Count**: 4844
- **Risky APIs**: 4542
  - 🔴 High Risk APIs: 279
  - 🟡 Medium Risk APIs: 113
- **Framework Category**: 大量高风险API

---

## ⚠️ APIs with HNP Risk (Unprotected)

### apply_filters() - 🟡 Medium Risk API
- **Usage Count**: 1395
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-login.php

### sprintf() - 🟡 Medium Risk API
- **Usage Count**: 1182
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-login.php

### elseif() - 🟡 Medium Risk API
- **Usage Count**: 827
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-login.php

### add() - 🟡 Medium Risk API
- **Usage Count**: 690
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-login.php

### get_option() - 🟡 Medium Risk API
- **Usage Count**: 536
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-login.php

### esc_attr() - 🟡 Medium Risk API
- **Usage Count**: 516
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-login.php

### do_action() - 🟡 Medium Risk API
- **Usage Count**: 487
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-login.php

### current_user_can() - 🟡 Medium Risk API
- **Usage Count**: 479
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-signup.php, wp-includes/comment.php

### esc_url() - 🔴 High Risk API
- **Usage Count**: 446
- **Risk Scenario**: URL generation - host header influences generated URLs
- **Sample Files**: wp-login.php

### add_action() - 🟡 Medium Risk API
- **Usage Count**: 425
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-login.php

### in_array() - 🟡 Medium Risk API
- **Usage Count**: 399
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-activate.php, wp-login.php

### prepare() - 🟡 Medium Risk API
- **Usage Count**: 396
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-includes/ms-blogs.php, wp-includes/http.php

### WP_Error() - 🟡 Medium Risk API
- **Usage Count**: 378
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-login.php

### str_replace() - 🟡 Medium Risk API
- **Usage Count**: 366
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-includes/https-migration.php, wp-login.php

### is_array() - 🟡 Medium Risk API
- **Usage Count**: 366
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-signup.php, wp-includes/http.php

### is_wp_error() - 🟡 Medium Risk API
- **Usage Count**: 360
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-login.php

### add_filter() - 🟡 Medium Risk API
- **Usage Count**: 308
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-signup.php, wp-activate.php

### get_post() - 🟡 Medium Risk API
- **Usage Count**: 274
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-includes/ms-blogs.php, wp-includes/comment.php

### unset() - 🟡 Medium Risk API
- **Usage Count**: 253
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-includes/http.php, wp-includes/ms-blogs.php

### query() - 🟡 Medium Risk API
- **Usage Count**: 234
- **Risk Scenario**: Requires manual analysis for specific impact
- **Sample Files**: wp-includes/comment.php

## 🛡️ Protection Recommendations

### Required Protection Measures:
1. **Trusted Proxy Configuration**: Configure framework's trusted proxy settings
2. **Host Validation**: Validate Host header against allowed list
3. **URL Generation Protection**: Use absolute URLs instead of relative URLs

### Configuration Examples:
```php
// WORDPRESS
// Configure appropriate trusted proxy and host validation based on framework type
```

---
*Report Generated: 2025-09-27 19:16:29*
