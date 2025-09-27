# PHP Framework HNP Risk Analysis Summary

## 📊 Overall Analysis Results

| Framework | Total Taint Flows | Total APIs | Risky APIs | High Risk | Medium Risk | Category |
|-----------|------------------|------------|------------|-----------|-------------|----------|
| **WordPress** | 2,685 | 256 | 256 | 239 | 14 | 🔴 **大量高风险API** |
| **Symfony** | 1,867 | 182 | 178 | 1 | 2 | 🟡 **主要测试相关** |
| **CodeIgniter** | 681 | 146 | 133 | 7 | 2 | 🔴 **多个高风险API** |
| **CakePHP** | 168 | 45 | 43 | 1 | 1 | 🟡 **少量高风险API** |
| **Laravel** | 74 | 31 | 17 | 0 | 1 | 🟢 **无高风险API** |
| **Yii** | 1,329 | 228 | 213 | 10 | 5 | 🔴 **多个高风险API** |

---

## 📋 Framework Categories

### 🔴 **大量高风险API - WordPress**
- **256 risky APIs** out of 256 total APIs (100% risk rate)
- **239 high-risk APIs** including URL generation functions
- **Key Risk APIs**: `esc_url`, `home_url`, `admin_url`, `wp_login_url`
- **Characteristics**: 几乎所有API都有高风险，URL生成功能大量存在

### 🔴 **多个高风险API - CodeIgniter**
- **133 risky APIs** out of 146 total APIs (91% risk rate)
- **7 high-risk APIs** including URL generation and routing
- **Key Risk APIs**: `buildReverseRoute`, `parse_url`, `route`, `redirect`
- **Characteristics**: 多个核心功能存在高风险API

### 🔴 **多个高风险API - Yii**
- **213 risky APIs** out of 228 total APIs (93% risk rate)
- **10 high-risk APIs** including URL generation and routing
- **Key Risk APIs**: `createUrl`, `getHostInfo`, `getHostName`, `redirect`
- **Characteristics**: 多个核心功能存在高风险API

### 🟡 **主要测试相关 - Symfony**
- **178 risky APIs** out of 182 total APIs (98% risk rate)
- **1 high-risk API** (mainly test-related)
- **Key Risk APIs**: `assertEquals`, `set`, `get`
- **Characteristics**: 主要是测试框架，生产环境风险有限

### 🟡 **少量高风险API - CakePHP**
- **43 risky APIs** out of 45 total APIs (96% risk rate)
- **1 high-risk API** for URL generation
- **Key Risk APIs**: `fullBaseUrl`, `getHost`
- **Characteristics**: 只有少量高风险API，主要是URL生成相关

### 🟢 **无高风险API - Laravel**
- **17 risky APIs** out of 31 total APIs (55% risk rate)
- **0 high-risk APIs**
- **Key Risk APIs**: `varyHeader`, `get`, `matchToKeys`
- **Characteristics**: 没有高风险API，主要是CORS和路由相关

---

## 🛡️ Protection Recommendations

### Framework-Specific Recommendations:
1. **WordPress**: 需要立即配置可信代理和主机验证（大量高风险API）
2. **CodeIgniter**: 需要实现URL生成保护和可信代理设置（多个高风险API）
3. **Yii**: 需要配置URL生成保护和可信代理设置（多个高风险API）
4. **Symfony**: 主要检查测试框架配置（主要测试相关）
5. **CakePHP**: 需要配置URL生成保护（少量高风险API）
6. **Laravel**: 主要检查CORS中间件配置（无高风险API）

### General Protection Measures:
- Configure trusted proxy settings
- Validate Host headers against allowed lists
- Use absolute URLs instead of relative URLs
- Implement proper redirect validation
- Review and secure URL generation functions

---

## 📈 Analysis Statistics

- **Total Frameworks Analyzed**: 6
- **Total Taint Flows Detected**: 6,804
- **Total APIs Analyzed**: 888
- **Total Risky APIs**: 840 (95% risk rate)
- **Total High-Risk APIs**: 258
- **Total Medium-Risk APIs**: 25

---

*Report Generated: 2025-09-27 18:50:00*
*Analysis Tool: HNP PHP Analysis System v1.0*
