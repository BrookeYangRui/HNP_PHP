# HNP Scanner Report

**扫描时间**: 2025-09-28 18:13:38
**总发现数**: 3

## 📊 扫描摘要

### 按严重程度
- 🔴 **高**: 0 个
- 🟡 **中**: 0 个
- 🟢 **低**: 3 个

### 按安全状态
- 🚨 **绝对URL构造不当**: 0 个
- ⚠️ **代理信任错误**: 0 个
- 📝 **旁路使用**: 3 个
- ✅ **安全**: 0 个

### 按规则类型
- **unknown**: 3 个

## 🔍 详细发现

### 🟢 low 严重程度

#### 📁 :

- **规则**: ``
- **状态**: ``
- **严重程度**: ``
- **Sink**: ``

---

#### 📁 :

- **规则**: ``
- **状态**: ``
- **严重程度**: ``
- **Sink**: ``

---

#### 📁 :

- **规则**: ``
- **状态**: ``
- **严重程度**: ``
- **Sink**: ``

---

## 💡 修复建议

### 通用建议
1. **启用严格域名白名单**: 对所有Host使用进行白名单验证
2. **配置可信代理**: 正确设置框架的信任代理列表
3. **使用框架安全方法**: 优先使用框架提供的安全URL构建方法
4. **输入验证**: 对所有用户输入进行严格验证和净化

### 针对发现问题的建议

### 代码示例

```php
// ❌ 不安全的做法
$host = $_SERVER['HTTP_HOST'];
header('Location: https://' . $host . '/redirect');

// ✅ 安全的做法
$allowedHosts = ['example.com', 'www.example.com'];
$host = $_SERVER['HTTP_HOST'];
if (in_array($host, $allowedHosts, true)) {
    header('Location: https://' . $host . '/redirect');
} else {
    header('Location: https://example.com/redirect');
}
```
