# PHP Web框架HNP扫描功能

## 概述

本扫描器现在支持对主流PHP Web框架进行专门的HNP（Host Name Pollution）漏洞检测，包括：

- **Laravel** - 检测url()、asset()、redirect()等helper函数
- **Symfony** - 检测UrlGenerator、RedirectResponse等组件
- **WordPress** - 检测home_url()、site_url()、wp_redirect()等函数
- **CodeIgniter** - 检测base_url()、site_url()、redirect()等函数
- **CakePHP** - 检测Url::build()、redirect()等函数
- **Yii2** - 检测Url::to()、redirect()等函数

## 新增功能

### 1. 框架检测器 (`framework_detector.py`)
- 自动识别项目使用的PHP框架
- 分析框架配置文件
- 评估HNP风险等级
- 提供安全建议

### 2. 框架特定规则 (`rules/php-frameworks-hnp.yml`)
- 针对不同框架的专门扫描规则
- 检测框架特定的HNP漏洞模式
- 更精确的漏洞识别

### 3. 增强的CLI工具 (`cli/framework_scan.py`)
- 框架感知的扫描功能
- 详细的扫描报告
- 支持JSON和文本输出格式

## 使用方法

### 框架扫描CLI工具

```bash
cd /home/rui/HNP_PHP/php-hnp-scanner-pro
source .venv/bin/activate

# 扫描单个项目
python cli/framework_scan.py /path/to/php/project

# 输出JSON格式
python cli/framework_scan.py /path/to/php/project --output json

# 保存结果到文件
python cli/framework_scan.py /path/to/php/project --save report.json
```

### 批量扫描（已集成框架检测）

```bash
cd /home/rui/HNP_PHP/php-hnp-scanner-pro
source .venv/bin/activate
python hnp_scanner.py
```

### 单独使用框架检测器

```bash
cd /home/rui/HNP_PHP/php-hnp-scanner-pro
source .venv/bin/activate
python framework_detector.py /path/to/php/project
```

## 检测的框架模式

### Laravel
- `url()` helper函数
- `asset()` helper函数
- `redirect()` 函数
- `route()` helper函数

### Symfony
- `$this->generateUrl()`
- `$urlGenerator->generate()`
- `new RedirectResponse()`
- `$request->getHost()`

### WordPress
- `home_url()` 函数
- `get_home_url()` 函数
- `site_url()` 函数
- `get_site_url()` 函数
- `wp_redirect()` 函数

### CodeIgniter
- `base_url()` 函数
- `site_url()` 函数
- `redirect()` 函数

### CakePHP
- `Url::build()` 方法
- `$this->Url->build()` 方法
- `$this->redirect()` 方法

### Yii2
- `Url::to()` 方法
- `$this->url()` 方法
- `$this->redirect()` 方法

## 风险等级评估

扫描器会根据框架配置自动评估HNP风险等级：

- **LOW** - 已正确配置信任的主机/代理
- **MEDIUM** - 部分配置缺失
- **HIGH** - 缺少关键安全配置
- **CRITICAL** - 存在严重安全风险

## 安全建议

扫描器会根据检测结果提供具体的安全建议：

### Laravel
- 在`.env`文件中配置`APP_URL`
- 正确配置`TrustProxies`中间件
- 避免信任所有代理（`$proxies = '*'`）

### Symfony
- 配置`trusted_hosts`
- 正确设置代理信任配置

### WordPress
- 在`wp-config.php`中定义`WP_HOME`和`WP_SITEURL`常量

### CodeIgniter
- 在配置文件中设置`base_url`

### CakePHP
- 配置`App.fullBaseUrl`

### Yii2
- 在配置中设置`baseUrl`

## 输出示例

```
🔍 扫描项目: /path/to/project
正在检测框架...
检测到框架: laravel
风险等级: HIGH
使用框架特定规则: rules/php-frameworks-hnp.yml
正在执行HNP扫描...
✅ 扫描完成，发现 3 个HNP问题

=== HNP扫描报告 ===
项目路径: /path/to/project
框架: laravel
风险等级: HIGH
发现数量: 3
使用规则: rules/php-frameworks-hnp.yml

=== 框架信息 ===
配置文件: .env, TrustProxies.php

=== 建议 ===
- 建议在.env中配置APP_URL
- TrustProxies配置为信任所有代理，存在严重安全风险

=== 发现的问题 ===
1. Laravel HNP - url() helper without pinned base URL
   文件: app/Http/Controllers/AuthController.php
   行号: 45
   代码: $url = url('/dashboard');

2. Laravel HNP - redirect() without pinned base URL
   文件: app/Http/Controllers/AuthController.php
   行号: 52
   代码: return redirect('/login');
```

## 注意事项

1. 框架检测基于项目结构和配置文件的存在
2. 某些框架可能有多种检测模式
3. 建议结合手动代码审查验证扫描结果
4. 定期更新扫描规则以支持新版本的框架
