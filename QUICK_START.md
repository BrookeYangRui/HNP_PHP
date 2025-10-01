# 🚀 快速开始 - 交互式HNP分析器

## 📋 运行指令

### 1. 首次使用 - 设置框架
```bash
cd /home/rui/HNP_PHP
./setup_frameworks.sh
```

### 2. 启动交互式分析器
```bash
./run_interactive.sh
```

### 3. 选择要分析的框架
```
============================================================
🔍 HNP Framework Analyzer - Interactive Mode
============================================================
Select a framework to analyze:

  1. Laravel - Laravel Framework [✅ Available]
  2. Symfony - Symfony Framework [✅ Available]
  3. WordPress - WordPress CMS [✅ Available]
  4. CodeIgniter - CodeIgniter Framework [✅ Available]
  5. CakePHP - CakePHP Framework [✅ Available]
  6. Yii2 - Yii2 Framework [✅ Available]
  7. All Frameworks - Analyze all available frameworks [✅ Available]

  0. Exit
============================================================

Enter your choice (0-7): 1
```

### 4. 等待分析完成
系统会自动执行6个阶段：
- 🔍 Phase 1: Semgrep Discovery
- 📊 Phase 2: Extract Candidates  
- 🔧 Phase 3: Generate Psalm Stubs
- 🔬 Phase 4: Psalm Analysis
- 📋 Phase 5: Generate Detailed CSV
- 📈 Phase 6: Generate Summary

### 5. 查看结果
分析完成后，在 `results/{framework}/` 目录下会生成：

#### CSV报告（详细）
- `detailed_report.csv` - 包含所有API问题、taint流、分类信息

#### JSON报告（详细）
- `discovery.json` - Semgrep发现结果
- `psalm_analysis.json` - Psalm taint分析结果  
- `summary.json` - 分析总结

## 🎯 结果解读

### CSV报告列说明
- **Framework**: 框架名称
- **API Type**: API类型（重定向、CORS、Cookie等）
- **Severity**: Semgrep严重程度（ERROR/WARNING/INFO）
- **Taint Flow**: 完整的taint流路径
- **Psalm Confirmed**: 是否被Psalm确认（真正的安全风险）

### 分类说明
- **API Type**: 按功能分类（重定向、CORS、Cookie、URL构造等）
- **Severity**: Semgrep原始严重程度
- **Psalm Confirmed**: 是否被Psalm taint分析确认

## 🔧 快速命令

### 直接分析特定框架
```bash
python3 interactive_analyzer.py --framework 1  # Laravel
python3 interactive_analyzer.py --framework 2  # Symfony
python3 interactive_analyzer.py --framework 3  # WordPress
python3 interactive_analyzer.py --framework 4  # CodeIgniter
python3 interactive_analyzer.py --framework 5  # CakePHP
python3 interactive_analyzer.py --framework 6  # Yii2
```

### 查看结果
```bash
# 查看CSV报告
cat results/laravel/detailed_report.csv

# 查看JSON总结
cat results/laravel/summary.json | jq .

# 查看Psalm分析结果
cat results/laravel/psalm_analysis.json | jq .
```

### 环境检查
```bash
# 检查环境
./run_interactive.sh  # 会自动检查环境

# 手动检查
php --version
psalm --version
semgrep --version
```

## 📊 输出示例

### 分析结果摘要
```
============================================================
📊 ANALYSIS RESULTS FOR LARAVEL
============================================================
Total Issues Found: 15
Psalm Confirmed Issues: 3

Severity Distribution:
  - ERROR: 8
  - WARNING: 5
  - INFO: 2

API Types Found:
  - Redirect/Location Header: 8
  - CORS Header: 4
  - Cookie Domain: 2
  - URL Construction: 1

Files Analyzed:
  - frameworks/laravel/src/Illuminate/Http/Response.php
  - frameworks/laravel/src/Illuminate/Routing/Redirector.php
  - frameworks/laravel/src/Illuminate/Http/Middleware/HandleCors.php
  - frameworks/laravel/src/Illuminate/Cookie/CookieJar.php
  - frameworks/laravel/src/Illuminate/Support/Facades/URL.php

Detailed Reports:
  - CSV Report: results/laravel/detailed_report.csv
  - JSON Report: results/laravel/discovery.json
  - JSON Report: results/laravel/psalm_analysis.json
============================================================
```

## 🎓 学术使用

生成的CSV和JSON报告可以直接用于：
- 学术论文的数据分析
- 安全研究报告
- 框架安全评估
- HNP漏洞研究

## 📞 故障排除

### 常见问题
1. **框架未找到**: 运行 `./setup_frameworks.sh` 下载框架
2. **环境问题**: 检查PHP 8.3、Psalm、Semgrep是否安装
3. **分析失败**: 清理 `results/` 目录重新运行

### 清理重试
```bash
rm -rf results/*
./run_interactive.sh
```

## 🎉 开始分析

现在你可以开始分析PHP框架的HNP漏洞了！

```bash
cd /home/rui/HNP_PHP
./run_interactive.sh
```

选择框架，等待分析完成，查看详细的CSV和JSON报告！
