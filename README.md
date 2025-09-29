# HNP (Host Header Poisoning) Sink Discovery and Verification System

这是一个两阶段的sink发现和验证系统，用于自动发现PHP框架中可能导致Host Header Poisoning攻击的API。

## 系统架构

### 阶段1：发现模式 (Discovery Mode)
使用Semgrep的语义谓词规则来发现候选sink，不依赖具体的API名称白名单。

### 阶段2：验证模式 (Verification Mode)  
使用Psalm的taint分析来验证候选sink，确认它们是否真的构成安全风险。

## 环境要求

- **PHP**: 8.3.x LTS
- **Psalm**: 5.24.x (需要PHP ≥ 8.1)
- **Semgrep**: 1.82.x
- **Python**: 3.11.x

## 安装和配置

### 1. 安装依赖

```bash
# PHP 8.3 (已安装)
/usr/local/php8.3/bin/php --version

# Psalm 5.24 (已安装)
/home/rui/.config/composer/vendor/bin/psalm --version

# Semgrep 1.138.0 (已安装)
semgrep --version

# Python 3.11 (已安装)
python3.11 --version
```

### 2. 设置环境变量

```bash
export PATH="/usr/local/php8.3/bin:$PATH"
```

## 使用方法

### 运行完整的发现→验证流程

```bash
./run_discovery_verification.sh
```

这个脚本会：
1. 运行Semgrep发现规则
2. 提取候选sink
3. 生成临时Psalm stub
4. 运行Psalm taint分析
5. 更新sink注册表

### 手动运行各个阶段

#### 阶段1：发现
```bash
# 运行Semgrep发现规则
semgrep --config rules/discovery --json -o out/discover.json frameworks/

# 提取候选sink
python3 scripts/extract_candidates.py out/discover.json > out/candidate_sinks.csv

# 生成临时Psalm stub
python3 scripts/gen_temp_sinks_stub.py out/candidate_sinks.csv > rules/psalm-stubs/temp_sinks.phpstub
```

#### 阶段2：验证
```bash
# 运行Psalm taint分析
psalm --taint-analysis --output-format=json --report=out/psalm_verify.json $(cat out/candidates.txt)

# 更新注册表
python3 scripts/update_registry.py out/psalm_verify.json registry/hnp-sinks.yml
```

## 文件结构

```
HNP_PHP/
├── rules/
│   ├── discovery/           # Semgrep发现规则
│   │   ├── redirect-like.yml
│   │   ├── cors-like.yml
│   │   ├── cookie-domain-like.yml
│   │   └── absurl-outbound.yml
│   └── psalm-stubs/         # Psalm stub文件
│       └── temp_sinks.phpstub
├── scripts/                 # Python处理脚本
│   ├── extract_candidates.py
│   ├── gen_temp_sinks_stub.py
│   ├── update_registry.py
│   └── filter_candidates.py
├── out/                     # 输出文件
│   ├── discover.json
│   ├── candidate_sinks.csv
│   ├── psalm_verify.json
│   └── candidates.txt
├── registry/                # 注册表
│   └── hnp-sinks.yml
├── frameworks/              # 要分析的PHP框架代码
├── psalm.xml               # Psalm配置
└── run_discovery_verification.sh
```

## 发现规则说明

### 1. 重定向类 (redirect-like.yml)
发现写入Location头或返回3xx状态码的代码：
- `$RESP->withHeader('Location', $value)`
- `$OBJ->headers['Location'] = $value`
- 返回3xx状态码且设置了Location头

### 2. CORS类 (cors-like.yml)
发现写入Access-Control-Allow-Origin头的代码：
- `$RESP->withHeader('Access-Control-Allow-Origin', $value)`
- `$HEADERS['Access-Control-Allow-Origin'] = $value`

### 3. Cookie域类 (cookie-domain-like.yml)
发现设置cookie domain的代码：
- `setcookie(..., ['domain' => $value])`
- `$COOKIE->setDomain($value)`

### 4. 绝对URL类 (absurl-outbound.yml)
发现构造绝对URL的代码：
- `$url = $scheme . "://" . $host . $path`
- `$url = sprintf("%s://%s%s", $scheme, $host, $path)`

## 评分系统

候选sink会根据以下标准评分：
- +3：写入Location头或设置3xx+Location
- +2：方法名匹配`(with|set|add).*Header|Redirect|.*Domain`
- +1：参数名匹配`$domain|$origin|$location|$url`
- +2：类型实现`Psr\Http\Message\ResponseInterface`
- -2：仅在测试/示例代码中
- -1：仅用于日志/调试

## 输出文件

### discover.json
Semgrep的原始发现结果，包含所有匹配的代码位置。

### candidate_sinks.csv
提取的候选sink列表，包含评分和元数据。

### psalm_verify.json
Psalm的taint分析结果，确认哪些候选sink是真正的安全风险。

### hnp-sinks.yml
最终的sink注册表，包含已验证的sink及其元数据。

## 扩展和定制

### 添加新的发现规则
1. 在`rules/discovery/`中创建新的YAML文件
2. 定义语义谓词模式
3. 更新评分逻辑（在`extract_candidates.py`中）

### 添加新的sink类型
1. 更新`gen_temp_sinks_stub.py`中的stub生成逻辑
2. 更新`update_registry.py`中的注册表结构
3. 在`hnp-sinks.yml`中添加新的sink类型

## 注意事项

1. 确保`frameworks/`目录包含要分析的PHP框架代码
2. 首次运行可能需要较长时间，特别是对于大型框架
3. 系统会自动过滤低分候选sink以减少噪声
4. 建议定期运行以发现新添加的框架或API

## 故障排除

### Semgrep错误
- 检查规则文件语法
- 确保目标目录存在且包含PHP文件

### Psalm错误
- 检查PHP版本（需要8.1+）
- 确保stub文件语法正确
- 检查psalm.xml配置

### Python脚本错误
- 检查输入文件是否存在
- 确保CSV格式正确
- 检查YAML文件语法

## 贡献

欢迎提交新的发现规则、改进评分算法或优化验证流程。
