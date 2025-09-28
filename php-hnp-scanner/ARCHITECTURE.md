# HNP Scanner Architecture Documentation

## 📁 Project Structure

```
php-hnp-scanner/
├── ARCHITECTURE.md
├── README.md
├── bin/
│   └── hnp-scan.php           # Main entry point
├── rules/
│   └── hnp.json               # HNP detection rules configuration
└── src/
    ├── autoload.php           # Autoloader
    ├── Scanner.php            # Main controller
    ├── Frontend/
    │   ├── CompleteTokenizer.php      # Complete lexical analyzer
    │   └── CompleteAstBuilder.php     # Complete AST builder
    ├── Analysis/
    │   └── CompleteTaintEngine.php    # Complete taint analysis engine
    ├── Rules/
    │   └── RuleLoader.php             # Rule loader
    └── Report/
        ├── JsonWriter.php             # JSON report generator
        └── MarkdownWriter.php         # Markdown report generator
```

## 🔧 Core Components

### 1. Scanner.php - Main Controller

**Responsibilities**:
- Coordinate the entire scanning process
- Manage file discovery and AST building
- Call taint analysis engine
- Generate final reports

**Key Methods**:
- `run()` - Execute complete scanning workflow
- `discoverFiles()` - Discover PHP files
- `buildAsts()` - Build ASTs
- `performTaintAnalysis()` - Execute taint analysis
- `generateReports()` - Generate reports

### 2. CompleteTokenizer.php - Lexical Analyzer

**Responsibilities**:
- Lexical analysis based on PHP built-in `token_get_all()`
- Provide token stream navigation and query functionality
- Support position tracking and type checking

**Key Methods**:
- `tokenize()` - Perform lexical analysis on files
- `getCurrentToken()` - Get current token
- `advance()` - Advance to next token
- `isTokenType()` - Check token type
- `findTokens()` - Find specific token types

### 3. CompleteAstBuilder.php - AST Builder

**Responsibilities**:
- Build complete abstract syntax trees
- Support complex PHP syntax structures
- Identify functions, classes, variables, calls, etc.

**Key Methods**:
- `build()` - Build AST
- `parseFunction()` - Parse function definitions
- `parseVariable()` - Parse variables and assignments
- `parseFunctionCall()` - Parse function calls
- `parseConcatenation()` - Parse string concatenations

**AST Structure**:
```php
[
    'file' => 'file.php',
    'functions' => [...],
    'classes' => [...],
    'variables' => [...],
    'assignments' => [...],
    'calls' => [...],
    'concatenations' => [...],
    'expressions' => [...],
    'statements' => [...]
]
```

### 4. CompleteTaintEngine.php - Taint Analysis Engine

**Responsibilities**:
- Execute true taint tracking analysis
- Build data flow graphs and call graphs
- Implement inter-procedural analysis
- Detect taint sources, propagation, and sinks

**Key Methods**:
- `analyze()` - Execute complete taint analysis
- `identifySources()` - Identify taint sources
- `performTaintPropagation()` - Execute taint propagation
- `detectSinks()` - Detect taint sinks
- `performInterproceduralAnalysis()` - Inter-procedural analysis

**Taint Tracking Algorithm**:
1. Build data flow graph
2. Identify taint sources
3. Execute taint propagation
4. Iterate propagation until convergence
5. Detect taint sinks
6. Inter-procedural analysis

### 5. RuleLoader.php - Rule Loader

**Responsibilities**:
- Load and parse rule configuration files
- Support JSON and YAML formats
- Provide rule validation functionality

**Key Methods**:
- `load()` - Load rule files
- `parseYaml()` - Parse YAML format
- Automatic file format detection

### 6. Report Generators

#### JsonWriter.php
- Generate structured JSON reports
- Include complete taint tracking information
- Support machine-readable format

#### MarkdownWriter.php
- Generate human-readable Markdown reports
- Include detailed fix recommendations
- Support code highlighting and formatting

## 🔄 Data Flow

```
PHP Files → Lexical Analysis → AST Building → Taint Analysis → Report Generation
   ↓           ↓               ↓              ↓               ↓
File Discovery → Token Stream → Syntax Tree → Taint Graph → JSON/MD
```

## 🎯 Taint Tracking Model

### Taint Sources
- Server variables: `$_SERVER['HTTP_HOST']`
- Framework methods: `$request->getHost()`
- Header helpers: `getallheaders()['Host']`

### Taint Propagation
- Assignment propagation: `$host = $_SERVER['HTTP_HOST']`
- Function call propagation: `$url = buildUrl($host)`
- String concatenation propagation: `$fullUrl = 'https://' . $host`

### Taint Sinks
- Redirects: `header('Location: ' . $url)`
- CORS: `header('Access-Control-Allow-Origin: ' . $host)`
- Cookies: `setcookie('name', 'value', 0, '/', $host)`

### Sanitizers
- Whitelist validation: `in_array($host, $allowedHosts, true)`
- Domain validation: `filter_var($host, FILTER_VALIDATE_DOMAIN)`
- Normalization: `strtolower(trim($host, '.'))`

## 🚀 Performance Optimization

### Algorithm Optimization
- Incremental analysis: Only analyze changed files
- Smart caching: Cache AST and taint information
- Parallel processing: Multi-file parallel analysis

### Memory Optimization
- Streaming processing: Avoid loading all files at once
- Garbage collection: Timely release of unnecessary data
- Data structure optimization: Use efficient data structures

## 🔧 Extension Points

### Adding New Taint Source Types
1. Define new `kind` in rule files
2. Add identification logic in `CompleteTaintEngine`
3. Update report generators

### Adding New Taint Sink Types
1. Define new `sink` in rule files
2. Add detection logic in `CompleteTaintEngine`
3. Define corresponding security states and severity levels

### Adding New Sanitizer Types
1. Define new `sanitizer` in rule files
2. Add identification logic in `CompleteTaintEngine`
3. Implement sanitization effect evaluation

## 🧪 Testing Strategy

### Unit Testing
- Independent functionality testing for each component
- Boundary condition and error handling testing
- Performance and memory usage testing

### Integration Testing
- Complete scanning workflow testing
- Different rule configuration testing
- Various PHP syntax structure testing

### Real Project Testing
- Open source PHP project testing
- Compatibility testing across different frameworks
- Large-scale project performance testing

## 📊 Quality Metrics

- **Code Coverage**: >90%
- **Performance Benchmark**: 1000 files/minute
- **Memory Usage**: <100MB
- **Accuracy**: >95%
- **False Positive Rate**: <5%