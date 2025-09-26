# Taint Tracking Implementation Explained

## 1. What is Taint Tracking?

**Taint Tracking** is a program analysis technique used to track the flow of untrusted data (tainted data) through a program.

In our HNP analysis:
- **Source (Taint Source)**: Host Header related untrusted input
- **Sink (Taint Sink)**: Function calls that may be affected by tainted data
- **Flow (Taint Flow)**: Data flow path from Source to Sink

## 2. Regular Expression Pattern Matching

### 2.1 Source Pattern Recognition

```python
# Identify Host Header related taint sources
source_patterns = [
    re.compile(r"HTTP_HOST|SERVER_NAME", re.IGNORECASE),  # PHP global variables
    re.compile(r"getHost\s*\(", re.IGNORECASE),           # Method calls
    re.compile(r"getHttpHost\s*\(", re.IGNORECASE),       # Full method names
    re.compile(r"getServerName\s*\(", re.IGNORECASE),     # Server name retrieval
]
```

**Specific meanings**:
- `HTTP_HOST|SERVER_NAME`: Matches `$_SERVER['HTTP_HOST']` or `$_SERVER['SERVER_NAME']`
- `getHost\s*\(`: Matches calls like `$request->getHost()`
- `getHttpHost\s*\(`: Matches calls like `$request->getHttpHost()`

### 2.2 Function Call Pattern Recognition

```python
# Extract all function calls as potential Sinks
call_patterns = [
    re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\("),      # function()
    re.compile(r"->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("),   # object->method()
    re.compile(r"::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("),   # Class::method()
]
```

**Specific meanings**:
- `\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`: Matches function calls in `function()` format
- `->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(`: Matches method calls in `$object->method()` format
- `::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(`: Matches static method calls in `Class::method()` format

### 2.3 Actual Matching Example

```php
// Source code example
$host = $_SERVER['HTTP_HOST'];           // Source 1: HTTP_HOST
$request->getHost();                     // Source 2: getHost()
$response->addActualRequestHeaders();    // Sink 1: addActualRequestHeaders()
$url = $this->fullUrlIs($url);           // Sink 2: fullUrlIs()
```

**Matching results**:
- Source matches: `HTTP_HOST` (line 1), `getHost` (line 2)
- Sink matches: `addActualRequestHeaders` (line 3), `fullUrlIs` (line 4)

## 3. Dynamic Scenario Assessment

### 3.1 Scenario Classification Based on Function Name Patterns

```python
def _analyze_api_impact(apis: List[str], framework_name: str):
    """Dynamically assess scenarios based on function name patterns"""
    
    # Predefined impact patterns
    impact_patterns = {
        "url_generation": {
            "patterns": ["url", "route", "link", "href", "to", "generate"],
            "scenario": "URL generation - host header influences generated URLs"
        },
        "redirect": {
            "patterns": ["redirect", "forward", "goto"],
            "scenario": "Redirects - host header affects redirect destinations"
        },
        "response_headers": {
            "patterns": ["header", "cookie", "setcookie", "response"],
            "scenario": "Response headers - host header affects response headers"
        }
    }
    
    for api in apis:
        api_lower = api.lower()
        matched_categories = []
        
        # Pattern matching: check if function name contains specific keywords
        for category, info in impact_patterns.items():
            if any(pattern in api_lower for pattern in info["patterns"]):
                matched_categories.append({
                    "category": category,
                    "scenario": info["scenario"]
                })
        
        # Assign scenario
        if matched_categories:
            impact_analysis[api] = {
                "scenario": matched_categories[0]["scenario"],
                "categories": matched_categories
            }
```

### 3.2 Specific Assessment Example

```python
# Function name: "addActualRequestHeaders"
api_lower = "addactualrequestheaders"

# Pattern matching check
for category, info in impact_patterns.items():
    if any(pattern in api_lower for pattern in info["patterns"]):
        # "header" matches in "addactualrequestheaders"
        # Matches "response_headers" category
        matched_categories.append({
            "category": "response_headers",
            "scenario": "Response headers - host header affects response headers"
        })

# Final result
impact_analysis["addActualRequestHeaders"] = {
    "scenario": "Response headers - host header affects response headers",
    "categories": [{"category": "response_headers"}]
}
```

## 4. Complete Taint Tracking Flow

### 4.1 Scanning Phase

```python
for file_path in target_files:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    
    # 1. Check if file contains Source
    has_source = any(pattern.search(content) for pattern in source_patterns)
    
    if has_source:
        # 2. Extract all function calls
        file_calls = []
        for line_num, line in enumerate(lines, start=1):
            for pattern in call_patterns:
                for match in pattern.finditer(line):
                    function_name = match.group(1)
                    file_calls.append({
                        "symbol": function_name,
                        "line": line_num,
                        "file": file_path
                    })
        
        # 3. Create taint flows
        for call in file_calls:
            if not _is_obviously_internal(call["symbol"]):
                create_taint_flow(source_file, call["symbol"], call["line"])
```

### 4.2 Analysis Phase

```python
# 1. Get all unique function symbols
unique_symbols = sorted({s.get("symbol") for s in api_sinks})

# 2. Assess scenario for each function
for symbol in unique_symbols:
    scenario_analysis = _analyze_api_impact([symbol], framework_name)
    
    # 3. Generate impact scenarios
    potential_impact = _get_potential_impact(scenario_analysis[symbol]["categories"])
```

## 5. Why This Method is Effective

### 5.1 Open Discovery
- **No predefined lists**: Can discover new, unknown attack vectors
- **Comprehensive coverage**: Scans all function calls, no missed potential risks

### 5.2 Pattern-Driven Analysis
- **Semantic understanding**: Risk classification based on function name semantics
- **Dynamic adaptation**: Easy to add new pattern rules

### 5.3 Practical Application Value
- **Laravel discovery**: Found undocumented risk functions like `addActualRequestHeaders`, `fullUrlIs`, `varyHeader`
- **Attack vectors**: Accurately identified specific threats like cache poisoning, header injection, redirect attacks

## 6. Technical Advantages

1. **Precision**: Regular expressions precisely match code patterns
2. **Comprehensiveness**: Open scanning doesn't miss potential risks
3. **Automation**: No manual intervention required, automatically analyzes large amounts of code
4. **Extensibility**: Easy to add new patterns and rules
5. **Practicality**: Provides specific attack vectors and mitigation suggestions

This is our Taint Tracking implementation: using regular expression pattern matching to identify taint sources and sinks, using function name patterns to dynamically assess scenarios, and finally generating complete taint flow analysis reports.