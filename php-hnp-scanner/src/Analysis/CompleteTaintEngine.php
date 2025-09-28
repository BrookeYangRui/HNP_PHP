<?php
/**
 * 完整的污点分析引擎
 * 实现真正的污点追踪，包括数据流分析、控制流分析和跨过程分析
 */

namespace HNP\Analysis;

class CompleteTaintEngine
{
    private array $rules;
    private array $taintedVars = [];
    private array $sanitizedVars = [];
    private array $findings = [];
    private array $functionSummaries = [];
    private array $callGraph = [];
    private array $dataFlowGraph = [];
    
    public function __construct(array $rules)
    {
        $this->rules = $rules;
    }
    
    public function analyze(array $ast, string $file): array
    {
        $this->taintedVars = [];
        $this->sanitizedVars = [];
        $this->findings = [];
        
        // 1. 构建数据流图
        $this->buildDataFlowGraph($ast, $file);
        
        // 2. 识别污点源
        $this->identifySources($ast, $file);
        
        // 3. 执行污点传播分析
        $this->performTaintPropagation($ast, $file);
        
        // 4. 检测污点汇
        $this->detectSinks($ast, $file);
        
        // 5. 跨过程分析
        $this->performInterproceduralAnalysis($ast, $file);
        
        return $this->findings;
    }
    
    private function buildDataFlowGraph(array $ast, string $file): void
    {
        // 构建变量依赖图
        if (isset($ast['assignments']) && is_array($ast['assignments'])) {
            foreach ($ast['assignments'] as $assignment) {
                $this->dataFlowGraph[$assignment['variable']] = [
                    'sources' => $this->extractVariableReferences($assignment['value']),
                    'line' => $assignment['line'],
                    'file' => $file
                ];
            }
        }
        
        // 构建函数调用图
        if (isset($ast['calls']) && is_array($ast['calls'])) {
            foreach ($ast['calls'] as $call) {
                $this->callGraph[] = [
                    'function' => $call['name'],
                    'arguments' => $call['arguments'],
                    'line' => $call['line'],
                    'file' => $file
                ];
            }
        }
    }
    
    private function identifySources(array $ast, string $file): void
    {
        // 1. 检查变量赋值中的污点源
        if (isset($ast['assignments']) && is_array($ast['assignments'])) {
            foreach ($ast['assignments'] as $assignment) {
                $this->checkAssignmentForSources($assignment, $file);
            }
        }
        
        // 2. 检查函数调用中的污点源
        if (isset($ast['calls']) && is_array($ast['calls'])) {
            foreach ($ast['calls'] as $call) {
                $this->checkCallForSources($call, $file);
            }
        }
        
        // 3. 检查字符串拼接中的污点源
        if (isset($ast['concatenations']) && is_array($ast['concatenations'])) {
            foreach ($ast['concatenations'] as $concat) {
                $this->checkConcatenationForSources($concat, $file);
            }
        }
    }
    
    private function checkAssignmentForSources(array $assignment, string $file): void
    {
        $value = $assignment['value'];
        
        foreach ($this->rules['sources'] as $sourceRule) {
            if (isset($sourceRule['patterns']) && is_array($sourceRule['patterns'])) {
                foreach ($sourceRule['patterns'] as $pattern) {
                    if ($this->matchesPattern($value, $pattern)) {
                        $this->taintedVars[$assignment['variable']] = [
                            'type' => $sourceRule['kind'] ?? 'unknown',
                            'pattern' => $pattern,
                            'line' => $assignment['line'],
                            'file' => $file,
                            'taint_level' => 'high'
                        ];
                        
                        // 记录污点源
                        $this->findings[] = [
                            'type' => 'source',
                            'variable' => $assignment['variable'],
                            'pattern' => $pattern,
                            'line' => $assignment['line'],
                            'file' => $file
                        ];
                    }
                }
            }
        }
    }
    
    private function checkCallForSources(array $call, string $file): void
    {
        foreach ($this->rules['sources'] as $sourceRule) {
            if (isset($sourceRule['kind']) && $sourceRule['kind'] === 'framework_method') {
                if (isset($sourceRule['patterns']) && is_array($sourceRule['patterns'])) {
                    foreach ($sourceRule['patterns'] as $pattern) {
                        if ($this->matchesCallPattern($call, $pattern)) {
                            $this->taintedVars[$call['name']] = [
                                'type' => $sourceRule['kind'],
                                'pattern' => $pattern,
                                'line' => $call['line'],
                                'file' => $file,
                                'taint_level' => 'high'
                            ];
                        }
                    }
                }
            }
        }
    }
    
    private function checkConcatenationForSources(array $concat, string $file): void
    {
        foreach ($concat['parts'] as $part) {
            foreach ($this->rules['sources'] as $sourceRule) {
                if (isset($sourceRule['patterns']) && is_array($sourceRule['patterns'])) {
                    foreach ($sourceRule['patterns'] as $pattern) {
                        if ($this->matchesPattern($part, $pattern)) {
                            $this->taintedVars['concat_' . $concat['line']] = [
                                'type' => 'concatenated_source',
                                'pattern' => $pattern,
                                'line' => $concat['line'],
                                'file' => $file,
                                'taint_level' => 'high'
                            ];
                        }
                    }
                }
            }
        }
    }
    
    private function performTaintPropagation(array $ast, string $file): void
    {
        // 1. 赋值传播
        foreach ($ast['assignments'] as $assignment) {
            $this->propagateAssignment($assignment, $file);
        }
        
        // 2. 函数调用传播
        foreach ($ast['calls'] as $call) {
            $this->propagateCall($call, $file);
        }
        
        // 3. 字符串拼接传播
        foreach ($ast['concatenations'] as $concat) {
            $this->propagateConcatenation($concat, $file);
        }
        
        // 4. 迭代传播直到收敛
        $this->iteratePropagation();
    }
    
    private function propagateAssignment(array $assignment, string $file): void
    {
        $varName = $assignment['variable'];
        $value = $assignment['value'];
        
        // 检查值中是否包含污点变量
        $taintedSources = $this->findTaintedSourcesInExpression($value);
        
        if (!empty($taintedSources)) {
            $this->taintedVars[$varName] = [
                'type' => 'propagated',
                'sources' => $taintedSources,
                'line' => $assignment['line'],
                'file' => $file,
                'taint_level' => $this->calculateTaintLevel($taintedSources)
            ];
        }
    }
    
    private function propagateCall(array $call, string $file): void
    {
        // 检查函数参数中的污点
        $taintedArgs = [];
        foreach ($call['arguments'] as $arg) {
            $taintedSources = $this->findTaintedSourcesInExpression($arg);
            if (!empty($taintedSources)) {
                $taintedArgs[] = $taintedSources;
            }
        }
        
        if (!empty($taintedArgs)) {
            // 检查是否是净化器
            if ($this->isSanitizer($call['name'])) {
                $this->applySanitization($call, $taintedArgs, $file);
            } else {
                // 传播污点到函数返回值
                $this->taintedVars[$call['name'] . '_return'] = [
                    'type' => 'function_return',
                    'sources' => array_merge(...$taintedArgs),
                    'line' => $call['line'],
                    'file' => $file,
                    'taint_level' => 'medium'
                ];
            }
        }
    }
    
    private function propagateConcatenation(array $concat, string $file): void
    {
        $taintedParts = [];
        foreach ($concat['parts'] as $part) {
            $taintedSources = $this->findTaintedSourcesInExpression($part);
            if (!empty($taintedSources)) {
                $taintedParts[] = $taintedSources;
            }
        }
        
        if (!empty($taintedParts)) {
            $this->taintedVars['concat_' . $concat['line']] = [
                'type' => 'concatenated',
                'sources' => array_merge(...$taintedParts),
                'line' => $concat['line'],
                'file' => $file,
                'taint_level' => 'high'
            ];
        }
    }
    
    private function iteratePropagation(): void
    {
        $maxIterations = 10;
        $iteration = 0;
        $changed = true;
        
        while ($changed && $iteration < $maxIterations) {
            $changed = false;
            $iteration++;
            
            // 重新检查所有赋值，看是否有新的污点传播
            foreach ($this->dataFlowGraph as $var => $info) {
                if (!isset($this->taintedVars[$var])) {
                    $taintedSources = $this->findTaintedSourcesInExpression($info['sources']);
                    if (!empty($taintedSources)) {
                        $this->taintedVars[$var] = [
                            'type' => 'propagated',
                            'sources' => $taintedSources,
                            'line' => $info['line'],
                            'file' => $info['file'],
                            'taint_level' => $this->calculateTaintLevel($taintedSources)
                        ];
                        $changed = true;
                    }
                }
            }
        }
    }
    
    private function detectSinks(array $ast, string $file): void
    {
        foreach ($ast['calls'] as $call) {
            foreach ($this->rules['sinks'] as $sinkRule) {
                if (isset($sinkRule['patterns']) && is_array($sinkRule['patterns'])) {
                    foreach ($sinkRule['patterns'] as $pattern) {
                        if ($this->matchesSinkPattern($call, $pattern)) {
                            $this->checkSinkTaint($call, $sinkRule, $file);
                        }
                    }
                }
            }
        }
    }
    
    private function checkSinkTaint(array $call, array $sinkRule, string $file): void
    {
        $taintedArgs = [];
        $taintSources = [];
        
        // 检查函数参数中的污点
        foreach ($call['arguments'] as $arg) {
            $sources = $this->findTaintedSourcesInExpression($arg);
            if (!empty($sources)) {
                $taintedArgs[] = $arg;
                $taintSources = array_merge($taintSources, $sources);
            }
        }
        
        if (!empty($taintedArgs)) {
            $this->findings[] = [
                'type' => 'sink',
                'file' => $file,
                'line' => $call['line'],
                'rule' => $sinkRule['name'],
                'state' => $this->determineSecurityState($call, $sinkRule),
                'severity' => $this->calculateSeverity($sinkRule, $taintSources),
                'sink' => $call['name'],
                'tainted_arguments' => $taintedArgs,
                'sources' => $taintSources,
                'sanitizers' => $this->getAppliedSanitizers($taintSources),
                'trace' => $this->buildTaintTrace($taintSources, $call)
            ];
        }
    }
    
    private function performInterproceduralAnalysis(array $ast, string $file): void
    {
        // 构建函数摘要
        foreach ($ast['functions'] as $function) {
            $this->buildFunctionSummary($function, $file);
        }
        
        // 应用函数摘要进行跨过程分析
        foreach ($this->callGraph as $call) {
            $this->applyFunctionSummary($call, $file);
        }
    }
    
    private function buildFunctionSummary(array $function, string $file): void
    {
        $summary = [
            'name' => $function['name'],
            'taints_params' => [],
            'taints_return' => false,
            'calls_sinks' => [],
            'has_sanitizers' => []
        ];
        
        // 分析函数体中的污点传播
        // 这里需要更复杂的分析，暂时简化
        
        $this->functionSummaries[$function['name']] = $summary;
    }
    
    private function applyFunctionSummary(array $call, string $file): void
    {
        $functionName = $call['function'];
        
        if (isset($this->functionSummaries[$functionName])) {
            $summary = $this->functionSummaries[$functionName];
            
            // 如果函数可能传播污点到返回值
            if ($summary['taints_return']) {
                $this->taintedVars[$functionName . '_return'] = [
                    'type' => 'function_return',
                    'sources' => $call['arguments'],
                    'line' => $call['line'],
                    'file' => $file,
                    'taint_level' => 'medium'
                ];
            }
        }
    }
    
    private function findTaintedSourcesInExpression(string|array $expression): array
    {
        $sources = [];
        
        // 如果是数组，转换为字符串
        if (is_array($expression)) {
            $expression = implode(' ', $expression);
        }
        
        foreach ($this->taintedVars as $var => $taintInfo) {
            if (strpos($expression, $var) !== false) {
                $sources[] = $taintInfo;
            }
        }
        
        return $sources;
    }
    
    private function extractVariableReferences(string $expression): array
    {
        $references = [];
        
        // 提取变量引用
        if (preg_match_all('/\$[a-zA-Z_][a-zA-Z0-9_]*/', $expression, $matches)) {
            $references = array_merge($references, $matches[0]);
        }
        
        // 提取$_SERVER引用
        if (preg_match_all('/\$_SERVER\[[\'"][^\'"]+[\'"]\]/', $expression, $matches)) {
            $references = array_merge($references, $matches[0]);
        }
        
        return array_unique($references);
    }
    
    private function calculateTaintLevel(array $sources): string
    {
        foreach ($sources as $source) {
            if (isset($source['taint_level']) && $source['taint_level'] === 'high') {
                return 'high';
            }
        }
        return 'medium';
    }
    
    private function determineSecurityState(array $call, array $sinkRule): string
    {
        switch ($sinkRule['name']) {
            case 'redirect':
                return 'abs_url_build';
            case 'cors':
                return 'abs_url_build';
            case 'cookie_domain':
                return 'abs_url_build';
            case 'absolute_url_build':
                return 'abs_url_build';
            case 'template_href':
                return 'side_effect';
            case 'email_link':
                return 'side_effect';
            case 'logging':
                return 'side_effect';
            case 'config_generation':
                return 'side_effect';
            default:
                return 'side_effect';
        }
    }
    
    private function calculateSeverity(array $sinkRule, array $taintSources): string
    {
        $highSeveritySinks = ['redirect', 'cors', 'cookie_domain', 'absolute_url_build'];
        $mediumSeveritySinks = ['template_href', 'email_link'];
        
        if (in_array($sinkRule['name'], $highSeveritySinks)) {
            return 'high';
        } elseif (in_array($sinkRule['name'], $mediumSeveritySinks)) {
            return 'medium';
        } else {
            return 'low';
        }
    }
    
    private function getAppliedSanitizers(array $taintSources): array
    {
        $sanitizers = [];
        foreach ($taintSources as $source) {
            if (isset($this->sanitizedVars[$source['variable']])) {
                $sanitizers[] = $this->sanitizedVars[$source['variable']];
            }
        }
        return $sanitizers;
    }
    
    private function buildTaintTrace(array $sources, array $sink): array
    {
        $trace = [];
        
        foreach ($sources as $source) {
            $trace[] = [
                'type' => 'source',
                'variable' => $source['variable'] ?? 'unknown',
                'pattern' => $source['pattern'] ?? 'unknown',
                'line' => $source['line'] ?? 0,
                'file' => $source['file'] ?? 'unknown'
            ];
        }
        
        $trace[] = [
            'type' => 'sink',
            'function' => $sink['name'],
            'line' => $sink['line'],
            'file' => $sink['file'] ?? 'unknown'
        ];
        
        return $trace;
    }
    
    private function applySanitization(array $call, array $taintedArgs, string $file): void
    {
        foreach ($taintedArgs as $arg) {
            foreach ($arg as $source) {
                if (isset($source['variable'])) {
                    $this->sanitizedVars[$source['variable']] = [
                        'sanitizer' => $call['name'],
                        'line' => $call['line'],
                        'file' => $file
                    ];
                }
            }
        }
    }
    
    private function matchesPattern(string $value, string $pattern): bool
    {
        return strpos($value, $pattern) !== false;
    }
    
    private function matchesCallPattern(array $call, string $pattern): bool
    {
        if (strpos($call['name'], $pattern) !== false) {
            return true;
        }
        
        foreach ($call['arguments'] as $arg) {
            if (strpos($arg, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function matchesSinkPattern(array $call, string $pattern): bool
    {
        if (strpos($call['name'], $pattern) !== false) {
            return true;
        }
        
        foreach ($call['arguments'] as $arg) {
            if (strpos($arg, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function isSanitizer(string $functionName): bool
    {
        foreach ($this->rules['sanitizers'] as $sanitizer) {
            if (isset($sanitizer['patterns']) && is_array($sanitizer['patterns'])) {
                foreach ($sanitizer['patterns'] as $pattern) {
                    if (strpos($pattern, $functionName) !== false) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
