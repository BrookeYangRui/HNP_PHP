#!/usr/bin/env php
<?php
/**
 * Generate host-related call graph and program slices from Semgrep discovery results.
 *
 * Usage:
 *   php scripts/generate_host_call_graph.php <open_discovery.json> <output_dir>
 *
 * Produces:
 *   - host_call_graph.json containing call graph edges and per-finding slices.
 */

declare(strict_types=1);

spl_autoload_register(
    static function (string $class): void {
        $prefix = 'PhpParser\\';
        if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
            return;
        }
        $relative = substr($class, strlen($prefix));
        $path = __DIR__ . '/../vendor/nikic/php-parser/lib/PhpParser/' . str_replace('\\', '/', $relative) . '.php';
        if (is_file($path)) {
            require_once $path;
        }
    }
);

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\FunctionLike;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard as PrettyPrinter;

if ($argc < 3) {
    fwrite(STDERR, "Usage: php scripts/generate_host_call_graph.php <open_discovery.json> <output_dir>\n");
    exit(1);
}

$discoveryPath = $argv[1];
$outputDir = rtrim($argv[2], '/');

if (!is_file($discoveryPath)) {
    fwrite(STDERR, "Discovery file not found: {$discoveryPath}\n");
    exit(1);
}

if (!is_dir($outputDir) && !mkdir($outputDir, 0777, true) && !is_dir($outputDir)) {
    fwrite(STDERR, "Unable to create output directory: {$outputDir}\n");
    exit(1);
}

$discoveryData = json_decode((string) file_get_contents($discoveryPath), true);
if (!is_array($discoveryData)) {
    fwrite(STDERR, "Failed to parse discovery JSON: {$discoveryPath}\n");
    exit(1);
}

$findings = $discoveryData['results'] ?? [];
if (!$findings) {
    fwrite(STDOUT, "No discovery findings; skipping call graph generation.\n");
    exit(0);
}

// Group findings per file for efficient parsing.
$findingsByFile = [];
foreach ($findings as $finding) {
    if (!isset($finding['path'], $finding['start']['line'])) {
        continue;
    }
    $findingsByFile[$finding['path']][] = $finding;
}

$parserFactory = new ParserFactory();
$parser = $parserFactory->createForNewestSupportedVersion();
$printer = new PrettyPrinter();
$nodeFinder = new NodeFinder();

$edgeRecords = [];
$functionInfo = [];
$fileAstCache = [];
$hostFlows = [];

/**
 * Recursively connect parent references for quick upward traversal.
 *
 * @param Node $node
 */
function connectParents(Node $node): void
{
    foreach ($node->getSubNodeNames() as $name) {
        $child = $node->$name;
        if ($child instanceof Node) {
            $child->setAttribute('parent', $node);
            connectParents($child);
        } elseif (is_array($child)) {
            foreach ($child as $item) {
                if ($item instanceof Node) {
                    $item->setAttribute('parent', $node);
                    connectParents($item);
                }
            }
        }
    }
}

/**
 * Resolve namespace name for a node.
 *
 * @param Node $node
 * @return string
 */
function resolveNamespace(Node $node): string
{
    $current = $node;
    while ($current) {
        $parent = $current->getAttribute('parent');
        if ($parent instanceof Stmt\Namespace_) {
            return $parent->name ? $parent->name->toString() : '';
        }
        $current = $parent;
    }
    return '';
}

/**
 * Resolve enclosing class name for a node.
 *
 * @param Node $node
 * @return string
 */
function resolveClassName(Node $node): string
{
    $current = $node;
    while ($current) {
        $parent = $current->getAttribute('parent');
        if ($parent instanceof Stmt\ClassLike && $parent->name) {
            $namespace = resolveNamespace($parent);
            $className = $parent->name->toString();
            return $namespace ? $namespace . '\\' . $className : $className;
        }
        $current = $parent;
    }
    return '';
}

/**
 * Derive fully qualified function name.
 *
 * @param FunctionLike $functionNode
 * @param string       $filePath
 * @return string
 */
function getFunctionName(FunctionLike $functionNode, string $filePath): string
{
    if ($functionNode instanceof Stmt\Function_) {
        $namespace = resolveNamespace($functionNode);
        $name = $functionNode->name ? $functionNode->name->toString() : 'anonymous_function';
        return $namespace ? $namespace . '\\' . $name : $name;
    }

    if ($functionNode instanceof Stmt\ClassMethod) {
        $className = resolveClassName($functionNode);
        $methodName = $functionNode->name ? $functionNode->name->toString() : 'anonymous_method';
        if ($className) {
            return $className . '::' . $methodName;
        }
        return 'anonymous_class::' . $methodName;
    }

    $line = $functionNode->getStartLine();
    return sprintf('closure@%s:%d', $filePath, $line);
}

/**
 * Identify call target string from expression node.
 *
 * @param Node           $node
 * @param FunctionLike|null $functionLike
 * @param PrettyPrinter  $printer
 * @return array{type:string,name:string|null,signature:string|null}
 */
function resolveCallTarget(Node $node, ?FunctionLike $functionLike, PrettyPrinter $printer): array
{
    if ($node instanceof Stmt\Expression) {
        return resolveCallTarget($node->expr, $functionLike, $printer);
    }

    if ($node instanceof Expr\FuncCall) {
        if ($node->name instanceof Node\Name) {
            return [
                'type' => 'function',
                'name' => $node->name->toString(),
                'signature' => $printer->prettyPrintExpr($node),
            ];
        }
        return [
            'type' => 'function',
            'name' => $printer->prettyPrintExpr($node->name),
            'signature' => $printer->prettyPrintExpr($node),
        ];
    }

    if ($node instanceof Expr\StaticCall) {
        $className = $node->class instanceof Node\Name ? $node->class->toString() : $printer->prettyPrintExpr($node->class);
        $methodName = $node->name instanceof Node\Identifier ? $node->name->toString() : $printer->prettyPrintExpr($node->name);
        return [
            'type' => 'static_method',
            'name' => $className . '::' . $methodName,
            'signature' => $printer->prettyPrintExpr($node),
        ];
    }

    if ($node instanceof Expr\MethodCall) {
        $objectExpr = $printer->prettyPrintExpr($node->var);
        $methodName = $node->name instanceof Node\Identifier ? $node->name->toString() : $printer->prettyPrintExpr($node->name);

        $className = null;
        if ($functionLike && $node->var instanceof Expr\Variable && $node->var->name === 'this') {
            $className = resolveClassName($functionLike);
        }

        $callName = $className ? $className . '::' . $methodName : $methodName;

        return [
            'type' => 'method',
            'name' => $callName,
            'signature' => sprintf('%s->%s', $objectExpr, $methodName),
        ];
    }

    if ($node instanceof Expr\Assign) {
        if ($node->expr instanceof Node) {
            return resolveCallTarget($node->expr, $functionLike, $printer);
        }
        return [
            'type' => 'assignment',
            'name' => null,
            'signature' => $printer->prettyPrintExpr($node),
        ];
    }

    if ($node instanceof Expr\BinaryOp || $node instanceof Expr\AssignOp) {
        return [
            'type' => 'expression',
            'name' => null,
            'signature' => $printer->prettyPrintExpr($node),
        ];
    }

    if ($node instanceof Expr) {
        $signature = $printer->prettyPrintExpr($node);
    } elseif ($node instanceof Node\Name) {
        $signature = $node->toString();
    } else {
        $signature = $node->getType();
    }

    return [
        'type' => strtolower($node->getType()),
        'name' => null,
        'signature' => $signature,
    ];
}

/**
 * Detect host expression snippet using regex heuristics.
 *
 * @param string $lineContent
 * @return string|null
 */
function detectHostExpression(string $lineContent): ?string
{
    $patterns = [
        '/\$_SERVER\s*\[\s*[\'"]HTTP_[A-Z_]+[\'"]\s*\]/',
        '/\$_SERVER\s*\[\s*[\'"]SERVER_NAME[\'"]\s*\]/',
        '/->getHost\s*\(/',
        '/->getHttpHost\s*\(/',
        '/\bgetSchemeAndHttpHost\s*\(/',
        '/\bfullUrl\s*\(/',
        '/\broot\s*\(/',
        '/\burl\s*\(/',
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $lineContent, $matches)) {
            return $matches[0];
        }
    }

    if (preg_match('/\$_SERVER\s*\[[^\]]+\]/', $lineContent, $matches)) {
        return $matches[0];
    }

    return null;
}

/**
 * Find enclosing function-like node for a node.
 *
 * @param Node $node
 * @return FunctionLike|null
 */
function findEnclosingFunction(Node $node): ?FunctionLike
{
    $current = $node;
    while ($current) {
        if ($current instanceof FunctionLike) {
            return $current;
        }
        $current = $current->getAttribute('parent');
    }
    return null;
}

/**
 * Locate the most specific node covering target line.
 *
 * @param array<int, Node> $stmts
 * @param int              $line
 * @param NodeFinder       $finder
 * @return Node|null
 */
function findNodeCoveringLine(array $stmts, int $line, NodeFinder $finder): ?Node
{
    $candidates = $finder->find(
        $stmts,
        static function (Node $node) use ($line): bool {
            if (!$node->hasAttribute('startLine') || !$node->hasAttribute('endLine')) {
                return false;
            }
            $start = (int) $node->getAttribute('startLine');
            $end = (int) $node->getAttribute('endLine');
            return $start <= $line && $end >= $line;
        }
    );

    if (!$candidates) {
        return null;
    }

    usort(
        $candidates,
        static function (Node $a, Node $b): int {
            $spanA = ((int) $a->getAttribute('endLine') - (int) $a->getAttribute('startLine'));
            $spanB = ((int) $b->getAttribute('endLine') - (int) $b->getAttribute('startLine'));
            return $spanA <=> $spanB;
        }
    );

    $preferredClasses = [
        Expr\FuncCall::class,
        Expr\MethodCall::class,
        Expr\StaticCall::class,
        Expr\Assign::class,
        Expr\AssignOp::class,
        Expr\BinaryOp::class,
        Stmt\Return_::class,
        Stmt\Expression::class,
        Stmt\Echo_::class,
    ];

    foreach ($preferredClasses as $preferred) {
        foreach ($candidates as $candidate) {
            if ($candidate instanceof $preferred) {
                return $candidate;
            }
        }
    }

    return $candidates[0];
}

/**
 * Collect function calls within a function node.
 *
 * @param FunctionLike   $function
 * @param NodeFinder     $finder
 * @param PrettyPrinter  $printer
 * @return array<int, array{from:string,to:string,type:string,file:string,line:int}>
 */
function collectFunctionCalls(FunctionLike $function, NodeFinder $finder, PrettyPrinter $printer, string $filePath): array
{
    $calls = [];
    $functionName = getFunctionName($function, $filePath);

    $callNodes = $finder->find(
        $function->getStmts() ?? [],
        static fn(Node $node): bool => $node instanceof Expr\FuncCall || $node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall
    );

    foreach ($callNodes as $callNode) {
        $callTarget = resolveCallTarget($callNode, $function, $printer);
        if (!$callTarget['name']) {
            continue;
        }

        $calls[] = [
            'from' => $functionName,
            'to' => $callTarget['name'],
            'type' => $callTarget['type'],
            'file' => $filePath,
            'line' => (int) $callNode->getStartLine(),
        ];
    }

    return $calls;
}

// Parse files, collect function definitions and call graph edges.
foreach ($findingsByFile as $filePath => $_) {
    if (!is_file($filePath)) {
        // Attempt relative path from project root.
        $relativePath = __DIR__ . '/../' . ltrim($filePath, '/');
        if (is_file($relativePath)) {
            $filePath = realpath($relativePath) ?: $relativePath;
        } else {
            fwrite(STDERR, "Skipping missing file: {$filePath}\n");
            continue;
        }
    }

    $code = (string) file_get_contents($filePath);
    try {
        $stmts = $parser->parse($code) ?? [];
    } catch (Error $e) {
        fwrite(STDERR, "Parse error in {$filePath}: {$e->getMessage()}\n");
        continue;
    }

    foreach ($stmts as $stmt) {
        connectParents($stmt);
    }

    $fileAstCache[$filePath] = [
        'stmts' => $stmts,
        'lines' => preg_split("/(\r\n|\n|\r)/", $code) ?: [],
    ];

    $functionNodes = $nodeFinder->findInstanceOf($stmts, FunctionLike::class);
    foreach ($functionNodes as $functionNode) {
        $name = getFunctionName($functionNode, $filePath);
        $functionInfo[$name] = [
            'file' => $filePath,
            'start_line' => (int) $functionNode->getStartLine(),
            'end_line' => (int) $functionNode->getEndLine(),
        ];

        foreach (collectFunctionCalls($functionNode, $nodeFinder, $printer, $filePath) as $callEdge) {
            $edgeRecords[] = $callEdge;
        }
    }
}

// Build adjacency and reverse call graphs.
$adjacency = [];
$reverse = [];
foreach ($edgeRecords as $edge) {
    $adjacency[$edge['from']][] = $edge;
    $reverse[$edge['to']][] = $edge;
}

/**
 * Build call chains ending at the target function.
 *
 * @param string $target
 * @param array<string, array<int, array{from:string,to:string,type:string,file:string,line:int}>> $reverseGraph
 * @param int $maxDepth
 * @param int $maxPaths
 * @return array<int, array<int, array{function:string,call_site:array|null}>>
 */
function buildCallChains(string $target, array $reverseGraph, int $maxDepth = 4, int $maxPaths = 5): array
{
    if (!isset($reverseGraph[$target])) {
        return [[['function' => $target, 'call_site' => null]]];
    }

    $chains = [];
    $queue = [[
        'nodes' => [$target],
        'edges' => [],
    ]];

    while ($queue && count($chains) < $maxPaths) {
        $path = array_shift($queue);
        $current = $path['nodes'][0];

        if (!isset($reverseGraph[$current]) || count($path['nodes']) >= $maxDepth) {
            $chains[] = formatChain($path);
            continue;
        }

        foreach ($reverseGraph[$current] as $edge) {
            $caller = $edge['from'];
            if (in_array($caller, $path['nodes'], true)) {
                continue; // avoid cycles
            }
            $newNodes = $path['nodes'];
            array_unshift($newNodes, $caller);
            $newEdges = $path['edges'];
            array_unshift($newEdges, $edge);
            $queue[] = [
                'nodes' => $newNodes,
                'edges' => $newEdges,
            ];
        }
    }

    if (!$chains) {
        $chains[] = formatChain([
            'nodes' => [$target],
            'edges' => [],
        ]);
    }

    return $chains;
}

/**
 * Format a chain structure into an ordered list with call-site data.
 *
 * @param array{nodes:array<int,string>,edges:array<int,array{from:string,to:string,type:string,file:string,line:int}>} $path
 * @return array<int, array{function:string,call_site:array|null}>
 */
function formatChain(array $path): array
{
    $nodes = $path['nodes'];
    $edges = $path['edges'];
    $formatted = [];

    foreach ($nodes as $index => $functionName) {
        $callSite = null;
        if ($index > 0 && isset($edges[$index - 1])) {
            $edge = $edges[$index - 1];
            $callSite = [
                'file' => $edge['file'],
                'line' => $edge['line'],
            ];
        }
        $formatted[] = [
            'function' => $functionName,
            'call_site' => $callSite,
        ];
    }

    return $formatted;
}

// Process individual findings to assemble host flows.
foreach ($findingsByFile as $filePath => $fileFindings) {
    if (!isset($fileAstCache[$filePath])) {
        continue;
    }

    $stmts = $fileAstCache[$filePath]['stmts'];
    $fileLines = $fileAstCache[$filePath]['lines'];

    foreach ($fileFindings as $finding) {
        $line = (int) ($finding['start']['line'] ?? 0);
        if ($line <= 0) {
            continue;
        }

        $node = findNodeCoveringLine($stmts, $line, $nodeFinder);
        if (!$node) {
            continue;
        }

        $functionLike = findEnclosingFunction($node);
        $functionName = $functionLike ? getFunctionName($functionLike, $filePath) : sprintf('global@%s', $filePath);

        $targetCall = resolveCallTarget($node, $functionLike, $printer);
        if (!$targetCall['name'] && $node instanceof Expr\Assign && $node->expr instanceof Node) {
            $targetCall = resolveCallTarget($node->expr, $functionLike, $printer);
        }

        $lineContent = $fileLines[$line - 1] ?? '';
        $hostExpr = detectHostExpression($lineContent);

        $sliceStart = max(0, $line - 4);
        $sliceEnd = min(count($fileLines), $line + 3);
        $sliceLines = array_slice($fileLines, $sliceStart, $sliceEnd - $sliceStart);
        $programSlice = implode("\n", $sliceLines);

        $callChains = buildCallChains($functionName, $reverse);

        $hostFlows[] = [
            'file' => $filePath,
            'line' => $line,
            'function' => $functionName,
            'call_type' => $targetCall['type'],
            'call_target' => $targetCall['name'],
            'call_signature' => $targetCall['signature'],
            'host_expression' => $hostExpr,
            'program_slice' => $programSlice,
            'call_chains' => $callChains,
        ];
    }
}

// Aggregate edges for summary.
$edgeSummary = [];
foreach ($edgeRecords as $edge) {
    $key = $edge['from'] . '||' . $edge['to'];
    if (!isset($edgeSummary[$key])) {
        $edgeSummary[$key] = [
            'from' => $edge['from'],
            'to' => $edge['to'],
            'type' => $edge['type'],
            'occurrences' => 0,
            'examples' => [],
        ];
    }
    $edgeSummary[$key]['occurrences']++;
    if (count($edgeSummary[$key]['examples']) < 5) {
        $edgeSummary[$key]['examples'][] = [
            'file' => $edge['file'],
            'line' => $edge['line'],
        ];
    }
}

$output = [
    'generated_at' => date(DATE_ATOM),
    'discovery_file' => $discoveryPath,
    'total_findings' => count($findings),
    'total_host_flows' => count($hostFlows),
    'call_graph_edges' => array_values($edgeSummary),
    'host_flows' => $hostFlows,
];

$outputPath = $outputDir . '/host_call_graph.json';
$encoded = json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if ($encoded === false) {
    fwrite(STDERR, "Failed to encode call graph JSON.\n");
    exit(1);
}

file_put_contents($outputPath, $encoded);
fwrite(STDOUT, "Host call graph generated: {$outputPath}\n");
exit(0);
