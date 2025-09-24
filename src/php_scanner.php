<?php
/**
 * Minimal HNP PHP Scanner (Mock Implementation)
 * Simulates deep taint analysis for framework-level HNP detection
 */

function parseArgs($argv) {
    $args = [];
    for ($i = 1; $i < count($argv); $i += 2) {
        if (isset($argv[$i + 1])) {
            $args[$argv[$i]] = $argv[$i + 1];
        }
    }
    return $args;
}

function scanFramework($targetPath, $sources, $sinks) {
    $result = [
        'flows' => [],
        'sources' => [],
        'sinks' => [],
        'metadata' => [
            'target' => $targetPath,
            'sources' => explode(',', $sources),
            'sinks' => explode(',', $sinks),
            'timestamp' => date('Y-m-d H:i:s')
        ]
    ];
    
    // Simulate finding sources
    $sourcePatterns = [
        'host_name' => ['getHost', 'getHttpHost', 'HTTP_HOST', 'SERVER_NAME'],
        'http_host' => ['HTTP_HOST', 'getHttpHost'],
        'server_name' => ['SERVER_NAME', 'getServerName']
    ];
    
    // Simulate finding sinks
    $sinkPatterns = [
        'url_generation' => ['url(', 'route(', 'generate(', 'to('],
        'template_render' => ['view(', 'render(', 'twig->render'],
        'redirect' => ['redirect(', 'Redirect::', 'redirectTo']
    ];
    
    // Mock data based on framework type
    $framework = basename($targetPath);
    
    // Simulate different security levels per framework
    $mockData = [
        'laravel' => [
            'flows' => [
                ['source_type' => 'host_name', 'sink_type' => 'url_generation', 'has_guard' => true, 'has_validation' => false],
                ['source_type' => 'http_host', 'sink_type' => 'template_render', 'has_guard' => false, 'has_validation' => true],
                ['source_type' => 'server_name', 'sink_type' => 'redirect', 'has_guard' => false, 'has_validation' => false],
            ],
            'sources' => [
                ['type' => 'host_name', 'file' => 'app/Http/Controllers/Controller.php', 'line' => 15],
                ['type' => 'http_host', 'file' => 'app/Http/Middleware/TrustProxies.php', 'line' => 8],
            ],
            'sinks' => [
                ['type' => 'url_generation', 'file' => 'app/Http/Controllers/Controller.php', 'line' => 25],
                ['type' => 'template_render', 'file' => 'resources/views/layout.blade.php', 'line' => 12],
            ]
        ],
        'symfony' => [
            'flows' => [
                ['source_type' => 'host_name', 'sink_type' => 'url_generation', 'has_guard' => true, 'has_validation' => true],
                ['source_type' => 'http_host', 'sink_type' => 'template_render', 'has_guard' => true, 'has_validation' => false],
            ],
            'sources' => [
                ['type' => 'host_name', 'file' => 'src/Controller/DefaultController.php', 'line' => 20],
            ],
            'sinks' => [
                ['type' => 'url_generation', 'file' => 'src/Controller/DefaultController.php', 'line' => 30],
                ['type' => 'template_render', 'file' => 'templates/base.html.twig', 'line' => 5],
            ]
        ],
        'codeigniter' => [
            'flows' => [
                ['source_type' => 'host_name', 'sink_type' => 'url_generation', 'has_guard' => false, 'has_validation' => false],
                ['source_type' => 'http_host', 'sink_type' => 'redirect', 'has_guard' => false, 'has_validation' => false],
            ],
            'sources' => [
                ['type' => 'host_name', 'file' => 'app/Controllers/Home.php', 'line' => 10],
            ],
            'sinks' => [
                ['type' => 'url_generation', 'file' => 'app/Controllers/Home.php', 'line' => 18],
                ['type' => 'redirect', 'file' => 'app/Controllers/Home.php', 'line' => 22],
            ]
        ],
        'cakephp' => [
            'flows' => [
                ['source_type' => 'host_name', 'sink_type' => 'url_generation', 'has_guard' => true, 'has_validation' => false],
            ],
            'sources' => [
                ['type' => 'host_name', 'file' => 'src/Controller/PagesController.php', 'line' => 15],
            ],
            'sinks' => [
                ['type' => 'url_generation', 'file' => 'src/Controller/PagesController.php', 'line' => 25],
            ]
        ],
        'yii' => [
            'flows' => [
                ['source_type' => 'host_name', 'sink_type' => 'url_generation', 'has_guard' => false, 'has_validation' => true],
                ['source_type' => 'http_host', 'sink_type' => 'template_render', 'has_guard' => true, 'has_validation' => true],
            ],
            'sources' => [
                ['type' => 'host_name', 'file' => 'controllers/SiteController.php', 'line' => 12],
            ],
            'sinks' => [
                ['type' => 'url_generation', 'file' => 'controllers/SiteController.php', 'line' => 20],
                ['type' => 'template_render', 'file' => 'views/site/index.php', 'line' => 8],
            ]
        ]
    ];
    
    $data = $mockData[$framework] ?? $mockData['laravel'];
    $result['flows'] = $data['flows'];
    $result['sources'] = $data['sources'];
    $result['sinks'] = $data['sinks'];
    
    return $result;
}

// Main execution
$args = parseArgs($argv);
$target = $args['--target'] ?? '';
$outputFormat = $args['--output-format'] ?? 'json';
$sources = $args['--taint-sources'] ?? 'host_name,http_host,server_name';
$sinks = $args['--taint-sinks'] ?? 'url_generation,template_render,redirect';

if (empty($target)) {
    fwrite(STDERR, "Error: --target is required\n");
    exit(1);
}

if (!is_dir($target)) {
    fwrite(STDERR, "Error: Target directory does not exist: $target\n");
    exit(1);
}

$result = scanFramework($target, $sources, $sinks);

if ($outputFormat === 'json') {
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
} else {
    echo "Output format '$outputFormat' not supported\n";
    exit(1);
}
