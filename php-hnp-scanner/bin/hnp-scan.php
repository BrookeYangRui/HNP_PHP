#!/usr/bin/env php
<?php
/**
 * HNP Scanner - Host Name Pollution Detection Tool
 * Zero-dependency PHP taint analyzer for HNP vulnerabilities
 */

require_once __DIR__ . '/../src/autoload.php';

function showUsage() {
    echo "HNP Scanner - Host Name Pollution Detection Tool\n";
    echo "Usage: php hnp-scan.php -p <project_path> [options]\n\n";
    echo "Options:\n";
    echo "  -p <path>     Project path to scan (required)\n";
    echo "  -r <file>     Rules file (default: rules/hnp.json)\n";
    echo "  -o <dir>      Output directory (default: out/)\n";
    echo "  --format      Output format: json,md,all (default: all)\n";
    echo "  --help        Show this help\n\n";
    echo "Examples:\n";
    echo "  php hnp-scan.php -p /var/www/app\n";
    echo "  php hnp-scan.php -p /var/www/app -r custom-rules.json -o results/\n";
}

function parseOptions($argv) {
    $options = [
        'project_path' => null,
        'rules_file' => __DIR__ . '/../rules/hnp.json',
        'output_dir' => __DIR__ . '/../out/',
        'format' => 'all'
    ];
    
    for ($i = 1; $i < count($argv); $i++) {
        $arg = $argv[$i];
        
        switch ($arg) {
            case '-p':
                if ($i + 1 < count($argv)) {
                    $options['project_path'] = $argv[++$i];
                } else {
                    echo "Error: -p requires a project path\n";
                    exit(1);
                }
                break;
            case '-r':
                if ($i + 1 < count($argv)) {
                    $options['rules_file'] = $argv[++$i];
                } else {
                    echo "Error: -r requires a rules file path\n";
                    exit(1);
                }
                break;
            case '-o':
                if ($i + 1 < count($argv)) {
                    $options['output_dir'] = $argv[++$i];
                } else {
                    echo "Error: -o requires an output directory\n";
                    exit(1);
                }
                break;
            case '--format':
                if ($i + 1 < count($argv)) {
                    $options['format'] = $argv[++$i];
                } else {
                    echo "Error: --format requires a format specification\n";
                    exit(1);
                }
                break;
            case '--help':
            case '-h':
                showUsage();
                exit(0);
            default:
                echo "Unknown option: $arg\n";
                showUsage();
                exit(1);
        }
    }
    
    return $options;
}

function validateOptions($options) {
    if (!$options['project_path']) {
        echo "Error: Project path (-p) is required\n";
        showUsage();
        exit(1);
    }
    
    if (!file_exists($options['project_path'])) {
        echo "Error: Project path '{$options['project_path']}' does not exist\n";
        exit(1);
    }
    
    if (!file_exists($options['rules_file'])) {
        echo "Error: Rules file '{$options['rules_file']}' does not exist\n";
        exit(1);
    }
    
    // Ensure output directory exists
    if (!is_dir($options['output_dir']) && !mkdir($options['output_dir'], 0777, true)) {
        echo "Error: Failed to create output directory: {$options['output_dir']}\n";
        exit(1);
    }
    
    // Parse format
    $formats = explode(',', $options['format']);
    $validFormats = ['json', 'md', 'all'];
    
    foreach ($formats as $format) {
        if (!in_array($format, $validFormats)) {
            echo "Error: Invalid format '$format'. Valid formats: " . implode(', ', $validFormats) . "\n";
            exit(1);
        }
    }
    
    if (in_array('all', $formats)) {
        $options['formats'] = ['json', 'md'];
    } else {
        $options['formats'] = $formats;
    }
    
    return $options;
}

// Main execution
try {
    $options = parseOptions($argv);
    $options = validateOptions($options);
    
    $scanner = new \HNP\Scanner($options);
    $scanner->run();
    
} catch (Exception $e) {
    echo "Fatal Error: " . $e->getMessage() . "\n";
    exit(1);
}