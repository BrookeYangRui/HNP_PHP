<?php
/**
 * HNP Scanner - Main Controller
 * Coordinates the entire scanning process: file discovery -> lexical analysis -> AST building -> taint analysis -> report generation
 */

namespace HNP;

use HNP\Frontend\CompleteAstBuilder;
use HNP\Analysis\CompleteTaintEngine;
use HNP\Rules\RuleLoader;
use HNP\Report\JsonWriter;
use HNP\Report\MarkdownWriter;

class Scanner
{
    private array $options;
    private array $rules;
    private array $files = [];
    private array $findings = [];

    public function __construct(array $options)
    {
        $this->options = $options;
        $this->loadRules();
    }

    public function run(): void
    {
        echo "🔍 HNP Scanner - Host Name Pollution Detection\n";
        echo "===============================================\n";
        echo "Project: " . $this->options['project_path'] . "\n";
        echo "Rules: " . $this->options['rules_file'] . "\n";
        echo "Output: " . $this->options['output_dir'] . "\n";
        echo "Format: " . implode(', ', $this->options['formats']) . "\n\n";

        echo "📋 Loaded " . count($this->rules['sources']) . " source patterns\n";
        echo "🔍 Starting HNP scan...\n";

        $this->discoverFiles();
        echo "📁 Found " . count($this->files) . " PHP files\n";

        if (empty($this->files)) {
            echo "⚠️  No PHP files found to scan. Exiting.\n";
            $this->generateReports();
            return;
        }

        $astData = $this->buildAsts();
        echo "🌳 Built ASTs for " . count($astData) . " files\n";

        $this->performTaintAnalysis($astData);
        echo "🔬 Found " . count($this->findings) . " potential HNP issues\n";

        $this->generateReports();
        echo "📊 Reports generated in " . $this->options['output_dir'] . "\n";
        echo "✅ Scan completed successfully!\n";
        echo "Found " . count($this->findings) . " potential HNP issues\n";
    }

    private function loadRules(): void
    {
        $ruleLoader = new RuleLoader();
        $this->rules = $ruleLoader->load($this->options['rules_file']);
    }

    private function discoverFiles(): void
    {
        $this->files = $this->findPhpFiles($this->options['project_path']);
    }

    private function findPhpFiles(string $path): array
    {
        $files = [];
        if (!is_dir($path)) {
            if (is_file($path) && pathinfo($path, PATHINFO_EXTENSION) === 'php') {
                return [$path];
            }
            return [];
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                // Skip vendor directories but keep test files for validation
                if (strpos($file->getPathname(), '/vendor/') === false) {
                    $files[] = $file->getPathname();
                }
            }
        }

        return $files;
    }

    private function buildAsts(): array
    {
        $astBuilder = new CompleteAstBuilder();
        $astData = [];

        foreach ($this->files as $file) {
            try {
                $ast = $astBuilder->build($file);
                $astData[$file] = $ast;
            } catch (\Exception $e) {
                echo "⚠️  Failed to parse $file: " . $e->getMessage() . "\n";
            }
        }

        return $astData;
    }

    private function performTaintAnalysis(array $astData): void
    {
        $taintEngine = new CompleteTaintEngine($this->rules);
        
        foreach ($astData as $file => $ast) {
            $findings = $taintEngine->analyze($ast, $file);
            $this->findings = array_merge($this->findings, $findings);
        }
    }

    private function generateReports(): void
    {
        $outputDir = $this->options['output_dir'];
        $formats = $this->options['formats'];

        $reportData = [
            'scan_info' => [
                'timestamp' => date('Y-m-d H:i:s'),
                'total_findings' => count($this->findings),
                'scanner_version' => '1.0.0'
            ],
            'findings' => $this->findings,
            'summary' => $this->summarizeFindings()
        ];

        if (in_array('json', $formats)) {
            $jsonWriter = new JsonWriter();
            $jsonWriter->write($reportData, $outputDir . '/findings.json');
        }
        if (in_array('md', $formats)) {
            $markdownWriter = new MarkdownWriter();
            $markdownWriter->write($reportData, $outputDir . '/summary.md');
        }
    }

    private function summarizeFindings(): array
    {
        $summary = [
            'by_severity' => ['high' => 0, 'medium' => 0, 'low' => 0],
            'by_state' => ['abs_url_build' => 0, 'proxy_misconfig' => 0, 'side_effect' => 0, 'safe' => 0],
            'by_rule' => []
        ];

        foreach ($this->findings as $finding) {
            $severity = $finding['severity'] ?? 'unknown';
            $state = $finding['state'] ?? 'unknown';
            $rule = $finding['rule'] ?? 'unknown';
            
            $summary['by_severity'][strtolower($severity)]++;
            $summary['by_state'][strtolower(str_replace('-', '_', $state))]++;
            $summary['by_rule'][$rule] = ($summary['by_rule'][$rule] ?? 0) + 1;
        }

        return $summary;
    }
}