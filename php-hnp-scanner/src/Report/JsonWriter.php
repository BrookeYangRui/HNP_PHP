<?php
/**
 * JSON报告生成器
 * 将HNP检测结果输出为JSON格式
 */

namespace HNP\Report;

class JsonWriter
{
    public function write(array $findings, string $outputFile): void
    {
        $report = [
            'scan_info' => [
                'timestamp' => date('Y-m-d H:i:s'),
                'total_findings' => count($findings),
                'scanner_version' => '1.0.0'
            ],
            'findings' => $findings,
            'summary' => $this->generateSummary($findings)
        ];
        
        $json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        
        if (file_put_contents($outputFile, $json) === false) {
            throw new \Exception("Cannot write JSON report to: $outputFile");
        }
        
        echo "📄 JSON report written to: $outputFile\n";
    }
    
    private function generateSummary(array $findings): array
    {
        $summary = [
            'by_severity' => [
                'high' => 0,
                'medium' => 0,
                'low' => 0
            ],
            'by_state' => [
                'abs_url_build' => 0,
                'proxy_misconfig' => 0,
                'side_effect' => 0,
                'safe' => 0
            ],
            'by_rule' => []
        ];
        
        foreach ($findings as $finding) {
            // 按严重程度统计
            $severity = $finding['severity'] ?? 'low';
            $summary['by_severity'][$severity]++;
            
            // 按安全状态统计
            $state = $finding['state'] ?? 'side_effect';
            $summary['by_state'][$state]++;
            
            // 按规则类型统计
            $rule = $finding['rule'] ?? 'unknown';
            if (!isset($summary['by_rule'][$rule])) {
                $summary['by_rule'][$rule] = 0;
            }
            $summary['by_rule'][$rule]++;
        }
        
        return $summary;
    }
}
