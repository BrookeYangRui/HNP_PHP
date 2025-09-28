<?php
/**
 * Markdown报告生成器
 * 将HNP检测结果输出为Markdown格式
 */

namespace HNP\Report;

class MarkdownWriter
{
    public function write(array $findings, string $outputFile): void
    {
        $content = $this->generateMarkdown($findings);
        
        if (file_put_contents($outputFile, $content) === false) {
            throw new \Exception("Cannot write Markdown report to: $outputFile");
        }
        
        echo "📄 Markdown report written to: $outputFile\n";
    }
    
    private function generateMarkdown(array $findings): string
    {
        $content = "# HNP Scanner Report\n\n";
        $content .= "**扫描时间**: " . date('Y-m-d H:i:s') . "\n";
        $content .= "**总发现数**: " . count($findings) . "\n\n";
        
        // 生成摘要
        $content .= $this->generateSummarySection($findings);
        
        // 生成详细发现
        if (!empty($findings)) {
            $content .= $this->generateFindingsSection($findings);
        }
        
        // 生成建议
        $content .= $this->generateRecommendationsSection($findings);
        
        return $content;
    }
    
    private function generateSummarySection(array $findings): string
    {
        $summary = $this->calculateSummary($findings);
        
        $content = "## 📊 扫描摘要\n\n";
        
        // 按严重程度统计
        $content .= "### 按严重程度\n";
        $content .= "- 🔴 **高**: {$summary['by_severity']['high']} 个\n";
        $content .= "- 🟡 **中**: {$summary['by_severity']['medium']} 个\n";
        $content .= "- 🟢 **低**: {$summary['by_severity']['low']} 个\n\n";
        
        // 按安全状态统计
        $content .= "### 按安全状态\n";
        $content .= "- 🚨 **绝对URL构造不当**: {$summary['by_state']['abs_url_build']} 个\n";
        $content .= "- ⚠️ **代理信任错误**: {$summary['by_state']['proxy_misconfig']} 个\n";
        $content .= "- 📝 **旁路使用**: {$summary['by_state']['side_effect']} 个\n";
        $content .= "- ✅ **安全**: {$summary['by_state']['safe']} 个\n\n";
        
        // 按规则类型统计
        $content .= "### 按规则类型\n";
        foreach ($summary['by_rule'] as $rule => $count) {
            $content .= "- **{$rule}**: {$count} 个\n";
        }
        $content .= "\n";
        
        return $content;
    }
    
    private function generateFindingsSection(array $findings): string
    {
        $content = "## 🔍 详细发现\n\n";
        
        // 按严重程度分组
        $groupedFindings = $this->groupFindingsBySeverity($findings);
        
        foreach (['high', 'medium', 'low'] as $severity) {
            if (empty($groupedFindings[$severity])) {
                continue;
            }
            
            $severityEmoji = ['high' => '🔴', 'medium' => '🟡', 'low' => '🟢'][$severity];
            $content .= "### {$severityEmoji} {$severity} 严重程度\n\n";
            
            foreach ($groupedFindings[$severity] as $finding) {
                $content .= $this->formatFinding($finding);
            }
        }
        
        return $content;
    }
    
    private function formatFinding(array $finding): string
    {
        $content = "#### 📁 {$finding['file']}:{$finding['line']}\n\n";
        $content .= "- **规则**: `{$finding['rule']}`\n";
        $content .= "- **状态**: `{$finding['state']}`\n";
        $content .= "- **严重程度**: `{$finding['severity']}`\n";
        $content .= "- **Sink**: `{$finding['sink']}`\n\n";
        
        if (!empty($finding['sources'])) {
            $content .= "**污点源**:\n";
            foreach ($finding['sources'] as $source) {
                $content .= "- `{$source['pattern']}` (行 {$source['line']})\n";
            }
            $content .= "\n";
        }
        
        if (!empty($finding['sanitizers'])) {
            $content .= "**已应用净化器**:\n";
            foreach ($finding['sanitizers'] as $sanitizer) {
                $content .= "- `{$sanitizer['sanitizer']}` (行 {$sanitizer['line']})\n";
            }
            $content .= "\n";
        }
        
        $content .= "---\n\n";
        
        return $content;
    }
    
    private function generateRecommendationsSection(array $findings): string
    {
        $content = "## 💡 修复建议\n\n";
        
        $content .= "### 通用建议\n";
        $content .= "1. **启用严格域名白名单**: 对所有Host使用进行白名单验证\n";
        $content .= "2. **配置可信代理**: 正确设置框架的信任代理列表\n";
        $content .= "3. **使用框架安全方法**: 优先使用框架提供的安全URL构建方法\n";
        $content .= "4. **输入验证**: 对所有用户输入进行严格验证和净化\n\n";
        
        $content .= "### 针对发现问题的建议\n";
        
        $hasRedirectIssues = false;
        $hasCorsIssues = false;
        $hasCookieIssues = false;
        
        foreach ($findings as $finding) {
            switch ($finding['rule']) {
                case 'redirect':
                    $hasRedirectIssues = true;
                    break;
                case 'cors':
                    $hasCorsIssues = true;
                    break;
                case 'cookie_domain':
                    $hasCookieIssues = true;
                    break;
            }
        }
        
        if ($hasRedirectIssues) {
            $content .= "- **重定向问题**: 使用框架提供的安全重定向方法，避免直接拼接Host\n";
        }
        
        if ($hasCorsIssues) {
            $content .= "- **CORS问题**: 配置明确的允许域名列表，避免使用通配符\n";
        }
        
        if ($hasCookieIssues) {
            $content .= "- **Cookie域名问题**: 设置固定的Cookie域名，避免使用用户可控的Host\n";
        }
        
        $content .= "\n### 代码示例\n\n";
        $content .= "```php\n";
        $content .= "// ❌ 不安全的做法\n";
        $content .= "\$host = \$_SERVER['HTTP_HOST'];\n";
        $content .= "header('Location: https://' . \$host . '/redirect');\n\n";
        $content .= "// ✅ 安全的做法\n";
        $content .= "\$allowedHosts = ['example.com', 'www.example.com'];\n";
        $content .= "\$host = \$_SERVER['HTTP_HOST'];\n";
        $content .= "if (in_array(\$host, \$allowedHosts, true)) {\n";
        $content .= "    header('Location: https://' . \$host . '/redirect');\n";
        $content .= "} else {\n";
        $content .= "    header('Location: https://example.com/redirect');\n";
        $content .= "}\n";
        $content .= "```\n";
        
        return $content;
    }
    
    private function calculateSummary(array $findings): array
    {
        $summary = [
            'by_severity' => ['high' => 0, 'medium' => 0, 'low' => 0],
            'by_state' => ['abs_url_build' => 0, 'proxy_misconfig' => 0, 'side_effect' => 0, 'safe' => 0],
            'by_rule' => []
        ];
        
        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'low';
            $summary['by_severity'][$severity]++;
            
            $state = $finding['state'] ?? 'side_effect';
            $summary['by_state'][$state]++;
            
            $rule = $finding['rule'] ?? 'unknown';
            if (!isset($summary['by_rule'][$rule])) {
                $summary['by_rule'][$rule] = 0;
            }
            $summary['by_rule'][$rule]++;
        }
        
        return $summary;
    }
    
    private function groupFindingsBySeverity(array $findings): array
    {
        $grouped = ['high' => [], 'medium' => [], 'low' => []];
        
        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'low';
            $grouped[$severity][] = $finding;
        }
        
        return $grouped;
    }
}
