<?php
/**
 * 规则加载器
 * 加载和解析HNP检测规则配置
 */

namespace HNP\Rules;

class RuleLoader
{
    public function load(string $rulesFile): array
    {
        if (!file_exists($rulesFile)) {
            throw new \Exception("Rules file not found: $rulesFile");
        }
        
        $content = file_get_contents($rulesFile);
        if ($content === false) {
            throw new \Exception("Cannot read rules file: $rulesFile");
        }
        
        // 检查文件扩展名
        $extension = pathinfo($rulesFile, PATHINFO_EXTENSION);
        
        if ($extension === 'json') {
            return json_decode($content, true);
        } else {
            // 简化的YAML解析器（只处理基本的键值对和数组）
            return $this->parseYaml($content);
        }
    }
    
    private function parseYaml(string $content): array
    {
        $lines = explode("\n", $content);
        $rules = [];
        $currentSection = null;
        $currentItem = null;
        $currentSubKey = null;
        
        foreach ($lines as $line) {
            $line = trim($line);
            
            // 跳过注释和空行
            if (empty($line) || strpos($line, '#') === 0) {
                continue;
            }
            
            // 检查是否是新的section
            if (preg_match('/^(\w+):$/', $line, $matches)) {
                $currentSection = $matches[1];
                $rules[$currentSection] = [];
                $currentItem = null;
                $currentSubKey = null;
                continue;
            }
            
            // 检查是否是新的item（带-的）
            if (preg_match('/^- (\w+):$/', $line, $matches)) {
                $currentItem = $matches[1];
                $rules[$currentSection][] = [$currentItem => []];
                $currentSubKey = null;
                continue;
            }
            
            // 检查是否是子项（不带-的）
            if (preg_match('/^(\w+):$/', $line, $matches) && $currentItem !== null) {
                $currentSubKey = $matches[1];
                $lastIndex = count($rules[$currentSection]) - 1;
                $rules[$currentSection][$lastIndex][$currentItem][$currentSubKey] = [];
                continue;
            }
            
            // 检查是否是数组项
            if (preg_match('/^- (.+)$/', $line, $matches)) {
                $value = trim($matches[1], '"\'');
                
                if ($currentSubKey !== null && $currentItem !== null) {
                    $lastIndex = count($rules[$currentSection]) - 1;
                    if (!isset($rules[$currentSection][$lastIndex][$currentItem][$currentSubKey])) {
                        $rules[$currentSection][$lastIndex][$currentItem][$currentSubKey] = [];
                    }
                    $rules[$currentSection][$lastIndex][$currentItem][$currentSubKey][] = $value;
                } elseif ($currentItem !== null) {
                    $lastIndex = count($rules[$currentSection]) - 1;
                    if (!isset($rules[$currentSection][$lastIndex][$currentItem]['patterns'])) {
                        $rules[$currentSection][$lastIndex][$currentItem]['patterns'] = [];
                    }
                    $rules[$currentSection][$lastIndex][$currentItem]['patterns'][] = $value;
                } else {
                    $rules[$currentSection][] = $value;
                }
                continue;
            }
            
            // 检查是否是键值对
            if (preg_match('/^(\w+):\s*(.+)$/', $line, $matches)) {
                $key = $matches[1];
                $value = trim($matches[2], '"\'');
                
                if ($currentSubKey !== null && $currentItem !== null) {
                    $lastIndex = count($rules[$currentSection]) - 1;
                    $rules[$currentSection][$lastIndex][$currentItem][$currentSubKey][$key] = $value;
                } elseif ($currentItem !== null) {
                    $lastIndex = count($rules[$currentSection]) - 1;
                    $rules[$currentSection][$lastIndex][$currentItem][$key] = $value;
                } else {
                    $rules[$currentSection][$key] = $value;
                }
                continue;
            }
        }
        
        return $rules;
    }
}