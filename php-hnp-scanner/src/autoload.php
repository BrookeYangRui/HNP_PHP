<?php
/**
 * 简单的自动加载器
 * 为HNP扫描器提供类自动加载功能
 */

spl_autoload_register(function ($className) {
    // 移除命名空间前缀
    $className = str_replace('HNP\\', '', $className);
    
    // 转换为文件路径
    $filePath = __DIR__ . '/' . str_replace('\\', '/', $className) . '.php';
    
    if (file_exists($filePath)) {
        require_once $filePath;
    }
});
