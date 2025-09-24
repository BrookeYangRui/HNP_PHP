#!/usr/bin/env python3
"""
PHP Web框架检测器
检测项目使用的PHP框架并返回相应的配置信息
"""
import json
from pathlib import Path
import re

class FrameworkDetector:
    def __init__(self, project_path):
        self.project_path = Path(project_path)
        self.framework_info = {
            'framework': 'unknown',
            'version': None,
            'config_files': [],
            'hnp_risk_level': 'MEDIUM',
            'recommendations': []
        }
    
    def detect_framework(self):
        """检测项目使用的PHP框架"""
        # 检测Laravel
        if self._is_laravel():
            self.framework_info['framework'] = 'laravel'
            self._analyze_laravel_config()
        
        # 检测Symfony
        elif self._is_symfony():
            self.framework_info['framework'] = 'symfony'
            self._analyze_symfony_config()
        
        # 检测WordPress
        elif self._is_wordpress():
            self.framework_info['framework'] = 'wordpress'
            self._analyze_wordpress_config()
        
        # 检测CodeIgniter
        elif self._is_codeigniter():
            self.framework_info['framework'] = 'codeigniter'
            self._analyze_codeigniter_config()
        
        # 检测CakePHP
        elif self._is_cakephp():
            self.framework_info['framework'] = 'cakephp'
            self._analyze_cakephp_config()
        
        # 检测Yii2
        elif self._is_yii2():
            self.framework_info['framework'] = 'yii2'
            self._analyze_yii2_config()
        
        return self.framework_info
    
    def _is_laravel(self):
        """检测是否为Laravel项目"""
        indicators = [
            'artisan',
            'composer.json',
            'app/Http',
            'config/app.php',
            'vendor/laravel'
        ]
        return self._check_indicators(indicators)
    
    def _is_symfony(self):
        """检测是否为Symfony项目"""
        indicators = [
            'symfony.lock',
            'config/packages',
            'src/Controller',
            'vendor/symfony',
            'bin/console'
        ]
        return self._check_indicators(indicators)
    
    def _is_wordpress(self):
        """检测是否为WordPress项目"""
        indicators = [
            'wp-config.php',
            'wp-content',
            'wp-includes',
            'wp-admin',
            'index.php'
        ]
        return self._check_indicators(indicators)
    
    def _is_codeigniter(self):
        """检测是否为CodeIgniter项目"""
        indicators = [
            'application/config',
            'system/core',
            'index.php',
            'vendor/codeigniter'
        ]
        return self._check_indicators(indicators)
    
    def _is_cakephp(self):
        """检测是否为CakePHP项目"""
        indicators = [
            'config/app.php',
            'src/Controller',
            'vendor/cakephp',
            'bin/cake'
        ]
        return self._check_indicators(indicators)
    
    def _is_yii2(self):
        """检测是否为Yii2项目"""
        indicators = [
            'config/web.php',
            'vendor/yiisoft',
            'yii',
            'web/index.php'
        ]
        return self._check_indicators(indicators)
    
    def _check_indicators(self, indicators):
        """检查框架指示器"""
        for indicator in indicators:
            if (self.project_path / indicator).exists():
                return True
        return False
    
    def _analyze_laravel_config(self):
        """分析Laravel配置"""
        # 检查.env文件
        env_file = self.project_path / '.env'
        if env_file.exists():
            self.framework_info['config_files'].append('.env')
            try:
                env_content = env_file.read_text(encoding='utf-8', errors='ignore')
                if 'APP_URL=' in env_content:
                    self.framework_info['hnp_risk_level'] = 'LOW'
                    self.framework_info['recommendations'].append('APP_URL已配置，HNP风险较低')
                else:
                    self.framework_info['hnp_risk_level'] = 'HIGH'
                    self.framework_info['recommendations'].append('建议在.env中配置APP_URL')
            except Exception:
                pass
        
        # 检查TrustProxies中间件
        trust_proxies = self.project_path / 'app/Http/Middleware/TrustProxies.php'
        if trust_proxies.exists():
            self.framework_info['config_files'].append('TrustProxies.php')
            try:
                content = trust_proxies.read_text(encoding='utf-8', errors='ignore')
                if "protected $proxies = '*'" in content:
                    self.framework_info['hnp_risk_level'] = 'CRITICAL'
                    self.framework_info['recommendations'].append('TrustProxies配置为信任所有代理，存在严重安全风险')
            except Exception:
                pass
    
    def _analyze_symfony_config(self):
        """分析Symfony配置"""
        # 检查trusted_hosts配置
        config_dir = self.project_path / 'config/packages'
        if config_dir.exists():
            self.framework_info['config_files'].append('config/packages')
            # 查找trusted_hosts相关配置
            for config_file in config_dir.rglob('*.yaml'):
                try:
                    content = config_file.read_text(encoding='utf-8', errors='ignore')
                    if 'trusted_hosts' in content:
                        self.framework_info['hnp_risk_level'] = 'LOW'
                        self.framework_info['recommendations'].append('已配置trusted_hosts')
                        break
                except Exception:
                    continue
    
    def _analyze_wordpress_config(self):
        """分析WordPress配置"""
        wp_config = self.project_path / 'wp-config.php'
        if wp_config.exists():
            self.framework_info['config_files'].append('wp-config.php')
            try:
                content = wp_config.read_text(encoding='utf-8', errors='ignore')
                if 'WP_HOME' in content and 'WP_SITEURL' in content:
                    self.framework_info['hnp_risk_level'] = 'LOW'
                    self.framework_info['recommendations'].append('已配置WP_HOME和WP_SITEURL')
                else:
                    self.framework_info['hnp_risk_level'] = 'HIGH'
                    self.framework_info['recommendations'].append('建议配置WP_HOME和WP_SITEURL常量')
            except Exception:
                pass
    
    def _analyze_codeigniter_config(self):
        """分析CodeIgniter配置"""
        config_file = self.project_path / 'application/config/config.php'
        if config_file.exists():
            self.framework_info['config_files'].append('config.php')
            try:
                content = config_file.read_text(encoding='utf-8', errors='ignore')
                if '$config[\'base_url\']' in content:
                    self.framework_info['hnp_risk_level'] = 'LOW'
                    self.framework_info['recommendations'].append('已配置base_url')
                else:
                    self.framework_info['hnp_risk_level'] = 'HIGH'
                    self.framework_info['recommendations'].append('建议配置base_url')
            except Exception:
                pass
    
    def _analyze_cakephp_config(self):
        """分析CakePHP配置"""
        config_file = self.project_path / 'config/app.php'
        if config_file.exists():
            self.framework_info['config_files'].append('app.php')
            try:
                content = config_file.read_text(encoding='utf-8', errors='ignore')
                if 'App.fullBaseUrl' in content:
                    self.framework_info['hnp_risk_level'] = 'LOW'
                    self.framework_info['recommendations'].append('已配置fullBaseUrl')
                else:
                    self.framework_info['hnp_risk_level'] = 'HIGH'
                    self.framework_info['recommendations'].append('建议配置fullBaseUrl')
            except Exception:
                pass
    
    def _analyze_yii2_config(self):
        """分析Yii2配置"""
        config_file = self.project_path / 'config/web.php'
        if config_file.exists():
            self.framework_info['config_files'].append('web.php')
            try:
                content = config_file.read_text(encoding='utf-8', errors='ignore')
                if 'baseUrl' in content:
                    self.framework_info['hnp_risk_level'] = 'LOW'
                    self.framework_info['recommendations'].append('已配置baseUrl')
                else:
                    self.framework_info['hnp_risk_level'] = 'HIGH'
                    self.framework_info['recommendations'].append('建议配置baseUrl')
            except Exception:
                pass

def detect_framework(project_path):
    """检测项目框架的便捷函数"""
    detector = FrameworkDetector(project_path)
    return detector.detect_framework()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = detect_framework(sys.argv[1])
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("Usage: python framework_detector.py <project_path>")
