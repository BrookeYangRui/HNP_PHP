#!/usr/bin/env python3
"""
框架感知的HNP扫描器CLI工具
"""
import sys
import json
import argparse
from pathlib import Path

# 添加父目录到路径
sys.path.append(str(Path(__file__).parent.parent))

from framework_detector import detect_framework
import subprocess

def scan_project(project_path, output_format='json'):
    """扫描单个项目"""
    project_path = Path(project_path)
    
    if not project_path.exists():
        print(f"错误: 项目路径不存在: {project_path}")
        return None
    
    print(f"🔍 扫描项目: {project_path}")
    
    # 检测框架
    print("正在检测框架...")
    framework_info = detect_framework(project_path)
    
    print(f"检测到框架: {framework_info['framework']}")
    print(f"风险等级: {framework_info['hnp_risk_level']}")
    
    if framework_info['recommendations']:
        print("建议:")
        for rec in framework_info['recommendations']:
            print(f"  - {rec}")
    
    # 选择扫描规则
    if framework_info['framework'] != 'unknown':
        rules_file = "rules/php-frameworks-hnp.yml"
        print(f"使用框架特定规则: {rules_file}")
    else:
        rules_file = "rules/php-hnp-simple.yml"
        print(f"使用通用规则: {rules_file}")
    
    # 执行扫描
    print("正在执行HNP扫描...")
    cmd = [
        "semgrep", "scan",
        "--config", rules_file,
        "--json",
        "--include", "*.php",
        "--exclude", "vendor/",
        "--exclude", "node_modules/",
        "--exclude", ".git/",
        str(project_path)
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            # 尝试从stdout和stderr中提取JSON
            json_data = None
            
            # 首先尝试从stdout获取
            stdout_lines = result.stdout.strip().split('\n')
            for line in reversed(stdout_lines):
                if line.strip().startswith('{') and '"version"' in line:
                    try:
                        json_data = json.loads(line)
                        break
                    except:
                        continue
            
            # 如果stdout没有，尝试stderr
            if not json_data:
                stderr_lines = result.stderr.strip().split('\n')
                for line in reversed(stderr_lines):
                    if line.strip().startswith('{') and '"version"' in line:
                        try:
                            json_data = json.loads(line)
                            break
                        except:
                            continue
            
            if json_data:
                findings = json_data.get("results", [])
                print(f"✅ 扫描完成，发现 {len(findings)} 个HNP问题")
            else:
                print("❌ 无法解析扫描结果")
                findings = []
            
            # 生成报告
            report = {
                "project_path": str(project_path),
                "framework_info": framework_info,
                "findings": findings,
                "scan_summary": {
                    "total_findings": len(findings),
                    "rules_used": rules_file,
                    "scan_status": "success"
                }
            }
            
            return report
        else:
            print(f"❌ 扫描失败: {result.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        print("⏰ 扫描超时")
        return None
    except Exception as e:
        print(f"❌ 扫描出错: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='框架感知的HNP扫描器')
    parser.add_argument('project_path', help='要扫描的项目路径')
    parser.add_argument('--output', '-o', choices=['json', 'text'], default='text',
                       help='输出格式 (默认: text)')
    parser.add_argument('--save', '-s', help='保存结果到文件')
    
    args = parser.parse_args()
    
    # 执行扫描
    report = scan_project(args.project_path, args.output)
    
    if report is None:
        sys.exit(1)
    
    # 输出结果
    if args.output == 'json':
        output = json.dumps(report, indent=2, ensure_ascii=False)
    else:
        # 文本格式输出
        output = f"""
=== HNP扫描报告 ===
项目路径: {report['project_path']}
框架: {report['framework_info']['framework']}
风险等级: {report['framework_info']['hnp_risk_level']}
发现数量: {report['scan_summary']['total_findings']}
使用规则: {report['scan_summary']['rules_used']}

=== 框架信息 ===
配置文件: {', '.join(report['framework_info']['config_files'])}

=== 建议 ===
"""
        for rec in report['framework_info']['recommendations']:
            output += f"- {rec}\n"
        
        if report['findings']:
            output += "\n=== 发现的问题 ===\n"
            for i, finding in enumerate(report['findings'], 1):
                output += f"{i}. {finding['extra']['message']}\n"
                output += f"   文件: {finding['path']}\n"
                output += f"   行号: {finding['start']['line']}\n"
                output += f"   代码: {finding['extra']['lines']}\n\n"
    
    print(output)
    
    # 保存到文件
    if args.save:
        with open(args.save, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"结果已保存到: {args.save}")

if __name__ == "__main__":
    main()
