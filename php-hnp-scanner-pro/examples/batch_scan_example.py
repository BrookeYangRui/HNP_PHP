#!/usr/bin/env python3
"""
批量扫描示例脚本
演示如何使用批量 HNP 扫描器
"""
import subprocess
import sys
from pathlib import Path

def run_batch_scan():
    """运行批量扫描示例"""
    
    # 1. 创建示例仓库列表
    repo_list = Path("examples/sample_repos.txt")
    repo_list.write_text("""# 示例仓库列表
https://github.com/laravel/laravel
https://github.com/WordPress/WordPress
https://github.com/symfony/symfony
""", encoding="utf-8")
    
    print("🚀 开始批量 HNP 扫描示例")
    print("=" * 50)
    
    # 2. 运行批量扫描
    cmd = [
        sys.executable, "cli/batch_hnp_scan.py",
        str(repo_list),
        "--min-score", "HIGH",
        "--output-dir", "batch_demo_out",
        "--clone-dir", "temp_demo_repos",
        "--clone-timeout", "180"
    ]
    
    print(f"执行命令: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(cmd, cwd=Path(__file__).parent.parent, 
                              capture_output=True, text=True, timeout=1800)
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        print(f"返回码: {result.returncode}")
        
        # 3. 显示结果
        output_dir = Path("batch_demo_out")
        if output_dir.exists():
            print("\n📊 扫描结果:")
            print(f"- 报告: {output_dir}/batch-report.md")
            print(f"- 详细结果: {output_dir}/batch-results.json")
            print(f"- CSV 汇总: {output_dir}/batch-summary.csv")
            
            # 显示报告摘要
            report_file = output_dir / "batch-report.md"
            if report_file.exists():
                print("\n📋 报告摘要:")
                print("-" * 30)
                with report_file.open("r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for line in lines[:20]:  # 显示前20行
                        print(line.rstrip())
                if len(lines) > 20:
                    print("... (更多内容请查看完整报告)")
        
    except subprocess.TimeoutExpired:
        print("⏰ 扫描超时")
    except Exception as e:
        print(f"❌ 执行失败: {e}")

if __name__ == "__main__":
    run_batch_scan()
