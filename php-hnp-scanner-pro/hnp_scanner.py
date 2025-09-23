#!/usr/bin/env python3
"""
迭代式 HNP 扫描脚本 - 一个项目一个项目扫描，验证和补全规则
"""
import subprocess
import sys
import json
import csv
import time
import shutil
from pathlib import Path

def check_single_repo(repo_url, repo_name, expected_vuln, stars, year, index):
    """检查单个仓库并返回结果"""
    print(f"\n🔍 检查: {repo_name}")
    print(f"   预期: {expected_vuln}")
    
    # 克隆仓库
    clone_cmd = ["git", "clone", "--depth", "1", repo_url, f"temp_{repo_name}"]
    try:
        print("   正在克隆...")
        clone_result = subprocess.run(clone_cmd, capture_output=True, timeout=30)
        if clone_result.returncode != 0:
            print(f"   ❌ 克隆失败: {clone_result.stderr.decode('utf-8', errors='ignore')[:200]}")
            return {"status": "clone_failed", "findings": []}
        
        # 扫描
        print("   正在扫描...")
        cmd = [
            "semgrep", "scan",
            "--config", "rules/php-hnp.yml",
            "--json",
            "--include", "*.php",
            "--exclude", "vendor/",
            "--exclude", "node_modules/",
            "--exclude", ".git/",
            str(f"temp_{repo_name}")
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, encoding='utf-8', errors='ignore')
        
        findings = []
        if result.returncode == 0:
            data = json.loads(result.stdout)
            findings = data.get("results", [])
            print(f"   ✅ 找到 {len(findings)} 个 HNP 问题")
        else:
            print(f"   ❌ 扫描失败")
        
        # 清理
        shutil.rmtree(f"temp_{repo_name}", ignore_errors=True)
        
        return {"status": "success", "findings": findings}
        
    except subprocess.TimeoutExpired:
        print(f"   ⏰ 超时跳过 (需要手动测试)")
        # 清理
        shutil.rmtree(f"temp_{repo_name}", ignore_errors=True)
        return {"status": "timeout", "findings": []}
    except Exception as e:
        print(f"   ❌ 检查失败: {e}")
        # 清理
        shutil.rmtree(f"temp_{repo_name}", ignore_errors=True)
        return {"status": "error", "findings": []}

def analyze_finding(finding, project_path):
    """分析单个发现"""
    path = finding.get("path", "?")
    line = finding.get("start", {}).get("line", "?")
    
    # 获取相对路径
    rel_path = path.replace(str(project_path) + "\\", "").replace(str(project_path) + "/", "")
    
    # 获取源码片段和上下文
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        if line <= len(lines):
            source_code = lines[line - 1].strip()
            # 获取前后3行上下文
            start_line = max(1, line - 3)
            end_line = min(len(lines), line + 3)
            context_lines = []
            for i in range(start_line, end_line + 1):
                prefix = ">>> " if i == line else "    "
                context_lines.append(f"{prefix}{i:3d}: {lines[i-1].rstrip()}")
            context = "\\n".join(context_lines)
        else:
            source_code = "无法获取"
            context = "无法获取"
    except Exception as e:
        source_code = f"无法获取: {str(e)}"
        context = f"无法获取: {str(e)}"
    
    # 分析问题类型
    if "HTTP_HOST" in source_code:
        problem_type = "HTTP_HOST_Usage"
    elif "HTTP_X_FORWARDED_HOST" in source_code:
        problem_type = "X_FORWARDED_HOST_Usage"
    else:
        problem_type = "Unknown"
    
    # 分析 Sink 和利用场景
    sink_info = analyze_sink(source_code, context)
    
    return {
        "file_path": rel_path,
        "line_number": line,
        "problem_type": problem_type,
        "sink_type": sink_info["sink_type"],
        "sink_function": sink_info["sink_function"],
        "exploit_scenario": sink_info["exploit_scenario"],
        "risk_level": sink_info["risk_level"],
        "source_code": source_code,
        "context": context
    }

def analyze_sink(source_code, context):
    """分析 Sink 类型和利用场景"""
    code_lower = source_code.lower()
    context_lower = context.lower()
    
    # 重定向类 Sink - 检查上下文中的 header() 调用
    if "header(" in context_lower and ("location" in context_lower or "redirect" in context_lower):
        return {
            "sink_type": "Redirect_Sink",
            "sink_function": "header()/redirect()",
            "exploit_scenario": "攻击者可以重定向用户到恶意网站，进行钓鱼攻击",
            "risk_level": "HIGH"
        }
    
    # 邮件类 Sink
    elif any(keyword in code_lower for keyword in ["mail(", "email", "smtp", "phpmailer", "swiftmailer"]):
        return {
            "sink_type": "Email_Sink", 
            "sink_function": "mail()/PHPMailer/SwiftMailer",
            "exploit_scenario": "攻击者可以发送包含恶意链接的邮件，进行钓鱼攻击",
            "risk_level": "HIGH"
        }
    
    # 输出类 Sink
    elif any(keyword in code_lower for keyword in ["echo", "print", "printf", "var_dump"]):
        return {
            "sink_type": "Output_Sink",
            "sink_function": "echo/print/output",
            "exploit_scenario": "攻击者可以注入恶意脚本，进行XSS攻击",
            "risk_level": "MEDIUM"
        }
    
    # 文件包含类 Sink
    elif any(keyword in code_lower for keyword in ["include", "require", "include_once", "require_once"]):
        return {
            "sink_type": "File_Inclusion_Sink",
            "sink_function": "include/require",
            "exploit_scenario": "攻击者可以包含恶意文件，执行任意代码",
            "risk_level": "CRITICAL"
        }
    
    # 数据库类 Sink
    elif any(keyword in code_lower for keyword in ["query", "execute", "prepare", "mysqli", "pdo"]):
        return {
            "sink_type": "Database_Sink",
            "sink_function": "SQL query functions",
            "exploit_scenario": "攻击者可以注入恶意SQL，进行SQL注入攻击",
            "risk_level": "HIGH"
        }
    
    # URL构造类 Sink - 检查 return 语句中的 URL 构造
    elif ("return" in code_lower and ("http://" in code_lower or "https://" in code_lower)) or \
         any(keyword in code_lower for keyword in ["url", "link", "href", "src", "action"]):
        return {
            "sink_type": "URL_Construction_Sink",
            "sink_function": "URL construction",
            "exploit_scenario": "攻击者可以构造恶意URL，进行钓鱼或重定向攻击",
            "risk_level": "MEDIUM"
        }
    
    # 文件操作类 Sink
    elif any(keyword in code_lower for keyword in ["file_", "fopen", "fwrite", "copy", "move"]):
        return {
            "sink_type": "File_Operation_Sink",
            "sink_function": "File operations",
            "exploit_scenario": "攻击者可以操作文件系统，进行文件上传或路径遍历攻击",
            "risk_level": "HIGH"
        }
    
    # 配置类 Sink
    elif any(keyword in code_lower for keyword in ["config", "setting", "define", "ini_set"]):
        return {
            "sink_type": "Configuration_Sink",
            "sink_function": "Configuration",
            "exploit_scenario": "攻击者可以修改配置，影响应用行为",
            "risk_level": "MEDIUM"
        }
    
    # 日志类 Sink
    elif any(keyword in code_lower for keyword in ["log", "error_log", "syslog"]):
        return {
            "sink_type": "Logging_Sink",
            "sink_function": "Logging functions",
            "exploit_scenario": "攻击者可以注入恶意内容到日志，可能影响日志分析",
            "risk_level": "LOW"
        }
    
    # 默认情况
    else:
        return {
            "sink_type": "Unknown_Sink",
            "sink_function": "Unknown",
            "exploit_scenario": "需要进一步分析具体的利用场景",
            "risk_level": "LOW"
        }

def update_rules_based_on_findings(findings, repo_name):
    """根据发现更新规则"""
    if not findings:
        return
    
    print(f"   📝 分析发现，准备更新规则...")
    
    # 分析发现的模式
    patterns_found = set()
    for finding in findings:
        source_code = finding.get("source_code", "")
        if "HTTP_HOST" in source_code:
            patterns_found.add("HTTP_HOST")
        if "HTTP_X_FORWARDED_HOST" in source_code:
            patterns_found.add("HTTP_X_FORWARDED_HOST")
    
    # 检查当前规则是否覆盖了这些模式
    current_rules = Path("rules/php-hnp.yml").read_text(encoding='utf-8')
    
    needs_update = False
    for pattern in patterns_found:
        if pattern not in current_rules:
            print(f"   ⚠️  发现新模式: {pattern}")
            needs_update = True
    
    if needs_update:
        print(f"   🔧 需要更新规则文件")
        # 这里可以添加自动更新规则的逻辑
        # 暂时只是记录
        with open("rule_updates_needed.txt", "a", encoding='utf-8') as f:
            f.write(f"\\n{repo_name}: 需要添加模式 {patterns_found}\\n")

def main():
    """主函数"""
    # 读取 CSV 文件
    csv_file = Path("C:/Users/brook/code/HNP_PHP/defense_result_php.csv")
    if not csv_file.exists():
        print("❌ CSV 文件不存在")
        return
    
    # 创建输出 CSV
    output_file = "hnp_iterative_results.csv"
    manual_test_file = "manual_test_required.txt"
    rule_updates_file = "rule_updates_needed.txt"
    
    # 写入表头
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Index', 'Repository', 'URL', 'Stars', 'Year', 'Expected_Vuln_Type',
            'Has_HNP_Issue', 'Total_Findings', 'File_Path', 'Line_Number',
            'Problem_Type', 'Sink_Type', 'Sink_Function', 'Exploit_Scenario', 
            'Risk_Level', 'Source_Code', 'Context', 'Status'
        ])
    
    # 创建手动测试记录文件
    with open(manual_test_file, 'w', encoding='utf-8') as f:
        f.write("需要手动测试的项目列表\\n")
        f.write("=" * 50 + "\\n\\n")
    
    # 创建规则更新记录文件
    with open(rule_updates_file, 'w', encoding='utf-8') as f:
        f.write("需要更新的规则模式\\n")
        f.write("=" * 50 + "\\n\\n")
    
    # 读取项目列表
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        projects = list(reader)
    
    print(f"📋 总共 {len(projects)} 个项目，将扫描前 50 个")
    
    # 统计信息
    total_checked = 0
    total_with_hnp = 0
    total_findings = 0
    timeout_count = 0
    error_count = 0
    
    # 检查前50个项目
    for i, project in enumerate(projects[:50]):
        print(f"\\n🔄 进度: {i+1}/50")
        
        repo_name = project['Repository'].replace('/', '_')
        result = check_single_repo(
            project['URL'],
            project['Repository'],
            project['Matched Function'],
            project['Stars'],
            project['Year'],
            project['Index']
        )
        
        status = result["status"]
        findings = result["findings"]
        
        total_checked += 1
        if status == "timeout":
            timeout_count += 1
            # 记录到手动测试文件
            with open(manual_test_file, 'a', encoding='utf-8') as f:
                f.write(f"{project['Index']}. {project['Repository']}\\n")
                f.write(f"   URL: {project['URL']}\\n")
                f.write(f"   预期: {project['Matched Function']}\\n")
                f.write(f"   原因: 扫描超时 (30秒)\\n\\n")
        elif status == "error":
            error_count += 1
        elif findings:
            total_with_hnp += 1
            total_findings += len(findings)
            # 分析发现并更新规则
            update_rules_based_on_findings(findings, project['Repository'])
        
        # 写入结果到 CSV
        with open(output_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            if findings:
                # 有发现 - 每个发现写一行
                for finding in findings:
                    analyzed = analyze_finding(finding, f"temp_{repo_name}")
                    writer.writerow([
                        project['Index'],
                        project['Repository'],
                        project['URL'],
                        project['Stars'],
                        project['Year'],
                        project['Matched Function'],
                        'YES',
                        len(findings),
                        analyzed['file_path'],
                        analyzed['line_number'],
                        analyzed['problem_type'],
                        analyzed['sink_type'],
                        analyzed['sink_function'],
                        analyzed['exploit_scenario'],
                        analyzed['risk_level'],
                        analyzed['source_code'],
                        analyzed['context'],
                        status
                    ])
            else:
                # 无发现或失败
                writer.writerow([
                    project['Index'],
                    project['Repository'],
                    project['URL'],
                    project['Stars'],
                    project['Year'],
                    project['Matched Function'],
                    'NO' if status == "success" else 'SKIP',
                    0,
                    '',
                    '',
                    '',
                    '',
                    '',
                    '',
                    '',
                    '',
                    status
                ])
        
        print(f"   ✅ 结果已写入 CSV")
        
        # 每10个项目显示一次统计
        if (i + 1) % 10 == 0:
            print(f"\\n📊 当前统计: 检查了 {i+1} 个项目，{total_with_hnp} 个有 HNP 问题，共 {total_findings} 个发现")
    
    print(f"\\n🎉 完成！结果已保存到: {output_file}")
    print(f"📊 最终统计:")
    print(f"   - 总检查项目: {total_checked}")
    print(f"   - 有 HNP 问题: {total_with_hnp}")
    print(f"   - 总发现数量: {total_findings}")
    print(f"   - 超时跳过: {timeout_count}")
    print(f"   - 错误跳过: {error_count}")
    print(f"   - 检测率: {total_with_hnp/total_checked*100:.1f}%")
    print(f"   - 需要手动测试: {timeout_count} 个项目 (记录在 {manual_test_file})")
    print(f"   - 需要更新规则: 查看 {rule_updates_file}")

if __name__ == "__main__":
    main()
