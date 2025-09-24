#!/usr/bin/env python3
"""
清理tmp文件夹中的临时项目
"""
import shutil
import os
from pathlib import Path

def cleanup_tmp():
    """清理tmp文件夹中的所有内容"""
    tmp_dir = Path("tmp")
    
    if not tmp_dir.exists():
        print("tmp文件夹不存在，无需清理")
        return
    
    # 获取tmp文件夹中的所有内容
    items = list(tmp_dir.iterdir())
    
    if not items:
        print("tmp文件夹为空，无需清理")
        return
    
    print(f"发现 {len(items)} 个临时项目，开始清理...")
    
    # 删除所有内容
    for item in items:
        try:
            if item.is_dir():
                shutil.rmtree(item)
                print(f"✅ 已删除目录: {item.name}")
            else:
                item.unlink()
                print(f"✅ 已删除文件: {item.name}")
        except Exception as e:
            print(f"❌ 删除失败 {item.name}: {e}")
    
    print("清理完成！")

if __name__ == "__main__":
    cleanup_tmp()
