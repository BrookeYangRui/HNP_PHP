# tmp 文件夹说明

这个文件夹专门用于存放临时克隆的Git项目，用于HNP扫描器测试。

## 功能特点

- **自动创建**: 扫描器会自动创建此文件夹（如果不存在）
- **自动清理**: 每次扫描完成后自动删除临时项目
- **隔离存储**: 避免在项目根目录产生临时文件

## 使用方法

### 自动使用（推荐）
扫描器会自动使用此文件夹，无需手动操作：
```bash
cd /home/rui/HNP_PHP/php-hnp-scanner-pro
source .venv/bin/activate
python hnp_scanner.py
```

### 手动清理
如果需要手动清理所有临时文件：
```bash
cd /home/rui/HNP_PHP
python cleanup_tmp.py
```

## 注意事项

- 此文件夹中的内容会在扫描完成后自动删除
- 不要在此文件夹中存放重要文件
- 如果扫描过程中断，可能需要手动清理残留文件
