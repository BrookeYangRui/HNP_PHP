#!/usr/bin/env python3
"""
HNP Framework CLI - Download and manage PHP web frameworks for HNP analysis
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


FRAMEWORKS = [
    {
        "id": 1,
        "name": "Laravel",
        "repo": "https://github.com/laravel/laravel.git",
        "dir": "laravel",
    },
    {
        "id": 2,
        "name": "Symfony",
        "repo": "https://github.com/symfony/symfony-demo.git",
        "dir": "symfony",
    },
    {
        "id": 3,
        "name": "CodeIgniter",
        "repo": "https://github.com/codeigniter4/CodeIgniter4.git",
        "dir": "codeigniter",
    },
    {
        "id": 4,
        "name": "CakePHP",
        "repo": "https://github.com/cakephp/app.git",
        "dir": "cakephp",
    },
    {
        "id": 5,
        "name": "Yii",
        "repo": "https://github.com/yiisoft/yii2-app-basic.git",
        "dir": "yii",
    },
    {
        "id": 6,
        "name": "Slim",
        "repo": "https://github.com/slimphp/Slim-Skeleton.git",
        "dir": "slim",
    },
    {
        "id": 7,
        "name": "Laminas",
        "repo": "https://github.com/laminas/laminas-mvc-skeleton.git",
        "dir": "laminas",
    },
    {
        "id": 8,
        "name": "Phalcon",
        "repo": "https://github.com/phalcon/cphalcon.git",
        "dir": "phalcon",
    },
]


PROJECT_ROOT = "/home/rui/HNP_PHP"
FRAMEWORK_DIR = os.path.join(PROJECT_ROOT, "frameworks")
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports", "framework")


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def ensure_dirs() -> None:
    os.makedirs(FRAMEWORK_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)


def list_frameworks() -> None:
    print("Available PHP Web Frameworks:")
    for fw in FRAMEWORKS:
        print(f"  {fw['id']}. {fw['name']}")


def find_framework_by_id(choice: int) -> Optional[Dict]:
    for fw in FRAMEWORKS:
        if fw["id"] == choice:
            return fw
    return None


def run_cmd(cmd: List[str], cwd: Optional[str] = None) -> int:
    try:
        proc = subprocess.run(cmd, cwd=cwd, check=False)
        return proc.returncode
    except FileNotFoundError:
        eprint(f"Command not found: {' '.join(cmd)}")
        return 127


def git_clone_or_update(repo_url: str, dest_dir: str) -> None:
    if not shutil.which("git"):
        eprint("git not installed, please install git first")
        sys.exit(2)

    if os.path.isdir(dest_dir) and os.path.isdir(os.path.join(dest_dir, ".git")):
        print(f"Updating existing repository: {dest_dir}")
        code = run_cmd(["git", "pull", "--ff-only"], cwd=dest_dir)
        if code != 0:
            eprint("git pull failed, please check repository status")
            sys.exit(code)
        return

    if os.path.exists(dest_dir):
        eprint(f"Target directory exists but is not a git repository: {dest_dir}")
        sys.exit(1)

    print(f"Cloning {repo_url} -> {dest_dir}")
    code = run_cmd(["git", "clone", "--depth", "1", repo_url, dest_dir])
    if code != 0:
        eprint("git clone failed")
        sys.exit(code)


def download_framework(choice: int) -> str:
    fw = find_framework_by_id(choice)
    if not fw:
        eprint("Invalid selection")
        sys.exit(1)
    dest = os.path.join(FRAMEWORK_DIR, fw["dir"])
    git_clone_or_update(fw["repo"], dest)
    print(f"✅ Download completed: {fw['name']} -> {dest}")
    return dest


def interactive_menu() -> None:
    list_frameworks()
    try:
        choice = int(input("Enter framework number to download: ").strip())
    except ValueError:
        eprint("Please enter a valid number")
        sys.exit(1)
    download_framework(choice)


def main():
    ensure_dirs()
    parser = argparse.ArgumentParser(description="HNP Framework CLI")
    parser.add_argument("--list", action="store_true", help="List supported frameworks")
    parser.add_argument("--download", type=int, help="Download framework by number")
    parser.add_argument("--interactive", action="store_true", help="Interactive download")
    args = parser.parse_args()

    if args.list:
        list_frameworks()
        return

    if args.download is not None:
        download_framework(args.download)
        return

    if args.interactive or (not args.list and args.download is None):
        interactive_menu()


if __name__ == "__main__":
    main()


