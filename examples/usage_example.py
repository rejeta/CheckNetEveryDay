#!/usr/bin/env python3
"""
Windows网络流量智能分析工具 - 使用示例

展示如何使用本工具进行网络日志分析
"""

import os
import subprocess
import sys
from pathlib import Path


def run_example_example():
    """运行示例分析"""

    print("="*70)
    print("Windows网络流量智能分析工具 - 使用示例")
    print("="*70)

    # 示例1: 分析单个文件
    print("\n1. 分析单个JSONL文件（禁用AI分析）:")
    print("-" * 50)
    cmd1 = ["python", "src/main.py", "--file", "net_2026-01-21.jsonl", "--no-ai"]

    # 运行命令
    try:
        result = subprocess.run(cmd1, capture_output=True, text=True, timeout=120)
        print("运行结果:")
        print(result.stdout)
        if result.stderr:
            print("错误信息:")
            print(result.stderr)
    except subprocess.TimeoutExpired:
        print("命令执行超时")

    # 示例2: 生成AI分析报告（需要配置API Key）
    print("\n2. 生成AI分析报告（需要配置API Key）:")
    print("-" * 50)
    print("配置方法:")
    print("1. 选择AI服务商并获取API Key")
    print("2. 设置环境变量: export AI_API_KEY='your_api_key'")
    print("3. 或编辑 config/config.yaml 添加api_key")
    print("\n4. 然后运行:")
    cmd2 = ["python", "src/main.py", "--file", "net_2026-01-21.jsonl"]
    print(" ".join(cmd2))

    # 示例3: 分析整个目录
    print("\n3. 分析整个目录:")
    print("-" * 50)
    cmd3 = ["python", "src/main.py", "--dir", "data/"]
    print(" ".join(cmd3))

    # 示例4: 指定输出目录
    print("\n4. 指定输出目录:")
    print("-" * 50)
    cmd4 = ["python", "src/main.py", "--dir", "data/", "--output", "custom_output/"]
    print(" ".join(cmd4))

    # 示例5: 使用不同AI模型
    print("\n5. 使用不同AI模型:")
    print("-" * 50)
    print("智谱AI (推荐):")
    cmd5a = ["python", "src/main.py", "--file", "net_2026-01-21.jsonl", "--model", "zhipu"]
    print(" ".join(cmd5a))

    print("\n阿里云Qwen:")
    cmd5b = ["python", "src/main.py", "--file", "net_2026-01-21.jsonl", "--model", "qwen"]
    print(" ".join(cmd5b))

    print("\n月之暗面Kimi:")
    cmd5c = ["python", "src/main.py", "--file", "net_2026-01-21.jsonl", "--model", "kimi"]
    print(" ".join(cmd5c))

    print("\n" + "="*70)
    print("示例说明:")
    print("="*70)
    print("- 第1个示例展示了基础的日志分析功能")
    print("- AI分析需要配置API Key才能运行")
    print("- 建议先测试无AI分析模式，确认数据格式正确后再启用AI分析")
    print("- 输出的Markdown报告会保存在output/目录下")
    print("="*70)


if __name__ == "__main__":
    # 切换到脚本所在目录
    os.chdir(Path(__file__).parent.parent)
    run_example_example()