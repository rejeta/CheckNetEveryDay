"""
文件扫描模块

负责扫描目录，查找JSONL文件
"""
import os
from pathlib import Path
from typing import List, Optional


class FileScanner:
    """文件扫描器"""

    def __init__(self, data_dir: Optional[str] = None):
        """
        初始化文件扫描器

        Args:
            data_dir: 数据目录路径
        """
        self.data_dir = data_dir or 'data'

    def scan_directory(self, directory: Optional[str] = None) -> List[str]:
        """
        扫描目录中的所有JSONL文件

        Args:
            directory: 目录路径，默认为初始化时指定的目录

        Returns:
            JSONL文件路径列表
        """
        scan_dir = directory or self.data_dir

        if not os.path.exists(scan_dir):
            print(f"警告: 目录不存在 - {scan_dir}")
            return []

        jsonl_files = []

        try:
            # 递归扫描所有.jsonl文件
            for root, dirs, files in os.walk(scan_dir):
                for file in files:
                    if file.endswith('.jsonl'):
                        file_path = os.path.join(root, file)
                        jsonl_files.append(file_path)

            if not jsonl_files:
                print(f"提示: 目录中未找到JSONL文件 - {scan_dir}")
            else:
                print(f"找到 {len(jsonl_files)} 个JSONL文件:")
                for file_path in jsonl_files:
                    file_size = Path(file_path).stat().st_size / 1024  # KB
                    print(f"  - {file_path} ({file_size:.2f} KB)")

        except Exception as e:
            print(f"错误: 扫描目录失败 - {e}")

        # 按文件名排序
        jsonl_files.sort()

        return jsonl_files

    def scan_single_file(self, file_path: str) -> Optional[str]:
        """
        扫描单个JSONL文件

        Args:
            file_path: 文件路径

        Returns:
            文件路径（如果存在），否则返回None
        """
        if not os.path.exists(file_path):
            print(f"错误: 文件不存在 - {file_path}")
            return None

        if not file_path.endswith('.jsonl'):
            print(f"警告: 文件不是JSONL格式 - {file_path}")
            # 仍然返回，让解析器去处理

        file_size = Path(file_path).stat().st_size / 1024  # KB
        print(f"找到文件: {file_path} ({file_size:.2f} KB)")

        return file_path

    def get_file_info(self, file_path: str) -> dict:
        """
        获取文件详细信息

        Args:
            file_path: 文件路径

        Returns:
            文件信息字典
        """
        if not os.path.exists(file_path):
            return {
                'exists': False,
                'path': file_path,
            }

        path = Path(file_path)
        stat = path.stat()

        return {
            'exists': True,
            'path': str(path),
            'name': path.name,
            'size_bytes': stat.st_size,
            'size_kb': stat.st_size / 1024,
            'size_mb': stat.st_size / (1024 * 1024),
            'is_file': path.is_file(),
            'is_jsonl': file_path.endswith('.jsonl'),
        }

    def filter_by_size(self, file_paths: List[str], max_size_mb: float) -> List[str]:
        """
        按文件大小过滤

        Args:
            file_paths: 文件路径列表
            max_size_mb: 最大文件大小（MB）

        Returns:
            符合大小限制的文件路径列表
        """
        filtered = []
        max_size_bytes = max_size_mb * 1024 * 1024

        for file_path in file_paths:
            try:
                file_size = Path(file_path).stat().st_size
                if file_size <= max_size_bytes:
                    filtered.append(file_path)
                else:
                    size_mb = file_size / (1024 * 1024)
                    print(f"跳过: {file_path} (大小 {size_mb:.2f}MB 超过限制 {max_size_mb}MB)")
            except Exception as e:
                print(f"警告: 获取文件大小失败 {file_path} - {e}")

        return filtered

    def validate_files(self, file_paths: List[str]) -> List[str]:
        """
        验证文件列表，只返回存在的JSONL文件

        Args:
            file_paths: 文件路径列表

        Returns:
            有效的JSONL文件路径列表
        """
        valid_files = []

        for file_path in file_paths:
            if not os.path.exists(file_path):
                print(f"跳过: 文件不存在 - {file_path}")
                continue

            if not os.path.isfile(file_path):
                print(f"跳过: 不是文件 - {file_path}")
                continue

            if not file_path.endswith('.jsonl'):
                print(f"警告: 文件不是.jsonl扩展名 - {file_path}")

            valid_files.append(file_path)

        return valid_files
