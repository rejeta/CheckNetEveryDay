"""
JSONL文件解析模块

负责解析JSONL格式的网络连接日志文件
"""
import json
import chardet
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path


class JSONLParser:
    """JSONL文件解析器"""

    # 期望的字段列表
    EXPECTED_FIELDS = [
        'timestamp', 'process', 'command_line',
        'user', 'dest_ip', 'dest_port',
        'protocol', 'domain', 'source'
    ]

    def __init__(self, max_size_mb: int = 10):
        """
        初始化解析器

        Args:
            max_size_mb: 最大文件大小限制（MB）
        """
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.errors = []

    def detect_encoding(self, file_path: str) -> str:
        """
        检测文件编码

        Args:
            file_path: 文件路径

        Returns:
            编码名称，如 'utf-8', 'gbk'
        """
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read(10000)  # 读取前10KB来检测编码
                result = chardet.detect(raw_data)
                encoding = result['encoding']
                confidence = result['confidence']

                # 如果置信度太低，使用默认编码
                if confidence < 0.7:
                    encoding = 'utf-8'

                return encoding or 'utf-8'
        except Exception as e:
            print(f"警告: 检测编码失败 - {e}，使用UTF-8")
            return 'utf-8'

    def check_file_size(self, file_path: str) -> bool:
        """
        检查文件大小是否在限制范围内

        Args:
            file_path: 文件路径

        Returns:
            True if 文件大小符合要求, False otherwise
        """
        try:
            file_size = Path(file_path).stat().st_size
            if file_size > self.max_size_bytes:
                size_mb = file_size / (1024 * 1024)
                print(f"警告: 文件 {file_path} 大小 {size_mb:.2f}MB 超过限制 {self.max_size_bytes / (1024 * 1024)}MB")
                return False
            return True
        except Exception as e:
            print(f"错误: 检查文件大小失败 - {e}")
            return False

    def parse_line(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """
        解析单行JSONL数据

        Args:
            line: JSONL行字符串
            line_num: 行号

        Returns:
            解析后的字典，解析失败返回None
        """
        line = line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
            return data
        except json.JSONDecodeError as e:
            error_msg = f"第{line_num}行: JSON解析失败 - {e}"
            self.errors.append(error_msg)
            return None

    def validate_record(self, record: Dict[str, Any], line_num: int) -> bool:
        """
        验证记录是否包含必要字段

        Args:
            record: 记录字典
            line_num: 行号

        Returns:
            True if 验证通过, False otherwise
        """
        missing_fields = []
        for field in self.EXPECTED_FIELDS:
            if field not in record:
                missing_fields.append(field)

        if missing_fields:
            error_msg = f"第{line_num}行: 缺少字段 {missing_fields}"
            self.errors.append(error_msg)
            return False

        return True

    def parse_file(self, file_path: str, validate: bool = True) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        解析JSONL文件

        Args:
            file_path: JSONL文件路径
            validate: 是否验证字段完整性

        Returns:
            (记录列表, 错误列表)
        """
        self.errors = []
        records = []

        # 检查文件大小
        if not self.check_file_size(file_path):
            return records, self.errors

        # 检测编码
        encoding = self.detect_encoding(file_path)
        print(f"使用编码: {encoding} 解析文件: {file_path}")

        # 解析文件
        line_num = 0
        try:
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                for line in f:
                    line_num += 1

                    # 解析单行
                    record = self.parse_line(line, line_num)
                    if record is None:
                        continue

                    # 验证字段
                    if validate and not self.validate_record(record, line_num):
                        continue

                    records.append(record)

            print(f"成功解析 {len(records)} 条记录，遇到 {len(self.errors)} 个错误")

        except Exception as e:
            error_msg = f"读取文件失败: {e}"
            self.errors.append(error_msg)
            print(f"错误: {error_msg}")

        return records, self.errors

    def parse_multiple_files(self, file_paths: List[str], validate: bool = True) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        解析多个JSONL文件

        Args:
            file_paths: JSONL文件路径列表
            validate: 是否验证字段完整性

        Returns:
            (所有记录列表, 所有错误列表)
        """
        all_records = []
        all_errors = []

        for file_path in file_paths:
            print(f"\n解析文件: {file_path}")
            records, errors = self.parse_file(file_path, validate)
            all_records.extend(records)
            all_errors.extend(errors)

        print(f"\n总计: 解析 {len(all_records)} 条记录，{len(all_errors)} 个错误")
        return all_records, all_errors

    def get_error_summary(self, errors: List[str]) -> str:
        """
        获取错误摘要

        Args:
            errors: 错误列表

        Returns:
            错误摘要字符串
        """
        if not errors:
            return "无错误"

        summary = f"共 {len(errors)} 个错误:\n"
        # 只显示前20个错误
        for error in errors[:20]:
            summary += f"  - {error}\n"

        if len(errors) > 20:
            summary += f"  ... 还有 {len(errors) - 20} 个错误\n"

        return summary

    def extract_field_values(self, records: List[Dict[str, Any]], field: str) -> List[Any]:
        """
        从记录列表中提取指定字段的所有值

        Args:
            records: 记录列表
            field: 字段名

        Returns:
            字段值列表
        """
        return [record.get(field) for record in records if record.get(field)]

    def get_record_summary(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        获取记录摘要信息

        Args:
            records: 记录列表

        Returns:
            摘要信息字典
        """
        if not records:
            return {
                'total_count': 0,
                'field_counts': {field: 0 for field in self.EXPECTED_FIELDS},
            }

        summary = {
            'total_count': len(records),
        }

        # 统计每个字段的非空数量
        for field in self.EXPECTED_FIELDS:
            non_empty_count = sum(
                1 for record in records
                if record.get(field) not in [None, '']
            )
            summary[f'{field}_count'] = non_empty_count

        return summary
