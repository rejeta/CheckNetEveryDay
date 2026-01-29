"""
时间处理工具

提供时间解析、格式化、分布统计等功能
"""
from datetime import datetime, time
from typing import List, Dict, Any
from collections import Counter
from dateutil import parser as date_parser


class TimeParser:
    """时间解析器"""

    # ISO 8601时间戳格式
    ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"

    @staticmethod
    def parse(timestamp: str) -> datetime:
        """
        解析ISO 8601格式的时间戳

        Args:
            timestamp: 时间戳字符串

        Returns:
            datetime对象
        """
        try:
            # 尝试使用dateutil解析（支持多种格式）
            return date_parser.parse(timestamp)
        except Exception:
            # 回退到ISO格式解析
            try:
                # 处理不同的ISO 8601变体
                timestamp = timestamp.replace('+08:00', '+0800')
                timestamp = timestamp.replace(':', '')
                return datetime.strptime(timestamp, TimeParser.ISO_FORMAT)
            except Exception:
                print(f"警告: 无法解析时间戳: {timestamp}")
                return datetime.now()

    @staticmethod
    def format(dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
        """
        格式化datetime对象

        Args:
            dt: datetime对象
            fmt: 格式字符串

        Returns:
            格式化后的时间字符串
        """
        return dt.strftime(fmt)

    @staticmethod
    def get_hour(dt: datetime) -> int:
        """获取小时（0-23）"""
        return dt.hour

    @staticmethod
    def get_date(dt: datetime) -> str:
        """获取日期字符串"""
        return dt.strftime("%Y-%m-%d")

    @staticmethod
    def is_night_time(dt: datetime) -> bool:
        """
        判断是否为夜间时间（22:00-06:00）

        Args:
            dt: datetime对象

        Returns:
            True if 夜间, False otherwise
        """
        hour = dt.hour
        return hour >= 22 or hour < 6

    @staticmethod
    def is_weekend(dt: datetime) -> bool:
        """
        判断是否为周末（周六、周日）

        Args:
            dt: datetime对象

        Returns:
            True if 周末, False otherwise
        """
        # weekday(): Monday=0, Sunday=6
        return dt.weekday() >= 5

    @staticmethod
    def is_working_hours(dt: datetime) -> bool:
        """
        判断是否为工作时间（周一到周五，9:00-18:00）

        Args:
            dt: datetime对象

        Returns:
            True if 工作时间, False otherwise
        """
        if TimeParser.is_weekend(dt):
            return False
        hour = dt.hour
        return 9 <= hour < 18

    @staticmethod
    def get_time_period(dt: datetime) -> str:
        """
        获取时间段分类

        Args:
            dt: datetime对象

        Returns:
            时间段字符串: "凌晨"、"上午"、"下午"、"傍晚"、"深夜"
        """
        hour = dt.hour
        if 0 <= hour < 6:
            return "凌晨"
        elif 6 <= hour < 9:
            return "上午"
        elif 9 <= hour < 12:
            return "上午"
        elif 12 <= hour < 14:
            return "下午"
        elif 14 <= hour < 18:
            return "下午"
        elif 18 <= hour < 22:
            return "傍晚"
        else:
            return "深夜"

    @staticmethod
    def get_time_range(timestamps: List[str]) -> Dict[str, Any]:
        """
        获取时间范围信息

        Args:
            timestamps: 时间戳列表

        Returns:
            包含时间范围信息的字典
        """
        if not timestamps:
            return {
                'start': None,
                'end': None,
                'duration_seconds': 0,
                'duration_hours': 0,
            }

        parsed = [TimeParser.parse(ts) for ts in timestamps]
        start = min(parsed)
        end = max(parsed)
        duration = end - start

        return {
            'start': start,
            'end': end,
            'start_str': TimeParser.format(start),
            'end_str': TimeParser.format(end),
            'duration_seconds': duration.total_seconds(),
            'duration_hours': duration.total_seconds() / 3600,
            'duration_days': duration.total_seconds() / 86400,
        }

    @staticmethod
    def get_hour_distribution(timestamps: List[str]) -> Dict[int, int]:
        """
        获取按小时的连接分布

        Args:
            timestamps: 时间戳列表

        Returns:
            按小时（0-23）统计的字典
        """
        hours = [TimeParser.parse(ts).hour for ts in timestamps]
        return dict(Counter(hours))

    @staticmethod
    def get_date_distribution(timestamps: List[str]) -> Dict[str, int]:
        """
        获取按日期的连接分布

        Args:
            timestamps: 时间戳列表

        Returns:
            按日期统计的字典
        """
        dates = [TimeParser.get_date(TimeParser.parse(ts)) for ts in timestamps]
        return dict(Counter(dates))

    @staticmethod
    def get_time_period_distribution(timestamps: List[str]) -> Dict[str, int]:
        """
        获取按时间段的连接分布

        Args:
            timestamps: 时间戳列表

        Returns:
            按时间段统计的字典
        """
        periods = [TimeParser.get_time_period(TimeParser.parse(ts)) for ts in timestamps]
        return dict(Counter(periods))

    @staticmethod
    def get_abnormal_time_connections(timestamps: List[str]) -> List[str]:
        """
        获取非正常时间段的连接时间戳

        Args:
            timestamps: 时间戳列表

        Returns:
            非正常时间（夜间、周末工作时间）的时间戳列表
        """
        abnormal = []
        for ts in timestamps:
            dt = TimeParser.parse(ts)
            if TimeParser.is_night_time(dt):
                abnormal.append(ts)
            elif TimeParser.is_weekend(dt) and TimeParser.is_working_hours(dt):
                abnormal.append(ts)
        return abnormal

    @staticmethod
    def format_duration(seconds: float) -> str:
        """
        格式化时长

        Args:
            seconds: 秒数

        Returns:
            格式化的时长字符串
        """
        if seconds < 60:
            return f"{seconds:.1f}秒"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}分钟"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.1f}小时"
        else:
            days = seconds / 86400
            return f"{days:.1f}天"
