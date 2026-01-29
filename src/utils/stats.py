"""
统计计算工具

提供各种统计分析功能
"""
from typing import List, Dict, Any, Tuple
from collections import Counter, defaultdict


class StatsCalculator:
    """统计计算器"""

    @staticmethod
    def count_total(values: List[Any]) -> int:
        """统计总数"""
        return len(values)

    @staticmethod
    def count_unique(values: List[Any]) -> int:
        """统计唯一值数量"""
        return len(set(values))

    @staticmethod
    def get_top_items(values: List[Any], top_n: int = 10) -> List[Tuple[Any, int]]:
        """
        获取出现频率最高的N项

        Args:
            values: 值列表
            top_n: 返回前N项

        Returns:
            (值, 计数)的列表，按计数降序排列
        """
        counter = Counter(values)
        return counter.most_common(top_n)

    @staticmethod
    def get_percentage(part: int, total: int) -> float:
        """
        计算百分比

        Args:
            part: 部分值
            total: 总数

        Returns:
            百分比值（0-100）
        """
        if total == 0:
            return 0.0
        return (part / total) * 100

    @staticmethod
    def get_distribution(values: List[Any]) -> Dict[Any, int]:
        """
        获取值的分布统计

        Args:
            values: 值列表

        Returns:
            值到计数的字典
        """
        return dict(Counter(values))

    @staticmethod
    def filter_empty_values(values: List[Any]) -> List[Any]:
        """过滤空值"""
        return [v for v in values if v is not None and v != '']

    @staticmethod
    def calculate_protocol_stats(protocol_list: List[str]) -> Dict[str, Any]:
        """
        计算协议统计信息

        Args:
            protocol_list: 协议列表

        Returns:
            包含协议统计的字典
        """
        total = len(protocol_list)
        distribution = StatsCalculator.get_distribution(protocol_list)

        stats = {
            'total': total,
            'distribution': distribution,
            'tcp_count': distribution.get('tcp', 0),
            'udp_count': distribution.get('udp', 0),
            'tcp_percentage': 0.0,
            'udp_percentage': 0.0,
        }

        if total > 0:
            stats['tcp_percentage'] = StatsCalculator.get_percentage(stats['tcp_count'], total)
            stats['udp_percentage'] = StatsCalculator.get_percentage(stats['udp_count'], total)

        return stats

    @staticmethod
    def calculate_process_stats(process_list: List[str], top_n: int = 10) -> Dict[str, Any]:
        """
        计算进程统计信息

        Args:
            process_list: 进程路径列表
            top_n: 返回前N个进程

        Returns:
            包含进程统计的字典
        """
        total = len(process_list)
        top_processes = StatsCalculator.get_top_items(process_list, top_n)

        # 区分系统进程和应用进程
        system_count = sum(1 for p in process_list if p and ('Windows' in p or 'System32' in p.lower()))
        app_count = total - system_count

        stats = {
            'total': total,
            'unique_count': StatsCalculator.count_unique(process_list),
            'top_processes': top_processes,
            'system_process_count': system_count,
            'application_process_count': app_count,
            'system_percentage': StatsCalculator.get_percentage(system_count, total),
            'application_percentage': StatsCalculator.get_percentage(app_count, total),
        }

        return stats

    @staticmethod
    def calculate_user_stats(user_list: List[str]) -> Dict[str, Any]:
        """
        计算用户统计信息

        Args:
            user_list: 用户列表

        Returns:
            包含用户统计的字典
        """
        total = len(user_list)
        distribution = StatsCalculator.get_distribution(user_list)
        top_users = StatsCalculator.get_top_items(user_list, 10)

        # 识别特权账户
        privileged_accounts = [
            'SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE',
            'NT AUTHORITY\\SYSTEM', 'NT AUTHORITY\\NETWORK SERVICE', 'NT AUTHORITY\\LOCAL SERVICE'
        ]
        privileged_count = sum(
            distribution.get(user, 0)
            for user in privileged_accounts
            if user in distribution
        )

        stats = {
            'total': total,
            'unique_count': StatsCalculator.count_unique(user_list),
            'top_users': top_users,
            'privileged_count': privileged_count,
            'privileged_percentage': StatsCalculator.get_percentage(privileged_count, total),
        }

        return stats

    @staticmethod
    def calculate_port_stats(port_list: List[str]) -> Dict[str, Any]:
        """
        计算端口统计信息

        Args:
            port_list: 端口列表

        Returns:
            包含端口统计的字典
        """
        from .ip_utils import IPClassifier

        total = len(port_list)
        distribution = StatsCalculator.get_distribution(port_list)
        top_ports = StatsCalculator.get_top_items(port_list, 20)

        # 统计常见端口
        common_port_count = sum(
            distribution.get(port, 0)
            for port in IPClassifier.COMMON_PORTS.keys()
            if port in distribution
        )

        # 统计高危端口
        high_risk_port_count = sum(
            distribution.get(port, 0)
            for port in IPClassifier.HIGH_RISK_PORTS.keys()
            if port in distribution
        )

        stats = {
            'total': total,
            'unique_count': StatsCalculator.count_unique(port_list),
            'top_ports': top_ports,
            'common_port_count': common_port_count,
            'common_port_percentage': StatsCalculator.get_percentage(common_port_count, total),
            'high_risk_port_count': high_risk_port_count,
            'high_risk_port_percentage': StatsCalculator.get_percentage(high_risk_port_count, total),
        }

        return stats

    @staticmethod
    def calculate_ip_stats(ip_list: List[str]) -> Dict[str, Any]:
        """
        计算IP地址统计信息

        Args:
            ip_list: IP地址列表

        Returns:
            包含IP统计的字典
        """
        from .ip_utils import IPClassifier, IPType

        total = len(ip_list)
        unique_ips = StatsCalculator.count_unique(ip_list)
        top_ips = StatsCalculator.get_top_items(ip_list, 20)

        # 统计IPv4/IPv6分布
        ip_types = []
        categories = []
        for ip in ip_list:
            ip_type, ipv4, ipv6 = IPClassifier.parse_ip(ip)
            ip_types.append(ip_type.value if ipv4 or ipv6 else 'unknown')
            categories.append(IPClassifier.categorize_ip(ip).value)

        type_distribution = StatsCalculator.get_distribution(ip_types)
        category_distribution = StatsCalculator.get_distribution(categories)

        stats = {
            'total': total,
            'unique_count': unique_ips,
            'top_ips': top_ips,
            'ipv4_count': type_distribution.get('IPv4', 0),
            'ipv6_count': type_distribution.get('IPv6', 0),
            'internal_count': category_distribution.get('内网IP', 0),
            'external_count': category_distribution.get('外网IP', 0),
            'internal_percentage': StatsCalculator.get_percentage(
                category_distribution.get('内网IP', 0), total
            ),
            'external_percentage': StatsCalculator.get_percentage(
                category_distribution.get('外网IP', 0), total
            ),
        }

        return stats

    @staticmethod
    def calculate_domain_stats(domain_list: List[str]) -> Dict[str, Any]:
        """
        计算域名统计信息

        Args:
            domain_list: 域名列表

        Returns:
            包含域名统计的字典
        """
        # 过滤空域名
        filtered = StatsCalculator.filter_empty_values(domain_list)

        if not filtered:
            return {
                'total': len(domain_list),
                'non_empty_count': 0,
                'empty_count': len(domain_list),
                'unique_count': 0,
                'top_domains': [],
            }

        total = len(domain_list)
        non_empty = len(filtered)
        top_domains = StatsCalculator.get_top_items(filtered, 10)

        stats = {
            'total': total,
            'non_empty_count': non_empty,
            'empty_count': total - non_empty,
            'unique_count': StatsCalculator.count_unique(filtered),
            'top_domains': top_domains,
        }

        return stats
