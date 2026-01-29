"""
IP地址处理工具

提供IP地址分类、解析等功能
"""
import ipaddress
from typing import Tuple, Optional
from enum import Enum


class IPType(Enum):
    """IP地址类型枚举"""
    IPV4 = "IPv4"
    IPV6 = "IPv6"


class IPCategory(Enum):
    """IP地址分类枚举"""
    PRIVATE = "内网IP"
    PUBLIC = "外网IP"
    LOOPBACK = "回环地址"
    MULTICAST = "组播地址"
    UNKNOWN = "未知"


class IPClassifier:
    """IP地址分类器"""

    # 常见服务端口
    COMMON_PORTS = {
        '80': 'HTTP',
        '443': 'HTTPS',
        '53': 'DNS',
        '22': 'SSH',
        '21': 'FTP',
        '25': 'SMTP',
        '110': 'POP3',
        '143': 'IMAP',
        '3306': 'MySQL',
        '3389': 'RDP',
        '1433': 'MSSQL',
        '5432': 'PostgreSQL',
        '6379': 'Redis',
        '27017': 'MongoDB',
        '8080': 'HTTP-Alt',
        '8000': 'HTTP-Dev',
    }

    # 高危端口
    HIGH_RISK_PORTS = {
        '445': 'SMB',
        '135': 'RPC',
        '139': 'NetBIOS',
        '23': 'Telnet',
        '161': 'SNMP',
        '69': 'TFTP',
    }

    @staticmethod
    def parse_ip(ip_str: str) -> Tuple[IPType, Optional[ipaddress.IPv4Address],
                                       Optional[ipaddress.IPv6Address]]:
        """
        解析IP地址字符串

        Args:
            ip_str: IP地址字符串

        Returns:
            (IP类型, IPv4地址对象或None, IPv6地址对象或None)
        """
        try:
            if ':' in ip_str:
                # IPv6
                addr = ipaddress.IPv6Address(ip_str)
                return IPType.IPV6, None, addr
            else:
                # IPv4
                addr = ipaddress.IPv4Address(ip_str)
                return IPType.IPV4, addr, None
        except ValueError:
            return IPType.IPV4, None, None

    @staticmethod
    def categorize_ip(ip_str: str) -> IPCategory:
        """
        分类IP地址（内网/外网）

        Args:
            ip_str: IP地址字符串

        Returns:
            IP地址分类
        """
        try:
            if ':' in ip_str:
                addr = ipaddress.IPv6Address(ip_str)
                if addr.is_loopback:
                    return IPCategory.LOOPBACK
                if addr.is_private:
                    return IPCategory.PRIVATE
                if addr.is_multicast:
                    return IPCategory.MULTICAST
                return IPCategory.PUBLIC
            else:
                addr = ipaddress.IPv4Address(ip_str)
                if addr.is_loopback:
                    return IPCategory.LOOPBACK
                if addr.is_private:
                    return IPCategory.PRIVATE
                if addr.is_multicast:
                    return IPCategory.MULTICAST
                return IPCategory.PUBLIC
        except ValueError:
            return IPCategory.UNKNOWN

    @staticmethod
    def is_internal(ip_str: str) -> bool:
        """
        判断是否为内网IP

        Args:
            ip_str: IP地址字符串

        Returns:
            True if 内网IP, False otherwise
        """
        category = IPClassifier.categorize_ip(ip_str)
        return category in [IPCategory.PRIVATE, IPCategory.LOOPBACK]

    @staticmethod
    def is_external(ip_str: str) -> bool:
        """
        判断是否为外网IP

        Args:
            ip_str: IP地址字符串

        Returns:
            True if 外网IP, False otherwise
        """
        category = IPClassifier.categorize_ip(ip_str)
        return category == IPCategory.PUBLIC

    @staticmethod
    def get_port_service(port: str) -> str:
        """
        获取端口号对应的服务名称

        Args:
            port: 端口号（字符串）

        Returns:
            服务名称，如"HTTP"、"HTTPS"，未知则返回"未知"
        """
        # 处理空端口
        if not port or port == '':
            return '未知'

        return IPClassifier.COMMON_PORTS.get(port, '未知')

    @staticmethod
    def is_high_risk_port(port: str) -> bool:
        """
        判断是否为高危端口

        Args:
            port: 端口号（字符串）

        Returns:
            True if 高危端口, False otherwise
        """
        if not port or port == '':
            return False
        return port in IPClassifier.HIGH_RISK_PORTS

    @staticmethod
    def get_high_risk_service(port: str) -> Optional[str]:
        """
        获取高危端口对应的服务

        Args:
            port: 端口号（字符串）

        Returns:
            服务名称，如果不是高危端口则返回None
        """
        return IPClassifier.HIGH_RISK_PORTS.get(port)
