"""
威胁情报客户端模块

负责与AbuseIPDB API交互，查询IP威胁情报
"""
import requests
import ipaddress
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
import time
import os
from src.config import Config


class ThreatIntelClient:
    """威胁情报查询客户端"""

    def __init__(self, config: Config):
        """
        初始化威胁情报客户端

        Args:
            config: 配置对象
        """
        self.config = config
        self.api_key = self._get_api_key()
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.session = requests.Session()

        # 设置请求头
        if self.api_key:
            self.session.headers.update({
                'Key': self.api_key,
                'Accept': 'application/json'
            })

    def _get_api_key(self) -> str:
        """获取API密钥"""
        # 优先从环境变量获取
        env_key = os.getenv('ABUSEIPDB_API_KEY', '')
        if env_key:
            return env_key

        # 从配置文件获取
        return self.config.get('threat_intel.abuseipdb_api_key', '')

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询单个IP的威胁情报

        Args:
            ip: IP地址

        Returns:
            查询结果字典
        """
        if not self.api_key:
            return {
                'ip': ip,
                'error': 'No AbuseIPDB API key configured',
                'success': False,
                'query_time': datetime.now().isoformat()
            }

        try:
            # 验证IP格式
            ip_obj = ipaddress.ip_address(ip)
            version = 'v4' if isinstance(ip_obj, ipaddress.IPv4Address) else 'v6'

            # 构建请求
            url = f"{self.base_url}/check"
            params = {
                'ipAddress': ip,
                'maxAgeDays': self._get_max_age(),
                'verbose': self._get_verbose()
            }

            # 发送请求
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()

            # 解析响应
            data = response.json()
            self._normalize_response(data)

            return {
                'ip': ip,
                'data': data,
                'success': True,
                'query_time': datetime.now().isoformat()
            }

        except requests.exceptions.RequestException as e:
            return {
                'ip': ip,
                'error': f'Request failed: {str(e)}',
                'success': False,
                'query_time': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'ip': ip,
                'error': f'Unexpected error: {str(e)}',
                'success': False,
                'query_time': datetime.now().isoformat()
            }

    def check_ip_range(self, ip_range: str) -> List[Dict[str, Any]]:
        """
        查询IP段的威胁情报

        Args:
            ip_range: IP段，格式如 "127.0.0.1/24"

        Returns:
            查询结果列表
        """
        if not self.api_key:
            return [{
                'ip_range': ip_range,
                'error': 'No AbuseIPDB API key configured',
                'success': False,
                'query_time': datetime.now().isoformat()
            }]

        results = []
        try:
            # 解析IP段
            network = ipaddress.ip_network(ip_range, strict=False)

            # 根据段大小决定查询策略
            if network.num_addresses <= 256:
                # 小段，逐个查询
                for ip in network.hosts():
                    result = self.check_ip(str(ip))
                    results.append(result)
                    time.sleep(0.1)  # 避免API限速
            else:
                # 大段，使用批量查询（取前256个主机）
                results = self._query_large_network(network)

            return results

        except Exception as e:
            return [{
                'ip_range': ip_range,
                'error': f'Invalid IP range: {str(e)}',
                'success': False,
                'query_time': datetime.now().isoformat()
            }]

    def _query_large_network(self, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> List[Dict[str, Any]]:
        """
        查询大型网络的威胁情报（简化版，返回前256个IP）

        Args:
            network: IP网络对象

        Returns:
            查询结果列表
        """
        results = []
        ip_count = 0

        for ip in network.hosts():
            if ip_count >= 256:  # 限制查询数量
                break

            result = self.check_ip(str(ip))
            results.append(result)
            ip_count += 1
            time.sleep(0.1)  # 避免API限速

        return results

    def _normalize_response(self, data: Dict[str, Any]):
        """标准化API响应格式"""
        if 'data' in data and isinstance(data['data'], dict):
            response_data = data['data']
            # 确保必要字段存在
            if 'abuseConfidenceScore' not in response_data:
                response_data['abuseConfidenceScore'] = 0
            if 'isPublic' not in response_data:
                response_data['isPublic'] = True

    def _get_max_age(self) -> int:
        """获取最大查询天数"""
        return self.config.get('threat_intel.max_age_days', 90)

    def _get_verbose(self) -> bool:
        """获取详细查询选项"""
        return self.config.get('threat_intel.verbose', False)

    def is_enabled(self) -> bool:
        """检查是否启用威胁情报功能"""
        return self.config.get('threat_intel.enabled', False) and bool(self.api_key)


class ThreatIntelAnalyzer:
    """威胁情报分析器"""

    def __init__(self, client: ThreatIntelClient):
        """
        初始化威胁情报分析器

        Args:
            client: 威胁情报客户端
        """
        self.client = client

    def analyze_ips(self, ips: List[str], ip_ranges: List[str] = None) -> Dict[str, Any]:
        """
        分析IP列表的威胁情报

        Args:
            ips: IP地址列表
            ip_ranges: IP段列表

        Returns:
            威胁情报分析结果
        """
        results = {
            'query_count': 0,
            'malicious_ips': [],
            'suspicious_ips': [],
            'clean_ips': [],
            'errors': [],
            'summary': {}
        }

        # 查询单个IP
        for ip in ips:
            if not self._is_internal_ip(ip):
                result = self.client.check_ip(ip)
                results['query_count'] += 1
                self._process_result(result, results)

        # 查询IP段
        if ip_ranges:
            for ip_range in ip_ranges:
                if '/' in ip_range:  # 确保是有效的IP段
                    range_results = self.client.check_ip_range(ip_range)
                    results['query_count'] += len(range_results)
                    for result in range_results:
                        self._process_result(result, results)

        # 生成摘要
        results['summary'] = self._generate_summary(results)

        return results

    def _process_result(self, result: Dict[str, Any], results: Dict[str, Any]):
        """处理单个查询结果"""
        if result.get('success'):
            ip = result.get('ip', '')
            data = result.get('data', {})

            score = data.get('abuseConfidenceScore', 0)
            threat_types = data.get('threatTypes', [])

            if score >= 80:
                results['malicious_ips'].append({
                    'ip': ip,
                    'threat_type': ', '.join(threat_types) if threat_types else 'Malicious Activity',
                    'confidence_score': score,
                    'country': data.get('countryName', 'Unknown'),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReported', 'Unknown'),
                    'first_reported': data.get('firstReported', 'Unknown')
                })
            elif score >= 30:
                results['suspicious_ips'].append({
                    'ip': ip,
                    'threat_type': ', '.join(threat_types) if threat_types else 'Suspicious Activity',
                    'confidence_score': score,
                    'country': data.get('countryName', 'Unknown'),
                    'total_reports': data.get('totalReports', 0)
                })
            else:
                results['clean_ips'].append({
                    'ip': ip,
                    'confidence_score': score
                })
        else:
            results['errors'].append(result)

    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成威胁情报摘要"""
        return {
            'total_queried': results['query_count'],
            'malicious_count': len(results['malicious_ips']),
            'suspicious_count': len(results['suspicious_ips']),
            'clean_count': len(results['clean_ips']),
            'error_count': len(results['errors']),
            'malicious_percentage': self._get_percentage(len(results['malicious_ips']), results['query_count']),
            'risk_level': self._calculate_risk_level(results)
        }

    def _is_internal_ip(self, ip: str) -> bool:
        """检查是否是内部IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except:
            return True

    def _get_percentage(self, count: int, total: int) -> float:
        """计算百分比"""
        if total == 0:
            return 0.0
        return (count / total) * 100

    def _calculate_risk_level(self, results: Dict[str, Any]) -> str:
        """计算风险等级"""
        malicious_ratio = len(results['malicious_ips']) / max(results['query_count'], 1)
        suspicious_ratio = len(results['suspicious_ips']) / max(results['query_count'], 1)

        if malicious_ratio > 0.1 or suspicious_ratio > 0.3:
            return "高"
        elif malicious_ratio > 0.05 or suspicious_ratio > 0.15:
            return "中"
        else:
            return "低"