"""
日志分析核心模块

负责分析网络连接日志，生成统计数据
"""
from typing import List, Dict, Any
from collections import defaultdict

from src.utils import IPClassifier, TimeParser, StatsCalculator
from src.config import Config
from src.threat_intel_client import ThreatIntelClient, ThreatIntelAnalyzer

class LogAnalyzer:
    """日志分析器"""

    def __init__(self):
        """初始化日志分析器"""
        self.ip_classifier = IPClassifier()
        self.time_parser = TimeParser()
        self.stats_calculator = StatsCalculator()
        self.config = Config()

    def analyze(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        分析日志记录

        Args:
            records: 日志记录列表

        Returns:
            分析结果字典
        """
        if not records:
            return {
                'summary': {'total_count': 0},
                'time_analysis': {},
                'process_analysis': {},
                'user_analysis': {},
                'ip_analysis': {},
                'port_analysis': {},
                'protocol_analysis': {},
                'domain_analysis': {},
            }

        print("开始分析日志数据...")

        # 提取各字段数据
        timestamps = [r.get('timestamp') for r in records if r.get('timestamp')]
        processes = [r.get('process') for r in records if r.get('process')]
        users = [r.get('user') for r in records if r.get('user')]
        dest_ips = [r.get('dest_ip') for r in records if r.get('dest_ip')]
        dest_ports = [r.get('dest_port') for r in records if r.get('dest_port')]
        protocols = [r.get('protocol') for r in records if r.get('protocol')]
        domains = [r.get('domain') for r in records if r.get('domain')]

        # 执行各种分析
        result = {
            'summary': {
                'total_count': len(records),
                'unique_ips': len(set(dest_ips)),
                'unique_users': len(set(users)),
                'unique_processes': len(set(processes)),
            },
            'time_analysis': self._analyze_time(timestamps),
            'process_analysis': self._analyze_processes(processes, records),
            'user_analysis': self._analyze_users(users),
            'ip_analysis': self._analyze_ips(dest_ips),
            'port_analysis': self._analyze_ports(dest_ports),
            'protocol_analysis': self._analyze_protocols(protocols),
            'domain_analysis': self._analyze_domains(domains),
            'anomalies': self._detect_anomalies(records, timestamps, dest_ips, dest_ports),
        }

        print("日志分析完成")
        return result

    def analyze_with_threat_intel(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        结合威胁情报分析日志

        Args:
            records: 日志记录列表

        Returns:
            包含威胁情报的分析结果
        """
        # 先进行基础分析
        result = self.analyze(records)

        # 检查配置是否启用威胁情报
        if not self.config.get('threat_intel.enabled', False):
            return result

        # 收集外网IP
        external_ips = set()
        for record in records:
            dest_ip = record.get('dest_ip', '')
            if dest_ip and not self.ip_classifier.is_internal(dest_ip):
                external_ips.add(dest_ip)

        if not external_ips:
            return result

        # 查询威胁情报
        print(f"查询 {len(external_ips)} 个外网IP的威胁情报...")
        client = ThreatIntelClient(self.config)
        analyzer = ThreatIntelAnalyzer(client)

        threat_intel_result = analyzer.analyze_ips(list(external_ips))

        # 将威胁情报添加到分析结果中
        result['threat_intel'] = threat_intel_result

        return result

    def _analyze_time(self, timestamps: List[str]) -> Dict[str, Any]:
        """分析时间分布"""
        time_range = self.time_parser.get_time_range(timestamps)
        hour_dist = self.time_parser.get_hour_distribution(timestamps)
        date_dist = self.time_parser.get_date_distribution(timestamps)
        period_dist = self.time_parser.get_time_period_distribution(timestamps)
        abnormal_times = self.time_parser.get_abnormal_time_connections(timestamps)

        # 找出高峰时段
        peak_hour = max(hour_dist.items(), key=lambda x: x[1]) if hour_dist else (0, 0)

        return {
            'time_range': time_range,
            'hour_distribution': hour_dist,
            'date_distribution': date_dist,
            'period_distribution': period_dist,
            'peak_hour': peak_hour,
            'abnormal_time_count': len(abnormal_times),
            'abnormal_time_percentage': self.stats_calculator.get_percentage(
                len(abnormal_times), len(timestamps)
            ),
        }

    def _analyze_processes(self, processes: List[str], records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析进程信息"""
        stats = self.stats_calculator.calculate_process_stats(processes)

        # 分析特权进程的外网访问
        privileged_processes = {}
        for record in records:
            user = record.get('user', '')
            process = record.get('process', '')
            dest_ip = record.get('dest_ip', '')

            if 'SYSTEM' in user or 'NETWORK SERVICE' in user or 'LOCAL SERVICE' in user:
                if process and dest_ip and self.ip_classifier.is_external(dest_ip):
                    if process not in privileged_processes:
                        privileged_processes[process] = 0
                    privileged_processes[process] += 1

        stats['privileged_external_connections'] = [
            (process, count)
            for process, count in sorted(privileged_processes.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        return stats

    def _analyze_users(self, users: List[str]) -> Dict[str, Any]:
        """分析用户信息"""
        return self.stats_calculator.calculate_user_stats(users)

    def _analyze_ips(self, ips: List[str]) -> Dict[str, Any]:
        """分析IP地址信息"""
        # 原有统计分析
        stats = self.stats_calculator.calculate_ip_stats(ips)

        return stats

    def _analyze_ports(self, ports: List[str]) -> Dict[str, Any]:
        """分析端口信息"""
        from utils.ip_utils import IPClassifier

        stats = self.stats_calculator.calculate_port_stats(ports)

        # 详细端口信息
        port_details = {}
        for port, count in stats['top_ports'][:20]:
            port_details[port] = {
                'count': count,
                'service': IPClassifier.get_port_service(port),
                'is_high_risk': IPClassifier.is_high_risk_port(port),
                'high_risk_service': IPClassifier.get_high_risk_service(port),
            }

        stats['port_details'] = port_details

        return stats

    def _analyze_protocols(self, protocols: List[str]) -> Dict[str, Any]:
        """分析协议信息"""
        return self.stats_calculator.calculate_protocol_stats(protocols)

    def _analyze_domains(self, domains: List[str]) -> Dict[str, Any]:
        """分析域名信息"""
        return self.stats_calculator.calculate_domain_stats(domains)

    def _detect_anomalies(self, records: List[Dict[str, Any]],
                          timestamps: List[str],
                          dest_ips: List[str],
                          dest_ports: List[str]) -> Dict[str, Any]:
        """检测异常行为"""
        anomalies = {
            'abnormal_time_connections': [],
            'abnormal_time_count': 0,
            'high_risk_port_connections': [],
            'unusual_external_connections': [],
            'suspicious_process_ips': [],
            'uncommon_ports_count': 0,
            'uncommon_ports': [],
        }

        # 检测异常时间连接
        abnormal_timestamps = self.time_parser.get_abnormal_time_connections(timestamps)
        anomalies['abnormal_time_count'] = len(abnormal_timestamps)
        abnormal_timestamps_set = set(abnormal_timestamps)

        for record in records:
            timestamp = record.get('timestamp', '')
            dest_ip = record.get('dest_ip', '')
            dest_port = record.get('dest_port', '')
            process = record.get('process', '')

            # 异常时间连接（采样前10个）
            if timestamp in abnormal_timestamps_set and len(anomalies['abnormal_time_connections']) < 10:
                anomalies['abnormal_time_connections'].append({
                    'timestamp': timestamp,
                    'process': process,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                })

            # 高危端口连接（采样前10个）
            if self.ip_classifier.is_high_risk_port(dest_port):
                anomalies['high_risk_port_connections'].append({
                    'timestamp': timestamp,
                    'process': process,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'service': self.ip_classifier.get_high_risk_service(dest_port),
                })

        # 检测非常规端口访问
        port_dist = self.stats_calculator.get_distribution(dest_ports)
        common_ports = set(self.ip_classifier.COMMON_PORTS.keys())
        uncommon_ports = [p for p in port_dist.keys() if p and p not in common_ports and self.ip_classifier.get_port_service(p) == '未知']

        anomalies['uncommon_ports_count'] = len(uncommon_ports)
        anomalies['uncommon_ports'] = sorted(uncommon_ports, key=lambda x: port_dist[x], reverse=True)[:10]

        # 检测可疑进程-IP关联（相同进程访问大量不同外网IP）
        process_external_ips = defaultdict(set)
        for record in records:
            process = record.get('process', '')
            dest_ip = record.get('dest_ip', '')
            if process and dest_ip and self.ip_classifier.is_external(dest_ip):
                process_external_ips[process].add(dest_ip)

        for process, ips in sorted(process_external_ips.items(), key=lambda x: len(x[1]), reverse=True):
            if len(ips) > 5:  # 访问超过5个不同外网IP
                anomalies['suspicious_process_ips'].append({
                    'process': process,
                    'external_ip_count': len(ips),
                    'external_ips': list(ips)[:10],
                })

        return anomalies

    def get_summary_statistics(self, analysis_result: Dict[str, Any]) -> str:
        """
        获取分析结果的摘要统计

        Args:
            analysis_result: 分析结果

        Returns:
            摘要统计字符串
        """
        summary = []

        summary.append(f"总连接数: {analysis_result['summary']['total_count']}")
        summary.append(f"唯一IP数: {analysis_result['summary']['unique_ips']}")
        summary.append(f"唯一用户数: {analysis_result['summary']['unique_users']}")
        summary.append(f"唯一进程数: {analysis_result['summary']['unique_processes']}")

        # 时间范围
        time_range = analysis_result['time_analysis']['time_range']
        if time_range.get('start'):
            summary.append(f"时间范围: {time_range.get('start_str')} ~ {time_range.get('end_str')}")

        # 协议分布
        proto = analysis_result['protocol_analysis']
        summary.append(f"TCP连接: {proto['tcp_count']} ({proto['tcp_percentage']:.1f}%)")
        summary.append(f"UDP连接: {proto['udp_count']} ({proto['udp_percentage']:.1f}%)")

        # IP分布
        ip = analysis_result['ip_analysis']
        summary.append(f"内网IP: {ip['internal_count']} ({ip['internal_percentage']:.1f}%)")
        summary.append(f"外网IP: {ip['external_count']} ({ip['external_percentage']:.1f}%)")

        # 异常检测
        anomalies = analysis_result['anomalies']
        summary.append(f"异常时间连接: {anomalies['abnormal_time_count']}")
        summary.append(f"高危端口连接: {len(anomalies['high_risk_port_connections'])}")
        summary.append(f"可疑进程: {len(anomalies['suspicious_process_ips'])}")

        return "\n".join(summary)
