"""
报告生成模块

负责生成Markdown格式的分析报告
"""
from typing import Dict, Any, Optional
from datetime import datetime


class MarkdownReporter:
    """Markdown报告生成器"""

    def __init__(self):
        """初始化报告生成器"""
        self.report = ""

    def generate_report(self,
                       analysis_result: Dict[str, Any],
                       ai_analysis: str = None,
                       file_info: Dict[str, Any] = None) -> str:
        """
        生成完整的Markdown报告

        Args:
            analysis_result: 分析结果
            ai_analysis: AI生成的分析文本
            file_info: 文件信息

        Returns:
            Markdown格式的报告字符串
        """
        self.report = ""

        # 报告标题
        self._add_header(1, "Windows网络流量分析报告")
        self._add_horizontal_rule()
        self._add_metadata(file_info)

        # 执行摘要
        self._add_summary(analysis_result, ai_analysis)

        # 基础统计
        self._add_basic_statistics(analysis_result)

        # 时间分析
        self._add_time_analysis(analysis_result)

        # 进程分析
        self._add_process_analysis(analysis_result)

        # IP地址分析
        self._add_ip_analysis(analysis_result)

        # 端口分析
        self._add_port_analysis(analysis_result)

        # 用户分析
        self._add_user_analysis(analysis_result)

        # AI安全分析
        if ai_analysis:
            self._add_ai_analysis(ai_analysis)

        # 威胁情报分析
        if analysis_result.get('threat_intel') and analysis_result['threat_intel'].get('summary'):
            self._add_threat_intel_detailed(analysis_result['threat_intel'])

        # 异常检测
        self._add_anomalies(analysis_result)

        # 数据附录
        self._add_appendix(analysis_result)

        # 报告页脚
        self._add_footer()

        return self.report

    def _add_header(self, level: int, text: str):
        """添加标题"""
        prefix = "#" * level
        self.report += f"{prefix} {text}\n\n"

    def _add_horizontal_rule(self):
        """添加水平线"""
        self.report += "---\n\n"

    def _add_text(self, text: str):
        """添加文本段落"""
        self.report += f"{text}\n\n"

    def _add_list_item(self, level: int, text: str):
        """添加列表项"""
        prefix = "  " * level + "-"
        self.report += f"{prefix} {text}\n"

    def _add_table(self, headers: list, rows: list):
        """添加表格"""
        # 表头
        self.report += "| " + " | ".join(headers) + " |\n"
        # 分隔线
        self.report += "|" + "|".join(["---"] * len(headers)) + "|\n"
        # 数据行
        for row in rows:
            self.report += "| " + " | ".join(str(cell) for cell in row) + " |\n"
        self.report += "\n"

    def _add_code_block(self, code: str, language: str = ""):
        """添加代码块"""
        self.report += f"```{language}\n{code}\n```\n\n"

    def _add_metadata(self, file_info: Dict[str, Any]):
        """添加报告元数据"""
        self._add_header(2, "报告信息")

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._add_list_item(0, f"生成时间: {now}")

        if file_info:
            self._add_list_item(0, f"源文件: {file_info.get('name', 'N/A')}")
            size_mb = file_info.get('size_mb', 0)
            self._add_list_item(0, f"文件大小: {size_mb:.2f} MB")

        self._add_horizontal_rule()

    def _add_summary(self, analysis_result: Dict[str, Any], ai_analysis: str = None):
        """添加执行摘要"""
        self._add_header(2, "执行摘要")

        summary = analysis_result['summary']
        self._add_list_item(0, f"总连接数: **{summary['total_count']:,}**")
        self._add_list_item(0, f"唯一IP地址: **{summary['unique_ips']:,}**")
        self._add_list_item(0, f"唯一用户数: **{summary['unique_users']}**")
        self._add_list_item(0, f"唯一进程数: **{summary['unique_processes']}**")

        # 风险评估
        anomalies = analysis_result['anomalies']
        risk_level = self._calculate_risk_level(anomalies)
        risk_emoji = {"低": "🟢", "中": "🟡", "高": "🔴"}.get(risk_level, "⚪")

        self._add_text(f"\n**风险评估: {risk_emoji} {risk_level}风险**")

        # 关键发现
        key_findings = []
        if anomalies['high_risk_port_connections']:
            key_findings.append(f"发现 {len(anomalies['high_risk_port_connections'])} 个高危端口连接")
        if anomalies['abnormal_time_count'] > 0:
            key_findings.append(f"检测到 {anomalies['abnormal_time_count']} 个异常时间段连接")
        if anomalies['suspicious_process_ips']:
            key_findings.append(f"发现 {len(anomalies['suspicious_process_ips'])} 个可疑进程访问多个外网IP")

        if key_findings:
            self._add_header(3, "关键发现")
            for finding in key_findings:
                self._add_list_item(0, finding)

        self._add_horizontal_rule()

    def _calculate_risk_level(self, anomalies: Dict[str, Any]) -> str:
        """计算风险等级"""
        score = 0

        if len(anomalies['high_risk_port_connections']) > 5:
            score += 2
        elif len(anomalies['high_risk_port_connections']) > 0:
            score += 1

        if anomalies['abnormal_time_count'] > 50:
            score += 2
        elif anomalies['abnormal_time_count'] > 0:
            score += 1

        if len(anomalies['suspicious_process_ips']) > 2:
            score += 2
        elif len(anomalies['suspicious_process_ips']) > 0:
            score += 1

        if score >= 4:
            return "高"
        elif score >= 2:
            return "中"
        else:
            return "低"

    def _add_basic_statistics(self, analysis_result: Dict[str, Any]):
        """添加基础统计"""
        self._add_header(2, "基础统计")

        proto = analysis_result['protocol_analysis']
        self._add_header(3, "协议分布")
        self._add_list_item(0, f"TCP连接: **{proto['tcp_count']:,}** ({proto['tcp_percentage']:.1f}%)")
        self._add_list_item(0, f"UDP连接: **{proto['udp_count']:,}** ({proto['udp_percentage']:.1f}%)")

        ip = analysis_result['ip_analysis']
        self._add_header(3, "IP地址分布")
        self._add_list_item(0, f"内网IP: **{ip['internal_count']:,}** ({ip['internal_percentage']:.1f}%)")
        self._add_list_item(0, f"外网IP: **{ip['external_count']:,}** ({ip['external_percentage']:.1f}%)")

        domain = analysis_result['domain_analysis']
        self._add_header(3, "域名统计")
        self._add_list_item(0, f"有域名连接: **{domain['non_empty_count']:,}**")
        self._add_list_item(0, f"唯一域名数: **{domain['unique_count']}**")

        self._add_horizontal_rule()

    def _add_time_analysis(self, analysis_result: Dict[str, Any]):
        """添加时间分析"""
        self._add_header(2, "时间分布分析")

        time_info = analysis_result['time_analysis']
        time_range = time_info['time_range']

        if time_range.get('start'):
            self._add_header(3, "时间范围")
            self._add_list_item(0, f"开始时间: {time_range.get('start_str')}")
            self._add_list_item(0, f"结束时间: {time_range.get('end_str')}")
            duration = time_range.get('duration_hours', 0)
            self._add_list_item(0, f"持续时间: {duration:.2f} 小时")

        self._add_header(3, "时间分布")

        # 小时分布
        hour_dist = time_info['hour_distribution']
        peak_hour, peak_count = time_info['peak_hour']
        self._add_list_item(0, f"活跃时段: {peak_hour}:00 ({peak_count} 次连接)")

        # 时间段分布
        period_dist = time_info['period_distribution']
        if period_dist:
            self._add_header(4, "按时间段统计")
            for period in ["凌晨", "上午", "下午", "傍晚", "深夜"]:
                count = period_dist.get(period, 0)
                if count > 0:
                    self._add_list_item(1, f"{period}: {count} 次连接")

        # 异常时间
        abnormal_count = time_info['abnormal_time_count']
        abnormal_pct = time_info['abnormal_time_percentage']
        if abnormal_count > 0:
            self._add_text(f"⚠️ 检测到 **{abnormal_count}** 个异常时间段连接 ({abnormal_pct:.1f}%)")

        self._add_horizontal_rule()

    def _add_process_analysis(self, analysis_result: Dict[str, Any]):
        """添加进程分析"""
        self._add_header(2, "进程行为分析")

        proc = analysis_result['process_analysis']

        # 系统vs应用
        self._add_header(3, "进程类型分布")
        self._add_list_item(0, f"系统进程: **{proc['system_process_count']:,}** ({proc['system_percentage']:.1f}%)")
        self._add_list_item(0, f"应用进程: **{proc['application_process_count']:,}** ({proc['application_percentage']:.1f}%)")

        # Top 进程
        if proc['top_processes']:
            self._add_header(3, "Top 10 活跃进程")
            for process, count in proc['top_processes']:
                process_name = process.split('\\')[-1] if '\\' in process else process
                self._add_list_item(0, f"**{process_name}**: {count} 次连接")

        # 特权进程外网访问
        if proc.get('privileged_external_connections'):
            self._add_header(3, "特权进程外网访问")
            for process, count in proc['privileged_external_connections'][:5]:
                process_name = process.split('\\')[-1] if '\\' in process else process
                self._add_list_item(0, f"**{process_name}**: {count} 个外网IP")

        self._add_horizontal_rule()

    def _add_ip_analysis(self, analysis_result: Dict[str, Any]):
        """添加IP地址分析"""
        self._add_header(2, "IP访问分析")

        ip = analysis_result['ip_analysis']

        # Top IP
        if ip['top_ips']:
            self._add_header(3, "Top 10 访问的IP地址")
            for ip_addr, count in ip['top_ips']:
                threat_info = self._get_threat_info(ip_addr, analysis_result)
                if threat_info:
                    self._add_list_item(0, f"**{ip_addr}** ⚠️: {count} 次连接 - *威胁类型: {threat_info['threat_type']}*")
                else:
                    self._add_list_item(0, f"**{ip_addr}**: {count} 次连接")

        # 威胁情报分析
        self._add_threat_intel_analysis(analysis_result)

        self._add_horizontal_rule()

    def _add_port_analysis(self, analysis_result: Dict[str, Any]):
        """添加端口分析"""
        self._add_header(2, "端口分析")

        port = analysis_result['port_analysis']

        # 高危端口
        if port['high_risk_port_count'] > 0:
            self._add_header(3, "高危端口连接")
            self._add_list_item(0, f"高危端口连接数: **{port['high_risk_port_count']:,}** ({port['high_risk_port_percentage']:.1f}%)")

        # Top 端口
        if port['top_ports']:
            self._add_header(3, "Top 10 访问端口")
            for port_num, count in port['top_ports']:
                service = port['port_details'].get(port_num, {}).get('service', '未知')
                is_high_risk = port['port_details'].get(port_num, {}).get('is_high_risk', False)
                risk_mark = " ⚠️" if is_high_risk else ""
                self._add_list_item(0, f"端口 **{port_num}** ({service}){risk_mark}: {count} 次连接")

        # 非常规端口
        uncommon_count = analysis_result['anomalies']['uncommon_ports_count']
        if uncommon_count > 0:
            self._add_text(f"ℹ️ 发现 **{uncommon_count}** 个非常规端口访问")

        self._add_horizontal_rule()

    def _add_user_analysis(self, analysis_result: Dict[str, Any]):
        """添加用户分析"""
        self._add_header(2, "用户分析")

        user = analysis_result['user_analysis']

        # 特权账户
        self._add_header(3, "特权账户使用")
        self._add_list_item(0, f"特权账户连接: **{user['privileged_count']:,}** ({user['privileged_percentage']:.1f}%)")

        # Top 用户
        if user['top_users']:
            self._add_header(3, "Top 10 活跃用户")
            for username, count in user['top_users']:
                self._add_list_item(0, f"**{username}**: {count} 次连接")

        self._add_horizontal_rule()

    def _add_ai_analysis(self, ai_analysis: str):
        """添加AI分析结果"""
        self._add_header(2, "AI安全分析")

        # 将AI分析转换为Markdown格式
        ai_analysis_md = ai_analysis.replace('\n\n', '\n\n')
        self._add_text(ai_analysis_md)

        self._add_horizontal_rule()

    def _add_anomalies(self, analysis_result: Dict[str, Any]):
        """添加异常检测结果"""
        self._add_header(2, "异常检测")

        anomalies = analysis_result['anomalies']

        # 高危端口连接
        if anomalies['high_risk_port_connections']:
            self._add_header(3, "高危端口连接")
            for conn in anomalies['high_risk_port_connections'][:10]:
                process_name = conn['process'].split('\\')[-1] if '\\' in conn['process'] else conn['process']
                self._add_list_item(0, f"{process_name} -> {conn['dest_ip']}:{conn['dest_port']} ({conn['service']})")

        # 可疑进程
        if anomalies['suspicious_process_ips']:
            self._add_header(3, "可疑进程（访问大量外网IP）")
            for item in anomalies['suspicious_process_ips'][:5]:
                process_name = item['process'].split('\\')[-1] if '\\' in item['process'] else item['process']
                self._add_list_item(0, f"**{process_name}**: 访问了 {item['external_ip_count']} 个不同外网IP")

        self._add_horizontal_rule()

    def _add_appendix(self, analysis_result: Dict[str, Any]):
        """添加数据附录"""
        self._add_header(2, "数据附录")

        # 完整的端口列表
        port = analysis_result['port_analysis']
        if port['port_details']:
            self._add_header(3, "完整端口访问统计")
            for port_num, count in port['top_ports']:
                service = port['port_details'].get(port_num, {}).get('service', '未知')
                self._add_list_item(0, f"{port_num} ({service}): {count}")

        self._add_horizontal_rule()

    def _add_footer(self):
        """添加页脚"""
        self._add_text("---")
        self._add_text("*本报告由 Windows网络流量智能分析工具 自动生成*")
        self._add_text("*生成时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "*")

    def _get_threat_info(self, ip_addr: str, analysis_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        获取指定IP的威胁情报信息

        Args:
            ip_addr: IP地址
            analysis_result: 分析结果

        Returns:
            威胁信息字典，如果不存在则返回None
        """
        if 'threat_intel' in analysis_result:
            for threat in analysis_result['threat_intel'].get('malicious_ips', []):
                if threat['ip'] == ip_addr:
                    return threat
        return None

    def _add_threat_intel_detailed(self, threat_intel: Dict[str, Any]):
        """添加详细的威胁情报报告"""
        if not threat_intel.get('summary'):
            return

        self._add_header(2, "🚨 威胁情报详细报告")

        # 威胁概览
        summary = threat_intel['summary']
        self._add_header(3, "威胁概览")
        self._add_list_item(0, f"🔍 查询IP数: **{summary['total_queried']}**")
        self._add_list_item(0, f"🔴 恶意IP数: **{summary['malicious_count']}** ({summary['malicious_percentage']:.1f}%)")
        self._add_list_item(0, f"🟡 可疑IP数: **{summary['suspicious_count']}**")
        self._add_list_item(0, f"🟢 清洁IP数: **{summary['clean_count']}**")

        # 风险等级
        risk_level = summary['risk_level']
        risk_emoji = {"高": "🔴", "中": "🟡", "低": "🟢"}.get(risk_level, "⚪")
        self._add_text(f"\n**整体风险等级: {risk_emoji} {risk_level}**")

        # 恶意IP详情
        if threat_intel['malicious_ips']:
            self._add_header(3, "🔴 恶意IP详情")
            for threat in threat_intel['malicious_ips']:
                self._add_list_item(0, f"**{threat['ip']}**")
                self._add_list_item(1, f"威胁类型: {threat['threat_type']}")
                self._add_list_item(1, f"置信度: {threat['confidence_score']}/100")
                self._add_list_item(1, f"国家: {threat['country']}")
                self._add_list_item(1, f"报告次数: {threat['total_reports']}")
                self._add_list_item(1, f"首次发现: {threat['first_reported']}")
                self._add_list_item(1, f"最后发现: {threat['last_reported']}")
                self._add_text("")

        # 可疑IP详情
        if threat_intel['suspicious_ips']:
            self._add_header(3, "🟡 可疑IP详情")
            for threat in threat_intel['suspicious_ips']:
                self._add_list_item(0, f"**{threat['ip']}**")
                self._add_list_item(1, f"威胁类型: {threat['threat_type']}")
                self._add_list_item(1, f"置信度: {threat['confidence_score']}/100")
                self._add_list_item(1, f"国家: {threat['country']}")
                self._add_list_item(1, f"报告次数: {threat['total_reports']}")
                self._add_text("")

        # 错误信息
        if threat_intel['errors']:
            self._add_header(3, "❌ 查询错误")
            for error in threat_intel['errors'][:5]:
                if 'error' in error:
                    ip = error.get('ip', error.get('ip_range', 'N/A'))
                    self._add_list_item(0, f"IP: {ip}")
                    self._add_list_item(1, f"错误: {error['error']}")

        self._add_horizontal_rule()

    def _add_threat_intel_analysis(self, analysis_result: Dict[str, Any]):
        """添加威胁情报分析（保持向后兼容）"""
        self._add_threat_intel_detailed(analysis_result.get('threat_intel', {}))

    def save_report(self, file_path: str):
        """
        保存报告到文件

        Args:
            file_path: 报告文件路径
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(self.report)
            print(f"报告已保存: {file_path}")
        except Exception as e:
            print(f"保存报告失败: {e}")
