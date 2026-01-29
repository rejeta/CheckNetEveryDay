"""
AI客户端模块

负责调用AI服务商API进行智能分析
"""
import json
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin

import requests


class AIClient:
    """AI客户端基类"""

    def __init__(self, api_key: str, config: Dict[str, Any]):
        """
        初始化AI客户端

        Args:
            api_key: API密钥
            config: AI服务商配置
        """
        self.api_key = api_key
        self.api_base = config.get('api_base', '')
        self.model = config.get('model', '')
        self.timeout = config.get('timeout', 30)
        self.max_retries = config.get('max_retries', 3)

    def _call_api(self, messages: list) -> Optional[str]:
        """
        调用AI API（子类实现）

        Args:
            messages: 消息列表

        Returns:
            AI响应内容
        """
        raise NotImplementedError("子类必须实现_call_api方法")

    def _retry_call(self, messages: list) -> Optional[str]:
        """
        带重试机制的API调用

        Args:
            messages: 消息列表

        Returns:
            AI响应内容，失败返回None
        """
        last_error = None

        for attempt in range(self.max_retries):
            try:
                return self._call_api(messages)
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    wait_time = (attempt + 1) * 2
                    print(f"API调用失败，{wait_time}秒后重试... (尝试 {attempt + 1}/{self.max_retries})")
                    time.sleep(wait_time)

        print(f"API调用失败: {last_error}")
        return None

    def analyze_logs(self, analysis_result: Dict[str, Any]) -> Optional[str]:
        """
        分析日志，生成AI分析报告

        Args:
            analysis_result: 基础统计分析结果

        Returns:
            AI生成的分析文本
        """
        if not self.api_key:
            print("警告: 未配置API Key，跳过AI分析")
            return None

        # 构造提示词
        prompt = self._build_prompt(analysis_result)

        messages = [
            {
                "role": "system",
                "content": """你是一个网络安全分析专家，专门分析Windows网络连接日志。
你的任务是分析提供的网络连接统计信息，识别潜在的安全风险和异常行为，并提供专业的安全建议。

分析要点：
1. 识别异常的网络连接模式
2. 评估安全风险等级
3. 指出可疑的网络行为
4. 提供具体的安全建议"""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        print("正在调用AI分析...")
        response = self._retry_call(messages)

        if response:
            print("AI分析完成")
        else:
            print("AI分析失败")

        return response

    def _build_prompt(self, analysis_result: Dict[str, Any]) -> str:
        """
        构建AI分析的提示词

        Args:
            analysis_result: 分析结果

        Returns:
            提示词字符串
        """
        prompt = "请分析以下Windows网络连接日志的统计信息：\n\n"

        # 基础统计
        prompt += "## 基础统计\n"
        prompt += f"- 总连接数: {analysis_result['summary']['total_count']}\n"
        prompt += f"- 唯一IP数: {analysis_result['summary']['unique_ips']}\n"
        prompt += f"- 唯一用户数: {analysis_result['summary']['unique_users']}\n"
        prompt += f"- 唯一进程数: {analysis_result['summary']['unique_processes']}\n\n"

        # 时间分析
        time_range = analysis_result['time_analysis']['time_range']
        if time_range.get('start'):
            prompt += "## 时间分析\n"
            prompt += f"- 时间范围: {time_range.get('start_str')} ~ {time_range.get('end_str')}\n"
            prompt += f"- 持续时长: {time_range.get('duration_hours', 0):.2f} 小时\n"
            prompt += f"- 异常时间连接: {analysis_result['time_analysis']['abnormal_time_count']} ({analysis_result['time_analysis']['abnormal_time_percentage']:.1f}%)\n\n"

        # 进程分析
        proc = analysis_result['process_analysis']
        prompt += "## 进程分析\n"
        prompt += f"- 系统进程占比: {proc['system_percentage']:.1f}%\n"
        if proc['top_processes']:
            prompt += "- Top 5 活跃进程:\n"
            for process, count in proc['top_processes'][:5]:
                # 提取进程名
                process_name = process.split('\\')[-1] if '\\' in process else process
                prompt += f"  * {process_name}: {count} 次连接\n"
        prompt += "\n"

        # IP分析
        ip = analysis_result['ip_analysis']
        prompt += "## IP地址分析\n"
        prompt += f"- 内网IP: {ip['internal_count']} ({ip['internal_percentage']:.1f}%)\n"
        prompt += f"- 外网IP: {ip['external_count']} ({ip['external_percentage']:.1f}%)\n"
        if ip['top_ips']:
            prompt += "- Top 5 访问的IP:\n"
            for ip_addr, count in ip['top_ips'][:5]:
                prompt += f"  * {ip_addr}: {count} 次连接\n"
        prompt += "\n"

        # 端口分析
        port = analysis_result['port_analysis']
        prompt += "## 端口分析\n"
        prompt += f"- 高危端口连接: {port['high_risk_port_count']} ({port['high_risk_port_percentage']:.1f}%)\n"
        if port['top_ports']:
            prompt += "- Top 5 访问端口:\n"
            for port_num, count in port['top_ports'][:5]:
                service = port['port_details'].get(port_num, {}).get('service', '未知')
                prompt += f"  * 端口 {port_num} ({service}): {count} 次连接\n"
        prompt += "\n"

        # 用户分析
        user = analysis_result['user_analysis']
        prompt += "## 用户分析\n"
        prompt += f"- 特权账户连接: {user['privileged_count']} ({user['privileged_percentage']:.1f}%)\n"
        if user['top_users']:
            prompt += "- Top 5 用户:\n"
            for username, count in user['top_users'][:5]:
                prompt += f"  * {username}: {count} 次连接\n"
        prompt += "\n"

        # 异常检测
        anomalies = analysis_result['anomalies']
        prompt += "## 异常检测\n"
        prompt += f"- 高危端口连接数: {len(anomalies['high_risk_port_connections'])}\n"
        prompt += f"- 可疑进程数量: {len(anomalies['suspicious_process_ips'])}\n"
        if anomalies['suspicious_process_ips']:
            prompt += "- 可疑进程详情:\n"
            for item in anomalies['suspicious_process_ips'][:3]:
                process_name = item['process'].split('\\')[-1] if '\\' in item['process'] else item['process']
                prompt += f"  * {process_name} 访问了 {item['external_ip_count']} 个不同外网IP\n"

        prompt += "\n\n"
        prompt += "请基于以上统计信息，提供:\n"
        prompt += "1. 风险评估（低/中/高）\n"
        prompt += "2. 发现的安全问题和异常\n"
        prompt += "3. 具体的安全建议\n"
        prompt += "4. 需要关注的事项\n"

        return prompt


class ZhipuAIClient(AIClient):
    """智谱AI客户端"""

    def _call_api(self, messages: list) -> str:
        """调用智谱AI API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
        }

        response = requests.post(self.api_base, headers=headers, json=payload, timeout=self.timeout)
        response.raise_for_status()

        result = response.json()
        return result['choices'][0]['message']['content']


class QwenAIClient(AIClient):
    """阿里云Qwen客户端"""

    def _call_api(self, messages: list) -> str:
        """调用阿里云Qwen API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
        }

        response = requests.post(self.api_base, headers=headers, json=payload, timeout=self.timeout)
        response.raise_for_status()

        result = response.json()
        return result['choices'][0]['message']['content']


class KimiAIClient(AIClient):
    """月之暗面Kimi客户端"""

    def _call_api(self, messages: list) -> str:
        """调用月之暗面Kimi API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
        }

        response = requests.post(self.api_base, headers=headers, json=payload, timeout=self.timeout)
        response.raise_for_status()

        result = response.json()
        return result['choices'][0]['message']['content']


class OpenAIClient(AIClient):
    """OpenAI GPT客户端"""

    def _call_api(self, messages: list) -> str:
        """调用OpenAI API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
        }

        response = requests.post(self.api_base, headers=headers, json=payload, timeout=self.timeout)
        response.raise_for_status()

        result = response.json()
        return result['choices'][0]['message']['content']




def get_ai_client(provider: str, api_key: str, config: Dict[str, Any]) -> Optional[AIClient]:
    """
    根据提供商获取AI客户端

    Args:
        provider: 提供商名称 (zhipu, qwen, kimi, openai)
        api_key: API密钥
        config: 提供商配置

    Returns:
        AI客户端实例
    """
    client_map = {
        'zhipu': ZhipuAIClient,
        'qwen': QwenAIClient,
        'kimi': KimiAIClient,
        'openai': OpenAIClient,
    }

    client_class = client_map.get(provider.lower())
    if not client_class:
        print(f"错误: 不支持的AI提供商 - {provider}")
        return None

    return client_class(api_key, config)


