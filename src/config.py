"""
配置管理模块

负责加载和管理应用程序配置
"""
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """配置管理类"""

    def __init__(self, config_path: Optional[str] = None):
        """
        初始化配置

        Args:
            config_path: 配置文件路径，默认为config/config.yaml
        """
        self.config_path = config_path or self._get_default_config_path()
        self.config = self._load_config()

    def _get_default_config_path(self) -> str:
        """获取默认配置文件路径"""
        # 尝试多个可能的配置文件位置
        possible_paths = [
            "config/config.yaml",
            "../config/config.yaml",
            os.path.join(os.path.dirname(__file__), "../config/config.yaml"),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return "config/config.yaml"

    def _load_config(self) -> Dict[str, Any]:
        """
        加载配置文件

        Returns:
            配置字典
        """
        if not os.path.exists(self.config_path):
            print(f"警告: 配置文件不存在: {self.config_path}")
            return self._get_default_config()

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                return config if config else {}
        except Exception as e:
            print(f"错误: 加载配置文件失败 - {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            'ai_provider': 'zhipu',
            'api_key': '',
            'output_format': 'markdown',
            'analysis': {
                'detect_anomalies': True,
                'check_threat_intel': False,
                'include_time_distribution': True,
            },
            'risk_threshold': 'medium',
            'output_dir': 'output',
            'data_dir': 'data',
        }

    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置项

        Args:
            key: 配置键，支持点号分隔的嵌套键，如 'ai_provider' 或 'analysis.detect_anomalies'
            default: 默认值

        Returns:
            配置值
        """
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default

        return value

    def get_ai_provider(self) -> str:
        """获取AI提供商"""
        return self.get('ai_provider', 'zhipu')

    def get_api_key(self) -> str:
        """获取API密钥"""
        # 优先从环境变量读取
        api_key = os.getenv('AI_API_KEY', '')
        if api_key:
            return api_key
        return self.get('api_key', '')

    def get_output_format(self) -> str:
        """获取输出格式"""
        return self.get('output_format', 'markdown')

    def get_output_dir(self) -> str:
        """获取输出目录"""
        return self.get('output_dir', 'output')

    def get_data_dir(self) -> str:
        """获取数据目录"""
        return self.get('data_dir', 'data')

    def get_analysis_config(self) -> Dict[str, Any]:
        """获取分析配置"""
        return self.get('analysis', {})

    def get_risk_threshold(self) -> str:
        """获取风险阈值"""
        return self.get('risk_threshold', 'medium')

    def update(self, key: str, value: Any) -> None:
        """
        更新配置项

        Args:
            key: 配置键，支持点号分隔的嵌套键
            value: 新值
        """
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def save(self, path: Optional[str] = None) -> None:
        """
        保存配置到文件

        Args:
            path: 保存路径，默认为原配置文件路径
        """
        save_path = path or self.config_path
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            with open(save_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False,
                          allow_unicode=True, sort_keys=False)
            print(f"配置已保存到: {save_path}")
        except Exception as e:
            print(f"错误: 保存配置失败 - {e}")


class AIProvidersConfig:
    """AI服务提供商配置"""

    def __init__(self, config_path: Optional[str] = None):
        """
        初始化AI提供商配置

        Args:
            config_path: 配置文件路径
        """
        self.config_path = config_path or self._get_default_config_path()
        self.providers = self._load_config()

    def _get_default_config_path(self) -> str:
        """获取默认配置文件路径"""
        possible_paths = [
            "config/ai_providers.yaml",
            "../config/ai_providers.yaml",
            os.path.join(os.path.dirname(__file__), "../config/ai_providers.yaml"),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return "config/ai_providers.yaml"

    def _load_config(self) -> Dict[str, Any]:
        """加载AI提供商配置"""
        if not os.path.exists(self.config_path):
            return self._get_default_config()

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                return config if config else {}
        except Exception as e:
            print(f"警告: 加载AI提供商配置失败 - {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认AI提供商配置"""
        return {
            'zhipu': {
                'name': '智谱AI',
                'api_base': 'https://open.bigmodel.cn/api/paas/v4/chat/completions',
                'model': 'glm-4',
                'timeout': 30,
                'max_retries': 3,
            },
            'qwen': {
                'name': '阿里云Qwen',
                'api_base': 'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions',
                'model': 'qwen-plus',
                'timeout': 30,
                'max_retries': 3,
            },
            'kimi': {
                'name': '月之暗面Kimi',
                'api_base': 'https://api.moonshot.cn/v1/chat/completions',
                'model': 'moonshot-v1-8k',
                'timeout': 30,
                'max_retries': 3,
            },
            'openai': {
                'name': 'OpenAI GPT',
                'api_base': 'https://api.openai.com/v1/chat/completions',
                'model': 'gpt-4o',
                'timeout': 30,
                'max_retries': 3,
            }
        }

    def get_provider(self, provider_name: str) -> Optional[Dict[str, Any]]:
        """
        获取指定提供商的配置

        Args:
            provider_name: 提供商名称 (zhipu, qwen, kimi)

        Returns:
            提供商配置字典，如果不存在则返回None
        """
        return self.providers.get(provider_name)

    def list_providers(self) -> Dict[str, str]:
        """
        列出所有可用的AI提供商

        Returns:
            提供商名称到显示名称的映射
        """
        return {
            key: config.get('name', key)
            for key, config in self.providers.items()
        }
