# Windows网络流量智能分析工具

一个基于AI的智能分析工具，用于分析Windows网络连接日志（JSONL格式），生成结构化的分析报告，识别异常行为和潜在风险。

## 🚀 功能特性

### 核心功能
- ✅ **JSONL文件解析** - 支持批量解析JSONL格式网络连接日志
- ✅ **基础统计分析** - 时间分布、进程统计、IP分类、端口分析
- ✅ **AI智能分析** - 基于国产大模型的安全风险评估
- ✅ **Markdown报告生成** - 结构化的可视化分析报告

### 支持的分析维度
- **时间分析** - 连接时间分布、高峰时段、异常时间检测
- **进程分析** - 系统vs应用进程、特权进程外网访问
- **IP地址分析** - 内网/外网分类、访问频率统计
- **端口分析** - 常见端口、高危端口、服务识别
- **用户分析** - 特权账户统计、用户行为分析
- **异常检测** - 夜间连接、高危端口、可疑模式

### AI分析+威胁情报分析功能
- 🔍 **风险评估** - 自动计算风险等级（低/中/高）
- ⚠️ **异常识别** - 检测可疑网络连接模式
- 💡 **安全建议** - 基于分析结果提供具体建议

## 📋 系统要求

- Python 3.10+
- 内存: 最少 512MB（推荐 1GB+）
- 磁盘空间: 基础安装 50MB，日志文件按需

## 🛠️ 安装说明

### 1. 克隆/下载项目
```bash
# 如果是git仓库
git clone <repository-url>
cd CheckNetEveryDay

# 或者下载并解压到指定目录
```

### 2. 安装依赖
```bash
# 安装Python依赖
pip install -r requirements.txt

# 或者使用pip安装主要依赖
pip install jsonlines pandas numpy pyyaml requests python-dateutil chardet
```

### 3. 配置AI API密钥
选择一个AI服务商并获取API密钥：

#### 智谱AI
1. 访问 [智谱AI开放平台](https://open.bigmodel.cn/)
2. 注册账号并获取API Key
3. 配置到环境变量或配置文件：
```bash
# 方式1: 环境变量 (推荐)
export AI_API_KEY="your_zhipu_api_key_here"

# 方式2: 配置文件
# 编辑 config/config.yaml
api_key: "your_zhipu_api_key_here"
```

#### 阿里云Qwen
```bash
export AI_API_KEY="your_qwen_api_key_here"
# 然后在 config/config.yaml 中设置 ai_provider: qwen
```

#### 月之暗面Kimi
```bash
export AI_API_KEY="your_kimi_api_key_here"
# 然后在 config/config.yaml 中设置 ai_provider: kimi
```

#### OpenAI GPT
```bash
export AI_API_KEY="your_openai_api_key_here"
# 然后在 config/config.yaml 中设置 ai_provider: openai
```

**OpenAI 配置说明**：
- 支持 GPT-4o、GPT-4 Turbo、GPT-3.5 Turbo 等所有 OpenAI 模型
- 可在 `config/ai_providers.yaml` 中自由修改模型名称
- 支持使用 OpenAI 兼容的第三方 API 服务（修改 `api_base` 即可）
- 常用模型：`gpt-4o`、`gpt-4-turbo`、`gpt-3.5-turbo`

## 📖 使用指南

### 基本使用

#### 分析单个文件
```bash
python src/main.py --file data/net_2026-01-21.jsonl
```

#### 分析整个目录
```bash
python src/main.py --dir data/
```

#### 指定输出目录
```bash
python src/main.py --dir data/ --output output/
```

### 高级选项

#### 使用不同AI模型
```bash
# 使用阿里云Qwen
python src/main.py --file data/net.jsonl --model qwen

# 使用月之暗面Kimi
python src/main.py --file data/net.jsonl --model kimi

# 使用OpenAI GPT-4o
python src/main.py --file data/net.jsonl --model openai

# 使用OpenAI GPT-3.5 Turbo（需修改配置文件中的model）
python src/main.py --file data/net.jsonl --model openai
```

#### 禁用AI分析（仅基础统计）
```bash
python src/main.py --file data/net.jsonl --no-ai
```

#### 指定配置文件
```bash
python src/main.py --file data/net.jsonl --config custom_config.yaml
```

#### 限制文件大小
```bash
# 限制最大5MB
python src/main.py --dir data/ --max-size 5
```

### 查看帮助
```bash
python src/main.py --help
```

## 🔧 配置说明

### 主配置文件 (config/config.yaml)

```yaml
# AI服务商选择
ai_provider: zhipu

# API密钥
api_key: ""

# 输出格式
output_format: markdown

# 分析配置
analysis:
  detect_anomalies: true
  include_time_distribution: true

# 风险阈值
risk_threshold: medium
```

### AI服务商配置 (config/ai_providers.yaml)

包含各AI服务商的API基础URL、模型名称、超时时间等配置。


## 📄 许可证

本项目仅供学习和研究使用。请遵守相关法律法规。
