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

### AI分析功能
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

#### 智谱AI（推荐）
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

## 📁 项目结构

```
CheckNetEveryDay/
├── src/                          # 源代码目录
│   ├── __init__.py
│   ├── main.py                   # 主程序入口
│   ├── config.py                # 配置管理模块
│   ├── file_scanner.py          # 文件扫描模块
│   ├── jsonl_parser.py          # JSONL解析模块
│   ├── log_analyzer.py          # 日志分析核心模块
│   ├── ai_client.py             # AI客户端
│   ├── reporter.py              # 报告生成模块
│   └── utils/                    # 工具函数
│       ├── __init__.py
│       ├── ip_utils.py           # IP地址处理
│       ├── time_utils.py         # 时间处理
│       └── stats.py              # 统计计算
├── config/                       # 配置文件目录
│   ├── config.yaml              # 主配置文件
│   └── ai_providers.yaml        # AI服务商配置
├── data/                        # 输入数据目录
│   └── (放置.jsonl文件)
├── output/                       # 输出目录
│   └── (生成的报告)
├── tests/                        # 测试用例
├── examples/                     # 示例文件
├── requirements.txt              # 依赖清单
└── README.md                    # 项目说明
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

## 📊 输出示例

程序会生成包含以下内容的Markdown分析报告：

1. **执行摘要** - 关键发现、风险等级
2. **基础统计** - 连接数、IP数、进程数等
3. **时间分布分析** - 高峰时段、异常时间
4. **进程行为分析** - 系统进程、特权进程外网访问
5. **IP访问分析** - Top IP地址、内外网分布
6. **端口分析** - 常见端口、高危端口
7. **用户分析** - 特权账户使用情况
8. **AI安全分析** - 风险评估和安全建议
9. **异常检测** - 详细异常信息
10. **数据附录** - 完整统计数据

## 🎯 使用场景

### 网络安全分析
- 检测异常连接和可疑IP/端口访问
- 识别潜在的恶意活动
- 生成安全评估报告

### 系统运维监控
- 分析网络流量模式
- 监控进程网络行为
- 识别异常流量趋势

### 合规审计
- 网络访问记录分析
- 安全策略验证
- 风险审计支持

## 📋 支持的数据格式

输入的JSONL文件每行应包含以下字段：

```json
{
  "timestamp": "2026-01-21T18:30:47.7755863+08:00",
  "process": "C:\\Windows\\System32\\svchost.exe",
  "command_line": "",
  "user": "NT AUTHORITY\\NETWORK SERVICE",
  "dest_ip": "192.168.1.1",
  "dest_port": "53",
  "protocol": "udp",
  "domain": "",
  "source": "ip_only"
}
```

## 🔧 故障排除

### 常见问题

1. **"未找到有效的JSONL文件"**
   - 检查文件路径是否正确
   - 确保文件扩展名为.jsonl
   - 查看文件是否在指定目录

2. **"解析失败"**
   - 检查JSON格式是否正确
   - 确认每行都是有效的JSON对象

3. **"API调用失败"**
   - 检查API Key是否正确配置
   - 确认网络连接正常
   - 验证账户余额是否充足

4. **"内存不足"**
   - 减小max-size参数
   - 分批处理大文件

### 调试模式
遇到问题时，可以启用详细输出：

```bash
# 查看详细错误信息
python src/main.py --file data/net.jsonl 2>&1 | tee debug.log
```

## 🚧 开发和扩展

### 添加新的AI服务商
1. 在 `src/ai_client.py` 中创建新的客户端类
2. 在 `config/ai_providers.yaml` 中添加配置
3. 在 `get_ai_client()` 函数中注册

### 自定义分析规则
1. 在 `src/log_analyzer.py` 中添加新的分析方法
2. 在 `analyze()` 方法中调用新方法
3. 在 `src/reporter.py` 中添加报告输出

### 运行测试
```bash
# 安装测试依赖
pip install pytest pytest-cov

# 运行测试
pytest tests/

# 生成覆盖率报告
pytest tests/ --cov=src --cov-report=html
```

## 📄 许可证

本项目仅供学习和研究使用。请遵守相关法律法规。

## 🤝 贡献

欢迎提交问题报告和建议！

## 📞 联系方式

如有问题或建议，请通过以下方式联系：
- 创建GitHub Issue
- 发送邮件到维护者

---

*项目名称: Windows网络流量智能分析工具*
*版本: v1.2.0*
*最后更新: 2026-01-23*

## 🆕 v1.2.0 更新内容

### 新增功能
- ✅ **OpenAI GPT 集成** - 支持所有 OpenAI 模型（GPT-4o、GPT-4 Turbo、GPT-3.5 Turbo 等）
- ✅ **模型自由选择** - 用户可在配置文件中指定任意 OpenAI 模型
- ✅ **兼容 API 支持** - 支持 OpenAI 兼容的第三方 API 服务
- ✅ **命令行支持** - 新增 openai 模型选项