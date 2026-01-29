# 发布说明 - Windows网络流量智能分析工具 v1.1.0

## 版本信息
- **版本号**: v1.1.0
- **发布日期**: 2026-01-22
- **兼容性**: Python 3.10+
- **文件类型**: 压缩包分发

## 🎯 新增功能

### ThreatFox 威胁情报集成（核心功能）
- ✅ **实时恶意IP查询** - 集成 ThreatFox API，支持实时查询恶意 IP 情报
- ✅ **批量查询优化** - 一次最多查询 100 个 IP 地址，提高查询效率
- ✅ **智能过滤** - 自动过滤内网 IP，专注外网威胁查询
- ✅ **威胁情报可视化** - 在分析报告中直观显示威胁情报信息
- ✅ **风险标注** - 标注恶意 IP 及其威胁类型和风险等级
- ✅ **配置管理** - 支持 API Key 配置和功能开关控制

### AI 分析增强
- 🔍 **风险评估优化** - 改进风险等级算法，结合威胁情报数据
- ⚠️ **异常识别增强** - 基于威胁情报的恶意 IP 识别
- 💡 **安全建议改进** - 结合威胁情报提供更精准的安全建议

### 报告系统增强
- 📊 **威胁情报专门章节** - 新增"威胁情报发现"部分
- 🎨 **可视化改进** - 恶意 IP 标注（⚠️ 和 🔴 警告标识）
- 📋 **详细威胁信息** - 显示威胁类型、首次发现时间、最后发现时间

## 📁 发布包内容

### 核心文件结构
```
CheckNetEveryDay-v1.1.0/
├── src/                          # 源代码目录
│   ├── __init__.py
│   ├── main.py                   # 主程序入口
│   ├── config.py                # 配置管理模块
│   ├── file_scanner.py          # 文件扫描模块
│   ├── jsonl_parser.py          # JSONL解析模块
│   ├── log_analyzer.py          # 日志分析核心模块（含威胁情报）
│   ├── ai_client.py             # AI客户端（含ThreatFox）
│   ├── reporter.py              # 报告生成模块（含威胁情报展示）
│   └── utils/                    # 工具函数
│       ├── __init__.py
│       ├── ip_utils.py           # IP地址处理
│       ├── time_utils.py         # 时间处理
│       └── stats.py              # 统计计算
├── config/                       # 配置文件目录
│   ├── config.yaml              # 主配置文件（已启用威胁情报）
│   └── ai_providers.yaml        # AI服务商配置（含ThreatFox配置）
├── data/                        # 输入数据目录（空）
├── output/                      # 输出目录（空，用于生成报告）
├── tests/                       # 测试用例目录
├── examples/                    # 示例文件目录
├── docs/                        # 文档目录
│   ├── README.md               # 项目说明
│   ├── PRD-JSONL智能分析系统.md # 需求文档
│   ├── THREATFOX_INTEGRATION.md # ThreatFox集成说明
│   └── RELEASE_NOTES.md        # 发布说明
├── requirements.txt             # 依赖清单
├── setup.py                     # 安装脚本
└── package.py                  # 打包脚本
```

## 🛠️ 安装要求

### 系统要求
- **操作系统**: Windows/Linux/macOS
- **Python版本**: Python 3.10 或更高版本
- **内存**: 最少 512MB（推荐 1GB+）
- **磁盘空间**: 基础安装 50MB，日志文件按需

### 依赖包
```
jsonlines>=3.0.0
pandas>=1.3.0
numpy>=1.21.0
PyYAML>=6.0
requests>=2.25.0
python-dateutil>=2.8.0
chardet>=4.0.0
```

## 📋 安装步骤

### 1. 解压发布包
```bash
# 解压 CheckNetEveryDay-v1.1.0.zip 到目标目录
unzip CheckNetEveryDay-v1.1.0.zip
cd CheckNetEveryDay-v1.1.0
```

### 2. 安装依赖
```bash
# 安装 Python 依赖
pip install -r requirements.txt

# 或者使用 pip 安装主要依赖
pip install jsonlines pandas numpy pyyaml requests python-dateutil chardet
```

### 3. 配置 AI 服务（可选）
```bash
# 设置环境变量（推荐）
export AI_API_KEY="your_ai_api_key_here"

# 或直接编辑配置文件
# 编辑 config/config.yaml
```

### 4. 配置 ThreatFox（可选）
```bash
# 编辑 config/ai_providers.yaml 添加 ThreatFox API Key
threatfox:
  auth_key: "your_threatfox_api_key_here"
```

## 🚀 使用方法

### 基本使用
```bash
# 分析单个文件
python src/main.py --file data/net_2026-01-21.jsonl

# 分析整个目录
python src/main.py --dir data/

# 指定输出目录
python src/main.py --dir data/ --output output/
```

### 高级使用
```bash
# 使用不同AI模型
python src/main.py --file data/net.jsonl --model qwen
python src/main.py --file data/net.jsonl --model kimi

# 使用ThreatFox威胁情报
python src/main.py --file data/net.jsonl --model threatfox --no-ai

# 禁用AI分析（仅基础统计）
python src/main.py --file data/net.jsonl --no-ai
```

## 🔧 配置说明

### 主配置文件 (config/config.yaml)
```yaml
# AI服务商选择
ai_provider: zhipu

# API密钥
api_key: ""

# 分析配置
analysis:
  detect_anomalies: true
  check_threat_intel: true    # 启用威胁情报检查
  include_time_distribution: true

# 风险阈值
risk_threshold: medium
```

### AI服务商配置 (config/ai_providers.yaml)
包含智谱AI、阿里云Qwen、月之暗面Kimi 和 ThreatFox 的配置。

## 📊 输出示例

程序会生成包含以下内容的 Markdown 分析报告：
1. 执行摘要 - 关键发现、风险等级
2. 基础统计 - 连接数、IP数、进程数等
3. 时间分布分析 - 高峰时段、异常时间
4. 进程行为分析 - 系统进程、特权进程外网访问
5. IP访问分析 - Top IP地址、威胁情报标注
6. 端口分析 - 常见端口、高危端口
7. 用户分析 - 特权账户使用情况
8. 威胁情报分析 - 恶意IP发现、威胁类型详情
9. AI安全分析 - 风险评估和安全建议
10. 异常检测 - 详细异常信息
11. 数据附录 - 完整统计数据

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

## ⚠️ 注意事项

1. **API Key 管理**
   - ThreatFox API Key 需要用户自行获取和配置
   - 不要将 API Key 提交到版本控制系统
   - 定期检查 API Key 有效性

2. **性能考虑**
   - 威胁情报查询会增加分析时间
   - 大文件建议分批处理
   - 需要稳定的网络连接

3. **数据安全**
   - 本地处理数据，不泄露敏感信息
   - 生成的报告可能包含敏感信息，注意保管

## 🔄 更新说明

### 从 v1.0.0 升级到 v1.1.0
1. **完全兼容** - v1.1.0 完全兼容 v1.0.0 的配置文件
2. **默认启用威胁情报** - 新版本默认启用威胁情报功能
3. **新配置项** - 如需禁用威胁情报，设置 `check_threat_intel: false`
4. **文档更新** - 请阅读 `THREATFOX_INTEGRATION.md` 了解新功能

### 版本历史
- **v1.0.0** - 初始版本，基础功能和AI分析
- **v1.1.0** - 集成 ThreatFox 威胁情报，增强报告功能

## 📞 支持

如遇到问题，请参考：
- [README.md](README.md) - 基础使用说明
- [THREATFOX_INTEGRATION.md](THREATFOX_INTEGRATION.md) - ThreatFox集成说明
- [PRD-JSONL智能分析系统.md](PRD-JSONL智能分析系统.md) - 详细需求文档

## 📄 许可证

本项目仅供学习和研究使用。请遵守相关法律法规。

---

*发布日期: 2026-01-22*
*版本: v1.1.0*
*维护团队: Windows网络流量智能分析工具开发组*