"""
Windows网络流量智能分析工具 - 主程序入口

命令行接口，用于分析JSONL格式的网络连接日志
"""
import sys
import os
import argparse
from datetime import datetime

# 添加src目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import Config, AIProvidersConfig
from src.file_scanner import FileScanner
from src.jsonl_parser import JSONLParser
from src.log_analyzer import LogAnalyzer
from src.ai_client import get_ai_client
from src.reporter import MarkdownReporter


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="Windows网络流量智能分析工具 - 分析JSONL格式的网络连接日志",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 分析单个文件
  python src/main.py --file data/net_2026-01-21.jsonl

  # 分析文件夹下所有文件
  python src/main.py --dir data/

  # 指定输出目录
  python src/main.py --dir data/ --output output/

  # 使用特定AI模型
  python src/main.py --dir data/ --model qwen

  # 禁用AI分析
  python src/main.py --file data/net.jsonl --no-ai

  # 查询特定IP的威胁情报
  python src/main.py --check-ip 8.8.8.8
  python src/main.py --file data/net.jsonl --check-ip 8.8.8.8

  # 查询IP段的威胁情报
  python src/main.py --check-ip-range 192.168.1.0/24
  python src/main.py --file data/net.jsonl --check-ip-range 192.168.1.0/24

  # 禁用威胁情报检查
  python src/main.py --dir data/ --no-threat-intel

  # 使用自定义AbuseIPDB API密钥
  python src/main.py --dir data/ --abuseipdb-key "your-api-key"
        """
    )

    parser.add_argument(
        '--file', '-f',
        type=str,
        help='单个JSONL文件路径'
    )

    parser.add_argument(
        '--dir', '-d',
        type=str,
        help='包含JSONL文件的目录'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        default='output',
        help='报告输出目录 (默认: output)'
    )

    parser.add_argument(
        '--model', '-m',
        type=str,
        choices=['zhipu', 'qwen', 'kimi', 'openai'],
        help='AI模型选择 (zhipu/qwen/kimi/openai)'
    )

    parser.add_argument(
        '--no-ai',
        action='store_true',
        help='禁用AI分析'
    )

    parser.add_argument(
        '--config',
        type=str,
        help='配置文件路径 (默认: config/config.yaml)'
    )

    parser.add_argument(
        '--max-size',
        type=float,
        default=10,
        help='最大文件大小限制(MB) (默认: 10)'
    )

    # 威胁情报查询参数
    parser.add_argument(
        '--check-ip',
        type=str,
        help='查询单个IP的威胁情报'
    )

    parser.add_argument(
        '--check-ip-range',
        type=str,
        help='查询IP段的威胁情报（如 192.168.1.0/24）'
    )

    parser.add_argument(
        '--no-threat-intel',
        action='store_true',
        help='禁用威胁情报检查'
    )

    parser.add_argument(
        '--abuseipdb-key',
        type=str,
        help='AbuseIPDB API密钥（优先于配置文件）'
    )

    return parser.parse_args()


def main():
    """主函数"""
    # 解析命令行参数
    args = parse_args()

    # 验证参数
    if not args.file and not args.dir and not args.check_ip and not args.check_ip_range:
        print("错误: 必须指定 --file、--dir、--check-ip 或 --check-ip-range 参数")
        print("使用 --help 查看帮助信息")
        sys.exit(1)

    # 加载配置
    print("加载配置...")
    config = Config(args.config)
    ai_providers_config = AIProvidersConfig()

    # 覆盖配置（命令行参数优先）
    if args.model:
        config.update('ai_provider', args.model)
    if args.output:
        config.update('output_dir', args.output)
    if args.abuseipdb_key:
        config.update('threat_intel.abuseipdb_api_key', args.abuseipdb_key)
    if hasattr(args, 'no_threat_intel') and args.no_threat_intel:
        config.update('threat_intel.enabled', False)

    # 创建输出目录
    output_dir = config.get_output_dir()
    os.makedirs(output_dir, exist_ok=True)
    print(f"输出目录: {output_dir}")

    # 处理威胁情报查询命令
    threat_intel_only = bool(args.check_ip or args.check_ip_range)

    # 如果是IP查询模式，跳过文件扫描
    if threat_intel_only:
        pass
    else:
        # 扫描文件
        print("\n" + "="*60)
        print("扫描文件...")
        print("="*60)

        file_scanner = FileScanner()
        file_paths = []

        if args.file:
            # 单文件模式
            file_path = file_scanner.scan_single_file(args.file)
            if file_path:
                file_paths.append(file_path)
        else:
            # 目录模式
            file_paths = file_scanner.scan_directory(args.dir)

        if not file_paths:
            print("错误: 未找到有效的JSONL文件")
            sys.exit(1)

    # 处理威胁情报查询命令
    threat_intel_only = bool(args.check_ip or args.check_ip_range)

    if threat_intel_only:
        # 仅进行威胁情报查询
        from threat_intel_client import ThreatIntelClient

        print("\n" + "="*60)
        print("威胁情报查询...")
        print("="*60)

        client = ThreatIntelClient(config)
        if not client.is_enabled():
            print("警告: 威胁情报未启用或未配置API密钥")
            if args.check_ip:
                # 查询单个IP
                result = client.check_ip(args.check_ip)
                if result.get('success'):
                    data = result['data']
                    print(f"\nIP: {args.check_ip}")
                    print(f"威胁类型: {', '.join(data.get('threatTypes', ['未知']))}")
                    print(f"置信度: {data.get('abuseConfidenceScore', 0)}/100")
                    print(f"国家: {data.get('countryName', 'Unknown')}")
                    print(f"报告次数: {data.get('totalReports', 0)}")
                else:
                    print(f"查询失败: {result.get('error', '未知错误')}")
            elif args.check_ip_range:
                # 查询IP段
                print(f"查询IP段: {args.check_ip_range}")
                results = client.check_ip_range(args.check_ip_range)
                if results:
                    total = len(results)
                    malicious = sum(1 for r in results if r.get('success') and r['data'].get('abuseConfidenceScore', 0) >= 80)
                    print(f"查询完成: {total}个IP, {malicious}个恶意IP")
                else:
                    print("查询失败")

        sys.exit(0)

    # 过滤文件大小
    filtered_files = file_scanner.filter_by_size(file_paths, args.max_size)
    if not filtered_files:
        print("错误: 所有文件都超过大小限制")
        sys.exit(1)

    # 解析JSONL文件
    print("\n" + "="*60)
    print("解析JSONL文件...")
    print("="*60)

    parser = JSONLParser(max_size_mb=args.max_size)
    records, errors = parser.parse_multiple_files(filtered_files)

    if not records:
        print("错误: 未解析到有效记录")
        if errors:
            print("\n错误详情:")
            for error in errors[:10]:
                print(f"  - {error}")
        sys.exit(1)

    if errors:
        print(f"\n警告: 遇到 {len(errors)} 个解析错误")
        # 仅进行威胁情报查询
        from threat_intel_client import ThreatIntelClient

        print("\n" + "="*60)
        print("威胁情报查询...")
        print("="*60)

        client = ThreatIntelClient(config)
        if not client.is_enabled():
            print("警告: 威胁情报未启用或未配置API密钥")
            if args.check_ip:
                # 查询单个IP
                result = client.check_ip(args.check_ip)
                if result.get('success'):
                    data = result['data']
                    print(f"\nIP: {args.check_ip}")
                    print(f"威胁类型: {', '.join(data.get('threatTypes', ['未知']))}")
                    print(f"置信度: {data.get('abuseConfidenceScore', 0)}/100")
                    print(f"国家: {data.get('countryName', 'Unknown')}")
                    print(f"报告次数: {data.get('totalReports', 0)}")
                else:
                    print(f"查询失败: {result.get('error', '未知错误')}")
            elif args.check_ip_range:
                # 查询IP段
                print(f"查询IP段: {args.check_ip_range}")
                results = client.check_ip_range(args.check_ip_range)
                if results:
                    total = len(results)
                    malicious = sum(1 for r in results if r.get('success') and r['data'].get('abuseConfidenceScore', 0) >= 80)
                    print(f"查询完成: {total}个IP, {malicious}个恶意IP")
                else:
                    print("查询失败")

        sys.exit(0)

    # 分析日志数据
    print("\n" + "="*60)
    print("分析日志数据...")
    print("="*60)

    analyzer = LogAnalyzer()

    # 根据参数选择分析方法
    if args.no_threat_intel:
        analysis_result = analyzer.analyze(records)
    else:
        analysis_result = analyzer.analyze_with_threat_intel(records)

    # AI分析
    ai_analysis = None
    if not args.no_ai:
        print("\n" + "="*60)
        print("AI智能分析...")
        print("="*60)

        # 获取AI配置
        ai_provider = config.get_ai_provider()
        api_key = config.get_api_key()

        if api_key:
            provider_config = ai_providers_config.get_provider(ai_provider)
            if provider_config:
                ai_client = get_ai_client(ai_provider, api_key, provider_config)
                if ai_client:
                    ai_analysis = ai_client.analyze_logs(analysis_result)
            else:
                print(f"警告: 未找到AI提供商配置 - {ai_provider}")
        else:
            print("警告: 未配置API Key，跳过AI分析")
            print("提示: 请在config/config.yaml中配置api_key，或设置环境变量AI_API_KEY")

    # 生成报告
    print("\n" + "="*60)
    print("生成分析报告...")
    print("="*60)

    reporter = MarkdownReporter()
    report_content = reporter.generate_report(
        analysis_result=analysis_result,
        ai_analysis=ai_analysis,
        file_info=file_scanner.get_file_info(file_paths[0]) if len(file_paths) == 1 else None
    )

    # 保存报告
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"network_analysis_report_{timestamp}.md"
    report_path = os.path.join(output_dir, report_filename)

    reporter.save_report(report_path)

    # 打印摘要
    print("\n" + "="*60)
    print("分析摘要")
    print("="*60)
    print(analyzer.get_summary_statistics(analysis_result))

    print("\n" + "="*60)
    print("完成!")
    print("="*60)
    print(f"报告已保存: {report_path}")

    if errors:
        print(f"⚠️  共遇到 {len(errors)} 个解析错误")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)