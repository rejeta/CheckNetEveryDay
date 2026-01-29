"""
独立的威胁情报查询工具
"""
import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

# 添加src目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from src.config import Config
from src.threat_intel_client import ThreatIntelClient


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="独立的威胁情报查询工具"
    )

    parser.add_argument(
        '--ip',
        type=str,
        help='要查询的IP地址'
    )

    parser.add_argument(
        '--ip-range',
        type=str,
        help='要查询的IP段（如 192.168.1.0/24）'
    )

    parser.add_argument(
        '--api-key',
        type=str,
        help='AbuseIPDB API密钥'
    )

    parser.add_argument(
        '--config',
        type=str,
        help='配置文件路径'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='显示详细信息'
    )

    return parser.parse_args()


def print_result(result: dict, verbose: bool = False):
    """打印查询结果"""
    if not result.get('success'):
        print(f"查询失败: {result.get('error', '未知错误')}")
        return

    data = result['data']

    print(f"\n查询成功")
    print(f"IP: {result['ip']}")
    print(f"{'='*50}")

    # 基本信息
    print(f"国家: {data.get('countryName', 'Unknown')}")
    print(f"总报告次数: {data.get('totalReports', 0)}")
    print(f"威胁置信度: {data.get('abuseConfidenceScore', 0)}/100")

    # 时间信息
    if verbose:
        first_reported = data.get('firstReported', 'Unknown')
        last_reported = data.get('lastReported', 'Unknown')
        print(f"首次报告: {first_reported}")
        print(f"最后报告: {last_reported}")

    # 威胁类型
    threat_types = data.get('threatTypes', [])
    if threat_types:
        print(f"威胁类型:")
        for threat_type in threat_types:
            print(f"   - {threat_type}")
    else:
        print(f"威胁类型: 无")

    # 使用情况
    usage_types = data.get('usageTypes', [])
    if usage_types:
        print(f"使用类型:")
        for usage_type in usage_types:
            print(f"   - {usage_type}")

    # 风险评估
    score = data.get('abuseConfidenceScore', 0)
    if score >= 80:
        risk_level = "高风险"
    elif score >= 30:
        risk_level = "中风险"
    else:
        risk_level = "低风险"

    print(f"\n风险评估: {risk_level}")


def print_range_summary(results: list, total_ips: int = None):
    """打印IP段查询摘要"""
    if not results:
        print("没有查询结果")
        return

    successful = [r for r in results if r.get('success')]
    failed = [r for r in results if not r.get('success')]

    if total_ips is None:
        total_ips = len(results)

    malicious = sum(1 for r in successful if r['data'].get('abuseConfidenceScore', 0) >= 80)
    suspicious = sum(1 for r in successful if 30 <= r['data'].get('abuseConfidenceScore', 0) < 80)
    clean = sum(1 for r in successful if r['data'].get('abuseConfidenceScore', 0) < 30)

    print(f"\nIP段查询摘要")
    print(f"{"="*50}")
    print(f"总查询数: {len(results)}")
    print(f"成功查询: {len(successful)}")
    print(f"查询失败: {len(failed)}")
    print(f"恶意IP: {malicious}")
    print(f"可疑IP: {suspicious}")
    print(f"清洁IP: {clean}")

    if successful:
        malicious_pct = (malicious / len(successful)) * 100
        print(f"恶意IP比例: {malicious_pct:.1f}%")

    if failed and len(failed) <= 5:
        print(f"\n失败详情:")
        for failure in failed:
            ip = failure.get('ip', failure.get('ip_range', 'N/A'))
            error = failure.get('error', '未知错误')
            print(f"   {ip}: {error}")


def main():
    """主函数"""
    args = parse_args()

    # 验证参数
    if not args.ip and not args.ip_range:
        print("错误: 必须指定 --ip 或 --ip-range 参数")
        print("使用 --help 查看帮助信息")
        sys.exit(1)

    # 加载配置
    config = Config(args.config)

    # 覆盖配置
    if args.api_key:
        config.update('threat_intel.abuseipdb_api_key', args.api_key)

    # 创建客户端
    client = ThreatIntelClient(config)

    # 检查是否启用
    if not client.is_enabled():
        print("❌ 威胁情报功能未启用或未配置API密钥")
        print("请在配置文件中设置 threat_intel.enabled: true")
        print("并配置 abuseipdb_api_key")
        sys.exit(1)

    # 执行查询
    if args.ip:
        print(f"查询单个IP: {args.ip}")
        result = client.check_ip(args.ip)
        print_result(result, args.verbose)

    elif args.ip_range:
        print(f"查询IP段: {args.ip_range}")
        results = client.check_ip_range(args.ip_range)
        print_range_summary(results)

    # 查询时间
    print(f"\n查询完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


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