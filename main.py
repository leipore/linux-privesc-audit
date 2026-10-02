#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux Privilege Escalation Audit Tool — 主入口

流程:
    1. 加载所有 collectors 采集原始系统数据
    2. 通过 rules 引擎分析数据生成 findings
    3. 通过 output 模块输出 JSON / 文本报告

用法:
    python3 main.py                              # 采集 + 分析 + 文本报告
    python3 main.py -o report.json               # 同时输出 JSON
    python3 main.py --skip suid,filesystem       # 跳过耗时采集器
    python3 main.py --only sudo,cron             # 只运行指定采集器
    python3 main.py --list                       # 列出所有采集器
"""
import argparse
import sys
import traceback
from datetime import datetime

# --- Collectors ---
from collectors import (
    system as c_system,
    users as c_users,
    sudo as c_sudo,
    suid as c_suid,
    capabilities as c_capabilities,
    filesystem as c_filesystem,
    cron as c_cron,
    systemd as c_systemd,
    processes as c_processes,
    network as c_network,
    credentials as c_credentials,
    containers as c_containers,
    kubernetes as c_kubernetes,
    kernel as c_kernel,
    nfs as c_nfs,
    acl as c_acl,
)

# --- Rules ---
from rules import (
    sudo_rules,
    suid_rules,
    capability_rules,
    cron_rules,
    systemd_rules,
)

# --- Output ---
from output import json_report, text_report


# 采集器注册表 (名称 -> 模块)
COLLECTOR_REGISTRY = [
    ('system', c_system),
    ('users', c_users),
    ('sudo', c_sudo),
    ('suid', c_suid),
    ('capabilities', c_capabilities),
    ('filesystem', c_filesystem),
    ('cron', c_cron),
    ('systemd', c_systemd),
    ('processes', c_processes),
    ('network', c_network),
    ('credentials', c_credentials),
    ('containers', c_containers),
    ('kubernetes', c_kubernetes),
    ('kernel', c_kernel),
    ('nfs', c_nfs),
    ('acl', c_acl),
]

# 规则注册表 (名称 -> 模块), 名称需要和采集器同名以获取对应数据
RULE_REGISTRY = {
    'sudo': sudo_rules,
    'suid': suid_rules,
    'capabilities': capability_rules,
    'cron': cron_rules,
    'systemd': systemd_rules,
}


def run_collection(skip=None, only=None):
    """
    运行所有采集器。
    :param skip: 跳过的采集器名称集合
    :param only: 只运行的采集器名称集合 (None 表示运行全部)
    :return: {采集器名: 采集数据字典}
    """
    skip = set(skip or [])
    only = set(only) if only else None
    raw = {}

    for name, module in COLLECTOR_REGISTRY:
        if only is not None and name not in only:
            raw[name] = {'skipped': True, 'reason': 'not in --only'}
            continue
        if name in skip:
            raw[name] = {'skipped': True, 'reason': '--skip'}
            continue

        print(f"[*] 采集: {name} ...", flush=True)
        try:
            raw[name] = module.collect()
        except Exception as e:
            raw[name] = {'error': str(e)}
            print(f"[!] 采集器 {name} 失败: {e}", file=sys.stderr)
            traceback.print_exc()

    return raw


def run_rules(raw_data):
    """
    依次运行规则引擎。
    :param raw_data: run_collection() 返回的原始数据
    :return: findings 列表
    """
    findings = []
    for name, module in RULE_REGISTRY.items():
        data = raw_data.get(name, {})
        if not data or data.get('skipped') or data.get('error'):
            continue
        try:
            findings.extend(module.analyze(data))
        except Exception as e:
            print(f"[!] 规则 {name} 失败: {e}", file=sys.stderr)
    return findings


def build_report(raw_data, findings):
    """构建统一报告结构。"""
    summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0, 'total': 0}
    for f in findings:
        sev = f.get('severity', 'INFO').upper()
        summary[sev] = summary.get(sev, 0) + 1
        summary['total'] += 1

    # 按严重性排序
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    findings.sort(key=lambda x: order.get(x.get('severity', 'INFO'), 5))

    return {
        'metadata': {
            'tool': 'linux-privesc-audit',
            'version': '1.0',
            'timestamp': datetime.now().isoformat(),
            'host': raw_data.get('system', {}).get('hostname', 'unknown'),
        },
        'summary': summary,
        'findings': findings,
        'raw_data': raw_data,
    }


def parse_args():
    p = argparse.ArgumentParser(
        description='Linux 本地提权审计工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python3 main.py -o report.json\n"
               "  python3 main.py --skip suid,filesystem,acl\n"
               "  python3 main.py --only sudo,suid,credentials\n"
               "  python3 main.py --list\n"
    )
    p.add_argument('-o', '--output', help='JSON 报告输出路径')
    p.add_argument('--skip', help='跳过的采集器 (逗号分隔)')
    p.add_argument('--only', help='只运行指定采集器 (逗号分隔)')
    p.add_argument('--quiet', action='store_true', help='仅输出 JSON 至 stdout')
    p.add_argument('--list', action='store_true', help='列出所有采集器并退出')
    return p.parse_args()


def main():
    args = parse_args()

    if args.list:
        print("可用采集器:")
        for name, _ in COLLECTOR_REGISTRY:
            mark = ' [规则]' if name in RULE_REGISTRY else ''
            print(f"  - {name}{mark}")
        return 0

    skip = args.skip.split(',') if args.skip else None
    only = args.only.split(',') if args.only else None

    print("=" * 60)
    print(" Linux Privilege Escalation Audit")
    print("=" * 60)

    raw_data = run_collection(skip=skip, only=only)
    findings = run_rules(raw_data)
    report = build_report(raw_data, findings)

    # 文本报告
    if not args.quiet:
        text_report.print_report(report)

    # JSON 报告
    if args.output:
        json_report.save(report, args.output)
        print(f"[+] JSON 报告已保存: {args.output}")
    elif args.quiet:
        print(json_report.dumps(report))

    # 摘要
    s = report['summary']
    print(f"\n[摘要] 共 {s['total']} 项发现: "
          f"CRITICAL={s['CRITICAL']} HIGH={s['HIGH']} "
          f"MEDIUM={s['MEDIUM']} LOW={s['LOW']}")

    return 0


if __name__ == '__main__':
    sys.exit(main())