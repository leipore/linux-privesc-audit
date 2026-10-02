# -*- coding: utf-8 -*-
"""文本报告输出模块 (彩色终端)。"""


RESET = '\033[0m'
BOLD = '\033[1m'
RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
BLUE = '\033[94m'
GRAY = '\033[90m'

SEV_COLOR = {
    'CRITICAL': RED,
    'HIGH': RED,
    'MEDIUM': YELLOW,
    'LOW': GREEN,
    'INFO': GRAY,
}


def _color(sev):
    return SEV_COLOR.get(sev.upper(), RESET)


def print_report(report):
    """打印报告到终端。"""
    meta = report.get('metadata', {})
    summary = report.get('summary', {})
    findings = report.get('findings', [])
    raw = report.get('raw_data', {})

    width = 72
    print("\n" + "=" * width)
    print(f"{BOLD} Linux Privilege Escalation Audit Report{RESET}")
    print("=" * width)
    print(f" 主机:     {meta.get('host', 'N/A')}")
    print(f" 时间:     {meta.get('timestamp', 'N/A')}")
    print(f" 工具版本: {meta.get('tool')} v{meta.get('version')}")

    # 系统信息
    sysinfo = raw.get('system', {})
    if sysinfo:
        print(f" 内核:     {sysinfo.get('kernel_release', 'N/A')}")
        osr = sysinfo.get('os_release', {})
        print(f" 发行版:   {osr.get('PRETTY_NAME', osr.get('NAME', 'N/A'))}")

    # 当前用户
    uinfo = raw.get('users', {}).get('current_user', {})
    if uinfo:
        print(f" 当前用户: {uinfo.get('username')} (uid={uinfo.get('uid')})")

    print("-" * width)
    print(f"{BOLD}[摘要]{RESET}  总计 {summary.get('total', 0)} 项")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        cnt = summary.get(sev, 0)
        if cnt:
            print(f"   {_color(sev)}{sev:<9}{RESET} {cnt}")
    print("-" * width)

    if not findings:
        print(f"{GREEN}未发现明显提权风险。{RESET}")
        print("=" * width + "\n")
        return

    print(f"\n{BOLD}[发现详情]{RESET}\n")
    for i, f in enumerate(findings, 1):
        sev = f.get('severity', 'INFO').upper()
        c = _color(sev)
        print(f"{c}[{sev:^8}]{RESET} {BOLD}{f.get('id', '')}  {f.get('title', '')}{RESET}")
        if f.get('detail'):
            print(f"           {f['detail']}")
        ev = f.get('evidence')
        if ev:
            if isinstance(ev, list):
                for e in ev[:5]:
                    if isinstance(e, dict):
                        # 只打印最有代表性的一两个字段
                        key_line = ', '.join(f"{k}={v}" for k, v in e.items()
                                             if k in ('path', 'file', 'script', 'capability',
                                                      'note', 'rule', 'line', 'cron_line'))
                        print(f"           · {key_line}")
                    else:
                        print(f"           · {e}")
                if len(ev) > 5:
                    print(f"           · ... (其余 {len(ev) - 5} 条见 JSON 报告)")
            else:
                print(f"           证据: {str(ev)[:200]}")
        if f.get('remediation'):
            print(f"           修复: {f['remediation']}")
        print()

    print("=" * width)