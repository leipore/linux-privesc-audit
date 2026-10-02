# -*- coding: utf-8 -*-
"""Cron 规则: 可写脚本、通配符注入、PATH 劫持。"""
import os
import re


def _finding(id_, sev, title, detail, evidence=None, remediation=''):
    return {
        'id': id_,
        'category': 'cron',
        'severity': sev,
        'title': title,
        'detail': detail,
        'evidence': evidence,
        'remediation': remediation or '限制 cron 脚本的写权限, 使用绝对路径调用外部命令。'
    }


def _extract_scripts(line):
    """从 cron 行中提取脚本绝对路径。"""
    return re.findall(r'(/[^\s;|&]+\.(?:sh|py|pl|rb|php))', line)


def analyze(data):
    findings = []
    if not data:
        return findings

    files = data.get('files', [])
    writable_scripts = []
    wildcard_issues = []
    relative_cmds = []

    for f in files:
        content = f.get('content', '') or ''
        source = f.get('path', '')

        for line in content.split('\n'):
            s = line.strip()
            if not s or s.startswith('#'):
                continue

            # 通配符注入风险
            if '*' in s and not s.startswith('@'):
                parts = s.split()
                if len(parts) >= 6:
                    cmd = ' '.join(parts[5:])
                    if any(wd in cmd for wd in ['/tmp', '/var/tmp', '/home', '/opt']):
                        wildcard_issues.append({'source': source, 'line': s})

            # 提取脚本检查可写性
            for sp in _extract_scripts(s):
                if os.path.exists(sp):
                    if os.access(sp, os.W_OK):
                        writable_scripts.append({
                            'script': sp, 'source': source, 'cron_line': s,
                            'note': '脚本本身可写',
                        })
                    else:
                        d = os.path.dirname(sp)
                        if os.path.isdir(d) and os.access(d, os.W_OK):
                            writable_scripts.append({
                                'script': sp, 'source': source, 'cron_line': s,
                                'note': f'脚本所在目录 {d} 可写, 可替换',
                            })

            # 相对路径命令 (潜在 PATH 劫持)
            parts = s.split()
            if len(parts) >= 6:
                cmd = parts[5]
                if cmd and not cmd.startswith('/') and not cmd.startswith('@'):
                    relative_cmds.append({'source': source, 'cmd': cmd, 'line': s})

    if writable_scripts:
        findings.append(_finding(
            'CRON-001', 'CRITICAL',
            f'发现 {len(writable_scripts)} 个可写的 Cron 脚本/目录',
            '可注入提权命令, 等待 root 定时执行',
            evidence=writable_scripts[:20],
        ))

    if wildcard_issues:
        findings.append(_finding(
            'CRON-002', 'HIGH',
            f'发现 {len(wildcard_issues)} 个通配符注入风险',
            '命令含通配符且在可写目录执行, 可被利用注入参数',
            evidence=wildcard_issues[:20],
        ))

    if relative_cmds:
        findings.append(_finding(
            'CRON-003', 'MEDIUM',
            f'发现 {len(relative_cmds)} 个相对路径命令调用',
            'cron 中若 PATH 含可写目录, 可通过同名程序劫持',
            evidence=relative_cmds[:20],
        ))

    return findings