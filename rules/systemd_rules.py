# -*- coding: utf-8 -*-
"""systemd 规则: 可写单元、危险指令、PATH 劫持。"""
import re


DANGEROUS_DIRECTIVES = [
    # ExecStart 中调用相对路径命令 (PATH 劫持风险)
    ('ExecStart=', 'MEDIUM'),
    ('ExecStartPre=', 'MEDIUM'),
    ('ExecStartPost=', 'MEDIUM'),
    ('ExecReload=', 'MEDIUM'),
    ('ExecStop=', 'MEDIUM'),
]


def _finding(id_, sev, title, detail, evidence=None, remediation=''):
    return {
        'id': id_,
        'category': 'systemd',
        'severity': sev,
        'title': title,
        'detail': detail,
        'evidence': evidence,
        'remediation': remediation or '限制单元文件的写权限, 使用绝对路径, 避免使用 root 运行可写单元。'
    }


def analyze(data):
    findings = []
    if not data:
        return findings

    writable = data.get('writable_units', [])
    if writable:
        findings.append(_finding(
            'SYSD-001', 'CRITICAL',
            f'发现 {len(writable)} 个可写的 systemd 单元文件',
            '可修改单元文件使服务在重启时以 root 执行任意命令',
            evidence=[{'path': w['path']} for w in writable],
        ))

    # 相对路径 ExecStart
    relative_cmds = []
    for u in data.get('unit_files', []):
        content = u.get('content') or ''
        for line in content.split('\n'):
            for directive, _ in DANGEROUS_DIRECTIVES:
                if line.startswith(directive):
                    cmd = line.split('=', 1)[1].strip()
                    # 检查是否为相对路径
                    first = cmd.split()[0] if cmd.split() else ''
                    if first and not first.startswith('/') and not first.startswith('-'):
                        relative_cmds.append({
                            'unit': u['path'],
                            'line': line.strip(),
                            'cmd': first,
                        })

    if relative_cmds:
        findings.append(_finding(
            'SYSD-002', 'MEDIUM',
            f'发现 {len(relative_cmds)} 处相对路径调用命令',
            '如果服务的 PATH 包含可写目录, 可被劫持',
            evidence=relative_cmds[:20],
        ))

    return findings