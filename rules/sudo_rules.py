# -*- coding: utf-8 -*-
"""sudo 规则: 识别 NOPASSWD、危险命令、通配符等。"""
import re


# 通过 sudo 可获取 shell 的危险命令
DANGEROUS_SUDO_COMMANDS = [
    'vim', 'vi', 'nano', 'ed', 'emacs', 'less', 'more', 'man', 'ftp', 'gdb',
    'python', 'python3', 'perl', 'ruby', 'php', 'lua', 'node',
    'bash', 'sh', 'dash', 'zsh',
    'find', 'awk', 'sed', 'grep',
    'apt', 'apt-get', 'dpkg', 'yum', 'dnf',
    'tar', 'zip', 'unzip',
    'docker', 'systemctl', 'journalctl',
    'cp', 'mv', 'chmod', 'chown',
    'env', 'tee', 'xargs', 'nmap',
]


def _finding(id_, sev, title, detail, evidence=None, remediation=''):
    return {
        'id': id_,
        'category': 'sudo',
        'severity': sev,
        'title': title,
        'detail': detail,
        'evidence': evidence,
        'remediation': remediation or '撤销不必要的 sudo 权限, 使用 sudoers 白名单限制命令。'
    }


def analyze(data):
    findings = []
    if not data or not data.get('available'):
        return findings

    if data.get('sudo_l_returncode') != 0:
        return findings

    out = data.get('sudo_l_output', '')
    for line in out.split('\n'):
        ll = line.lower()

        # NOPASSWD
        if 'nopasswd' in ll:
            findings.append(_finding(
                'SUDO-001', 'HIGH',
                'sudo 配置包含 NOPASSWD',
                f'规则: {line.strip()}',
                evidence=line.strip(),
                remediation='移除 NOPASSWD, 或限制为特定安全命令。'
            ))

        # 完全 sudo 权限
        if 'all=(all)' in ll and re.search(r'\ball\b', ll.split('all=(all)')[-1]):
            findings.append(_finding(
                'SUDO-002', 'CRITICAL',
                'sudo 拥有完全权限 (ALL=(ALL) ALL)',
                f'规则: {line.strip()}',
                evidence=line.strip(),
                remediation='按需分配具体命令权限。'
            ))

        # 通配符
        if '*' in line and 'nopasswd' not in ll:
            findings.append(_finding(
                'SUDO-003', 'MEDIUM',
                'sudo 规则包含通配符',
                f'规则: {line.strip()}',
                evidence=line.strip(),
                remediation='避免使用通配符, 或严格限制其匹配范围。'
            ))

        # 危险命令
        for cmd in DANGEROUS_SUDO_COMMANDS:
            if re.search(r'\b' + re.escape(cmd) + r'\b', ll):
                findings.append(_finding(
                    'SUDO-004', 'HIGH',
                    f'可通过 sudo 执行危险命令: {cmd}',
                    f'规则: {line.strip()}',
                    evidence=line.strip(),
                    remediation=f'移除对 {cmd} 的 sudo 授权, 或按 GTFOBins 检查其逃逸方式。'
                ))
                break

    return findings