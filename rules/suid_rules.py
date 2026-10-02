# -*- coding: utf-8 -*-
"""SUID 规则: 危险二进制、可写 SUID 文件。"""

DEFAULT_SUID_WHITELIST = {
    'mount', 'umount', 'ping', 'ping6', 'su', 'passwd', 'chsh',
    'chfn', 'newgrp', 'gpasswd', 'fusermount', 'fusermount3',
    'pkexec', 'sudo', 'snap-confine', 'ntfs-3g',
    'dbus-daemon-launch-helper', 'unix_chkpwd',
}



DANGEROUS_SUID_BINARIES = [
    'bash', 'sh', 'dash', 'zsh', 'csh', 'ksh', 'ash', 'busybox',
    'nmap', 'vim', 'vi', 'nano', 'ed', 'emacs',
    'find', 'locate', 'mlocate', 'updatedb',
    'cp', 'mv', 'rm', 'cat', 'more', 'less', 'head', 'tail',
    'awk', 'gawk', 'mawk', 'sed', 'grep', 'egrep',
    'python', 'python2', 'python3', 'perl', 'ruby', 'php', 'lua', 'node',
    'tar', 'zip', 'unzip', 'gzip', 'bzip2', 'xz', '7z',
    'apt', 'apt-get', 'dpkg', 'yum', 'dnf', 'pacman',
    'docker', 'podman', 'lxc', 'nsenter',
    'mount', 'umount', 'fdisk', 'mkfs',
    'gdb', 'strace', 'ltrace',
    'env', 'tee', 'xargs', 'timeout', 'watch',
    'openssl', 'ssh', 'scp', 'rsync',
    'systemctl', 'journalctl',
    'curl', 'wget', 'nc', 'ncat', 'socat',
    'git', 'svn', 'npm',
]


def _finding(id_, sev, title, detail, evidence=None, remediation=''):
    return {
        'id': id_,
        'category': 'suid',
        'severity': sev,
        'title': title,
        'detail': detail,
        'evidence': evidence,
        'remediation': remediation or '移除不必要的 SUID 位, 或使用 setfacl/capabilities 替代。'
    }


def analyze(data):
    findings = []
    if not data:
        return findings

    suid = data.get('suid', []) or []
    sgid = data.get('sgid', []) or []
# 只对不在白名单内且命中 GTFOBins 的才报
    dangerous = [e for e in suid
             if e['name'] not in DEFAULT_SUID_WHITELIST
             and e['name'] in DANGEROUS_SUID_BINARIES]

    # 危险 SUID 二进制
    dangerous = []
    for entry in suid:
        path = entry.get('path', '')
        binary = path.rsplit('/', 1)[-1]
        if binary in DANGEROUS_SUID_BINARIES:
            dangerous.append(entry)
    if dangerous:
        findings.append(_finding(
            'SUID-001', 'HIGH',
            f'存在 {len(dangerous)} 个危险 SUID 二进制',
            '这些程序可通过 GTFOBins 技术用于提权',
            evidence=[e['path'] for e in dangerous],
        ))

    # 可写 SUID (极高危)
    writable = [e for e in suid if e.get('writable')]
    if writable:
        findings.append(_finding(
            'SUID-002', 'CRITICAL',
            f'存在 {len(writable)} 个可写 SUID 文件',
            '可直接修改文件内容以 root 权限执行任意代码',
            evidence=[e['path'] for e in writable],
            remediation='立即移除可写权限或 SUID 位。'
        ))

    # 危险 SGID
    dangerous_sgid = []
    for entry in sgid:
        path = entry.get('path', '')
        binary = path.rsplit('/', 1)[-1]
        if binary in DANGEROUS_SUID_BINARIES:
            dangerous_sgid.append(entry)
    if dangerous_sgid:
        findings.append(_finding(
            'SUID-003', 'MEDIUM',
            f'存在 {len(dangerous_sgid)} 个危险 SGID 二进制',
            'SGID 通常用于组权限提升',
            evidence=[e['path'] for e in dangerous_sgid],
        ))

    return findings