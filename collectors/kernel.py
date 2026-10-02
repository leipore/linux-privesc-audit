# -*- coding: utf-8 -*-
"""内核信息采集器: 版本、模块、已知 CVE 提示。"""
import os
import re
import subprocess


# 供参考的已知内核 CVE 匹配表 (仅作提示)
KERNEL_CVE_HINTS = {
    '2.6': 'CVE-2009-1185 (udev) / 多个旧内核漏洞',
    '3.13': 'CVE-2014-0196 (n_tty)',
    '3.16': 'CVE-2014-9322',
    '4.4': 'CVE-2016-5195 (Dirty COW)',
    '4.8': 'CVE-2016-8655 (AF_PACKET)',
    '5.8': 'CVE-2021-22555 (Netfilter)',
    '5.11': 'CVE-2022-0185 (fs_context)',
    '5.15': 'CVE-2022-0847 (Dirty Pipe)',
    '6.1': '需关注近期发布的内核 CVE',
}


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def collect():
    ver = _run('uname -r')
    data = {
        'release': ver,
        'full': _run('uname -a'),
        'modules': _run('lsmod 2>/dev/null | head -100'),
        'cve_hints': [],
        'sysctl': {},
    }

    # 匹配已知 CVE
    m = re.match(r'(\d+\.\d+)', ver)
    if m:
        base = m.group(1)
        for k, v in KERNEL_CVE_HINTS.items():
            if base == k or base.startswith(k + '.'):
                data['cve_hints'].append({'kernel': ver, 'match': k, 'hint': v})

    # 常见安全 sysctl
    for key in ['kernel.unprivileged_userns_clone',
                'kernel.unprivileged_bpf_disabled',
                'kernel.kptr_restrict',
                'kernel.dmesg_restrict',
                'kernel.yama.ptrace_scope',
                'net.ipv4.ip_forward',
                'fs.protected_hardlinks',
                'fs.protected_symlinks']:
        v = _run(f'sysctl -n {key} 2>/dev/null')
        if v != '':
            data['sysctl'][key] = v
    return data