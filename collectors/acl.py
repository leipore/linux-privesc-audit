# -*- coding: utf-8 -*-
"""ACL 采集器: 对关键路径执行 getfacl。"""
import os
import subprocess


TARGETS = [
    '/etc/passwd', '/etc/shadow', '/etc/sudoers',
    '/etc/cron.d', '/etc/cron.daily', '/etc/systemd/system',
    '/root', '/usr/local/bin', '/usr/local/sbin',
]


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def collect():
    data = {'entries': [], 'available': False}
    if _run('command -v getfacl') == '':
        return data
    data['available'] = True

    for t in TARGETS:
        if not os.path.exists(t):
            continue
        out = _run(f'getfacl -p {t} 2>/dev/null')
        if out:
            data['entries'].append({'path': t, 'acl': out})
    return data