# -*- coding: utf-8 -*-
"""文件系统权限采集器: 全局可写文件/目录、关键路径可写检测。"""
import os
import pwd
import subprocess


CRITICAL_PATHS = [
    '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/sudoers.d',
    '/etc/crontab', '/etc/cron.d', '/etc/init.d', '/etc/systemd/system',
    '/usr/local/bin', '/usr/local/sbin', '/root',
]


def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def _owner(path):
    try:
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except Exception:
        return 'unknown'


def collect():
    data = {
        'world_writable_files': [],
        'world_writable_dirs': [],
        'critical_writable': [],
    }

    out = _run(
        "find / -xdev -type f -perm -o+w "
        "! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' "
        "! -path '/run/*' ! -path '/tmp/*' ! -path '/var/tmp/*' "
        "2>/dev/null | head -200"
    )
    data['world_writable_files'] = [x for x in out.split('\n') if x.strip()]

    out = _run(
        "find / -xdev -type d -perm -o+w "
        "! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' "
        "! -path '/run/*' ! -path '/tmp' ! -path '/var/tmp' "
        "2>/dev/null | head -100"
    )
    data['world_writable_dirs'] = [x for x in out.split('\n') if x.strip()]

    for p in CRITICAL_PATHS:
        if os.path.exists(p) and os.access(p, os.W_OK):
            data['critical_writable'].append({
                'path': p,
                'owner': _owner(p),
                'is_dir': os.path.isdir(p),
            })
    return data