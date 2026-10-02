# -*- coding: utf-8 -*-
"""systemd 单元采集器: 服务、定时器、可写单元文件。"""
import os
import subprocess


SYSTEMD_PATHS = [
    '/etc/systemd/system',
    '/lib/systemd/system',
    '/usr/lib/systemd/system',
    '/run/systemd/system',
]


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def _read(p):
    try:
        with open(p, 'r', errors='ignore') as f:
            return f.read(16384)
    except Exception:
        return None


def collect():
    data = {
        'services': [],
        'timers': [],
        'writable_units': [],
        'unit_files': [],
    }

    data['services'] = _run('systemctl list-units --type=service --no-pager 2>/dev/null').split('\n')
    data['timers'] = _run('systemctl list-timers --no-pager 2>/dev/null').split('\n')

    for base in SYSTEMD_PATHS:
        if not os.path.isdir(base):
            continue
        try:
            for root, dirs, files in os.walk(base):
                depth = root[len(base):].count(os.sep)
                if depth > 2:
                    dirs[:] = []
                    continue
                for f in files:
                    if not (f.endswith('.service') or f.endswith('.timer') or f.endswith('.socket')):
                        continue
                    fp = os.path.join(root, f)
                    entry = {
                        'path': fp,
                        'writable': os.access(fp, os.W_OK),
                        'content': _read(fp),
                    }
                    data['unit_files'].append(entry)
                    if entry['writable']:
                        data['writable_units'].append(entry)
        except Exception:
            pass
    return data