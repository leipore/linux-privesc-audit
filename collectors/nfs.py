# -*- coding: utf-8 -*-
"""NFS 采集器: exports 配置、挂载信息。"""
import os
import subprocess


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def _read(p):
    try:
        with open(p) as f:
            return f.read()
    except Exception:
        return ''


def collect():
    data = {
        'exports': _read('/etc/exports'),
        'exports_d': [],
        'mounts': _run('mount | grep -i nfs'),
        'showmount': _run('showmount -e 2>/dev/null'),
        'fstab': _read('/etc/fstab'),
    }

    if os.path.isdir('/etc/exports.d'):
        try:
            for f in os.listdir('/etc/exports.d'):
                fp = os.path.join('/etc/exports.d', f)
                if os.path.isfile(fp):
                    data['exports_d'].append({'path': fp, 'content': _read(fp)})
        except Exception:
            pass
    return data