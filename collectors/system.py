# -*- coding: utf-8 -*-
"""系统信息采集器: 主机名、内核、发行版、启动时间等。"""
import os
import platform
import subprocess
from datetime import datetime


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def collect():
    """采集系统级信息。"""
    data = {
        'hostname': platform.node(),
        'kernel_release': platform.release(),
        'kernel_version': platform.version(),
        'architecture': platform.machine(),
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'uptime': _run('uptime -p') or _run('uptime'),
        'boot_time': _run('who -b'),
        'date': datetime.now().isoformat(),
        'selinux': _run('getenforce'),
        'apparmor': _run('aa-status --enabled && echo enabled'),
        'os_release': {},
    }
    # /etc/os-release
    try:
        with open('/etc/os-release', 'r') as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    k, v = line.split('=', 1)
                    data['os_release'][k] = v.strip('"')
    except Exception:
        pass
    return data