# -*- coding: utf-8 -*-
"""Linux Capabilities 采集器。"""
import subprocess


def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except Exception:
        return '', -1


def collect():
    data = {'available': False, 'entries': []}
    out, rc = _run('command -v getcap')
    if rc != 0:
        return data

    data['available'] = True
    out, _ = _run('getcap -r / 2>/dev/null', timeout=90)
    for line in out.split('\n'):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            data['entries'].append({
                'file': parts[0],
                'capabilities': ' '.join(parts[1:]),
            })
    return data