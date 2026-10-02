# -*- coding: utf-8 -*-
"""sudo 权限采集器。"""
import subprocess


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), -1


def collect():
    data = {
        'available': False,
        'sudo_version': '',
        'sudo_l_output': '',
        'sudo_l_error': '',
        'sudo_l_returncode': -1,
        'sudoers_readable': False,
        'sudoers_content': '',
    }
    out, _, rc = _run('command -v sudo')
    if rc != 0 or not out:
        return data
    data['available'] = True

    data['sudo_version'] = _run('sudo --version 2>/dev/null | head -1')[0]

    out, err, rc = _run('sudo -n -l 2>&1')
    data['sudo_l_output'] = out
    data['sudo_l_error'] = err
    data['sudo_l_returncode'] = rc

    # 检查 sudoers 是否可读 (极少数配置)
    for p in ['/etc/sudoers', '/etc/sudoers.d']:
        try:
            with open(p, 'r') as f:
                data['sudoers_content'] += f'\n### {p}\n' + f.read(8192)
            data['sudoers_readable'] = True
        except Exception:
            pass
    return data