# -*- coding: utf-8 -*-
"""进程采集器: root 进程、监听服务、环境变量泄漏。"""
import os
import subprocess


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def _proc_env(pid):
    """读取指定进程的环境变量 (可能因权限失败)。"""
    try:
        with open(f'/proc/{pid}/environ', 'rb') as f:
            return f.read().decode(errors='ignore').replace('\x00', '\n')
    except Exception:
        return None


def collect():
    data = {'processes': [], 'root_processes': [], 'env_leaks': []}

    out = _run('ps aux --sort=-%mem 2>/dev/null | head -100')
    for line in out.split('\n')[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        entry = {
            'user': parts[0],
            'pid': parts[1],
            'cpu': parts[2],
            'mem': parts[3],
            'command': parts[10],
        }
        data['processes'].append(entry)
        if entry['user'] == 'root':
            data['root_processes'].append(entry)

    # 尝试读取进程环境 (敏感泄漏)
    for p in data['processes'][:30]:
        env = _proc_env(p['pid'])
        if not env:
            continue
        lower = env.lower()
        for kw in ['password', 'passwd', 'secret', 'token', 'api_key', 'aws_']:
            if kw in lower:
                data['env_leaks'].append({
                    'pid': p['pid'],
                    'user': p['user'],
                    'command': p['command'],
                    'matched_env': env[:2000],
                    'keyword': kw,
                })
                break
    return data