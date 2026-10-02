# -*- coding: utf-8 -*-
"""Cron 计划任务采集器。"""
import os
import subprocess


CRON_PATHS = [
    '/etc/crontab',
    '/etc/cron.d',
    '/etc/cron.daily',
    '/etc/cron.hourly',
    '/etc/cron.weekly',
    '/etc/cron.monthly',
    '/var/spool/cron',
    '/var/spool/cron/crontabs',
]


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def _read(path):
    try:
        with open(path, 'r', errors='ignore') as f:
            return f.read()
    except Exception:
        return None


def collect():
    data = {'files': [], 'user_crontab': '', 'spool': []}

    for p in CRON_PATHS:
        if os.path.isfile(p):
            c = _read(p)
            if c is not None:
                data['files'].append({'path': p, 'content': c, 'is_dir': False,
                                      'writable': os.access(p, os.W_OK)})
        elif os.path.isdir(p):
            try:
                for f in os.listdir(p):
                    fp = os.path.join(p, f)
                    if os.path.isfile(fp):
                        c = _read(fp)
                        if c is not None:
                            data['files'].append({'path': fp, 'content': c, 'is_dir': False,
                                                  'writable': os.access(fp, os.W_OK)})
            except Exception:
                pass

    data['user_crontab'] = _run('crontab -l 2>/dev/null')
    return data