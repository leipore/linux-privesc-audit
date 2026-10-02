# -*- coding: utf-8 -*-
"""SUID / SGID 文件采集器。"""
import os
import pwd
import grp
import subprocess



def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def _stat_info(path):
    try:
        st = os.stat(path)
        return {
            'path': path,
            'owner': pwd.getpwuid(st.st_uid).pw_name,
            'group': grp.getgrgid(st.st_gid).gr_name,
            'permissions': oct(st.st_mode)[-4:],
            'writable': os.access(path, os.W_OK),
            'size': st.st_size,
        }
    except Exception:
        return {'path': path}


def collect():
    data = {'suid': [], 'sgid': [], 'findings': []}

    out = _run("find / -xdev -perm -4000 -type f 2>/dev/null")
    for line in out.split('\n'):
        line = line.strip()
        if line:
            data['suid'].append(_stat_info(line))

    out = _run("find / -xdev -perm -2000 -type f 2>/dev/null")
    for line in out.split('\n'):
        line = line.strip()
        if line:
            data['sgid'].append(_stat_info(line))

    return data