# -*- coding: utf-8 -*-
"""用户与组信息采集器。"""
import os
import pwd
import grp
import subprocess


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def _current_user():
    try:
        pw = pwd.getpwuid(os.getuid())
        return {
            'username': pw.pw_name,
            'uid': pw.pw_uid,
            'gid': pw.pw_gid,
            'home': pw.pw_dir,
            'shell': pw.pw_shell,
            'gecos': pw.pw_gecos,
        }
    except Exception:
        return {}


def _current_groups():
    """返回当前用户所属所有组名。"""
    groups = []
    try:
        groups.append(grp.getgrgid(os.getgid()).gr_name)
    except Exception:
        pass
    try:
        pw = pwd.getpwuid(os.getuid())
        for g in grp.getgrall():
            if pw.pw_name in g.gr_mem and g.gr_name not in groups:
                groups.append(g.gr_name)
    except Exception:
        pass
    return groups


def _all_users():
    users = []
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                p = line.split(':')
                if len(p) >= 7:
                    users.append({
                        'username': p[0],
                        'uid': int(p[2]) if p[2].isdigit() else -1,
                        'gid': int(p[3]) if p[3].isdigit() else -1,
                        'home': p[5],
                        'shell': p[6],
                    })
    except Exception:
        pass
    return users


def _all_groups():
    out = []
    for g in grp.getgrall():
        out.append({'name': g.gr_name, 'gid': g.gr_gid, 'members': g.gr_mem})
    return out


def collect():
    return {
        'current_user': _current_user(),
        'current_uid': os.getuid(),
        'current_gid': os.getgid(),
        'is_root': os.getuid() == 0,
        'current_groups': _current_groups(),
        'all_users': _all_users(),
        'all_groups': _all_groups(),
        'who': _run('who'),
        'w': _run('w -h'),
        'last_logins': _run('last -n 10'),
    }