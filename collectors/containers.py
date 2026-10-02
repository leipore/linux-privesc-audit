# -*- coding: utf-8 -*-
"""容器采集器: Docker/Podman/LXC 环境、socket、危险组。"""
import os
import pwd
import grp
import subprocess


DANGEROUS_GROUP_NAMES = ['docker', 'lxd', 'lxc', 'disk', 'shadow', 'kmem',
                         'adm', 'video', 'sudo', 'wheel', 'staff', 'plugdev']

DOCKER_SOCKETS = [
    '/var/run/docker.sock',
    '/run/docker.sock',
    '/var/run/podman/podman.sock',
    '/run/containerd/containerd.sock',
]


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def _detect_runtime():
    if os.path.exists('/.dockerenv'):
        return 'docker'
    if os.path.exists('/run/.containerenv'):
        return 'podman'
    try:
        with open('/proc/1/cgroup') as f:
            c = f.read()
        for k in ('docker', 'lxc', 'kubepods', 'containerd', 'podman'):
            if k in c:
                return k
    except Exception:
        pass
    try:
        with open('/proc/1/environ', 'rb') as f:
            env = f.read().decode(errors='ignore')
        if 'container=' in env:
            return 'generic'
    except Exception:
        pass
    return None


def _current_groups():
    groups = []
    try:
        groups.append(grp.getgrgid(os.getgid()).gr_name)
    except Exception:
        pass
    try:
        pw = pwd.getpwuid(os.getuid())
        for g in grp.getgrall():
            if pw.pw_name in g.gr_mem:
                groups.append(g.gr_name)
    except Exception:
        pass
    return list(dict.fromkeys(groups))


def _sockets():
    out = []
    for s in DOCKER_SOCKETS:
        if os.path.exists(s):
            try:
                st = os.stat(s)
                out.append({
                    'path': s,
                    'writable': os.access(s, os.W_OK),
                    'permissions': oct(st.st_mode)[-4:],
                    'owner': pwd.getpwuid(st.st_uid).pw_name,
                    'group': grp.getgrgid(st.st_gid).gr_name,
                })
            except Exception:
                pass
    return out


def collect():
    groups = _current_groups()
    return {
        'in_container': _detect_runtime() is not None,
        'runtime': _detect_runtime(),
        'current_groups': groups,
        'dangerous_groups': [g for g in groups if g in DANGEROUS_GROUP_NAMES],
        'sockets': _sockets(),
        'docker_version': _run('docker version --format "{{.Server.Version}}" 2>/dev/null'),
        'lxd_present': os.path.exists('/snap/bin/lxc') or _run('command -v lxc') != '',
    }