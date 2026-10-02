# -*- coding: utf-8 -*-
"""网络采集器: 监听端口、接口、路由、防火墙。"""
import subprocess


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def collect():
    return {
        'listening': _run('ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null'),
        'interfaces': _run('ip -brief addr 2>/dev/null || ifconfig -a'),
        'routes': _run('ip route 2>/dev/null || route -n'),
        'arp': _run('ip neigh 2>/dev/null || arp -a'),
        'iptables': _run('iptables -L -n 2>/dev/null'),
        'firewalld': _run('firewall-cmd --list-all 2>/dev/null'),
        'hosts': _read_hosts(),
    }


def _read_hosts():
    try:
        with open('/etc/hosts') as f:
            return f.read()
    except Exception:
        return ''