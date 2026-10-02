# -*- coding: utf-8 -*-
"""Capabilities 规则: 识别可提权的 capability 分配。"""

DANGEROUS_CAPS = {
    'cap_setuid':     ('CRITICAL', '可任意设置 UID, 直接切到 root'),
    'cap_setgid':     ('CRITICAL', '可任意设置 GID'),
    'cap_sys_admin':  ('CRITICAL', '拥有大量管理员操作能力 (mount 等)'),
    'cap_sys_ptrace': ('CRITICAL', '可 ptrace 任意进程, 注入 root 进程'),
    'cap_dac_override': ('CRITICAL', '绕过文件读写权限检查'),
    'cap_dac_read_search': ('HIGH', '可读取任意文件'),
    'cap_sys_module': ('CRITICAL', '可加载内核模块'),
    'cap_sys_chroot': ('HIGH', '可 chroot 逃逸'),
    'cap_net_raw':    ('MEDIUM', '可构造原始数据包 (中间人/嗅探)'),
    'cap_net_admin':  ('HIGH', '网络管理能力'),
    'cap_net_bind_service': ('LOW', '可绑定低端口'),
    'cap_sys_rawio':  ('CRITICAL', '可进行原始 I/O'),
    'cap_mknod':      ('HIGH', '可创建任意设备节点'),
    'cap_fowner':     ('MEDIUM', '可修改文件属主'),
    'cap_kill':       ('MEDIUM', '可向任意进程发送信号'),
    'cap_setfcap':    ('HIGH', '可设置文件 capabilities'),
}


def _finding(id_, sev, title, detail, evidence=None, remediation=''):
    return {
        'id': id_,
        'category': 'capabilities',
        'severity': sev,
        'title': title,
        'detail': detail,
        'evidence': evidence,
        'remediation': remediation or '移除不必要的 capabilities, 使用 systemd 沙箱或 seccomp 限制。'
    }


def analyze(data):
    findings = []
    if not data or not data.get('available'):
        return findings

    hits = []
    for e in data.get('entries', []):
        caps = e.get('capabilities', '').lower()
        for cap, (sev, note) in DANGEROUS_CAPS.items():
            if cap in caps:
                hits.append({
                    'file': e['file'],
                    'capability': cap,
                    'severity': sev,
                    'note': note,
                    'raw': e['capabilities'],
                })

    # 按严重性归组
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM']:
        group = [h for h in hits if h['severity'] == sev]
        if group:
            findings.append(_finding(
                f'CAP-{sev[:1]}',
                sev,
                f'发现 {len(group)} 个 {sev} 级别的 capability',
                '文件 capabilities 可被用于提权',
                evidence=group,
            ))
    return findings