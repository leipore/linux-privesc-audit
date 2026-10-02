# -*- coding: utf-8 -*-
"""JSON 报告输出模块。"""
import json
from datetime import datetime


def _serialize(obj):
    """处理非 JSON 原生类型。"""
    if isinstance(obj, (set, tuple)):
        return list(obj)
    if isinstance(obj, bytes):
        return obj.decode(errors='ignore')
    if hasattr(obj, 'isoformat'):
        return obj.isoformat()
    return str(obj)


def dumps(report):
    """返回 JSON 字符串。"""
    return json.dumps(report, indent=2, ensure_ascii=False, default=_serialize)


def save(report, path):
    """保存 JSON 报告。"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(dumps(report))
    return path