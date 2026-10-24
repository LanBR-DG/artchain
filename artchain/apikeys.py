# -*- coding: utf-8 -*-
"""开放平台 API Key 管理：签发、校验、吊销与限流。

设计要点：
- 明文密钥只在创建时返回一次，落盘仅存 SHA-256 哈希——数据库/目录泄漏不泄钥；
- 密钥形如 ak_<40 hex>，带 8 位 key_id 便于运维指认与吊销；
- 权限分 read / write 两档，接口按档鉴权；
- 限流为进程内滑动窗口（读 120 次/分、写 30 次/分），超限返回 429。
"""

import hashlib
import json
import os
import secrets
import threading
import time
from collections import deque

KEY_FILE = "api_keys.json"
KEY_PREFIX = "ak_"
SCOPES = ("read", "write")

# 每个密钥每 60 秒窗口内的请求上限（按本次请求所属权限档计）
RATE_LIMITS = {"read": 120, "write": 30}
RATE_WINDOW_SECONDS = 60

_lock = threading.Lock()
# 限流滑动窗口：{key_id: deque(timestamps)}
_windows = {}
# last_used/uses 的落盘节流：{key_id: 上次落盘时间}
_last_flush = {}


class ApiKeyError(Exception):
    pass


def _key_hash(plain):
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def _path(store):
    return os.path.join(store.root, KEY_FILE)


def _load(store):
    path = _path(store)
    if not os.path.exists(path):
        return {"keys": []}
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
        raise ApiKeyError("API Key 存储文件格式异常：%s" % path)
    return payload


def _save(store, payload):
    store.ensure_dirs()
    with store.lock():
        store._write_json(_path(store), payload)


def create_key(store, name, scopes, note=""):
    """签发新密钥。返回 (记录, 明文密钥)——明文仅此一次，请当面交付。"""
    name = (name or "").strip()
    if not name:
        raise ApiKeyError("请给密钥起一个名字（用于审计指认）")
    scopes = tuple(s for s in (scopes or ("read",)) if s in SCOPES)
    if not scopes:
        raise ApiKeyError("权限档只能是 %s 的组合" % "/".join(SCOPES))
    plain = KEY_PREFIX + secrets.token_hex(20)
    record = {
        "id": secrets.token_hex(4),
        "name": name,
        "key_hash": _key_hash(plain),
        "scopes": list(scopes),
        "note": note or "",
        "created_at": int(time.time()),
        "revoked_at": None,
        "last_used_at": None,
        "uses": 0,
    }
    with _lock:
        payload = _load(store)
        payload["keys"].append(record)
        _save(store, payload)
    return record, plain


def list_keys(store):
    """运维视图：不含任何密钥材料（哈希也不出，只给指认信息）。"""
    with _lock:
        return [{k: v for k, v in rec.items() if k != "key_hash"}
                for rec in _load(store)["keys"]]


def revoke_key(store, key_id):
    with _lock:
        payload = _load(store)
        for rec in payload["keys"]:
            if rec["id"] == key_id:
                rec["revoked_at"] = int(time.time())
                _save(store, payload)
                return rec
    raise ApiKeyError("找不到密钥：%s" % key_id)


def verify_key(store, plain):
    """校验明文密钥。通过则返回记录（并累计用量），否则返回 None。"""
    if not plain or not plain.startswith(KEY_PREFIX):
        return None
    digest = _key_hash(plain)
    with _lock:
        payload = _load(store)
        hit = None
        for rec in payload["keys"]:
            if rec["key_hash"] == digest:
                hit = rec
                break
        if hit is None or hit.get("revoked_at"):
            return None
        hit["uses"] = int(hit.get("uses") or 0) + 1
        hit["last_used_at"] = int(time.time())
        # 用量落盘节流：同一密钥 30 秒内最多写一次盘，热路径不刷盘
        now = time.time()
        if now - _last_flush.get(hit["id"], 0) > 30:
            _last_flush[hit["id"]] = now
            _save(store, payload)
        return hit


def check_rate(key_id, scope):
    """滑动窗口限流。返回 (是否放行, 窗口内已用次数, 上限)。"""
    limit = RATE_LIMITS.get(scope, RATE_LIMITS["read"])
    now = time.time()
    with _lock:
        window = _windows.setdefault(key_id, deque())
        while window and now - window[0] > RATE_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= limit:
            return False, len(window), limit
        window.append(now)
        return True, len(window), limit
