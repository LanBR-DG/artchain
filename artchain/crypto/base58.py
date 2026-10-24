# -*- coding: utf-8 -*-
"""Base58Check 编码（比特币风格）。

用于把公钥哈希编码成人类可读、可校对（带 4 字节校验和）的地址字符串，
例如 ART 开头的一串字符。
"""

import hashlib

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = dict((c, i) for i, c in enumerate(_ALPHABET))

# 解码长度上限。
#
# b58decode 每读一个字符就做一次大整数乘加，整体是 O(n²)，而且中间的大整数
# 随输入线性增长。调用链（verify_tx 校验 tx["sender"]、状态机校验 data["to"]）
# 跑的都是别人同步过来的链数据，且持链锁；不给上限的话，
# 一个超长字符串就能让节点长时间卡在校验里。
# 128 字符远超实际需要：地址约 34 字符，私钥约 44 字符。
MAX_B58_LEN = 128


def b58encode(raw):
    """字节串 -> Base58 字符串。"""
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("b58encode 需要 bytes 类型")
    n = int.from_bytes(bytes(raw), "big")
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_ALPHABET[r])
    # 保留前导零字节（每个 0x00 对应一个 '1'）
    pad = 0
    for b in raw:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out))


def b58decode(text):
    """Base58 字符串 -> 字节串。非法字符会抛 ValueError。"""
    if not isinstance(text, str):
        raise TypeError("b58decode 需要 str 类型")
    # 长度检查必须放在逐字符循环之前——那才是 O(n²) 的开销所在。
    if len(text) > MAX_B58_LEN:
        raise ValueError("Base58 字符串过长（上限 %d 字符）" % MAX_B58_LEN)
    n = 0
    for ch in text:
        if ch not in _INDEX:
            raise ValueError("Base58 字符串包含非法字符：%r" % (ch,))
        n = n * 58 + _INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    pad = 0
    for ch in text:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


def _checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def b58check_encode(payload):
    """带 4 字节校验和的 Base58 编码。"""
    payload = bytes(payload)
    return b58encode(payload + _checksum(payload))


def b58check_decode(text):
    """校验并解码 Base58Check 字符串，返回原始载荷（不含校验和）。"""
    raw = b58decode(text)
    if len(raw) < 5:
        raise ValueError("Base58Check 数据过短")
    payload, chk = raw[:-4], raw[-4:]
    if _checksum(payload) != chk:
        raise ValueError("Base58Check 校验和不匹配，地址可能被篡改或抄错")
    return payload
