# -*- coding: utf-8 -*-
"""ChaCha20 流密码 + HMAC-SHA256 认证，用于加密钱包私钥。

采用 "先加密后认证"（Encrypt-then-MAC）结构：
    密钥派生：PBKDF2-HMAC-SHA256(password, salt, 迭代次数) -> 64 字节，
              前 32 字节为加密密钥，后 32 字节为认证密钥。
    加密    ：ChaCha20（RFC 8439，96 位随机 nonce）
    认证    ：hmac-sha256(mac_key, nonce || ciphertext)

这样即便攻击者拿到钱包文件，也必须付出 PBKDF2 迭代次数的暴力破解代价，
且任何字节被篡改都会在解密前被 MAC 拦截。
"""

import hashlib
import hmac
import os
import struct

DEFAULT_ITERATIONS = 200000
_MAGIC = b"expand 32-byte k"

# 迭代次数上限。PBKDF2 的开销与迭代次数成正比，信封里的这个值又是可改的；
# 没有上限的话，一个被改过的钱包文件可以让解锁动作卡到天荒地老。
# 取值留了 50 倍余量，正常调整 KDF 强度不会撞到。
_MAX_ITERATIONS = 10 * 1000 * 1000

# 信封格式版本。改动密文布局、KDF 参数或 MAC 覆盖范围时都必须递增，
# 解密端据此分派，否则老文件将无法判断该用哪套规则解析。
ENVELOPE_VERSION = 2


def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_block(key, counter, nonce):
    """生成 64 字节的密钥流块。key 32 字节，nonce 12 字节。"""
    if len(key) != 32:
        raise ValueError("ChaCha20 密钥必须为 32 字节")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce 必须为 12 字节")
    # RFC 8439 的 16 字状态：常量(4) | 密钥(8) | 计数器(1) | nonce(3)。
    #
    # 注意这里必须恰好 16 个字。旧实现写成了 17 个字（把计数器铺成两个 32 位
    # 字），可下面的加和只取 range(16)，于是最后一个字被静默丢弃——
    # 也就是 12 字节 nonce 的最后一字节从未参与密钥流，实际只有 64 位 nonce。
    state = (
        list(struct.unpack("<4I", _MAGIC))
        + list(struct.unpack("<8I", key))
        + [counter & 0xFFFFFFFF]
        + list(struct.unpack("<3I", nonce))
    )
    working = list(state)
    for _ in range(10):  # 10 轮双轮 = 20 轮
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    out = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_xor(key, nonce, data):
    """对数据做 ChaCha20 异或（加解密同一函数）。"""
    out = bytearray()
    counter = 0
    data = bytes(data)
    # 32 位计数器最多覆盖 256GB。超了就必须换 nonce，绝不能回绕——
    # 回绕会让同一个密钥流被用第二次，密文立刻可破。
    if len(data) > (0xFFFFFFFF + 1) * 64:
        raise ValueError("数据过长，超出 ChaCha20 单一 nonce 的计数器容量")
    for offset in range(0, len(data), 64):
        ks = chacha20_block(key, counter, nonce)
        chunk = data[offset:offset + 64]
        out.extend(b ^ k for b, k in zip(chunk, ks))
        counter += 1
    return bytes(out)


def _derive_keys(password, salt, iterations):
    if isinstance(password, str):
        password = password.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=64)
    return dk[:32], dk[32:]


def _mac_input(version, iterations, salt, nonce, ct):
    """被 MAC 覆盖的输入。

    除了密文本身，还必须覆盖版本号与迭代次数这类"解析参数"：
    旧实现只认证 nonce||ct，攻击者把 iterations 改小不会被发现，
    而迭代次数正是暴力破解的成本，等于让攻击者自己把门锁拆了。
    """
    return b"|".join([
        b"artchain-envelope",
        str(version).encode("ascii"),
        str(iterations).encode("ascii"),
        salt.hex().encode("ascii"),
        nonce.hex().encode("ascii"),
        ct.hex().encode("ascii"),
    ])


def encrypt(password, plaintext, iterations=DEFAULT_ITERATIONS):
    """返回可直接 JSON 序列化的密文信封字典。"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if not 1 <= iterations <= _MAX_ITERATIONS:
        raise ValueError("PBKDF2 迭代次数超出合理范围")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    enc_key, mac_key = _derive_keys(password, salt, iterations)
    ct = chacha20_xor(enc_key, nonce, plaintext)
    mac = hmac.new(mac_key, _mac_input(ENVELOPE_VERSION, iterations, salt, nonce, ct),
                   hashlib.sha256).digest()
    return {
        "version": ENVELOPE_VERSION,
        "kdf": "pbkdf2-hmac-sha256",
        "iterations": iterations,
        "cipher": "chacha20",
        "mac": "hmac-sha256",
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ct": ct.hex(),
        "mac_value": mac.hex(),
    }


def decrypt(password, envelope):
    """解密信封；密码错误或数据被篡改时抛出 ValueError。"""
    if not isinstance(envelope, dict):
        raise ValueError("密文信封格式不正确")

    # 先按版本分派，再解析。没有 version 的是旧格式（17 字状态、MAC 不覆盖
    # 迭代次数），本版本不再支持——直接报错，好过用错误的规则解出垃圾。
    version = envelope.get("version")
    if version is None:
        raise ValueError("这是旧版信封格式，当前版本已不再支持，请重新创建钱包")
    try:
        version = int(version)
    except (TypeError, ValueError):
        raise ValueError("密文信封格式不正确")
    if version != ENVELOPE_VERSION:
        raise ValueError("不支持的密文信封版本：%s" % (version,))

    try:
        iterations = int(envelope["iterations"])
        salt = bytes.fromhex(envelope["salt"])
        nonce = bytes.fromhex(envelope["nonce"])
        ct = bytes.fromhex(envelope["ct"])
        mac = bytes.fromhex(envelope["mac_value"])
    except (KeyError, ValueError, TypeError):
        raise ValueError("密文信封格式不正确")

    if not 1 <= iterations <= _MAX_ITERATIONS:
        raise ValueError("密文信封的迭代次数超出合理范围")
    if len(salt) != 16 or len(nonce) != 12 or len(mac) != 32:
        raise ValueError("密文信封的字段长度不正确")

    enc_key, mac_key = _derive_keys(password, salt, iterations)
    expect = hmac.new(mac_key, _mac_input(ENVELOPE_VERSION, iterations, salt, nonce, ct),
                      hashlib.sha256).digest()
    if not hmac.compare_digest(expect, mac):
        raise ValueError("密码错误，或钱包文件已被篡改")
    return chacha20_xor(enc_key, nonce, ct)
