# -*- coding: utf-8 -*-
"""secp256k1 椭圆曲线与 ECDSA 数字签名（纯标准库实现）。

设计要点：
  * 曲线参数与比特币/以太坊所用完全一致（y^2 = x^3 + 7 mod p）。
  * 随机数 k 采用 RFC 6979 确定性生成，杜绝"随机数复用导致私钥泄露"这类事故，
    同时保证同一 (私钥, 消息) 永远得到同一签名，便于校验与复现。
  * 签名结果做 low-S 规范化（s <= n/2），可抵抗签名可延展性攻击。
  * 签名编码为紧凑的 r||s 各 32 字节（共 64 字节 / 128 个十六进制字符）。
"""

import hashlib
import hmac
import secrets
import threading

from . import base58

# ---------------------------------------------------------------- 曲线参数
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

# 地址版本字节，仅用于让地址具备可辨识前缀
ADDR_VERSION = 0x23


class CryptoError(Exception):
    """密码学相关错误。"""


# ---------------------------------------------------------------- 基础运算
def _inv(a, m):
    """扩展欧几里得算法求 a 在模 m 下的乘法逆元。"""
    a %= m
    if a == 0:
        raise ZeroDivisionError("模逆运算的参数不能为 0")
    lm, hm = 1, 0
    low, high = a, m
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % m


def is_on_curve(pt):
    """判断点是否落在曲线上（None 表示无穷远点，视为合法）。"""
    if pt is None:
        return True
    x, y = pt
    return (y * y - x * x * x - B) % P == 0


def point_neg(pt):
    if pt is None:
        return None
    x, y = pt
    return (x, (-y) % P)


# ---------------------------------------------------------------- Jacobian 坐标
# 内部点运算全部用 Jacobian 坐标 (X, Y, Z)，仿射坐标 (x, y) = (X/Z², Y/Z³)。
# 好处：点加与倍点不再需要模逆（纯 Python 里最贵的运算），一次标量乘法只在
# 最后转回仿射时做一次逆。对外 API 仍以仿射坐标进出，行为与旧实现完全一致。
# 公式取自 EFD（dbl-2009-l 的 a=0 特例、add-1998-cmo-2 及其 Z2=1 混合加法特例），
# 并与旧实现做过全量差分测试（_bench 与自检）。


def _jac_double(pj):
    """Jacobian 倍点。None 表示无穷远点。"""
    if pj is None:
        return None
    x, y, z = pj
    if y == 0:
        return None
    a = x * x % P
    b = y * y % P
    c = b * b % P
    d = 2 * ((x + b) * (x + b) - a - c) % P   # = 4·x·y²
    e = 3 * a % P
    f = e * e % P
    x3 = (f - 2 * d) % P
    y3 = (e * (d - x3) - 8 * c) % P
    z3 = 2 * y * z % P
    return (x3, y3, z3)


def _jac_add(pj, qj):
    """两个 Jacobian 点相加，覆盖相等、互逆、无穷远点全部情形。"""
    if pj is None:
        return qj
    if qj is None:
        return pj
    x1, y1, z1 = pj
    x2, y2, z2 = qj
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 * z2z2 % P
    s2 = y2 * z1 * z1z1 % P
    if u1 == u2:
        if s1 != s2:
            return None
        return _jac_double(pj)
    h = (u2 - u1) % P
    i = (2 * h) * (2 * h) % P
    j = h * i % P
    r = 2 * (s2 - s1) % P
    v = u1 * i % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * s1 * j) % P
    z3 = ((z1 + z2) * (z1 + z2) - z1z1 - z2z2) * h % P
    return (x3, y3, z3)


def _jac_mixed_add(pj, affine):
    """Jacobian 点 + 仿射点（Z2=1 的特例，省一半乘法）。"""
    if pj is None:
        return (affine[0], affine[1], 1)
    x1, y1, z1 = pj
    x2, y2 = affine
    z1z1 = z1 * z1 % P
    u2 = x2 * z1z1 % P
    s2 = y2 * z1 * z1z1 % P
    h = (u2 - x1) % P
    if h == 0:
        if s2 == y1:
            return _jac_double(pj)
        return None
    hh = h * h % P
    i = 4 * hh % P
    j = h * i % P
    r = 2 * (s2 - y1) % P
    v = x1 * i % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * y1 * j) % P
    z3 = ((z1 + h) * (z1 + h) - z1z1 - hh) % P
    return (x3, y3, z3)


def _jac_to_affine(pj):
    if pj is None:
        return None
    x, y, z = pj
    if z == 0:
        return None
    zi = _inv(z, P)
    zi2 = zi * zi % P
    return (x * zi2 % P, y * zi2 * zi % P)


# 基点的 4 位窗口表：_G_TABLE[i] = i·G 的仿射坐标（i=1..15，0 为 None）。
# 惰性构建 + 双重检查锁：HTTP 服务是多线程的，首波并发验签可能同时触发表构建。
_G_TABLE = None
_G_TABLE_LOCK = threading.Lock()


def _g_table():
    global _G_TABLE
    if _G_TABLE is None:
        with _G_TABLE_LOCK:
            if _G_TABLE is None:
                table = [None] * 16
                table[1] = G
                pj = (GX, GY, 1)
                for i in range(2, 16):
                    pj = _jac_add(pj, (GX, GY, 1))
                    table[i] = _jac_to_affine(pj)
                _G_TABLE = tuple(table)
    return _G_TABLE


def point_double(pt):
    if pt is None:
        return None
    return _jac_to_affine(_jac_double((pt[0] % P, pt[1] % P, 1)))


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p[0] % P, p[1] % P
    x2, y2 = q[0] % P, q[1] % P
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        return point_double((x1, y1))
    return _jac_to_affine(_jac_mixed_add((x1, y1, 1), (x2, y2)))


def _window_mul(k):
    """4 位窗口法计算 k·G（Jacobian）：256 次倍点 + 至多 63 次混合加法。"""
    table = _g_table()
    acc = None
    for i in range(252, -1, -4):
        for _ in range(4):
            acc = _jac_double(acc)
        w = (k >> i) & 0xF
        if w:
            acc = _jac_mixed_add(acc, table[w])
    return acc


def point_mul(k, pt=G):
    """标量乘法 k * pt（二进制双倍-相加）。

    pt 是基点时走预计算窗口表，约为通用路径的 4 倍；通用路径同样在
    Jacobian 坐标里完成，只在最后转回仿射时做一次模逆。
    """
    if pt is None:
        return None
    k = k % N
    if k == 0:
        return None
    if pt == G:
        return _jac_to_affine(_window_mul(k))
    qj = (pt[0] % P, pt[1] % P, 1)
    acc = None
    while k:
        if k & 1:
            acc = _jac_add(acc, qj)
        qj = _jac_double(qj)
        k >>= 1
    return _jac_to_affine(acc)


# ---------------------------------------------------------------- 密钥编解码
def generate_private_key():
    """生成一个密码学安全的私钥（1 <= d < n）。"""
    return secrets.randbelow(N - 1) + 1


def private_key_to_int(value):
    if isinstance(value, (bytes, bytearray)):
        d = int.from_bytes(bytes(value), "big")
    elif isinstance(value, str):
        d = int(value, 16)
    else:
        d = int(value)
    if not 1 <= d < N:
        raise CryptoError("私钥超出 secp256k1 合法范围")
    return d


def private_key_to_hex(d):
    return "%064x" % (d % N)


def encode_pubkey(pt, compressed=True):
    """点 -> 公钥字节串。压缩格式 33 字节，非压缩格式 65 字节。"""
    if pt is None:
        raise CryptoError("无穷远点不能作为公钥")
    x, y = pt
    if compressed:
        prefix = 0x02 if y % 2 == 0 else 0x03
        return bytes([prefix]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def decode_pubkey(data):
    """公钥字节串 / 十六进制字符串 -> 曲线上的点。"""
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data)
        except ValueError:
            raise CryptoError("公钥不是合法的十六进制字符串")
    data = bytes(data)
    if len(data) == 65 and data[0] == 0x04:
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:65], "big")
        pt = (x, y)
    elif len(data) == 33 and data[0] in (0x02, 0x03):
        x = int.from_bytes(data[1:33], "big")
        if x >= P:
            raise CryptoError("公钥 x 坐标超出域范围")
        y_sq = (pow(x, 3, P) + B) % P
        # p ≡ 3 (mod 4)，可直接用 (p+1)/4 次幂开方
        y = pow(y_sq, (P + 1) // 4, P)
        if (y * y) % P != y_sq:
            raise CryptoError("公钥不在曲线上")
        if (y % 2 == 0) != (data[0] == 0x02):
            y = (-y) % P
        pt = (x, y)
    else:
        raise CryptoError("公钥长度或前缀不合法")
    if not is_on_curve(pt):
        raise CryptoError("公钥不在曲线上")
    return pt


def pubkey_from_private(d, compressed=True):
    return encode_pubkey(point_mul(private_key_to_int(d)), compressed)


def pubkey_to_address(pubkey):
    """公钥 -> 地址（sha256 截断 20 字节 + Base58Check）。"""
    if isinstance(pubkey, str):
        pubkey = bytes.fromhex(pubkey)
    digest = hashlib.sha256(bytes(pubkey)).digest()[:20]
    return base58.b58check_encode(bytes([ADDR_VERSION]) + digest)


def address_payload(address):
    """校验地址并返回 20 字节公钥哈希。"""
    raw = base58.b58check_decode(address)
    if len(raw) != 21:
        raise CryptoError("地址长度不合法")
    if raw[0] != ADDR_VERSION:
        raise CryptoError("地址版本号不匹配（不是本链地址）")
    return raw[1:]


def is_valid_address(address):
    try:
        if not isinstance(address, str):
            return False
        address_payload(address)
        return True
    except Exception:
        return False


def address_from_pubkey_hex(pubkey_hex):
    return pubkey_to_address(bytes.fromhex(pubkey_hex))


# ---------------------------------------------------------------- ECDSA
def _sha256(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def _rfc6979_k(d, h1):
    """RFC 6979 确定性 k 生成器。"""
    v = b"\x01" * 32
    k = b"\x00" * 32
    xb = d.to_bytes(32, "big")
    # secp256k1 的 qlen == hlen == 256，bits2octets 即对 n 取模后的大端 32 字节
    hb = (int.from_bytes(h1, "big") % N).to_bytes(32, "big")

    k = hmac.new(k, v + b"\x00" + xb + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + xb + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 0 < cand < N:
            yield cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(private_key, message, low_s=True):
    """对消息（bytes 或 str）签名，返回 128 个十六进制字符的 r||s。"""
    d = private_key_to_int(private_key)
    h1 = _sha256(message)
    z = int.from_bytes(h1, "big")
    for k in _rfc6979_k(d, h1):
        pt = point_mul(k)
        if pt is None:
            continue
        r = pt[0] % N
        if r == 0:
            continue
        s = (_inv(k, N) * (z + r * d)) % N
        if s == 0:
            continue
        if low_s and s > N // 2:
            s = N - s
        return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()
    raise CryptoError("签名失败：未能生成合法的 k")


def verify(pubkey, message, signature):
    """验证签名。pubkey 可为点 / 字节 / 十六进制串，signature 为 128 位十六进制串。"""
    try:
        pt = pubkey if (isinstance(pubkey, tuple) or pubkey is None) else decode_pubkey(pubkey)
    except Exception:
        return False
    if pt is None:
        return False
    if not isinstance(signature, str):
        return False
    sig = signature.strip().lower()
    if len(sig) != 128:
        return False
    try:
        r = int(sig[:64], 16)
        s = int(sig[64:], 16)
    except ValueError:
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    # 强制低 S。(r, s) 与 (r, N-s) 是同一消息、同一公钥的两个合法签名，
    # 不加这条限制的话，任何人都能把一笔已上链的交易改写成另一个 sig 字符串；
    # 而 txid 把 sig 一起哈希（tx.py 的 compute_txid），于是同一笔交易
    # 会派生出多个不同 txid，去重与存在性证明随之失效。
    # sign() 侧本来就做了低 S 规范化，验证侧必须同样严格，否则那道防护形同虚设。
    if s > N // 2:
        return False

    h1 = _sha256(message)
    z = int.from_bytes(h1, "big") % N
    w = _inv(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    # Shamir 技巧：u1·G + u2·Q 在一个循环里完成（256 次倍点 + 至多 256 次混合加法），
    # 而不是两次独立的标量乘法（约 512 次倍点），且全程不需要模逆。
    acc = None
    for i in range(255, -1, -1):
        acc = _jac_double(acc)
        if (u1 >> i) & 1:
            acc = _jac_mixed_add(acc, G)
        if (u2 >> i) & 1:
            acc = _jac_mixed_add(acc, pt)
    pt2 = _jac_to_affine(acc)
    if pt2 is None:
        return False
    return pt2[0] % N == r
