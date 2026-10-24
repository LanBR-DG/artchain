# -*- coding: utf-8 -*-
"""BIP32 分层确定性密钥派生（纯标准库实现）。

从 BIP39 种子派生出确定性的私钥树：
    种子 -> 主密钥（HMAC-SHA512("Bitcoin seed")）-> CKDpriv 逐层派生

本链使用路径 m/44'/20100'/0'/0/0：
  * 44'  = BIP44 目的层
  * 20100' = 币种号。**ArtChain 自用编号，尚未在 SLIP-44 注册**，
             正式对外发布前应向 SLIP-44 申请注册或改用它网已注册的编号。
  * 0'   = 账户层（account 0）
  * 0    = 找零层（外部链）
  * 0    = 地址序号（第 0 个地址）

同一副助记词在任何实现了 BIP39+BIP32 的钱包里派生出的私钥完全一致。
"""

import hashlib
import hmac

from . import secp256k1 as ec

ARTCHAIN_COIN_TYPE = 20100
ARTCHAIN_PATH = "m/44'/%d'/0'/0/0" % ARTCHAIN_COIN_TYPE

_HARDENED = 0x80000000


def master_from_seed(seed):
    """种子 -> (主私钥 k, 链码 c)，各 32 字节。"""
    if len(seed) not in (16, 32, 64):
        raise ValueError("种子长度应为 16/32/64 字节（BIP39 输出为 64）")
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return i[:32], i[32:]


def ckd_priv(k, c, index):
    """子密钥派生：index >= 2^31 为硬化派生，否则为普通派生。"""
    if index >= _HARDENED:
        data = b"\x00" + k + index.to_bytes(4, "big")
    else:
        data = ec.encode_pubkey(ec.point_mul(int.from_bytes(k, "big")), compressed=True) \
            + index.to_bytes(4, "big")
    i = hmac.new(c, data, hashlib.sha512).digest()
    child_k = ((int.from_bytes(i[:32], "big") + int.from_bytes(k, "big")) % ec.N)
    if child_k == 0 or int.from_bytes(i[:32], "big") >= ec.N:
        raise ValueError("派生出非法子密钥（概率可忽略），请更换种子")
    return child_k.to_bytes(32, "big"), i[32:]


def derive_private_key(seed, path=None):
    """按路径从种子派生 secp256k1 私钥整数。path 如 "m/44'/20100'/0'/0/0"。"""
    path = path or ARTCHAIN_PATH
    k, c = master_from_seed(seed)
    parts = [p for p in str(path).split("/") if p and p != "m"]
    for part in parts:
        hardened = part.endswith("'")
        index = int(part.rstrip("'")) + (_HARDENED if hardened else 0)
        k, c = ckd_priv(k, c, index)
    d = int.from_bytes(k, "big")
    if not 1 <= d < ec.N:
        raise ValueError("派生出的私钥超出 secp256k1 范围")
    return d
