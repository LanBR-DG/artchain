# -*- coding: utf-8 -*-
"""由助记词派生的动态口令（60 秒自动轮换，TOTP 思路）。

设计目标：钱包口令不再是需要死记的固定值——
  * 口令 = HMAC(助记词种子, 时间窗口) 的 Base58 摘要，10 位混合大小写字母数字；
  * 每 60 秒自动变化一次；
  * 忘记口令时，输入助记词即可随时查看当前口令并解锁——
    助记词是唯一的总钥匙，口令只是它的时间函数。

安全边界（与 TOTP 一致）：
  * 由口令无法反推助记词（HMAC 单向）；
  * 但口令熵约 58 位且与时间相关，只适合作为本机钱包文件的访问口令，
    不适合独立作为资产级凭据；
  * 口令只在「文件加密时记录的窗口」有效；文件里存有窗口号
    （envelope.window），跨窗口后用旧口令必然解不开——这正是口令轮换的意义。
    容错路径是助记词直解（from_mnemonic_unlocked），完全不受窗口影响；
    「查看口令」会同时把文件重加密到当前窗口（rekey_rotating）。
"""

import hashlib
import hmac
import time

from . import base58, bip39

STEP_SECONDS = 60
PASSWORD_LENGTH = 10


def window_of(timestamp=None):
    """时间戳所属的窗口号（Unix 秒 // 60）。"""
    return int((timestamp if timestamp is not None else time.time()) // STEP_SECONDS)


def password_for(mnemonic, window=None):
    """派生某个时间窗口的口令：10 位混合大小写字母数字（Base58 字符集）。"""
    window = window_of() if window is None else int(window)
    seed = bip39.to_seed(mnemonic)
    digest = hmac.new(seed[:32], window.to_bytes(8, "big"), hashlib.sha512).digest()
    code = base58.b58encode(digest[:6])
    if len(code) < PASSWORD_LENGTH:
        code = base58.b58encode(digest[6:12]) + code
    return code[:PASSWORD_LENGTH]


def current_password(mnemonic):
    """返回 (当前窗口口令, 窗口号)。"""
    window = window_of()
    return password_for(mnemonic, window), window


def seconds_left(timestamp=None):
    """当前窗口剩余秒数（界面倒计时用）。"""
    ts = timestamp if timestamp is not None else time.time()
    return STEP_SECONDS - int(ts) % STEP_SECONDS
