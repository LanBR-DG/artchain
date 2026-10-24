# -*- coding: utf-8 -*-
"""BIP39 助记词（纯标准库实现，与主流钱包完全互通）。

    助记词 = 钱包本身：12/24 个英文单词编码了私钥的种子熵，
    抄写下来即可在任何支持 BIP39 的钱包里恢复资金与身份。
    本模块实现：
      * 熵 <-> 助记词（128 位 = 12 词 / 256 位 = 24 词，含校验和）
      * 助记词 -> 种子（PBKDF2-HMAC-SHA512，2048 轮，"mnemonic"+口令）
      * 校验（词表、长度、校验和），拒绝拼错/替换过的助记词

    词表取自 BIP39 官方仓库（bitcoin/bips，bip-0039/english.txt），
    与以太坊、MetaMask 等主流钱包逐字一致。助记词里的空口令
    （BIP39 passphrase）本实现暂不使用——种子上不再叠加口令层。
"""

import hashlib
import hmac
import secrets

_WORDLIST_PATH = __file__.rsplit(".", 1)[0] + "_english.txt"

_WORDS = None
_INDEX = None


def _load():
    global _WORDS, _INDEX
    if _WORDS is None:
        with open(_WORDLIST_PATH, "r", encoding="utf-8") as fh:
            _WORDS = tuple(line.strip() for line in fh if line.strip())
        if len(_WORDS) != 2048:
            raise RuntimeError("BIP39 词表不完整：%d 词（应为 2048）" % len(_WORDS))
        _INDEX = {word: i for i, word in enumerate(_WORDS)}
    return _WORDS, _INDEX


class MnemonicError(Exception):
    """助记词不合法（词不在表内、长度错误或校验和不匹配）。"""


def _checksum_bits(entropy):
    """前 CS 位校验和（CS = 熵长 / 32）。"""
    digest = hashlib.sha256(entropy).digest()[0]
    cs = len(entropy) * 8 // 32
    return digest >> (8 - cs)


def entropy_to_mnemonic(entropy):
    """熵字节 -> 助记词字符串。entropy 必须是 16/20/24/28/32 字节。"""
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise MnemonicError("熵长度必须是 16/20/24/28/32 字节（128-256 位）")
    words, _ = _load()
    bits = int.from_bytes(entropy, "big") << (len(entropy) * 8 // 32)
    bits |= _checksum_bits(entropy)
    total = len(entropy) * 8 // 32 + len(entropy) * 8
    out = []
    for shift in range(total - 11, -1, -11):
        out.append(words[(bits >> shift) & 0x7FF])
    return " ".join(out)


def mnemonic_to_entropy(mnemonic):
    """助记词字符串 -> 熵字节（校验和不匹配抛 MnemonicError）。"""
    words, index = _load()
    parts = mnemonic.strip().split()
    if len(parts) not in (12, 15, 18, 21, 24):
        raise MnemonicError("助记词长度应为 12/15/18/21/24 个单词，实际 %d" % len(parts))
    bits = 0
    for word in parts:
        try:
            i = index[word]
        except KeyError:
            raise MnemonicError("助记词包含不在标准词表中的单词：%r" % word)
        bits = (bits << 11) | i
    ent_bits = len(parts) * 11 * 32 // 33   # ENT = W*11*32/33，CS = W*11/33
    cs_bits = len(parts) * 11 - ent_bits
    entropy = (bits >> cs_bits).to_bytes(ent_bits // 8, "big")
    if (bits & ((1 << cs_bits) - 1)) != _checksum_bits(entropy):
        raise MnemonicError("助记词校验和不匹配——可能存在抄写错误或单词被替换")
    return entropy


def validate(mnemonic):
    """助记词是否合法（词表 + 长度 + 校验和）。"""
    try:
        mnemonic_to_entropy(mnemonic)
        return True
    except MnemonicError:
        return False


def normalize(mnemonic):
    """规范化：去首尾空白、统一空格（NFKD 用于非 ASCII 场景，英文词表无差异）。"""
    import unicodedata
    return " ".join(unicodedata.normalize("NFKD", str(mnemonic)).strip().split())


def to_seed(mnemonic, passphrase=""):
    """BIP39：PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048) -> 64 字节种子。"""
    import unicodedata
    m = unicodedata.normalize("NFKD", normalize(mnemonic)).encode("utf-8")
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", m, salt, 2048, 64)


def generate(strength=128):
    """生成一副新助记词（strength 128 = 12 词，256 = 24 词）。"""
    if strength not in (128, 160, 192, 224, 256):
        raise MnemonicError("强度必须是 128/160/192/224/256 位")
    return entropy_to_mnemonic(secrets.token_bytes(strength // 8))


def word_list():
    """全部 2048 个标准单词（供界面联想提示与离线校验使用）。"""
    words, _ = _load()
    return words
