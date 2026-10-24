# -*- coding: utf-8 -*-
"""钱包：BIP39 助记词钱包（与主流钱包互通）。

钱包 = 12/24 个英文单词（BIP39 助记词）推导出的 secp256k1 密钥对：
  * 助记词是钱包的唯一备份——抄写下来，任何支持 BIP39+BIP32 的钱包都能恢复；
  * 钱包文件里只保存经口令加密的助记词（PBKDF2 + ChaCha20 + HMAC）；
  * 口令只负责加密本机文件，与助记词是两件事：忘记口令可以用助记词重新导入，
    丢失助记词则任何人（包括平台）都无法找回。

旧版钱包文件保存的是十六进制私钥，加载时按「先十六进制、再助记词」自动识别，
老钱包升级后无需任何迁移即可解锁。
"""

import sys
import time

from .crypto import bip32, bip39, chacha20, rotpwd
from .crypto import secp256k1 as ec
from .store import StoreError

PLAINTEXT_WARNING = "!! 明文助记词，仅供演示，切勿用于真实资产 !!"


class WalletError(Exception):
    pass


def _key_from_blob(name, raw):
    """把解密出来的明文还原成私钥整数，返回 (private_key, mnemonic)。

    新格式的明文是助记词，旧格式是 64 位十六进制私钥——两条路径都支持，
    保证升级前的钱包文件依然可以解锁。两条路径都失败才判文件损坏。
    """
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("ascii")
        except UnicodeDecodeError:
            # 口令对但明文不是文本，说明文件本身坏了（MAC 只保证没被改，
            # 不保证内容真的是我们写进去的那种格式）。
            raise WalletError("钱包 %s 解密后的内容不是文本，文件可能已损坏" % name)
    text = str(raw).strip()
    if len(text) == 64:
        try:
            return int(text, 16), None
        except ValueError:
            pass
    try:
        mnemonic = bip39.normalize(text)
        if bip39.validate(mnemonic):
            seed = bip39.to_seed(mnemonic)
            return bip32.derive_private_key(seed), mnemonic
    except (ValueError, bip39.MnemonicError):
        pass
    raise WalletError("钱包 %s 解密后的内容既不是合法助记词也不是十六进制私钥，文件可能已损坏" % name)


class Wallet(object):
    """一个 secp256k1 钱包。"""

    def __init__(self, name, address, pubkey, private_key=None, created_at=None,
                 encrypted=True, meta=None, mnemonic=None):
        self.name = name
        self.address = address
        self.pubkey = pubkey
        self._private_key = private_key
        self.created_at = int(created_at if created_at is not None else time.time())
        self.encrypted = encrypted
        self.meta = meta or {}
        # 助记词（新格式钱包有；旧格式钱包为 None，落盘时保持旧格式）
        self.mnemonic = mnemonic

    # ---------------------------------------------------------- 构造
    @classmethod
    def create(cls, store, name, password=None, compressed=True, meta=None):
        """新建钱包并落盘。password 为 None 表示明文存储（演示用）。

        助记词在内部生成但不在此返回——需要向用户一次性展示助记词的
        场景（CLI/网页）请改用 create_with_mnemonic。
        """
        wallet, _mnemonic = cls.create_with_mnemonic(
            store, name, password=password, compressed=compressed, meta=meta)
        return wallet

    @classmethod
    def create_with_mnemonic(cls, store, name, password=None, compressed=True, meta=None,
                             mnemonic=None, words=12, rotating=False):
        """新建钱包并落盘，返回 (wallet, mnemonic)。

        mnemonic 提供时按其恢复（导入路径），否则按 words（12 或 24）生成。
        助记词只在这一次返回值中出现——平台不保存明文助记词，请立即抄写。
        rotating=True 时文件用「当前窗口的动态口令」加密（rotpwd），
        口令每 60 秒变化，随时可用助记词重新查看（rekey_rotating）。
        """
        cls._validate_name(name)
        if name in store.list_wallets():
            raise WalletError("钱包 %s 已存在" % name)
        if mnemonic is not None:
            mnemonic = bip39.normalize(mnemonic)
            if not bip39.validate(mnemonic):
                raise WalletError("助记词不合法：请核对每个单词的拼写与顺序")
        else:
            if words not in (12, 24):
                raise WalletError("助记词长度只支持 12 或 24 个单词")
            mnemonic = bip39.generate(256 if words == 24 else 128)
        seed = bip39.to_seed(mnemonic)
        private_key = bip32.derive_private_key(seed)
        pubkey = ec.pubkey_from_private(private_key, compressed=compressed)
        address = ec.pubkey_to_address(pubkey)
        wallet = cls(name, address, pubkey.hex(), private_key=private_key,
                     mnemonic=mnemonic, meta=meta)
        if rotating:
            password_used, window = rotpwd.current_password(mnemonic)
            wallet.encrypted = True
            wallet._save_with_mode(store, password_used, mode="rotating", window=window)
        else:
            wallet.encrypted = password is not None
            wallet.save(store, password)
        return wallet, mnemonic

    @classmethod
    def from_mnemonic(cls, store, name, mnemonic, password=None, compressed=True, meta=None):
        """从助记词导入 / 恢复钱包（换设备后找回身份的唯一途径）。"""
        wallet, _mnemonic = cls.create_with_mnemonic(
            store, name, password=password, compressed=compressed, meta=meta,
            mnemonic=mnemonic)
        return wallet

    @classmethod
    def from_mnemonic_unlocked(cls, store, name, mnemonic):
        """按名称 + 助记词直接构造已解锁钱包（不触碰钱包文件）。

        助记词就是密钥本身，因此对固定口令与动态口令两种格式都有效；
        地址不匹配即拒绝——防止助记词抄错解锁到别人的身份。
        """
        payload = store.load_wallet(name)
        mnemonic = bip39.normalize(mnemonic)
        if not bip39.validate(mnemonic):
            raise WalletError("助记词不合法：请核对每个单词的拼写与顺序")
        private_key = bip32.derive_private_key(bip39.to_seed(mnemonic))
        pubkey = ec.pubkey_from_private(private_key)
        if ec.pubkey_to_address(pubkey) != payload.get("address"):
            raise WalletError("助记词与该钱包地址不匹配")
        return cls(name, payload["address"], pubkey.hex(), private_key=private_key,
                   created_at=payload.get("created_at"), encrypted=bool(payload.get("crypto")),
                   meta=payload.get("meta") or {}, mnemonic=mnemonic)

    def rekey_rotating(self, store):
        """把钱包文件改加密为「当前窗口的动态口令」，返回 (当前口令, 剩余秒数)。

        口令每 60 秒变化；之后任何时候都可以用助记词重新查看（本方法）或
        直接解锁（from_mnemonic_unlocked）。固定口令钱包可随时切到本模式。
        """
        if not self.mnemonic:
            raise WalletError("该钱包是旧版格式（无助记词），无法切换动态口令模式；"
                              "请先用助记词重建钱包")
        password, window = rotpwd.current_password(self.mnemonic)
        self._save_with_mode(store, password, mode="rotating", window=window)
        return password, rotpwd.seconds_left()

    @staticmethod
    def _validate_name(name):
        if not name or not isinstance(name, str):
            raise WalletError("钱包名称不能为空")
        if len(name) > 64:
            raise WalletError("钱包名称过长")
        for ch in name:
            if not (ch.isalnum() or ch in "-_."):
                raise WalletError("钱包名称只能包含字母、数字、横线、下划线和点")
        if name.startswith("."):
            raise WalletError("钱包名称不能以点开头")

    @classmethod
    def load(cls, store, name, password=None):
        """读取钱包；加密钱包必须提供正确口令。"""
        payload = store.load_wallet(name)
        encrypted = bool(payload.get("crypto"))
        private_key = None
        mnemonic = None
        if encrypted:
            if password is None:
                raise WalletError("钱包 %s 已加密，请提供口令" % name)
            try:
                raw = chacha20.decrypt(password, payload["crypto"])
            except ValueError as exc:
                raise WalletError("钱包 %s 解密失败：%s" % (name, exc))
            private_key, mnemonic = _key_from_blob(name, raw)
        else:
            raw = payload.get("mnemonic") or payload.get("private_key", "")
            private_key, mnemonic = _key_from_blob(name, raw)
        wallet = cls(name, payload["address"], payload["pubkey"], private_key=private_key,
                     created_at=payload.get("created_at"), encrypted=encrypted,
                     meta=payload.get("meta") or {}, mnemonic=mnemonic)
        # 自检：私钥推导出的地址必须与文件记录一致
        derived = ec.pubkey_to_address(ec.pubkey_from_private(private_key))
        if derived != wallet.address:
            raise WalletError("钱包 %s 的公私钥不匹配，文件可能已损坏" % name)
        return wallet

    # ---------------------------------------------------------- 持久化
    def to_payload(self, password=None):
        if self._private_key is None:
            raise WalletError("钱包已锁定，无法保存：请先用口令解锁")
        payload = {
            "name": self.name,
            "address": self.address,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "meta": self.meta,
        }
        # 新格式存助记词（钱包的唯一备份）；旧格式钱包没有助记词，
        # 重存时保持十六进制私钥的原格式不变。
        secret = self.mnemonic or ec.private_key_to_hex(self._private_key)
        if password is None:
            payload["crypto"] = None
            payload["warning"] = PLAINTEXT_WARNING
            if self.mnemonic:
                payload["mnemonic"] = self.mnemonic
            else:
                payload["private_key"] = ec.private_key_to_hex(self._private_key)
        else:
            payload["crypto"] = chacha20.encrypt(password, secret)
        return payload

    def save(self, store, password=None):
        store.save_wallet(self.name, self.to_payload(password))
        return self

    def _save_with_mode(self, store, password, mode=None, window=None):
        """加密落盘并在密文信封里附加口令模式与窗口号（动态口令模式用）。"""
        payload = self.to_payload(password)
        if mode:
            payload["crypto"]["pw_mode"] = mode
            payload["crypto"]["window"] = window
        store.save_wallet(self.name, payload)
        return self

    # ---------------------------------------------------------- 能力
    def has_private_key(self):
        return self._private_key is not None

    def private_key(self):
        if self._private_key is None:
            raise WalletError("钱包已锁定：请先提供口令解锁")
        return self._private_key

    def sign(self, message):
        """用私钥对消息签名，返回 128 位十六进制字符串。"""
        return ec.sign(self.private_key(), message)

    def public_info(self):
        """对外可公开的信息（绝不包含私钥）。"""
        return {
            "name": self.name,
            "address": self.address,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "encrypted": self.encrypted,
            "short_address": "%s...%s" % (self.address[:8], self.address[-6:]),
        }


def load_wallet_or_fail(store, name, password=None):
    try:
        return Wallet.load(store, name, password)
    except StoreError as exc:
        raise WalletError(str(exc))


def find_or_create(store, name, password=None, compressed=True):
    """存在即加载，不存在则创建（供 API 与演示脚本使用）。"""
    if name in store.list_wallets():
        return Wallet.load(store, name, password), False
    return Wallet.create(store, name, password=password, compressed=compressed), True


def generate_offline(compressed=True):
    """不落盘地生成一组身份（冷钱包 / 一次性地址），含助记词。"""
    mnemonic = bip39.generate(128)
    private_key = bip32.derive_private_key(bip39.to_seed(mnemonic))
    pubkey = ec.pubkey_from_private(private_key, compressed=compressed)
    return {
        "mnemonic": mnemonic,
        "private_key": ec.private_key_to_hex(private_key),
        "pubkey": pubkey.hex(),
        "address": ec.pubkey_to_address(pubkey),
        "warning": PLAINTEXT_WARNING,
    }


def describe_env():
    """返回当前运行环境的简要信息（供 --version / 诊断使用）。"""
    from . import imagelib
    return {
        "python": sys.version.split()[0],
        "image_backend": imagelib.backend_name(),
        "image_formats": "/".join(imagelib.supported_formats()),
    }
