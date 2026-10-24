# -*- coding: utf-8 -*-
"""交易（Transaction）：一次链上确权动作的载体。

所有确权行为都表达为交易：
    REGISTER  著作权登记（作品指纹上链确权）
    TRANSFER  版权转让
    LICENSE   授权许可
    DISPUTE   权属争议声明
    ADJUDICATE 争议裁决（驳回异议则恢复有效，支持异议则登记转为无效）
    REVOKE    撤销登记
    POST      社区发帖 / 回复（正文与可选附图哈希直接上链）
    LIKE      给帖子点赞（一个地址对一帖只能赞一次，上链即永久）
    GENESIS   创世交易（仅出现在 0 号区块）

签名字段覆盖除 txid 外的全部字段（含 sig），因此对交易任何一处改动都会
导致 txid 变化且验签失败。msg 采用"键排序 + 紧凑分隔符"的规范化 JSON，
保证跨平台、跨进程哈希一致。
"""

import hashlib
import json
import re
import time

from ..crypto import secp256k1 as ec

TX_GENESIS = "GENESIS"
TX_REGISTER = "REGISTER"
TX_TRANSFER = "TRANSFER"
TX_LICENSE = "LICENSE"
TX_DISPUTE = "DISPUTE"
TX_REVOKE = "REVOKE"
TX_ADJUDICATE = "ADJUDICATE"
TX_POST = "POST"
TX_LIKE = "LIKE"
TX_PAY = "PAY"          # 平台积分：点对点转账
TX_MINT = "MINT"        # 平台积分：铸造（仅限链上登记的运营方地址）
TX_BURN = "BURN"        # 平台积分：销毁（仅限运营方，回收流通量）

ALL_TYPES = (TX_GENESIS, TX_REGISTER, TX_TRANSFER, TX_LICENSE, TX_DISPUTE, TX_REVOKE,
             TX_ADJUDICATE, TX_POST, TX_LIKE, TX_PAY, TX_MINT, TX_BURN)

# 版本兼容说明：老链数据不含 PAY/MINT/BURN，新版本节点加载毫无影响；
# 但**旧版本**节点同步到含积分交易的新链时，会按「未知交易类型」拒绝整条链。
# 单机演示无所谓，混合部署请先升级所有节点再启用积分功能。

# 积分的最小单位：链上金额一律是「最小单位的整数」，永不出现浮点。
# 8 位小数意味着 1 积分 = 10^8 最小单位，展示层再换算回来。
POINT_DECIMALS = 8
POINT_SCALE = 10 ** POINT_DECIMALS
# 单笔金额的上限（最小单位）：2^63 以内保证任何语言的大整数都不溢出
POINT_MAX_UNITS = 2 ** 63 - 1

# 争议裁决的两种结论。放在这里而不是散在各层，
# 是因为状态机、service、CLI、HTTP、前端都要认这两个字面量，
# 任何一处写错都只能等到运行期才暴露。
RULING_REJECT = "驳回"      # 异议不成立，恢复为有效
RULING_UPHOLD = "支持"      # 异议成立，登记转为已无效
RULINGS = (RULING_REJECT, RULING_UPHOLD)

TX_VERSION = 1

_AMOUNT_RE = re.compile(r"^\d+(\.\d{1,2})?$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_POINT_RE = re.compile(r"^\d{1,15}(\.\d{1,8})?$")


class TxError(Exception):
    """交易格式或签名错误。"""


# ------------------------------------------------------------ 规范化与哈希
def canonical(obj):
    """规范化 JSON 编码：键排序、无多余空白、UTF-8。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _core(tx, drop=("txid", "sig")):
    return dict((k, v) for k, v in tx.items() if k not in drop)


def signing_bytes(tx):
    """被签名的字节串（不含 txid 与 sig）。"""
    return canonical(_core(tx))


def compute_txid(tx):
    """交易哈希：对"除 txid 之外的全部字段（含签名）"做 SHA-256。"""
    return hashlib.sha256(canonical(_core(tx, drop=("txid",)))).hexdigest()


# ------------------------------------------------------------ 构造与签名
def work_id_for(file_hash, creator_address):
    """由"文件指纹 + 权利人地址"确定性地推导作品编号。

    同一个文件被同一个人登记，永远得到同一个作品编号，天然防止重复登记。
    """
    raw = ("ARTCHAIN-WORK|%s|%s" % (file_hash, creator_address)).encode("utf-8")
    return "WK" + hashlib.sha256(raw).hexdigest()[:24]


def post_id_for(txid):
    """由交易哈希确定性地推导帖子编号。

    与 work_id_for 不同，帖子没有"内容指纹"可依赖——两个人发一模一样的
    "早上好"也应该是两条帖子。而 txid 覆盖了签名与 nonce，天然全网唯一；
    它本身就在交易里，任何节点重放同一笔交易都会算出同一个编号，
    确定性不成问题。签名不同 => txid 不同 => 帖子不同，这正是我们要的语义。
    """
    return "PS" + str(txid)[:20]


def normalize_amount(value, field="金额"):
    """校验并规范化金额（最多两位小数），返回字符串。"""
    if value is None or value == "":
        return None
    text = str(value).strip()
    if not _AMOUNT_RE.match(text):
        raise TxError("%s格式不正确，应为非负数字且最多两位小数：%r" % (field, value))
    return text


def normalize_date(value, field="日期"):
    if value is None or value == "":
        return None
    text = str(value).strip()
    if not _DATE_RE.match(text):
        raise TxError("%s格式不正确，应为 YYYY-MM-DD：%r" % (field, value))
    return text


# ------------------------------------------------------------ 积分金额
def points_to_units(value, field="金额"):
    """把用户输入的金额换算成链上的整数最小单位。

    刻意拒绝 float 类型：二进制浮点无法精确表示十进制小数（0.1 没有有限
    二进制展开），从根上杜绝「0.1 + 0.2 ≠ 0.3」这一类账面错误——这是积分
    系统的账本，不允许有任何浮点掺入。
    """
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise TxError("%s必须是数字" % field)
    if isinstance(value, float):
        raise TxError("%s不接受小数类型，请传整数或字符串（链上金额只用最小单位，"
                      "浮点会引入舍入误差）：%r" % (field, value))
    if isinstance(value, int):
        units = value * POINT_SCALE
        text = None
    else:
        text = str(value).strip()
        if not _POINT_RE.match(text):
            raise TxError("%s格式不正确：最多 %d 位小数，且只允许数字与一个小数点：%r"
                          % (field, POINT_DECIMALS, value))
        if "." in text:
            whole, frac = text.split(".", 1)
            units = int(whole) * POINT_SCALE + int(frac.ljust(POINT_DECIMALS, "0"))
        else:
            units = int(text) * POINT_SCALE
    if units <= 0:
        raise TxError("%s必须大于 0" % field)
    if units > POINT_MAX_UNITS:
        raise TxError("%s超出单笔上限" % field)
    return units


def units_to_text(units, decimals=POINT_DECIMALS):
    """把整数最小单位换算成展示文本（尾随 0 裁剪）。"""
    try:
        units = int(units)
    except (TypeError, ValueError):
        return "—"
    sign = "-" if units < 0 else ""
    units = abs(units)
    whole = units // (10 ** decimals)
    frac = units % (10 ** decimals)
    if not frac:
        return "%s%d" % (sign, whole)
    text = ("%0*d" % (decimals, frac)).rstrip("0")
    return "%s%d.%s" % (sign, whole, text)


def make_tx(tx_type, sender, pubkey, data, memo="", nonce=None, timestamp=None):
    """构造一笔未签名交易。"""
    if tx_type not in ALL_TYPES:
        raise TxError("未知的交易类型：%s" % tx_type)
    if tx_type == TX_GENESIS:
        nonce = 0
    else:
        if nonce is None:
            raise TxError("普通交易必须提供 nonce（用于防重放）")
        nonce = int(nonce)
    tx = {
        "version": TX_VERSION,
        "type": tx_type,
        "time": int(timestamp if timestamp is not None else time.time()),
        "sender": sender,
        "pubkey": pubkey or "",
        "nonce": nonce,
        "memo": memo or "",
        "data": data or {},
        "sig": "",
    }
    return tx


def sign_tx(tx, private_key):
    """就地签名并写入 txid，返回同一对象。"""
    tx["sig"] = ec.sign(private_key, signing_bytes(tx))
    tx["txid"] = compute_txid(tx)
    return tx


def verify_tx(tx, allow_genesis=False):
    """校验交易结构与签名。返回 (是否通过, 错误信息)。"""
    if not isinstance(tx, dict):
        return False, "交易不是字典结构"
    for field in ("version", "type", "time", "sender", "data", "sig", "txid"):
        if field not in tx:
            return False, "交易缺少字段：%s" % field
    if tx["version"] != TX_VERSION:
        return False, "不支持的交易版本：%s" % tx["version"]
    tx_type = tx["type"]
    if tx_type not in ALL_TYPES:
        return False, "未知交易类型：%s" % tx_type
    if tx_type == TX_GENESIS:
        if not allow_genesis:
            return False, "创世交易只能出现在 0 号区块"
        if tx.get("txid") != compute_txid(tx):
            return False, "创世交易哈希不匹配"
        return True, ""

    if not isinstance(tx.get("data"), dict):
        return False, "交易 data 必须是对象"
    if not isinstance(tx.get("time"), int) or tx["time"] <= 0:
        return False, "交易时间戳非法"
    try:
        if int(tx.get("nonce", 0)) < 1:
            return False, "nonce 必须为正整数"
    except (TypeError, ValueError):
        return False, "nonce 必须是整数"

    sender = tx["sender"]
    if not ec.is_valid_address(sender):
        return False, "发起方地址不合法：%s" % sender
    pubkey = tx.get("pubkey") or ""
    try:
        derived = ec.address_from_pubkey_hex(pubkey)
    except Exception as exc:
        return False, "公钥不合法：%s" % exc
    if derived != sender:
        return False, "地址与公钥不匹配（地址 %s，公钥推导得到 %s）" % (sender, derived)

    if tx.get("txid") != compute_txid(tx):
        return False, "交易哈希不匹配，数据可能被篡改"
    if not ec.verify(pubkey, signing_bytes(tx), tx["sig"]):
        return False, "交易签名验证失败"
    return True, ""
