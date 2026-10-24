# -*- coding: utf-8 -*-
"""确权状态机：把一条条交易解释成"谁拥有哪件作品"的世界状态。

状态机是区块链的"业务裁判"：
  * 确定性——同样的交易序列必然得到同样的状态，任何节点重放都能得到一致结果；
  * 严格性——只有当前权利人本人签名才能转让 / 许可，且争议中或已撤销的作品锁死；
  * 可审计——每一次权属变动都写入 history，配合区块高度可完整溯源。

状态结构：
    works[work_id]        作品档案（含全部指纹）
    owners[work_id]       当前权利人地址
    history[work_id]      权属变更记录（登记/转让/许可/争议/撤销）
    licenses[work_id]     授权许可台账
    by_file_hash[fh]      文件指纹 -> work_id（用于查重与侵权比对）
    nonces[address]       各地址已用过的最大 nonce（防重放）
    posts[post_id]        社区帖子档案（正文与附图哈希直接在链上）
    likes[post_id]        点赞地址列表（每地址至多一次，无撤销）
    reply_counts[post_id] 帖子直接回复数（查询索引，由 POST 交易确定性维护）

    balances[address]     平台积分余额（整数最小单位，8 位小数）
    total_supply          积分流通总量（= 铸造累计 - 销毁累计）
    points_log            积分流水（MINT/BURN/PAY 全部记录，按上链顺序追加）
"""

import copy
import os

from .tx import (POINT_MAX_UNITS, RULING_REJECT, RULING_UPHOLD, RULINGS, TX_ADJUDICATE,
                 TX_BURN, TX_DISPUTE, TX_GENESIS, TX_LICENSE, TX_LIKE, TX_MINT, TX_PAY,
                 TX_POST, TX_REGISTER, TX_REVOKE, TX_TRANSFER, TxError, normalize_amount,
                 normalize_date, post_id_for, work_id_for)

from ..crypto import secp256k1 as ec

STATUS_ACTIVE = "有效"
STATUS_DISPUTED = "争议中"
STATUS_REVOKED = "已撤销"
# 裁决支持异议后的终态。刻意不复用「已撤销」：
# 「已撤销」是权利人自己反悔撤回，「已无效」是第三方裁决认定这次登记不该成立，
# 两者的成因、可争议性和后续处置都不同，混成一态会让 history 失去解释力。
STATUS_INVALID = "已无效"

# 争议记录自身的状态。一条争议从提出到终结只会走其中一条路径。
DISPUTE_OPEN = "待裁决"
DISPUTE_REJECTED = "已驳回"
DISPUTE_UPHELD = "已支持"
DISPUTE_CLOSED = "已终止"   # 争议没了结，但作品被撤销，争议自动关掉

_MAX_TITLE = 200
_MAX_TEXT = 2000
_MAX_TOPIC = 20

# 链下原件的存放前缀。stored_path 会原样上链，读取时被拼进本地路径，
# 所以"什么样的 stored_path 算合法"必须由链规则统一定死，不能只靠读取端兜底。
_BLOB_PREFIX = "files"


def valid_stored_path(relative_path):
    """链规则：stored_path 必须是 files/ 下的、不含 .. 的相对路径。

    允许为空串（登记时选择不保存原件）。
    拒绝绝对路径、盘符路径、以及任何 .. 段——这些都会让读取端拼出 data/ 之外的路径。
    """
    if relative_path in (None, ""):
        return True
    if not isinstance(relative_path, str):
        return False
    if os.path.isabs(relative_path) or os.path.splitdrive(relative_path)[0]:
        return False
    parts = [p for p in relative_path.replace("\\", "/").split("/")]
    if any(part in ("", ".", "..") for part in parts):
        return False
    return parts[0] == _BLOB_PREFIX


class LedgerError(Exception):
    """交易无法被状态机接受（业务规则不通过）。"""

    def __init__(self, message, code="INVALID"):
        Exception.__init__(self, message)
        self.code = code


class Ledger(object):
    """确权账本（世界状态）。"""

    def __init__(self):
        self.works = {}
        self.owners = {}
        self.history = {}
        self.licenses = {}
        self.by_file_hash = {}
        self.nonces = {}
        self.disputes = []
        self.posts = {}
        self.likes = {}
        self.reply_counts = {}   # 帖子编号 -> 直接回复数（查询索引，重放时确定性重建）
        self.chain_meta = {}
        self.balances = {}       # 地址 -> 积分余额（整数最小单位）
        self.total_supply = 0    # 流通总量（整数最小单位）
        self.points_log = []     # 积分流水（MINT/BURN/PAY）

    # ---------------------------------------------------------- 工具
    def copy(self):
        return copy.deepcopy(self)

    def next_nonce(self, address):
        return int(self.nonces.get(address, 0)) + 1

    def get_work(self, work_id):
        return self.works.get(work_id)

    def owner_of(self, work_id):
        return self.owners.get(work_id)

    def find_by_file_hash(self, file_hash):
        work_id = self.by_file_hash.get(file_hash)
        return self.works.get(work_id) if work_id else None

    def list_works(self, owner=None, keyword=None, status=None):
        items = []
        for work_id, work in self.works.items():
            if owner and work.get("owner") != owner:
                continue
            if status and work.get("status") != status:
                continue
            if keyword:
                haystack = " ".join(str(work.get(f, "")) for f in
                                    ("work_id", "title", "author", "category", "description"))
                if keyword.lower() not in haystack.lower():
                    continue
            items.append(work)
        items.sort(key=lambda w: (w.get("registered_at", 0), w.get("work_id", "")))
        return items

    def stats(self):
        total = len(self.works)
        active = sum(1 for w in self.works.values() if w.get("status") == STATUS_ACTIVE)
        disputed = sum(1 for w in self.works.values() if w.get("status") == STATUS_DISPUTED)
        revoked = sum(1 for w in self.works.values() if w.get("status") == STATUS_REVOKED)
        invalid = sum(1 for w in self.works.values() if w.get("status") == STATUS_INVALID)
        transfers = sum(int(w.get("transfer_count", 0)) for w in self.works.values())
        licenses = sum(len(v) for v in self.licenses.values())
        return {
            "works_total": total,
            "works_active": active,
            "works_disputed": disputed,
            "works_revoked": revoked,
            "works_invalid": invalid,
            "owners_total": len(set(self.owners.values())),
            "transfers_total": transfers,
            "licenses_total": licenses,
            "disputes_total": len(self.disputes),
            "disputes_open": sum(1 for d in self.disputes if d.get("status") == DISPUTE_OPEN),
            "posts_total": len(self.posts),
            "likes_total": sum(len(v) for v in self.likes.values()),
            "points_supply": self.total_supply,
            "points_holders": sum(1 for v in self.balances.values() if int(v) > 0),
            "points_transfers": sum(1 for e in self.points_log if e.get("type") == TX_PAY),
            "points_operator": self.chain_meta.get("operator_address") or "",
            "points_cap": self.chain_meta.get("max_supply"),
        }

    def open_dispute(self, work_id):
        """取该作品当前尚未裁决的那条争议；没有则返回 None。"""
        for entry in reversed(self.disputes):
            if entry.get("work_id") != work_id:
                continue
            # disputes 按追加顺序排列，倒着扫遇到的第一条就是该作品最近的一条争议。
            # 它若已终结，说明这件作品没有悬着的异议了。
            return entry if entry.get("status") == DISPUTE_OPEN else None
        return None

    # ---------------------------------------------------------- 校验
    def _require_address(self, address, field="地址"):
        if not ec.is_valid_address(address):
            raise LedgerError("%s不合法：%r" % (field, address), "BAD_ADDRESS")
        return address

    def _require_text(self, value, field, maxlen=_MAX_TEXT, required=True):
        if value is None:
            value = ""
        value = str(value).strip()
        if not value and required:
            raise LedgerError("%s不能为空" % field, "MISSING_FIELD")
        if len(value) > maxlen:
            raise LedgerError("%s过长（最多 %d 字）" % (field, maxlen), "TOO_LONG")
        return value

    def _require_active(self, work, action):
        status = work.get("status", STATUS_ACTIVE)
        if status == STATUS_DISPUTED:
            raise LedgerError("作品《%s》正处于权属争议中，暂不能%s" % (work.get("title"), action),
                              "WORK_DISPUTED")
        if status == STATUS_REVOKED:
            raise LedgerError("作品《%s》的登记已被撤销，不能再%s" % (work.get("title"), action),
                              "WORK_REVOKED")
        if status == STATUS_INVALID:
            raise LedgerError("作品《%s》的登记已被裁决为无效，不能再%s" % (work.get("title"), action),
                              "WORK_INVALID")
        return work

    # ---------------------------------------------------------- 应用交易
    def apply(self, tx, height, block_hash_value, block_time=None):
        """把一笔交易应用到状态上。失败抛 LedgerError（调用方须整体回滚）。"""
        tx_type = tx.get("type")
        sender = tx.get("sender")
        data = tx.get("data") or {}
        record_time = int(tx.get("time") or 0)

        if tx_type == TX_GENESIS:
            if height != 0:
                raise LedgerError("创世交易只能存在于 0 号区块", "BAD_GENESIS")
            operator_address = data.get("operator_address") or ""
            if operator_address and not ec.is_valid_address(operator_address):
                raise LedgerError("创世区块的运营方地址不合法", "BAD_OPERATOR")
            max_supply = data.get("max_supply")
            if max_supply not in (None, ""):
                try:
                    max_supply = int(max_supply)
                except (TypeError, ValueError):
                    raise LedgerError("积分总量上限必须是整数最小单位", "BAD_SUPPLY")
                if max_supply <= 0:
                    raise LedgerError("积分总量上限必须大于 0", "BAD_SUPPLY")
            self.chain_meta = {
                "name": data.get("name", "ArtChain 艺术品确权链"),
                "description": data.get("description", ""),
                "created_at": record_time,
                "operator": data.get("operator", ""),
                # 发行权：MINT/BURN 只认这个地址。为空 = 旧链兼容模式，
                # 铸造不受限（create_genesis 与 CLI/网页会给出醒目警示）。
                "operator_address": operator_address,
                # 总量上限（整数最小单位，None = 不限）
                "max_supply": max_supply,
            }
            return {"type": TX_GENESIS, "message": "创世区块已建立"}

        # 防重放：同一地址的 nonce 必须严格递增
        expected_min = self.nonces.get(sender, 0) + 1
        nonce = int(tx.get("nonce") or 0)
        if nonce < expected_min:
            raise LedgerError("nonce 过小（收到 %d，至少需要 %d），可能是重放交易" % (nonce, expected_min),
                              "BAD_NONCE")

        handler = {
            TX_REGISTER: self._apply_register,
            TX_TRANSFER: self._apply_transfer,
            TX_LICENSE: self._apply_license,
            TX_DISPUTE: self._apply_dispute,
            TX_REVOKE: self._apply_revoke,
            TX_ADJUDICATE: self._apply_adjudicate,
            TX_POST: self._apply_post,
            TX_LIKE: self._apply_like,
            TX_PAY: self._apply_pay,
            TX_MINT: self._apply_mint,
            TX_BURN: self._apply_burn,
        }.get(tx_type)
        if handler is None:
            raise LedgerError("状态机不支持该交易类型：%s" % tx_type, "BAD_TYPE")
        result = handler(tx, data, height, block_hash_value, record_time)
        # nonce 的写入刻意放在业务处理成功之后：让 apply 要么完整生效、要么完全不变。
        # 各业务 handler 同样是「先校验后变更」，因此失败的一笔交易不会在账本里
        # 留下半截状态——调用方才能放心地反复用同一个账本对象做多笔交易的预演。
        self.nonces[sender] = nonce
        return result

    # ---------------------------------------------------------- REGISTER
    def _apply_register(self, tx, data, height, block_hash_value, record_time):
        sender = tx["sender"]
        file_hash = self._require_text(data.get("file_hash"), "文件哈希", 128)
        if len(file_hash) != 64:
            raise LedgerError("文件哈希应为 64 位十六进制 SHA-256", "BAD_FINGERPRINT")
        try:
            int(file_hash, 16)
        except ValueError:
            raise LedgerError("文件哈希不是合法的十六进制", "BAD_FINGERPRINT")

        expected_id = work_id_for(file_hash, sender)
        work_id = self._require_text(data.get("work_id"), "作品编号", 64)
        if work_id != expected_id:
            raise LedgerError("作品编号与文件指纹不匹配（应为 %s）" % expected_id, "BAD_WORK_ID")
        if work_id in self.works:
            raise LedgerError("该作品已完成确权登记，编号 %s" % work_id, "ALREADY_REGISTERED")

        existing = self.find_by_file_hash(file_hash)
        if existing is not None:
            raise LedgerError(
                "该文件指纹已被作品《%s》（%s）登记于权利人 %s 名下；"
                "如认为对方侵权，请使用 dispute 指令发起权属争议" % (
                    existing.get("title"), existing.get("work_id"), existing.get("owner")),
                "FINGERPRINT_TAKEN")

        title = self._require_text(data.get("title"), "作品名称", _MAX_TITLE)
        category = self._require_text(data.get("category", "其他"), "作品类别", 40)
        author = self._require_text(data.get("author", ""), "作者署名", 120, required=False)
        description = self._require_text(data.get("description", ""), "作品说明", _MAX_TEXT, required=False)
        creator_at = data.get("created_at") or ""
        if creator_at:
            creator_at = normalize_date(creator_at, "创作完成日期")
        year = data.get("year")
        if year not in (None, ""):
            try:
                year = int(year)
            except (TypeError, ValueError):
                raise LedgerError("创作年份必须是整数", "BAD_FIELD")
            if not 1000 <= year <= 2999:
                raise LedgerError("创作年份超出合理范围", "BAD_FIELD")

        meta = data.get("meta") or {}
        if not isinstance(meta, dict):
            raise LedgerError("meta 必须是对象", "BAD_FIELD")

        # stored_path 会被读取端拼进本地文件路径，越界的路径一律不接受。
        stored_path = data.get("stored_path", "")
        if not valid_stored_path(stored_path):
            raise LedgerError("stored_path 必须是 files/ 下的相对路径，不能包含 .. 或盘符", "BAD_FIELD")

        work = {
            "work_id": work_id,
            "title": title,
            "category": category,
            "author": author or sender[:10],
            "description": description,
            "created_at": creator_at,
            "year": year,
            "meta": meta,
            # 指纹
            "file_hash": file_hash,
            "size": int(data.get("size") or 0),
            "kind": data.get("kind", "binary"),
            "phash": data.get("phash"),
            "ahash": data.get("ahash"),
            "dhash": data.get("dhash"),
            "simhash": data.get("simhash"),
            # 注意：图像尺寸必须与下面的区块高度 "height" 区分开，
            # 否则 "height" 会被区块高度覆盖，图像高度就丢了。
            "image_width": data.get("width"),
            "image_height": data.get("height"),
            "mime": data.get("mime", ""),
            "stored_path": stored_path,
            # 权属
            "creator": sender,
            "owner": sender,
            "status": STATUS_ACTIVE,
            "registered_at": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
            "transfer_count": 0,
            "license_count": 0,
        }
        self.works[work_id] = work
        self.owners[work_id] = sender
        self.by_file_hash[file_hash] = work_id
        self.history.setdefault(work_id, []).append({
            "action": "登记确权",
            "type": TX_REGISTER,
            "from": None,
            "to": sender,
            "time": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
            "detail": "首次将作品指纹写入区块链，完成著作权存证确权",
        })
        return {"type": TX_REGISTER, "work_id": work_id, "message": "作品《%s》确权成功" % title,
                "work": work}

    # ---------------------------------------------------------- TRANSFER
    def _apply_transfer(self, tx, data, height, block_hash_value, record_time):
        sender = tx["sender"]
        work_id = self._require_text(data.get("work_id"), "作品编号", 64)
        work = self.works.get(work_id)
        if work is None:
            raise LedgerError("作品不存在：%s" % work_id, "NO_WORK")
        self._require_active(work, "转让")
        if self.owners.get(work_id) != sender:
            raise LedgerError("只有当前权利人才能转让该作品（当前权利人：%s）" % self.owners.get(work_id),
                              "NOT_OWNER")
        to = self._require_address(data.get("to"), "受让方地址")
        if to == sender:
            raise LedgerError("不能把作品转让给自己", "BAD_TARGET")
        price = normalize_amount(data.get("price"), "转让价款")
        note = self._require_text(data.get("note", ""), "备注", _MAX_TEXT, required=False)

        self.owners[work_id] = to
        work["owner"] = to
        work["transfer_count"] = int(work.get("transfer_count", 0)) + 1
        self.history.setdefault(work_id, []).append({
            "action": "版权转让",
            "type": TX_TRANSFER,
            "from": sender,
            "to": to,
            "price": price,
            "time": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
            "detail": note or ("转让价款 %s" % price if price else "无偿转让"),
        })
        return {"type": TX_TRANSFER, "work_id": work_id, "to": to,
                "message": "《%s》著作权已转让至 %s" % (work.get("title"), to)}

    # ---------------------------------------------------------- LICENSE
    def _apply_license(self, tx, data, height, block_hash_value, record_time):
        sender = tx["sender"]
        work_id = self._require_text(data.get("work_id"), "作品编号", 64)
        work = self.works.get(work_id)
        if work is None:
            raise LedgerError("作品不存在：%s" % work_id, "NO_WORK")
        self._require_active(work, "对外授权")
        if self.owners.get(work_id) != sender:
            raise LedgerError("只有当前权利人才有权对外授权（当前权利人：%s）" % self.owners.get(work_id),
                              "NOT_OWNER")
        to = self._require_address(data.get("to"), "被许可方地址")
        scope = self._require_text(data.get("scope", "非独家"), "授权类型", 40)
        if scope not in ("独家", "非独家"):
            raise LedgerError("授权类型只能是「独家」或「非独家」", "BAD_FIELD")
        territory = self._require_text(data.get("territory", "全球"), "授权地域", 80, required=False) or "全球"
        royalty = normalize_amount(data.get("royalty"), "授权费用")
        start = normalize_date(data.get("start"), "授权起始日")
        end = normalize_date(data.get("end"), "授权截止日")
        if start and end and start > end:
            raise LedgerError("授权截止日不能早于起始日", "BAD_DATE")
        purpose = self._require_text(data.get("purpose", ""), "授权用途", _MAX_TEXT, required=False)

        if scope == "独家":
            for lic in self.licenses.get(work_id, []):
                if lic.get("scope") == "独家" and lic.get("status") == "生效中":
                    raise LedgerError(
                        "该作品已存在独家授权（被许可方 %s，区块 #%s）" % (lic.get("to"), lic.get("height")),
                        "EXCLUSIVE_CONFLICT")

        license_id = "LC" + tx["txid"][:20]
        entry = {
            "license_id": license_id,
            "work_id": work_id,
            "licensor": sender,
            "to": to,
            "scope": scope,
            "territory": territory,
            "royalty": royalty,
            "start": start,
            "end": end,
            "purpose": purpose,
            "status": "生效中",
            "time": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
        }
        self.licenses.setdefault(work_id, []).append(entry)
        work["license_count"] = int(work.get("license_count", 0)) + 1
        self.history.setdefault(work_id, []).append({
            "action": "授权许可",
            "type": TX_LICENSE,
            "from": sender,
            "to": to,
            "time": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
            "detail": "%s授权 %s，地域 %s%s" % (
                scope, purpose or "（用途未注明）", territory,
                "，费用 %s" % royalty if royalty else ""),
        })
        return {"type": TX_LICENSE, "work_id": work_id, "license_id": license_id,
                "message": "《%s》已向 %s 出具%s授权" % (work.get("title"), to, scope)}

    # ---------------------------------------------------------- DISPUTE
    def _apply_dispute(self, tx, data, height, block_hash_value, record_time):
        sender = tx["sender"]
        work_id = self._require_text(data.get("work_id"), "作品编号", 64)
        work = self.works.get(work_id)
        if work is None:
            raise LedgerError("作品不存在：%s" % work_id, "NO_WORK")
        if self.owners.get(work_id) == sender:
            raise LedgerError("权利人本人不能对自己的登记提出异议，如需撤回请使用撤销登记",
                              "BAD_TARGET")
        # 只有「有效」的作品可以被提异议。这一条是后补的：此前这里不校验状态，
        # 于是争议中的作品能被反复提异议，已经撤销的作品更会被一次异议拉回「争议中」——
        # 「已撤销」是权利人自己撤回后的终态，不该被异议复活。
        self._require_active(work, "提出异议")
        reason = self._require_text(data.get("reason"), "异议理由", _MAX_TEXT)
        evidence = data.get("evidence_hash") or ""
        if evidence:
            evidence = self._require_text(evidence, "证据哈希", 128)

        work["status"] = STATUS_DISPUTED
        entry = {
            "work_id": work_id,
            "title": work.get("title"),
            "claimant": sender,
            "reason": reason,
            "evidence_hash": evidence,
            # 争议自己也有生命周期：提出时是「待裁决」，裁决后由 _apply_adjudicate
            # 改写为「已驳回」或「已支持」。没有这个字段就无从判断哪些争议还悬着。
            "status": DISPUTE_OPEN,
            "ruling": None,
            "arbiter": None,
            "resolved_at": None,
            "resolved_height": None,
            "resolution_txid": None,
            "time": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
        }
        self.disputes.append(entry)
        self.history.setdefault(work_id, []).append({
            "action": "权属争议",
            "type": TX_DISPUTE,
            "from": sender,
            "to": None,
            "time": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
            "detail": reason,
        })
        return {"type": TX_DISPUTE, "work_id": work_id,
                "message": "《%s》已被标记为争议中" % work.get("title")}

    # ---------------------------------------------------------- REVOKE
    def _apply_revoke(self, tx, data, height, block_hash_value, record_time):
        sender = tx["sender"]
        work_id = self._require_text(data.get("work_id"), "作品编号", 64)
        work = self.works.get(work_id)
        if work is None:
            raise LedgerError("作品不存在：%s" % work_id, "NO_WORK")
        if self.owners.get(work_id) != sender:
            raise LedgerError("只有当前权利人才能撤销登记", "NOT_OWNER")
        if work.get("status") == STATUS_REVOKED:
            raise LedgerError("该作品登记已被撤销", "WORK_REVOKED")
        # 「已无效」是第三方裁决的结论，不能让登记人用一次「撤销登记」把它改写成
        # 「自己主动撤回」——那等于事后篡改裁决结果留在链上的含义。
        if work.get("status") == STATUS_INVALID:
            raise LedgerError("该作品登记已被裁决为无效，不能再以撤销登记覆盖该裁决结果",
                              "WORK_INVALID")
        reason = self._require_text(data.get("reason", "权利人主动撤回"), "撤销理由", _MAX_TEXT,
                                    required=False) or "权利人主动撤回"

        work["status"] = STATUS_REVOKED
        # 撤销是权利人自己认输，作品此后不再是「争议中」，那条悬着的异议
        # 也就无从裁决了。这里把它标记为「已终止」而不是留着不管，
        # 否则 disputes 里会永久躺着一批「待裁决」却永远没人能裁的记录。
        pending = self.open_dispute(work_id)
        if pending is not None:
            pending["status"] = DISPUTE_CLOSED
            pending["ruling"] = "登记方撤销登记，争议自动终止"
            pending["resolved_at"] = record_time
            pending["resolved_height"] = height
            pending["resolution_txid"] = tx["txid"]
        # 撤销后释放指纹占用，允许他人重新登记
        if self.by_file_hash.get(work.get("file_hash")) == work_id:
            self.by_file_hash.pop(work.get("file_hash"), None)
        self.history.setdefault(work_id, []).append({
            "action": "撤销登记",
            "type": TX_REVOKE,
            "from": sender,
            "to": None,
            "time": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
            "detail": reason,
        })
        return {"type": TX_REVOKE, "work_id": work_id,
                "message": "《%s》的登记已撤销" % work.get("title")}

    # ---------------------------------------------------------- ADJUDICATE
    def _apply_adjudicate(self, tx, data, height, block_hash_value, record_time):
        """对一条悬着的权属异议作出裁决，让它有终局。

        在此之前 dispute 只能把作品锁死，没有任何解开的路径，
        一件被提异议的作品会永久停在「争议中」。

        裁决权：**任何与本案无利害关系的第三方**。
        这条规则与 dispute 是对称的——那边是「任何非权利人可提异议」，
        这边是「任何非当事人可作裁决」。两个当事人都要排除：
        权利人（有保住登记的动机）和异议提出人（有推翻登记的动机）。
        链上没有、也刻意不引入中心化的仲裁人身份，所以不设白名单。
        """
        sender = tx["sender"]
        work_id = self._require_text(data.get("work_id"), "作品编号", 64)
        work = self.works.get(work_id)
        if work is None:
            raise LedgerError("作品不存在：%s" % work_id, "NO_WORK")

        # 先找悬着的争议。找不到就说明这件作品没什么可裁的：
        # 有效作品还没人提异议，已撤销/已无效的作品其争议早已终结。
        dispute = self.open_dispute(work_id)
        if dispute is None:
            raise LedgerError(
                "作品《%s》当前状态为「%s」，没有待裁决的争议；只有「争议中」的作品需要裁决"
                % (work.get("title"), work.get("status", STATUS_ACTIVE)),
                "NO_DISPUTE")

        owner = self.owners.get(work_id)
        if sender == owner:
            raise LedgerError("当前权利人不能裁决针对自己的异议；如认可该异议请使用撤销登记",
                              "BAD_ARBITER")
        if sender == dispute.get("claimant"):
            raise LedgerError("异议提出人不能裁决自己提出的异议，裁决须由第三方作出",
                              "BAD_ARBITER")

        ruling = self._require_text(data.get("ruling"), "裁决结论", 10)
        if ruling not in RULINGS:
            raise LedgerError("裁决结论只能是「%s」或「%s」，收到 %r" % (
                RULING_REJECT, RULING_UPHOLD, ruling), "BAD_RULING")
        reason = self._require_text(data.get("reason"), "裁决理由", _MAX_TEXT)
        evidence = data.get("evidence_hash") or ""
        if evidence:
            evidence = self._require_text(evidence, "证据哈希", 128)

        if ruling == RULING_UPHOLD:
            work["status"] = STATUS_INVALID
            # 与撤销登记同理：登记既然被判定不成立，指纹就不该继续被它占着，
            # 否则真正的作者永远无法登记同一份文件——那等于用一次错误登记
            # 把作品从链上永久锁死。释放后由真实作者重新登记。
            if self.by_file_hash.get(work.get("file_hash")) == work_id:
                self.by_file_hash.pop(work.get("file_hash"), None)
            outcome = "异议成立，该登记被认定为无效"
        else:
            work["status"] = STATUS_ACTIVE
            outcome = "异议不成立，维持原登记"

        dispute["status"] = DISPUTE_UPHELD if ruling == RULING_UPHOLD else DISPUTE_REJECTED
        dispute["ruling"] = ruling
        dispute["arbiter"] = sender
        dispute["resolve_reason"] = reason
        dispute["resolve_evidence_hash"] = evidence
        dispute["resolved_at"] = record_time
        dispute["resolved_height"] = height
        dispute["resolution_txid"] = tx["txid"]

        self.history.setdefault(work_id, []).append({
            "action": "争议裁决",
            "type": TX_ADJUDICATE,
            "from": sender,
            "to": None,
            "time": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
            "detail": "%s异议：%s" % (ruling, reason),
        })
        return {"type": TX_ADJUDICATE, "work_id": work_id, "ruling": ruling,
                "status": work["status"],
                "message": "《%s》的权属争议已裁决：%s，作品状态转为「%s」" % (
                    work.get("title"), outcome, work["status"])}

    # ---------------------------------------------------------- POST
    def _apply_post(self, tx, data, height, block_hash_value, record_time):
        """社区发帖 / 回复。正文全文上链，附图只上哈希（原件走链下 files/）。

        帖子编号由 txid 确定性推导（见 tx.post_id_for），任何节点重放
        同一笔交易都会得到同一个编号；txid 全链唯一由 validate_blocks
        的 seen_txids 把关，所以这里不需要、也不可能撞号。
        """
        sender = tx["sender"]
        text = self._require_text(data.get("text"), "帖子正文", _MAX_TEXT)
        topic = self._require_text(data.get("topic", ""), "话题", _MAX_TOPIC, required=False)
        reply_to = self._require_text(data.get("reply_to", ""), "父帖编号", 64, required=False)
        if reply_to and reply_to not in self.posts:
            raise LedgerError("要回复的帖子不存在：%s" % reply_to, "NO_POST")

        image_hash = data.get("image_hash") or ""
        if image_hash:
            image_hash = self._require_text(image_hash, "附图哈希", 128)
            if len(image_hash) != 64:
                raise LedgerError("附图哈希应为 64 位十六进制 SHA-256", "BAD_FINGERPRINT")
            try:
                int(image_hash, 16)
            except ValueError:
                raise LedgerError("附图哈希不是合法的十六进制", "BAD_FINGERPRINT")

        # 与 REGISTER 同款防线：stored_path 会被读取端拼进本地路径，
        # 越界路径一律拒绝。允许为空（只上哈希、不在本节点存图）。
        stored_path = data.get("stored_path", "")
        if not valid_stored_path(stored_path):
            raise LedgerError("stored_path 必须是 files/ 下的相对路径，不能包含 .. 或盘符",
                              "BAD_FIELD")

        post_id = post_id_for(tx["txid"])
        self.posts[post_id] = {
            "post_id": post_id,
            "author": sender,
            "text": text,
            "topic": topic,
            "image_hash": image_hash,
            "stored_path": stored_path,
            "reply_to": reply_to,
            "time": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
        }
        self.likes.setdefault(post_id, [])
        # 维护「父帖 -> 直接回复数」索引，让列表页不必 O(全部帖子) 地数回复。
        if reply_to:
            self.reply_counts[reply_to] = int(self.reply_counts.get(reply_to, 0)) + 1
        return {"type": TX_POST, "post_id": post_id,
                "message": "%s已写入区块链（编号 %s）" % ("回复" if reply_to else "帖子", post_id)}

    # ---------------------------------------------------------- LIKE
    def _apply_like(self, tx, data, height, block_hash_value, record_time):
        """点赞。一个地址对一帖只能赞一次。

        刻意不提供「取消赞」交易：点赞是一次签名的公开表态，写进区块
        就是历史的一部分。要收回表态？链上没有后悔药——这正是它比
        中心化服务器上的计数器的可信之处。
        """
        sender = tx["sender"]
        post_id = self._require_text(data.get("post_id"), "帖子编号", 64)
        if post_id not in self.posts:
            raise LedgerError("帖子不存在：%s" % post_id, "NO_POST")
        liked = self.likes.setdefault(post_id, [])
        if sender in liked:
            raise LedgerError("该地址已经赞过这帖——链上的赞没有后悔药，也不能重复盖章",
                              "ALREADY_LIKED")
        liked.append(sender)
        return {"type": TX_LIKE, "post_id": post_id, "likes": len(liked),
                "message": "点赞已上链（该帖共 %d 个赞）" % len(liked)}

    # ---------------------------------------------------------- 平台积分
    def _require_units(self, value, field):
        """链规则：交易里的金额字段就是整数最小单位，这里只做合法性校验。

        用户输入到最小单位的换算发生在 service 层（points_to_units），
        状态机刻意不再换算——否则同一笔金额会被换算两次（历史教训）。
        """
        if isinstance(value, bool):
            raise LedgerError("%s必须是整数最小单位" % field, "BAD_AMOUNT")
        try:
            units = int(value)
        except (TypeError, ValueError):
            raise LedgerError("%s必须是整数最小单位" % field, "BAD_AMOUNT")
        if units <= 0:
            raise LedgerError("%s必须大于 0" % field, "BAD_AMOUNT")
        if units > POINT_MAX_UNITS:
            raise LedgerError("%s超出单笔上限" % field, "BAD_AMOUNT")
        return units

    def _is_operator(self, address):
        """积分发行权：与创世区块登记的运营方地址比对。

        运营方地址为空说明这是升级前建的旧链（创世区块没有这个字段），
        此时铸造不受限——这是为旧演示链保留的兼容模式，新链务必填写。
        """
        declared = self.chain_meta.get("operator_address") or ""
        return not declared or address == declared

    def _require_operator(self, sender):
        declared = self.chain_meta.get("operator_address") or ""
        if not declared:
            return  # 兼容模式：放行（调用方负责给出警示文案）
        if sender != declared:
            raise LedgerError("积分铸造/销毁仅限运营方地址 %s（当前发起方 %s）"
                              % (declared, sender), "NOT_OPERATOR")

    def _points_log(self, kind, tx, data, height, block_hash_value, record_time):
        entry = {
            "type": kind,
            "from": tx["sender"] if kind != TX_MINT else None,
            "to": data.get("to") if kind == TX_PAY else tx["sender"],
            "amount": data["amount"],
            "memo": data.get("memo") or "",
            "time": record_time,
            "height": height,
            "block_hash": block_hash_value,
            "txid": tx["txid"],
        }
        self.points_log.append(entry)
        return entry

    def _apply_mint(self, tx, data, height, block_hash_value, record_time):
        """铸造：增发积分并计入运营方余额。发行权写死在链规则里。"""
        sender = tx["sender"]
        self._require_operator(sender)
        amount = self._require_units(data.get("amount"), "铸造数量")
        cap = self.chain_meta.get("max_supply")
        if cap and self.total_supply + amount > cap:
            raise LedgerError("铸造后流通量将超过总量上限 %s（当前流通 %s）"
                              % (cap, self.total_supply), "SUPPLY_CAP")
        self.total_supply += amount
        self.balances[sender] = int(self.balances.get(sender, 0)) + amount
        entry = self._points_log(TX_MINT, tx, data, height, block_hash_value, record_time)
        return {"type": TX_MINT, "amount": amount, "to": sender,
                "supply": self.total_supply,
                "message": "已铸造积分，计入 %s，流通量更新" % sender}

    def _apply_burn(self, tx, data, height, block_hash_value, record_time):
        """销毁：从运营方余额回收积分并缩减流通量。"""
        sender = tx["sender"]
        self._require_operator(sender)
        amount = self._require_units(data.get("amount"), "销毁数量")
        balance = int(self.balances.get(sender, 0))
        if balance < amount:
            raise LedgerError("余额不足：运营方当前持有 %s，试图销毁 %s"
                              % (balance, amount), "INSUFFICIENT_BALANCE")
        self.total_supply -= amount
        self.balances[sender] = balance - amount
        entry = self._points_log(TX_BURN, tx, data, height, block_hash_value, record_time)
        return {"type": TX_BURN, "amount": amount, "from": sender,
                "supply": self.total_supply,
                "message": "积分已销毁，流通量缩减"}

    def _apply_pay(self, tx, data, height, block_hash_value, record_time):
        """转账：点对点积分划转。校验余额、目标地址与「不能转给自己」。"""
        sender = tx["sender"]
        to = self._require_address(data.get("to"), "收款方地址")
        if to == sender:
            raise LedgerError("不能把积分转给自己", "BAD_TARGET")
        amount = self._require_units(data.get("amount"), "转账金额")
        balance = int(self.balances.get(sender, 0))
        if balance < amount:
            raise LedgerError("余额不足：当前持有 %s，试图转出 %s"
                              % (balance, amount), "INSUFFICIENT_BALANCE")
        self.balances[sender] = balance - amount
        self.balances[to] = int(self.balances.get(to, 0)) + amount
        entry = self._points_log(TX_PAY, tx, data, height, block_hash_value, record_time)
        return {"type": TX_PAY, "amount": amount, "from": sender, "to": to,
                "message": "积分转账成功"}
