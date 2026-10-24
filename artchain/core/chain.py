# -*- coding: utf-8 -*-
"""区块链主体：出块、校验、状态推进、持久化与节点间同步。

链的合法性由 validate_blocks() 一次性完整校验：
    * 结构完整性（字段、高度递增、前向哈希链接、时间单调不减）
    * Merkle 根与实际交易集合一致
    * 区块头哈希满足难度目标（工作量证明）
    * 每笔交易签名有效、txid 唯一（防重放 / 防重复打包）
    * 逐笔重放交易，状态机不得抛错

任何一个环节不通过，整条链都会被拒绝——这是"不可篡改"的技术来源。
"""

import threading
import time

from .block import (GENESIS_PREV_HASH, block_hash, make_block, meets_difficulty,
                    merkle_proof, merkle_root, mine_block, verify_merkle_proof)
from .state import Ledger, LedgerError
from .tx import TX_GENESIS, compute_txid, make_tx, verify_tx

DEFAULT_DIFFICULTY = 4
MAX_TXS_PER_BLOCK = 500
CHAIN_FORMAT_VERSION = 1


class ChainError(Exception):
    """区块链层面的错误。"""


def validate_blocks(blocks, expected_difficulty=None):
    """完整校验一条链，返回 (是否合法, 错误列表, 重放得到的账本)。"""
    errors = []

    def err(msg):
        errors.append(msg)
        return False

    ledger = Ledger()

    if not isinstance(blocks, list) or not blocks:
        err("链数据为空或格式不正确")
        return False, errors, ledger

    seen_txids = set()
    prev = None

    for index, block in enumerate(blocks):
        where = "区块 #%s" % block.get("height", index)
        if not isinstance(block, dict):
            err("%s 不是对象" % where)
            break
        for field in ("version", "height", "prev_hash", "time", "txs", "merkle_root",
                      "difficulty", "nonce", "hash"):
            if field not in block:
                err("%s 缺少字段 %s" % (where, field))
                return False, errors, ledger
        if block["height"] != index:
            err("%s 高度与位置不符（期望 %d）" % (where, index))
        if not isinstance(block["txs"], list):
            err("%s 的交易列表格式不正确" % where)
            return False, errors, ledger
        if expected_difficulty is not None and int(block["difficulty"]) != int(expected_difficulty):
            err("%s 难度 %s 与本链设定 %s 不一致" % (where, block["difficulty"], expected_difficulty))

        if index == 0:
            if block["prev_hash"] != GENESIS_PREV_HASH:
                err("%s 的 prev_hash 不是创世值" % where)
            if len(block["txs"]) != 1 or block["txs"][0].get("type") != TX_GENESIS:
                err("%s 必须且只能包含一笔创世交易" % where)
        else:
            if block["prev_hash"] != prev["hash"]:
                err("%s 的 prev_hash 与上一区块哈希不匹配（链已断裂）" % where)
            if int(block["time"]) < int(prev["time"]):
                err("%s 的时间戳早于上一区块" % where)

        txids = [t.get("txid", "") for t in block["txs"]]
        if merkle_root(txids) != block["merkle_root"]:
            err("%s 的 Merkle 根与交易集合不一致" % where)

        recomputed = block_hash(block)
        if recomputed != block["hash"]:
            err("%s 的区块哈希不匹配（区块头被篡改）" % where)
        if not meets_difficulty(block["hash"], int(block["difficulty"])):
            err("%s 的工作量证明不满足难度 %s" % (where, block["difficulty"]))

        for pos, tx in enumerate(block["txs"]):
            ok, message = verify_tx(tx, allow_genesis=(index == 0))
            if not ok:
                err("%s 第 %d 笔交易无效：%s" % (where, pos, message))
                continue
            txid = tx.get("txid")
            if txid in seen_txids:
                err("%s 第 %d 笔交易重复出现（txid %s...）" % (where, pos, str(txid)[:16]))
                continue
            seen_txids.add(txid)
            try:
                ledger.apply(tx, block["height"], block["hash"])
            except LedgerError as exc:
                err("%s 第 %d 笔交易被状态机拒绝：%s" % (where, pos, exc))
            except Exception as exc:  # 状态机异常同样视为非法链
                err("%s 第 %d 笔交易处理异常：%s" % (where, pos, exc))

        prev = block

    return (len(errors) == 0), errors, ledger


class Blockchain(object):
    """一条艺术品确权链。"""

    def __init__(self, difficulty=DEFAULT_DIFFICULTY, store=None, autosave=True):
        self.difficulty = int(difficulty)
        self.blocks = []
        self.ledger = Ledger()
        self.mempool = []
        self.store = store
        self.autosave = autosave
        self.lock = threading.RLock()
        self._tx_index = {}   # txid -> (height, block_hash, index)
        # 磁盘上的区块数（None = 不确定，可能从未落盘或来源非本地存储）。
        # 出块时磁盘链恰好衔接（== 链长-1）才能走追加写，否则退回整链重写自愈。
        self._disk_blocks = None
        # 「账本 + 全部待打包交易」的预演缓存：提交新交易时不必每次 deepcopy 整个账本。
        # _probe_height 记录缓存建立时的链高，链高变化（出了块）后重建。
        self._probe = None
        self._probe_height = -1

    # ---------------------------------------------------------- 基本信息
    @property
    def ready(self):
        return len(self.blocks) > 0

    @property
    def height(self):
        return self.blocks[-1]["height"] if self.blocks else -1

    def last_block(self):
        return self.blocks[-1] if self.blocks else None

    def require_ready(self):
        if not self.ready:
            raise ChainError("区块链尚未初始化，请先执行 init 命令创建创世区块")

    def statistics(self):
        stats = self.ledger.stats()
        stats.update({
            "height": self.height,
            "blocks": len(self.blocks),
            "difficulty": self.difficulty,
            "pending_txs": len(self.mempool),
            "latest_block_hash": self.last_block()["hash"] if self.ready else "",
            "latest_block_time": self.last_block()["time"] if self.ready else 0,
            "chain_name": self.ledger.chain_meta.get("name", ""),
        })
        return stats

    # ---------------------------------------------------------- 创世
    def create_genesis(self, name="ArtChain 艺术品确权链", description="", operator="",
                       operator_address="", max_supply=None, timestamp=None):
        """创建创世区块。

        operator_address 是积分发行权（MINT/BURN）的归属地址，写进创世交易
        即成为链规则；留空表示旧链兼容模式（铸造不受限，务必仅在演示环境使用）。
        max_supply 是积分总量上限（整数最小单位，None = 不限）。
        """
        ts = int(timestamp if timestamp is not None else time.time())
        genesis_tx = make_tx(TX_GENESIS, "SYSTEM", "", {
            "name": name,
            "description": description,
            "operator": operator,
            "operator_address": operator_address or "",
            "max_supply": max_supply,
        }, timestamp=ts)
        genesis_tx["txid"] = compute_txid(genesis_tx)
        block = make_block(0, GENESIS_PREV_HASH, [genesis_tx], miner=operator or "SYSTEM",
                           difficulty=self.difficulty, timestamp=ts)
        mine_block(block)
        self.blocks = [block]
        self.ledger = Ledger()
        self.ledger.apply(genesis_tx, 0, block["hash"])
        self.mempool = []
        self._reindex()
        self._invalidate_probe()
        return block

    # ---------------------------------------------------------- 交易池
    def _reindex(self):
        self._tx_index = {}
        for block in self.blocks:
            self._index_block(block)

    def _index_block(self, block):
        for pos, tx in enumerate(block["txs"]):
            self._tx_index[tx.get("txid")] = (block["height"], block["hash"], pos)

    def _invalidate_probe(self):
        self._probe = None
        self._probe_height = -1

    def _get_probe(self, height):
        """返回「当前账本 + 全部待打包交易」的预演账本（按需重建，链高变化即失效）。

        正常提交路径进来的交易都已通过预演，重建时不会失败；若落盘数据不一致
        导致某笔池中交易无法应用，直接把它丢掉——它反正永远无法被打包。
        """
        if self._probe is None or self._probe_height != height:
            probe = self.ledger.copy()
            kept = []
            for pending in self.mempool:
                try:
                    probe.apply(pending, height, "mempool-preview")
                    kept.append(pending)
                except LedgerError:
                    continue
            self.mempool = kept
            self._probe = probe
            self._probe_height = height
        return self._probe

    def has_tx(self, txid):
        return txid in self._tx_index

    def find_tx(self, txid):
        """按 txid 查找交易，返回 (区块, 交易, 区块内下标)。"""
        found = self._tx_index.get(txid)
        if not found:
            return None, None, None
        height, _block_hash, pos = found
        block = self.blocks[height]
        return block, block["txs"][pos], pos

    def pending(self):
        return list(self.mempool)

    def submit(self, tx, verify=True):
        """提交交易到待打包池。返回 (是否接受, 说明)。"""
        with self.lock:
            self.require_ready()
            if verify:
                ok, message = verify_tx(tx)
                if not ok:
                    return False, "交易校验失败：%s" % message
            txid = tx.get("txid")
            if self.has_tx(txid):
                return False, "该交易已经在链上（txid %s...）" % txid[:16]
            for pending in self.mempool:
                if pending.get("txid") == txid:
                    return False, "该交易已在待打包池中"
            if len(self.mempool) >= MAX_TXS_PER_BLOCK:
                return False, "待打包池已满，请先挖矿出块"

            # 在预演账本上试应用，确保业务规则能通过（真正的判定在出块与校验时再做一次）。
            # 预演账本缓存了「账本 + 已排队交易」，提交多笔交易时不必反复 deepcopy；
            # 前提是 Ledger.apply 在校验失败时不留下半截状态（见 core/state.py），
            # 若仍有意外异常，宁可丢掉缓存下次重建，也不能带着坏状态继续用。
            height = self.height + 1
            probe = self._get_probe(height)
            try:
                probe.apply(tx, height, "mempool-preview")
            except LedgerError as exc:
                return False, str(exc)
            except Exception as exc:
                self._invalidate_probe()
                return False, "交易预演失败：%s" % exc

            self.mempool.append(tx)
            # 提交只动交易池：链文件一个字节都不用重写（旧版这里会整链落盘，
            # 链越长每笔提交越慢——现在提交成本与链长完全无关）。
            if self.autosave and self.store:
                self.store.save_mempool(self.mempool)
            return True, "已进入待打包池"

    # ---------------------------------------------------------- 挖矿出块
    def mine(self, miner="", timestamp=None, max_seconds=None, progress=None):
        """把待打包池中的交易打包成新区块并完成工作量证明。"""
        with self.lock:
            self.require_ready()
            height = self.height + 1
            txs = list(self.mempool)[:MAX_TXS_PER_BLOCK]
            block = make_block(height, self.last_block()["hash"], txs, miner,
                               self.difficulty, timestamp=timestamp)
            mine_block(block, max_seconds=max_seconds, progress=progress)

            # 先在副本上推进状态，全部成功后一次性提交，保证不会出现"出块成功但状态半截"
            probe = self.ledger.copy()
            for tx in txs:
                probe.apply(tx, height, block["hash"])

            self.blocks.append(block)
            self.ledger = probe
            self.mempool = self.mempool[len(txs):]
            # 新块只往索引里追加，不必重建整张表；预演缓存随链高变化而失效（惰性重建）。
            self._index_block(block)
            if self.autosave and self.store:
                self._save_block(block)
            return block

    def _save_block(self, block):
        """落盘一个新出区块。

        磁盘链恰好衔接（本块之前的都在盘上）时走追加写，成本与链长无关；
        磁盘状态不确定（从未落盘、from_dict 加载、或外部改过文件）时，
        退回整链重写自愈——宁可慢一次，也不能追加出一条断链文件。
        """
        if self._disk_blocks == len(self.blocks) - 1:
            self.store.append_block(block)
            self.store.save_mempool(self.mempool)
            self._disk_blocks = len(self.blocks)
        else:
            self._save()

    # ---------------------------------------------------------- 校验与同步
    def verify(self):
        """全链重新校验，返回 (是否合法, 错误列表)。"""
        ok, errors, ledger = validate_blocks(self.blocks, self.difficulty)
        if ok:
            self.ledger = ledger
            self._reindex()
            self._invalidate_probe()
        return ok, errors

    def replace_chain(self, blocks):
        """用对端更长的链替换本地链（最长链共识）。返回 (是否替换, 说明)。"""
        with self.lock:
            if not isinstance(blocks, list) or not blocks:
                return False, "对端链数据为空"
            if len(blocks) <= len(self.blocks):
                return False, "对端链并不更长（本地 %d 块，对端 %d 块）" % (
                    len(self.blocks), len(blocks))
            ok, errors, ledger = validate_blocks(blocks, self.difficulty)
            if not ok:
                return False, "对端链未通过校验：" + "；".join(errors[:3])
            self.blocks = blocks
            self.ledger = ledger
            self._reindex()
            self._invalidate_probe()
            # 清理已上链或已失效的待打包交易：同一个预演账本上顺序试应用，
            # 应用失败的直接丢弃（旧版每笔交易都要复制一次整个账本，
            # 大交易池同步一次是 O(n²) 的复制量）。
            survivors = []
            probe = self.ledger.copy()
            next_height = self.height + 1
            for tx in self.mempool:
                if self.has_tx(tx.get("txid")):
                    continue
                try:
                    probe.apply(tx, next_height, "sync-preview")
                except Exception:
                    continue
                survivors.append(tx)
            self.mempool = survivors
            if self.autosave and self.store:
                self._save()
            return True, "已切换至对端链，当前高度 %d" % self.height

    # ---------------------------------------------------------- 确权证明
    def proof_of(self, work_id):
        """为某件作品生成"上链存在性证明"（供确权证书使用）。"""
        work = self.ledger.get_work(work_id)
        if work is None:
            return None
        block, tx, pos = self.find_tx(work.get("txid"))
        if block is None:
            return None
        proof = merkle_proof([t["txid"] for t in block["txs"]], pos)
        return {
            "work_id": work_id,
            "txid": tx["txid"],
            "height": block["height"],
            "block_hash": block["hash"],
            "block_time": block["time"],
            "merkle_root": block["merkle_root"],
            "merkle_proof": proof,
            "tx_index": pos,
            "tx_count": len(block["txs"]),
        }

    @staticmethod
    def check_proof(proof):
        """离线验证一份存在性证明是否自洽。"""
        return verify_merkle_proof(proof.get("txid"), proof.get("merkle_proof") or [],
                                   proof.get("merkle_root"))

    # ---------------------------------------------------------- 序列化
    def to_dict(self):
        return {
            "format": "artchain",
            "format_version": CHAIN_FORMAT_VERSION,
            "difficulty": self.difficulty,
            "blocks": self.blocks,
        }

    def from_dict(self, payload, verify=True):
        if not isinstance(payload, dict) or payload.get("format") != "artchain":
            raise ChainError("链数据格式不正确（缺少 artchain 标识）")
        blocks = payload.get("blocks")
        # 链文件里记录的难度才是权威值：建链时可能用 --difficulty 指定过非默认难度，
        # 若这里沿用默认值做校验，整条链会被误判为非法而无法加载。
        stored = payload.get("difficulty")
        if stored is not None:
            try:
                self.difficulty = int(stored)
            except (TypeError, ValueError):
                raise ChainError("链数据里的难度值非法：%r" % (stored,))
        if verify:
            ok, errors, ledger = validate_blocks(blocks, self.difficulty)
            if not ok:
                raise ChainError("链数据校验失败：" + "；".join(errors[:5]))
            self.ledger = ledger
        self.blocks = list(blocks or [])
        self._reindex()
        self._invalidate_probe()
        # from_dict 只是把数据装进内存，磁盘上有没有这条链、衔接到哪个高度，
        # 这里并不知道（sync 接口就是这么用的：拉远端链进来，本地不落盘）。
        # 保持 None，让下一次出块走整链重写，直到某次 save() 把计数对齐。
        self._disk_blocks = None
        return self

    def _save(self):
        if not self.store:
            return
        self.store.save_chain(self.to_dict())
        self.store.save_mempool(self.mempool)
        self._disk_blocks = len(self.blocks)

    def load(self, verify=True):
        if not self.store or not self.store.has_chain():
            return False
        payload = self.store.load_chain()
        self.from_dict(payload, verify=verify)
        self.mempool = self.store.load_mempool() or []
        # 丢掉池中已经上链的交易
        self.mempool = [tx for tx in self.mempool if not self.has_tx(tx.get("txid"))]
        # load 刚从磁盘读回整条链，内存与磁盘此刻严格一致。
        self._disk_blocks = len(self.blocks)
        return True

    def save(self):
        with self.lock:
            self._save()
