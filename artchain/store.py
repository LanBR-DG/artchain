# -*- coding: utf-8 -*-
"""本地存储层：链数据、交易池、钱包、链下作品原件的读写。

目录结构（默认在项目根目录下的 data/）：
    data/
      blocks.ndjson     区块链主数据（追加式日志：一行一个区块，出块只追加不重写）
      chain_meta.json   链元信息（格式标识、难度）
      chain.json        旧版整链文件（只作迁移来源，读入后改名为 chain.json.bak 留档）
      mempool.json      待打包交易池
      config.json       链配置（难度、节点信息等）
      peers.json        已知的其他节点
      wallets/*.json    加密钱包（私钥经 ChaCha20 加密 + HMAC 认证）
      files/<sha>.<ext> 链下保存的作品原件（链上只存指纹）

所有整文件写操作都采用"写临时文件 + 原子替换"，避免断电或并发导致文件半截；
跨进程写入用一把基于文件的排它锁串行化（读链数据也短暂持锁，
避免与并发追加写出半行日志）。出块路径只往 blocks.ndjson 末尾追加一行，
写入成本与链长无关——整链重写只发生在建链、换链与旧格式迁移时。
"""

import errno
import json
import os
import shutil
import time

CHAIN_FILE = "chain.json"
BLOCKS_FILE = "blocks.ndjson"
META_FILE = "chain_meta.json"
MEMPOOL_FILE = "mempool.json"
CONFIG_FILE = "config.json"
PEERS_FILE = "peers.json"
CONSENTS_FILE = "consents.json"
PURCHASE_ORDERS_FILE = "purchase_orders.json"

_LOCK_STALE_SECONDS = 60
_LOCK_TIMEOUT_SECONDS = 15


class StoreError(Exception):
    pass


def default_data_dir():
    """默认数据目录：环境变量 ARTCHAIN_DATA > 项目根目录下的 data/。"""
    env = os.environ.get("ARTCHAIN_DATA")
    if env:
        return os.path.abspath(env)
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    return os.path.join(root, "data")


class _FileLock(object):
    """基于排它创建锁文件的简易跨进程锁。"""

    def __init__(self, path, timeout=_LOCK_TIMEOUT_SECONDS):
        self.path = path
        self.timeout = timeout
        self.acquired = False

    def __enter__(self):
        deadline = time.time() + self.timeout
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode("ascii"))
                os.close(fd)
                self.acquired = True
                return self
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                # 陈旧锁自动回收（持锁进程可能已崩溃）
                try:
                    if time.time() - os.path.getmtime(self.path) > _LOCK_STALE_SECONDS:
                        os.remove(self.path)
                        continue
                except OSError:
                    continue
                if time.time() > deadline:
                    raise StoreError("获取数据目录锁超时：%s（可能有另一个进程正在写入）" % self.path)
                time.sleep(0.05)

    def __exit__(self, exc_type, exc, tb):
        if self.acquired:
            try:
                os.remove(self.path)
            except OSError:
                pass
            self.acquired = False
        return False


class Store(object):
    """数据目录的读写封装。"""

    def __init__(self, root=None):
        self.root = os.path.abspath(root or default_data_dir())
        self.chain_path = os.path.join(self.root, CHAIN_FILE)
        self.blocks_path = os.path.join(self.root, BLOCKS_FILE)
        self.meta_path = os.path.join(self.root, META_FILE)
        self.mempool_path = os.path.join(self.root, MEMPOOL_FILE)
        self.config_path = os.path.join(self.root, CONFIG_FILE)
        self.peers_path = os.path.join(self.root, PEERS_FILE)
        self.consents_path = os.path.join(self.root, CONSENTS_FILE)
        self.purchase_orders_path = os.path.join(self.root, PURCHASE_ORDERS_FILE)
        self.wallets_dir = os.path.join(self.root, "wallets")
        self.files_dir = os.path.join(self.root, "files")
        self.lock_path = os.path.join(self.root, ".lock")

    # ---------------------------------------------------------- 基础设施
    def ensure_dirs(self):
        for path in (self.root, self.wallets_dir, self.files_dir):
            if not os.path.isdir(path):
                os.makedirs(path)
        return self

    def lock(self, timeout=_LOCK_TIMEOUT_SECONDS):
        self.ensure_dirs()
        return _FileLock(self.lock_path, timeout=timeout)

    @staticmethod
    def _write_json(path, payload):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    @staticmethod
    def _read_json(path, default=None):
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    # ---------------------------------------------------------- 链数据
    def has_chain(self):
        return os.path.exists(self.blocks_path) or os.path.exists(self.chain_path)

    def save_chain(self, payload):
        """整链落盘（建链 / 换链 / 迁移时用）。出块路径请走 append_block。"""
        self.ensure_dirs()
        blocks = payload.get("blocks") if isinstance(payload, dict) else None
        if not isinstance(blocks, list):
            raise StoreError("链数据缺少 blocks 列表")
        with self.lock():
            self._write_json(self.meta_path, {
                "format": payload.get("format", "artchain"),
                "format_version": payload.get("format_version", 1),
                "difficulty": payload.get("difficulty"),
            })
            tmp = self.blocks_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                for block in blocks:
                    fh.write(json.dumps(block, ensure_ascii=False, separators=(",", ":")))
                    fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.blocks_path)

    def append_block(self, block):
        """往区块日志末尾追加一个区块（出块热路径：成本与链长无关）。"""
        self.ensure_dirs()
        payload = json.dumps(block, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        with self.lock():
            with open(self.blocks_path, "r+b") as fh:
                fh.seek(0, os.SEEK_END)
                if fh.tell() > 0:
                    fh.seek(-1, os.SEEK_END)
                    if fh.read(1) != b"\n":
                        # 兜底：日志末尾缺换行（正常流程不会发生，防手工编辑过的文件）
                        fh.write(b"\n")
                fh.seek(0, os.SEEK_END)
                fh.write(payload)
                fh.write(b"\n")
                fh.flush()
                os.fsync(fh.fileno())

    @staticmethod
    def _truncate_blocks_log(path, size):
        with open(path, "r+b") as fh:
            fh.truncate(size)
            fh.flush()
            os.fsync(fh.fileno())

    def _load_blocks_log(self):
        """读区块日志为区块列表，并修复"写了一半的尾巴"（预写日志语义）。

        追加写在 fsync 前崩溃只会损坏最后一行：整块没写完 => 回退到上一个
        完整块（配套的 mempool.json 会把其中的交易重新待打包，账不丢）；
        写完了只缺换行 => 补换行。中间任何一行损坏都不是崩溃能造成的，
        必须报错，不能悄悄丢块。
        """
        with open(self.blocks_path, "rb") as fh:
            raw = fh.read()
        blocks = []
        offset = 0
        while offset < len(raw):
            nl = raw.find(b"\n", offset)
            if nl == -1:
                # 文件不以换行结尾：最后一段是"没有换行符的尾巴"
                tail = raw[offset:]
                if not tail.strip():
                    break
                try:
                    blocks.append(json.loads(tail.decode("utf-8")))
                    with open(self.blocks_path, "ab") as fh:  # 补上换行，后续追加才不粘连
                        fh.write(b"\n")
                        fh.flush()
                        os.fsync(fh.fileno())
                except (ValueError, UnicodeDecodeError):
                    self._truncate_blocks_log(self.blocks_path, offset)
                break
            line = raw[offset:nl]
            try:
                if line.strip():
                    blocks.append(json.loads(line.decode("utf-8")))
            except (ValueError, UnicodeDecodeError):
                if not raw[nl + 1:].strip():
                    self._truncate_blocks_log(self.blocks_path, offset)
                    break
                raise StoreError("区块日志中间存在损坏行（偏移 %d），这不再是崩溃残留，"
                                 "请检查磁盘或从备份恢复" % offset)
            offset = nl + 1
        return blocks

    def load_chain(self):
        """读整链。优先读追加式日志；旧版 chain.json 读入后一次性迁移并留档。"""
        if os.path.exists(self.blocks_path):
            with self.lock():
                blocks = self._load_blocks_log()
            meta = self._read_json(self.meta_path, {}) or {}
            return {
                "format": "artchain",
                "format_version": meta.get("format_version", 1),
                "difficulty": meta.get("difficulty"),
                "blocks": blocks,
            }
        if os.path.exists(self.chain_path):
            # 旧版整链文件：读入 -> 改写成新格式 -> 原文件改名 .bak 留档。
            # 迁移失败不会动旧文件，随时可以重试。
            payload = self._read_json(self.chain_path)
            if payload is None:
                raise StoreError("未找到链数据文件：%s" % self.chain_path)
            if not isinstance(payload, dict) or not isinstance(payload.get("blocks"), list):
                raise StoreError("链数据文件损坏：%s" % self.chain_path)
            self.save_chain(payload)
            os.replace(self.chain_path, self.chain_path + ".bak")
            return self.load_chain()
        raise StoreError("未找到链数据文件：%s" % self.blocks_path)

    def save_mempool(self, txs):
        self.ensure_dirs()
        with self.lock():
            self._write_json(self.mempool_path, list(txs))

    def load_mempool(self):
        return self._read_json(self.mempool_path, []) or []

    # ---------------------------------------------------------- 配置与节点
    def load_config(self):
        return self._read_json(self.config_path, {}) or {}

    def save_config(self, config):
        self.ensure_dirs()
        with self.lock():
            self._write_json(self.config_path, config)

    # ---------------------------------------------------------- 协议同意留痕
    def load_consents(self):
        payload = self._read_json(self.consents_path, {}) or {}
        return payload.get("records", []) if isinstance(payload, dict) else []

    def latest_consent(self, wallet):
        for record in reversed(self.load_consents()):
            if record.get("wallet") == wallet:
                return record
        return None

    def record_consent(self, wallet, versions, timestamp=None):
        """追加一条协议同意记录（含文档版本与服务端时间，可作告知同意的证据）。"""
        self.ensure_dirs()
        with self.lock():
            records = self.load_consents()
            records.append({
                "wallet": wallet,
                "time": int(timestamp if timestamp is not None else time.time()),
                "versions": dict(versions or {}),
            })
            self._write_json(self.consents_path, {"records": records})
        return records[-1]

    def load_peers(self):
        return self._read_json(self.peers_path, []) or []

    def save_peers(self, peers):
        self.ensure_dirs()
        with self.lock():
            self._write_json(self.peers_path, list(peers))

    def add_peer(self, url):
        peers = self.load_peers()
        if url not in peers:
            peers.append(url)
            self.save_peers(peers)
        return peers

    # ---------------------------------------------------------- 积分购买订单
    def load_purchase_orders(self):
        """读购买订单。货币化支付对应交易记录，落盘就当流水台账。"""
        payload = self._read_json(self.purchase_orders_path, {}) or {}
        return payload.get("orders", []) if isinstance(payload, dict) else []

    def save_purchase_orders(self, orders):
        self.ensure_dirs()
        with self.lock():
            self._write_json(self.purchase_orders_path, {"orders": list(orders)})

    def append_purchase_order(self, order):
        """追加订单；用读改写原子提交，重试处理同名创建。"""
        self.ensure_dirs()
        with self.lock():
            orders = self.load_purchase_orders()
            order_id = order["id"]
            existing = next((o for o in orders if o["id"] == order_id), None)
            if existing:
                # 创建调用里同一 id 重复时（防御）：覆盖到现有订单。
                existing.update(order)
                self._write_json(self.purchase_orders_path, {"orders": orders})
                return existing
            orders.append(order)
            self._write_json(self.purchase_orders_path, {"orders": orders})
        return order

    def update_purchase_order(self, order_id, **patch):
        self.ensure_dirs()
        with self.lock():
            orders = self.load_purchase_orders()
            hit = next((o for o in orders if o["id"] == order_id), None)
            if hit is None:
                raise StoreError("订单不存在：%s" % order_id)
            hit.update(patch)
            self._write_json(self.purchase_orders_path, {"orders": orders})
        return hit

    # ---------------------------------------------------------- 钱包
    def wallet_path(self, name):
        return os.path.join(self.wallets_dir, "%s.json" % name)

    def save_wallet(self, name, payload):
        self.ensure_dirs()
        self._write_json(self.wallet_path(name), payload)

    def load_wallet(self, name):
        path = self.wallet_path(name)
        if not os.path.exists(path):
            raise StoreError("钱包不存在：%s" % name)
        return self._read_json(path)

    def list_wallets(self):
        if not os.path.isdir(self.wallets_dir):
            return []
        names = []
        for entry in sorted(os.listdir(self.wallets_dir)):
            if entry.endswith(".json"):
                names.append(entry[:-5])
        return names

    def delete_wallet(self, name):
        path = self.wallet_path(name)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    # ---------------------------------------------------------- 作品原件
    def save_blob(self, data, sha256_hex, suffix=""):
        """把作品原件保存到链下，返回相对路径。"""
        self.ensure_dirs()
        if suffix and not suffix.startswith("."):
            suffix = "." + suffix
        filename = "%s%s" % (sha256_hex, suffix)
        path = os.path.join(self.files_dir, filename)
        if not os.path.exists(path):
            tmp = path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        return os.path.join("files", filename)

    def blob_abspath(self, relative_path):
        """把链下相对路径解析成绝对路径，并确认它没有跑到 data/ 之外。

        stored_path 直接来自交易数据（state.py 的 data.get("stored_path")），
        是不可信输入：恶意方可以签一笔 stored_path = "../../Windows/win.ini"
        的交易，同步进本地链之后再让 /api/blob 把它读出来。
        这里做包含性兜底——返回 None 会让调用方按"没有原件"处理（404）。

        写入侧的规则定在链上（core/state.py 的 valid_stored_path），两侧都校验是刻意的：
        读取侧要能挡住已经在链上的历史坏数据——它们可能来自同步，从没经过本机写入。
        """
        if not relative_path:
            return None
        if os.path.isabs(relative_path):
            return None
        root = os.path.realpath(self.root)
        candidate = os.path.realpath(os.path.join(root, relative_path))
        # realpath 会解开软链接与 ..，所以比较必须在 realpath 之后做。
        if candidate != root and not candidate.startswith(root + os.sep):
            return None
        return candidate

    def blob_data(self, relative_path):
        path = self.blob_abspath(relative_path)
        if not path or not os.path.exists(path):
            return None
        with open(path, "rb") as fh:
            return fh.read()

    def storage_usage(self):
        total = 0
        count = 0
        if os.path.isdir(self.files_dir):
            for entry in os.listdir(self.files_dir):
                full = os.path.join(self.files_dir, entry)
                if os.path.isfile(full):
                    total += os.path.getsize(full)
                    count += 1
        chain_size = 0
        for path in (self.blocks_path, self.meta_path, self.chain_path):
            if os.path.exists(path):
                chain_size += os.path.getsize(path)
        return {"blob_count": count, "blob_bytes": total, "chain_bytes": chain_size}

    def reset(self, keep_wallets=True):
        """清空链数据（危险操作，供测试与演示重来使用）。"""
        removed = []
        for path in (self.blocks_path, self.meta_path, self.chain_path,
                     self.chain_path + ".bak", self.mempool_path, self.peers_path):
            if os.path.exists(path):
                os.remove(path)
                removed.append(os.path.basename(path))
        if not keep_wallets and os.path.isdir(self.wallets_dir):
            shutil.rmtree(self.wallets_dir)
            removed.append("wallets/")
        return removed
