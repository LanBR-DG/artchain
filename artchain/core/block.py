# -*- coding: utf-8 -*-
"""区块、Merkle 树与工作量证明（PoW）。

区块头字段（参与哈希）：
    version / height / prev_hash / time / merkle_root / miner / difficulty / nonce

Merkle 树把区块内所有交易压缩成一个根哈希，任何一笔交易被改动都会导致
根哈希变化；同时可为单笔交易生成 O(log n) 大小的**存在性证明**，
确权证书里就带着这份证明，脱离本系统也能独立验证。
"""

import hashlib
import json
import time

BLOCK_VERSION = 1
GENESIS_PREV_HASH = "0" * 64


def hash_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _hash_pair(left_hex, right_hex):
    return hashlib.sha256(bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()


# ------------------------------------------------------------ Merkle 树
def merkle_root(txids):
    """由交易哈希列表计算 Merkle 根。"""
    if not txids:
        return hash_hex(b"")
    layer = list(txids)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])  # 奇数个则复制最后一个
        layer = [_hash_pair(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def merkle_proof(txids, index):
    """生成第 index 笔交易的 Merkle 存在性证明。"""
    if not txids:
        raise ValueError("区块内没有交易")
    if not 0 <= index < len(txids):
        raise IndexError("交易下标越界")
    proof = []
    layer = list(txids)
    idx = index
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        if idx % 2 == 0:
            sibling = layer[idx + 1]
            proof.append({"position": "right", "hash": sibling})
        else:
            sibling = layer[idx - 1]
            proof.append({"position": "left", "hash": sibling})
        layer = [_hash_pair(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        idx //= 2
    return proof


def verify_merkle_proof(txid, proof, root):
    """用证明验证某笔交易确实属于该 Merkle 根。"""
    current = txid
    for step in proof:
        sibling = step.get("hash")
        if not sibling:
            return False
        if step.get("position") == "left":
            current = _hash_pair(sibling, current)
        else:
            current = _hash_pair(current, sibling)
    return current == root


# ------------------------------------------------------------ 区块
def header_of(block):
    """抽取区块头（参与哈希计算的字段）。"""
    return {
        "version": block.get("version", BLOCK_VERSION),
        "height": block["height"],
        "prev_hash": block["prev_hash"],
        "time": block["time"],
        "merkle_root": block["merkle_root"],
        "miner": block.get("miner", ""),
        "difficulty": block["difficulty"],
        "nonce": block["nonce"],
    }


def block_hash(block):
    """计算区块头哈希。"""
    return hash_hex(json.dumps(header_of(block), sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def meets_difficulty(hash_hex_value, difficulty):
    """哈希值是否满足前导 difficulty 个十六进制 0 的目标。"""
    if difficulty <= 0:
        return True
    return hash_hex_value.startswith("0" * difficulty)


def _header_json_parts(block):
    """把区块头拆成「nonce 之前」「nonce 之后」两段 JSON 字节串。

    键排序后 nonce 恰好位于头部的正中间，因此其余字段在挖矿循环里完全不变，
    可以预序列化一次。字符串值必须走 json.dumps 转义，保证与 block_hash()
    的规范化输出逐字节一致（矿工与校验方不能算出两个不同的哈希）。
    """
    head = '{"difficulty":%d,"height":%d,"merkle_root":%s,"miner":%s,"nonce":' % (
        int(block["difficulty"]), int(block["height"]),
        json.dumps(block["merkle_root"], ensure_ascii=False, separators=(",", ":")),
        json.dumps(block.get("miner", ""), ensure_ascii=False, separators=(",", ":")),
    )
    tail = ',"prev_hash":%s,"time":%d,"version":%d}' % (
        json.dumps(block["prev_hash"], ensure_ascii=False, separators=(",", ":")),
        int(block["time"]), int(block.get("version", BLOCK_VERSION)),
    )
    return head.encode("utf-8"), tail.encode("utf-8")


def _header_hash_with_parts(head, tail, nonce):
    """用预序列化的区块头片段计算区块头哈希（与 block_hash 逐字节等价）。"""
    return hashlib.sha256(head + str(nonce).encode("ascii") + tail).hexdigest()


def make_block(height, prev_hash, txs, miner, difficulty, timestamp=None):
    """组装一个未挖矿的区块。"""
    block = {
        "version": BLOCK_VERSION,
        "height": height,
        "prev_hash": prev_hash,
        "time": int(timestamp if timestamp is not None else time.time()),
        "txs": list(txs),
        "merkle_root": merkle_root([t.get("txid", "") for t in txs]),
        "miner": miner or "",
        "difficulty": int(difficulty),
        "nonce": 0,
        "hash": "",
    }
    return block


def mine_block(block, max_seconds=None, progress=None):
    """就地挖矿，返回挖好的区块。

    progress: 可选的回调 progress(attempts, elapsed)，用于打印挖矿进度。

    性能要点：挖矿循环里唯一变化的是 nonce（nonce 用尽时才是时间戳），
    所以区块头除 nonce 外的部分只序列化一次，每次尝试只是一次字符串拼接
    + 一次 SHA-256。拼出来的字节串与 block_hash() 完全一致。
    """
    difficulty = int(block["difficulty"])
    target_prefix = "0" * difficulty
    head, tail = _header_json_parts(block)
    nonce = 0
    started = time.time()
    attempts = 0
    while True:
        block["nonce"] = nonce
        h = _header_hash_with_parts(head, tail, nonce)
        attempts += 1
        if h.startswith(target_prefix):
            block["hash"] = h
            return block
        nonce += 1
        if nonce > 0xFFFFFFFF:  # nonce 用尽则调整时间戳继续（时间戳变了必须重算两段）
            block["time"] += 1
            nonce = 0
            head, tail = _header_json_parts(block)
        if progress and attempts % 20000 == 0:
            progress(attempts, time.time() - started)
        if max_seconds and time.time() - started > max_seconds:
            raise TimeoutError("挖矿超时（已尝试 %d 次）" % attempts)
