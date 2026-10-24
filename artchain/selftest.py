# -*- coding: utf-8 -*-
"""内置自检：不依赖任何第三方测试框架，一条命令验证全部核心能力。

    python -m artchain selftest

覆盖范围：
    密码学      曲线点运算、曲线阶、ECDSA 签名/验签/防篡改/确定性、地址校验
    钱包加密    ChaCha20+HMAC 加解密、错误口令拦截、密文篡改拦截
    图像指纹    PNG 五种行滤波器的编解码往返、灰度正确性、感知指纹鲁棒性
    文本指纹    SimHash 对近似文本与无关文本的区分度
    默克尔/出块 Merkle 存在性证明（1-9 笔交易全覆盖）与工作量证明
    端到端流程  建链、开户、登记确权、侵权比对、转让、授权、争议、裁决、证书、离线验证、重载
    社区上链    发帖、回复、点赞、重复赞拦截、正文校验、附图哈希、帖子篡改检测、重载
    平台积分    金额换算精度、铸造/转账/销毁、发行权限、总量上限、重载

全部用例使用独立的临时数据目录，不会影响你的正式数据。
"""

import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile

from . import certificate, fingerprint as fp, imagelib, service
from .core import block as block_mod
from .core.chain import Blockchain, validate_blocks
from .core.tx import (TX_PAY, TX_POST, TX_TRANSFER, TxError, make_tx, points_to_units,
                      post_id_for, sign_tx, units_to_text)
from .crypto import bip32, bip39, chacha20, rotpwd
from .crypto import secp256k1 as ec
from .store import Store, StoreError
from .wallet import Wallet, WalletError

_STATE = {}


class Suite(object):
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.passed = 0
        self.failed = 0
        self.failures = []
        self._group = ""

    def group(self, name):
        self._group = name
        print("")
        print("  %s" % name)
        print("  " + "-" * 58)

    def case(self, name, fn):
        try:
            detail = fn()
            self.passed += 1
            line = "    [通过] %s" % name
            if detail:
                line = "    [通过] %-26s %s" % (name, detail)
            print(line)
        except AssertionError as exc:
            self.failed += 1
            self.failures.append((self._group, name, str(exc) or "断言失败"))
            print("    [失败] %-26s %s" % (name, exc or "断言失败"))
        except Exception as exc:  # noqa: BLE001 - 自检需要捕获所有异常并汇报
            self.failed += 1
            self.failures.append((self._group, name, "%s: %s" % (type(exc).__name__, exc)))
            print("    [异常] %-26s %s: %s" % (name, type(exc).__name__, exc))


# ================================================================= 公共夹具
def _gray(rgb, width, height):
    out = bytearray()
    for i in range(width * height):
        r, g, b = rgb[i * 3], rgb[i * 3 + 1], rgb[i * 3 + 2]
        out.append((r * 299 + g * 587 + b * 114) // 1000)
    return bytes(out)


def _png(width=96, height=96, variant=0, brightness=0):
    return imagelib.encode_png(width, height,
                               imagelib.make_demo_image(width, height, variant, brightness))


def _alt_png(width=96, height=96):
    """一张与示例作品风格迥异的图片（用于验证"不误判"）。"""
    return imagelib.encode_png(width, height, imagelib.make_alt_image(width, height))


def _fixture():
    """构建端到端测试环境（只建一次）。"""
    if _STATE.get("ready"):
        return _STATE
    tmp = tempfile.mkdtemp(prefix="artchain-selftest-")
    store = Store(tmp).ensure_dirs()
    chain = Blockchain(difficulty=3, store=store)
    chain.create_genesis(name="自检链", operator="自检程序")
    alice = Wallet.create(store, "alice", password="pw-alice")
    bob = Wallet.create(store, "bob", password="pw-bob")
    # carol 既不是权利人也不是异议人，专门用来验证"裁决须由无关第三方作出"。
    carol = Wallet.create(store, "carol", password="pw-carol")
    # operator 是积分测试里的「平台运营方」钱包（只用于测试链）。
    op = Wallet.create(store, "operator", password="pw-op")
    _STATE.update({"ready": True, "tmp": tmp, "store": store, "chain": chain,
                   "alice": alice, "bob": bob, "carol": carol, "op": op, "work_id": None})
    return _STATE


def _cleanup():
    tmp = _STATE.get("tmp")
    if tmp and os.path.isdir(tmp):
        shutil.rmtree(tmp, ignore_errors=True)
    for extra in _STATE.get("extra_tmps", []):
        if os.path.isdir(extra):
            shutil.rmtree(extra, ignore_errors=True)


def _points_chain(max_supply=None):
    """为积分测试单开一条「带运营方地址」的链（与主 fixture 隔离）。"""
    tmp = tempfile.mkdtemp(prefix="artchain-points-")
    _STATE.setdefault("extra_tmps", []).append(tmp)
    store = Store(tmp).ensure_dirs()
    chain = Blockchain(difficulty=1, store=store)
    chain.create_genesis(name="积分测试链", operator="平台运营方",
                         operator_address=_STATE["op"].address,
                         max_supply=max_supply)
    return store, chain


# ================================================================= 密码学
def t_curve_base():
    assert ec.is_on_curve(ec.G), "基点不在曲线上"
    assert ec.point_mul(1) == ec.G, "1*G 应等于基点"
    pub = ec.pubkey_from_private(1)
    assert pub.hex() == "02" + "%064x" % ec.GX, "私钥 1 的压缩公钥应为 02||Gx"
    assert ec.point_add(ec.G, ec.G) == ec.point_double(ec.G), "G+G 应等于 2G"
    return "1*G = 基点，公钥推导正确"


def t_curve_order():
    assert ec.point_mul(ec.N) is None, "n*G 应为无穷远点"
    neg = ec.point_mul(ec.N - 1)
    assert neg == (ec.GX, (ec.P - ec.GY) % ec.P), "(n-1)*G 应等于 -G"
    assert ec.point_add(ec.G, neg) is None, "G + (-G) 应为无穷远点"
    return "n*G = 无穷远点，(n-1)*G = -G"


def t_sign_verify():
    d = ec.generate_private_key()
    pub = ec.pubkey_from_private(d)
    msg = "《晨》布面油画 2024".encode("utf-8")
    sig = ec.sign(d, msg)
    assert len(sig) == 128, "签名应为 128 位十六进制"
    assert ec.verify(pub, msg, sig), "合法签名应验证通过"
    assert not ec.verify(pub, msg + b"!", sig), "被改动的消息不应通过验证"
    tampered = ("0" if sig[0] != "0" else "1") + sig[1:]
    assert not ec.verify(pub, msg, tampered), "被改动的签名不应通过验证"
    other = ec.pubkey_from_private(ec.generate_private_key())
    assert not ec.verify(other, msg, sig), "他人公钥不应通过验证"
    assert ec.sign(d, msg) == sig, "RFC6979 应产生确定性签名"
    s = int(sig[64:], 16)
    assert s <= ec.N // 2, "签名应做 low-S 规范化"
    return "签名/验签/防篡改/确定性/low-S"


def t_address():
    d1 = ec.generate_private_key()
    d2 = ec.generate_private_key()
    a1 = ec.pubkey_to_address(ec.pubkey_from_private(d1))
    a2 = ec.pubkey_to_address(ec.pubkey_from_private(d2))
    assert a1 != a2, "不同私钥不应产生相同地址"
    assert ec.is_valid_address(a1), "生成的地址应通过校验"
    assert len(ec.address_payload(a1)) == 20, "地址载荷应为 20 字节"
    bad = a1[:-1] + ("1" if a1[-1] != "1" else "2")
    assert not ec.is_valid_address(bad), "被篡改的地址应校验失败"
    assert not ec.is_valid_address(""), "空地址应校验失败"
    return "地址生成/校验和/防篡改"


def t_wallet_crypto():
    secret = b"0123456789abcdef-private-key-material"
    env = chacha20.encrypt("正确口令", secret, iterations=1000)
    assert chacha20.decrypt("正确口令", env) == secret, "加解密往返应一致"
    for wrong in ("错误口令", ""):
        try:
            chacha20.decrypt(wrong, env)
            raise AssertionError("错误口令不应解密成功")
        except ValueError:
            pass
    broken = dict(env)
    ct = broken["ct"]
    broken["ct"] = ("0" if ct[0] != "0" else "1") + ct[1:]
    try:
        chacha20.decrypt("正确口令", broken)
        raise AssertionError("被篡改的密文不应解密成功")
    except ValueError:
        pass
    return "ChaCha20+HMAC 加解密/防错口令/防篡改"


# ================================================================= 图像指纹
def t_png_filters():
    w, h = 24, 16
    rgb = imagelib.make_demo_image(w, h, variant=1)
    expect = _gray(rgb, w, h)
    for ftype in range(5):
        data = imagelib.encode_png(w, h, rgb, filter_type=ftype)
        dw, dh, gray = imagelib.png_to_gray(data)
        assert (dw, dh) == (w, h), "滤波器 %d 解出的尺寸不正确" % ftype
        assert len(gray) == w * h, "滤波器 %d 解出的像素数不正确" % ftype
        for i in range(0, len(gray), 23):
            assert gray[i] == expect[i], "滤波器 %d 第 %d 个像素不一致（%d != %d）" % (
                ftype, i, gray[i], expect[i])
    return "5 种行滤波器编解码往返一致"


def t_png_scanline():
    """构造带明显水平/垂直梯度的图，确保 Sub/Up/Average/Paeth 分支确实被走到。"""
    w, h = 17, 9  # 奇数宽度也能正确处理末行补齐
    rgb = bytearray()
    for y in range(h):
        for x in range(w):
            rgb.append((x * 13 + y * 7) % 256)
            rgb.append((x * 5 + y * 29) % 256)
            rgb.append((x * 3 + y * 11) % 256)
    rgb = bytes(rgb)
    expect = _gray(rgb, w, h)
    for ftype in range(5):
        gray = imagelib.png_to_gray(imagelib.encode_png(w, h, rgb, filter_type=ftype))[2]
        assert gray == expect, "滤波器 %d 在奇数宽度梯度图上还原失败" % ftype
    return "奇数宽度与梯度图全部还原一致"


def t_phash_robust():
    w = h = 96
    g1 = _gray(imagelib.make_demo_image(w, h, variant=0), w, h)
    g2 = _gray(imagelib.make_demo_image(w, h, variant=0, brightness=12), w, h)
    p1 = imagelib.phash_bits(g1, w, h)
    p2 = imagelib.phash_bits(g2, w, h)
    dist = bin(p1 ^ p2).count("1")
    assert dist <= 8, "整图调亮 12 级后 pHash 距离应很小，实际 %d" % dist
    assert imagelib.resize_gray(bytes([10, 20, 30, 40]), 2, 2, 1, 1) == [25.0], "缩放实现不正确"
    a1 = imagelib.ahash_bits(g1, w, h)
    d1 = imagelib.dhash_bits(g1, w, h)
    assert imagelib.ahash_bits(g1, w, h) == a1 and imagelib.dhash_bits(g1, w, h) == d1, \
        "同一输入的感知哈希应稳定"
    return "调亮 12 级后 pHash 距离 = %d" % dist


def t_fingerprint_similarity():
    fa = fp.fingerprint_bytes(_png(variant=0), "晨.png")
    fb = fp.fingerprint_bytes(_png(variant=0, brightness=12), "晨-转载.png")
    fc = fp.fingerprint_bytes(_alt_png(), "另一幅.png")
    assert fa["kind"] == "image" and fa["phash"], "PNG 应被识别为图像并算出感知指纹"
    assert fa["sha256"] != fb["sha256"], "调亮后的文件字节指纹应当不同"
    sim_same = fp.similarity(fa, fb)
    sim_diff = fp.similarity(fa, fc)
    assert sim_same["score"] >= 0.85, "同一作品的微改版本相似度应 >= 0.85，实际 %.3f" % sim_same["score"]
    assert not sim_same["exact"], "微改版本不应被判为字节级相同"
    assert sim_diff["score"] < 0.85, "不同作品的相似度应 < 0.85，实际 %.3f" % sim_diff["score"]
    exactly = fp.similarity(fa, fp.fingerprint_bytes(_png(variant=0), "同一文件.png"))
    assert exactly["exact"] and exactly["score"] == 1.0, "相同文件应判为完全一致"
    return "微改 %.3f / 不同作品 %.3f" % (sim_same["score"], sim_diff["score"])


def t_text_fingerprint():
    base = "《晨》系作者于二〇二四年春在珠江口写生完成的布面油画，尺寸一百二十乘九十厘米。" * 12
    near = base.replace("珠江口", "珠江入海口").replace("一百二十", "一二〇")
    far = "本文件记录了无人机频谱监测设备的验收测试数据，包含信道功率与天线增益。" * 12
    h1 = fp.simhash_text(base)
    assert h1, "文本应算出 SimHash"
    d_near = fp.hamming_distance(h1, fp.simhash_text(near))
    d_far = fp.hamming_distance(h1, fp.simhash_text(far))
    assert d_near < d_far, "近似文本的距离(%s)应小于无关文本(%s)" % (d_near, d_far)
    assert d_near <= 12, "少量改动后 SimHash 距离应较小，实际 %s" % d_near
    assert fp.fingerprint_bytes(base.encode("utf-8"), "作品说明.txt")["kind"] == "text", \
        "文本文件应被识别为文本作品"
    return "近似文本距离 %s / 无关文本距离 %s" % (d_near, d_far)


# ================================================================= Merkle 与 PoW
def t_merkle():
    for n in range(1, 10):
        txids = [hashlib.sha256(("tx-%d-%d" % (n, i)).encode()).hexdigest() for i in range(n)]
        root = block_mod.merkle_root(txids)
        assert len(root) == 64
        for i in range(n):
            proof = block_mod.merkle_proof(txids, i)
            assert block_mod.verify_merkle_proof(txids[i], proof, root), \
                "n=%d 第 %d 笔的 Merkle 证明验证失败" % (n, i)
            bad = ("0" if txids[i][0] != "0" else "1") + txids[i][1:]
            assert not block_mod.verify_merkle_proof(bad, proof, root), \
                "被篡改的交易不应通过 Merkle 证明"
        assert block_mod.merkle_root(txids[:1]) == txids[0], "单笔交易的根应等于其哈希"
    return "1-9 笔交易的存在性证明全部可验证"


def t_pow():
    blk = block_mod.make_block(1, "0" * 64, [], "TEST", 3, timestamp=1700000000)
    block_mod.mine_block(blk, max_seconds=60)
    assert blk["hash"].startswith("000"), "区块哈希应满足难度 3"
    assert block_mod.block_hash(blk) == blk["hash"], "区块头哈希应可复算"
    blk["nonce"] += 1
    assert block_mod.block_hash(blk) != blk["hash"], "改动 nonce 后哈希应变化（工作量证明被破坏）"
    assert not block_mod.meets_difficulty(blk["hash"], 64), "难度判定应正确"
    return "难度 3 挖矿成功，区块头防篡改"


# ================================================================= 端到端
def t_chain_genesis():
    fx = _fixture()
    chain = fx["chain"]
    assert chain.ready, "创世区块应已建立"
    assert chain.height == 0, "初始高度应为 0"
    assert chain.blocks[0]["prev_hash"] == "0" * 64, "创世区块的前序哈希应为全 0"
    ok, errors = chain.verify()
    assert ok, "创世链应通过校验：%s" % errors[:3]
    return "创世区块建立并通过校验"


def t_wallet_persist():
    fx = _fixture()
    store, alice = fx["store"], fx["alice"]
    again = Wallet.load(store, "alice", "pw-alice")
    assert again.address == alice.address, "重新加载的钱包地址应一致"
    try:
        Wallet.load(store, "alice", "错误口令")
        raise AssertionError("错误口令不应解锁钱包")
    except WalletError:
        pass
    payload = store.load_wallet("alice")
    assert payload.get("crypto"), "钱包私钥应以密文形式保存"
    assert "private_key" not in payload, "加密钱包文件中不应出现明文私钥"
    assert alice.sign(b"hello") == again.sign(b"hello"), "同一私钥的签名应一致"
    return "钱包加密落盘/口令校验/签名一致"


def t_register_work():
    fx = _fixture()
    res = service.register_work(
        fx["chain"], fx["store"], fx["alice"], _png(variant=0), filename="晨.png",
        title="晨", category="美术作品", author="张三", year=2024, created_at="2024-03-18",
        description="布面油画")
    assert res["mined"], "登记后应已挖矿上链"
    assert res["work_id"].startswith("WK"), "作品编号应以 WK 开头"
    work = fx["chain"].ledger.get_work(res["work_id"])
    assert work is not None, "作品应写入账本"
    assert work["owner"] == fx["alice"].address, "权利人应为登记人"
    assert work["file_hash"] == res["fingerprint"]["sha256"], "链上应记录文件 SHA-256"
    assert work["phash"], "链上应记录感知指纹"
    assert res["stored_path"], "原件应保存到链下存储"
    fx["work_id"] = res["work_id"]
    return "《晨》已确权，区块 #%s" % res["height"]


def t_duplicate_fingerprint():
    fx = _fixture()
    try:
        service.register_work(fx["chain"], fx["store"], fx["bob"], _png(variant=0),
                              filename="晨-副本.png", title="晨（副本）")
        raise AssertionError("同一文件指纹不应被第二个权利人重复登记")
    except service.ServiceError as exc:
        assert "指纹" in str(exc), "拒绝原因应说明指纹冲突，实际：%s" % exc
    return "重复登记被拒绝并提示发起争议"


def t_compare_hit():
    fx = _fixture()
    report = service.compare_content(fx["chain"], _png(variant=0, brightness=12),
                                     filename="疑似侵权.png")
    assert report["checked"] >= 1, "应有可比对的链上作品"
    best = report["results"][0]
    assert best["id"] == fx["work_id"], "最相似作品应是《晨》"
    assert best["level"] >= 3, "调亮后的复制品应判为疑似及以上，实际等级 %d（%.3f）" % (
        best["level"], best["score"])
    assert report["risk"]["work_id"] == fx["work_id"], "风险摘要应指向该作品"
    return "命中《晨》，相似度 %.3f，等级 %d" % (best["score"], best["level"])


def t_compare_miss():
    fx = _fixture()
    report = service.compare_content(fx["chain"], _alt_png(), filename="另一幅.png",
                                     work_id=fx["work_id"])
    best = report["results"][0]
    assert best["level"] <= 2, "无关作品不应判为疑似，实际等级 %d（%.3f）" % (best["level"],
                                                                        best["score"])
    return "无关作品相似度 %.3f，未误判" % best["score"]


def t_transfer():
    fx = _fixture()
    chain, work_id = fx["chain"], fx["work_id"]
    service.transfer_work(chain, fx["store"], fx["alice"], work_id, fx["bob"].address,
                          price="12000.00", note="画廊收购")
    assert chain.ledger.owner_of(work_id) == fx["bob"].address, "权利人应变为 bob"
    work = chain.ledger.get_work(work_id)
    assert work["transfer_count"] == 1, "转让次数应为 1"
    try:
        service.transfer_work(chain, fx["store"], fx["alice"], work_id, fx["alice"].address)
        raise AssertionError("已不是权利人不应再能转让")
    except service.ServiceError as exc:
        assert "权利人" in str(exc), "拒绝原因应说明非权利人，实际：%s" % exc
    try:
        service.transfer_work(chain, fx["store"], fx["bob"], work_id, fx["bob"].address)
        raise AssertionError("不应允许把作品转让给自己")
    except service.ServiceError:
        pass
    return "转让生效，越权转让被拒绝"


def t_license():
    fx = _fixture()
    chain, work_id = fx["chain"], fx["work_id"]
    service.license_work(chain, fx["store"], fx["bob"], work_id, fx["alice"].address,
                         scope="独家", territory="中国大陆", royalty="800.00",
                         start="2026-01-01", end="2027-01-01", purpose="画册出版")
    assert len(chain.ledger.licenses.get(work_id, [])) == 1, "许可应写入台账"
    try:
        service.license_work(chain, fx["store"], fx["bob"], work_id, fx["alice"].address,
                             scope="独家")
        raise AssertionError("同一作品不应存在两项独家授权")
    except service.ServiceError as exc:
        assert "独家" in str(exc), "拒绝原因应说明独家冲突，实际：%s" % exc
    return "独家授权登记，重复独家被拒绝"


def t_mempool():
    fx = _fixture()
    chain, store = fx["chain"], fx["store"]
    res = service.license_work(chain, store, fx["bob"], fx["work_id"], fx["alice"].address,
                               scope="非独家", purpose="网页展示", auto_mine=False)
    assert not res["mined"], "关闭自动挖矿时不应出块"
    assert len(chain.mempool) == 1, "交易应进入待打包池"
    assert res["txid"] in [t["txid"] for t in chain.pending()], "待打包池应包含该交易"
    before = chain.height
    service.mine_now(chain, store, fx["bob"].address)
    assert len(chain.mempool) == 0, "出块后待打包池应清空"
    assert chain.height == before + 1, "出块后高度应加一"
    return "待打包池 -> 出块 -> 清空"


def t_replay_protection():
    fx = _fixture()
    chain, bob = fx["chain"], fx["bob"]
    used_nonce = chain.ledger.nonces.get(bob.address, 0)
    tx = make_tx(TX_TRANSFER, bob.address, bob.pubkey,
                 {"work_id": fx["work_id"], "to": fx["alice"].address, "price": "1.00"},
                 nonce=max(1, used_nonce))
    sign_tx(tx, bob.private_key())
    accepted, message = chain.submit(tx)
    assert not accepted, "重复 nonce 的交易不应被接受"
    assert "nonce" in message or "重放" in message, "拒绝原因应说明 nonce 问题，实际：%s" % message
    return "重放交易被 nonce 机制拒绝"


def t_dispute_lock():
    fx = _fixture()
    chain, work_id = fx["chain"], fx["work_id"]
    service.dispute_work(chain, fx["store"], fx["alice"], work_id, "该作品系本人 2023 年创作，被抢先登记")
    assert chain.ledger.get_work(work_id)["status"] == "争议中", "作品状态应变为争议中"
    assert len(chain.ledger.disputes) >= 1, "争议记录应写入账本"
    try:
        service.transfer_work(chain, fx["store"], fx["bob"], work_id, fx["alice"].address)
        raise AssertionError("争议中的作品不应允许转让")
    except service.ServiceError as exc:
        assert "争议" in str(exc), "拒绝原因应说明争议状态，实际：%s" % exc
    return "争议登记生效并锁定转让"


def t_dispute_adjudicate():
    """裁决：把「争议中」这个死结解开，且只有无关第三方解得开。

    刻意另造一件作品而不是复用《晨》：《晨》是后续证书、原件校验、重载等
    用例的共同前提，把它裁决成「已无效」会连累一大片。这里自己造、自己走完。
    """
    fx = _fixture()
    chain, store = fx["chain"], fx["store"]
    alice, bob, carol = fx["alice"], fx["bob"], fx["carol"]

    work_id = service.register_work(chain, store, alice, _png(variant=9),
                                    filename="待裁决.png", title="待裁决作品")["work_id"]
    assert chain.ledger.get_work(work_id)["status"] == "有效", "新登记的作品应为有效"

    # 转让给 bob 之后再让 alice 提异议，两个当事人就分别是 bob 和 alice，
    # carol 才是与本案无利害关系的第三方。
    service.transfer_work(chain, store, alice, work_id, bob.address, price="1.00")
    service.dispute_work(chain, store, alice, work_id, "该作品实为本人创作，被抢先登记")
    assert chain.ledger.get_work(work_id)["status"] == "争议中", "异议后应进入争议中"

    # 当事人双方都不能裁决——否则等于被告自己当法官
    try:
        service.adjudicate_work(chain, store, bob, work_id, "驳回", "我说了算")
        raise AssertionError("当前权利人不应有权裁决针对自己的异议")
    except service.ServiceError as exc:
        assert "权利人" in str(exc), "拒绝原因应说明权利人无裁决权，实际：%s" % exc
    try:
        service.adjudicate_work(chain, store, alice, work_id, "支持", "我说了算")
        raise AssertionError("异议提出人不应有权裁决自己的异议")
    except service.ServiceError as exc:
        assert "异议提出人" in str(exc), "拒绝原因应说明异议人无裁决权，实际：%s" % exc

    # 结论只能二选一，别的一律不认
    try:
        service.adjudicate_work(chain, store, carol, work_id, "随便", "理由")
        raise AssertionError("非法的裁决结论不应被接受")
    except service.ServiceError as exc:
        assert "裁决结论" in str(exc), "拒绝原因应说明结论非法，实际：%s" % exc

    # 第三方驳回 → 恢复有效，转让重新开放
    service.adjudicate_work(chain, store, carol, work_id, "驳回", "证据不足，维持原登记")
    assert chain.ledger.get_work(work_id)["status"] == "有效", "驳回后应恢复为有效"
    assert chain.ledger.open_dispute(work_id) is None, "裁决后不应再有未决争议"

    # 同一件作品可以再次被提异议；这次改判支持 → 登记转为已无效
    service.dispute_work(chain, store, alice, work_id, "补充了新证据")
    service.adjudicate_work(chain, store, carol, work_id, "支持", "新证据足以推翻原登记")
    work = chain.ledger.get_work(work_id)
    assert work["status"] == "已无效", "支持异议后应转为已无效，实际 %s" % work["status"]
    assert chain.ledger.by_file_hash.get(work["file_hash"]) is None, \
        "判定无效后应释放指纹占用，真实作者才能重新登记同一份文件"

    try:
        service.transfer_work(chain, store, bob, work_id, carol.address)
        raise AssertionError("已无效的作品不应允许转让")
    except service.ServiceError as exc:
        assert "无效" in str(exc), "拒绝原因应说明登记已无效，实际：%s" % exc
    # 登记人也不能用「撤销登记」把裁决结论改写成「自己主动撤回」
    try:
        service.revoke_work(chain, store, bob, work_id, reason="想改成主动撤销")
        raise AssertionError("已无效的作品不应允许再用撤销登记覆盖裁决结果")
    except service.ServiceError as exc:
        assert "无效" in str(exc), "拒绝原因应说明登记已无效，实际：%s" % exc

    records = [d for d in chain.ledger.disputes if d["work_id"] == work_id]
    assert len(records) == 2, "两次异议应各留一条记录，实际 %d" % len(records)
    assert records[0]["status"] == "已驳回" and records[0]["arbiter"] == carol.address, \
        "第一条争议应记为已驳回，裁决人为 carol"
    assert records[1]["status"] == "已支持" and records[1]["ruling"] == "支持", \
        "第二条争议应记为已支持"
    assert all(d["status"] != "待裁决" for d in records), "本案不应再有未决争议"
    return "第三方裁决：驳回恢复有效、支持转为无效并释放指纹"


def t_chain_verify():
    fx = _fixture()
    chain = fx["chain"]
    ok, errors = chain.verify()
    assert ok, "整链校验应通过：%s" % errors[:3]
    assert chain.height >= 4, "全流程后高度应 >= 4，实际 %d" % chain.height
    return "整链校验通过（高度 #%d）" % chain.height


def t_tamper_detected():
    fx = _fixture()
    chain = fx["chain"]
    tampered = copy.deepcopy(chain.blocks)
    tampered[1]["txs"][0]["data"]["title"] = "被篡改的标题"
    ok, errors, _ledger = validate_blocks(tampered, chain.difficulty)
    assert not ok, "被篡改的链必须校验失败"
    joined = "；".join(errors)
    assert ("Merkle" in joined) or ("哈希" in joined), "应检出哈希不一致，实际：%s" % joined

    tampered2 = copy.deepcopy(chain.blocks)
    tampered2[1]["nonce"] += 1
    ok2, _errors2, _l2 = validate_blocks(tampered2, chain.difficulty)
    assert not ok2, "改动区块头后必须校验失败"

    # 整链替换：把最后一笔交易删掉，应当被拒绝
    shorter = copy.deepcopy(chain.blocks)
    del shorter[2]["txs"][0]
    ok3, _e3, _l3 = validate_blocks(shorter, chain.difficulty)
    assert not ok3, "删除交易后必须校验失败"
    return "篡改标题/随机数/删除交易均被检出"


def t_certificate():
    fx = _fixture()
    chain, store, work_id = fx["chain"], fx["store"], fx["work_id"]
    cert = certificate.build_certificate(chain, work_id, store=store, issuer="自检程序")
    assert cert["evidence"]["merkle_proof_valid"], "证书里的 Merkle 证明应自洽"
    assert cert["fingerprint"]["sha256"], "证书应包含 SHA-256"

    # 链上核对模式：与本地链逐项比对一致，才算真的证明了确权成立。
    result = certificate.verify_certificate(cert, chain=chain)
    assert result["valid"], "链上核对应通过：%s" % result["problems"]
    assert result["trusted"], "与本地链比对一致时 trusted 必须为真"

    # 离线模式：自洽通过，但绝不能声称可信。
    offline = certificate.verify_certificate(cert)
    assert offline["valid"], "离线自洽校验应通过：%s" % offline["problems"]
    assert not offline["trusted"], "离线模式不得声称可信"
    assert offline["notes"], "离线模式必须给出说明，不能默默返回通过"

    assert "艺术品区块链确权证书" in certificate.render_text(cert), "文本证书渲染异常"
    assert "Merkle" in certificate.render_html(cert), "HTML 证书渲染异常"
    assert '"work_id"' in certificate.render_json(cert), "JSON 证书渲染异常"

    bad = copy.deepcopy(cert)
    bad["evidence"]["txid"] = "0" * 64
    assert not certificate.verify_certificate(bad)["valid"], "被改动的证书必须验证失败"
    bad2 = copy.deepcopy(cert)
    bad2["evidence"]["merkle_root"] = "f" * 64
    assert not certificate.verify_certificate(bad2)["valid"], "被改动的 Merkle 根必须验证失败"

    # 伪造证书：把难度改成 0，再按改后的区块头重算 block_hash。
    # 这样"区块头哈希满足自身声明的难度"依旧成立（难度 0 恒真），
    # 于是离线自洽校验会放行——这正是离线结论不可信的原因，必须如实断言出来。
    forged = copy.deepcopy(cert)
    ev = forged["evidence"]
    ev["block_difficulty"] = 0
    ev["block_hash"] = block_mod.block_hash({
        "version": ev.get("block_version", 1),
        "height": ev["height"],
        "prev_hash": ev["prev_hash"],
        "time": ev["block_time"],
        "merkle_root": ev["merkle_root"],
        "miner": ev.get("miner", ""),
        "difficulty": 0,
        "nonce": ev["block_nonce"],
    })
    assert certificate.verify_certificate(forged)["valid"], \
        "伪造证书在离线模式下会自洽通过——离线结论不可信，这一点必须被测试固定下来"
    assert not certificate.verify_certificate(forged, chain=chain)["trusted"], \
        "链上核对必须拒绝难度被篡改的证书"
    return "证书生成、链上核对、离线降级、防篡改、难度伪造拦截"


def t_original_check():
    fx = _fixture()
    result = service.verify_original(fx["chain"], fx["store"], fx["work_id"])
    assert result.get("available"), "原件应可在链下存储中找到"
    assert result["match"], "原件指纹应与链上一致"
    blob_path = fx["store"].blob_abspath(fx["chain"].ledger.get_work(fx["work_id"])["stored_path"])
    original = open(blob_path, "rb").read()
    with open(blob_path, "wb") as fh:  # 模拟"原件被掉包"
        fh.write(original[:-8] + b"tampered")
    broken = service.verify_original(fx["chain"], fx["store"], fx["work_id"])
    assert not broken["match"], "原件被改动后应检出不一致"
    with open(blob_path, "wb") as fh:
        fh.write(original)
    return "原件校验可检出掉包"


def t_reload():
    fx = _fixture()
    chain, store = fx["chain"], fx["store"]
    again = Blockchain(difficulty=3, store=store)
    assert again.load(), "应从磁盘重新加载链数据"
    assert again.height == chain.height, "重载后高度应一致"
    assert again.ledger.owner_of(fx["work_id"]) == fx["chain"].ledger.owner_of(fx["work_id"]), \
        "重载后权利人应一致"
    assert again.ledger.get_work(fx["work_id"])["title"] == "晨", "重载后作品信息应一致"
    ok, errors = again.verify()
    assert ok, "重载后的链应通过校验：%s" % errors[:3]
    return "从磁盘重载后状态一致"


# ================================================================= 社区上链
def t_post_publish():
    fx = _fixture()
    chain, store, alice = fx["chain"], fx["store"], fx["alice"]
    res = service.publish_post(chain, store, alice,
                               "创世之作《晨》完成登记，指纹不会说谎。",
                               topic="创作手记")
    assert res["mined"], "发帖后应已挖矿上链"
    post_id = res["post_id"]
    assert post_id.startswith("PS"), "帖子编号应以 PS 开头"
    post = chain.ledger.posts.get(post_id)
    assert post is not None, "帖子应写入账本"
    assert post["author"] == alice.address, "作者应为发帖人"
    assert post["topic"] == "创作手记", "话题应记录在链上"
    assert post_id == post_id_for(post["txid"]), "帖子编号应由交易哈希确定性推导"
    assert chain.statistics()["posts_total"] >= 1, "统计里应计入帖子总数"
    fx["post_id"] = post_id
    return "帖子已写入区块 #%s，编号 %s" % (res["height"], post_id[:12])


def t_post_reply():
    fx = _fixture()
    chain, store, bob = fx["chain"], fx["store"], fx["bob"]
    res = service.publish_post(chain, store, bob, "恭喜确权！收藏家视角前来打卡。",
                               reply_to=fx["post_id"])
    detail = service.post_detail(chain, fx["post_id"])
    assert len(detail["replies"]) == 1, "父帖下应有一条回复"
    assert detail["replies"][0]["post_id"] == res["post_id"], "回复应挂在父帖下"
    assert detail["replies"][0]["reply_to"] == fx["post_id"], "回复应记录父帖编号"
    assert detail["proof"] and detail["proof"]["valid"], "帖子应能出具自洽的 Merkle 证明"
    try:
        service.publish_post(chain, store, bob, "回复一个不存在的帖子", reply_to="PS00000000")
        raise AssertionError("回复不存在的帖子不应被接受")
    except service.ServiceError as exc:
        assert "不存在" in str(exc), "拒绝原因应说明父帖不存在，实际：%s" % exc
    return "回复挂在父帖下，回复不存在的帖子被拒绝"


def t_post_like():
    fx = _fixture()
    chain, store, bob, carol = fx["chain"], fx["store"], fx["bob"], fx["carol"]
    service.like_post(chain, store, bob, fx["post_id"])
    service.like_post(chain, store, carol, fx["post_id"])
    detail = service.post_detail(chain, fx["post_id"])
    assert detail["post"]["likes"] == 2, "赞数应为 2，实际 %d" % detail["post"]["likes"]
    assert bob.address in detail["liked_by"], "点赞名单应包含 bob"
    viewer = service.list_posts(chain, viewer=bob.address)
    mine = [p for p in viewer["posts"] if p["post_id"] == fx["post_id"]]
    assert mine and mine[0]["liked_by_viewer"], "以 bob 视角应显示已赞"

    # 重复点赞要在交易池预演阶段就被状态机拒绝，不允许上链
    try:
        service.like_post(chain, store, bob, fx["post_id"])
        raise AssertionError("同一地址不应重复点赞同一帖")
    except service.ServiceError as exc:
        assert "已经赞过" in str(exc), "拒绝原因应说明重复点赞，实际：%s" % exc
    try:
        service.like_post(chain, store, bob, "PS00000000")
        raise AssertionError("给不存在的帖子点赞不应被接受")
    except service.ServiceError as exc:
        assert "不存在" in str(exc), "拒绝原因应说明帖子不存在，实际：%s" % exc
    return "点赞计数正确，重复赞与幽灵帖均被拒绝"


def t_post_limits():
    fx = _fixture()
    chain, store, alice = fx["chain"], fx["store"], fx["alice"]
    try:
        service.publish_post(chain, store, alice, "   ")
        raise AssertionError("空正文不应被接受")
    except service.ServiceError as exc:
        assert "不能为空" in str(exc), "拒绝原因应说明正文为空，实际：%s" % exc
    try:
        service.publish_post(chain, store, alice, "长" * 2001)
        raise AssertionError("超长正文不应被接受")
    except service.ServiceError as exc:
        assert "过长" in str(exc), "拒绝原因应说明正文过长，实际：%s" % exc
    return "空正文与超长正文在构造交易前即被拦截"


def t_post_image():
    fx = _fixture()
    chain, store, carol = fx["chain"], fx["store"], fx["carol"]
    png = _alt_png()
    res = service.publish_post(chain, store, carol, "分享一张作品图",
                               image=png, image_name="分享.png")
    post = chain.ledger.posts[res["post_id"]]
    assert post["image_hash"] == fp.sha256_bytes(png), "链上应记录附图 SHA-256"
    assert post["stored_path"], "附图原件应保存到链下存储"
    assert store.blob_data(post["stored_path"]) == png, "链下读回的附图应与上传一致"
    return "附图哈希上链、原件链下可读回"


def t_post_tamper():
    fx = _fixture()
    chain = fx["chain"]
    tampered = copy.deepcopy(chain.blocks)
    target = None
    for block in tampered:
        for tx in block["txs"]:
            if tx.get("type") == TX_POST and str(tx.get("data", {}).get("text", "")).startswith("创世之作"):
                target = tx
                break
        if target is not None:
            break
    assert target is not None, "链上应能找到社区发帖交易"
    target["data"]["text"] = "被篡改的帖子"
    ok, errors, _ledger = validate_blocks(tampered, chain.difficulty)
    assert not ok, "篡改帖子正文后整链校验必须失败"
    joined = "；".join(errors)
    assert ("哈希" in joined) or ("Merkle" in joined), "应检出哈希不一致，实际：%s" % joined
    return "篡改帖子正文被哈希校验检出"


def t_post_reload():
    fx = _fixture()
    chain, store = fx["chain"], fx["store"]
    again = Blockchain(difficulty=3, store=store)
    assert again.load(), "应从磁盘重新加载链数据"
    post = again.ledger.posts.get(fx["post_id"])
    assert post is not None, "重载后帖子应仍在账本中"
    assert str(post["text"]).startswith("创世之作"), "重载后帖子正文应一致"
    assert len(again.ledger.likes.get(fx["post_id"], [])) == 2, "重载后点赞记录应被重放重建"
    ok, errors = again.verify()
    assert ok, "含社区交易的链重载后应通过校验：%s" % errors[:3]
    return "含帖子/回复/点赞的链重载后状态一致"


# ================================================================= 平台积分
def t_points_units():
    """金额换算：8 位小数、整数最小单位、拒绝浮点与超精度输入。"""
    assert points_to_units("12.5") == 12 * 10 ** 8 + 5 * 10 ** 7, "12.5 的换算应精确"
    assert points_to_units("0.00000001") == 1, "最小单位换算应为 1"
    assert points_to_units(7) == 7 * 10 ** 8, "整数输入应按 8 位小数换算"
    assert units_to_text(points_to_units("12.5")) == "12.5", "展示文本应还原"
    assert units_to_text(points_to_units("1000")) == "1000", "整数展示不带小数尾巴"
    assert units_to_text(1) == "0.00000001", "最小单位展示应完整"
    for bad, why in ((0.5, "浮点"), ("1.123456789", "超精度"), ("0", "零"), ("-5", "负数"), ("abc", "非数字")):
        try:
            points_to_units(bad)
            raise AssertionError("非法金额 %r 不应被接受（%s）" % (bad, why))
        except TxError:
            pass
    return "金额换算精确，浮点/超精度/零/负数/非数字全部拒绝"


def t_points_mint_pay():
    fx = _fixture()
    chain, store, alice, bob = fx["chain"], fx["store"], fx["alice"], fx["bob"]
    res = service.mint_points(chain, store, alice, "1000", memo="初始发行")
    assert res["mined"] and res["amount_text"] == "1000", "铸造 1000 应已上链"
    assert chain.ledger.total_supply == points_to_units("1000"), "流通量应更新"
    assert chain.ledger.balances[alice.address] == points_to_units("1000"), "铸造应计入发起方余额"
    res = service.transfer_points(chain, store, alice, bob.address, "12.5", memo="分红")
    assert res["mined"] and res["amount_text"] == "12.5", "转账应已上链"
    assert chain.ledger.balances[bob.address] == points_to_units("12.5"), "收款方余额应正确"
    assert chain.ledger.balances[alice.address] == points_to_units("987.5"), "转出方余额应正确"
    log = chain.ledger.points_log
    assert len(log) == 2 and log[0]["type"] == "MINT" and log[1]["type"] == TX_PAY, "流水顺序应正确"
    assert log[1]["memo"] == "分红" and log[1]["to"] == bob.address, "流水字段应完整"
    stats = chain.statistics()
    assert stats["points_supply"] == points_to_units("1000"), "统计里的流通量应正确"
    assert stats["points_holders"] == 2 and stats["points_transfers"] == 1, "持币数与转账数应正确"
    overview = service.points_overview(chain, address=bob.address)
    assert overview["balance_text"] == "12.5", "按地址查询余额应正确"
    return "铸造 1000、转账 12.5：余额、流通量、流水与统计全部一致"


def t_points_operator_rules():
    fx = _fixture()
    store, chain = _points_chain()
    alice, bob, op = fx["alice"], fx["bob"], fx["op"]
    for action in (lambda: service.mint_points(chain, store, alice, "10"),
                   lambda: service.burn_points(chain, store, bob, "1")):
        try:
            action()
            raise AssertionError("非运营方的铸造/销毁不应被接受")
        except service.ServiceError as exc:
            assert "运营方" in str(exc), "拒绝原因应说明发行权限：%s" % exc
    service.mint_points(chain, store, op, "100")
    assert chain.ledger.balances[op.address] == points_to_units("100"), "运营方铸造应入账"
    for bad, keyword in ((lambda: service.transfer_points(chain, store, op, op.address, "1"), "自己"),
                         (lambda: service.transfer_points(chain, store, op, bob.address, "999999"), "余额不足"),
                         (lambda: service.transfer_points(chain, store, op, "ART999999", "1"), "地址")):
        try:
            bad()
            raise AssertionError("非法转账不应被接受")
        except service.ServiceError as exc:
            assert keyword in str(exc), "拒绝原因应说明%s：%s" % (keyword, exc)
    service.transfer_points(chain, store, op, bob.address, "10")
    service.burn_points(chain, store, op, "30")
    assert chain.ledger.total_supply == points_to_units("70"), "销毁后流通量应缩减"
    assert chain.ledger.balances[bob.address] == points_to_units("10"), "转账收款应正确"
    return "铸造/销毁仅限运营方；自转、余额不足、坏地址、非运营方销毁全部被拒"


def t_points_supply_cap():
    fx = _fixture()
    store, chain = _points_chain(max_supply=points_to_units("1000"))
    op = fx["op"]
    service.mint_points(chain, store, op, "1000")
    assert chain.ledger.total_supply == points_to_units("1000"), "铸满上限应成功"
    try:
        service.mint_points(chain, store, op, "0.00000001")
        raise AssertionError("超过总量上限的铸造不应被接受")
    except service.ServiceError as exc:
        assert "上限" in str(exc), "拒绝原因应说明总量上限：%s" % exc
    return "总量上限在链规则内强制执行，超发被拒"


def t_points_reload():
    fx = _fixture()
    chain, store, alice = fx["chain"], fx["store"], fx["alice"]
    service.mint_points(chain, store, alice, "50", memo="重载验证")
    again = Blockchain(difficulty=3, store=store)
    assert again.load(), "应从磁盘重新加载链数据"
    assert again.ledger.total_supply == chain.ledger.total_supply, "重载后流通量应一致"
    assert again.ledger.balances == chain.ledger.balances, "重载后余额表应一致"
    assert len(again.ledger.points_log) == len(chain.ledger.points_log), "重载后流水应一致"
    ok, errors = again.verify()
    assert ok, "含积分交易的链重载后应通过校验：%s" % errors[:3]
    return "含铸造/转账的链重载后状态一致并通过校验"


# ================================================================= 助记词钱包
def t_mnemonic_vectors():
    """BIP39 官方规范向量：熵↔助记词↔种子必须与主流钱包逐字节一致。"""
    e1 = bytes.fromhex("00000000000000000000000000000000")
    m1 = ("abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon about")
    seed1 = ("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19"
             "a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    assert bip39.entropy_to_mnemonic(e1) == m1, "官方向量：熵->助记词应逐字一致"
    assert bip39.mnemonic_to_entropy(m1).hex() == e1.hex(), "官方向量：助记词->熵应一致"
    assert bip39.to_seed(m1).hex() == seed1, "官方向量：种子应逐字节一致"

    e2 = bytes(32)   # 256 位全零 -> 24 词 abandon…art
    m2 = ("abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon abandon abandon abandon abandon art")
    assert bip39.entropy_to_mnemonic(e2) == m2, "官方向量：24 词助记词应逐字一致"
    assert bip39.mnemonic_to_entropy(m2) == e2, "官方向量：24 词熵回读应一致"

    assert bip39.validate(m1) and bip39.validate(m2), "官方向量应通过校验"
    assert not bip39.validate(m1.replace("about", "zoo")), "篡改单词应被校验和拒绝"
    assert not bip39.validate("abandon abandon abandon"), "错误长度应被拒绝"
    return "官方规范向量逐字一致，校验和拦截篡改与错词"


def t_mnemonic_wallet():
    """助记词钱包：生成 -> 签名验签 -> 同词导入恢复出同一地址。"""
    fx = _fixture()
    store = fx["store"]
    wallet, mnemonic = Wallet.create_with_mnemonic(store, "助记词钱包", password="pw-mn")
    assert len(mnemonic.split()) == 12, "默认应为 12 词"
    assert bip39.validate(mnemonic), "生成的助记词应合法"
    sig = wallet.sign(b"mnemonic-wallet-signature")
    assert ec.verify(wallet.pubkey, b"mnemonic-wallet-signature", sig), "派生私钥应能签名验签"

    # 同词导入 = 同一身份（换设备恢复的核心保证）
    restored = Wallet.from_mnemonic(store, "助记词钱包-恢复", mnemonic, password="pw-mn2")
    assert restored.address == wallet.address, "同一助记词导入应恢复出同一地址"
    assert restored.pubkey == wallet.pubkey, "公钥应一致"

    # 换一个词就是另一个人
    words = mnemonic.split()
    words[3] = "zoo" if words[3] != "zoo" else "zebra"
    other_mn = " ".join(words)
    if bip39.validate(other_mn):
        other = Wallet.from_mnemonic(store, "助记词钱包-换词", other_mn, password="x")
        assert other.address != wallet.address, "不同助记词不应得到同一地址"
    return "助记词生成合法可签名，同词导入恢复同一身份，换词则身份不同"


def t_mnemonic_legacy_compat():
    """旧格式钱包（十六进制私钥）升级后仍能解锁、签名，且重存不丢格式。"""
    fx = _fixture()
    store = fx["store"]
    priv = ec.generate_private_key()
    pub = ec.pubkey_from_private(priv)
    addr = ec.pubkey_to_address(pub)
    crypto = chacha20.encrypt("legacy-pass", ec.private_key_to_hex(priv))
    store.save_wallet("旧版钱包", {
        "name": "旧版钱包", "address": addr, "pubkey": pub.hex(),
        "created_at": 12345, "meta": {}, "crypto": crypto,
    })
    wallet = Wallet.load(store, "旧版钱包", "legacy-pass")
    assert wallet.address == addr, "旧格式钱包应能解锁出原地址"
    assert wallet.mnemonic is None, "旧格式钱包没有助记词字段"
    sig = wallet.sign(b"legacy")
    assert ec.verify(pub, b"legacy", sig), "旧格式钱包应能签名"
    payload = wallet.to_payload("legacy-pass")
    assert "private_key" not in payload and payload.get("crypto"), "重存应保持加密旧格式"
    return "旧版十六进制私钥钱包升级后可解锁、可签名，格式不被破坏"


def t_rotpwd():
    """动态口令：每窗口变化、±1 窗口容差、助记词直解与重查看。"""
    fx = _fixture()
    store = fx["store"]
    wallet, mnemonic = Wallet.create_with_mnemonic(store, "动态口令钱包", rotating=True)
    payload = store.load_wallet("动态口令钱包")
    envelope = payload.get("crypto") or {}
    assert envelope.get("pw_mode") == "rotating" and envelope.get("window") is not None, \
        "动态口令钱包应记录模式与窗口号"
    w = int(envelope["window"])
    pw = rotpwd.password_for(mnemonic, w)
    assert len(pw) == rotpwd.PASSWORD_LENGTH, "口令应为固定长度"
    assert pw == rotpwd.password_for(mnemonic, w), "同一窗口口令应确定"
    assert pw != rotpwd.password_for(mnemonic, w + 1), "相邻窗口口令应不同"
    Wallet.load(store, "动态口令钱包", pw), "记录窗口的口令应能解锁"
    # 口令只在记录窗口有效：过期窗口必然解不开（这正是「口令会变化」的含义）
    try:
        Wallet.load(store, "动态口令钱包", rotpwd.password_for(mnemonic, w + 1))
        raise AssertionError("过期窗口的口令不应能解锁")
    except WalletError:
        pass
    # 容错路径是助记词直解——不受窗口影响
    unlocked = Wallet.from_mnemonic_unlocked(store, "动态口令钱包", mnemonic)
    assert unlocked.address == wallet.address, "助记词直解应得到同一身份"
    try:
        Wallet.from_mnemonic_unlocked(store, "动态口令钱包", bip39.generate(128))
        raise AssertionError("错误助记词不应解锁")
    except WalletError:
        pass
    pw_now, left = unlocked.rekey_rotating(store)
    assert 1 <= left <= rotpwd.STEP_SECONDS, "剩余秒数应在窗口内"
    Wallet.load(store, "动态口令钱包", pw_now), "重查看后的当前口令应能解锁"
    return "口令每窗口变化、过期口令失效、助记词直解与重查看全部一致"


def t_apikeys():
    """开放平台密钥：明文仅一次、落盘只存哈希、吊销即失效。"""
    from . import apikeys
    tmp = tempfile.mkdtemp(prefix="artchain-apikeys-")
    store = Store(tmp).ensure_dirs()
    record, plain = apikeys.create_key(store, "自检合作方", ("read", "write"))
    assert plain.startswith(apikeys.KEY_PREFIX) and len(plain) > 20, "密钥格式异常"
    payload = json.load(open(os.path.join(tmp, apikeys.KEY_FILE),
                             encoding="utf-8"))
    stored = payload["keys"][0]
    assert plain not in json.dumps(payload, ensure_ascii=False), "落盘不得含明文密钥"
    assert stored["key_hash"], "落盘应只存哈希"
    hit = apikeys.verify_key(store, plain)
    assert hit and hit["id"] == record["id"], "合法密钥应通过校验"
    assert apikeys.verify_key(store, plain[:-2] + "00") is None, "错钥应被拒绝"
    assert apikeys.verify_key(store, "") is None, "空钥应被拒绝"
    listed = apikeys.list_keys(store)
    assert all("key_hash" not in item for item in listed), "列表不得泄露哈希"
    apikeys.revoke_key(store, record["id"])
    assert apikeys.verify_key(store, plain) is None, "吊销后应立即失效"
    try:
        apikeys.create_key(store, "坏权限", ("admin",))
        raise AssertionError("非法权限档应被拒绝")
    except apikeys.ApiKeyError:
        pass
    return "签发/校验/吊销/权限档校验全通过，落盘无明文"


def t_apikeys_ratelimit():
    """开放平台限流：窗口内放行、超限拒绝、权限档独立计数。"""
    from . import apikeys
    key_id = "selftest-rate"
    limit = apikeys.RATE_LIMITS["write"]
    for _ in range(limit):
        ok, _used, _cap = apikeys.check_rate(key_id, "write")
        assert ok, "窗口内应放行"
    ok, used, cap = apikeys.check_rate(key_id, "write")
    assert not ok and used == limit and cap == limit, "超限应拒绝并回报上限"
    ok, _used, _cap = apikeys.check_rate(key_id, "read")
    assert ok, "读档限额独立于写档，不应被写档耗尽连带拒绝"
    return "写档 %d 次/分封顶、读写分档计数" % limit


def t_geofence():
    """地区识别：本机回环按默认从严、明确大陆/海外 IP 命中正确、内网段不外泄。"""
    from . import geofence
    cn_ranges = geofence.cn_ranges()
    assert len(cn_ranges) > 50, "内置核心网段应覆盖主要运营商（电信/联通/移动/教育网）"
    # 知名大陆服务地址（114DNS / AliDNS）落在内置清单
    for cn_ip in ("114.114.114.114", "223.5.5.5", "180.76.76.76", "36.128.1.1",
                  "211.136.0.1"):
        region, label, detail = geofence.region_of(cn_ip)
        assert region == "CN", "%s 应识别为 CN（实际 %s）" % (cn_ip, region)
    # 明确海外
    for other_ip in ("8.8.8.8", "1.1.1.1", "208.67.222.222"):
        region, _label, _d = geofence.region_of(other_ip)
        assert region == "OTHER", "%s 应识别为 OTHER（实际 %s）" % (other_ip, region)
    # 内网按 default 处理——必须从 CN 出发（合规从严）
    region, _label, detail = geofence.region_of("127.0.0.1", default="CN")
    assert region == "CN" and detail == "loopback", "本机回环应按默认地区归类"
    # 代理头信任模型：直连客户端不可伪造 XFF
    from .geofence import client_ip
    sock_ip = "8.8.8.8"
    ip = client_ip({"X-Forwarded-For": "114.114.114.114"}, sock_ip,
                    trust_proxy=False)
    assert ip == sock_ip, "未开启 trust_proxy 时直连客户端的 XFF 应被忽略"
    # 开启 trust_proxy 后头优先
    ip = client_ip({"X-Forwarded-For": "114.114.114.114"}, sock_ip,
                    trust_proxy=True)
    assert ip == "114.114.114.114", "trust_proxy=true 时应采纳 XFF 首项"
    return "大陆/海外/本机/代理头四象限全部识别正确"


def t_purchase_flow():
    """积分购买：定价、地区拦截、订单状态机、运营方交付闭环。"""
    from . import service as svc
    fx = _fixture()
    store = fx["store"]
    chain = fx["chain"]
    operator = fx["op"]
    # 准备买家钱包（口令 = None，未加密，仅用于本地演示）
    buyer = Wallet.create(store, "buy-points")
    buyer_address = buyer.address

    # CN 视角下 USDT/ETH 应锁定，微信可见
    cn_methods = svc.purchase_methods(store, "CN")
    wechat = next(r for r in cn_methods if r["id"] == "wechat")
    alipay = next(r for r in cn_methods if r["id"] == "alipay")
    unionpay = next(r for r in cn_methods if r["id"] == "unionpay")
    usdt = next(r for r in cn_methods if r["id"] == "usdt")
    eth = next(r for r in cn_methods if r["id"] == "eth")
    assert (wechat["available"] and alipay["available"] and
            unionpay["available"] and
            not usdt["available"] and not eth["available"]), \
        "CN 视角应只开放法币通道（微信/支付宝/银联），加密通道锁定：" \
        "%s" % [(r["id"], r["available"]) for r in cn_methods]
    other_methods = svc.purchase_methods(store, "OTHER")
    assert all(r["available"] for r in other_methods), \
        "非 CN 视角应全部可用：%s" % [(r["id"], r["available"]) for r in other_methods]
    assert len(other_methods) == 5, "应有 5 个通道（3 法币 + 2 加密）"

    # CN IP 直接创建 ETH 订单：业务层抛 ServiceError，含「中国大陆」字样
    try:
        svc.create_purchase_order(store, buyer_address, "10", "eth", "CN",
                                  client_ip="114.114.114.114")
        raise AssertionError("CN+ETH 不应允许创建订单")
    except svc.ServiceError as exc:
        assert "中国大陆" in str(exc) or "加密货币" in str(exc)

    # 微信下单：pending 状态、对价合理、订单号 PO- 前缀
    order = svc.create_purchase_order(store, buyer_address, "1000", "wechat", "CN")
    assert order["status"] == "pending" and order["buyer"] == buyer_address, \
        "下单结果异常：%s" % order
    assert order["points_text"] == "1000", \
        "积分精度异常：%s" % order["points_text"]
    assert order["id"].startswith("PO-"), "订单号格式：%s" % order["id"]
    assert "微信" in order["instructions"], "缺少微信说明：%s" % order["instructions"]
    # 取消：pending 可取消；再次取消应被拒
    svc.cancel_purchase_order(store, order["id"])
    cancelled = next(o for o in svc.list_purchase_orders(store)
                     if o["id"] == order["id"])
    assert cancelled["status"] == "canceled"
    try:
        svc.cancel_purchase_order(store, order["id"])
        raise AssertionError("重复取消不应成功")
    except svc.ServiceError:
        pass

    # 海外 ETH 订单 → 运营方交付：MINT + PAY，链上余额增量
    eth_order = svc.create_purchase_order(store, buyer_address, "5", "eth",
                                          "OTHER", client_ip="8.8.8.8")
    before = int(chain.ledger.balances.get(buyer_address, 0))
    result = svc.confirm_payment(chain, store, operator, eth_order["id"],
                                  payment_ref="0xdeadbeef")
    after = int(chain.ledger.balances.get(buyer_address, 0))
    expected = int(eth_order["points_units"])
    diff = after - before
    msg = ("买家余额应增加 %d（订单 %s）；实测 before=%d after=%d diff=%d"
           % (expected, eth_order["id"], before, after, diff))
    assert diff == expected, msg
    assert result["order"]["status"] == "delivered"
    assert len(result["order"]["delivered_txids"]) == 2, \
        "应有 MINT 与 PAY 两个 txid，实际：%s" % result["order"]["delivered_txids"]
    try:
        svc.confirm_payment(chain, store, operator, eth_order["id"])
        raise AssertionError("重复确认不应成功")
    except svc.ServiceError:
        pass

    # 订单列表按地址过滤：买家只看到自己下的
    my_orders = svc.list_purchase_orders(store, address=buyer_address)
    assert all(o["buyer"] == buyer_address for o in my_orders), \
        "按地址过滤应只返回买家自己的订单"
    return "地区拦截/微信下单/取消/海外 ETH 交付闭环全部成立"


# ================================================================= 存储与落盘
def _store_tmp(prefix="artchain-store-"):
    """为存储层用例单开目录（与主 fixture 隔离，结束后统一清理）。"""
    tmp = tempfile.mkdtemp(prefix=prefix)
    _STATE.setdefault("extra_tmps", []).append(tmp)
    return tmp


def _log_lines(store):
    with open(store.blocks_path, "r", encoding="utf-8") as fh:
        return [line for line in fh.read().splitlines() if line.strip()]


def t_store_append_only():
    """出块走追加日志：一行一区块，提交交易不触碰区块文件。"""
    tmp = _store_tmp()
    store = Store(tmp).ensure_dirs()
    chain = Blockchain(difficulty=1, store=store)
    chain.create_genesis(name="存储测试链", operator="自检程序")
    chain.save()
    assert os.path.exists(store.blocks_path), "建链落盘后应生成追加式区块日志"

    alice = _STATE["alice"]
    res = service.publish_post(chain, store, alice, "待打包阶段不重写链文件", auto_mine=False)
    assert not res["mined"], "关闭自动挖矿时不应出块"
    size_before = os.path.getsize(store.blocks_path)
    mtime_before = os.path.getmtime(store.blocks_path)
    assert store.load_mempool(), "提交的交易池应已单独落盘"
    assert os.path.getsize(store.blocks_path) == size_before, "提交交易不应改动区块日志"
    assert os.path.getmtime(store.blocks_path) == mtime_before, "提交交易不应改动区块日志时间戳"

    for i in range(3):
        service.publish_post(chain, store, alice, "存储层追加测试 %d" % i)
    lines = _log_lines(store)
    assert len(lines) == len(chain.blocks), "日志行数应与区块数一致"
    assert json.loads(lines[-1])["hash"] == chain.last_block()["hash"], "最后一行应是最新区块"

    again = Blockchain(difficulty=1, store=store)
    assert again.load(), "应能从追加日志重载链"
    assert again.height == chain.height, "重载后高度应一致"
    assert again.last_block()["hash"] == chain.last_block()["hash"], "重载后链尖应一致"
    ok, errors = again.verify()
    assert ok, "追加落盘的链应通过校验：%s" % errors[:3]
    return "%d 块追加落盘，提交零重写，重载一致" % len(lines)


def t_store_legacy_migration():
    """旧版 chain.json 读入时一次性迁移为追加日志，原文件留档 .bak。"""
    tmp = _store_tmp()
    store = Store(tmp).ensure_dirs()
    src = Blockchain(difficulty=1, store=store)
    src.create_genesis(name="旧格式链", operator="自检程序")
    legacy = src.to_dict()
    # 手工摆出旧版单文件格式（create_genesis 不落盘，此时目录还是空的）
    with open(store.chain_path, "w", encoding="utf-8") as fh:
        json.dump(legacy, fh, ensure_ascii=False, indent=2)

    assert store.has_chain(), "旧格式文件应被识别为已有链"
    payload = store.load_chain()
    assert [b["hash"] for b in payload["blocks"]] == [b["hash"] for b in legacy["blocks"]], \
        "迁移后区块内容应与旧文件一致"
    assert payload["difficulty"] == legacy["difficulty"], "迁移后难度应保留"
    assert os.path.exists(store.blocks_path), "迁移后应生成追加日志"
    assert os.path.exists(store.chain_path + ".bak"), "旧文件应留档为 .bak"
    assert not os.path.exists(store.chain_path), "旧文件不应残留在原位"

    again = store.load_chain()
    assert again["blocks"] == payload["blocks"], "再次读取应直接走新格式且内容一致"
    chain = Blockchain(difficulty=1, store=store)
    assert chain.load() and chain.height == src.height, "迁移后的链应可正常加载"
    return "旧链一次性迁移，原件留档 .bak"


def t_store_disk_selfheal():
    """磁盘衔接状态未知时出块退回整链重写自愈，之后恢复追加。"""
    tmp = _store_tmp()
    store = Store(tmp).ensure_dirs()
    src = Blockchain(difficulty=1, store=store)
    src.create_genesis(name="自愈测试链", operator="自检程序")
    src.save()
    # 模拟同步路径：链数据经 from_dict 只进内存，磁盘衔接状态未知
    chain = Blockchain(difficulty=1, store=store)
    chain.from_dict(src.to_dict())
    alice = _STATE["alice"]
    service.publish_post(chain, store, alice, "未知磁盘状态，出块应整链重写")
    service.publish_post(chain, store, alice, "对齐之后恢复追加")
    lines = _log_lines(store)
    assert len(lines) == len(chain.blocks) == 3, "重写+追加后日志应与链完全一致"
    again = Blockchain(difficulty=1, store=store)
    assert again.load() and again.height == chain.height, "自愈落盘后应可重载"
    ok, errors = again.verify()
    assert ok, "自愈落盘的链应通过校验：%s" % errors[:3]
    return "未知状态整链重写自愈，其后恢复增量追加"


def t_store_crash_recovery():
    """断电在日志尾巴上留下半行时，重载回退到上一个完整块。"""
    tmp = _store_tmp("artchain-crash-")
    store = Store(tmp).ensure_dirs()
    chain = Blockchain(difficulty=1, store=store)
    chain.create_genesis(name="崩溃恢复测试链", operator="自检程序")
    alice = _STATE["alice"]
    for i in range(3):
        service.publish_post(chain, store, alice, "崩溃恢复前置块 %d" % i)
    good_lines = _log_lines(store)
    good_height = chain.height

    # 场景一：半行（整块没写完就断电）
    with open(store.blocks_path, "ab") as fh:
        fh.write(good_lines[-1][:len(good_lines[-1]) // 2].encode("utf-8"))
    payload = store.load_chain()
    assert len(payload["blocks"]) == good_height + 1, \
        "半行应被回退，链高应为 %d，实际 %d" % (good_height + 1, len(payload["blocks"]) - 1)
    assert _log_lines(store) == good_lines, "回退后日志应回到完整状态"
    # mempool 里还留着的交易在下次加载时重新待打包，账不丢
    again = Blockchain(difficulty=1, store=store)
    assert again.load() and again.height == good_height, "崩溃恢复后链应完整可用"
    ok, errors = again.verify()
    assert ok, "崩溃恢复后的链应通过校验：%s" % errors[:3]

    # 场景二：完整块但缺结尾换行（fsync 前 crash 的另一种形态）
    service.publish_post(chain, store, alice, "补齐后的正常块")
    raw = open(store.blocks_path, "rb").read()
    with open(store.blocks_path, "wb") as fh:
        fh.write(raw.rstrip(b"\n"))
    payload = store.load_chain()
    assert len(payload["blocks"]) == good_height + 2, "缺换行的完整块应保留并被补齐"
    assert raw == open(store.blocks_path, "rb").read(), "重读后应补上结尾换行"
    append_after = Blockchain(difficulty=1, store=store)
    append_after.load()
    service.publish_post(append_after, store, alice, "补换行后的追加块")
    tail = _log_lines(store)[-1]
    assert json.loads(tail)["height"] == good_height + 2, "补换行后应能继续追加"
    assert all(line.startswith("{") for line in _log_lines(store)), "追加后行间不应粘连"

    # 场景三：中间行损坏不是崩溃能造成的，必须报错而不是悄悄丢块
    corrupt = good_lines[0][: len(good_lines[0]) // 2]  # 半截 JSON，必然无法解析
    assert corrupt != good_lines[0], "损坏注入未生效"
    with open(store.blocks_path, "wb") as fh:
        fh.write((corrupt + "\n" + "\n".join(good_lines[1:]) + "\n").encode("utf-8"))
    try:
        store.load_chain()
        raise AssertionError("中间行损坏应报错")
    except (StoreError, ValueError):
        pass
    return "半行回退/缺换行补齐/中行损坏报错 三种崩溃形态全部正确"


# ================================================================= 入口
CASES = (
    ("密码学基础", (
        ("椭圆曲线点运算", t_curve_base),
        ("曲线阶与无穷远点", t_curve_order),
        ("ECDSA 签名与验签", t_sign_verify),
        ("地址生成与校验", t_address),
    )),
    ("钱包加密", (
        ("ChaCha20 加密存储", t_wallet_crypto),
        ("钱包落盘与解锁", t_wallet_persist),
    )),
    ("图像指纹", (
        ("PNG 行滤波器", t_png_filters),
        ("奇数宽度与梯度图", t_png_scanline),
        ("感知哈希鲁棒性", t_phash_robust),
        ("指纹相似度判定", t_fingerprint_similarity),
    )),
    ("文本指纹", (
        ("SimHash 相似度", t_text_fingerprint),
    )),
    ("Merkle 树与工作量证明", (
        ("Merkle 存在性证明", t_merkle),
        ("工作量证明与防篡改", t_pow),
    )),
    ("区块链端到端流程", (
        ("创世区块", t_chain_genesis),
        ("作品登记确权", t_register_work),
        ("重复指纹拦截", t_duplicate_fingerprint),
        ("侵权比对命中", t_compare_hit),
        ("侵权比对不误判", t_compare_miss),
        ("版权转让", t_transfer),
        ("授权许可", t_license),
        ("待打包池与出块", t_mempool),
        ("重放攻击防护", t_replay_protection),
        ("权属争议锁定", t_dispute_lock),
        ("争议裁决解绑", t_dispute_adjudicate),
        ("整链完整性校验", t_chain_verify),
        ("篡改检测", t_tamper_detected),
        ("确权证书", t_certificate),
        ("链下原件校验", t_original_check),
        ("数据重载", t_reload),
    )),
    ("社区上链", (
        ("发帖上链", t_post_publish),
        ("回复挂父帖", t_post_reply),
        ("点赞与重复赞拦截", t_post_like),
        ("正文长度校验", t_post_limits),
        ("附图哈希上链", t_post_image),
        ("帖子篡改检测", t_post_tamper),
        ("社区数据重载", t_post_reload),
    )),
    ("平台积分", (
        ("金额换算与精度防护", t_points_units),
        ("铸造与转账往返", t_points_mint_pay),
        ("发行权限与转账防线", t_points_operator_rules),
        ("总量上限", t_points_supply_cap),
        ("积分链重载", t_points_reload),
    )),
    ("助记词钱包", (
        ("BIP39 官方向量", t_mnemonic_vectors),
        ("助记词生成与恢复", t_mnemonic_wallet),
        ("旧格式钱包兼容", t_mnemonic_legacy_compat),
        ("动态口令", t_rotpwd),
    )),
    ("开放平台", (
        ("密钥签发与吊销", t_apikeys),
        ("限流分档计数", t_apikeys_ratelimit),
        ("IP 地区识别", t_geofence),
        ("积分购买订单闭环", t_purchase_flow),
    )),
    ("存储与落盘", (
        ("追加日志与零重写提交", t_store_append_only),
        ("旧格式一次性迁移", t_store_legacy_migration),
        ("磁盘状态自愈", t_store_disk_selfheal),
        ("断电残行恢复", t_store_crash_recovery),
    )),
)


def run(verbose=True):
    print("")
    print("=" * 62)
    print("  ArtChain 内置自检")
    print("  Python %s ｜ 图像后端：%s" % (sys.version.split()[0], imagelib.backend_name()))
    print("=" * 62)
    suite = Suite(verbose=verbose)
    try:
        for group_name, cases in CASES:
            suite.group(group_name)
            for name, fn in cases:
                suite.case(name, fn)
    finally:
        _cleanup()

    print("")
    print("=" * 62)
    total = suite.passed + suite.failed
    if suite.failed == 0:
        print("  全部通过：%d / %d 项" % (suite.passed, total))
        print("=" * 62)
        return 0
    print("  通过 %d 项，失败 %d 项（共 %d 项）" % (suite.passed, suite.failed, total))
    print("")
    for group_name, name, reason in suite.failures:
        print("  [失败] %s / %s" % (group_name, name))
        print("         %s" % reason)
    print("=" * 62)
    return 1
