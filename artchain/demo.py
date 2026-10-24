# -*- coding: utf-8 -*-
"""一键演示：把艺术品确权的完整业务链路跑一遍。

    python -m artchain demo          使用当前数据目录演示（已有链则复用）
    python -m artchain demo --reset  先清空数据再演示

演示脚本会自动生成两幅示例画作，并模拟一个完整的场景：
画家登记确权 -> 被盗图（调亮后转载）-> 侵权比对取证 -> 版权转让 -> 授权许可
-> 权属争议锁定 -> 第三方裁决解绑 -> 证书导出与离线验证 -> 全链完整性校验
"""

import os
import time

from . import certificate, fingerprint, imagelib, service
from .core.tx import work_id_for
from .wallet import Wallet

DEMO_PASSWORD = "demo-1234"
ARTIST = "画家张三"
COLLECTOR = "收藏家李四"
# 裁决必须由与本案无利害关系的第三方发起，当事人双方都不行，
# 所以演示里必须真有第三个钱包，不能拿画家或收藏家顶替。
ARBITER = "鉴定机构"


def _line(text=""):
    print(text)


def _step(index, text):
    print("")
    print("  [%d] %s" % (index, text))
    print("  " + "-" * 60)


def _info(label, value):
    print("      %-10s %s" % (label + "：", value))


def _ensure_wallet(store, name):
    if name in store.list_wallets():
        return Wallet.load(store, name, DEMO_PASSWORD), False
    return Wallet.create(store, name, password=DEMO_PASSWORD), True


def run(ctx, reset=False, keep=True):
    store = ctx.store
    if reset and store.has_chain():
        removed = store.reset(keep_wallets=False)
        _line("  已清空旧数据：%s" % "、".join(removed))

    _line("")
    _line("=" * 64)
    _line("  ArtChain 艺术品区块链确权 —— 完整业务演示")
    _line("=" * 64)
    _line("  数据目录：%s" % store.root)
    _line("  演示口令：%s（仅用于本演示钱包）" % DEMO_PASSWORD)

    # ---------------------------------------------------------- 1 建链
    _step(1, "初始化区块链（创建创世区块）")
    if not store.has_chain():
        ctx.chain.create_genesis(name="ArtChain 艺术品确权链", operator="演示运营方",
                                 description="用于艺术品著作权存证确权的演示链")
        ctx.chain.save()
        _info("创世区块哈希", ctx.chain.blocks[0]["hash"])
    else:
        ctx.ensure_loaded()
        _info("复用已有链", "当前高度 #%d" % ctx.chain.height)
    chain = ctx.chain
    _info("挖矿难度", "%d（区块哈希需以 %d 个 0 开头）" % (chain.difficulty, chain.difficulty))

    # ---------------------------------------------------------- 2 开户
    _step(2, "创建参与方钱包")
    alice, created_a = _ensure_wallet(store, ARTIST)
    bob, created_b = _ensure_wallet(store, COLLECTOR)
    carol, created_c = _ensure_wallet(store, ARBITER)
    _info("画家", "%s  %s" % (alice.name, alice.address))
    _info("收藏家", "%s  %s" % (bob.name, bob.address))
    _info("鉴定机构", "%s  %s" % (carol.name, carol.address))
    if created_a or created_b or created_c:
        _info("私钥保护", "ChaCha20 口令加密（PBKDF2 20 万次迭代）")
    else:
        _info("私钥保护", "复用已有钱包")

    # ---------------------------------------------------------- 3 生成作品
    _step(3, "生成示例画作并保存到本地")
    demo_dir = os.path.join(store.root, "demo")
    if not os.path.isdir(demo_dir):
        os.makedirs(demo_dir)
    art_path = os.path.join(demo_dir, "作品-晨.png")
    with open(art_path, "wb") as fh:
        fh.write(imagelib.encode_png(192, 192, imagelib.make_demo_image(192, 192, variant=0)))
    _info("作品文件", art_path)

    # ---------------------------------------------------------- 4 登记确权
    _step(4, "画家《晨》登记确权（指纹上链）")
    with open(art_path, "rb") as fh:
        content = fh.read()
    # 该演示具有确定性：同一份演示文件 + 同一钱包 = 同一个作品编号
    if chain.ledger.get_work(work_id_for(fingerprint.sha256_bytes(content), alice.address)):
        _line("")
        _line("  检测到当前数据目录已经跑过一次演示，为避免破坏已有数据已自动停止。")
        _line("  如需重新演示，请执行：python -m artchain demo --reset")
        return 1
    result = service.register_work(
        chain, store, alice, content, filename="作品-晨.png", title="晨", category="美术作品",
        author="张三", year=2024, created_at="2024-03-18",
        description="布面油画 120x90cm，珠江口写生")
    work_id = result["work_id"]
    work = chain.ledger.get_work(work_id)
    _info("作品编号", work_id)
    _info("SHA-256", work["file_hash"])
    _info("pHash", work["phash"])
    _info("交易哈希", result["txid"])
    _info("所在区块", "#%d（%s）" % (result["height"],
                                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result["block_time"]))))
    _line("      -> 指纹已写入区块链，此后任何改动都会被发现")

    # ---------------------------------------------------------- 5 盗图比对
    _step(5, "模拟盗图：把作品调亮后另存并转载，进行侵权比对")
    suspect_path = os.path.join(demo_dir, "疑似侵权-调亮版.png")
    with open(suspect_path, "wb") as fh:
        fh.write(imagelib.encode_png(192, 192,
                                     imagelib.make_demo_image(192, 192, variant=0, brightness=14)))
    with open(suspect_path, "rb") as fh:
        suspect = fh.read()
    report = service.compare_content(chain, suspect, filename="疑似侵权-调亮版.png")
    best = report["results"][0]
    _info("文件字节指纹", "与原件不同（%s…）" % report["target_fingerprint"]["sha256"][:16])
    _info("感知指纹距离", "pHash %s 位 / aHash %s 位 / dHash %s 位" % (
        best["distances"].get("phash"), best["distances"].get("ahash"),
        best["distances"].get("dhash")))
    _info("相似度评分", "%.4f" % best["score"])
    _info("比对结论", best["conclusion"])
    _info("最相似作品", "《%s》（%s）" % (best["label"]["title"], best["id"]))
    _line("      -> 字节指纹不同但感知指纹高度接近，可定位到链上在先登记的作品")

    # ---------------------------------------------------------- 6 不误判
    _step(6, "反例验证：拿一幅无关作品比对，不应误判")
    other_path = os.path.join(demo_dir, "另一幅作品-几何.png")
    with open(other_path, "wb") as fh:
        fh.write(imagelib.encode_png(192, 192, imagelib.make_alt_image(192, 192)))
    with open(other_path, "rb") as fh:
        other = fh.read()
    report2 = service.compare_content(chain, other, filename="另一幅作品-几何.png",
                                      work_id=work_id)
    best2 = report2["results"][0]
    _info("相似度评分", "%.4f" % best2["score"])
    _info("比对结论", best2["conclusion"])

    # ---------------------------------------------------------- 7 转让
    _step(7, "版权转让：画家把《晨》转让给收藏家")
    transfer = service.transfer_work(chain, store, alice, work_id, bob.address,
                                     price="12000.00", note="画廊成交")
    _info("受让方", bob.address)
    _info("转让价款", "12000.00 元")
    _info("交易哈希", transfer["txid"])
    _info("当前权利人", chain.ledger.owner_of(work_id))

    # ---------------------------------------------------------- 8 授权
    _step(8, "授权许可：收藏家向画家授予独家出版授权")
    lic = service.license_work(chain, store, bob, work_id, alice.address, scope="独家",
                               territory="中国大陆", royalty="800.00",
                               start="2026-01-01", end="2028-12-31", purpose="画册出版")
    _info("被许可方", alice.address)
    _info("授权类型", "独家 / 中国大陆 / 2026-01-01 至 2028-12-31")
    _info("交易哈希", lic["txid"])

    # ---------------------------------------------------------- 9 争议
    _step(9, "权属争议：第三方对该作品提出异议")
    service.dispute_work(chain, store, alice, work_id, "该作品实为本人 2023 年创作，被抢先登记",
                         evidence_hash="a" * 64)
    _info("作品状态", chain.ledger.get_work(work_id)["status"])
    blocked = False
    try:
        service.transfer_work(chain, store, bob, work_id, alice.address)
    except service.ServiceError:
        blocked = True
    _info("转让校验", "已阻断（争议期间禁止转让）" if blocked else "未阻断（异常）")

    # ---------------------------------------------------------- 10 裁决
    _step(10, "争议裁决：无关第三方驳回异议，作品解除锁定")
    # 异议人是画家、权利人是收藏家，两个人都是本案当事人，都不能裁决，
    # 必须由与本案无关的鉴定机构作出——链上会拒绝当事人自行裁决。
    service.adjudicate_work(chain, store, carol, work_id, "驳回",
                            "异议人提交的底稿无法证明创作时间早于登记时间，异议不成立")
    _info("裁决人", "%s  %s" % (carol.name, carol.address))
    _info("裁决结论", "驳回异议（异议不成立，维持原登记）")
    _info("作品状态", chain.ledger.get_work(work_id)["status"])
    _info("待裁决争议", "%d 起" % chain.ledger.stats()["disputes_open"])
    # "锁解开了"不能只靠打印状态断言——真的发起一笔转让，看它是否还被拦。
    reopened = True
    try:
        service.transfer_work(chain, store, bob, work_id, alice.address, price="12000.00",
                              note="争议裁决后恢复流转")
    except service.ServiceError:
        reopened = False
    _info("转让校验", "已放行（争议已裁决，作品恢复流转）" if reopened else "仍被阻断（异常）")
    # ValueError 在 cli.main 的捕获清单里，会以一行可读的错误退出，
    # 而不是甩一段 traceback 给用户。
    if not blocked or not reopened:
        raise ValueError("争议锁定或裁决解绑的行为与预期不符，演示中止")

    # ---------------------------------------------------------- 11 证书
    _step(11, "导出确权证书并做链上核对")
    cert = certificate.build_certificate(chain, work_id, store=store, issuer="演示运营方")
    cert_path = os.path.join(demo_dir, "确权证书-%s.html" % work_id)
    with open(cert_path, "w", encoding="utf-8") as fh:
        fh.write(certificate.render_html(cert))
    json_path = os.path.join(demo_dir, "确权证书-%s.json" % work_id)
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(certificate.render_json(cert))
    # 传 chain 才是链上核对模式——只做离线自洽校验证明不了确权成立。
    verify = certificate.verify_certificate(cert, chain=chain)
    _info("HTML 证书", cert_path)
    _info("JSON 证书", json_path)
    _info("Merkle 层数", "%d 层" % len(cert["evidence"]["merkle_proof"]))
    _info("链上核对", "通过" if verify["trusted"] else "未通过：%s" % verify["problems"])
    _line("      -> 可用 python -m artchain verify-cert --file \"%s\" 独立复核" % json_path)

    # ---------------------------------------------------------- 12 全链校验
    _step(12, "全链完整性校验")
    ok, errors = chain.verify()
    stats = chain.statistics()
    _info("区块高度", "#%d（共 %d 个区块）" % (stats["height"], stats["blocks"]))
    _info("交易总数", sum(len(b["txs"]) for b in chain.blocks))
    _info("作品总数", "%d 件" % stats["works_total"])
    _info("校验结果", "通过" if ok else "失败：%s" % errors[:3])

    # ---------------------------------------------------------- 收尾
    _line("")
    _line("=" * 64)
    _line("  演示完成。接下来可以：")
    _line("    python -m artchain status                      查看链概览")
    _line("    python -m artchain works                       查看全部确权作品")
    _line("    python -m artchain work --id %s" % work_id)
    _line("    python -m artchain serve --open                打开网页版界面")
    _line("    python -m artchain selftest                    运行内置自检")
    _line("")
    _line("  演示生成的文件都在：%s" % demo_dir)
    _line("=" * 64)
    return 0
