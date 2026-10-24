# -*- coding: utf-8 -*-
"""确权证书：把链上信息整理成可交付、可独立验证的证明文件。

证书包含三类内容：
  1. 作品档案与多维指纹（谁、何时、什么作品、指纹是什么）
  2. 上链证明（交易哈希、区块高度、区块哈希、Merkle 根与 Merkle 路径）
  3. 权属沿革与授权许可

其中 Merkle 路径使得**不依赖本系统**也能验证：
只要把 txid 按路径逐层哈希，最终能得到区块头里的 Merkle 根，
且该区块头哈希满足难度目标，即可证明这份登记确实被写进了区块链。
"""

import html
import json
import time

from .core.block import verify_merkle_proof
from .core.tx import TX_GENESIS, verify_tx, work_id_for

CERT_VERSION = "1.0"


class CertificateError(Exception):
    pass


def _fmt_time(ts):
    if not ts:
        return "—"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts)))
    except (ValueError, OSError, TypeError):
        return str(ts)


def build_certificate(chain, work_id, store=None, issuer=""):
    """生成证书数据（可直接序列化为 JSON）。"""
    work = chain.ledger.get_work(work_id)
    if work is None:
        raise CertificateError("作品不存在：%s" % work_id)
    proof = chain.proof_of(work_id)
    if proof is None:
        raise CertificateError("未能找到该作品的上链交易，无法出具证书")

    proof_valid = chain.check_proof(proof)
    license_list = chain.ledger.licenses.get(work_id, [])
    history = chain.ledger.history.get(work_id, [])
    block = chain.blocks[proof["height"]]

    cert = {
        "certificate_version": CERT_VERSION,
        "certificate_id": "ART-%s-%06d" % (work_id, proof["height"]),
        "issued_at": int(time.time()),
        "issuer": issuer or chain.ledger.chain_meta.get("operator", "") or "ArtChain 自建链",
        "chain": {
            "name": chain.ledger.chain_meta.get("name", "ArtChain 艺术品确权链"),
            "height": chain.height,
            "difficulty": chain.difficulty,
            "blocks": len(chain.blocks),
        },
        "work": {
            "work_id": work["work_id"],
            "title": work.get("title"),
            "category": work.get("category"),
            "author": work.get("author"),
            "year": work.get("year"),
            "created_at": work.get("created_at"),
            "description": work.get("description"),
            "status": work.get("status"),
            "meta": work.get("meta") or {},
        },
        "fingerprint": {
            "sha256": work.get("file_hash"),
            "phash": work.get("phash"),
            "ahash": work.get("ahash"),
            "dhash": work.get("dhash"),
            "simhash": work.get("simhash"),
            "size": work.get("size"),
            "kind": work.get("kind"),
            "mime": work.get("mime"),
            "width": work.get("image_width"),
            "height": work.get("image_height"),
        },
        "ownership": {
            "creator": work.get("creator"),
            "owner": work.get("owner"),
            "registered_at": work.get("registered_at"),
            "transfer_count": work.get("transfer_count", 0),
            "license_count": work.get("license_count", 0),
        },
        "evidence": {
            "txid": proof["txid"],
            "height": proof["height"],
            "block_hash": block["hash"],
            "block_time": block["time"],
            "block_nonce": block["nonce"],
            "block_difficulty": block["difficulty"],
            # 以下三项用于离线复核区块头哈希（缺一不可）
            "block_version": block.get("version", 1),
            "prev_hash": block.get("prev_hash"),
            "miner": block.get("miner", ""),
            "merkle_root": proof["merkle_root"],
            "merkle_proof": proof["merkle_proof"],
            "tx_index": proof["tx_index"],
            "tx_count": proof["tx_count"],
            "merkle_proof_valid": proof_valid,
        },
        "licenses": license_list,
        "history": history,
    }
    if store is not None and work.get("stored_path"):
        from . import fingerprint as fp_mod
        blob = store.blob_data(work["stored_path"])
        if blob is not None:
            cert["original_check"] = {
                "path": work["stored_path"],
                "match": fp_mod.sha256_bytes(blob) == work.get("file_hash"),
            }
    return cert


def _verify_against_chain(chain, cert, problems):
    """把证书逐项拿去和本地链比对（链上核对模式）。

    对不上就往 problems 里追加原因，返回是否全部对上。
    """
    evidence = cert.get("evidence") or {}
    work = cert.get("work") or {}
    fingerprint = cert.get("fingerprint") or {}
    ownership = cert.get("ownership") or {}
    before = len(problems)

    height = evidence.get("height")
    txid = evidence.get("txid")
    if not isinstance(height, int) or isinstance(height, bool) or not 0 <= height < len(chain.blocks):
        problems.append("证书声明的区块高度 #%s 在本地区块链上不存在" % (height,))
        return False

    block = chain.blocks[height]
    # 难度必须由链说了算。离线模式里难度取自证书自身，所以声称 difficulty=0
    # 就能平凡通过 PoW 检查——这正是假证书能成立的原因，这里把口子堵上。
    if int(block.get("difficulty", 0)) != int(evidence.get("block_difficulty") or 0):
        problems.append("证书声明的难度与链上该区块的难度不一致")
    if block.get("hash") != evidence.get("block_hash"):
        problems.append("证书声明的区块哈希与链上该高度的区块不符")
    if block.get("merkle_root") != evidence.get("merkle_root"):
        problems.append("证书声明的 Merkle 根与链上该区块不符")

    txs = block.get("txs") or []
    found = None
    for index, tx in enumerate(txs):
        if tx.get("txid") == txid:
            found = (index, tx)
            break
    if found is None:
        problems.append("证书声明的交易不在链上该区块中")
        return False

    index, tx = found
    declared_index = evidence.get("tx_index")
    if declared_index is not None and int(declared_index) != index:
        problems.append("证书声明的交易序号与链上不一致")

    # 签名有效才说明这笔登记确实是该地址签发的，而不是别人替他编的。
    is_genesis = tx.get("type") == TX_GENESIS
    ok_sig, why = verify_tx(tx, allow_genesis=is_genesis and height == 0)
    if not ok_sig:
        problems.append("链上该交易的签名校验失败：%s" % why)

    data = tx.get("data") or {}
    if data.get("work_id") != work.get("work_id"):
        problems.append("链上交易的作品编号与证书不一致")
    if data.get("file_hash") != fingerprint.get("sha256"):
        problems.append("链上交易的文件指纹与证书不一致")
    if tx.get("sender") != ownership.get("creator"):
        problems.append("链上交易的发起方与证书声明的原始权利人不一致")

    return len(problems) == before


def verify_certificate(cert, chain=None):
    """验证一份证书。两种模式的结论强度完全不同：

    **离线模式（chain=None）**只做自洽校验：证书内部的 Merkle 路径能否还原到
    它自己声明的 Merkle 根、区块头哈希能否满足它自己声明的难度。这能发现
    "证书被改动过"，但**证明不了确权成立**——任何人都可以自选指纹与作者、
    挖一个难度为 0 的独立区块，拼出一份完全自洽的证书。因此该模式返回的
    trusted 恒为 False，valid 只代表"自洽"。

    **链上核对模式（传入 chain）**把证书里的每一项都拿去和本地链比对：
    该高度确实存在那个区块、区块头各字段一致、难度符合链的规则、交易确实在
    区块里、签名有效、交易内容与证书声称的作品一致。只有这一模式通过，
    才能说"该登记确实已写入区块链"。

    调用方若把 valid 当作确权凭证使用，必须传入 chain 并同时检查 trusted。
    """
    from .core.block import block_hash, meets_difficulty

    problems = []
    notes = []
    evidence = cert.get("evidence") or {}
    work = cert.get("work") or {}
    fingerprint = cert.get("fingerprint") or {}
    ownership = cert.get("ownership") or {}

    if not evidence.get("txid") or not evidence.get("merkle_root"):
        problems.append("证书缺少交易哈希或 Merkle 根")
    else:
        if not verify_merkle_proof(evidence["txid"], evidence.get("merkle_proof") or [],
                                   evidence["merkle_root"]):
            problems.append("Merkle 存在性证明验证失败（交易可能不在该区块中）")

    # 用证书里的区块头字段重算哈希，确认工作量证明成立
    header = {
        "version": evidence.get("block_version", 1),
        "height": evidence.get("height"),
        "prev_hash": evidence.get("prev_hash"),
        "time": evidence.get("block_time"),
        "merkle_root": evidence.get("merkle_root"),
        "miner": evidence.get("miner", ""),
        "difficulty": evidence.get("block_difficulty"),
        "nonce": evidence.get("block_nonce"),
    }
    missing = [k for k in ("height", "time", "difficulty", "nonce", "prev_hash") if header.get(k) is None]
    if missing:
        problems.append("证书缺少区块头字段 %s，无法复核工作量证明" % "、".join(missing))
    else:
        recomputed = block_hash(header)
        if recomputed != evidence.get("block_hash"):
            problems.append("区块哈希重算不一致（区块头被改动）")
        elif not meets_difficulty(recomputed, int(evidence.get("block_difficulty") or 0)):
            problems.append("区块哈希不满足难度目标（工作量证明无效）")

    if fingerprint.get("sha256") and ownership.get("creator"):
        expected = work_id_for(fingerprint["sha256"], ownership["creator"])
        if work.get("work_id") and work["work_id"] != expected:
            problems.append("作品编号与指纹/权利人推导结果不一致")

    if chain is None:
        trusted = False
        notes.append("离线模式：仅核对了证书自身的自洽性，未与任何链数据比对。"
                     "自洽不等于真实——伪造者可以造出一份自洽的证书。"
                     "要确认确权成立，请改用链上核对模式（传入 chain）。")
    else:
        trusted = _verify_against_chain(chain, cert, problems)

    return {
        "valid": not problems,
        "trusted": trusted,
        "mode": "chain" if chain is not None else "offline",
        "problems": problems,
        "notes": notes,
        "certificate_id": cert.get("certificate_id"),
        "work_id": work.get("work_id"),
        "txid": evidence.get("txid"),
        "height": evidence.get("height"),
    }


def _line(label, value):
    return "  %-14s %s" % (label + "：", "—" if value in (None, "") else value)


def render_text(cert):
    """纯文本证书（适合终端打印或存档）。"""
    work = cert["work"]
    fp = cert["fingerprint"]
    ev = cert["evidence"]
    own = cert["ownership"]
    chain_info = cert["chain"]

    out = []
    out.append("=" * 70)
    out.append("                    艺术品区块链确权证书")
    out.append("=" * 70)
    out.append(_line("证书编号", cert["certificate_id"]))
    out.append(_line("出具时间", _fmt_time(cert["issued_at"])))
    out.append(_line("出具机构", cert["issuer"]))
    out.append(_line("所在链", "%s（高度 #%d，难度 %d）" % (chain_info["name"], chain_info["height"],
                                                          chain_info["difficulty"])))
    out.append("")
    out.append("【作品信息】")
    out.append(_line("作品编号", work["work_id"]))
    out.append(_line("作品名称", work["title"]))
    out.append(_line("作品类别", work["category"]))
    out.append(_line("作者署名", work["author"]))
    out.append(_line("创作年份", work.get("year")))
    out.append(_line("创作日期", work.get("created_at")))
    if work.get("description"):
        out.append(_line("作品说明", work["description"]))
    out.append("")
    out.append("【数字指纹】")
    out.append(_line("SHA-256", fp["sha256"]))
    if fp.get("phash"):
        out.append(_line("pHash", fp["phash"]))
        out.append(_line("aHash", fp.get("ahash")))
        out.append(_line("dHash", fp.get("dhash")))
    if fp.get("simhash"):
        out.append(_line("SimHash", fp["simhash"]))
    out.append(_line("文件类型", "%s / %s" % (fp.get("kind"), fp.get("mime"))))
    out.append(_line("文件大小", "%s 字节" % fp.get("size")))
    if fp.get("width"):
        out.append(_line("图像尺寸", "%s x %s" % (fp["width"], fp["height"])))
    out.append("")
    out.append("【权属状态】")
    out.append(_line("原始权利人", own["creator"]))
    out.append(_line("当前权利人", own["owner"]))
    out.append(_line("登记时间", _fmt_time(own["registered_at"])))
    out.append(_line("权属状态", work.get("status")))
    out.append(_line("转让次数", own["transfer_count"]))
    out.append(_line("许可数量", own["license_count"]))
    out.append("")
    out.append("【上链存证】")
    out.append(_line("交易哈希", ev["txid"]))
    out.append(_line("区块高度", "#%d" % ev["height"]))
    out.append(_line("区块哈希", ev["block_hash"]))
    out.append(_line("出块时间", _fmt_time(ev["block_time"])))
    out.append(_line("Merkle 根", ev["merkle_root"]))
    out.append(_line("区块内位置", "第 %d / %d 笔" % (ev["tx_index"] + 1, ev["tx_count"])))
    out.append(_line("证明校验", "通过" if ev["merkle_proof_valid"] else "未通过"))
    out.append("")
    out.append("  Merkle 存在性证明路径：")
    for depth, step in enumerate(ev["merkle_proof"]):
        out.append("    [%d] %-5s %s" % (depth, step["position"], step["hash"]))
    if "original_check" in cert:
        check = cert["original_check"]
        out.append("")
        out.append("  【原件校验】%s" % ("与链上指纹一致" if check["match"] else "与链上指纹不一致！"))
    if cert["history"]:
        out.append("")
        out.append("【权属沿革】")
        for item in cert["history"]:
            out.append("  - %s  #%s  %s  %s" % (
                _fmt_time(item.get("time")), item.get("height"), item.get("action"),
                item.get("detail", "")))
    if cert["licenses"]:
        out.append("")
        out.append("【授权许可】")
        for lic in cert["licenses"]:
            out.append("  - %s 至 %s  %s授权给 %s（地域 %s）%s" % (
                lic.get("start") or "不限", lic.get("end") or "不限", lic.get("scope"),
                lic.get("to"), lic.get("territory"),
                "，费用 %s" % lic["royalty"] if lic.get("royalty") else ""))
    out.append("")
    out.append("-" * 70)
    out.append("验证方式：任何人可用 python -m artchain verify-cert <证书文件> 独立复核。")
    out.append("验证原理：将交易哈希按上述 Merkle 路径逐层哈希，最终应得到 Merkle 根；")
    out.append("          区块头（含该根）的哈希满足前导零难度目标，即证明登记已进入区块链。")
    out.append("=" * 70)
    return "\n".join(out)


def render_html(cert):
    """自包含的 HTML 证书（浏览器打开可直接打印为 PDF）。"""
    work = cert["work"]
    fp = cert["fingerprint"]
    ev = cert["evidence"]
    own = cert["ownership"]
    esc = lambda v: html.escape("—" if v in (None, "") else str(v))

    rows = []
    for depth, step in enumerate(ev["merkle_proof"]):
        rows.append("<tr><td>%d</td><td>%s</td><td class='mono'>%s</td></tr>" % (
            depth, "左" if step["position"] == "left" else "右", esc(step["hash"])))
    proof_rows = "".join(rows) or "<tr><td colspan='3'>该区块仅含一笔交易，无需路径</td></tr>"

    history_rows = "".join(
        "<tr><td>%s</td><td>#%s</td><td>%s</td><td>%s</td><td class='mono small'>%s</td></tr>" % (
            _fmt_time(item.get("time")), esc(item.get("height")), esc(item.get("action")),
            esc(item.get("detail")), esc(item.get("txid")))
        for item in cert["history"]) or "<tr><td colspan='5'>暂无流转记录</td></tr>"

    license_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(lic.get("start")), esc(lic.get("end")), esc(lic.get("scope")), esc(lic.get("to")),
            esc(lic.get("territory")), esc(lic.get("royalty")))
        for lic in cert["licenses"]) or "<tr><td colspan='6'>暂无授权记录</td></tr>"

    status_class = "ok" if work.get("status") == "有效" else "warn"
    proof_class = "ok" if ev["merkle_proof_valid"] else "bad"

    return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>确权证书 %(cert_id)s</title>
<style>
  :root { --ink:#1a1a1a; --muted:#6b6b6b; --line:#dcd7cd; --gold:#8a6d3b; --bg:#fbf9f5; }
  * { box-sizing: border-box; }
  body { margin:0; padding:32px; background:#eee9e0; color:var(--ink);
         font-family:"Microsoft YaHei","PingFang SC","Songti SC",serif; }
  .cert { max-width:900px; margin:0 auto; background:var(--bg); padding:44px 52px;
          border:1px solid var(--line); box-shadow:0 2px 24px rgba(0,0,0,.08); }
  h1 { text-align:center; font-size:26px; letter-spacing:6px; margin:0 0 6px; }
  .sub { text-align:center; color:var(--muted); font-size:13px; letter-spacing:2px; margin-bottom:26px; }
  .seal { text-align:center; color:var(--gold); font-size:12px; letter-spacing:3px;
          border-top:1px solid var(--line); border-bottom:1px solid var(--line); padding:8px 0; margin-bottom:26px; }
  h2 { font-size:15px; margin:26px 0 10px; padding-left:10px; border-left:3px solid var(--gold); }
  table { width:100%%; border-collapse:collapse; font-size:13px; }
  td, th { padding:7px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
  th { color:var(--muted); font-weight:normal; width:150px; }
  .kv td:first-child { color:var(--muted); width:150px; }
  .mono { font-family:Consolas,Menlo,monospace; word-break:break-all; font-size:12px; }
  .small { font-size:11px; }
  .ok { color:#2c7a4b; } .warn { color:#b58900; } .bad { color:#c0392b; }
  .stamp { float:right; margin-top:10px; border:2px solid var(--gold); color:var(--gold);
           padding:8px 14px; transform:rotate(-6deg); font-size:12px; letter-spacing:2px; }
  footer { margin-top:30px; font-size:12px; color:var(--muted); line-height:1.9;
           border-top:1px dashed var(--line); padding-top:14px; }
  @media (max-width: 640px) {
    body { padding: 12px; }
    .cert { padding: 20px 16px; border-radius: 12px; }
    h1 { font-size: 20px; letter-spacing: 2px; }
    .sub { font-size: 11px; letter-spacing: 1px; margin-bottom: 16px; }
    .seal { font-size: 11px; letter-spacing: 1px; padding: 6px 0; margin-bottom: 18px; word-break: break-all; }
    table { display: block; overflow-x: auto; -webkit-overflow-scrolling: touch; }
    .kv td:first-child, th { width: 100px; min-width: 80px; }
    .stamp { float: none; display: inline-block; margin: 12px 0; }
  }
  @media print { body { background:#fff; padding:0; } .cert { box-shadow:none; border:none; } }
</style>
</head>
<body>
<div class="cert">
  <h1>艺术品区块链确权证书</h1>
  <div class="sub">ARTWORK RIGHTS CERTIFICATE ON BLOCKCHAIN</div>
  <div class="seal">证书编号 %(cert_id)s ｜ 出具时间 %(issued)s ｜ 出具机构 %(issuer)s</div>

  <h2>一、作品信息</h2>
  <table class="kv">
    <tr><td>作品编号</td><td class="mono">%(work_id)s</td></tr>
    <tr><td>作品名称</td><td>%(title)s</td></tr>
    <tr><td>作品类别</td><td>%(category)s</td></tr>
    <tr><td>作者署名</td><td>%(author)s</td></tr>
    <tr><td>创作年份</td><td>%(year)s</td></tr>
    <tr><td>创作完成日期</td><td>%(created_at)s</td></tr>
    <tr><td>作品说明</td><td>%(description)s</td></tr>
  </table>

  <h2>二、数字指纹（内容存证）</h2>
  <table class="kv">
    <tr><td>SHA-256</td><td class="mono">%(sha256)s</td></tr>
    <tr><td>感知哈希 pHash</td><td class="mono">%(phash)s</td></tr>
    <tr><td>感知哈希 aHash</td><td class="mono">%(ahash)s</td></tr>
    <tr><td>感知哈希 dHash</td><td class="mono">%(dhash)s</td></tr>
    <tr><td>文本指纹 SimHash</td><td class="mono">%(simhash)s</td></tr>
    <tr><td>文件信息</td><td>%(fileinfo)s</td></tr>
  </table>

  <h2>三、权属状态</h2>
  <table class="kv">
    <tr><td>原始权利人</td><td class="mono">%(creator)s</td></tr>
    <tr><td>当前权利人</td><td class="mono">%(owner)s</td></tr>
    <tr><td>登记时间</td><td>%(registered_at)s</td></tr>
    <tr><td>权属状态</td><td class="%(status_class)s">%(status)s</td></tr>
    <tr><td>转让 / 许可</td><td>%(transfer_count)s 次转让 ／ %(license_count)s 项许可</td></tr>
  </table>

  <h2>四、上链存证</h2>
  <table class="kv">
    <tr><td>交易哈希</td><td class="mono">%(txid)s</td></tr>
    <tr><td>所在区块</td><td>#%(height)s（共 %(chain_blocks)s 区块，当前链高 #%(chain_height)s）</td></tr>
    <tr><td>区块哈希</td><td class="mono">%(block_hash)s</td></tr>
    <tr><td>区块时间</td><td>%(block_time)s</td></tr>
    <tr><td>难度 / 随机数</td><td>%(difficulty)s ／ %(nonce)s</td></tr>
    <tr><td>Merkle 根</td><td class="mono">%(merkle_root)s</td></tr>
    <tr><td>存在性证明</td><td class="%(proof_class)s">%(proof_text)s（第 %(tx_index)s / %(tx_count)s 笔）</td></tr>
  </table>
  <table style="margin-top:10px">
    <tr><th style="width:60px">层级</th><th style="width:80px">方向</th><th>兄弟节点哈希</th></tr>
    %(proof_rows)s
  </table>

  <h2>五、权属沿革</h2>
  <table>
    <tr><th style="width:150px">时间</th><th style="width:70px">区块</th><th style="width:90px">事项</th><th>说明</th><th style="width:160px">交易哈希</th></tr>
    %(history_rows)s
  </table>

  <h2>六、授权许可</h2>
  <table>
    <tr><th>起始</th><th>截止</th><th>类型</th><th>被许可方</th><th>地域</th><th>费用</th></tr>
    %(license_rows)s
  </table>

  <div class="stamp">区块链存证</div>
  <footer>
    <b>验证方法：</b>本证书可脱离本系统独立验证——将上表 Merkle 路径从交易哈希开始逐层哈希
    （方向为"左"时把兄弟节点放在左侧），最终结果应等于 Merkle 根；再将区块头
    （版本、高度、前序哈希、时间、Merkle 根、出块人、难度、随机数）做 SHA-256，
    其结果应等于区块哈希且满足前导 %(difficulty)s 个零的难度目标。<br>
    <b>免责说明：</b>区块链存证证明的是"该数字指纹在某一时刻已被固定且此后未被篡改"，
    不构成对作品独创性、权属归属的法律认定；如发生权属纠纷，仍需结合创作过程证据依法认定。
  </footer>
</div>
</body>
</html>
""" % {
        "cert_id": esc(cert["certificate_id"]),
        "issued": esc(_fmt_time(cert["issued_at"])),
        "issuer": esc(cert["issuer"]),
        "work_id": esc(work["work_id"]),
        "title": esc(work["title"]),
        "category": esc(work["category"]),
        "author": esc(work["author"]),
        "year": esc(work.get("year")),
        "created_at": esc(work.get("created_at")),
        "description": esc(work.get("description")),
        "sha256": esc(fp["sha256"]),
        "phash": esc(fp.get("phash")),
        "ahash": esc(fp.get("ahash")),
        "dhash": esc(fp.get("dhash")),
        "simhash": esc(fp.get("simhash")),
        "fileinfo": esc("%s ｜ %s ｜ %s 字节%s" % (
            fp.get("kind"), fp.get("mime"), fp.get("size"),
            " ｜ %sx%s" % (fp["width"], fp["height"]) if fp.get("width") else "")),
        "creator": esc(own["creator"]),
        "owner": esc(own["owner"]),
        "registered_at": esc(_fmt_time(own["registered_at"])),
        "status": esc(work.get("status")),
        "status_class": status_class,
        "transfer_count": esc(own["transfer_count"]),
        "license_count": esc(own["license_count"]),
        "txid": esc(ev["txid"]),
        "height": esc(ev["height"]),
        "chain_height": esc(cert["chain"]["height"]),
        "chain_blocks": esc(cert["chain"]["blocks"]),
        "block_hash": esc(ev["block_hash"]),
        "block_time": esc(_fmt_time(ev["block_time"])),
        "difficulty": esc(ev["block_difficulty"]),
        "nonce": esc(ev["block_nonce"]),
        "merkle_root": esc(ev["merkle_root"]),
        "proof_class": proof_class,
        "proof_text": "验证通过" if ev["merkle_proof_valid"] else "验证未通过",
        "tx_index": esc(ev["tx_index"] + 1),
        "tx_count": esc(ev["tx_count"]),
        "proof_rows": proof_rows,
        "history_rows": history_rows,
        "license_rows": license_rows,
    }


def render_json(cert):
    return json.dumps(cert, ensure_ascii=False, indent=2)
