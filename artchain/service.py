# -*- coding: utf-8 -*-
"""业务服务层：把「钱包 + 指纹 + 区块链」串成一个个可复用的确权动作。

CLI 和 HTTP API 都调用这一层，保证两条入口的行为与校验完全一致。
每个动作的典型流程是：
    采集指纹 -> 构造交易 -> 钱包签名 -> 提交交易池 -> （可选）立即出块上链
"""

import mimetypes
import os
import secrets
import time

from . import fingerprint as fp_mod
from .core.block import merkle_proof
from .core.tx import (RULING_REJECT, RULING_UPHOLD, RULINGS, TX_ADJUDICATE, TX_BURN,
                      TX_DISPUTE, TX_LICENSE, TX_LIKE, TX_MINT, TX_PAY, TX_POST, TX_REGISTER,
                      TX_REVOKE, TX_TRANSFER, TxError, make_tx, normalize_amount,
                      normalize_date, points_to_units, post_id_for, sign_tx, units_to_text,
                      work_id_for)
from .crypto.base58 import b58check_decode
from .geofence import REGION_CN
from .wallet import WalletError

# 作品类别（可自由扩展，此处给出常用选项）
CATEGORIES = ("美术作品", "摄影作品", "书法作品", "文字作品", "设计作品", "雕塑作品",
              "音乐作品", "影视作品", "数字艺术", "工艺美术", "其他")


class ServiceError(Exception):
    """业务动作失败。"""


# ---------------------------------------------------------------- 基础工具
def next_nonce_for(chain, address):
    """计算某地址下一笔交易应使用的 nonce（链上已用 + 池中已排队）。"""
    nonce = chain.ledger.next_nonce(address)
    for tx in chain.mempool:
        if tx.get("sender") == address:
            nonce = max(nonce, int(tx.get("nonce", 0)) + 1)
    return nonce


def guess_mime(filename):
    if not filename:
        return "application/octet-stream"
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def _submit_and_finish(chain, store, tx, auto_mine=True, miner=None):
    ok, message = chain.submit(tx)
    if not ok:
        raise ServiceError(message)
    block = None
    if auto_mine:
        block = chain.mine(miner or tx["sender"])
    # 不需要显式 save()：submit 落交易池、mine 落区块都已各自增量落盘，
    # 这里再整链重写一次纯属双写（链越长浪费越大）。
    return {
        "txid": tx["txid"],
        "type": tx["type"],
        "submitted": True,
        "mined": block is not None,
        "height": block["height"] if block else None,
        "block_hash": block["hash"] if block else None,
        "block_time": block["time"] if block else None,
        "message": "已上链" if block else "已进入待打包池（执行 mine 后上链）",
    }


# ---------------------------------------------------------------- 登记确权
def register_work(chain, store, wallet, content, filename="", title=None, category="美术作品",
                  author="", year=None, created_at="", description="", meta=None,
                  store_file=True, auto_mine=True):
    """把一件作品登记上链完成确权。content 为 bytes。"""
    if not content:
        raise ServiceError("作品内容为空，无法登记")
    title = (title or "").strip() or (os.path.splitext(filename)[0] if filename else "未命名作品")
    if category not in CATEGORIES:
        category = "其他"

    fp = fp_mod.fingerprint_bytes(content, filename=filename)
    work_id = work_id_for(fp["sha256"], wallet.address)

    stored_path = ""
    if store is not None and store_file:
        suffix = os.path.splitext(filename)[1].lower().lstrip(".") if filename else ""
        stored_path = store.save_blob(content, fp["sha256"], suffix)

    data = {
        "work_id": work_id,
        "title": title,
        "category": category,
        "author": author or "",
        "year": year,
        "created_at": created_at or "",
        "description": description or "",
        "meta": meta or {},
        "file_hash": fp["sha256"],
        "size": fp["size"],
        "kind": fp["kind"],
        "phash": fp["phash"],
        "ahash": fp["ahash"],
        "dhash": fp["dhash"],
        "simhash": fp["simhash"],
        "width": fp["width"],
        "height": fp["height"],
        "mime": guess_mime(filename),
        "stored_path": stored_path,
    }
    try:
        tx = make_tx(TX_REGISTER, wallet.address, wallet.pubkey, data,
                     nonce=next_nonce_for(chain, wallet.address))
        sign_tx(tx, wallet.private_key())
    except (TxError, WalletError) as exc:
        raise ServiceError("构造登记交易失败：%s" % exc)

    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result.update({"work_id": work_id, "fingerprint": fp, "title": title,
                   "filename": filename, "stored_path": stored_path})
    return result


# ---------------------------------------------------------------- 版权转让
def transfer_work(chain, store, wallet, work_id, to, price=None, note="", auto_mine=True):
    price = normalize_amount(price, "转让价款")
    data = {"work_id": work_id, "to": to, "price": price, "note": note}
    tx = make_tx(TX_TRANSFER, wallet.address, wallet.pubkey, data,
                 nonce=next_nonce_for(chain, wallet.address))
    sign_tx(tx, wallet.private_key())
    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result.update({"work_id": work_id, "to": to, "price": price})
    return result


# ---------------------------------------------------------------- 授权许可
def license_work(chain, store, wallet, work_id, to, scope="非独家", territory="全球",
                 royalty=None, start=None, end=None, purpose="", auto_mine=True):
    royalty = normalize_amount(royalty, "授权费用")
    start = normalize_date(start, "授权起始日")
    end = normalize_date(end, "授权截止日")
    data = {"work_id": work_id, "to": to, "scope": scope, "territory": territory,
            "royalty": royalty, "start": start, "end": end, "purpose": purpose}
    tx = make_tx(TX_LICENSE, wallet.address, wallet.pubkey, data,
                 nonce=next_nonce_for(chain, wallet.address))
    sign_tx(tx, wallet.private_key())
    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result.update({"work_id": work_id, "to": to, "scope": scope})
    return result


# ---------------------------------------------------------------- 权属争议
def dispute_work(chain, store, wallet, work_id, reason, evidence_hash="", auto_mine=True):
    data = {"work_id": work_id, "reason": reason, "evidence_hash": evidence_hash}
    tx = make_tx(TX_DISPUTE, wallet.address, wallet.pubkey, data,
                 nonce=next_nonce_for(chain, wallet.address))
    sign_tx(tx, wallet.private_key())
    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result.update({"work_id": work_id})
    return result


# ---------------------------------------------------------------- 撤销登记
def revoke_work(chain, store, wallet, work_id, reason="", auto_mine=True):
    data = {"work_id": work_id, "reason": reason or "权利人主动撤回"}
    tx = make_tx(TX_REVOKE, wallet.address, wallet.pubkey, data,
                 nonce=next_nonce_for(chain, wallet.address))
    sign_tx(tx, wallet.private_key())
    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result.update({"work_id": work_id})
    return result


# ---------------------------------------------------------------- 争议裁决
def adjudicate_work(chain, store, wallet, work_id, ruling, reason, evidence_hash="",
                    auto_mine=True):
    """对一件争议中的作品作出裁决。ruling 取「驳回」或「支持」。

    权限由状态机把关（任何非当事人第三方），这里只做参数形状检查，
    让错误在构造交易之前就报出来，而不是等挖完矿才失败。
    """
    ruling = str(ruling or "").strip()
    if ruling not in RULINGS:
        raise ServiceError("裁决结论只能是「%s」或「%s」，收到 %r" % (
            RULING_REJECT, RULING_UPHOLD, ruling))
    reason = str(reason or "").strip()
    if not reason:
        raise ServiceError("裁决理由不能为空")
    data = {"work_id": work_id, "ruling": ruling, "reason": reason,
            "evidence_hash": evidence_hash or ""}
    tx = make_tx(TX_ADJUDICATE, wallet.address, wallet.pubkey, data,
                 nonce=next_nonce_for(chain, wallet.address))
    sign_tx(tx, wallet.private_key())
    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result.update({"work_id": work_id, "ruling": ruling})
    return result


# ---------------------------------------------------------------- 手动出块
def mine_now(chain, store, miner_address, timestamp=None):
    block = chain.mine(miner_address or "", timestamp=timestamp)
    # mine() 出块时已增量落盘，这里不再整链重写。
    return {"height": block["height"], "hash": block["hash"], "tx_count": len(block["txs"]),
            "time": block["time"], "nonce": block["nonce"], "difficulty": block["difficulty"]}


# ---------------------------------------------------------------- 侵权比对
def compare_content(chain, content, filename="", work_id=None, top=10):
    """把一份可疑文件与链上已登记作品逐一比对，返回相似度排行。"""
    if not content:
        raise ServiceError("比对内容为空")
    target = fp_mod.fingerprint_bytes(content, filename=filename)

    if work_id:
        work = chain.ledger.get_work(work_id)
        if work is None:
            raise ServiceError("作品不存在：%s" % work_id)
        works = [work]
    else:
        works = chain.ledger.list_works()

    candidates = []
    for work in works:
        candidates.append({
            "id": work["work_id"],
            "fingerprint": {
                "sha256": work.get("file_hash"),
                "phash": work.get("phash"),
                "ahash": work.get("ahash"),
                "dhash": work.get("dhash"),
                "simhash": work.get("simhash"),
                "kind": work.get("kind"),
            },
            "label": {
                "work_id": work["work_id"],
                "title": work.get("title"),
                "author": work.get("author"),
                "owner": work.get("owner"),
                "category": work.get("category"),
                "status": work.get("status"),
                "registered_at": work.get("registered_at"),
                "height": work.get("height"),
                "txid": work.get("txid"),
                "size": work.get("size"),
                "kind": work.get("kind"),
                # 前端比对结果里要展示作品缩略图，带上链下原件的路径
                #（前端自行判断是否存在、加载失败则隐藏）。
                "stored_path": work.get("stored_path"),
            },
        })

    results = fp_mod.compare_against(target, candidates)
    return {
        "target_fingerprint": target,
        "checked": len(candidates),
        "results": results[:max(1, int(top))],
        "risk": _risk_summary(results),
    }


def _risk_summary(results):
    if not results:
        return {"level": 0, "text": "链上暂无可比对的作品"}
    best = results[0]
    return {
        "level": best["level"],
        "score": best["score"],
        "text": best["conclusion"],
        "work_id": best["id"],
        "title": (best.get("label") or {}).get("title"),
    }


def compare_against_registered(chain, file_hash):
    """仅凭文件哈希（不加载原件）快速判断该文件是否已登记。"""
    work = chain.ledger.find_by_file_hash(file_hash)
    return work


# ---------------------------------------------------------------- 原件校验
def verify_original(chain, store, work_id):
    """校验链下保存的原件是否仍与链上指纹一致（防调包）。"""
    work = chain.ledger.get_work(work_id)
    if work is None:
        raise ServiceError("作品不存在：%s" % work_id)
    stored = work.get("stored_path")
    if not stored or store is None:
        return {"available": False, "reason": "该作品未在本地保存原件（仅上链指纹）"}
    blob = store.blob_data(stored)
    if blob is None:
        return {"available": False, "reason": "原件文件已丢失：%s" % stored}
    actual = fp_mod.sha256_bytes(blob)
    return {
        "available": True,
        "match": actual == work.get("file_hash"),
        "expected": work.get("file_hash"),
        "actual": actual,
        "path": stored,
        "message": "原件与链上指纹一致" if actual == work.get("file_hash") else "原件已被改动，与链上指纹不符！",
    }


# ---------------------------------------------------------------- 权属查询
def work_detail(chain, work_id):
    """汇总一件作品的确权全貌（档案 + 历史 + 许可 + 上链证明）。"""
    work = chain.ledger.get_work(work_id)
    if work is None:
        raise ServiceError("作品不存在：%s" % work_id)
    proof = chain.proof_of(work_id)
    if proof:
        proof["valid"] = chain.check_proof(proof)
    return {
        "work": work,
        "history": chain.ledger.history.get(work_id, []),
        "licenses": chain.ledger.licenses.get(work_id, []),
        # 前端要靠这个判断"这件作品有没有悬着的异议"，
        # 光看 status == 争议中 不够——还得知道是谁提的、为什么，
        # 以及裁决后这条异议变成了什么结果。
        "disputes": [d for d in chain.ledger.disputes if d.get("work_id") == work_id],
        "proof": proof,
    }


def owner_history(chain, address):
    """某地址名下的作品与参与的流转。"""
    owned = chain.ledger.list_works(owner=address)
    created = [w for w in chain.ledger.works.values() if w.get("creator") == address]
    return {"address": address, "owned": owned, "created": created,
            "owned_count": len(owned), "created_count": len(created)}


# ---------------------------------------------------------------- 社区发帖
def publish_post(chain, store, wallet, text, topic="", reply_to="",
                 image=None, image_name="", auto_mine=True):
    """发布社区帖子（reply_to 非空即为回复）。

    与作品登记同构的存储策略：文字全文上链，附图只把 SHA-256 写上链，
    原件存进链下 files/（stored_path 会被状态机按链规则校验）。
    """
    text = str(text or "").strip()
    if not text:
        raise ServiceError("帖子正文不能为空")
    if len(text) > 2000:
        raise ServiceError("帖子正文过长（最多 2000 字）")

    image_hash = ""
    stored_path = ""
    if image:
        image_hash = fp_mod.sha256_bytes(image)
        if store is not None:
            suffix = os.path.splitext(image_name or "")[1].lower().lstrip(".")
            stored_path = store.save_blob(image, image_hash, suffix)

    data = {
        "text": text,
        "topic": str(topic or "").strip(),
        "reply_to": str(reply_to or "").strip(),
        "image_hash": image_hash,
        "stored_path": stored_path,
    }
    try:
        tx = make_tx(TX_POST, wallet.address, wallet.pubkey, data,
                     nonce=next_nonce_for(chain, wallet.address))
        sign_tx(tx, wallet.private_key())
    except (TxError, WalletError) as exc:
        raise ServiceError("构造发帖交易失败：%s" % exc)

    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result.update({"post_id": post_id_for(tx["txid"]), "text": text,
                   "topic": data["topic"], "image_hash": image_hash,
                   "stored_path": stored_path})
    return result


# ---------------------------------------------------------------- 社区点赞
def like_post(chain, store, wallet, post_id, auto_mine=True):
    post_id = str(post_id or "").strip()
    if not post_id:
        raise ServiceError("缺少帖子编号")
    data = {"post_id": post_id}
    try:
        tx = make_tx(TX_LIKE, wallet.address, wallet.pubkey, data,
                     nonce=next_nonce_for(chain, wallet.address))
        sign_tx(tx, wallet.private_key())
    except (TxError, WalletError) as exc:
        raise ServiceError("构造点赞交易失败：%s" % exc)
    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result.update({"post_id": post_id})
    return result


# ---------------------------------------------------------------- 平台积分
def _points_result(result, chain):
    """把积分动作的返回体补上余额展示（整数单位 -> 人类可读文本）。"""
    result["amount_text"] = units_to_text(result.get("amount", 0))
    result["supply_text"] = units_to_text(chain.ledger.total_supply)
    return result


def transfer_points(chain, store, wallet, to, amount, memo="", auto_mine=True):
    """把积分转给另一个地址。amount 接受整数或字符串（最多 8 位小数）。"""
    amount_units = points_to_units(amount, "转账金额")
    data = {"to": str(to or "").strip(), "amount": amount_units, "memo": str(memo or "")}
    tx = make_tx(TX_PAY, wallet.address, wallet.pubkey, data,
                 nonce=next_nonce_for(chain, wallet.address))
    sign_tx(tx, wallet.private_key())
    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result["amount"] = amount_units
    result["to"] = data["to"]
    return _points_result(result, chain)


def mint_points(chain, store, wallet, amount, memo="", auto_mine=True):
    """铸造积分（仅限运营方地址，权限由状态机把关）。"""
    amount_units = points_to_units(amount, "铸造数量")
    data = {"amount": amount_units, "memo": str(memo or "")}
    tx = make_tx(TX_MINT, wallet.address, wallet.pubkey, data,
                 nonce=next_nonce_for(chain, wallet.address))
    sign_tx(tx, wallet.private_key())
    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result["amount"] = amount_units
    result["to"] = wallet.address
    return _points_result(result, chain)


def burn_points(chain, store, wallet, amount, memo="", auto_mine=True):
    """销毁积分（仅限运营方地址）。"""
    amount_units = points_to_units(amount, "销毁数量")
    data = {"amount": amount_units, "memo": str(memo or "")}
    tx = make_tx(TX_BURN, wallet.address, wallet.pubkey, data,
                 nonce=next_nonce_for(chain, wallet.address))
    sign_tx(tx, wallet.private_key())
    result = _submit_and_finish(chain, store, tx, auto_mine=auto_mine)
    result["amount"] = amount_units
    result["from"] = wallet.address
    return _points_result(result, chain)


# ================================================================= 积分购买
# 售卖平台积分：买家选通道（微信支付 / USDT / ETH）下单，按对价付款后由运营方铸造
# 并交付给买家地址。加密货币通道对识别为中国大陆的访问方默认关闭（依 924 通知
# 合规要求，由 geofence 模块判定）。
#
# 关键设计：
#   - 订单是合法可追溯的台账（落盘 purchase_orders.json），每笔订单都有固定 ID、
#     买家地址、积分数量、支付通道、对价金额、状态机（pending → paid → delivered
#     或 canceled/expired），便于对账与审计；
#   - 价格表与收款地址都从 store 配置里读，operator 可以按市场行情调整；
#   - 积分按 8 位整数精度计算；对价仅用于显示，不影响链上数值一致；
#   - 关闭支付通道不等于禁止拥有积分——CN IP 仍可使用微信通道，且已有积分可继续
#     在链内流通。
ORDER_TTL_SECONDS = 30 * 60            # 订单 30 分钟未付款自动过期
RAIL_ORDER = ("wechat", "alipay", "unionpay", "usdt", "eth")

DEFAULT_RAILS = {
    "wechat":   {"label": "微信支付",   "currency": "CNY",
                 "points_per_unit": 10,     "crypto": False},
    "alipay":   {"label": "支付宝",     "currency": "CNY",
                 "points_per_unit": 10,     "crypto": False},
    "unionpay": {"label": "银联",       "currency": "CNY",
                 "points_per_unit": 10,     "crypto": False},
    "usdt":     {"label": "USDT 稳定币", "currency": "USDT",
                 "points_per_unit": 70,     "crypto": True},
    "eth":      {"label": "以太坊 ETH",  "currency": "ETH",
                 "points_per_unit": 200000, "crypto": True},
}

CN_LOCKED_REASON = ("加密货币支付功能不面向中国大陆地区开放（依 924 通知合规要求）。"
                    "如认为地区识别有误，请联系客服。")


def _config_rails(store):
    """合并默认通道定义与 store 配置文件里的覆盖项。"""
    config = store.load_config()
    overrides = config.get("price_book") or {}
    out = {k: dict(v) for k, v in DEFAULT_RAILS.items()}
    for rail, spec in overrides.items():
        merged = dict(out.get(rail, {"currency": rail, "points_per_unit": 1, "crypto": True}))
        for k, v in spec.items():
            merged[k] = v
        out[rail] = merged
    return out


def purchase_methods(store, region):
    """根据当前地区返回可见支付通道列表与锁定原因。"""
    rails = _config_rails(store)
    result = []
    for rid in RAIL_ORDER:
        spec = rails.get(rid) or {}
        locked = bool(spec.get("crypto")) and region == REGION_CN
        result.append({"id": rid, "label": spec.get("label", rid.upper()),
                       "currency": spec.get("currency", ""),
                       "points_per_unit": int(spec.get("points_per_unit") or 1),
                       "crypto": bool(spec.get("crypto")),
                       "available": not locked,
                       "locked_reason": CN_LOCKED_REASON if locked else ""})
    return result


def _validate_address(address):
    try:
        raw = b58check_decode(address)
    except (ValueError, Exception) as exc:               # noqa: BLE001
        raise ServiceError("收款地址格式不合法：%s" % exc)
    if len(raw) not in (20, 21):                          # pubkey hash (20) 或带前缀 (21)
        raise ServiceError("收款地址格式不合法")


def _expiration_sweep(orders, now=None):
    now = now or int(time.time())
    for order in orders:
        if order.get("status") == "pending" and order.get("expires_at", 0) < now:
            order["status"] = "expired"
    return orders


def create_purchase_order(store, address, points, rail, region, client_ip=""):
    """创建订单。汇率按 1 单位法币/币 → points_per_unit 积分计算对价（仅展示）。"""
    if rail not in RAIL_ORDER:
        raise ServiceError("不支持的支付通道：%s" % rail)
    rails = _config_rails(store)
    spec = rails[rail]
    if spec.get("crypto") and region == REGION_CN:
        raise ServiceError(CN_LOCKED_REASON)
    _validate_address(address)
    units = points_to_units(points, "购买数量")
    points_text = units_to_text(units)
    ppu = int(spec["points_per_unit"])
    amount_value = units / 10**8 / ppu
    decimals = 6 if spec.get("currency") == "ETH" else 2
    amount_text = ("%%.%df" % decimals) % amount_value
    order_id = "PO-" + secrets.token_hex(6).upper()
    now = int(time.time())
    config = store.load_config()
    deposit = (config.get("payment_addresses") or {}).get(rail, "")
    instructions = {
        "wechat":   ("请使用微信扫码向商户付款 %s %s，并备注订单号 %s。"
                     "（演示版未接入真实商户；正式上线时替换为商户二维码或 JSAPI 下单链接）")
                    % (amount_text, spec.get("currency", ""), order_id),
        "alipay":   ("请使用支付宝扫码向商户付款 %s %s，并备注订单号 %s。"
                     "（演示版未接入真实商户；正式上线时替换为商户二维码或扫码下单链接）")
                    % (amount_text, spec.get("currency", ""), order_id),
        "unionpay": ("请使用银联（云闪付 / 银联在线）向商户付款 %s %s，并备注订单号 %s。"
                     "（演示版未接入真实商户；正式上线时替换为银联收银台或云闪付二维码）")
                    % (amount_text, spec.get("currency", ""), order_id),
        "usdt":     ("请向收款地址 %s 转账 %s %s（ERC20/TRC20 可在 config 中分别配置）。"
                   "转账后请在客服处提供交易哈希以便加速确认。订单号：%s")
                    % (deposit or "<未配置收款地址>", amount_text,
                       spec.get("currency", ""), order_id),
        "eth":      ("请向收款地址 %s 转账 %s ETH（主网，gas 由发送方自付）。"
                   "转账后请在客服处提供交易哈希以便加速确认。订单号：%s")
                    % (deposit or "<未配置收款地址>", amount_text, order_id),
    }
    order = {
        "id": order_id, "buyer": address,
        "points_units": int(units), "points_text": points_text,
        "rail": rail, "region": region, "client_ip": client_ip,
        "currency": spec.get("currency", ""),
        "amount_text": amount_text, "amount_decimals": decimals,
        "status": "pending", "created_at": now,
        "expires_at": now + ORDER_TTL_SECONDS,
        "payment_ref": "", "instructions": instructions[rail],
        "delivered_txids": [], "delivered_height": None,
        "delivered_at": None, "note": ""}
    return store.append_purchase_order(order)


def list_purchase_orders(store, address=None, status=None, sweep_expired=True):
    orders = store.load_purchase_orders()
    if sweep_expired:
        _expiration_sweep(orders)
        store.save_purchase_orders(orders)
    result = orders
    if address:
        result = [o for o in result if o.get("buyer") == address]
    if status:
        result = [o for o in result if o.get("status") == status]
    return list(reversed(result))


def cancel_purchase_order(store, order_id):
    orders = store.load_purchase_orders()
    hit = next((o for o in orders if o["id"] == order_id), None)
    if hit is None:
        raise ServiceError("订单不存在：%s" % order_id)
    if hit["status"] != "pending":
        raise ServiceError("当前状态 %s，不可取消" % hit["status"])
    hit["status"] = "canceled"
    hit["canceled_at"] = int(time.time())
    store.save_purchase_orders(orders)
    return hit


def confirm_payment(chain, store, wallet, order_id, payment_ref=""):
    """运营方确认收款后调用：先 MINT 到运营方自身，再 PAY 到买家地址。

    兼容性模式（运营方地址为空）下任何钱包都可作为铸造者；生产环境应在链创世时
    设置 operator_address 字段限定铸造权限。"""
    orders = store.load_purchase_orders()
    _expiration_sweep(orders)
    store.save_purchase_orders(orders)
    order = next((o for o in orders if o["id"] == order_id), None)
    if order is None:
        raise ServiceError("订单不存在：%s" % order_id)
    if order["status"] not in ("pending",):
        raise ServiceError("订单当前状态 %s，不可重复确认" % order["status"])
    if order["buyer"] == wallet.address:
        raise ServiceError("不能用自己的钱包给同一订单交付积分，请用运营方钱包")
    units = int(order["points_units"])
    points_text = order["points_text"]
    order_id_ = order["id"]
    mint_result = mint_points(chain, store, wallet, points_text,
                              memo="订单 %s 铸造" % order_id_, auto_mine=True)
    transfer_result = transfer_points(chain, store, wallet, order["buyer"],
                                      points_text, memo="订单 %s 交付" % order_id_,
                                      auto_mine=True)
    order["status"] = "delivered"
    order["payment_ref"] = payment_ref or order.get("payment_ref") or ""
    order["delivered_txids"] = [mint_result.get("txid"), transfer_result.get("txid")]
    order["delivered_height"] = (transfer_result.get("height") or
                                 mint_result.get("height"))
    order["delivered_at"] = int(time.time())
    store.update_purchase_order(order_id_,
        status=order["status"], payment_ref=order["payment_ref"],
        delivered_txids=order["delivered_txids"],
        delivered_height=order["delivered_height"],
        delivered_at=order["delivered_at"])
    return {"order": order, "mint": mint_result, "transfer": transfer_result}


def points_overview(chain, address=None, limit=50):
    """积分概览：流通量、持币人数、可选某地址的余额与最近流水。"""
    ledger = chain.ledger
    log = ledger.points_log
    recent = []
    for entry in reversed(log):
        if address and entry.get("from") != address and entry.get("to") != address:
            continue
        recent.append({
            "type": entry["type"],
            "from": entry.get("from"),
            "to": entry.get("to"),
            "amount": entry["amount"],
            "amount_text": units_to_text(entry["amount"]),
            "memo": entry.get("memo") or "",
            "time": entry["time"],
            "height": entry["height"],
            "txid": entry["txid"],
        })
        if len(recent) >= limit:
            break
    overview = {
        "supply": ledger.total_supply,
        "supply_text": units_to_text(ledger.total_supply),
        "holders": sum(1 for v in ledger.balances.values() if int(v) > 0),
        "operator": ledger.chain_meta.get("operator") or "",
        "operator_address": ledger.chain_meta.get("operator_address") or "",
        "max_supply": ledger.chain_meta.get("max_supply"),
        "max_supply_text": (units_to_text(ledger.chain_meta.get("max_supply"))
                            if ledger.chain_meta.get("max_supply") else ""),
        "recent": recent,
        "recent_total": len(log),
    }
    if address:
        overview["address"] = address
        overview["balance"] = int(ledger.balances.get(address, 0))
        overview["balance_text"] = units_to_text(overview["balance"])
    return overview


def units_balance_text(chain, address):
    """某地址积分余额的展示文本。"""
    return units_to_text(int(chain.ledger.balances.get(address, 0)))


def top_balances(chain, limit=20):
    """余额排行（供概览页展示）。"""
    items = sorted(
        ((addr, int(v)) for addr, v in chain.ledger.balances.items() if int(v) > 0),
        key=lambda pair: pair[1], reverse=True)
    return [{"address": addr, "balance": v, "balance_text": units_to_text(v)}
            for addr, v in items[:limit]]


# ---------------------------------------------------------------- 社区查询
def _post_view(chain, post, viewer=None):
    """把一条帖子组装成前端要的结构（赞数、回复数、我是否已赞）。"""
    post_id = post["post_id"]
    liked_by = chain.ledger.likes.get(post_id, [])
    view = dict(post)
    view["likes"] = len(liked_by)
    view["replies"] = int(chain.ledger.reply_counts.get(post_id, 0))
    view["liked_by_viewer"] = bool(viewer) and viewer in liked_by
    return view


def list_posts(chain, author=None, topic=None, limit=50, viewer=None, with_replies=False):
    """帖子列表，新的在前。默认只列顶层帖，回复通过 post_detail 挂在父帖下。"""
    posts = list(chain.ledger.posts.values())
    if not with_replies:
        posts = [p for p in posts if not p.get("reply_to")]
    if author:
        posts = [p for p in posts if p.get("author") == author]
    if topic:
        posts = [p for p in posts if p.get("topic") == topic]
    posts.sort(key=lambda p: (p.get("time", 0), p.get("post_id", "")), reverse=True)
    try:
        limit = max(1, min(int(limit or 50), 200))
    except (TypeError, ValueError):
        limit = 50
    return {"total": len(posts),
            "posts": [_post_view(chain, p, viewer) for p in posts[:limit]]}


def post_detail(chain, post_id, viewer=None):
    """单帖全貌：正文、父帖、回复、点赞名单、Merkle 存在性证明。"""
    post = chain.ledger.posts.get(post_id)
    if post is None:
        raise ServiceError("帖子不存在：%s" % post_id)
    replies = [p for p in chain.ledger.posts.values() if p.get("reply_to") == post_id]
    replies.sort(key=lambda p: (p.get("time", 0), p.get("post_id", "")))
    parent = chain.ledger.posts.get(post.get("reply_to") or "")

    # 与作品确权证明（Blockchain.proof_of）完全同构的存在性证明——
    # proof_of 只认作品编号，帖子在这里照方抓药：同一套 find_tx + merkle_proof。
    proof = None
    block, tx, pos = chain.find_tx(post.get("txid"))
    if block is not None:
        proof = {
            "post_id": post_id,
            "txid": tx["txid"],
            "height": block["height"],
            "block_hash": block["hash"],
            "block_time": block["time"],
            "merkle_root": block["merkle_root"],
            "merkle_proof": merkle_proof([t["txid"] for t in block["txs"]], pos),
            "tx_index": pos,
            "tx_count": len(block["txs"]),
        }
        proof["valid"] = chain.check_proof(proof)
    return {
        "post": _post_view(chain, post, viewer),
        "parent": _post_view(chain, parent, viewer) if parent else None,
        "replies": [_post_view(chain, p, viewer) for p in replies],
        "liked_by": list(chain.ledger.likes.get(post_id, [])),
        "proof": proof,
    }
