# -*- coding: utf-8 -*-
"""ArtChain 命令行界面。

用法：python -m artchain <命令> [参数]
执行 python -m artchain --help 或 python -m artchain <命令> --help 查看详细说明。
"""

import argparse
import getpass
import json
import os
import sys
import time
import unicodedata

from . import __version__, imagelib
from . import certificate as cert_mod
from . import service
from .core.chain import DEFAULT_DIFFICULTY, Blockchain, ChainError
from .core.state import LedgerError
from .core.tx import RULING_UPHOLD, RULINGS, TxError, points_to_units, units_to_text
from .store import Store, StoreError, default_data_dir
from .wallet import Wallet, WalletError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


# ================================================================ 输出辅助
def _width(text):
    """按终端显示宽度计算字符串宽度（中日韩全角字符算 2）。"""
    total = 0
    for ch in str(text):
        total += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return total


def _pad(text, target):
    text = str(text)
    return text + " " * max(0, target - _width(text))


def _truncate(text, limit):
    text = str(text)
    if limit <= 0 or _width(text) <= limit:
        return text
    out = ""
    used = 0
    for ch in text:
        w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + w > limit - 1:
            break
        out += ch
        used += w
    return out + "…"


def render_table(headers, rows, max_widths=None):
    """渲染一张对齐的文本表格。"""
    if not rows:
        return "  （无数据）"
    columns = len(headers)
    cells = [[_truncate(c, max_widths[i]) if max_widths else str(c) for i, c in enumerate(row)]
             for row in rows]
    widths = [_width(h) for h in headers]
    for row in cells:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], _width(cell))
    lines = ["  " + "  ".join(_pad(h, widths[i]) for i, h in enumerate(headers))]
    lines.append("  " + "  ".join("-" * widths[i] for i in range(columns)))
    for row in cells:
        lines.append("  " + "  ".join(_pad(c, widths[i]) for i, c in enumerate(row)))
    return "\n".join(lines)


def title(text):
    print("")
    print(text)
    print("=" * max(40, _width(text)))


def ok(text):
    print("  [完成] %s" % text)


def warn(text):
    print("  [注意] %s" % text)


def fail(text):
    print("  错误：%s" % text, file=sys.stderr)


def fmt_time(ts):
    if not ts:
        return "—"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts)))
    except (ValueError, OSError, TypeError):
        return str(ts)


def fmt_size(num):
    try:
        num = int(num)
    except (TypeError, ValueError):
        return "—"
    if num < 1024:
        return "%d B" % num
    if num < 1024 * 1024:
        return "%.1f KB" % (num / 1024.0)
    return "%.1f MB" % (num / 1048576.0)


# ================================================================ 上下文
class Context(object):
    """把数据目录、存储与区块链装配到一起。"""

    def __init__(self, data_dir=None, difficulty=None, verify_on_load=True):
        self.store = Store(data_dir or default_data_dir()).ensure_dirs()
        self.chain = Blockchain(difficulty=difficulty or DEFAULT_DIFFICULTY, store=self.store)
        self.loaded = False
        self.verify_on_load = verify_on_load

    def ensure_loaded(self, required=True):
        """加载本地链；required=True 时未初始化直接报错。"""
        if self.loaded:
            return True
        if self.store.has_chain():
            if self.chain.load(verify=self.verify_on_load):
                self.loaded = True
                return True
        if required:
            raise ChainError("尚未初始化区块链。请先执行：python -m artchain init")
        return False

    def wallet(self, name, password=None, prompt=True):
        if name not in self.store.list_wallets():
            raise WalletError("钱包不存在：%s（可用 wallet list 查看）" % name)
        payload = self.store.load_wallet(name)
        if not payload.get("crypto"):
            # 未加密钱包（创建时选择不设口令）。没有密文就没有可校验的秘密，
            # 认证在这一层无从谈起——这是"不加密"这个选择的固有代价，不是漏判。
            # 代价是：任何能访问 API 的进程都能用它签名，所以只适合本机演示。
            # HTTP 层另有明文传输的提示，见 api.py 顶部说明。
            return Wallet.load(self.store, name, None)

        secret = password
        # 环境变量回退只对交互式 CLI 路径（prompt=True）开放。
        # HTTP 层以 prompt=False 调用，刻意拿不到这个隐式口令来源——
        # 否则"请求体里不带 password 字段"就等于自动通过鉴权。
        if secret is None and prompt:
            secret = os.environ.get("ARTCHAIN_PASSWORD")
        if secret is None and prompt:
            try:
                secret = getpass.getpass("请输入钱包 %s 的口令：" % name)
            except (EOFError, KeyboardInterrupt):
                raise WalletError("已取消输入口令")
        if secret is None:
            if prompt:
                raise WalletError("钱包 %s 已加密，需要通过 --password 或环境变量 ARTCHAIN_PASSWORD 提供口令"
                                  % name)
            raise WalletError("钱包 %s 已加密，必须在请求中提供 password" % name)
        return Wallet.load(self.store, name, secret)


# ================================================================ init
def cmd_init(ctx, args):
    if ctx.store.has_chain() and not args.force:
        ctx.ensure_loaded()
        warn("区块链已存在（当前高度 #%d）。如需重建请加 --force（会清空链数据）" % ctx.chain.height)
        return EXIT_ERROR
    if ctx.store.has_chain() and args.force:
        removed = ctx.store.reset(keep_wallets=True)
        ok("已清空旧链数据：%s" % "、".join(removed) if removed else "无")
    ctx.chain.difficulty = args.difficulty
    max_supply = None
    if args.max_supply:
        try:
            max_supply = points_to_units(args.max_supply, "积分总量上限")
        except TxError as exc:
            fail(str(exc))
            return EXIT_ERROR
    block = ctx.chain.create_genesis(name=args.name, description=args.desc,
                                     operator=args.operator,
                                     operator_address=args.operator_address or "",
                                     max_supply=max_supply)
    ctx.chain.save()
    title("创世区块已生成")
    print("  链名称      %s" % args.name)
    print("  运营方      %s" % (args.operator or "—"))
    print("  运营方地址  %s" % (args.operator_address or "未设置"))
    print("  积分上限    %s" % (("%s 积分" % args.max_supply) if args.max_supply else "不限"))
    print("  挖矿难度    %d（区块哈希需以 %d 个 0 开头）" % (args.difficulty, args.difficulty))
    print("  创世哈希    %s" % block["hash"])
    print("  数据目录    %s" % ctx.store.root)
    if not args.operator_address:
        warn("未设置运营方地址：积分铸造将处于兼容模式（任何地址均可铸造），"
             "生产环境请务必用 --operator-address 指定")
    print("")
    print("下一步：python -m artchain wallet new --name 你的钱包名")
    return EXIT_OK


# ================================================================ 状态
def cmd_status(ctx, args):
    if not ctx.ensure_loaded(required=False):
        title("ArtChain 尚未初始化")
        print("  数据目录    %s" % ctx.store.root)
        print("  请执行：python -m artchain init")
        return EXIT_ERROR
    stats = ctx.chain.statistics()
    if args.json:
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return EXIT_OK
    title("ArtChain 区块链确权系统")
    print("  链名称      %s" % (stats["chain_name"] or "—"))
    print("  区块高度    #%d（共 %d 个区块）" % (stats["height"], stats["blocks"]))
    print("  挖矿难度    %d" % stats["difficulty"])
    print("  待打包交易  %d" % stats["pending_txs"])
    print("  作品总数    %d（有效 %d / 争议中 %d / 已撤销 %d / 已无效 %d）" % (
        stats["works_total"], stats["works_active"], stats["works_disputed"],
        stats["works_revoked"], stats["works_invalid"]))
    if stats.get("disputes_total"):
        print("  权属争议    %d 起（待裁决 %d 起）" % (
            stats["disputes_total"], stats["disputes_open"]))
    print("  权利人数    %d" % stats["owners_total"])
    print("  转让/许可   %d 次 / %d 项" % (stats["transfers_total"], stats["licenses_total"]))
    print("  积分流通    %s（%d 个地址持有）" % (
        units_to_text(stats.get("points_supply", 0)), stats.get("points_holders", 0)))
    if stats.get("points_operator"):
        print("  积分运营方  %s" % stats["points_operator"])
    print("  最新区块    #%d %s  %s" % (
        stats["height"], stats["latest_block_hash"][:16] + "…", fmt_time(stats["latest_block_time"])))
    usage = ctx.store.storage_usage()
    print("  数据目录    %s" % ctx.store.root)
    print("  存储占用    链 %s / 链下原件 %d 个（%s）" % (
        fmt_size(usage["chain_bytes"]), usage["blob_count"], fmt_size(usage["blob_bytes"])))
    if stats["pending_txs"]:
        print("")
        print("  提示：待打包交易需要在挖矿后才会写入区块，执行 python -m artchain mine --mine-with <钱包名>")
    return EXIT_OK


# ================================================================ 钱包
def cmd_wallet(ctx, args):
    if args.wallet_action == "new":
        password = args.password
        if password is None and not args.no_password:
            try:
                first = getpass.getpass("请设置钱包口令（直接回车表示不加密，仅限演示）：")
                if first:
                    second = getpass.getpass("请再次输入口令：")
                    if first != second:
                        fail("两次输入的口令不一致")
                        return EXIT_ERROR
                    password = first
            except (EOFError, KeyboardInterrupt):
                fail("已取消")
                return EXIT_ERROR
        # 先生成助记词并展示，抄写验证通过后才落盘——验证失败不会留下半成品钱包
        from .crypto import bip39 as _bip39
        mnemonic = _bip39.generate(256 if args.words == 24 else 128)
        words = mnemonic.split()
        title("请抄写你的助记词（%d 个英文单词）" % len(words))
        for i in range(0, len(words), 4):
            print("    " + "   ".join("%2d. %-12s" % (j + 1, words[j])
                                     for j in range(i, min(i + 4, len(words)))))
        print("")
        warn("助记词是钱包的唯一备份：任何人拿到它都能控制这个钱包，")
        warn("平台不保存、也无法找回它。请按顺序抄写在纸上并离线保管，")
        warn("切勿截图、切勿发送给他人、切勿存入网盘或聊天记录。")
        if not args.skip_verify:
            import secrets as _secrets
            rng = _secrets.SystemRandom()
            positions = sorted(rng.sample(range(len(words)), 3))
            for pos in positions:
                try:
                    answer = getpass.getpass("验证：请输入第 %d 个单词：" % (pos + 1))
                except (EOFError, KeyboardInterrupt):
                    fail("已取消，钱包未创建")
                    return EXIT_ERROR
                if not answer or answer.strip().lower() != words[pos]:
                    fail("第 %d 个单词抄写不一致（应为 %s），钱包未创建。请重新执行 wallet new"
                         % (pos + 1, words[pos]))
                    return EXIT_ERROR
        wallet = Wallet.from_mnemonic(ctx.store, args.name, mnemonic,
                                      password=password, meta={"label": args.label})
        title("钱包已创建")
        print("  名称        %s" % wallet.name)
        print("  地址        %s" % wallet.address)
        print("  公钥        %s" % wallet.pubkey)
        print("  保护方式    %s" % ("ChaCha20 口令加密" if wallet.encrypted else "未加密（明文，仅限演示）"))
        print("")
        print("  助记词已由你抄写保管；忘记口令时可用它重新导入（wallet import）。")
        if not wallet.encrypted:
            warn("该钱包助记词以明文保存在钱包文件中，任何人拿到文件即可盗用，请勿用于真实资产")
        return EXIT_OK

    if args.wallet_action == "import":
        from .crypto import bip39 as _bip39
        mnemonic = args.mnemonic
        if not mnemonic:
            try:
                mnemonic = getpass.getpass("请粘贴助记词（12/24 个英文单词，空格分隔）：")
            except (EOFError, KeyboardInterrupt):
                fail("已取消")
                return EXIT_ERROR
        mnemonic = _bip39.normalize(mnemonic or "")
        if not _bip39.validate(mnemonic):
            fail("助记词不合法：请核对每个单词的拼写与顺序")
            return EXIT_ERROR
        wallet = Wallet.from_mnemonic(ctx.store, args.name, mnemonic,
                                      password=args.password,
                                      meta={"label": args.label})
        title("钱包已从助记词恢复")
        print("  名称        %s" % wallet.name)
        print("  地址        %s" % wallet.address)
        print("  公钥        %s" % wallet.pubkey)
        print("  保护方式    %s" % ("ChaCha20 口令加密" if wallet.encrypted else "未加密（明文，仅限演示）"))
        if ctx.ensure_loaded(required=False):
            balance = units_to_text(int(ctx.chain.ledger.balances.get(wallet.address, 0)))
            if balance != "0":
                print("  积分余额    %s（链上记录已随身份找回）" % balance)
        return EXIT_OK

    if args.wallet_action == "list":
        names = ctx.store.list_wallets()
        if not names:
            print("  暂无钱包。执行 python -m artchain wallet new --name 名字 创建。")
            return EXIT_OK
        rows = []
        for name in names:
            payload = ctx.store.load_wallet(name)
            rows.append([name, _truncate(payload.get("address", ""), 22),
                         "已加密" if payload.get("crypto") else "明文",
                         fmt_time(payload.get("created_at")),
                         (payload.get("meta") or {}).get("label", "")])
        title("钱包列表")
        print(render_table(["名称", "地址", "保护方式", "创建时间", "备注"], rows,
                           max_widths=[16, 24, 10, 20, 20]))
        return EXIT_OK

    if args.wallet_action == "show":
        payload = ctx.store.load_wallet(args.name)
        info = {
            "name": payload.get("name", args.name),
            "address": payload.get("address", ""),
            "pubkey": payload.get("pubkey", ""),
            "created_at": payload.get("created_at"),
            "encrypted": bool(payload.get("crypto")),
            "short_address": "%s...%s" % (payload.get("address", "")[:8],
                                          payload.get("address", "")[-6:]),
        }
        if args.json:
            print(json.dumps(info, ensure_ascii=False, indent=2))
            return EXIT_OK
        title("钱包详情：%s" % info["name"])
        print("  地址        %s" % info["address"])
        print("  公钥        %s" % info["pubkey"])
        print("  创建时间    %s" % fmt_time(info["created_at"]))
        print("  保护方式    %s" % ("口令加密" if info["encrypted"] else "明文（危险）"))
        if args.mnemonic:
            wallet = ctx.wallet(args.name, args.password)
            print("")
            if wallet.mnemonic:
                warn("助记词即将显示。请确认周围无人、屏幕不被拍摄。")
                print("  助记词：")
                words = wallet.mnemonic.split()
                for i in range(0, len(words), 4):
                    print("    " + "   ".join("%2d. %-12s" % (j + 1, words[j])
                                             for j in range(i, min(i + 4, len(words)))))
            else:
                warn("该钱包是旧版格式（十六进制私钥），没有助记词；"
                     "如需迁移请导出备份后重建钱包并转移资产")
        if ctx.ensure_loaded(required=False):
            owned = ctx.chain.ledger.list_works(owner=info["address"])
            created = [w for w in ctx.chain.ledger.works.values()
                       if w.get("creator") == info["address"]]
            print("  名下作品    %d 件（其中原创登记 %d 件）" % (len(owned), len(created)))
            if owned and not args.json:
                rows = [[_truncate(w["work_id"], 27), _truncate(w["title"], 18), w["status"]]
                        for w in owned]
                print("")
                print(render_table(["作品编号", "作品名称", "状态"], rows, max_widths=[28, 20, 10]))
        return EXIT_OK

    if args.wallet_action == "export":
        wallet = ctx.wallet(args.name, args.password)
        target = args.out or ("wallet-%s-backup.json" % args.name)
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(wallet.to_payload(args.new_password), fh, ensure_ascii=False, indent=2)
        ok("钱包备份已导出：%s" % os.path.abspath(target))
        if not args.new_password:
            warn("该备份未加密，请妥善保管并及时删除")
        return EXIT_OK

    fail("未知的钱包子命令")
    return EXIT_USAGE


# ================================================================ 登记确权
def cmd_register(ctx, args):
    ctx.ensure_loaded()
    if not os.path.exists(args.file):
        fail("找不到文件：%s" % args.file)
        return EXIT_ERROR
    wallet = ctx.wallet(args.wallet, args.password)
    with open(args.file, "rb") as fh:
        content = fh.read()
    meta = _parse_meta(args.meta)

    result = service.register_work(
        ctx.chain, ctx.store, wallet, content, filename=os.path.basename(args.file),
        title=args.title, category=args.category, author=args.author, year=args.year,
        created_at=args.created or "", description=args.desc or "", meta=meta,
        store_file=not args.no_store, auto_mine=not args.no_mine)

    fp = result["fingerprint"]
    title("作品确权登记成功")
    print("  作品编号    %s" % result["work_id"])
    print("  作品名称    %s" % result["title"])
    print("  作品类别    %s" % args.category)
    print("  作者署名    %s" % (args.author or "—"))
    print("  权利人      %s" % wallet.address)
    print("")
    print("  数字指纹")
    print("    SHA-256   %s" % fp["sha256"])
    if fp.get("phash"):
        print("    pHash     %s   （感知指纹，可抗压缩/缩放）" % fp["phash"])
        print("    aHash     %s" % fp["ahash"])
        print("    dHash     %s" % fp["dhash"])
    if fp.get("simhash"):
        print("    SimHash   %s   （文本指纹）" % fp["simhash"])
    print("    类型/大小 %s / %s" % (fp["kind"], fmt_size(fp["size"])))
    if fp.get("width"):
        print("    图像尺寸  %s x %s" % (fp["width"], fp["height"]))
    print("")
    print("  上链信息")
    print("    交易哈希  %s" % result["txid"])
    if result["mined"]:
        print("    所在区块  #%d（%s）" % (result["height"], fmt_time(result["block_time"])))
        print("    区块哈希  %s" % result["block_hash"])
        ok("作品已完成确权并写入区块链")
    else:
        warn("交易已进入待打包池，执行 python -m artchain mine 后才会真正上链")
    print("")
    print("  查看证书：python -m artchain cert --work %s" % result["work_id"])
    return EXIT_OK


def _parse_meta(pairs):
    meta = {}
    for item in pairs or []:
        if "=" not in item:
            raise service.ServiceError("--meta 需要 key=value 格式：%r" % item)
        key, value = item.split("=", 1)
        meta[key.strip()] = value.strip()
    return meta


# ================================================================ 转让/许可/争议/撤销
def cmd_transfer(ctx, args):
    ctx.ensure_loaded()
    wallet = ctx.wallet(args.wallet, args.password)
    result = service.transfer_work(ctx.chain, ctx.store, wallet, args.work, args.to,
                                   price=args.price, note=args.note or "",
                                   auto_mine=not args.no_mine)
    title("版权转让成功")
    print("  作品编号    %s" % result["work_id"])
    print("  受让方      %s" % result["to"])
    print("  转让价款    %s" % (result["price"] or "无偿"))
    print("  交易哈希    %s" % result["txid"])
    if result["mined"]:
        print("  所在区块    #%d" % result["height"])
    else:
        warn("交易待打包，执行 mine 后上链")
    return EXIT_OK


def cmd_license(ctx, args):
    ctx.ensure_loaded()
    wallet = ctx.wallet(args.wallet, args.password)
    result = service.license_work(
        ctx.chain, ctx.store, wallet, args.work, args.to, scope=args.scope,
        territory=args.territory, royalty=args.royalty, start=args.start, end=args.end,
        purpose=args.purpose or "", auto_mine=not args.no_mine)
    title("授权许可已登记")
    print("  作品编号    %s" % result["work_id"])
    print("  被许可方    %s" % result["to"])
    print("  授权类型    %s" % result["scope"])
    print("  交易哈希    %s" % result["txid"])
    if not result["mined"]:
        warn("交易待打包，执行 mine 后上链")
    return EXIT_OK


def cmd_dispute(ctx, args):
    ctx.ensure_loaded()
    wallet = ctx.wallet(args.wallet, args.password)
    result = service.dispute_work(ctx.chain, ctx.store, wallet, args.work, args.reason,
                                  evidence_hash=args.evidence or "", auto_mine=not args.no_mine)
    title("权属争议已登记")
    print("  作品编号    %s" % result["work_id"])
    print("  异议人      %s" % wallet.address)
    print("  争议理由    %s" % args.reason)
    print("  交易哈希    %s" % result["txid"])
    warn("该作品已锁定，争议解决前无法转让或对外授权")
    print("  解除方式    由任何与本案无关的第三方执行 adjudicate 指令作出裁决")
    return EXIT_OK


def cmd_adjudicate(ctx, args):
    ctx.ensure_loaded()
    wallet = ctx.wallet(args.wallet, args.password)
    result = service.adjudicate_work(ctx.chain, ctx.store, wallet, args.work, args.ruling,
                                     args.reason, evidence_hash=args.evidence or "",
                                     auto_mine=not args.no_mine)
    # 状态机的返回值不经 _submit_and_finish 透出，裁决后的状态要从账本回读。
    work = ctx.chain.ledger.get_work(args.work) or {}
    title("争议裁决已上链")
    print("  作品编号    %s" % result["work_id"])
    print("  裁决结论    %s异议" % result["ruling"])
    print("  裁决人      %s" % wallet.address)
    print("  裁决理由    %s" % args.reason)
    print("  作品状态    %s" % work.get("status", "—"))
    print("  交易哈希    %s" % result["txid"])
    if args.ruling == RULING_UPHOLD:
        warn("该登记已被判定无效，指纹占用已释放，真实作者可以重新登记")
    else:
        warn("异议不成立，作品恢复为有效，转让与授权重新开放")
    return EXIT_OK


def cmd_revoke(ctx, args):
    ctx.ensure_loaded()
    wallet = ctx.wallet(args.wallet, args.password)
    result = service.revoke_work(ctx.chain, ctx.store, wallet, args.work, reason=args.reason or "",
                                 auto_mine=not args.no_mine)
    title("登记已撤销")
    print("  作品编号    %s" % result["work_id"])
    print("  交易哈希    %s" % result["txid"])
    return EXIT_OK


# ================================================================ 平台积分
def cmd_points(ctx, args):
    ctx.ensure_loaded()
    overview = service.points_overview(ctx.chain, address=args.address, limit=args.limit or 20)
    title("平台积分")
    print("  流通总量    %s" % overview["supply_text"])
    if overview["max_supply_text"]:
        print("  总量上限    %s" % overview["max_supply_text"])
    print("  持币地址    %d 个" % overview["holders"])
    operator = overview["operator_address"] or overview["operator"]
    if overview["operator_address"]:
        print("  运营方地址  %s（%s）" % (overview["operator_address"], overview["operator"] or "—"))
        print("  运营方余额  %s" % service.units_balance_text(ctx.chain, overview["operator_address"]))
    else:
        warn("创世区块未登记运营方地址：积分铸造处于兼容模式（任何地址均可铸造），"
             "生产环境务必重建链并填写 --operator-address")
    if args.address:
        print("")
        print("  查询地址    %s" % args.address)
        print("  积分余额    %s" % overview["balance_text"])

    if args.top:
        print("")
        print("余额排行（前 %d）" % args.top)
        rows = [[a[:24] + ("…" if len(a) > 24 else ""), t]
                for a, t in ((b["address"], b["balance_text"])
                             for b in service.top_balances(ctx.chain, limit=args.top))]
        print(render_table(["地址", "余额"], rows, max_widths=[26, 24]))

    if overview["recent"]:
        print("")
        print("最近流水（前 %d 条）" % len(overview["recent"]))
        kind_map = {"PAY": "转账", "MINT": "铸造", "BURN": "销毁"}
        rows = []
        for e in overview["recent"]:
            who = e.get("to") or e.get("from") or "—"
            rows.append([fmt_time(e["time"]), kind_map.get(e["type"], e["type"]),
                         who[:22] + ("…" if len(who) > 22 else ""),
                         ("+" if e["type"] == "MINT" else
                          ("-" if e["type"] == "BURN" else "→")),
                         e["amount_text"], "#%d" % e["height"]])
        print(render_table(["时间", "类型", "对方", "方向", "金额", "区块"],
                           rows, max_widths=[19, 4, 24, 2, 20, 6]))
    elif not args.address:
        print("")
        print("  暂无积分流水。运营方可执行 python -m artchain mint --wallet <钱包> --amount 1000")
    return EXIT_OK


def cmd_pay(ctx, args):
    ctx.ensure_loaded()
    wallet = ctx.wallet(args.wallet, args.password)
    result = service.transfer_points(ctx.chain, ctx.store, wallet, args.to, args.amount,
                                     memo=args.memo or "", auto_mine=not args.no_mine)
    title("积分转账成功")
    print("  收款方      %s" % args.to)
    print("  转账金额    %s" % result["amount_text"])
    print("  交易哈希    %s" % result["txid"])
    if result["mined"]:
        print("  所在区块    #%d" % result["height"])
    else:
        warn("交易待打包，执行 mine 后上链")
    return EXIT_OK


def cmd_mint(ctx, args):
    ctx.ensure_loaded()
    wallet = ctx.wallet(args.wallet, args.password)
    declared = ctx.chain.ledger.chain_meta.get("operator_address") or ""
    if declared and wallet.address != declared:
        fail("积分铸造仅限运营方地址 %s（当前钱包 %s）" % (declared, wallet.address))
        return EXIT_ERROR
    if not declared:
        warn("创世区块未登记运营方地址，当前为兼容模式——生产环境务必重建链并填写 --operator-address")
    result = service.mint_points(ctx.chain, ctx.store, wallet, args.amount,
                                 memo=args.memo or "", auto_mine=not args.no_mine)
    title("积分铸造成功")
    print("  铸造数量    %s" % result["amount_text"])
    print("  计入地址    %s" % wallet.address)
    print("  当前流通    %s" % result["supply_text"])
    print("  交易哈希    %s" % result["txid"])
    if not result["mined"]:
        warn("交易待打包，执行 mine 后上链")
    return EXIT_OK


def cmd_burn(ctx, args):
    ctx.ensure_loaded()
    wallet = ctx.wallet(args.wallet, args.password)
    declared = ctx.chain.ledger.chain_meta.get("operator_address") or ""
    if declared and wallet.address != declared:
        fail("积分销毁仅限运营方地址 %s（当前钱包 %s）" % (declared, wallet.address))
        return EXIT_ERROR
    result = service.burn_points(ctx.chain, ctx.store, wallet, args.amount,
                                 memo=args.memo or "", auto_mine=not args.no_mine)
    title("积分销毁成功")
    print("  销毁数量    %s" % result["amount_text"])
    print("  当前流通    %s" % result["supply_text"])
    print("  交易哈希    %s" % result["txid"])
    if not result["mined"]:
        warn("交易待打包，执行 mine 后上链")
    return EXIT_OK


# ================================================================ 挖矿
def cmd_mine(ctx, args):
    ctx.ensure_loaded()
    miner = ""
    if args.mine_with:
        miner = ctx.wallet(args.mine_with, args.password).address
    elif args.address:
        miner = args.address
    pending = len(ctx.chain.mempool)
    if pending == 0 and not args.allow_empty:
        warn("待打包池为空，无需出块（如确需出空块请加 --allow-empty）")
        return EXIT_ERROR
    ts = None
    if args.time is not None:
        ts = int(args.time)
    started = time.time()
    print("  正在挖矿（难度 %d，待打包 %d 笔），请稍候…" % (ctx.chain.difficulty, pending))
    result = service.mine_now(ctx.chain, ctx.store, miner, timestamp=ts)
    title("出块成功")
    print("  区块高度    #%d" % result["height"])
    print("  区块哈希    %s" % result["hash"])
    print("  交易数量    %d 笔" % result["tx_count"])
    print("  随机数      %d" % result["nonce"])
    print("  出块时间    %s" % fmt_time(result["time"]))
    print("  耗时        %.2f 秒" % (time.time() - started))
    return EXIT_OK


# ================================================================ 查询
def cmd_works(ctx, args):
    ctx.ensure_loaded()
    works = ctx.chain.ledger.list_works(owner=args.owner, keyword=args.keyword, status=args.status)
    if args.json:
        print(json.dumps(works, ensure_ascii=False, indent=2))
        return EXIT_OK
    title("链上已确权作品（%d 件）" % len(works))
    rows = []
    for work in works:
        rows.append([
            _truncate(work["work_id"], 27),
            _truncate(work["title"], 20),
            work.get("category", ""),
            _truncate(work.get("author", ""), 12),
            _truncate(work.get("owner", ""), 16),
            work.get("status", ""),
            "#%s" % work.get("height"),
            fmt_time(work.get("registered_at")),
        ])
    print(render_table(["作品编号", "作品名称", "类别", "作者", "当前权利人", "状态", "区块", "登记时间"],
                       rows, max_widths=[28, 20, 10, 12, 16, 8, 6, 20]))
    print("")
    print("  查看详情：python -m artchain work --id <作品编号>")
    return EXIT_OK


def cmd_work(ctx, args):
    ctx.ensure_loaded()
    detail = service.work_detail(ctx.chain, args.id)
    work = detail["work"]
    if args.json:
        print(json.dumps(detail, ensure_ascii=False, indent=2))
        return EXIT_OK
    proof = detail["proof"]
    title("作品确权详情")
    print("  作品编号    %s" % work["work_id"])
    print("  作品名称    %s" % work.get("title"))
    print("  作品类别    %s" % work.get("category"))
    print("  作者署名    %s" % (work.get("author") or "—"))
    print("  创作年份    %s" % (work.get("year") or "—"))
    print("  权属状态    %s" % work.get("status"))
    print("  原始权利人  %s" % work.get("creator"))
    print("  当前权利人  %s" % work.get("owner"))
    print("  登记时间    %s" % fmt_time(work.get("registered_at")))
    print("")
    print("  数字指纹")
    print("    SHA-256   %s" % work.get("file_hash"))
    if work.get("phash"):
        print("    pHash     %s" % work.get("phash"))
        print("    aHash     %s" % work.get("ahash"))
        print("    dHash     %s" % work.get("dhash"))
    if work.get("simhash"):
        print("    SimHash   %s" % work.get("simhash"))
    print("    文件       %s ｜ %s ｜ %s" % (
        work.get("kind"), work.get("mime"), fmt_size(work.get("size"))))
    print("")
    print("  上链存证")
    print("    交易哈希  %s" % work.get("txid"))
    print("    所在区块  #%s" % work.get("height"))
    print("    区块哈希  %s" % work.get("block_hash"))
    if proof:
        print("    Merkle 根 %s" % proof["merkle_root"])
        print("    存在性证明 %s（路径 %d 层）" % (
            "验证通过" if proof.get("valid") else "验证未通过", len(proof["merkle_proof"])))
    if detail["history"]:
        print("")
        print("  权属沿革")
        rows = [[fmt_time(h.get("time")), "#%s" % h.get("height"), h.get("action"),
                 _truncate(h.get("detail", ""), 30), _truncate(h.get("txid", ""), 20)]
                for h in detail["history"]]
        print(render_table(["时间", "区块", "事项", "说明", "交易哈希"], rows,
                           max_widths=[20, 6, 10, 32, 22]))
    if detail["licenses"]:
        print("")
        print("  授权许可")
        rows = [[lic.get("start") or "—", lic.get("end") or "—", lic.get("scope"),
                 _truncate(lic.get("to", ""), 16), lic.get("territory"),
                 lic.get("royalty") or "—", lic.get("status")] for lic in detail["licenses"]]
        print(render_table(["起始", "截止", "类型", "被许可方", "地域", "费用", "状态"], rows,
                           max_widths=[12, 12, 8, 16, 10, 10, 8]))
    print("")
    print("  导出证书：python -m artchain cert --work %s --format html" % work["work_id"])
    return EXIT_OK


def cmd_blocks(ctx, args):
    ctx.ensure_loaded()
    blocks = ctx.chain.blocks
    if args.height is not None:
        if not 0 <= args.height < len(blocks):
            fail("区块高度超出范围（0 - %d）" % (len(blocks) - 1))
            return EXIT_ERROR
        block = blocks[args.height]
        if args.json:
            print(json.dumps(block, ensure_ascii=False, indent=2))
            return EXIT_OK
        title("区块 #%d" % block["height"])
        print("  区块哈希    %s" % block["hash"])
        print("  前序哈希    %s" % block["prev_hash"])
        print("  Merkle 根   %s" % block["merkle_root"])
        print("  出块时间    %s" % fmt_time(block["time"]))
        print("  出块人      %s" % (block.get("miner") or "—"))
        print("  难度/随机数 %d / %d" % (block["difficulty"], block["nonce"]))
        print("  交易数量    %d" % len(block["txs"]))
        print("")
        rows = []
        for pos, tx in enumerate(block["txs"]):
            rows.append([pos, tx.get("type"), _truncate(tx.get("sender", ""), 16),
                         _truncate(tx.get("txid", ""), 24), fmt_time(tx.get("time"))])
        print(render_table(["#", "类型", "发起方", "交易哈希", "时间"], rows,
                           max_widths=[4, 10, 16, 26, 20]))
        return EXIT_OK

    limit = args.limit
    subset = list(reversed(blocks[-limit:]))
    if args.json:
        print(json.dumps(subset, ensure_ascii=False, indent=2))
        return EXIT_OK
    title("区块浏览（最近 %d 个）" % len(subset))
    rows = [[b["height"], _truncate(b["hash"], 34), _truncate(b["merkle_root"], 24),
             len(b["txs"]), fmt_time(b["time"])] for b in subset]
    print(render_table(["高度", "区块哈希", "Merkle 根", "交易数", "出块时间"], rows,
                       max_widths=[6, 36, 26, 8, 20]))
    return EXIT_OK


def cmd_mempool(ctx, args):
    ctx.ensure_loaded()
    pending = ctx.chain.mempool
    if args.json:
        print(json.dumps(pending, ensure_ascii=False, indent=2))
        return EXIT_OK
    title("待打包交易（%d 笔）" % len(pending))
    rows = [[_truncate(tx.get("txid", ""), 26), tx.get("type"), _truncate(tx.get("sender", ""), 16),
             tx.get("nonce"), fmt_time(tx.get("time"))] for tx in pending]
    print(render_table(["交易哈希", "类型", "发起方", "nonce", "提交时间"], rows,
                       max_widths=[28, 10, 16, 6, 20]))
    if pending:
        print("")
        print("  执行 python -m artchain mine --mine-with <钱包名> 打包出块")
    return EXIT_OK


# ================================================================ 校验
def cmd_verify(ctx, args):
    ctx.ensure_loaded()
    print("  正在重新校验整条链（%d 个区块）…" % len(ctx.chain.blocks))
    started = time.time()
    ok_flag, errors = ctx.chain.verify()
    elapsed = time.time() - started
    if ok_flag:
        title("链完整性校验通过")
        print("  区块数量    %d" % len(ctx.chain.blocks))
        print("  当前高度    #%d" % ctx.chain.height)
        print("  交易总数    %d" % sum(len(b["txs"]) for b in ctx.chain.blocks))
        print("  校验耗时    %.3f 秒" % elapsed)
        print("")
        print("  校验内容：前向哈希链接、Merkle 根、工作量证明、交易签名、")
        print("            交易唯一性、状态机重放（权属变更是否合法）")
        ok("整条链未被篡改")
        return EXIT_OK
    title("链校验未通过")
    for item in errors[:20]:
        fail(item)
    if len(errors) > 20:
        fail("……另有 %d 条错误" % (len(errors) - 20))
    return EXIT_ERROR


def cmd_verify_cert(ctx, args):
    with open(args.file, "r", encoding="utf-8") as fh:
        cert = json.load(fh)
    # 默认走链上核对：有本地链就拿去逐项比对，那才是能证明"确权成立"的模式。
    # --offline 退回只做自洽校验，结论弱得多，只适合手边没有链的场合。
    chain = None
    if not args.offline and ctx.ensure_loaded(required=False):
        chain = ctx.chain
    result = cert_mod.verify_certificate(cert, chain=chain)
    title("证书验证（%s）" % ("链上核对" if chain is not None else "离线自洽校验"))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return EXIT_OK if (result["valid"] and result["trusted"]) else EXIT_ERROR
    print("  证书编号    %s" % (result.get("certificate_id") or "—"))
    print("  作品编号    %s" % (result.get("work_id") or "—"))
    print("  交易哈希    %s" % (result.get("txid") or "—"))
    print("  区块高度    #%s" % (result.get("height") or "—"))
    print("")
    if result["trusted"]:
        ok("已与本地链逐项核对一致，该登记确实已写入区块链")
        return EXIT_OK
    if result["valid"]:
        # 自洽但未经链核对——这**不是**确权成立的证据，绝不能报成功。
        warn("证书自洽，但未与任何链数据核对，不能据此认定确权成立")
        for item in result["notes"]:
            print("  %s" % item)
        return EXIT_ERROR
    for item in result["problems"]:
        fail(item)
    for item in result["notes"]:
        print("  %s" % item)
    return EXIT_ERROR


# ================================================================ 侵权比对
def cmd_compare(ctx, args):
    ctx.ensure_loaded()
    if args.file:
        if not os.path.exists(args.file):
            fail("找不到文件：%s" % args.file)
            return EXIT_ERROR
        with open(args.file, "rb") as fh:
            content = fh.read()
        filename = os.path.basename(args.file)
    else:
        fail("请通过 --file 指定要比对的作品文件")
        return EXIT_ERROR

    report = service.compare_content(ctx.chain, content, filename=filename,
                                     work_id=args.work, top=args.top)
    target = report["target_fingerprint"]
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return EXIT_OK

    title("侵权比对取证")
    print("  待比对文件  %s" % filename)
    print("  SHA-256     %s" % target["sha256"])
    if target.get("phash"):
        print("  pHash       %s" % target["phash"])
    print("  文件类型    %s ｜ %s" % (target["kind"], fmt_size(target["size"])))
    print("  比对样本    %d 件链上作品" % report["checked"])
    print("")

    if not report["results"]:
        print("  链上暂无已登记作品可供比对。")
        return EXIT_OK

    rows = []
    level_text = {5: "完全一致", 4: "高度疑似", 3: "疑似", 2: "部分相似", 1: "不相似"}
    for item in report["results"]:
        label = item["label"]
        dist = item["distances"]
        rows.append([
            "%.4f" % item["score"],
            level_text.get(item["level"], "—"),
            _truncate(item["id"], 27),
            _truncate(label.get("title", ""), 18),
            _truncate(label.get("owner", ""), 16),
            label.get("status", ""),
            dist.get("phash") if dist.get("phash") is not None else "—",
            "#%s" % label.get("height"),
        ])
    print(render_table(["相似度", "判定", "作品编号", "作品名称", "权利人", "状态", "pHash距离", "区块"],
                       rows, max_widths=[8, 10, 28, 18, 16, 8, 10, 6]))

    risk = report["risk"]
    print("")
    print("  比对结论    %s" % risk["text"])
    if risk.get("work_id"):
        best = report["results"][0]
        print("  最相似作品  《%s》（%s）" % (risk.get("title"), risk["work_id"]))
        print("  链上登记    %s 于区块 #%s" % (
            fmt_time((best["label"] or {}).get("registered_at")), (best["label"] or {}).get("height")))
        if best["level"] >= 3:
            print("")
            print("  取证建议")
            print("    1) 目标文件与链上作品的 SHA-256 不同但感知指纹高度接近，")
            print("       说明对方很可能在原件基础上做了压缩/缩放/调色等改动；")
            print("    2) 链上登记时间可作为「在先创作」的时间戳证据，")
            print("       执行 python -m artchain cert --work %s 导出带 Merkle 证明的证书；" % risk["work_id"])
            print("    3) 若权属存在争议，可用 dispute 指令在链上固定争议记录。")
    return EXIT_OK


def cmd_check_original(ctx, args):
    ctx.ensure_loaded()
    result = service.verify_original(ctx.chain, ctx.store, args.work)
    title("链下原件校验")
    print("  作品编号    %s" % args.work)
    if not result["available"]:
        warn(result["reason"])
        return EXIT_OK
    print("  原件路径    %s" % result["path"])
    print("  链上指纹    %s" % result["expected"])
    print("  实际指纹    %s" % result["actual"])
    print("")
    if result["match"]:
        ok(result["message"])
        return EXIT_OK
    fail(result["message"])
    return EXIT_ERROR


# ================================================================ 证书
def cmd_cert(ctx, args):
    ctx.ensure_loaded()
    cert = cert_mod.build_certificate(ctx.chain, args.work, store=ctx.store, issuer=args.issuer or "")
    fmt = args.format
    if fmt == "json":
        content, suffix = cert_mod.render_json(cert), "json"
    elif fmt == "text":
        content, suffix = cert_mod.render_text(cert), "txt"
    else:
        content, suffix = cert_mod.render_html(cert), "html"
    out = args.out or ("证书-%s.%s" % (cert["work"]["work_id"], suffix))
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(content)
    ok("确权证书已导出：%s" % os.path.abspath(out))
    if fmt == "html":
        print("     用浏览器打开后可打印为 PDF。")
    if fmt == "json":
        print("     可用 python -m artchain verify-cert --file <该文件> 做离线验证。")
    if args.print:
        print("")
        print(content)
    return EXIT_OK


# ================================================================ 节点与同步
def cmd_peer(ctx, args):
    if args.peer_action == "add":
        peers = ctx.store.add_peer(args.url.rstrip("/"))
        ok("已添加节点，当前共 %d 个：%s" % (len(peers), "、".join(peers)))
        return EXIT_OK
    if args.peer_action == "remove":
        peers = [p for p in ctx.store.load_peers() if p != args.url.rstrip("/")]
        ctx.store.save_peers(peers)
        ok("已移除，剩余 %d 个节点" % len(peers))
        return EXIT_OK
    peers = ctx.store.load_peers()
    title("已知节点（%d 个）" % len(peers))
    if not peers:
        print("  暂无。可用 peer add --url http://127.0.0.1:8001 添加。")
    for peer in peers:
        print("  - %s" % peer)
    return EXIT_OK


def cmd_purchase(ctx, args):
    """积分购买/兑换通道：地区识别、定价、订单管理与交付。"""
    from . import geofence
    action = args.purchase_action or "methods"
    if action == "region":
        ip = (args.ip or "127.0.0.1").strip()
        config = ctx.store.load_config()
        default_region = config.get("geofence_default_region") or "CN"
        region, label, detail = geofence.region_of(
            ip, store=ctx.store, default=default_region)
        title("IP 地区识别")
        print("  IP 地址       %s" % ip)
        print("  判定结果      %s（%s，%s）" % (label, region, detail))
        info = geofence.ranges_info(ctx.store)
        print("  网段清单      %s，共 %d 段" % (info["source"], info["count"]))
        print("  默认地区      %s" % default_region)
        return EXIT_OK
    if action == "methods":
        config = ctx.store.load_config()
        default_region = config.get("geofence_default_region") or "CN"
        ip = (args.ip or "127.0.0.1").strip()
        region, label, _d = geofence.region_of(ip, store=ctx.store,
                                                default=default_region)
        title("积分购买通道（模拟 %s 视角）" % label)
        for rail in service.purchase_methods(ctx.store, region):
            status = ("✓ 可用" if rail["available"]
                      else "✗ 锁定：" + rail["locked_reason"])
            print("  %-8s %-12s 1 %-4s = %s 积分   %s"
                  % (rail["id"], rail["label"], rail["currency"],
                     rail["points_per_unit"], status))
        return EXIT_OK
    if action == "orders":
        orders = service.list_purchase_orders(
            ctx.store, address=args.address, status=args.status)
        title("购买订单（%d 条）" % len(orders))
        if not orders:
            print("  暂无订单")
        for order in orders[:20]:
            print("  %s  %-6s  %-12s → 买家 %s…  状态 %s"
                  % (order["id"], order["rail"], order["amount_text"],
                     order["buyer"][:12], order["status"]))
        return EXIT_OK
    if action == "cancel":
        if not args.order:
            fail("请提供 --order 订单号")
            return EXIT_ERROR
        order = service.cancel_purchase_order(ctx.store, args.order)
        title("订单已取消")
        print("  ID      %s" % order["id"])
        print("  状态    %s" % order["status"])
        return EXIT_OK
    if action == "confirm":
        ctx.ensure_loaded()
        if not args.order:
            fail("请提供 --order 订单号")
            return EXIT_ERROR
        wallet = ctx.wallet(args.wallet, args.password)
        declared = ctx.chain.ledger.chain_meta.get("operator_address") or ""
        if declared and wallet.address != declared:
            fail("订单交付需由运营方地址 %s 操作，当前钱包 %s"
                 % (declared, wallet.address))
            return EXIT_ERROR
        result = service.confirm_payment(
            ctx.chain, ctx.store, wallet, args.order, payment_ref=args.ref or "")
        title("订单已交付")
        order = result["order"]
        print("  ID          %s" % order["id"])
        print("  买家        %s" % order["buyer"])
        print("  积分        %s" % order["points_text"])
        print("  MINT txid   %s…  区块 #%s" %
              (str(result["mint"]["txid"])[:16], result["mint"].get("height")))
        print("  PAY  txid   %s…  区块 #%s" %
              (str(result["transfer"]["txid"])[:16],
               result["transfer"].get("height")))
        return EXIT_OK
    fail("未知的 purchase 子命令：%s" % action)
    return EXIT_ERROR


def cmd_apikey(ctx, args):
    from . import apikeys
    action = args.apikey_action or "list"
    if action == "create":
        scopes = [s.strip() for s in (args.scopes or "read").split(",") if s.strip()]
        record, plain = apikeys.create_key(ctx.store, args.name, scopes,
                                           note=args.note)
        title("API Key 已签发")
        print("  名称      %s" % record["name"])
        print("  ID        %s" % record["id"])
        print("  权限档    %s" % ", ".join(record["scopes"]))
        print("")
        print("  明文密钥（仅此一次显示，请当面交付合作方）：")
        print("    %s" % plain)
        print("")
        print("  调用示例：")
        print('    curl -H "Authorization: Bearer %s" '
              "http://127.0.0.1:8080/open/v1/status" % plain)
        return EXIT_OK
    if action == "revoke":
        record = apikeys.revoke_key(ctx.store, args.id)
        ok("已吊销：%s（%s）" % (record["name"], record["id"]))
        return EXIT_OK
    keys = apikeys.list_keys(ctx.store)
    title("API Key（%d 个）" % len(keys))
    if not keys:
        print("  暂无。可用 apikey create --name 合作方XX --scopes read,write 签发。")
    for rec in keys:
        state = "已吊销" if rec.get("revoked_at") else "有效"
        print("  %s  %-16s scopes=%-11s uses=%-6d %-4s %s"
              % (rec["id"], rec["name"], ",".join(rec["scopes"]),
                 rec.get("uses") or 0, state, rec.get("note") or ""))
    return EXIT_OK


def cmd_sync(ctx, args):
    ctx.ensure_loaded()
    from . import api as api_mod
    peers = [args.url] if args.url else ctx.store.load_peers()
    if not peers:
        fail("没有可同步的节点，请先用 peer add 添加，或用 --url 直接指定")
        return EXIT_ERROR
    changed = False
    for peer in peers:
        try:
            remote = api_mod.fetch_remote_chain(peer, timeout=args.timeout)
        except Exception as exc:
            fail("节点 %s 连接失败：%s" % (peer, exc))
            continue
        print("  节点 %s 高度 #%s（本地 #%d）" % (peer, len(remote) - 1, ctx.chain.height))
        replaced, message = ctx.chain.replace_chain(remote)
        print("    %s" % message)
        changed = changed or replaced
    if changed:
        ctx.chain.save()
        ok("本地链已更新至高度 #%d" % ctx.chain.height)
    return EXIT_OK


# ================================================================ 服务
def cmd_serve(ctx, args):
    from . import api as api_mod
    ctx.ensure_loaded(required=False)
    api_mod.serve(ctx, host=args.host, port=args.port, open_browser=args.open)
    return EXIT_OK


def cmd_desktop(ctx, args):
    """打开桌面可视化窗口（Tkinter）。"""
    from . import desktop
    try:
        return desktop.main(ctx)
    except ImportError as exc:
        fail("桌面窗口需要 Tkinter，当前 Python 未提供：%s" % exc)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - 无图形环境等都要给出可读提示
        fail("桌面窗口启动失败：%s" % exc)
        return EXIT_ERROR


# ================================================================ 其它
def cmd_reset(ctx, args):
    if not args.yes:
        print("  该操作会删除链数据（钱包默认保留）。确认请加 --yes")
        return EXIT_USAGE
    removed = ctx.store.reset(keep_wallets=not args.with_wallets)
    ok("已清空：%s" % ("、".join(removed) if removed else "本来就没有数据"))
    return EXIT_OK


def cmd_version(ctx, args):
    from .wallet import describe_env
    info = describe_env()
    print("ArtChain %s" % __version__)
    print("  Python        %s" % info["python"])
    print("  图像后端      %s" % info["image_backend"])
    print("  支持格式      %s" % info["image_formats"])
    print("  数据目录      %s" % ctx.store.root)
    return EXIT_OK


def cmd_selftest(ctx, args):
    from . import selftest
    return selftest.run(verbose=not args.quiet)


def cmd_demo(ctx, args):
    from . import demo
    return demo.run(ctx, reset=args.reset, keep=args.keep)


# ================================================================ 解析器
def build_parser():
    parser = argparse.ArgumentParser(
        prog="artchain",
        description="ArtChain —— 基于区块链的艺术品数字确权系统（纯 Python 标准库实现）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""常用示例：
  python -m artchain init                             初始化区块链
  python -m artchain wallet new --name 张三            创建钱包
  python -m artchain register --wallet 张三 --file 画作.png --title 晨
  python -m artchain works                            查看已确权作品
  python -m artchain compare --file 疑似侵权.png       侵权比对取证
  python -m artchain cert --work WK... --format html   导出确权证书
  python -m artchain serve                            启动网页版与 API
  python -m artchain desktop                          打开桌面可视化窗口
  python -m artchain demo                             一键跑通完整演示
  python -m artchain selftest                          运行内置自检
""")
    parser.add_argument("--data", help="数据目录（默认：项目下的 data/，也可用环境变量 ARTCHAIN_DATA）")
    parser.add_argument("--version", action="version", version="ArtChain %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("init", help="初始化区块链（创建创世区块）")
    p.add_argument("--name", default="ArtChain 艺术品确权链", help="链名称")
    p.add_argument("--desc", default="", help="链描述")
    p.add_argument("--operator", default="", help="运营方名称")
    p.add_argument("--operator-address", default="",
                   help="运营方钱包地址（积分铸造/销毁的权限归属，强烈建议填写）")
    p.add_argument("--max-supply", default="",
                   help="积分总量上限（例如 1000000，留空表示不限）")
    p.add_argument("--difficulty", type=int, default=DEFAULT_DIFFICULTY,
                   help="挖矿难度（前导 0 的个数，默认 %d，越大越慢）" % DEFAULT_DIFFICULTY)
    p.add_argument("--force", action="store_true", help="已存在链时强制重建（会清空链数据）")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("status", help="查看链与账本概览")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("wallet", help="钱包管理")
    pw = p.add_subparsers(dest="wallet_action")
    q = pw.add_parser("new", help="创建钱包")
    q.add_argument("--name", required=True, help="钱包名称")
    q.add_argument("--password", help="口令（不建议写在命令行，省略后会交互输入）")
    q.add_argument("--no-password", action="store_true", help="不加密助记词（仅限演示）")
    q.add_argument("--words", type=int, default=12, choices=[12, 24],
                   help="助记词长度（12/24 个英文单词，默认 12）")
    q.add_argument("--skip-verify", action="store_true", help="跳过抄写验证（自动化脚本用，慎用）")
    q.add_argument("--label", default="", help="备注")
    q.set_defaults(func=cmd_wallet)
    q = pw.add_parser("import", help="从助记词导入 / 恢复钱包")
    q.add_argument("--name", required=True, help="钱包名称")
    q.add_argument("--mnemonic", help="12/24 个英文单词（省略则交互输入，避免写入命令行历史）")
    q.add_argument("--password", help="为钱包文件设置口令")
    q.add_argument("--label", default="", help="备注")
    q.set_defaults(func=cmd_wallet)
    q = pw.add_parser("list", help="列出钱包")
    q.set_defaults(func=cmd_wallet)
    q = pw.add_parser("show", help="查看钱包详情")
    q.add_argument("--name", required=True)
    q.add_argument("--password")
    q.add_argument("--mnemonic", action="store_true", help="显示助记词（会先给出安全警告）")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_wallet)
    q = pw.add_parser("export", help="导出钱包备份")
    q.add_argument("--name", required=True)
    q.add_argument("--password")
    q.add_argument("--out", help="导出文件路径")
    q.add_argument("--new-password", help="备份使用的新口令；留空表示不加密")
    q.set_defaults(func=cmd_wallet)

    def add_action_args(q, with_wallet=True):
        if with_wallet:
            q.add_argument("--wallet", required=True, help="用于签名的钱包名称")
            q.add_argument("--password", help="钱包口令（省略则交互输入或用 ARTCHAIN_PASSWORD）")
        q.add_argument("--no-mine", action="store_true", help="只提交到待打包池，不立即出块")

    p = sub.add_parser("register", help="登记作品并完成确权")
    add_action_args(p)
    p.add_argument("--file", required=True, help="作品文件路径")
    p.add_argument("--title", help="作品名称（默认取文件名）")
    p.add_argument("--category", default="美术作品", choices=list(service.CATEGORIES),
                   help="作品类别")
    p.add_argument("--author", default="", help="作者署名")
    p.add_argument("--year", type=int, help="创作年份")
    p.add_argument("--created", help="创作完成日期 YYYY-MM-DD")
    p.add_argument("--desc", help="作品说明")
    p.add_argument("--meta", action="append", help="附加元数据 key=value，可重复")
    p.add_argument("--no-store", action="store_true", help="不把原件保存到链下存储")
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("transfer", help="转让著作权")
    add_action_args(p)
    p.add_argument("--work", required=True, help="作品编号")
    p.add_argument("--to", required=True, help="受让方地址")
    p.add_argument("--price", help="转让价款")
    p.add_argument("--note", help="备注")
    p.set_defaults(func=cmd_transfer)

    p = sub.add_parser("license", help="登记授权许可")
    add_action_args(p)
    p.add_argument("--work", required=True, help="作品编号")
    p.add_argument("--to", required=True, help="被许可方地址")
    p.add_argument("--scope", default="非独家", choices=["独家", "非独家"], help="授权类型")
    p.add_argument("--territory", default="全球", help="授权地域")
    p.add_argument("--royalty", help="授权费用")
    p.add_argument("--start", help="起始日 YYYY-MM-DD")
    p.add_argument("--end", help="截止日 YYYY-MM-DD")
    p.add_argument("--purpose", help="授权用途")
    p.set_defaults(func=cmd_license)

    p = sub.add_parser("dispute", help="对某件作品提出权属异议")
    add_action_args(p)
    p.add_argument("--work", required=True, help="作品编号")
    p.add_argument("--reason", required=True, help="异议理由")
    p.add_argument("--evidence", help="证据文件的 SHA-256")
    p.set_defaults(func=cmd_dispute)

    p = sub.add_parser("revoke", help="撤销自己的登记")
    add_action_args(p)
    p.add_argument("--work", required=True, help="作品编号")
    p.add_argument("--reason", help="撤销理由")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("adjudicate", help="裁决权属争议（须由与本案无关的第三方发起）")
    add_action_args(p)
    p.add_argument("--work", required=True, help="作品编号")
    p.add_argument("--ruling", required=True, choices=RULINGS,
                   help="驳回＝异议不成立，恢复有效；支持＝异议成立，登记转为无效")
    p.add_argument("--reason", required=True, help="裁决理由")
    p.add_argument("--evidence", help="裁决依据的证据文件 SHA-256")
    p.set_defaults(func=cmd_adjudicate)

    p = sub.add_parser("mine", help="打包待处理交易并出块")
    p.add_argument("--mine-with", help="出块钱包名称")
    p.add_argument("--password", help="钱包口令")
    p.add_argument("--address", help="直接指定出块人地址")
    p.add_argument("--time", type=int, help="指定区块时间戳（用于复现）")
    p.add_argument("--allow-empty", action="store_true", help="允许打包空区块")
    p.set_defaults(func=cmd_mine)

    p = sub.add_parser("points", help="平台积分：查看流通量与流水")
    p.add_argument("--address", help="查询某个地址的余额与流水")
    p.add_argument("--top", type=int, help="同时显示余额排行前 N 名")
    p.add_argument("--limit", type=int, default=20, help="流水显示条数（默认 20）")
    p.set_defaults(func=cmd_points)

    p = sub.add_parser("pay", help="平台积分：转账给其他地址")
    add_action_args(p)
    p.add_argument("--to", required=True, help="收款方地址")
    p.add_argument("--amount", required=True, help="转账金额（最多 8 位小数）")
    p.add_argument("--memo", help="备注")
    p.set_defaults(func=cmd_pay)

    p = sub.add_parser("mint", help="平台积分：铸造（仅限运营方地址）")
    add_action_args(p)
    p.add_argument("--amount", required=True, help="铸造数量（最多 8 位小数）")
    p.add_argument("--memo", help="备注")
    p.set_defaults(func=cmd_mint)

    p = sub.add_parser("burn", help="平台积分：销毁（仅限运营方地址）")
    add_action_args(p)
    p.add_argument("--amount", required=True, help="销毁数量（最多 8 位小数）")
    p.add_argument("--memo", help="备注")
    p.set_defaults(func=cmd_burn)

    p = sub.add_parser("works", help="列出已确权作品")
    p.add_argument("--owner", help="按当前权利人筛选")
    p.add_argument("--keyword", help="按名称/作者/编号搜索")
    p.add_argument("--status", choices=["有效", "争议中", "已撤销"], help="按状态筛选")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_works)

    p = sub.add_parser("work", help="查看作品确权详情")
    p.add_argument("--id", required=True, help="作品编号")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_work)

    p = sub.add_parser("blocks", help="浏览区块")
    p.add_argument("--height", type=int, help="查看指定高度的区块")
    p.add_argument("--limit", type=int, default=15, help="列出最近多少个区块")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_blocks)

    p = sub.add_parser("mempool", help="查看待打包交易")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_mempool)

    p = sub.add_parser("verify", help="重新校验整条链的完整性")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("verify-cert", help="验证一份确权证书")
    p.add_argument("--file", required=True, help="证书文件（JSON 格式）")
    p.add_argument("--offline", action="store_true",
                   help="只做自洽校验，不与本地链比对（结论较弱，无法证明确权成立）")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify_cert)

    p = sub.add_parser("compare", help="侵权比对取证")
    p.add_argument("--file", required=True, help="待比对的作品文件")
    p.add_argument("--work", help="只与指定作品比对")
    p.add_argument("--top", type=int, default=10, help="返回最相似的前 N 条")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("check-original", help="校验链下原件是否与链上指纹一致")
    p.add_argument("--work", required=True, help="作品编号")
    p.set_defaults(func=cmd_check_original)

    p = sub.add_parser("cert", help="导出确权证书")
    p.add_argument("--work", required=True, help="作品编号")
    p.add_argument("--format", default="html", choices=["html", "json", "text"], help="证书格式")
    p.add_argument("--out", help="输出文件路径")
    p.add_argument("--issuer", help="出具机构名称")
    p.add_argument("--print", action="store_true", help="同时在终端打印证书内容")
    p.set_defaults(func=cmd_cert)

    p = sub.add_parser("peer", help="节点管理")
    pp = p.add_subparsers(dest="peer_action")
    q = pp.add_parser("add", help="添加节点")
    q.add_argument("--url", required=True, help="节点地址，如 http://127.0.0.1:8001")
    q.set_defaults(func=cmd_peer)
    q = pp.add_parser("list", help="列出节点")
    q.set_defaults(func=cmd_peer)
    q = pp.add_parser("remove", help="移除节点")
    q.add_argument("--url", required=True)
    q.set_defaults(func=cmd_peer)

    p = sub.add_parser("sync", help="与其他节点同步（最长链共识）")
    p.add_argument("--url", help="指定单个节点；省略则同步 peers 中的全部节点")
    p.add_argument("--timeout", type=float, default=10.0)
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("apikey", help="开放平台 API Key 管理（签发/列表/吊销）")
    pa = p.add_subparsers(dest="apikey_action")
    q = pa.add_parser("create", help="签发新密钥（明文仅显示一次）")
    q.add_argument("--name", required=True, help="密钥名字（审计指认用）")
    q.add_argument("--scopes", default="read",
                   help="权限档，逗号分隔：read / write（默认 read）")
    q.add_argument("--note", default="", help="备注（如：合作方 XX 平台）")
    q.set_defaults(func=cmd_apikey)
    q = pa.add_parser("list", help="列出密钥（不含密钥材料）")
    q.set_defaults(func=cmd_apikey)
    q = pa.add_parser("revoke", help="吊销密钥")
    q.add_argument("--id", required=True, help="密钥 id（list 可见）")
    q.set_defaults(func=cmd_apikey)

    p = sub.add_parser("purchase", help="积分购买/兑换通道（地区识别、定价、订单管理与交付）")
    pp = p.add_subparsers(dest="purchase_action")
    q = pp.add_parser("region", help="IP 地区识别（测试用）")
    q.add_argument("--ip", help="要测试的 IP（缺省 127.0.0.1）")
    q = pp.add_parser("methods", help="列出可见支付通道（按当前 IP 模拟）")
    q.add_argument("--ip", help="模拟访客 IP（缺省 127.0.0.1）")
    q = pp.add_parser("orders", help="列出订单")
    q.add_argument("--address", help="按买家地址过滤")
    q.add_argument("--status", help="按状态过滤：pending/delivered/canceled/expired")
    q = pp.add_parser("cancel", help="取消待支付订单")
    q.add_argument("--order", required=True, help="订单号")
    q = pp.add_parser("confirm", help="运营方确认收款并交付积分（MINT+PAY）")
    q.add_argument("--order", required=True, help="订单号")
    q.add_argument("--wallet", required=True, help="运营方钱包名")
    q.add_argument("--password", help="钱包口令/助记词")
    q.add_argument("--ref", help="支付凭证（ETH/USDT 交易哈希等）")
    p.set_defaults(func=cmd_purchase)

    p = sub.add_parser("serve", help="启动 HTTP API 与网页界面")
    p.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机）")
    p.add_argument("--port", type=int, default=8080, help="端口")
    p.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("desktop", help="打开桌面可视化窗口（Tkinter，无需浏览器）")
    p.set_defaults(func=cmd_desktop)

    p = sub.add_parser("reset", help="清空链数据")
    p.add_argument("--yes", action="store_true", help="确认执行")
    p.add_argument("--with-wallets", action="store_true", help="连钱包一起删除")
    p.set_defaults(func=cmd_reset)

    p = sub.add_parser("version", help="显示版本与环境信息")
    p.set_defaults(func=cmd_version)

    p = sub.add_parser("selftest", help="运行内置自检（密码学/图像/区块链/全流程）")
    p.add_argument("--quiet", action="store_true", help="只输出结果")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("demo", help="一键跑通完整业务演示")
    p.add_argument("--reset", action="store_true", help="先清空数据再演示")
    p.add_argument("--keep", action="store_true", help="演示结束后保留数据（默认也保留）")
    p.set_defaults(func=cmd_demo)

    return parser


def main(argv=None):
    # Windows 控制台默认不是 UTF-8，这里主动切换，保证中文与表格正常显示
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE

    ctx = Context(data_dir=args.data)
    try:
        return args.func(ctx, args)
    except (ChainError, WalletError, StoreError, TxError, LedgerError, ValueError,
            service.ServiceError, cert_mod.CertificateError, imagelib.UnsupportedImage) as exc:
        print("", file=sys.stderr)
        fail(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        fail("已被用户中断")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
