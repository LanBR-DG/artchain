# -*- coding: utf-8 -*-
"""HTTP API 与网页界面服务（基于标准库 http.server，无第三方依赖）。

    python -m artchain serve --port 8080 --open

接口一览（统一返回 {"ok": true, "data": ...} 或 {"ok": false, "error": "..."}）：
    GET  /                          网页界面
    GET  /api/status                链与账本概览
    GET  /api/chain                 全部区块（节点同步用）
    GET  /api/block/<高度>           单个区块
    GET  /api/works                 已确权作品列表
    GET  /api/work/<作品编号>        作品确权详情（含上链证明）
    GET  /api/mempool               待打包交易
    GET  /api/wallets               钱包列表（仅公开信息）
    GET  /api/network               已知节点
    GET  /api/blob/<作品编号>        链下保存的作品原件
    GET  /api/cert/<作品编号>        确权证书（html/json/text）
    GET  /api/posts                 社区帖子列表（可按作者/话题过滤）
    GET  /api/post/<帖子编号>        帖子详情（回复、点赞名单、上链证明）
    GET  /api/postimg/<帖子编号>     帖子附图（链下保存的原件）
    POST /api/login                 解锁钱包即登录（返回公开信息+链上足迹）
    POST /api/wallet/new            新建钱包
    POST /api/register              登记确权
    POST /api/post                  社区发帖 / 回复（正文全文上链）
    POST /api/like                  点赞（一址一赞，上链即永久）
    POST /api/transfer              版权转让
    POST /api/license               授权许可
    POST /api/dispute               权属争议
    POST /api/adjudicate            争议裁决（驳回异议 / 支持异议）
    POST /api/revoke                撤销登记
    POST /api/mine                  手动出块
    POST /api/compare               侵权比对
    POST /api/verify                全链校验
    POST /api/peer                  添加节点
    POST /api/sync                  与节点同步

安全提示：本服务默认只监听 127.0.0.1，且写操作需要提交钱包口令（明文走 HTTP），
仅适合本机演示与内网试用；若要对外提供服务，请自行叠加 HTTPS 与鉴权层。
"""

import base64
import collections
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

from . import __version__, apikeys, certificate, fingerprint, geofence, imagelib, service
from .core.chain import DEFAULT_DIFFICULTY, ChainError
from .core.state import LedgerError
from .crypto import rotpwd
from .store import StoreError
from .wallet import Wallet, WalletError

MAX_BODY = 64 * 1024 * 1024      # 单次上传上限 64MB
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

_MIME = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
    ".bmp": "image/bmp", ".webp": "image/webp", ".tif": "image/tiff", ".tiff": "image/tiff",
    ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
    ".pdf": "application/pdf", ".svg": "image/svg+xml",
}

# 允许 inline（浏览器直接展示）的后缀白名单。
#
# 刻意不含 .svg：SVG 是 XML，内部可以带 <script>，一旦以 image/svg+xml 内联返回，
# 上传者就能在别人的浏览器里执行脚本——典型的存储型 XSS。
# .txt/.md 也不内联（避免内容被当成 HTML 解析），普通图片类型则没有这个问题。
# 原件后缀来自上传者可控的 filename，所以这里必须是白名单而不是黑名单。
_SAFE_INLINE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}

# 缩略图内存缓存：键 (stored_path, width)。缩略图生成一次（尤其纯 Python 解码
# 大图时耗时明显），之后直接命中缓存；LRU 上限防止长跑服务的内存无界增长。
_THUMB_CACHE = collections.OrderedDict()
_THUMB_CACHE_MAX = 64
_THUMB_CACHE_LOCK = threading.Lock()

# 非内联内容一律用这个响应头兜底：即便将来白名单被放宽，
# sandbox 也会让浏览器把内容放进唯一来源里，不给它碰本站 cookie/storage 的机会。
_BLOB_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"

# 法律协议的现行版本：同意记录由服务端写入版本号（不信任客户端传参），
# 文档修订时递增对应版本，历史同意记录即可证明用户当时同意的是哪一版。
LEGAL_DOC_VERSIONS = {"terms": "1.0", "privacy": "1.0", "points": "1.1", "community": "1.0"}


def _blob_filename(stored_path, base_name, title=""):
    """构造 Content-Disposition 用的文件名，返回 (ascii 回退名, UTF-8 star 名或 None)。

    只保留 ASCII 的安全字符：标题和路径都来自链上数据（可能是别人同步过来的），
    直接拼进响应头会被换行符注入伪造额外的头。
    """
    ext = os.path.splitext(stored_path or "")[1].lower()
    ext = "".join(ch for ch in ext if ch.isalnum() or ch == ".")[:12]
    ascii_name = "%s%s" % (base_name or "file", ext)
    ascii_name = "".join(ch for ch in ascii_name if ch.isalnum() or ch in "._-") or "file"
    title = (title or "").strip()
    if not title:
        return ascii_name, None
    return ascii_name, quote("%s%s" % (title, ext), safe="")


class ApiError(Exception):
    def __init__(self, message, status=400):
        Exception.__init__(self, message)
        self.status = status


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "ArtChain/%s" % __version__
    protocol_version = "HTTP/1.1"
    ctx = None          # 由 serve() 注入
    quiet = False
    # 单连接的读写超时（秒）。StreamRequestHandler.setup 会把它设到 socket 上。
    # 不设的话，客户端只要声明一个 Content-Length 再慢慢滴字节，
    # 就能让 self.rfile.read(length) 无限期阻塞，长期占住一个处理线程。
    timeout = 30

    # ------------------------------------------------------------ 基础
    def log_message(self, fmt, *args):
        if not self.quiet:
            print("  %s - %s" % (time.strftime("%H:%M:%S"), fmt % args))

    def _send(self, body, content_type, status=200, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(body, "application/json; charset=utf-8", status)

    def _ok(self, data):
        self._send_json({"ok": True, "data": data})

    def _fail(self, message, status=400):
        self._send_json({"ok": False, "error": str(message)}, status)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            # 这里刻意不读请求体就返回 413。但在 HTTP/1.1 的 keep-alive 下，
            # 未读的字节会留在缓冲里，被当成下一个请求的请求行来解析（连接错位）。
            # 与其去读掉几十 MB，不如直接关掉这条连接。
            self.close_connection = True
            raise ApiError("请求体过大（上限 %d 字节）" % MAX_BODY, 413)
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            raise ApiError("请求体不是合法的 JSON")
        if not isinstance(payload, dict):
            raise ApiError("请求体必须是 JSON 对象")
        return payload

    @staticmethod
    def _decode_upload(payload):
        encoded = payload.get("content_base64") or ""
        if not encoded:
            raise ApiError("缺少文件内容 content_base64")
        try:
            data = base64.b64decode(encoded, validate=False)
        except Exception:
            raise ApiError("文件内容不是合法的 base64 编码")
        if not data:
            raise ApiError("上传的文件为空")
        if len(data) > MAX_BODY:
            raise ApiError("文件过大", 413)
        return data

    def _ctx(self):
        if self.ctx is None:
            raise ApiError("服务未初始化", 500)
        return self.ctx

    def _chain(self):
        ctx = self._ctx()
        ctx.ensure_loaded()
        # 必须返回 Blockchain 本身。曾经这里返回的是 Context，
        # 而 Context 上既没有 ledger / height / mempool，也没有 statistics()，
        # 于是所有 /api/* 路由都会 AttributeError 后变成 500——
        # 网页能打开，但每一个接口都是死的。
        return ctx.chain

    def _wallet(self, payload):
        """按请求体里的 wallet / password 解锁钱包。"""
        ctx = self._ctx()
        name = (payload.get("wallet") or "").strip()
        if not name:
            raise ApiError("缺少 wallet 字段")
        # 只用请求体里的口令。曾经这里会回退到环境变量 ARTCHAIN_PASSWORD，
        # 那等于让任何不带 password 字段的请求自动通过鉴权——已移除。
        # 注意 Context.wallet 收到的 prompt 是 False，它内部的环境变量回退
        # 也因此不会被触发，两处必须同时保持这个约束。
        password = payload.get("password")
        try:
            return ctx.wallet(name, password, prompt=False)
        except WalletError as exc:
            raise ApiError(str(exc), 401)

    def _serve_stored(self, stored_path, base_name, title="", wants_download=False,
                      missing="该文件没有在本地保存，无法读取"):
        """按白名单策略返回链下 files/ 里保存的文件（作品原件与帖子附图共用）。

        安全约束与原 /api/blob 完全一致，改动这里等于同时改动两者：
        blob_abspath 内部做了 realpath 包含性校验，越界路径按"没有原件"处理；
        只有白名单内的图片才 inline，其余（含 .svg / .txt / .pdf）一律下载；
        响应统一带 sandbox CSP 兜底。
        """
        ctx = self._ctx()
        data = ctx.store.blob_data(stored_path)
        if data is None:
            raise ApiError(missing, 404)
        ext = os.path.splitext(stored_path)[1].lower()
        ctype = _MIME.get(ext, "application/octet-stream")
        ascii_name, star_name = _blob_filename(stored_path, base_name, title)
        if wants_download or ext not in _SAFE_INLINE_EXT:
            disposition = 'attachment; filename="%s"' % ascii_name
            if star_name:
                disposition += "; filename*=UTF-8''%s" % star_name
        else:
            disposition = 'inline; filename="%s"' % ascii_name
        headers = {
            "Content-Disposition": disposition,
            "Content-Security-Policy": _BLOB_CSP,
        }
        return ((data, ctype), 200, "raw", headers)

    # ------------------------------------------------------------ 路由
    def do_OPTIONS(self):
        self._send(b"", "text/plain", 204, {"Allow": "GET, POST, OPTIONS"})

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        try:
            if path.startswith("/open/"):
                # 开放平台：API Key 鉴权 + 权限档 + 限流，独立于控制台接口
                result = self._route_open(method, path, query)
            elif method == "GET":
                result = self._route_get(path, query)
            else:
                result = self._route_post(path, query)
            if isinstance(result, tuple):     # (data, status) / (payload, status, "raw"[, 额外响应头])
                if len(result) >= 3 and result[2] == "raw":
                    extra = result[3] if len(result) > 3 else None
                    self._send(result[0][0], result[0][1], result[1], extra)
                else:
                    self._send_json({"ok": True, "data": result[0]}, result[1])
            else:
                self._ok(result)
        except ApiError as exc:
            self._fail(exc, exc.status)
        except (ChainError, service.ServiceError, WalletError, LedgerError,
                certificate.CertificateError, StoreError) as exc:
            self._fail(exc, 400)
        except ValueError as exc:
            self._fail(exc, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except socket.timeout:
            # 读请求超时（见 ApiHandler.timeout）。这里不能再写响应——对端很可能
            # 根本没在等；直接标记关闭，交给上层 handle_one_request 收尾。
            self.close_connection = True
        except Exception as exc:  # noqa: BLE001 - 兜底，避免单个请求打挂服务
            import traceback
            traceback.print_exc()
            self._fail("服务内部错误：%s" % exc, 500)

    # ------------------------------------------------------------ 开放平台
    def _client_region(self):
        """基于请求来源 + 配置的代理信任策略，返回 (ip, region, label)。"""
        ctx = self._ctx()
        config = ctx.store.load_config()
        trust_proxy = bool(config.get("geofence_trust_proxy"))
        default_region = config.get("geofence_default_region") or "CN"
        ip = geofence.client_ip(self.headers, self.client_address[0],
                                 trust_proxy=trust_proxy)
        region, label, _detail = geofence.region_of(ip, store=ctx.store,
                                                    default=default_region)
        return ip, region, label

    def _open_auth(self, scope):
        """开放平台鉴权：Bearer / X-API-Key -> 校验哈希 -> 权限档 -> 滑动限流。"""
        presented = ""
        header = self.headers.get("Authorization") or ""
        if header.lower().startswith("bearer "):
            presented = header.split(None, 1)[1].strip()
        presented = presented or (self.headers.get("X-API-Key") or "").strip()
        if not presented:
            raise ApiError("缺少 API Key：请携带 Authorization: Bearer ak_... "
                           "或 X-API-Key 请求头", 401)
        record = apikeys.verify_key(self._ctx().store, presented)
        if record is None:
            raise ApiError("API Key 无效或已吊销", 401)
        if scope not in record.get("scopes", []):
            raise ApiError("该 Key 无 %s 权限（已授予：%s）"
                           % (scope, ",".join(record.get("scopes", []))), 403)
        ok, _used, limit = apikeys.check_rate(record["id"], scope)
        if not ok:
            raise ApiError("限流：单 Key 每分钟最多 %d 次 %s 请求，请稍后再试"
                           % (limit, scope), 429)
        return record

    @staticmethod
    def _open_work_view(work):
        """对外作品视图：只给确权相关字段，不含 stored_path 等服务端路径。"""
        return {key: work.get(key) for key in (
            "work_id", "title", "author", "owner", "category", "status",
            "registered_at", "height", "txid", "size", "kind",
            "file_hash", "phash", "ahash", "dhash", "simhash")}

    def _route_open(self, method, path, query):
        parts = [seg for seg in path.split("/") if seg]
        if len(parts) < 2 or parts[0] != "open" or parts[1] != "v1":
            raise ApiError("开放接口路径应为 /open/v1/...", 404)
        rest = "/".join(parts[2:])
        # 权限档：只有提交已签名交易是写；验证/比对只读链上数据，属读档
        scope = "write" if (method == "POST" and rest == "tx") else "read"
        record = self._open_auth(scope)
        payload = self._read_json_body() if method == "POST" else {}
        chain = self._chain()

        if method == "GET":
            if rest == "status":
                stats = chain.statistics()
                return {"open_api": "v1", "key": record["name"],
                        "chain_name": stats.get("chain_name"),
                        "height": stats.get("height"),
                        "difficulty": stats.get("difficulty"),
                        "latest_block_hash": stats.get("latest_block_hash"),
                        "works_total": stats.get("works_total"),
                        "points_supply": stats.get("points_supply"),
                        "points_holders": stats.get("points_holders"),
                        "server_version": __version__}
            if rest == "works":
                return {"works": [self._open_work_view(w)
                                  for w in chain.ledger.list_works()]}
            if rest.startswith("works/"):
                work = chain.ledger.get_work(rest.split("/", 1)[1])
                if work is None:
                    raise ApiError("作品不存在", 404)
                return {"work": self._open_work_view(work),
                        "proof": chain.proof_of(work["work_id"])}
            if rest == "points":
                return service.points_overview(chain)
            if rest.startswith("block/"):
                try:
                    height = int(rest.split("/", 1)[1])
                except ValueError:
                    raise ApiError("块高必须是整数", 400)
                if not 0 <= height < len(chain.blocks):
                    raise ApiError("块高越界", 404)
                return {"block": chain.blocks[height]}
            if rest.startswith("proof/"):
                proof = chain.proof_of(rest.split("/", 1)[1])
                if proof is None:
                    raise ApiError("作品不存在或尚未上链", 404)
                proof["self_consistent"] = chain.check_proof(proof)
                return proof
            if rest == "nonce":
                address = (query.get("address") or [""])[0].strip()
                if not address:
                    raise ApiError("请提供 address 参数", 400)
                return {"address": address,
                        "next_nonce": service.next_nonce_for(chain, address)}
            if rest == "keyinfo":
                return {key: record.get(key) for key in
                        ("id", "name", "scopes", "uses", "last_used_at",
                         "created_at")}
            raise ApiError("未知开放接口：GET /open/v1/%s" % rest, 404)

        if rest == "verify":
            digest = (payload.get("fingerprint") or payload.get("sha256")
                      or "").strip()
            if not digest and payload.get("content_base64"):
                content = self._decode_upload(payload)
                digest = fingerprint.fingerprint_bytes(
                    content, filename=payload.get("filename") or "")["sha256"]
            if not digest:
                raise ApiError("请提供 fingerprint（sha256）或 content_base64", 400)
            hits = [self._open_work_view(w) for w in chain.ledger.list_works()
                    if w.get("file_hash") == digest]
            return {"fingerprint": digest, "matched": bool(hits), "works": hits}
        if rest == "compare":
            content = self._decode_upload(payload)
            return service.compare_content(chain, content,
                                           filename=payload.get("filename") or "",
                                           work_id=payload.get("work_id"),
                                           top=int(payload.get("top") or 10))
        if rest == "tx":
            tx = payload.get("tx")
            if not isinstance(tx, dict):
                raise ApiError("请在 tx 字段提供已签名的交易对象", 400)
            ok, message = chain.submit(tx, verify=True)
            if not ok:
                raise ApiError(message, 400)
            result = {"accepted": True, "txid": tx.get("txid")}
            if payload.get("auto_mine", True):
                result["mined"] = service.mine_now(chain, self._ctx().store, "")
            return result
        raise ApiError("未知开放接口：POST /open/v1/%s" % rest, 404)

    # ------------------------------------------------------------ GET
    def _route_get(self, path, query):
        ctx = self._ctx()

        if path in ("/", "/index.html"):
            return self._serve_index()

        if path == "/api/health":
            return {"status": "ok", "version": __version__, "time": int(time.time())}

        if path == "/api/status":
            chain = self._chain()
            stats = chain.statistics()
            stats["peers"] = ctx.store.load_peers()
            stats["wallets"] = len(ctx.store.list_wallets())
            stats["storage"] = ctx.store.storage_usage()
            stats["image_backend"] = imagelib.backend_name()
            stats["data_dir"] = ctx.store.root
            return stats

        if path == "/api/chain":
            chain = self._chain()
            return {"height": chain.height, "difficulty": chain.difficulty,
                    "blocks": chain.blocks}

        if path.startswith("/api/block/"):
            chain = self._chain()
            try:
                height = int(path.rsplit("/", 1)[-1])
            except ValueError:
                raise ApiError("区块高度必须是整数")
            if not 0 <= height < len(chain.blocks):
                raise ApiError("区块高度超出范围", 404)
            return chain.blocks[height]

        if path == "/api/works":
            chain = self._chain()
            owner = (query.get("owner") or [None])[0]
            keyword = (query.get("q") or [None])[0]
            status = (query.get("status") or [None])[0]
            works = chain.ledger.list_works(owner=owner, keyword=keyword, status=status)
            return {"total": len(works), "works": works}

        if path.startswith("/api/work/"):
            chain = self._chain()
            work_id = path.rsplit("/", 1)[-1]
            return service.work_detail(chain, work_id)

        if path == "/api/mempool":
            chain = self._chain()
            return {"total": len(chain.mempool), "txs": chain.mempool}

        if path == "/api/wallets":
            items = []
            for name in ctx.store.list_wallets():
                payload = ctx.store.load_wallet(name)
                items.append({
                    "name": payload.get("name", name),
                    "address": payload.get("address", ""),
                    "encrypted": bool(payload.get("crypto")),
                    "created_at": payload.get("created_at"),
                    "label": (payload.get("meta") or {}).get("label", ""),
                })
            return {"total": len(items), "wallets": items}

        if path == "/api/network":
            return {"peers": ctx.store.load_peers(), "node": self.headers.get("Host", "")}

        if path.startswith("/api/blob/"):
            chain = self._chain()
            work_id = path.rsplit("/", 1)[-1]
            work = chain.ledger.get_work(work_id)
            if work is None:
                raise ApiError("作品不存在", 404)
            wants_download = bool((query.get("download") or [""])[0])
            return self._serve_stored(work.get("stored_path") or "",
                                      work.get("work_id") or "artwork",
                                      title=work.get("title"),
                                      wants_download=wants_download,
                                      missing="该作品没有可在本地读取的原件")

        if path.startswith("/api/thumb/"):
            # 缩略图：列表页 40px 的小图不再整幅下载原件（移动端流量的关键差异）。
            # Pillow 覆盖全部格式；纯标准库路径用自研彩色 PNG/BMP 解码 + 盒式采样，
            # 两者都处理不了的格式回退原图字节。
            chain = self._chain()
            work_id = path.rsplit("/", 1)[-1]
            work = chain.ledger.get_work(work_id)
            if work is None:
                raise ApiError("作品不存在", 404)
            stored = work.get("stored_path") or ""
            if not stored:
                raise ApiError("该作品没有在本地保存原件", 404)
            try:
                width = int((query.get("w") or ["96"])[0])
            except (TypeError, ValueError):
                raise ApiError("w 必须是整数")
            width = max(16, min(width, 512))
            key = (stored, width)
            with _THUMB_CACHE_LOCK:
                hit = _THUMB_CACHE.get(key)
                if hit is not None:
                    _THUMB_CACHE.move_to_end(key)
            if hit is None:
                blob = ctx.store.blob_data(stored)
                if blob is None:
                    raise ApiError("原件文件已丢失：%s" % stored, 404)
                try:
                    thumb, _mime = imagelib.thumbnail_bytes(blob, width)
                except imagelib.UnsupportedImage as exc:
                    raise ApiError("无法生成缩略图：%s" % exc, 415)
                if thumb is None:
                    # 无 Pillow 且原件不是 PNG/BMP：按扩展名回退原图
                    ext = os.path.splitext(stored)[1].lower()
                    ctype = _MIME.get(ext, "application/octet-stream")
                    return ((blob, ctype), 200, "raw",
                            {"Content-Security-Policy": _BLOB_CSP})
                with _THUMB_CACHE_LOCK:
                    _THUMB_CACHE[key] = thumb
                    while len(_THUMB_CACHE) > _THUMB_CACHE_MAX:
                        _THUMB_CACHE.popitem(last=False)
            return ((hit or thumb, "image/png"), 200, "raw",
                    {"Content-Security-Policy": _BLOB_CSP})

        if path.startswith("/api/cert/"):
            chain = self._chain()
            work_id = path.rsplit("/", 1)[-1]
            fmt = (query.get("format") or ["html"])[0].lower()
            cert = certificate.build_certificate(chain, work_id, store=ctx.store)
            if fmt == "json":
                return ((certificate.render_json(cert).encode("utf-8"),
                         "application/json; charset=utf-8"), 200, "raw")
            if fmt == "text":
                return ((certificate.render_text(cert).encode("utf-8"),
                         "text/plain; charset=utf-8"), 200, "raw")
            return ((certificate.render_html(cert).encode("utf-8"),
                     "text/html; charset=utf-8"), 200, "raw")

        if path == "/api/posts":
            chain = self._chain()
            return service.list_posts(
                chain,
                author=(query.get("author") or [None])[0],
                topic=(query.get("topic") or [None])[0],
                limit=(query.get("limit") or ["50"])[0],
                viewer=(query.get("viewer") or [None])[0])

        if path.startswith("/api/post/"):
            chain = self._chain()
            post_id = path.rsplit("/", 1)[-1]
            return service.post_detail(chain, post_id,
                                       viewer=(query.get("viewer") or [None])[0])

        if path.startswith("/api/postimg/"):
            chain = self._chain()
            post_id = path.rsplit("/", 1)[-1]
            post = chain.ledger.posts.get(post_id)
            if post is None:
                raise ApiError("帖子不存在", 404)
            if not (post.get("stored_path") or ""):
                raise ApiError("该帖子没有在本地保存附图", 404)
            wants_download = bool((query.get("download") or [""])[0])
            return self._serve_stored(post["stored_path"], post_id,
                                      wants_download=wants_download,
                                      missing="该帖子的附图没有在本地保存")

        if path == "/api/points":
            chain = self._chain()
            address = (query.get("address") or [None])[0]
            try:
                limit = int((query.get("limit") or ["20"])[0])
            except (TypeError, ValueError):
                limit = 20
            overview = service.points_overview(chain, address=address, limit=limit)
            top = (query.get("top") or [None])[0]
            if top:
                try:
                    overview["top"] = service.top_balances(chain, limit=int(top))
                except (TypeError, ValueError):
                    raise ApiError("top 必须是整数")
            return overview

        if path == "/api/purchase/methods":
            ip, region, region_label = self._client_region()
            return {"ip": ip, "region": region, "region_label": region_label,
                    "rails": service.purchase_methods(ctx.store, region),
                    "ranges": geofence.ranges_info(ctx.store)}

        if path == "/api/purchase/orders":
            address = (query.get("address") or [None])[0]
            status = (query.get("status") or [None])[0]
            orders = service.list_purchase_orders(ctx.store, address=address,
                                                  status=status)
            return {"orders": orders}

        if path == "/api/consent":
            ctx = self._ctx()
            wallet = (query.get("wallet") or [None])[0]
            record = ctx.store.latest_consent(wallet) if wallet else None
            return {"wallet": wallet, "consented": record is not None,
                    "record": record, "versions": LEGAL_DOC_VERSIONS}

        if path == "/api/bip39-words":
            # 导入助记词界面的联想提示用词表（公开标准数据，无敏感信息）
            from .crypto import bip39 as _bip39
            return {"words": list(_bip39.word_list())}

        # ---- PWA 静态资源（manifest / Service Worker / 应用图标） ----
        if path in ("/manifest.webmanifest", "/sw.js"):
            return self._serve_web_asset(path.lstrip("/"))
        if path.startswith("/icons/"):
            name = path.rsplit("/", 1)[-1]
            if name in ("icon-180.png", "icon-192.png", "icon-512.png",
                        "icon-maskable-512.png"):
                return self._serve_web_asset("icons/" + name)

        # ---- 法律协议页面（白名单：仅这几份文档与共享样式） ----
        if path.startswith("/legal/"):
            name = path.rsplit("/", 1)[-1]
            if name in ("terms.html", "privacy.html", "points.html",
                        "community.html", "style.css"):
                return self._serve_web_asset("legal/" + name)

        raise ApiError("未知接口：%s" % path, 404)

    def _serve_web_asset(self, rel):
        """返回 web/ 目录下的静态文件（白名单已在上层路由把关）。"""
        full = os.path.join(WEB_DIR, rel)
        if not os.path.isfile(full):
            raise ApiError("资源不存在：%s" % rel, 404)
        if rel.endswith(".webmanifest"):
            ctype = "application/manifest+json; charset=utf-8"
        elif rel.endswith(".js"):
            ctype = "application/javascript; charset=utf-8"
        elif rel.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        elif rel.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        else:
            ctype = "image/png"
        with open(full, "rb") as fh:
            return ((fh.read(), ctype), 200, "raw")

    def _serve_index(self):
        path = os.path.join(WEB_DIR, "index.html")
        if not os.path.exists(path):
            raise ApiError("未找到网页界面文件：%s" % path, 500)
        with open(path, "rb") as fh:
            return ((fh.read(), "text/html; charset=utf-8"), 200, "raw")

    # ------------------------------------------------------------ POST
    def _route_post(self, path, query):
        ctx = self._ctx()
        payload = self._read_json_body()

        if path == "/api/init":
            if ctx.store.has_chain():
                raise ApiError("该数据目录已存在区块链，如需重建请使用命令行 init --force")
            try:
                difficulty = int(payload.get("difficulty") or DEFAULT_DIFFICULTY)
            except (TypeError, ValueError):
                raise ApiError("难度必须是整数")
            if not 1 <= difficulty <= 6:
                raise ApiError("难度需在 1-6 之间（越大出块越慢）")
            ctx.chain.difficulty = difficulty
            block = ctx.chain.create_genesis(
                name=payload.get("name") or "ArtChain 艺术品确权链",
                description=payload.get("description") or "",
                operator=payload.get("operator") or "")
            ctx.chain.save()
            ctx.loaded = True
            return {"height": block["height"], "hash": block["hash"],
                    "difficulty": difficulty, "message": "创世区块已创建"}

        if path == "/api/wallet/new":
            name = (payload.get("name") or "").strip()
            password = payload.get("password")
            if not name:
                raise ApiError("请填写钱包名称")
            if name in ctx.store.list_wallets():
                raise ApiError("钱包 %s 已存在" % name)
            # 助记词只在创建响应里出现这一次——服务端不保存明文，
            # 前端负责展示并要求用户抄写验证。
            wallet, mnemonic = Wallet.create_with_mnemonic(
                ctx.store, name, password=password,
                meta={"label": payload.get("label") or ""},
                words=int(payload.get("words") or 12))
            info = wallet.public_info()
            info["mnemonic"] = mnemonic
            return info

        if path == "/api/wallet/import":
            name = (payload.get("name") or "").strip()
            password = payload.get("password")
            mnemonic = (payload.get("mnemonic") or "").strip()
            if not name:
                raise ApiError("请填写钱包名称")
            if not mnemonic:
                raise ApiError("请填写助记词")
            if name in ctx.store.list_wallets():
                raise ApiError("钱包 %s 已存在" % name)
            wallet = Wallet.from_mnemonic(
                ctx.store, name, mnemonic, password=password,
                meta={"label": payload.get("label") or ""})
            return wallet.public_info()

        if path == "/api/register":
            chain = self._chain()
            wallet = self._wallet(payload)
            content = self._decode_upload(payload)
            filename = payload.get("filename") or "未命名作品"
            result = service.register_work(
                chain, ctx.store, wallet, content, filename=filename,
                title=payload.get("title"), category=payload.get("category") or "美术作品",
                author=payload.get("author") or "", year=payload.get("year"),
                created_at=payload.get("created_at") or "",
                description=payload.get("description") or "",
                meta=payload.get("meta") or {},
                store_file=payload.get("store_file", True),
                auto_mine=payload.get("auto_mine", True))
            return result

        if path == "/api/transfer":
            chain = self._chain()
            wallet = self._wallet(payload)
            return service.transfer_work(chain, ctx.store, wallet,
                                         payload.get("work_id") or "", payload.get("to") or "",
                                         price=payload.get("price"), note=payload.get("note") or "",
                                         auto_mine=payload.get("auto_mine", True))

        if path == "/api/license":
            chain = self._chain()
            wallet = self._wallet(payload)
            return service.license_work(
                chain, ctx.store, wallet, payload.get("work_id") or "",
                payload.get("to") or "", scope=payload.get("scope") or "非独家",
                territory=payload.get("territory") or "全球", royalty=payload.get("royalty"),
                start=payload.get("start"), end=payload.get("end"),
                purpose=payload.get("purpose") or "", auto_mine=payload.get("auto_mine", True))

        if path == "/api/dispute":
            chain = self._chain()
            wallet = self._wallet(payload)
            return service.dispute_work(chain, ctx.store, wallet, payload.get("work_id") or "",
                                        payload.get("reason") or "",
                                        evidence_hash=payload.get("evidence_hash") or "",
                                        auto_mine=payload.get("auto_mine", True))

        if path == "/api/adjudicate":
            chain = self._chain()
            wallet = self._wallet(payload)
            return service.adjudicate_work(
                chain, ctx.store, wallet, payload.get("work_id") or "",
                payload.get("ruling") or "", payload.get("reason") or "",
                evidence_hash=payload.get("evidence_hash") or "",
                auto_mine=payload.get("auto_mine", True))

        if path == "/api/revoke":
            chain = self._chain()
            wallet = self._wallet(payload)
            return service.revoke_work(chain, ctx.store, wallet, payload.get("work_id") or "",
                                       reason=payload.get("reason") or "",
                                       auto_mine=payload.get("auto_mine", True))

        if path == "/api/mine":
            chain = self._chain()
            miner = ""
            if payload.get("wallet"):
                miner = self._wallet(payload).address
            elif payload.get("address"):
                miner = payload["address"]
            return service.mine_now(chain, ctx.store, miner)

        if path == "/api/compare":
            chain = self._chain()
            content = self._decode_upload(payload)
            return service.compare_content(chain, content,
                                           filename=payload.get("filename") or "",
                                           work_id=payload.get("work_id"),
                                           top=int(payload.get("top") or 10))

        if path == "/api/verify":
            chain = self._chain()
            ok, errors = chain.verify()
            return {"valid": ok, "errors": errors[:20],
                    "height": chain.height,
                    "blocks": len(chain.blocks),
                    "txs": sum(len(b["txs"]) for b in chain.blocks)}

        if path == "/api/peer":
            peer_url = (payload.get("url") or "").strip().rstrip("/")
            if not peer_url:
                raise ApiError("请填写节点地址")
            return {"peers": ctx.store.add_peer(peer_url)}

        if path == "/api/purchase/cancel":
            order_id = (payload.get("order_id") or "").strip()
            if not order_id:
                raise ApiError("请提供 order_id")
            return service.cancel_purchase_order(ctx.store, order_id)

        if path == "/api/purchase/order":
            address = (payload.get("address") or "").strip()
            rail = (payload.get("rail") or "").strip().lower()
            points = payload.get("points")
            if not address or not rail or points is None:
                raise ApiError("请提供 address / rail / points")
            ip, region, _label = self._client_region()
            try:
                order = service.create_purchase_order(
                    ctx.store, address, points, rail, region, client_ip=ip)
            except service.ServiceError as exc:
                # 加密通道对 CN 的关闭：状态 403，错误码明确
                if "中国大陆" in str(exc) or "加密货币" in str(exc):
                    raise ApiError(str(exc), 403)
                raise
            return {"order": order}

        if path == "/api/sync":
            chain = self._chain()
            url = (payload.get("url") or "").strip().rstrip("/")
            peers = [url] if url else ctx.store.load_peers()
            if not peers:
                raise ApiError("没有可同步的节点，请先添加")
            report = []
            for peer in peers:
                try:
                    remote = fetch_remote_chain(peer, timeout=15.0)
                except Exception as exc:
                    report.append({"peer": peer, "ok": False, "message": str(exc)})
                    continue
                replaced, message = chain.replace_chain(remote)
                report.append({"peer": peer, "ok": replaced, "message": message,
                               "remote_height": len(remote) - 1})
            if any(item["ok"] for item in report):
                chain.save()
            return {"report": report, "height": chain.height}

        if path == "/api/login":
            # 「钱包即账号」：能解锁钱包就是登录成功，没有独立的用户表。
            # 口令错误时 _wallet 抛 WalletError -> 401，前端据此提示。
            wallet = self._wallet(payload)
            return _session_info(ctx, wallet)

        if path == "/api/login-mnemonic":
            # 助记词即密钥：输入 12 词直接解锁对应钱包（固定口令/动态口令格式均适用）
            _name, wallet = _wallet_by_mnemonic(ctx, payload.get("mnemonic"))
            return _session_info(ctx, wallet)

        if path == "/api/reveal-password":
            # 查看当前动态口令：同时把钱包文件重加密到当前窗口，
            # 返回的口令在 60 秒内可用于普通口令解锁。
            name, wallet = _wallet_by_mnemonic(ctx, payload.get("mnemonic"))
            try:
                password, expires_in = wallet.rekey_rotating(ctx.store)
            except WalletError as exc:
                raise ApiError(str(exc), 400)
            return {"wallet": name, "address": wallet.address,
                    "password": password, "expires_in": expires_in,
                    "step_seconds": rotpwd.STEP_SECONDS,
                    "message": "口令每 %d 秒自动变化；到期后重新查看即可"
                               % rotpwd.STEP_SECONDS}

        if path == "/api/post":
            chain = self._chain()
            wallet = self._wallet(payload)
            image = None
            if payload.get("content_base64"):
                image = self._decode_upload(payload)
            return service.publish_post(
                chain, ctx.store, wallet, payload.get("text") or "",
                topic=payload.get("topic") or "",
                reply_to=payload.get("reply_to") or "",
                image=image, image_name=payload.get("filename") or "",
                auto_mine=payload.get("auto_mine", True))

        if path == "/api/like":
            chain = self._chain()
            wallet = self._wallet(payload)
            return service.like_post(chain, ctx.store, wallet,
                                     payload.get("post_id") or "",
                                     auto_mine=payload.get("auto_mine", True))

        if path == "/api/pay":
            chain = self._chain()
            wallet = self._wallet(payload)
            return service.transfer_points(
                chain, ctx.store, wallet, payload.get("to") or "",
                payload.get("amount"), memo=payload.get("memo") or "",
                auto_mine=payload.get("auto_mine", True))

        if path == "/api/mint":
            chain = self._chain()
            wallet = self._wallet(payload)
            return service.mint_points(
                chain, ctx.store, wallet, payload.get("amount"),
                memo=payload.get("memo") or "",
                auto_mine=payload.get("auto_mine", True))

        if path == "/api/burn":
            chain = self._chain()
            wallet = self._wallet(payload)
            return service.burn_points(
                chain, ctx.store, wallet, payload.get("amount"),
                memo=payload.get("memo") or "",
                auto_mine=payload.get("auto_mine", True))

        if path == "/api/consent":
            ctx = self._ctx()
            wallet = (payload.get("wallet") or "").strip()
            if not wallet:
                raise ApiError("缺少 wallet 字段")
            # 幂等：同一钱包、同一文档版本只留一条记录，重复解锁不刷屏
            record = ctx.store.latest_consent(wallet)
            if record and record.get("versions") == LEGAL_DOC_VERSIONS:
                return {"wallet": wallet, "consented": True, "record": record,
                        "versions": LEGAL_DOC_VERSIONS}
            record = ctx.store.record_consent(wallet, LEGAL_DOC_VERSIONS)
            return {"wallet": wallet, "consented": True, "record": record,
                    "versions": LEGAL_DOC_VERSIONS}

        raise ApiError("未知接口：%s" % path, 404)


# ================================================================ 对外工具
def _session_info(ctx, wallet):
    """组装登录会话返回：公开信息 + 链上足迹（/api/login 与助记词解锁共用）。"""
    info = wallet.public_info()
    address = wallet.address
    info["footprint"] = {"works_owned": 0, "works_created": 0,
                         "posts": 0, "likes_given": 0, "tx_count": 0}
    # 链未初始化也允许登录（用户正是登录后才去建创世区块的），
    # 此时足迹全为零，前端凭 chain_ready 决定是否展示初始化面板。
    info["chain_ready"] = ctx.ensure_loaded(required=False)
    if info["chain_ready"]:
        ledger = ctx.chain.ledger
        info["footprint"] = {
            "works_owned": sum(1 for w in ledger.works.values()
                               if w.get("owner") == address),
            "works_created": sum(1 for w in ledger.works.values()
                                 if w.get("creator") == address),
            "posts": sum(1 for p in ledger.posts.values()
                         if p.get("author") == address),
            "likes_given": sum(1 for lst in ledger.likes.values() if address in lst),
            "tx_count": int(ledger.nonces.get(address, 0)),
        }
    return info


def _wallet_by_mnemonic(ctx, mnemonic):
    """按助记词在本地钱包里找匹配者，返回 (名称, 已解锁钱包)；找不到抛错。"""
    mnemonic = (mnemonic or "").strip()
    if not mnemonic:
        raise ApiError("请填写助记词")
    for name in ctx.store.list_wallets():
        try:
            wallet = Wallet.from_mnemonic_unlocked(ctx.store, name, mnemonic)
            return name, wallet
        except WalletError:
            continue
    raise ApiError("没有钱包与这副助记词匹配（请核对 12 个单词的顺序）", 404)


def _warm_thumb_cache(ctx):
    """后台预热缩略图缓存：纯 Python 解码大图首帧可达秒级，
    启动时把已有作品的两个常用尺寸先生成好，用户第一次打开列表就是秒开。"""
    def worker():
        try:
            ctx.ensure_loaded()
            for work in list(ctx.chain.ledger.works.values()):
                stored = work.get("stored_path") or ""
                blob = ctx.store.blob_data(stored) if stored else None
                if blob is None:
                    continue
                for width in (96, 240):
                    try:
                        thumb, _ = imagelib.thumbnail_bytes(blob, width)
                    except Exception:
                        continue
                    if thumb is None:
                        continue
                    with _THUMB_CACHE_LOCK:
                        _THUMB_CACHE[(stored, width)] = thumb
                        while len(_THUMB_CACHE) > _THUMB_CACHE_MAX:
                            _THUMB_CACHE.popitem(last=False)
        except Exception:
            pass

    threading.Thread(target=worker, daemon=True).start()


def fetch_remote_chain(base_url, timeout=10.0):
    """从另一个节点拉取完整区块列表。"""
    url = base_url.rstrip("/") + "/api/chain"
    request = urllib.request.Request(url, headers={"User-Agent": "ArtChain/%s" % __version__})
    with urllib.request.urlopen(request, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    if not payload.get("ok"):
        raise ApiError("节点返回错误：%s" % payload.get("error"))
    return payload["data"]["blocks"]


def find_free_port(host, start=8080, tries=20):
    for port in range(start, start + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                continue
    raise ApiError("在 %d-%d 范围内找不到可用端口" % (start, start + tries))


def serve(ctx, host="127.0.0.1", port=8080, open_browser=False, quiet=False):
    """启动 HTTP 服务（阻塞）。"""
    ApiHandler.ctx = ctx
    ApiHandler.quiet = quiet
    _warm_thumb_cache(ctx)
    try:
        httpd = ThreadingHTTPServer((host, port), ApiHandler)
    except OSError as exc:
        raise ApiError("无法监听 %s:%d（%s）。可换个端口：--port 8081" % (host, port, exc))
    httpd.daemon_threads = True
    url = "http://%s:%d/" % (host if host != "0.0.0.0" else "127.0.0.1", port)

    print("")
    print("=" * 64)
    print("  ArtChain 服务已启动")
    print("=" * 64)
    print("  网页界面    %s" % url)
    print("  接口根路径  %sapi/status" % url)
    print("  数据目录    %s" % ctx.store.root)
    if ctx.store.has_chain():
        ctx.ensure_loaded()
        stats = ctx.chain.statistics()
        print("  当前链高    #%d（作品 %d 件，待打包 %d 笔）" % (
            stats["height"], stats["works_total"], stats["pending_txs"]))
    else:
        print("  提示        尚未初始化链，可先在网页上点击「初始化」或执行 init 命令")
    print("")
    print("  安全提醒    本服务仅监听本机，写操作需提交钱包口令；请勿直接暴露到公网。")
    print("  按 Ctrl+C 停止服务。")
    print("=" * 64)

    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("")
        print("  正在关闭服务…")
    finally:
        httpd.server_close()
    return 0
