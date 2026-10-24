# -*- coding: utf-8 -*-
"""ArtChain 开放平台 SDK（零依赖，纯标准库）。

两块能力：

- :class:`OpenClient` —— HTTP 客户端：携带 API Key 调用 ``/open/v1`` 接口，
  读档（状态/作品/证明/积分/验证）与写档（提交已签名交易）；
- :class:`LocalSigner` —— 本地签名器：私钥与助记词**永不离开本机**，
  只在本地完成构造与签名，网络上跑的只有签好名的交易。

第三方接入的典型流程::

    from artchain.sdk import OpenClient, LocalSigner

    client = OpenClient("http://节点地址:8080", "ak_你的密钥")
    signer = LocalSigner.from_mnemonic("你的 12 个助记词单词 ...")

    nonce = client.next_nonce(signer.address)["next_nonce"]
    tx = signer.make_tx("PAY", {"to": 对方地址, "units": 100000000}, nonce=nonce)
    print(client.submit_tx(tx))          # 默认自动打包出块

读档接口不需要签名，有 read 权限的 Key 即可；写档接口只接受**已签名**交易，
节点会做完整校验（签名、nonce、业务规则预演），因此服务端从头到尾碰不到私钥。
"""

import base64
import json
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE_URL = "http://127.0.0.1:8080"


class OpenAPIError(Exception):
    """开放接口调用失败：message 为服务端错误说明，status 为 HTTP 状态码。"""

    def __init__(self, message, status=0, payload=None):
        Exception.__init__(self, message)
        self.status = status
        self.payload = payload


class OpenClient(object):
    """带 API Key 的 /open/v1 客户端。"""

    def __init__(self, base_url=DEFAULT_BASE_URL, api_key="", timeout=20):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or ""
        self.timeout = timeout

    # ------------------------------------------------------------ 基础
    def _request(self, method, path, payload=None):
        url = self.base_url + path
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if self.api_key:
            request.add_header("Authorization", "Bearer " + self.api_key)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8"))
            except Exception:                                  # noqa: BLE001
                raise OpenAPIError("HTTP %d" % exc.code, exc.code)
            raise OpenAPIError(body.get("error") or ("HTTP %d" % exc.code),
                               exc.code, body)
        except urllib.error.URLError as exc:
            raise OpenAPIError("无法连接节点：%s" % exc.reason)
        if not body.get("ok"):
            raise OpenAPIError(body.get("error", "未知错误"), 0, body)
        return body.get("data")

    # ------------------------------------------------------------ 读档
    def status(self):
        """链状态与开放平台信息（含本次调用所用 Key 的名字）。"""
        return self._request("GET", "/open/v1/status")

    def keyinfo(self):
        """当前 Key 的权限档与用量。"""
        return self._request("GET", "/open/v1/keyinfo")

    def works(self):
        """已确权作品列表（对外视图，不含服务端路径）。"""
        return self._request("GET", "/open/v1/works")["works"]

    def work(self, work_id):
        """单件作品详情 + 上链存在性证明。"""
        return self._request("GET", "/open/v1/works/" + urllib.parse.quote(work_id))

    def proof(self, work_id):
        """Merkle 包含证明（可离线自验：self_consistent 字段）。"""
        return self._request("GET", "/open/v1/proof/" + urllib.parse.quote(work_id))

    def block(self, height):
        """指定块高的完整区块。"""
        return self._request("GET", "/open/v1/block/%d" % int(height))["block"]

    def points(self):
        """平台积分账本概览（供给、持有人、流水）。"""
        return self._request("GET", "/open/v1/points")

    def next_nonce(self, address):
        """某地址的下一个可用 nonce（构造交易前必查，防重放）。"""
        return self._request("GET", "/open/v1/nonce?address="
                             + urllib.parse.quote(address))

    def verify_fingerprint(self, sha256_hex):
        """用文件指纹（sha256）查链上锚定：是否命中、命中哪些作品。"""
        return self._request("POST", "/open/v1/verify",
                             {"fingerprint": sha256_hex})

    def verify_file(self, content, filename=""):
        """直接传文件字节：服务端复算指纹后查链上锚定。"""
        return self._request("POST", "/open/v1/verify", {
            "content_base64": base64.b64encode(bytes(content)).decode("ascii"),
            "filename": filename})

    def compare(self, content, filename="", work_id=None, top=10):
        """侵权比对：把一份文件与链上作品逐一相似度排行。"""
        payload = {
            "content_base64": base64.b64encode(bytes(content)).decode("ascii"),
            "filename": filename, "top": int(top)}
        if work_id:
            payload["work_id"] = work_id
        return self._request("POST", "/open/v1/compare", payload)

    # ------------------------------------------------------------ 写档
    def submit_tx(self, tx, auto_mine=True):
        """提交一笔**已签名**交易；auto_mine=True 时节点随即打包出块。"""
        return self._request("POST", "/open/v1/tx",
                             {"tx": tx, "auto_mine": bool(auto_mine)})


class LocalSigner(object):
    """本地签名器：私钥不出本机。依赖本仓库的 crypto/core 模块做派生与签名。"""

    def __init__(self, private_key, mnemonic=None):
        from .crypto import secp256k1 as ec
        if isinstance(private_key, str):
            private_key = int(private_key, 16)
        self.private_key = int(private_key)
        pubkey = ec.pubkey_from_private(self.private_key, compressed=True)
        self.pubkey = pubkey.hex()
        self.address = ec.pubkey_to_address(pubkey)
        self.mnemonic = mnemonic

    @classmethod
    def from_mnemonic(cls, mnemonic):
        """从 12/24 词助记词派生（BIP39 -> BIP32 m/44'/20100'/0'/0/0）。"""
        from .crypto import bip32, bip39
        words = " ".join(str(mnemonic).split())
        if not bip39.validate(words):
            raise ValueError("助记词校验失败（词表/校验位不匹配）")
        return cls(bip32.derive_private_key(bip39.to_seed(words)), mnemonic=words)

    @classmethod
    def generate(cls):
        """现场生成一组新身份（返回 (signer, mnemonic)），助记词请自行妥善保管。"""
        from .crypto import bip32, bip39
        mnemonic = bip39.generate(128)
        return cls(bip32.derive_private_key(bip39.to_seed(mnemonic)),
                   mnemonic=mnemonic), mnemonic

    def make_tx(self, tx_type, data, nonce, memo=""):
        """构造并签名一笔交易（nonce 请用 OpenClient.next_nonce 获取）。"""
        from .core.tx import make_tx, sign_tx
        tx = make_tx(tx_type, self.address, self.pubkey, data,
                     memo=memo, nonce=int(nonce))
        return sign_tx(tx, self.private_key)

    def make_pay_tx(self, to_address, units, nonce, memo=""):
        """积分转账交易（units 为最小单位整数，1 积分 = 10**8；链上字段名 amount）。"""
        return self.make_tx("PAY", {"to": to_address, "amount": int(units)},
                            nonce=nonce, memo=memo)
