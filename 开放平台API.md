# ArtChain 开放平台 API 文档（v1）

让第三方系统接入 ArtChain 链：查询确权数据、验证作品指纹、提交已签名交易。
所有开放接口挂在 `/open/v1` 前缀下，与控制台接口（`/api/*`）完全隔离，
**必须携带 API Key** 才能调用。

---

## 1. 获取 API Key

密钥由链的运营方在服务器本机签发（不开放远程申请）：

```bash
# 签发一把读写钥（明文只显示这一次！）
python -m artchain apikey create --name 合作方XX --scopes read,write --note 合同编号-2026-001

# 查看已签发的密钥（不含密钥材料）
python -m artchain apikey list

# 吊销
python -m artchain apikey revoke --id 6822f873
```

安全模型：

- 明文密钥形如 `ak_<40 位十六进制>`，**只在创建时显示一次**；
- 落盘文件 `data/api_keys.json` 仅存 SHA-256 哈希——目录泄漏不泄钥；
- 吊销立即生效；被吊销的 Key 调用返回 401。

## 2. 鉴权方式

两种请求头任选其一：

```
Authorization: Bearer ak_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
X-API-Key: ak_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

权限档（scopes）：

| 档 | 能力 |
| --- | --- |
| `read` | 全部查询与验证接口（含 verify / compare） |
| `write` | 提交已签名交易（`POST /open/v1/tx`） |

限流（单 Key、滑动窗口 60 秒）：read 120 次/分，write 30 次/分；超限返回 `429`。

## 3. 接口一览

统一响应信封：`{"ok": true, "data": {...}}`；失败为
`{"ok": false, "error": "说明"}` + 对应 HTTP 状态码。

### 读档（read）

| 接口 | 方法 | 说明 |
| --- | --- | --- |
| `/open/v1/status` | GET | 链状态：块高、难度、最新块哈希、作品数、积分供给 |
| `/open/v1/keyinfo` | GET | 当前 Key 的名字、权限档、累计用量 |
| `/open/v1/works` | GET | 已确权作品列表（对外视图，不含服务端路径） |
| `/open/v1/works/<work_id>` | GET | 单件作品详情 + 上链存在性证明 |
| `/open/v1/proof/<work_id>` | GET | Merkle 包含证明（带 `self_consistent` 自验位） |
| `/open/v1/block/<height>` | GET | 指定块高完整区块 |
| `/open/v1/points` | GET | 积分账本概览：供给、持有人、余额、流水 |
| `/open/v1/nonce?address=<addr>` | GET | 该地址下一个可用 nonce（构造交易前必查） |
| `/open/v1/verify` | POST | 指纹查链：`{"fingerprint": "<sha256>"}` 或 `{"content_base64": ..., "filename": ...}` |
| `/open/v1/compare` | POST | 侵权比对：文件与链上作品相似度排行 |

### 写档（write）

| 接口 | 方法 | 说明 |
| --- | --- | --- |
| `/open/v1/tx` | POST | 提交**已签名**交易：`{"tx": {...}, "auto_mine": true}` |

节点对提交的交易做完整校验（结构、签名、nonce 防重放、业务规则预演），
任何一项不过即拒绝——**服务端全程碰不到你的私钥**。

## 4. curl 示例

```bash
KEY="ak_你的密钥"

# 链状态
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8080/open/v1/status

# 作品列表
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8080/open/v1/works

# 指纹验证（把本地文件的 sha256 与链上锚定比对）
curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"fingerprint":"<文件sha256>"}' http://127.0.0.1:8080/open/v1/verify
```

## 5. Python SDK（零依赖）

仓库自带 `artchain/sdk.py`，纯标准库：

```python
from artchain.sdk import OpenClient, LocalSigner

client = OpenClient("http://节点:8080", "ak_你的密钥")
print(client.status())                     # 链状态
print(client.works())                      # 作品列表

# 本地签名：私钥/助记词永不离开本机
signer = LocalSigner.from_mnemonic("你的 12 个助记词单词 ...")
nonce = client.next_nonce(signer.address)["next_nonce"]
tx = signer.make_pay_tx(对方地址, 150000000, nonce=nonce, memo="货款结算")  # 1.5 积分
print(client.submit_tx(tx))                # 默认自动打包出块
```

`LocalSigner.generate()` 可现场生成新身份（返回 signer 与助记词）；
`make_tx(tx_type, data, nonce)` 支持全部 11 种交易类型的本地构造与签名。
完整可运行示例见 `openapi_e2e.py`（同时是开放平台的回归测试）。

## 6. 错误码

| HTTP | 含义 |
| --- | --- |
| 400 | 参数或交易校验失败（error 内含具体原因） |
| 401 | 缺少 / 无效 / 已吊销的 API Key |
| 403 | Key 的权限档不足（如只读钥调写接口） |
| 404 | 接口或资源不存在 |
| 429 | 触发限流（60 秒滑动窗口） |

## 7. 接入建议

1. **查询类集成**（溯源展示、侵权监测）：只需 read 钥，直接调 works / verify / compare；
2. **交易类集成**（代客登记、积分结算）：read+write 钥 + 本地签名器；助记词务必留在你自己的密钥库，不要经过任何第三方；
3. 提交交易前先查 `next_nonce`，失败重试时**重新查 nonce**（旧 nonce 已被占用）；
4. 对返回的 `proof` 做离线自验（`self_consistent` 或自行复算 Merkle 路径），把信任锚从"相信服务器"降级为"相信数学"。
