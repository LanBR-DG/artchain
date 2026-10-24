# ArtChain · 艺术品区块链确权系统

[English](README.md) | 中文手册

一套以 **Python 标准库**实现的艺术品登记与存证实验系统，核心功能零第三方依赖。

项目用于学习、本机演示与原型研究，尚未经过独立安全审计。请勿使用真实资金钱包的助记词。
包含自建区块链、密码学钱包、图像感知指纹、侵权比对取证、确权证书与
HTTP API / 网页界面。

```
                    ┌──────────────┐
   作品文件 ──指纹──>│  REGISTER 交易 │──签名──> 交易池 ──挖矿──> 区块
                    └──────────────┘                              │
                                                                  ▼
   疑似侵权文件 ──感知指纹比对──> 链上在先登记记录 <──状态机重放── 账本
```

---

## 一、快速开始

> 需要 Python 3.8+（建议 3.10+）。**不需要 pip install 任何东西。**

```bat
cd artchain

python -m artchain selftest         :: 1. 先跑内置自检，确认环境正常
python -m artchain demo             :: 2. 一键跑通完整业务演示
python -m artchain serve --open     :: 3. 打开网页版界面
python -m artchain desktop          :: 4. 或打开桌面可视化窗口（Tkinter，免浏览器）
```

`demo` 会自动生成两幅示例画作，把「登记确权 → 盗图比对 → 证书导出 →
转让 → 授权 → 争议锁定 → 全链校验」完整跑一遍。想重跑加 `--reset`。

不带参数直接运行可以看到全部命令：

```bat
python -m artchain --help
```

---

## 二、它到底做了什么

一件作品的确权流程：

1. **采集指纹**——对作品文件计算 SHA-256（字节级唯一指纹），以及
   pHash / aHash / dHash（感知指纹，抗压缩、缩放、调色）与 SimHash（文本指纹）。
2. **构造交易**——把指纹、作品名、类别、作者、创作日期等信息打包成
   `REGISTER` 交易，用钱包私钥（secp256k1 + ECDSA，RFC 6979 确定性签名）签名。
3. **上链存证**——交易进入待打包池，挖矿时打包进区块，区块头哈希满足
   前导零难度目标，Merkle 根锚定全部交易。
4. **产生证书**——为作品生成带 **Merkle 存在性证明**的确权证书，
   任何人可离线验证「这份登记确实写进了那条链」，无需信任出证方。

确权之后还能做：

| 能力 | 说明 |
|---|---|
| 版权转让 | 权利人签名把作品转给他人，历史完整留痕 |
| 授权许可 | 登记独家 / 非独家许可，含地域、期限、费用；独家授权自动排他 |
| 权属争议 | 第三方提出异议即锁定作品，争议期间禁止转让与授权 |
| 争议裁决 | 由**与本案无关的第三方**裁决异议：驳回则恢复有效，支持则登记转为无效并释放指纹 |
| 撤销登记 | 权利人撤回登记，同时释放文件指纹占用 |
| 侵权比对 | 对可疑文件做感知指纹比对，按相似度排行并给出取证建议 |
| 原件校验 | 校验链下保存的原件是否仍与链上指纹一致（防调包） |
| 节点同步 | 多节点按最长链原则交换区块，达成一致 |

**为什么改了文件也能比对出来？** SHA-256 只能发现「字节完全相同」，
所以盗图者只要重新压缩一次就绕过了。感知指纹（pHash 等）提取的是图像
的**低频结构特征**——把画调亮、缩小、转 JPG，它基本不变。系统按
`pHash 0.50 + dHash 0.20 + aHash 0.15 + SimHash 0.15` 加权算相似度，
并给出 5 档判定。

---

## 三、目录结构

```
artchain/
├── artchain/
│   ├── crypto/             密码学原语（全部手写，零依赖）
│   │   ├── secp256k1.py     椭圆曲线、ECDSA 签名、RFC 6979、地址编码
│   │   ├── base58.py        Base58Check 编码
│   │   └── chacha20.py      ChaCha20 流加密 + HMAC-SHA256 认证加密
│   ├── core/               区块链内核
│   │   ├── tx.py            交易结构、规范化序列化、签名与校验
│   │   ├── block.py         区块头、Merkle 树与存在性证明、工作量证明
│   │   ├── state.py         确权状态机（谁拥有哪件作品）
│   │   └── chain.py         链主体：出块、全链校验、最长链同步
│   ├── imagelib.py         纯 Python PNG/BMP 解码器 + PNG 编码器 + DCT
│   ├── fingerprint.py      SHA-256 / pHash / aHash / dHash / SimHash 与相似度
│   ├── wallet.py           钱包：密钥生成、加密存储、签名
│   ├── store.py            数据目录与原子化持久化
│   ├── service.py          业务服务层（CLI 与 API 共用同一套校验）
│   ├── certificate.py      确权证书：生成、渲染、离线验证
│   ├── cli.py              命令行界面
│   ├── api.py              HTTP API 服务
│   ├── desktop.py          桌面可视化窗口（Tkinter，零第三方依赖）
│   ├── selftest.py         内置自检（11 组 53 项）
│   ├── demo.py             一键业务演示
│   └── web/index.html      网页界面（单文件，原生 JS）
├── data/                   运行时生成：链、钱包、原件（可整体删除）
└── README.md
```

---

## 四、命令行速查

所有命令都支持 `--data <目录>` 指定数据目录（默认源码根目录下的 `data/`，
也可用环境变量 `ARTCHAIN_DATA`）。

### 初始化与查看

```bat
python -m artchain init                                   :: 创建创世区块
python -m artchain init --difficulty 3                    :: 难度调低（出块更快）
python -m artchain status                                 :: 链与账本概览
python -m artchain version                                :: 环境与图像后端信息
```

### 钱包

钱包采用 **BIP39 助记词**（12/24 个英文单词，采用 BIP39 编码；ArtChain 的派生路径、地址与账本独立，不能据此宣称资产互通）：

- **助记词 = 钱包本身**：抄写下来即是最可靠的备份；平台不保存、无法找回。
- **动态口令（可选）**：口令不再需要死记——由助记词派生、每 60 秒自动轮换的
  10 位复杂密文；网页「导入钱包」页输入助记词即可查看当前口令或用助记词直接解锁。
- 密钥由 BIP32 路径 `m/44'/20100'/0'/0/0` 派生（20100 为 ArtChain 自用
  币种号，尚未在 SLIP-44 注册，正式发布前应申请注册）。

```bat
python -m artchain wallet new --name 张三                 :: 创建（展示助记词并要求抄写验证）
python -m artchain wallet new --name 张三 --words 24      :: 24 词版本
python -m artchain wallet import --name 张三              :: 从助记词导入/恢复（交互粘贴）
python -m artchain wallet list                            :: 列出全部钱包
python -m artchain wallet show --name 张三                :: 查看详情与名下作品
python -m artchain wallet show --name 张三 --mnemonic     :: 查看助记词（有安全警告）
python -m artchain wallet export --name 张三 --out 备份.json :: 导出备份
```

旧版钱包（十六进制私钥格式）无需迁移即可继续解锁与签名；
网页端创建钱包同样走「展示助记词 → 验证抄写」流程，登录门支持
「导入钱包」页签。钱包口令也可用环境变量传入，避免明文出现在命令行历史里：

```bat
set ARTCHAIN_PASSWORD=你的口令
```

### 登记与流转

```bat
:: 登记确权（默认立即出块上链）
python -m artchain register --wallet 张三 --file "画作.png" --title 晨 ^
       --category 美术作品 --author 张三 --year 2024 --created 2024-03-18 ^
       --desc "布面油画 120x90cm"

:: 只进待打包池，稍后统一出块
python -m artchain register --wallet 张三 --file 画作.png --no-mine
python -m artchain mine --mine-with 张三

:: 转让 / 授权 / 争议 / 裁决 / 撤销
python -m artchain transfer --wallet 张三 --work WK... --to ART... --price 12000.00
python -m artchain license  --wallet 李四 --work WK... --to ART... --scope 独家 ^
       --territory 中国大陆 --royalty 800.00 --start 2026-01-01 --end 2028-12-31
python -m artchain dispute  --wallet 王五 --work WK... --reason "该作品系本人原创"
:: 裁决只能由与本案无关的第三方发起：权利人和异议人自己裁决会被链上拒绝
python -m artchain adjudicate --wallet 鉴定机构 --work WK... --ruling 驳回 ^
       --reason "异议人提交的底稿无法证明早于登记时间"
python -m artchain revoke   --wallet 张三 --work WK... --reason "误登记"
```

### 查询与取证

```bat
python -m artchain works                                   :: 全部确权作品
python -m artchain works --owner ART... --status 有效       :: 按权利人/状态筛选
python -m artchain work --id WK...                         :: 作品确权详情
python -m artchain blocks --limit 10                       :: 最近区块
python -m artchain blocks --height 3                       :: 指定区块及其交易
python -m artchain mempool                                 :: 待打包交易
python -m artchain verify                                  :: 全链完整性校验
python -m artchain check-original --work WK...             :: 链下原件是否被调包

:: 侵权比对：这是核心取证能力
python -m artchain compare --file "疑似侵权图.jpg"
python -m artchain compare --file 可疑.jpg --work WK... --json
```

### 平台积分

链上金额一律是「整数最小单位」（1 积分 = 10^8 最小单位，8 位小数），
账本里永不出现浮点。铸造（MINT）与销毁（BURN）仅限创世区块登记的
`--operator-address`；旧链未登记时为兼容模式（任何地址可铸造，仅演示）。

```bat
:: 建链时指定运营方地址与总量上限（发行权写死在链规则里）
python -m artchain init --operator 平台运营部 --operator-address ART... --max-supply 1000000

python -m artchain mint  --wallet 运营方 --amount 100000          :: 铸造（计入运营方余额）
python -m artchain pay   --wallet 运营方 --to ART... --amount 500 :: 转账
python -m artchain burn  --wallet 运营方 --amount 1000            :: 销毁（缩减流通量）
python -m artchain points                                          :: 流通量/持币/最近流水
python -m artchain points --address ART... --top 10                :: 查余额 + 排行榜
```

### 证书

```bat
python -m artchain cert --work WK... --format html --issuer "某某美术馆"
python -m artchain cert --work WK... --format json --out 证书.json
python -m artchain verify-cert --file 证书.json             :: 离线独立复核
```

`verify-cert` 只需要证书 JSON 文件本身，**不需要区块链数据**——它靠
Merkle 存在性证明和区块头哈希重算来判断登记是否真实上链。

### 多节点

开两个终端模拟两个机构：

```bat
:: 终端 A
python -m artchain --data data-a init
python -m artchain --data data-a serve --port 8080

:: 终端 B
python -m artchain --data data-b init
python -m artchain --data data-b peer add --url http://127.0.0.1:8080
python -m artchain --data data-b sync                     :: 按最长链原则同步
```

---

## 五、网页界面

```bat
python -m artchain serve --open          :: 默认 http://127.0.0.1:8080/
python -m artchain serve --port 9000     :: 换端口
```

六个页签：**概览**（KPI 指标卡 + 区块交易量柱状图）、**登记确权**
（拖文件即上链）、**作品库**（检索 + 权属沿革 + 许可台账）、
**侵权比对**（相似度排行 + 取证结论）、**区块浏览**（区块与交易明细）、
**钱包与工具**（建钱包、节点同步、交易池）。

手机浏览器上自动切换为 iOS 式底部标签栏（概览 / 登记 / 作品 / 社区 / 我的），
支持下拉刷新、密码显隐、缩略图按需加载；同时是**可安装的 PWA**——
iOS Safari「添加到主屏幕」、安卓 / 鸿蒙浏览器与 Chrome / Edge 均可安装为独立应用
（含离线外壳缓存，接口数据始终实时）。

首次打开若数据目录为空，页面会提示「初始化区块链」，点一下即建链。

### 桌面窗口（不用浏览器）

```bat
python -m artchain desktop        :: 打开桌面可视化窗口
```

四个页签：**概览**（KPI 指标卡 + 每块交易量柱状图）、**区块链**（把区块画成一条
链，点击任意区块看它的交易明细）、**作品**（全部确权作品，点击看权属沿革、
授权许可与上链证明）、**侵权比对**（选文件即比对，列出相似度排行）。

用的是 Python 自带的 Tkinter，**不需要安装任何东西**。若数据目录为空，
窗口上会出现「生成演示数据并初始化」按钮，点一下即可。

### 直接调 API

统一返回 `{"ok": true, "data": ...}` 或 `{"ok": false, "error": "..."}`。

```bat
:: 链概览
curl http://127.0.0.1:8080/api/status

:: 登记确权（文件走 base64 JSON，避免 multipart 的麻烦）
:: POST /api/register
:: {"wallet":"张三","password":"...","filename":"a.png",
::  "content_base64":"...","title":"晨","category":"美术作品"}

:: 侵权比对
:: POST /api/compare  {"filename":"可疑.jpg","content_base64":"...","top":10}

:: 全链校验
:: POST /api/verify   {}
```

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 链与账本概览 |
| GET | `/api/chain` | 全部区块（同步用） |
| GET | `/api/block/<高度>` | 单个区块 |
| GET | `/api/works` | 作品列表，支持 `?q=&owner=&status=` |
| GET | `/api/work/<作品编号>` | 作品详情（含 Merkle 证明） |
| GET | `/api/mempool` | 待打包交易 |
| GET | `/api/wallets` | 钱包列表（仅公开信息） |
| GET | `/api/network` | 已知节点 |
| GET | `/api/blob/<作品编号>` | 链下保存的原件 |
| GET | `/api/thumb/<作品编号>?w=96` | 作品缩略图（服务端缩放，16–512；无 Pillow 时纯标准库支持 PNG/BMP） |
| GET | `/api/cert/<作品编号>` | 确权证书，`?format=html\|json\|text` |
| POST | `/api/init` | 初始化链（仅当尚未建链） |
| POST | `/api/wallet/new` | 新建钱包 |
| POST | `/api/register` | 登记确权 |
| POST | `/api/transfer` | 版权转让 |
| POST | `/api/license` | 授权许可 |
| POST | `/api/dispute` | 权属争议 |
| POST | `/api/adjudicate` | 争议裁决（`ruling`：`驳回` / `支持`） |
| POST | `/api/revoke` | 撤销登记 |
| POST | `/api/mine` | 手动出块 |
| POST | `/api/compare` | 侵权比对 |
| POST | `/api/verify` | 全链校验 |
| POST | `/api/peer` | 添加节点 |
| POST | `/api/sync` | 与节点同步 |
| GET | `/api/points` | 积分概览（流通量/持币/流水），`?address=&top=` |
| POST | `/api/pay` | 积分转账 `{"to","amount","memo"}` |
| POST | `/api/mint` | 铸造积分（仅限运营方地址） |
| POST | `/api/burn` | 销毁积分（仅限运营方地址） |

---

## 六、内置自检

```bat
python -m artchain selftest            :: 全部跑一遍，逐项列出
python -m artchain selftest --quiet    :: 只看结果
```

自检覆盖 11 组共 53 项，全部在系统临时目录里跑，**不会碰你的数据**：

| 分组 | 覆盖内容 |
|---|---|
| 密码学基础 | 椭圆曲线基点/阶、签名与验签、篡改签名必须被拒、地址编解码 |
| 钱包加密 | ChaCha20 加解密、错误口令必须失败、钱包落盘与重载 |
| 图像指纹 | PNG 5 种行滤波、交错扫描行、pHash 抗调色、指纹相似度 |
| 文本指纹 | SimHash 对改写稳健、对无关文本不误判 |
| Merkle 与 PoW | Merkle 根与存在性证明、工作量证明难度 |
| 端到端流程 | 建链、登记、重复登记拦截、比对命中与不误判、转让、授权、交易池、重放保护、争议锁定、全链校验、篡改检测、证书与离线验证、重载 |
| 社区上链 | 发帖、回复、点赞、长度限制、附图、篡改检测与重载 |
| 平台积分 | 精度、发行权限、转账、总量上限与重载 |
| 助记词钱包 | BIP39 向量、恢复、旧格式兼容与动态口令 |
| 开放平台 | API Key、限流、IP 地区识别与购买订单流程 |
| 存储与落盘 | 追加日志、迁移、自愈与断电恢复 |

输出示例：

```
============================================================
  ArtChain 内置自检
============================================================
  [密码学基础]
    ✓ 椭圆曲线基点
    ✓ 签名与验签
    ...
  全部通过：53 / 53 项
```

---

## 七、安全说明

**这套系统适合本机演示、教学与内网试点。** 上线到公网前请务必注意：

1. **HTTP 服务默认只监听 `127.0.0.1`**，且写操作要在请求体里提交钱包口令
   （明文走 HTTP）。若确需对外提供服务，请自行叠加 HTTPS 与鉴权层，
   并把口令校验换成签名挑战（服务端不接触明文口令）。
2. **钱包私钥以 ChaCha20 + HMAC-SHA256 认证加密存储**，密钥由
   PBKDF2-HMAC-SHA256（20 万次迭代）从口令派生。但口令强度决定一切，
   弱口令等于没有加密。`wallet new --no-password` 创建的**明文钱包仅供演示**，
   切勿用于真实资产。
3. **创世区块由本机生成**。这是一条自建实验链，代码未限制出块权限，
   适合作为机构内部的存证账本；它不提供公链那样的去中心化信任，
   链的权威性来自运营方与节点共识。
4. **确权 ≠ 版权登记**。链上存证证明的是「某时刻某人已持有该文件的指纹」，
   链内时间戳由节点提供，不构成独立可信时间源；它不替代正式著作权登记，
   也不直接等于法律意义上的权属判定。
5. 数据目录 `data/` 内含链数据、钱包私钥与作品原件，请像对待财务数据
   一样对待它——备份、限权、加密磁盘。

### 法律协议与合规

登录门已接入四份法律协议（用户服务协议 / 隐私政策 / 平台积分规则 /
社区规范）的**勾选同意与服务端留痕**（`consents.json` 记录钱包、时间、
文档版本）。协议文本在 `artchain/web/legal/`，其中【】占位符必须按实际
运营主体替换；正式对外运营前请按 `legal/README.md` 的法务清单逐项经
执业律师审查——尤其积分定性（不可变现/不可提现/生态内单用途）、链上
数据不可删除的告知、以及 ICP/公安/**区块链信息服务**三项备案。

---

## 八、常见问题

**Q：出块很慢 / 卡在挖矿？**
难度每 +1 出块时间期望翻 16 倍。默认难度 4 通常不到 1 秒；
若机器慢，用 `init --difficulty 3` 建链，或换更快的机器。

**Q：`register` 报「该文件指纹已被作品《X》登记」？**
同一份文件不能重复确权。若你才是真正的作者，用 `dispute` 发起权属争议。

**Q：中文在 Windows 终端显示乱码？**
程序已主动把输出切到 UTF-8。若仍异常，先执行 `chcp 65001`。

**Q：没有装 Pillow，能处理 JPG 吗？**
内置了纯 Python 的 PNG 与 BMP 解码器，这两种格式开箱即用。
JPG / GIF / TIFF / WebP 需要 Pillow（`pip install pillow`），
装了会自动启用；没装时登记 JPG 仍可用（SHA-256 指纹照常计算），
只是感知指纹不可用。用 `python -m artchain version` 可查看当前后端。

**Q：想清空重来？**
```bat
python -m artchain reset --yes                 :: 清链，保留钱包
python -m artchain reset --yes --with-wallets  :: 连钱包一起清
```
或者直接删掉 `data/` 目录。

## 开发与发布

安装包运行时建议显式传入 `--data ./data`，避免向安装目录写入数据。
贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，边界说明见 [SECURITY.md](SECURITY.md)。
第三方词表说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 开源许可证

本项目采用 [MIT License](LICENSE)，Copyright (c) 2026 LanBR-DG。
第三方材料保留其自身的许可和署名说明。
