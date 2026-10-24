# -*- coding: utf-8 -*-
"""ArtChain —— 艺术品区块链确权系统。

纯 Python 标准库实现，不依赖任何第三方包：
  * 自建区块链（区块、PoW 共识、Merkle 树、链式校验）
  * secp256k1 椭圆曲线 + ECDSA 数字签名（RFC 6979 确定性 k）
  * 作品双指纹（SHA-256 精确指纹 + pHash/aHash/dHash 感知指纹 + SimHash 文本指纹）
  * 著作权登记、版权转让、授权许可、争议声明的链上留痕
  * 侵权比对取证与确权证书（含 Merkle 存在性证明）导出
  * CLI 命令行 + HTTP API + 网页界面

快速开始：
    python -m artchain init
    python -m artchain selftest
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
