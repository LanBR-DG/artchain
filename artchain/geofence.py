# -*- coding: utf-8 -*-
"""地区识别（IP 地理围栏）：判断请求来源是否为中国大陆，用于支付通道合规。

设计说明：
- 零依赖纯 Python。内置一份「核心运营商 CIDR 清单」（电信/联通/移动/教育网
  以及阿里/腾讯/百度云的国内段），开箱即可识别绝大多数大陆流量；
- 生产环境建议把全量清单放到 数据目录/cn_ipv4.txt（一行一个 CIDR，
  来源可用 APNIC delegated 统计或 ipip.net 的 china.ip），存在时
  自动改用全量清单并随文件修改热加载；
- 本机/内网地址（127/10/172.16/192.168/CGNAT 等）按配置的默认地区处理
  （geofence_default_region，默认 "CN"——合规从严）；
- X-Forwarded-For / X-Real-IP 只在两种情况下被信任：对端是本机回环
  （本地调试方便伪造头部测试），或配置 geofence_trust_proxy=true
  （部署在自有反向代理之后时打开）。不信任直连客户端发来的头——
  否则地理围栏形同虚设。
"""

import os
import time

REGION_CN = "CN"          # 中国大陆
REGION_OTHER = "OTHER"    # 其他地区

_CN_RANGES_CORE = (
    # 中国电信（CHINANET）主干段
    "1.80.0.0/13", "1.188.0.0/14", "1.192.0.0/13", "14.16.0.0/12",
    "14.144.0.0/12", "14.208.0.0/12", "27.16.0.0/12", "27.184.0.0/13",
    "58.32.0.0/13", "58.48.0.0/13", "58.56.0.0/13", "59.32.0.0/11",
    "59.172.0.0/15", "60.0.0.0/11", "61.128.0.0/10", "61.144.0.0/13",
    "61.232.0.0/14", "101.80.0.0/12", "101.224.0.0/13", "110.16.0.0/14",
    "110.80.0.0/13", "110.184.0.0/13", "113.12.0.0/14", "113.64.0.0/10",
    "113.132.0.0/14", "113.136.0.0/13", "114.114.0.0/16",
    "116.4.0.0/14", "116.16.0.0/12", "116.224.0.0/12", "117.8.0.0/13",
    "117.32.0.0/13", "118.112.0.0/13", "120.32.0.0/12", "121.56.0.0/13",
    "121.224.0.0/12", "122.224.0.0/12", "123.144.0.0/12", "124.72.0.0/13",
    "124.112.0.0/13", "124.161.0.0/16", "125.40.0.0/13", "125.64.0.0/11",
    "180.136.0.0/13", "180.152.0.0/13", "180.160.0.0/11", "183.0.0.0/10",
    "202.96.0.0/12", "218.0.0.0/11", "218.88.0.0/13", "219.128.0.0/11",
    "219.144.0.0/13", "219.152.0.0/14", "220.160.0.0/11", "222.64.0.0/11",
    "222.172.0.0/15", "222.240.0.0/13", "223.240.0.0/13",
    # 中国联通
    "1.24.0.0/13", "1.202.0.0/15", "27.8.0.0/13", "42.224.0.0/12",
    "58.240.0.0/12", "61.135.0.0/16", "101.200.0.0/13", "110.75.0.0/16",
    "113.44.0.0/14", "123.112.0.0/12", "124.64.0.0/15", "125.33.0.0/16",
    "175.16.0.0/13", "202.106.0.0/16", "221.0.0.0/13", "221.204.0.0/15",
    # 中国移动
    "36.128.0.0/10", "39.128.0.0/10", "111.0.0.0/10", "112.0.0.0/10",
    "117.128.0.0/10", "120.192.0.0/10", "183.192.0.0/10", "211.136.0.0/13",
    "223.64.0.0/10",
    # 教育网 / 科技网
    "58.192.0.0/11", "58.194.0.0/15", "58.200.0.0/13", "59.64.0.0/11",
    "125.216.0.0/13", "125.222.0.0/15", "159.226.0.0/16", "162.105.0.0/16",
    "166.111.0.0/16", "202.4.128.0/19", "202.38.64.0/18", "202.112.0.0/13",
    "202.120.0.0/15", "202.192.0.0/12", "210.32.0.0/13", "210.72.0.0/14",
    "211.64.0.0/13", "211.71.0.0/16", "219.224.0.0/13", "219.242.0.0/15",
    "222.16.0.0/12",
    # 阿里云 / 腾讯云 / 百度（国内段）
    "39.96.0.0/13", "47.92.0.0/12", "59.110.0.0/16", "101.32.0.0/16",
    "106.11.0.0/16", "115.239.0.0/16", "119.28.0.0/15", "119.75.0.0/16",
    "123.125.0.0/16", "123.151.0.0/16", "124.156.0.0/16", "140.143.0.0/16",
    "140.205.0.0/16", "163.177.0.0/16", "180.76.0.0/16", "182.61.0.0/16",
    "212.129.128.0/17", "220.181.0.0/16", "223.5.0.0/16", "139.196.0.0/14",
    "49.51.0.0/16", "81.70.0.0/16", "94.191.0.0/17", "45.40.192.0/18",
    "58.87.64.0/18",
)

# 本机/内网段：不当作任何国家，交给默认地区策略
_PRIVATE_CIDRS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15",
)

_loopback_names = {"localhost", "::1", "::ffff:127.0.0.1"}


def _ip_to_int(ip):
    """严格 IPv4 点分十进制 -> 整数。拒绝前导零（防歧义/绕过）。"""
    try:
        parts = (ip or "").strip().split(".")
        if len(parts) != 4:
            return None
        n = 0
        for part in parts:
            if not part.isdigit() or (len(part) > 1 and part.startswith("0")):
                return None
            value = int(part, 10)
            if not 0 <= value <= 255:
                return None
            n = (n << 8) | value
        return n
    except AttributeError:
        return None


def _parse_cidr(text):
    text = text.strip()
    if not text or text.startswith("#"):
        return None
    net, sep, bits = text.partition("/")
    base = _ip_to_int(net)
    if base is None:
        return None
    try:
        width = int(bits) if sep else 32
    except ValueError:
        return None
    if not 0 <= width <= 32:
        return None
    mask = (0xFFFFFFFF << (32 - width)) & 0xFFFFFFFF
    return (base & mask, mask)


_PRIVATE = tuple(e for e in (_parse_cidr(c) for c in _PRIVATE_CIDRS) if e)

# 全量清单热加载缓存：{"path": str, "mtime": float, "ranges": tuple, "count": int}
_full_cache = {"path": None, "mtime": 0.0, "ranges": None, "count": None}


def _full_path(store):
    return os.path.join(store.root, "cn_ipv4.txt") if store else None


def cn_ranges(store=None):
    """返回生效的大陆网段表：全量清单存在则用全量，否则用内置核心清单。"""
    path = _full_path(store)
    if path and os.path.isfile(path):
        mtime = os.path.getmtime(path)
        if _full_cache["path"] != path or _full_cache["mtime"] != mtime:
            ranges = []
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    entry = _parse_cidr(line)
                    if entry:
                        ranges.append(entry)
            _full_cache.update(path=path, mtime=mtime,
                               ranges=tuple(ranges), count=len(ranges))
        return _full_cache["ranges"]
    _full_cache.update(path=None, mtime=0.0, ranges=None, count=None)
    return _CORE_TUPLES


_CORE_TUPLES = tuple(e for e in (_parse_cidr(c) for c in _CN_RANGES_CORE) if e)


def _hit(ranges, value):
    for net, mask in ranges:
        if (value & mask) == net:
            return True
    return False


def is_private(ip):
    value = _ip_to_int(ip or "")
    if value is None:
        return (ip or "").strip() in _loopback_names
    return _hit(_PRIVATE, value)


def client_ip(headers, socket_ip, trust_proxy=False):
    """解析请求真实 IP：仅本机回环或配置信任代理时才采纳转发头。"""
    sock = (socket_ip or "").strip()
    if trust_proxy or is_private(sock):
        get = headers.get if hasattr(headers, "get") else (lambda k: None)
        real = (get("X-Real-IP") or "").strip()
        if real:
            return real
        forwarded = (get("X-Forwarded-For") or "").strip()
        if forwarded:
            return forwarded.split(",")[0].strip()
    return sock


def region_of(ip, store=None, default=REGION_CN):
    """返回 (region, label, detail)。本机/内网按 default 从严归类。"""
    ip = (ip or "").strip()
    value = _ip_to_int(ip)
    if value is None:
        if ip in _loopback_names:
            return default, "本机", "loopback"
        return default, "未知来源", "unparseable"
    if _hit(_PRIVATE, value):
        # 127.0.0.0/8 是回环口，其余内网段也算 private；把 loopback 单独标记
        if (value >> 24) == 127:
            return default, "本机回环（按默认地区处理）", "loopback"
        return default, "本机/内网（按默认地区处理）", "private"
    if _hit(cn_ranges(store), value):
        return REGION_CN, "中国大陆", "cn-range"
    return REGION_OTHER, "其他地区", "other"


def ranges_info(store=None):
    """诊断用：当前生效清单的规模与来源。"""
    path = _full_path(store)
    if path and os.path.isfile(path):
        cn_ranges(store)   # 确保缓存已刷新
        return {"source": path, "count": _full_cache["count"]}
    return {"source": "内置核心清单", "count": len(_CORE_TUPLES)}
