# -*- coding: utf-8 -*-
"""作品指纹：给一件作品算出可用于"确权 + 比对"的多维指纹。

一次指纹采集会同时得到：
  * sha256    —— 字节级精确指纹，文件被改动一个比特就会变
  * phash     —— 感知哈希（DCT 低频 8x8），抗 JPEG 压缩、缩放、轻微调色
  * ahash     —— 均值哈希，抗亮度/对比度整体变化
  * dhash     —— 差分哈希，对渐变与光照更稳健
  * simhash   —— 文本指纹（文字作品 / 美术作品题跋），抗少量字词增删

比对时按加权汉明距离给出相似度评分与风险等级，用于侵权比对取证。
"""

import hashlib
import os

from . import imagelib

# 图像类扩展名（用于人工提示，实际以文件头为准）
IMAGE_EXTENSIONS = (".png", ".bmp", ".jpg", ".jpeg", ".gif", ".webp", ".tif", ".tiff")
TEXT_EXTENSIONS = (".txt", ".md", ".csv", ".json", ".xml", ".html", ".htm", ".srt", ".log")

# 各分量的权重（只在双方都有该分量时才参与加权，最后归一化）
_WEIGHTS = {"phash": 0.50, "dhash": 0.20, "ahash": 0.15, "simhash": 0.15}


class FingerprintError(Exception):
    """指纹采集失败。"""


# ------------------------------------------------------------ 精确指纹
def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    """流式计算文件 SHA-256，避免把大文件整体读进内存。"""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------ 文本指纹
def _is_probably_text(data):
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return False
    sample = data[:8192]
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126 or b >= 0x80)
    return printable / float(len(sample)) > 0.90


def decode_text(data):
    """尽力把字节解码成文本（UTF-8 -> GBK -> Latin-1）。"""
    for enc in ("utf-8", "utf-8-sig", "gb18030", "big5"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="ignore")


def tokenize(text):
    """分词：英文/数字按词切分，中文按单字 + 相邻二元组切分。"""
    tokens = []
    buf = []
    for ch in text:
        if ch.isascii() and (ch.isalnum() or ch in "_-"):
            buf.append(ch.lower())
        else:
            if buf:
                tokens.append("".join(buf))
                buf = []
            if "一" <= ch <= "鿿":
                tokens.append(ch)
    if buf:
        tokens.append("".join(buf))
    # 中文单字加入相邻二元组，提升短语层面的区分度
    cjk = [t for t in tokens if len(t) == 1 and "一" <= t <= "鿿"]
    tokens.extend(cjk[i] + cjk[i + 1] for i in range(len(cjk) - 1))
    return tokens


def simhash_text(text):
    """64 位 SimHash，返回 16 位十六进制字符串；文本为空时返回 None。"""
    tokens = tokenize(text)
    if not tokens:
        return None
    vector = [0] * 64
    for tok in tokens:
        h = int.from_bytes(hashlib.sha256(tok.encode("utf-8")).digest()[:8], "big")
        for i in range(64):
            vector[i] += 1 if (h >> i) & 1 else -1
    bits = 0
    for i in range(64):
        if vector[i] > 0:
            bits |= (1 << i)
    return "%016x" % bits


# ------------------------------------------------------------ 统一指纹
def fingerprint_bytes(data, filename="", with_image=True):
    """对一段字节流采集指纹，返回指纹字典。"""
    if not isinstance(data, (bytes, bytearray)):
        raise FingerprintError("指纹输入必须是 bytes")
    data = bytes(data)
    fp = {
        "sha256": sha256_bytes(data),
        "size": len(data),
        "kind": "binary",
        "width": None,
        "height": None,
        "phash": None,
        "ahash": None,
        "dhash": None,
        "simhash": None,
        "image_backend": None,
    }
    ext = os.path.splitext(filename)[1].lower() if filename else ""

    fmt = imagelib.detect_format(data)
    if with_image and (fmt is not None or ext in IMAGE_EXTENSIONS):
        try:
            w, h, gray = imagelib.load_gray(data)
            fp["kind"] = "image"
            fp["width"] = w
            fp["height"] = h
            fp["image_backend"] = imagelib.backend_name()
            fp["phash"] = "%016x" % imagelib.phash_bits(gray, w, h)
            fp["ahash"] = "%016x" % imagelib.ahash_bits(gray, w, h)
            fp["dhash"] = "%016x" % imagelib.dhash_bits(gray, w, h)
            return fp
        except imagelib.UnsupportedImage as exc:
            fp["image_error"] = str(exc)
        except Exception as exc:  # 解码异常不应阻断确权，退化为字节指纹
            fp["image_error"] = "图像解析失败：%s" % exc

    if _is_probably_text(data) or ext in TEXT_EXTENSIONS:
        text = decode_text(data)
        digest = simhash_text(text)
        if digest is not None:
            fp["kind"] = "text"
            fp["simhash"] = digest
            fp["char_count"] = len(text)
            return fp

    return fp


def fingerprint_file(path, with_image=True):
    """对文件采集指纹。"""
    with open(path, "rb") as fh:
        data = fh.read()
    fp = fingerprint_bytes(data, filename=os.path.basename(path), with_image=with_image)
    fp["filename"] = os.path.basename(path)
    return fp


# ------------------------------------------------------------ 比对
def hamming_distance(a, b):
    """两个十六进制指纹的比特汉明距离；任一为空返回 None。"""
    if not a or not b:
        return None
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return None


# 风险等级：(最低得分, 等级编号, 结论)
LEVELS = (
    (0.93, 4, "高度疑似同一作品（存在压缩/缩放/调色等轻微改动）"),
    (0.85, 3, "疑似同一作品，建议人工复核"),
    (0.75, 2, "存在一定相似性，需结合创作过程进一步判断"),
    (0.00, 1, "未发现实质性相似"),
)


def similarity(fp_a, fp_b):
    """比较两份指纹，返回评分与结论。"""
    result = {
        "score": 0.0,
        "exact": False,
        "level": 1,
        "conclusion": LEVELS[-1][2],
        "distances": {},
        "components": [],
        "note": "",
    }
    if not fp_a or not fp_b:
        result["note"] = "缺少指纹数据"
        return result

    if fp_a.get("sha256") and fp_a.get("sha256") == fp_b.get("sha256"):
        result["exact"] = True
        result["score"] = 1.0
        result["level"] = 5
        result["conclusion"] = "字节级完全一致（同一份文件）"
        return result

    weighted = 0.0
    used_weight = 0.0
    for name, weight in _WEIGHTS.items():
        dist = hamming_distance(fp_a.get(name), fp_b.get(name))
        if dist is None:
            continue
        result["distances"][name] = dist
        bits = 64
        similarity_ratio = 1.0 - dist / float(bits)
        # 相似度低于 0.5 视为无关，避免负分干扰
        similarity_ratio = max(0.0, similarity_ratio)
        weighted += weight * similarity_ratio
        used_weight += weight
        result["components"].append({
            "name": name, "distance": dist, "ratio": round(similarity_ratio, 4), "weight": weight,
        })

    if used_weight <= 0:
        result["note"] = "双方没有可比较的感知指纹（可能是纯字节文件）"
        return result

    score = weighted / used_weight
    result["score"] = round(score, 4)
    for threshold, level, conclusion in LEVELS:
        if score >= threshold:
            result["level"] = level
            result["conclusion"] = conclusion
            break
    if fp_a.get("kind") == "text" and "simhash" in result["distances"]:
        result["note"] = "文本作品仅按 SimHash 语义相似度评估"
    return result


def compare_against(target_fp, candidates):
    """把目标指纹与一批候选指纹比对，按相似度降序返回。

    candidates: [{"id": ..., "fingerprint": {...}, "label": {...}}, ...]
    """
    results = []
    for item in candidates:
        sim = similarity(target_fp, item.get("fingerprint") or {})
        entry = {
            "id": item.get("id"),
            "label": item.get("label") or {},
            "score": sim["score"],
            "level": sim["level"],
            "conclusion": sim["conclusion"],
            "exact": sim["exact"],
            "distances": sim["distances"],
        }
        results.append(entry)
    results.sort(key=lambda r: (r["score"], r["level"]), reverse=True)
    return results
