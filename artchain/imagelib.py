# -*- coding: utf-8 -*-
"""纯标准库图像处理：PNG / BMP 解码、灰度缩放、二维 DCT。

为了保证"零第三方依赖"，这里手写了 PNG 解码器（含 5 种行滤波器、调色板、
1/2/4/8/16 位深）和 BMP 解码器。如果本机恰好装了 Pillow，会自动优先使用
Pillow，从而额外支持 JPEG / GIF / TIFF / WebP 等格式。

对外主要接口：
    load_gray(path) -> (width, height, gray_bytes)
    resize_gray(gray, w, h, nw, nh) -> [float, ...]
    phash_bits / ahash_bits / dhash_bits -> 64 位整数
"""

import math
import struct
import zlib

try:  # 可选加速：装了 Pillow 就用它，没装也不影响运行
    from PIL import Image as _PILImage
except Exception:  # pragma: no cover - 取决于运行环境
    _PILImage = None

# Pillow 的"解压炸弹"异常类型。用 getattr 取而不是直接引用属性名：
# 老版本 Pillow 没有这个类，直接写 except 会在异常真正发生时才报 AttributeError。
# 取不到时用空元组，`except ()` 恒不匹配，等同于该分支不存在。
_PIL_BOMB_ERROR = getattr(_PILImage, "DecompressionBombError", ())

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# 支持的格式（按是否有 Pillow 区分）
PURE_PYTHON_FORMATS = ("PNG", "BMP")
PILLOW_FORMATS = ("PNG", "BMP", "JPEG", "GIF", "TIFF", "WEBP", "PPM")

# 解码资源上限。
#
# 宽高都直接读自文件头，是攻击者可控的 32 位整数，而下面会按 width*height
# 一次性开缓冲区。不设上限的话，一个 65535×65535 的头部（文件本身可能只有几百
# 字节）就能让进程去分配约 4GB。同理 zlib 解压也必须限量，
# 否则几十 KB 的 IDAT 可以膨胀到任意大小（解压炸弹）。
# 入口是 HTTP 的 /api/register 与 /api/compare。
MAX_IMAGE_PIXELS = 40 * 1000 * 1000        # 4000 万像素，够任何艺术品扫描件
MAX_DECODED_BYTES = 256 * 1024 * 1024      # 单张图解码后的字节上限


def _check_pixels(width, height, kind="图片"):
    """在按尺寸分配内存之前先卡住上限。"""
    if width <= 0 or height <= 0:
        raise ValueError("%s尺寸非法：%sx%s" % (kind, width, height))
    if width * height > MAX_IMAGE_PIXELS:
        raise UnsupportedImage(
            "%s尺寸过大：%sx%s，超过上限 %d 像素" % (kind, width, height, MAX_IMAGE_PIXELS))


class UnsupportedImage(Exception):
    """无法解码的图片格式。"""


# ------------------------------------------------------------------ PNG
def _paeth(a, b, c):
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _unfilter(raw, width, height, bpp, stride):
    """还原 PNG 扫描线的滤波（0=None 1=Sub 2=Up 3=Average 4=Paeth）。"""
    out = bytearray()
    prev = bytearray(stride)
    pos = 0
    for _ in range(height):
        ftype = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        if len(line) != stride:
            raise ValueError("PNG 图像数据不完整")
        pos += stride
        if ftype == 0:
            pass
        elif ftype == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                c = prev[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + _paeth(a, prev[i], c)) & 0xFF
        else:
            raise ValueError("未知的 PNG 滤波类型：%d" % ftype)
        out += line
        prev = line
    return bytes(out)


def _palette_gray(palette, index):
    """从 PLTE 调色板取第 index 项并转灰度。"""
    if palette is None:
        return 0
    off = index * 3
    if off + 2 >= len(palette):
        return 0
    r, g, b = palette[off], palette[off + 1], palette[off + 2]
    return (r * 299 + g * 587 + b * 114) // 1000


def _png_rows_to_gray(px, width, height, bit_depth, color_type, channels, palette):
    out = bytearray(width * height)
    if bit_depth == 8:
        for i in range(width * height):
            o = i * channels
            if color_type in (0, 4):          # 灰度 / 灰度+透明
                g = px[o]
            elif color_type in (2, 6):        # RGB / RGBA
                g = (px[o] * 299 + px[o + 1] * 587 + px[o + 2] * 114) // 1000
            else:                             # 调色板
                g = _palette_gray(palette, px[o])
            out[i] = g
    elif bit_depth == 16:
        step = channels * 2
        for i in range(width * height):
            o = i * step
            if color_type in (0, 4):
                g = px[o]                     # 大端，取高字节
            else:
                g = (px[o] * 299 + px[o + 2] * 587 + px[o + 4] * 114) // 1000
            out[i] = g
    else:                                     # 1 / 2 / 4 位
        maxv = (1 << bit_depth) - 1
        per = 8 // bit_depth
        row_bytes = (width * bit_depth + 7) // 8
        for y in range(height):
            base = y * row_bytes
            for x in range(width):
                byte = px[base + x // per]
                shift = 8 - bit_depth * (x % per + 1)
                v = (byte >> shift) & maxv
                if color_type == 3:
                    out[y * width + x] = _palette_gray(palette, v)
                else:
                    out[y * width + x] = v * 255 // maxv
    return bytes(out)


def png_to_gray(data):
    """解码 PNG，返回 (width, height, gray_bytes)。"""
    width, height, px, bit_depth, color_type, channels, palette = _png_decode(data)
    return width, height, _png_rows_to_gray(px, width, height, bit_depth, color_type, channels, palette)


def png_to_rgb(data):
    """解码 PNG，返回 (width, height, rgb_bytes)（缩略图管线用，保留色彩）。"""
    width, height, px, bit_depth, color_type, channels, palette = _png_decode(data)
    return width, height, _png_rows_to_rgb(px, width, height, bit_depth, color_type, channels, palette)


def _png_decode(data):
    """解析 PNG 结构 + 反滤波，返回原始像素与全部元信息。"""
    if data[:8] != PNG_SIG:
        raise UnsupportedImage("不是合法的 PNG 文件")
    pos = 8
    width = height = bit_depth = color_type = None
    interlace = 0
    idat = bytearray()
    palette = None
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + length]
        if len(chunk) != length:
            raise ValueError("PNG 数据块长度越界")
        pos += 12 + length
        if ctype == b"IHDR":
            if len(chunk) < 13:
                raise ValueError("PNG IHDR 数据块不完整")
            width = int.from_bytes(chunk[0:4], "big")
            height = int.from_bytes(chunk[4:8], "big")
            bit_depth = chunk[8]
            color_type = chunk[9]
            if chunk[10] != 0:
                raise UnsupportedImage("不支持的 PNG 压缩方式")
            interlace = chunk[11]
            if chunk[12] != 0:
                raise UnsupportedImage("不支持的 PNG 滤波方式")
        elif ctype == b"PLTE":
            palette = chunk
        elif ctype == b"IDAT":
            idat += chunk
        elif ctype == b"IEND":
            break
    if width is None or not width or not height:
        raise ValueError("PNG 缺少 IHDR 或尺寸非法")
    if interlace != 0:
        raise UnsupportedImage("暂不支持隔行扫描（Adam7）的 PNG，请先转存为普通 PNG")
    if color_type not in (0, 2, 3, 4, 6):
        raise UnsupportedImage("不支持的 PNG 颜色类型：%s" % color_type)
    if bit_depth not in (1, 2, 4, 8, 16):
        raise UnsupportedImage("不支持的 PNG 位深：%s" % bit_depth)
    if color_type == 3 and bit_depth == 16:
        raise UnsupportedImage("调色板 PNG 不支持 16 位深")

    # 尺寸上限必须在任何按尺寸分配内存的动作之前检查。
    _check_pixels(width, height, "PNG")

    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    bits_pp = channels * bit_depth
    stride = (width * bits_pp + 7) // 8
    bpp = max(1, bits_pp // 8)
    # 每行前面有 1 字节滤波器类型，所以完整解码结果是 (stride+1)*height。
    expected = (stride + 1) * height
    if expected > MAX_DECODED_BYTES:
        raise UnsupportedImage("PNG 解码后数据过大，超过上限 %d 字节" % MAX_DECODED_BYTES)
    # 用 decompressobj 并传入 max_length：解压输出被限制在 expected 以内，
    # 多出来的部分留在 unconsumed_tail 里，于是压缩炸弹撑不爆内存。
    # 注意 zlib.decompress 的 bufsize 参数只是初始缓冲区大小，起不到限制作用。
    decomp = zlib.decompressobj()
    try:
        raw = decomp.decompress(bytes(idat), expected)
    except zlib.error:
        raise ValueError("PNG 图像数据解压失败（文件可能已损坏）")
    if decomp.unconsumed_tail:
        raise ValueError("PNG 图像数据超出 IHDR 声明的尺寸")
    if len(raw) < expected:
        raise ValueError("PNG 图像数据不完整")
    px = _unfilter(raw, width, height, bpp, stride)
    return width, height, px, bit_depth, color_type, channels, palette


def _png_rows_to_rgb(px, width, height, bit_depth, color_type, channels, palette):
    """把解码后的像素流还原成 RGB（灰度复制到三通道，透明通道忽略）。"""
    out = bytearray(width * height * 3)
    if bit_depth == 8:
        for i in range(width * height):
            o = i * channels
            if color_type in (0, 4):          # 灰度 / 灰度+透明
                r = g = b = px[o]
            elif color_type in (2, 6):        # RGB / RGBA
                r, g, b = px[o], px[o + 1], px[o + 2]
            else:                             # 调色板
                r, g, b = _palette_rgb(palette, px[o])
            d = i * 3
            out[d], out[d + 1], out[d + 2] = r, g, b
    elif bit_depth == 16:
        step = channels * 2
        for i in range(width * height):
            o = i * step
            if color_type in (0, 4):
                r = g = b = px[o]             # 大端，取高字节
            else:
                r, g, b = px[o], px[o + 2], px[o + 4]
            d = i * 3
            out[d], out[d + 1], out[d + 2] = r, g, b
    else:                                     # 1 / 2 / 4 位
        maxv = (1 << bit_depth) - 1
        per = 8 // bit_depth
        row_bytes = (width * bit_depth + 7) // 8
        for y in range(height):
            base = y * row_bytes
            for x in range(width):
                byte = px[base + x // per]
                shift = 8 - bit_depth * (x % per + 1)
                v = (byte >> shift) & maxv
                if color_type == 3:
                    r, g, b = _palette_rgb(palette, v)
                else:
                    v = v * 255 // maxv
                    r = g = b = v
                d = (y * width + x) * 3
                out[d], out[d + 1], out[d + 2] = r, g, b
    return bytes(out)


def _palette_rgb(palette, index):
    """从 PLTE 调色板取第 index 项的 RGB。"""
    if palette is None:
        return (0, 0, 0)
    off = index * 3
    if off + 2 >= len(palette):
        return (0, 0, 0)
    return (palette[off], palette[off + 1], palette[off + 2])


# ------------------------------------------------------------------ BMP
def bmp_to_gray(data):
    """解码未压缩的 24/32 位 BMP，返回 (width, height, gray_bytes)。"""
    width, height, px, bpp, row_stride, data_off, bottom_up = _bmp_decode(data)
    step = bpp // 8
    out = bytearray(width * height)
    for y in range(height):
        src_y = (height - 1 - y) if bottom_up else y
        base = data_off + src_y * row_stride
        for x in range(width):
            o = base + x * step
            b, g, r = px[o], px[o + 1], px[o + 2]
            out[y * width + x] = (r * 299 + g * 587 + b * 114) // 1000
    return width, height, bytes(out)


def bmp_to_rgb(data):
    """解码未压缩的 24/32 位 BMP，返回 (width, height, rgb_bytes)。"""
    width, height, px, bpp, row_stride, data_off, bottom_up = _bmp_decode(data)
    step = bpp // 8
    out = bytearray(width * height * 3)
    for y in range(height):
        src_y = (height - 1 - y) if bottom_up else y
        base = data_off + src_y * row_stride
        for x in range(width):
            o = base + x * step
            d = (y * width + x) * 3
            # BMP 像素顺序是 BGR
            out[d], out[d + 1], out[d + 2] = px[o + 2], px[o + 1], px[o]
    return width, height, bytes(out)


def _bmp_decode(data):
    """解析 BMP 头部并返回 (width, height, px, bpp, row_stride, data_off, bottom_up)。"""
    if data[:2] != b"BM":
        raise UnsupportedImage("不是合法的 BMP 文件")
    if len(data) < 54:
        raise ValueError("BMP 文件头不完整")
    data_off = int.from_bytes(data[10:14], "little")
    hdr_size = int.from_bytes(data[14:18], "little")
    if hdr_size < 40:
        raise UnsupportedImage("不支持的 BMP 头类型（仅支持 BITMAPINFOHEADER 及以上）")
    width = int.from_bytes(data[18:22], "little", signed=True)
    height = int.from_bytes(data[22:26], "little", signed=True)
    bpp = int.from_bytes(data[28:30], "little")
    compression = int.from_bytes(data[30:34], "little")
    if compression != 0:
        raise UnsupportedImage("仅支持未压缩（BI_RGB）的 BMP")
    if bpp not in (24, 32):
        raise UnsupportedImage("仅支持 24 位或 32 位 BMP")
    if width <= 0 or height == 0:
        raise ValueError("BMP 尺寸非法")
    bottom_up = height > 0
    height = abs(height)
    _check_pixels(width, height, "BMP")
    row_stride = ((width * bpp + 31) // 32) * 4
    if data_off + row_stride * height > len(data):
        raise ValueError("BMP 像素数据不完整")
    return width, height, data, bpp, row_stride, data_off, bottom_up


# ------------------------------------------------------------------ 统一入口
def detect_format(data):
    if data[:8] == PNG_SIG:
        return "PNG"
    if data[:2] == b"BM":
        return "BMP"
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "TIFF"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP"
    if data[:2] in (b"P6", b"P5"):
        return "PPM"
    return None


def load_gray(path_or_bytes):
    """加载图片为灰度。返回 (width, height, gray_bytes)。

    优先使用 Pillow（若已安装），否则回退到内置的 PNG/BMP 解码器。
    """
    if isinstance(path_or_bytes, (bytes, bytearray)):
        data = bytes(path_or_bytes)
        path = None
    else:
        path = path_or_bytes
        with open(path, "rb") as fh:
            data = fh.read()

    fmt = detect_format(data)
    if fmt is None:
        raise UnsupportedImage("无法识别的图片格式（支持 PNG / BMP，装 Pillow 后可支持 JPEG 等）")

    if _PILImage is not None:
        try:
            import io
            img = _PILImage.open(io.BytesIO(data))
            _check_pixels(img.size[0], img.size[1], "图片")
            img = img.convert("L")
            return img.size[0], img.size[1], img.tobytes()
        except _PIL_BOMB_ERROR:
            # Pillow 判定这是解压炸弹。这是它的明确结论，不能吞掉之后
            # 再拿内置解码器去试——那就等于绕过了这道防护。
            raise UnsupportedImage("图片过大，疑似解压炸弹，已拒绝解码")
        except UnsupportedImage:
            raise
        except Exception:
            pass  # 其它情况（比如 Pillow 打不开这个变体）才退回内置解码器

    if fmt == "PNG":
        return png_to_gray(data)
    if fmt == "BMP":
        return bmp_to_gray(data)
    raise UnsupportedImage(
        "当前环境未安装 Pillow，内置解码器只支持 PNG 和 BMP，无法处理 %s 格式" % fmt
    )


def supported_formats():
    return PILLOW_FORMATS if _PILImage is not None else PURE_PYTHON_FORMATS


def backend_name():
    return "Pillow" if _PILImage is not None else "内置解码器（PNG/BMP）"


# ------------------------------------------------------------------ 缩放与 DCT
def resize_gray(gray, w, h, nw, nh):
    """用均值盒式滤波把灰度图缩放到 nw*nh，返回浮点列表（行优先）。"""
    if w <= 0 or h <= 0:
        raise ValueError("源图尺寸非法")
    out = []
    for ty in range(nh):
        y0 = ty * h // nh
        y1 = max(y0 + 1, (ty + 1) * h // nh)
        for tx in range(nw):
            x0 = tx * w // nw
            x1 = max(x0 + 1, (tx + 1) * w // nw)
            total = 0
            count = 0
            for y in range(y0, y1):
                base = y * w
                for x in range(x0, x1):
                    total += gray[base + x]
                    count += 1
            out.append(total / float(count))
    return out


_DCT_CACHE = {}


def _dct_matrix(n):
    """返回 n*n 的 DCT-II 正交变换矩阵（带缓存）。"""
    cached = _DCT_CACHE.get(n)
    if cached is not None:
        return cached
    mat = []
    for k in range(n):
        scale = math.sqrt(1.0 / n) if k == 0 else math.sqrt(2.0 / n)
        row = [scale * math.cos(math.pi * (2 * i + 1) * k / (2.0 * n)) for i in range(n)]
        mat.append(row)
    _DCT_CACHE[n] = mat
    return mat


def dct2(px, n):
    """二维 DCT（可分离：先按行再按列），输入为 n*n 的行优先列表。"""
    mat = _dct_matrix(n)
    tmp = [[0.0] * n for _ in range(n)]
    for r in range(n):
        row = px[r * n:(r + 1) * n]
        for k in range(n):
            mk = mat[k]
            s = 0.0
            for i in range(n):
                s += mk[i] * row[i]
            tmp[r][k] = s
    out = [0.0] * (n * n)
    for c in range(n):
        for k in range(n):
            mk = mat[k]
            s = 0.0
            for r in range(n):
                s += mk[r] * tmp[r][c]
            out[k * n + c] = s
    return out


def _median(values):
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


# ------------------------------------------------------------------ 感知哈希
def phash_bits(gray, w, h):
    """pHash：DCT 低频 8x8 中位数哈希，抗压缩 / 缩放 / 轻微调色。"""
    small = resize_gray(gray, w, h, 32, 32)
    coeff = dct2(small, 32)
    vals = []
    for v in range(8):
        for u in range(8):
            if v == 0 and u == 0:
                continue
            vals.append(coeff[v * 32 + u])
    med = _median(vals)
    bits = 0
    for v in range(8):
        for u in range(8):
            if v == 0 and u == 0:
                bits = bits << 1          # 直流分量固定为 0，不参与比较
            else:
                bits = (bits << 1) | (1 if coeff[v * 32 + u] > med else 0)
    return bits


def ahash_bits(gray, w, h):
    """aHash：8x8 灰度均值哈希。"""
    small = resize_gray(gray, w, h, 8, 8)
    avg = sum(small) / float(len(small))
    bits = 0
    for v in small:
        bits = (bits << 1) | (1 if v > avg else 0)
    return bits


def dhash_bits(gray, w, h):
    """dHash：9x8 水平差分哈希，对亮度整体变化更鲁棒。"""
    small = resize_gray(gray, w, h, 9, 8)
    bits = 0
    for r in range(8):
        base = r * 9
        for c in range(8):
            bits = (bits << 1) | (1 if small[base + c] > small[base + c + 1] else 0)
    return bits


# ------------------------------------------------------------------ 缩略图
def thumbnail_bytes(data, max_side=128):
    """把一张图压成最长边 max_side 的 PNG 缩略图，返回 (png_bytes, "image/png")。

    处理不了时返回 (None, None)——调用方应回退到原图：
      * 有 Pillow：覆盖全部 Pillow 格式（JPEG/GIF/WebP 等），缩略后存 PNG；
      * 纯标准库：只支持 PNG / BMP，用盒式采样（区域内均值）缩放，
        保留色彩——比最近邻平滑，避免缩略图出现锯齿。
    """
    if _PILImage is not None:
        try:
            import io
            img = _PILImage.open(io.BytesIO(data))
            _check_pixels(img.size[0], img.size[1], "图片")
            img.thumbnail((max_side, max_side))
            buf = io.BytesIO()
            img.convert("RGB").save(buf, "PNG")
            return buf.getvalue(), "image/png"
        except _PIL_BOMB_ERROR:
            raise UnsupportedImage("图片过大，疑似解压炸弹，已拒绝解码")
        except Exception:
            pass   # Pillow 打不开的变体落回纯标准库路径

    fmt = detect_format(data)
    if fmt == "PNG":
        w, h, rgb = png_to_rgb(data)
    elif fmt == "BMP":
        w, h, rgb = bmp_to_rgb(data)
    else:
        return None, None

    scale = min(1.0, float(max_side) / max(w, h))
    nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
    out = bytearray(nw * nh * 3)
    for ty in range(nh):
        y0 = ty * h // nh
        y1 = max(y0 + 1, (ty + 1) * h // nh)
        for tx in range(nw):
            x0 = tx * w // nw
            x1 = max(x0 + 1, (tx + 1) * w // nw)
            r = g = b = 0
            for y in range(y0, y1):
                base = (y * w + x0) * 3
                for x in range(x0, x1):
                    o = base + (x - x0) * 3
                    r += rgb[o]
                    g += rgb[o + 1]
                    b += rgb[o + 2]
            n = (y1 - y0) * (x1 - x0)
            d = (ty * nw + tx) * 3
            out[d], out[d + 1], out[d + 2] = r // n, g // n, b // n
    return encode_png(nw, nh, bytes(out)), "image/png"


# ------------------------------------------------------------------ PNG 编码
def _png_chunk(tag, data):
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def encode_png(width, height, rgb, filter_type=0):
    """把 RGB 字节流编码为 PNG。

    filter_type 用于指定所有扫描线使用哪种滤波器（0-4），
    既方便生成演示图片，也让自检能覆盖解码器的全部滤波分支。
    """
    if len(rgb) < width * height * 3:
        raise ValueError("RGB 数据长度不足")
    if filter_type not in (0, 1, 2, 3, 4):
        raise ValueError("filter_type 只能是 0-4")
    bpp = 3
    stride = width * 3
    raw = bytearray()
    prev = bytes(stride)
    for y in range(height):
        line = bytes(rgb[y * stride:(y + 1) * stride])
        filtered = bytearray(stride)
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if filter_type == 0:
                pred = 0
            elif filter_type == 1:
                pred = a
            elif filter_type == 2:
                pred = b
            elif filter_type == 3:
                pred = (a + b) >> 1
            else:
                pred = _paeth(a, b, c)
            filtered[i] = (line[i] - pred) & 0xFF
        raw.append(filter_type)
        raw += filtered
        prev = line
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (PNG_SIG
            + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 6))
            + _png_chunk(b"IEND", b""))


# 示例画作的构图（相对坐标、半径、颜色偏移）
_DEMO_BLOBS = (
    (0.32, 0.30, 0.22, (95, -25, 35)),
    (0.63, 0.42, 0.19, (-45, 70, 15)),
    (0.46, 0.70, 0.26, (25, 15, -60)),
    (0.79, 0.74, 0.15, (70, 45, 95)),
    (0.18, 0.62, 0.13, (-30, -40, 60)),
)


def _blobs_for(variant):
    """按变体号确定性地生成构图（位置、大小、配色都不同）。"""
    out = []
    flipped = variant % 3
    for index, (bx, by, rad, add) in enumerate(_DEMO_BLOBS):
        h = (variant * 7919 + index * 104729) % 1000
        dx = ((h % 37) - 18) / 60.0
        dy = ((h // 37 % 31) - 15) / 60.0
        if flipped == 1:
            bx, by = by, bx
        elif flipped == 2:
            bx, by = 1.0 - bx, 1.0 - by
        shift = variant * 53
        out.append((
            bx + dx * 0.30,
            by + dy * 0.30,
            rad * (0.80 + (h % 50) / 100.0),
            (add[0] + shift, add[1] - shift, add[2] + shift // 2),
        ))
    return out


def make_demo_image(width=192, height=192, variant=0, brightness=0):
    """生成一张确定的"抽象画"RGB 位图，用于演示与自检。

    variant      改变底纹频率、相位与构图（模拟不同的作品）
    brightness   整体提升亮度（模拟"盗图后调亮再发布"）
    """
    blobs = _blobs_for(variant)
    phase = variant * 0.83
    freq_x = 9.0 + (variant % 5) * 3.0
    freq_y = 11.0 + (variant % 3) * 4.0
    px = bytearray()
    for y in range(height):
        for x in range(width):
            r = 127.0 + 110.0 * math.sin(x / freq_x + phase)
            g = 127.0 + 110.0 * math.sin(y / freq_y + phase * 1.7)
            b = 127.0 + 110.0 * math.sin((x + y) / 13.0 + phase * 2.3)
            for bx, by, rad, add in blobs:
                dx = x - bx * width
                dy = y - by * height
                if dx * dx + dy * dy < (rad * width) ** 2:
                    r += add[0]
                    g += add[1]
                    b += add[2]
            px.append(max(0, min(255, int(r + brightness))))
            px.append(max(0, min(255, int(g + brightness))))
            px.append(max(0, min(255, int(b + brightness))))
    return bytes(px)


def make_alt_image(width=192, height=192, cell=12):
    """生成一张风格迥异的"几何硬边"图（棋盘 + 斜条纹）。

    用于自检与演示中的"无关作品不误判"场景。
    """
    step = max(1, cell // 2)
    px = bytearray()
    for y in range(height):
        for x in range(width):
            checker = ((x // cell) + (y // cell)) % 2
            stripe = ((x + y) // step) % 2
            if checker:
                color = (232, 48, 48) if stripe else (36, 36, 220)
            else:
                color = (248, 248, 248) if stripe else (18, 18, 18)
            px += bytes(color)
    return bytes(px)


def write_demo_png(path, width=192, height=192, variant=0, brightness=0):
    data = make_demo_image(width, height, variant=variant, brightness=brightness)
    with open(path, "wb") as fh:
        fh.write(encode_png(width, height, data))
    return path
