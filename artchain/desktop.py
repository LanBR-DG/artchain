# -*- coding: utf-8 -*-
"""桌面可视化窗口（Tkinter，Python 标准库自带，零第三方依赖）。

    python -m artchain desktop            打开窗口
    python -m artchain desktop --data X   指定数据目录

四个页签：
    概览      链与账本的关键指标 + 每块交易量柱状图
    区块链    把区块画成一条链，点击任意区块看它的交易明细
    作品      全部确权作品，点击看权属沿革、授权许可与上链证明
    侵权比对  选一个文件，与链上作品做感知指纹比对

设计上刻意只用最基础的 ttk 部件（Notebook / Treeview / Canvas / Text），
所有明细都用只读 Text 渲染，避免大量动态 Label 带来的排版问题。

注意：Tkinter 必须在主线程创建和刷新，因此耗时动作（生成演示数据）放到
后台线程里跑，完成后通过 root.after 回到主线程刷新界面。
"""

import os
import threading

from . import service

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    TK_IMPORT_ERROR = None
except Exception as exc:  # noqa: BLE001 - 无图形环境时给出可读提示
    tk = None
    TK_IMPORT_ERROR = exc

# ------------------------------------------------------------------ 配色与尺寸
# 苹果风格，与 web/index.html、独立展示版同一套基准：
# 灰底 #f5f5f7、白卡、系统蓝 #0071e3、正文 #1d1d1f。改这里即可整体换肤。
BG = "#f5f5f7"
PANEL = "#ffffff"
INK = "#1d1d1f"
MUTED = "#6e6e73"
LINE = "#d2d2d7"
GRID = "#e8e8ed"           # 更浅的分隔线/卡片描边
BLUE = "#0071e3"           # 系统蓝（强调、选中、当前区块）
BLUE_SOFT = "#eaf3fd"      # 淡蓝填充（选中态底色）
BLUE_MID = "#b3d7fb"       # 图表中非当前区块的浅蓝
ARROW = "#a1a1a6"          # 链视图连接箭头
OK = "#248a3d"
WARN = "#b25000"
BAD = "#d70015"

FONT = ("Microsoft YaHei UI", 10)
FONT_BOLD = ("Microsoft YaHei UI", 10, "bold")
FONT_TITLE = ("Microsoft YaHei UI", 14, "bold")
FONT_BRAND = ("Microsoft YaHei UI", 15, "bold")
FONT_KPI = ("Microsoft YaHei UI", 16, "bold")
FONT_MONO = ("Consolas", 9)

BLOCK_W = 112
BLOCK_H = 66
BLOCK_GAP = 36
CANVAS_MARGIN = 22

STATUS_TEXT = {5: "完全一致", 4: "高度疑似", 3: "疑似", 2: "部分相似", 1: "不相似"}


def _friendly_error():
    return ("未找到可用的 Tkinter 图形库：%s\n\n"
            "Windows 官方 Python 安装包自带 Tkinter，若缺失请重新安装 Python 并勾选 "
            "tcl/tk and IDLE 组件。" % TK_IMPORT_ERROR)


# ================================================================== 主窗口
class DesktopApp(object):
    """ArtChain 桌面可视化窗口。"""

    def __init__(self, ctx, refresh_ms=3000):
        if tk is None:
            raise RuntimeError(_friendly_error())
        self.ctx = ctx
        self.refresh_ms = int(refresh_ms)
        self.selected_height = None
        self.selected_work_id = None
        self._hits = []          # 链视图里的点击热区 [(x1, y1, x2, y2, height)]
        self._busy = False
        self._works_signature = None   # 作品列表的内容签名，用于避免无谓重建

        self.root = tk.Tk()
        self.root.title("ArtChain 艺术品区块链确权系统")
        self.root.geometry("1180x760")
        self.root.minsize(980, 640)
        self.root.configure(bg=BG)
        self._init_style()

        self._build_header()
        self._build_tabs()
        self._build_statusbar()

        self.refresh_all()
        self.root.after(self.refresh_ms, self._tick)

    # -------------------------------------------------------------- 样式
    def _init_style(self):
        style = ttk.Style()
        for theme in ("clam", "vista", "default"):
            try:
                style.theme_use(theme)
                break
            except tk.TclError:
                continue
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(18, 8), font=FONT)
        style.map("TNotebook.Tab",
                  background=[("selected", PANEL)],
                  foreground=[("selected", INK)],
                  expand=[("selected", (0, 0, 0, 0))])
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=INK, font=FONT)
        style.configure("Panel.TLabel", background=PANEL, foreground=INK, font=FONT)
        style.configure("Muted.TLabel", background=PANEL, foreground=MUTED, font=FONT)
        style.configure("Title.TLabel", background=BG, foreground=INK, font=FONT_TITLE)
        style.configure("Kpi.TLabel", background=PANEL, foreground=BLUE, font=FONT_TITLE)
        # 主按钮：蓝底白字（clam 主题下 background/light/dark 三件套才吃得进颜色）
        style.configure("TButton", font=FONT, padding=(12, 6), borderwidth=0,
                        background=BLUE, foreground="#ffffff",
                        lightcolor=BLUE, darkcolor=BLUE, focuscolor=BLUE)
        style.map("TButton",
                  background=[("active", "#2a8ceb"), ("pressed", "#0058b0"),
                              ("disabled", LINE)],
                  foreground=[("disabled", MUTED)])
        style.configure("TEntry", fieldbackground=BG, font=FONT)
        style.configure("Treeview", font=FONT, rowheight=28, background=PANEL,
                        fieldbackground=PANEL, borderwidth=0)
        style.configure("Treeview.Heading", font=FONT, foreground=MUTED)
        style.map("Treeview", background=[("selected", BLUE_SOFT)],
                  foreground=[("selected", INK)])

    # -------------------------------------------------------------- 顶栏
    def _build_header(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(bar, text="ArtChain", bg=BG, fg=BLUE,
                 font=FONT_BRAND).pack(side="left")
        tk.Label(bar, text="  艺术品区块链确权系统 · 桌面版", bg=BG, fg=MUTED,
                 font=FONT).pack(side="left", pady=(4, 0))
        ttk.Button(bar, text="重新加载链", command=self.reload_chain).pack(side="right")
        ttk.Button(bar, text="刷新", command=self.refresh_all).pack(side="right", padx=6)

    # -------------------------------------------------------------- 页签
    def _build_tabs(self):
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=14, pady=6)
        self.tab_overview = ttk.Frame(self.nb)
        self.tab_chain = ttk.Frame(self.nb)
        self.tab_works = ttk.Frame(self.nb)
        self.tab_compare = ttk.Frame(self.nb)
        self.nb.add(self.tab_overview, text="概览")
        self.nb.add(self.tab_chain, text="区块链")
        self.nb.add(self.tab_works, text="作品")
        self.nb.add(self.tab_compare, text="侵权比对")

        self._build_overview()
        self._build_chain()
        self._build_works()
        self._build_compare()

    # -------------------------------------------------------------- 概览页
    def _build_overview(self):
        wrap = tk.Frame(self.tab_overview, bg=BG)
        wrap.pack(fill="both", expand=True)

        self.kpi_frame = tk.Frame(wrap, bg=BG)
        self.kpi_frame.pack(fill="x", pady=(4, 10))
        self.kpi_labels = {}
        for key, title in (("height", "区块高度"), ("works_total", "确权作品"),
                           ("works_active", "有效作品"), ("works_disputed", "争议中"),
                           ("works_invalid", "已无效"),
                           ("difficulty", "挖矿难度"), ("pending_txs", "待打包"),
                           ("licenses_total", "授权许可"), ("transfers_total", "转让次数")):
            card = tk.Frame(self.kpi_frame, bg=PANEL, highlightbackground=GRID,
                            highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=4)
            tk.Label(card, text=title, bg=PANEL, fg=MUTED, font=FONT).pack(
                anchor="w", padx=12, pady=(10, 0))
            value = tk.Label(card, text="—", bg=PANEL, fg=BLUE, font=FONT_KPI)
            value.pack(anchor="w", padx=12, pady=(0, 10))
            self.kpi_labels[key] = value

        box = tk.Frame(wrap, bg=PANEL, highlightbackground=GRID, highlightthickness=1)
        box.pack(fill="both", expand=True, pady=(0, 4))
        tk.Label(box, text="每个区块的交易量", bg=PANEL, fg=INK,
                 font=FONT_BOLD).pack(anchor="w", padx=12, pady=(10, 0))
        self.chart = tk.Canvas(box, bg=PANEL, highlightthickness=0, height=260)
        self.chart.pack(fill="both", expand=True, padx=12, pady=10)
        self.chart.bind("<Configure>", lambda _e: self._draw_chart())

    def _draw_chart(self):
        canvas = self.chart
        canvas.delete("all")
        chain = self.ctx.chain
        if not chain.ready:
            canvas.create_text(20, 30, anchor="nw", fill=MUTED, font=FONT,
                               text="尚未初始化区块链。")
            return
        blocks = chain.blocks[-40:]
        if not blocks:
            return
        width = max(canvas.winfo_width(), 200)
        height = max(canvas.winfo_height(), 120)
        counts = [len(b.get("txs") or []) for b in blocks]
        peak = max(counts) or 1
        pad_l, pad_b, pad_t = 34, 26, 12
        available = width - pad_l - 12
        slot = max(6.0, available / float(len(blocks)))
        bar_w = max(4.0, slot * 0.62)

        for frac in (0.0, 0.5, 1.0):
            y = height - pad_b - (height - pad_b - pad_t) * frac
            canvas.create_line(pad_l, y, width - 6, y, fill=GRID)
            canvas.create_text(pad_l - 6, y, anchor="e", text=str(int(peak * frac)),
                               fill=MUTED, font=FONT_MONO)

        for i, block in enumerate(blocks):
            count = counts[i]
            bar_h = (height - pad_b - pad_t) * (count / float(peak))
            x1 = pad_l + i * slot + (slot - bar_w) / 2.0
            y1 = height - pad_b - bar_h
            colour = BLUE if block.get("height") == chain.height else BLUE_MID
            canvas.create_rectangle(x1, y1, x1 + bar_w, height - pad_b,
                                    fill=colour, outline="")
            if slot > 22 or i % 2 == 0:
                canvas.create_text(x1 + bar_w / 2.0, height - pad_b + 10,
                                   text=str(block.get("height")), fill=MUTED, font=FONT_MONO)
            if count:
                canvas.create_text(x1 + bar_w / 2.0, y1 - 8, text=str(count),
                                   fill=MUTED, font=FONT_MONO)

    # -------------------------------------------------------------- 区块链页
    def _build_chain(self):
        pane = tk.PanedWindow(self.tab_chain, orient="horizontal", bg=BG,
                              sashwidth=6, borderwidth=0)
        pane.pack(fill="both", expand=True)

        left = tk.Frame(pane, bg=BG)
        self.chain_canvas = tk.Canvas(left, bg=PANEL, highlightthickness=1,
                                      highlightbackground=GRID, height=200)
        hbar = ttk.Scrollbar(left, orient="horizontal", command=self.chain_canvas.xview)
        self.chain_canvas.configure(xscrollcommand=hbar.set)
        self.chain_canvas.pack(fill="both", expand=True)
        hbar.pack(fill="x")
        tk.Label(left, text="点击任意区块查看它的交易明细", bg=BG, fg=MUTED,
                 font=FONT).pack(anchor="w", pady=4)
        self.chain_canvas.bind("<Button-1>", self._on_chain_click)
        pane.add(left, minsize=420, stretch="always")

        right = tk.Frame(pane, bg=PANEL, highlightbackground=GRID, highlightthickness=1)
        self.chain_detail = self._make_text(right)
        pane.add(right, minsize=320, stretch="always")
        self.chain_detail.configure(state="normal")
        self.chain_detail.insert("1.0", "尚未选择区块。")
        self.chain_detail.configure(state="disabled")

    def _draw_chain(self):
        canvas = self.chain_canvas
        canvas.delete("all")
        self._hits = []
        chain = self.ctx.chain
        if not chain.ready:
            canvas.create_text(CANVAS_MARGIN, CANVAS_MARGIN, anchor="nw", font=FONT,
                               fill=MUTED, text="尚未初始化区块链。")
            canvas.configure(scrollregion=(0, 0, 400, 200))
            return

        y1 = 26
        y2 = y1 + BLOCK_H
        for i, block in enumerate(chain.blocks):
            x1 = CANVAS_MARGIN + i * (BLOCK_W + BLOCK_GAP)
            x2 = x1 + BLOCK_W
            height = block.get("height", i)
            selected = (height == self.selected_height)
            canvas.create_rectangle(
                x1, y1, x2, y2,
                fill=BLUE_SOFT if selected else PANEL,
                outline=BLUE if selected else GRID,
                width=3 if selected else 1)
            canvas.create_text(x1 + BLOCK_W / 2.0, y1 + 14, text="#%d" % height,
                               fill=INK, font=FONT_BOLD)
            canvas.create_text(x1 + BLOCK_W / 2.0, y1 + 34,
                               text="%d 笔交易" % len(block.get("txs") or []),
                               fill=MUTED, font=FONT)
            canvas.create_text(x1 + BLOCK_W / 2.0, y1 + 52,
                               text=str(block.get("hash", ""))[:10],
                               fill=BLUE, font=FONT_MONO)
            self._hits.append((x1, y1, x2, y2, height))
            if i < len(chain.blocks) - 1:
                canvas.create_line(x2, y1 + BLOCK_H / 2.0, x2 + BLOCK_GAP - 6,
                                   y1 + BLOCK_H / 2.0, arrow=tk.LAST, fill=ARROW, width=2)

        total_w = CANVAS_MARGIN * 2 + len(chain.blocks) * BLOCK_W + \
            max(0, len(chain.blocks) - 1) * BLOCK_GAP
        canvas.configure(scrollregion=(0, 0, max(total_w, 400), y2 + 40))

    def _on_chain_click(self, event):
        x = self.chain_canvas.canvasx(event.x)
        y = self.chain_canvas.canvasy(event.y)
        for x1, y1, x2, y2, height in self._hits:
            if x1 <= x <= x2 and y1 <= y <= y2:
                self.selected_height = height
                self._show_block(height)
                self._draw_chain()
                return

    def _show_block(self, height):
        chain = self.ctx.chain
        if not 0 <= height < len(chain.blocks):
            self._set_text(self.chain_detail, "区块不存在。")
            return
        block = chain.blocks[height]
        lines = [
            "区块 #%s" % block.get("height"),
            "=" * 46,
            "区块哈希    %s" % block.get("hash"),
            "前序哈希    %s" % block.get("prev_hash"),
            "Merkle 根   %s" % block.get("merkle_root"),
            "出块时间    %s" % _fmt_time(block.get("time")),
            "出块人      %s" % (block.get("miner") or "—"),
            "难度/随机数 %s / %s" % (block.get("difficulty"), block.get("nonce")),
            "交易数量    %d 笔" % len(block.get("txs") or []),
            "",
            "交易明细",
            "-" * 46,
        ]
        for pos, tx in enumerate(block.get("txs") or []):
            data = tx.get("data") or {}
            summary = _tx_summary(tx)
            lines.append("%d. [%s] %s" % (pos + 1, tx.get("type"), summary))
            lines.append("   发起方 %s" % _short(tx.get("sender")))
            lines.append("   nonce  %s    时间 %s" % (tx.get("nonce"), _fmt_time(tx.get("time"))))
            lines.append("   txid   %s" % tx.get("txid"))
            if tx.get("type") == "REGISTER":
                lines.append("   作品   %s《%s》" % (data.get("work_id"), data.get("title")))
            elif tx.get("type") == "TRANSFER":
                lines.append("   受让方 %s  价款 %s" % (_short(data.get("to")),
                                                  data.get("price") or "无偿"))
            elif tx.get("type") == "LICENSE":
                lines.append("   被许可 %s  %s授权" % (_short(data.get("to")), data.get("scope")))
            elif tx.get("type") == "DISPUTE":
                lines.append("   异议理由 %s" % data.get("reason"))
            elif tx.get("type") == "ADJUDICATE":
                lines.append("   裁决结论 %s异议  理由 %s" % (data.get("ruling"),
                                                        data.get("reason")))
            elif tx.get("type") == "REVOKE":
                lines.append("   撤销理由 %s" % data.get("reason"))
            lines.append("")
        if not block.get("txs"):
            lines.append("（空区块）")
        self._set_text(self.chain_detail, "\n".join(lines))

    # -------------------------------------------------------------- 作品页
    def _build_works(self):
        pane = tk.PanedWindow(self.tab_works, orient="horizontal", bg=BG,
                              sashwidth=6, borderwidth=0)
        pane.pack(fill="both", expand=True)

        left = tk.Frame(pane, bg=BG)
        search = tk.Frame(left, bg=BG)
        search.pack(fill="x", pady=(0, 6))
        tk.Label(search, text="检索", bg=BG, fg=INK, font=FONT).pack(side="left")
        self.work_query = tk.StringVar()
        entry = ttk.Entry(search, textvariable=self.work_query, font=FONT)
        entry.pack(side="left", fill="x", expand=True, padx=6)
        entry.bind("<Return>", lambda _e: self.refresh_works())
        ttk.Button(search, text="搜索", command=self.refresh_works).pack(side="left")

        columns = ("work_id", "title", "category", "author", "owner", "status", "height")
        self.work_tree = ttk.Treeview(left, columns=columns, show="headings", height=18)
        for key, title, width in (("work_id", "作品编号", 190), ("title", "名称", 140),
                                  ("category", "类别", 90), ("author", "作者", 90),
                                  ("owner", "当前权利人", 130), ("status", "状态", 70),
                                  ("height", "区块", 60)):
            self.work_tree.heading(key, text=title)
            self.work_tree.column(key, width=width, anchor="w")
        vbar = ttk.Scrollbar(left, orient="vertical", command=self.work_tree.yview)
        self.work_tree.configure(yscrollcommand=vbar.set)
        self.work_tree.pack(side="left", fill="both", expand=True)
        vbar.pack(side="left", fill="y")
        self.work_tree.bind("<<TreeviewSelect>>", self._on_work_select)
        pane.add(left, minsize=520, stretch="always")

        right = tk.Frame(pane, bg=PANEL, highlightbackground=GRID, highlightthickness=1)
        self.work_detail = self._make_text(right)
        pane.add(right, minsize=340, stretch="always")
        self._set_text(self.work_detail, "尚未选择作品。")

    def refresh_works(self):
        tree = self.work_tree
        keyword = (self.work_query.get() or "").strip() or None
        try:
            works = self.ctx.chain.ledger.list_works(keyword=keyword)
        except Exception as exc:  # noqa: BLE001
            self.set_status("读取作品失败：%s" % exc, BAD)
            return
        # 定时刷新如果每次都重建列表，会把用户当前选中的行冲掉；
        # 因此只在作品集合真的发生变化的才重建（注意还有查询词变化）。
        signature = (keyword,) + tuple(
            (w.get("work_id"), w.get("title"), w.get("owner"), w.get("status"))
            for w in works)
        if signature == self._works_signature:
            return
        self._works_signature = signature

        selected = self.selected_work_id
        for item in tree.get_children():
            tree.delete(item)
        for work in works:
            tree.insert("", "end", iid=work.get("work_id"), values=(
                work.get("work_id"), work.get("title"), work.get("category"),
                work.get("author"), _short(work.get("owner")), work.get("status"),
                "#%s" % work.get("height")))
        if selected and tree.exists(selected):
            tree.selection_set(selected)
        self.set_status("共 %d 件作品" % len(works))

    def _on_work_select(self, _event):
        selection = self.work_tree.selection()
        if not selection:
            return
        self.selected_work_id = selection[0]
        self._show_work(self.selected_work_id)

    def _show_work(self, work_id):
        try:
            detail = service.work_detail(self.ctx.chain, work_id)
        except Exception as exc:  # noqa: BLE001
            self._set_text(self.work_detail, "读取作品详情失败：%s" % exc)
            return
        work = detail["work"]
        proof = detail.get("proof") or {}
        lines = [
            "《%s》" % work.get("title"),
            "=" * 46,
            "作品编号    %s" % work.get("work_id"),
            "作品类别    %s" % work.get("category"),
            "作者署名    %s" % (work.get("author") or "—"),
            "创作年份    %s" % (work.get("year") or "—"),
            "创作日期    %s" % (work.get("created_at") or "—"),
            "权属状态    %s" % work.get("status"),
            "原始权利人  %s" % _short(work.get("creator")),
            "当前权利人  %s" % _short(work.get("owner")),
            "登记时间    %s" % _fmt_time(work.get("registered_at")),
            "",
            "数字指纹",
            "-" * 46,
            "SHA-256     %s" % work.get("file_hash"),
        ]
        if work.get("phash"):
            lines.append("pHash       %s" % work.get("phash"))
            lines.append("aHash       %s" % work.get("ahash"))
            lines.append("dHash       %s" % work.get("dhash"))
        if work.get("simhash"):
            lines.append("SimHash     %s" % work.get("simhash"))
        lines.append("文件        %s ｜ %s ｜ %s 字节" % (
            work.get("kind"), work.get("mime"), work.get("size")))
        if work.get("image_width"):
            lines.append("图像尺寸    %s x %s" % (
                work.get("image_width"), work.get("image_height")))

        lines.extend(["", "上链存证", "-" * 46,
                      "交易哈希    %s" % work.get("txid"),
                      "所在区块    #%s" % work.get("height")])
        if proof:
            lines.append("Merkle 根   %s" % proof.get("merkle_root"))
            lines.append("存在性证明  %s（路径 %d 层）" % (
                "验证通过" if proof.get("valid") else "验证未通过",
                len(proof.get("merkle_proof") or [])))

        history = detail.get("history") or []
        if history:
            lines.extend(["", "权属沿革", "-" * 46])
            for item in history:
                lines.append("%s  #%s  %s" % (_fmt_time(item.get("time")),
                                            item.get("height"), item.get("action")))
                if item.get("detail"):
                    lines.append("    %s" % item.get("detail"))
                lines.append("    %s → %s" % (_short(item.get("from")), _short(item.get("to"))))

        licenses = detail.get("licenses") or []
        if licenses:
            lines.extend(["", "授权许可", "-" * 46])
            for lic in licenses:
                lines.append("%s授权  被许可方 %s" % (lic.get("scope"), _short(lic.get("to"))))
                lines.append("    地域 %s  期限 %s 至 %s  费用 %s" % (
                    lic.get("territory"), lic.get("start") or "不限",
                    lic.get("end") or "不限", lic.get("royalty") or "—"))
                lines.append("    状态 %s" % lic.get("status"))
        self._set_text(self.work_detail, "\n".join(lines))

    # -------------------------------------------------------------- 比对页
    def _build_compare(self):
        wrap = tk.Frame(self.tab_compare, bg=BG)
        wrap.pack(fill="both", expand=True)

        bar = tk.Frame(wrap, bg=BG)
        bar.pack(fill="x", pady=(2, 8))
        ttk.Button(bar, text="选择文件并比对…", command=self.do_compare).pack(side="left")
        self.compare_path = tk.StringVar(value="未选择文件")
        tk.Label(bar, textvariable=self.compare_path, bg=BG, fg=MUTED,
                 font=FONT).pack(side="left", padx=10)

        self.compare_conclusion = tk.Label(wrap, text="—", bg=PANEL, fg=INK, font=FONT_BOLD,
                                           anchor="w", justify="left", wraplength=1000,
                                           highlightbackground=GRID, highlightthickness=1,
                                           padx=12, pady=10)
        self.compare_conclusion.pack(fill="x", pady=(0, 8))

        columns = ("score", "level", "work_id", "title", "owner", "phash", "height")
        self.compare_tree = ttk.Treeview(wrap, columns=columns, show="headings", height=14)
        for key, title, width in (("score", "相似度", 80), ("level", "判定", 90),
                                  ("work_id", "作品编号", 190), ("title", "名称", 150),
                                  ("owner", "权利人", 130), ("phash", "pHash距离", 90),
                                  ("height", "区块", 60)):
            self.compare_tree.heading(key, text=title)
            self.compare_tree.column(key, width=width, anchor="w")
        self.compare_tree.pack(fill="both", expand=True)
        self.compare_tree.bind("<<TreeviewSelect>>", self._on_compare_select)

    def do_compare(self):
        if self._busy:
            return
        path = filedialog.askopenfilename(title="选择要比对的文件",
                                          filetypes=[("图片 / 文本", "*.png *.jpg *.jpeg *.bmp *.gif *.webp *.txt *.md"),
                                                     ("所有文件", "*.*")])
        if not path:
            return
        self.compare_path.set(path)
        if not self.ctx.chain.ready:
            messagebox.showinfo("提示", "尚未初始化区块链，没有可比对的作品。")
            return
        try:
            with open(path, "rb") as fh:
                content = fh.read()
        except OSError as exc:
            messagebox.showerror("读取失败", "无法读取文件：%s" % exc)
            return

        self.set_status("正在比对 %s …" % os.path.basename(path))
        self.root.update_idletasks()
        try:
            report = service.compare_content(self.ctx.chain, content,
                                             filename=os.path.basename(path))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("比对失败", str(exc))
            self.set_status("比对失败：%s" % exc, BAD)
            return

        for item in self.compare_tree.get_children():
            self.compare_tree.delete(item)
        for row in report.get("results") or []:
            label = row.get("label") or {}
            distances = row.get("distances") or {}
            self.compare_tree.insert("", "end", values=(
                "%.4f" % row.get("score", 0),
                STATUS_TEXT.get(row.get("level"), "—"),
                row.get("id"), label.get("title"), _short(label.get("owner")),
                distances.get("phash") if distances.get("phash") is not None else "—",
                "#%s" % label.get("height")))

        risk = report.get("risk") or {}
        fingerprint = report.get("target_fingerprint") or {}
        colour = BAD if risk.get("level", 0) >= 4 else (WARN if risk.get("level", 0) == 3 else OK)
        text = "比对结论：%s\n样本 %d 件 ｜ 相似度 %.4f ｜ 文件 SHA-256 %s" % (
            risk.get("text", "—"), report.get("checked", 0), risk.get("score", 0.0),
            fingerprint.get("sha256", "—"))
        if risk.get("work_id"):
            text += "\n最相似作品：《%s》（%s）" % (risk.get("title"), risk.get("work_id"))
        self.compare_conclusion.configure(text=text, fg=colour)
        self.set_status("比对完成，共比对 %d 件链上作品" % report.get("checked", 0))

    def _on_compare_select(self, _event):
        selection = self.compare_tree.selection()
        if not selection:
            return
        values = self.compare_tree.item(selection[0], "values")
        if values and len(values) > 2:
            work_id = values[2]
            self.selected_work_id = work_id
            self._show_work(work_id)
            self.nb.select(self.tab_works)
            if self.work_tree.exists(work_id):
                self.work_tree.selection_set(work_id)

    # -------------------------------------------------------------- 公共刷新
    def refresh_all(self):
        ctx = self.ctx
        loaded = False
        try:
            loaded = ctx.ensure_loaded(required=False)
        except Exception as exc:  # noqa: BLE001
            self.set_status("加载链数据失败：%s" % exc, BAD)
            return
        if not loaded:
            self._show_empty_state()
            return
        self.refresh_kpis()
        self._draw_chart()
        self._draw_chain()
        self.refresh_works()
        self.set_status("数据目录 %s ｜ 链高 #%d" % (ctx.store.root, ctx.chain.height))

    def _show_empty_state(self):
        for label in self.kpi_labels.values():
            label.configure(text="—")
        self._draw_chart()
        self._draw_chain()
        for item in self.work_tree.get_children():
            self.work_tree.delete(item)
        self._set_text(self.work_detail, "尚未初始化区块链。\n\n点下方按钮生成演示数据。")
        self.set_status("尚未初始化区块链：%s" % self.ctx.store.root, WARN)
        if not hasattr(self, "init_button"):
            self.init_button = ttk.Button(self.root, text="生成演示数据并初始化",
                                          command=self.seed_demo)
            self.init_button.pack(side="bottom", pady=8)

    def refresh_kpis(self):
        stats = self.ctx.chain.statistics()
        for key, label in self.kpi_labels.items():
            value = stats.get(key)
            label.configure(text="—" if value is None else str(value))

    def reload_chain(self):
        self.ctx.loaded = False
        try:
            self.ctx.ensure_loaded(required=False)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("重新加载失败", str(exc))
            return
        self.refresh_all()

    def seed_demo(self):
        """后台线程跑一遍演示，完成后回主线程刷新。"""
        if self._busy:
            return
        self._busy = True
        self.set_status("正在生成演示数据，请稍候（约 10 秒）…")

        def worker():
            message = None
            try:
                from . import demo
                demo.run(self.ctx)
            except Exception as exc:  # noqa: BLE001
                message = str(exc)
            self.root.after(0, lambda: self._after_seed(message))

        threading.Thread(target=worker, daemon=True).start()

    def _after_seed(self, message):
        self._busy = False
        if message:
            messagebox.showerror("生成失败", message)
            self.set_status("生成演示数据失败：%s" % message, BAD)
            return
        if hasattr(self, "init_button"):
            self.init_button.destroy()
            del self.init_button
        self.reload_chain()

    # -------------------------------------------------------------- 状态栏
    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", side="bottom", padx=14, pady=(0, 10))
        self.status = tk.Label(bar, text="", bg=BG, fg=MUTED, font=FONT, anchor="w")
        self.status.pack(fill="x")

    def set_status(self, text, colour=MUTED):
        try:
            self.status.configure(text=text, fg=colour)
        except tk.TclError:
            pass

    def _tick(self):
        if not self._busy:
            try:
                self.refresh_all()
            except Exception as exc:  # noqa: BLE001 - 定时刷新不应打挂窗口
                self.set_status("刷新失败：%s" % exc, BAD)
        self.root.after(self.refresh_ms, self._tick)

    # -------------------------------------------------------------- 辅助
    @staticmethod
    def _make_text(parent):
        holder = tk.Frame(parent, bg=PANEL)
        holder.pack(fill="both", expand=True)
        text = tk.Text(holder, bg=PANEL, fg=INK, font=FONT, wrap="word",
                       relief="flat", padx=12, pady=10, insertwidth=0)
        bar = ttk.Scrollbar(holder, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=bar.set)
        text.pack(side="left", fill="both", expand=True)
        bar.pack(side="left", fill="y")
        text.configure(state="disabled")
        return text

    @staticmethod
    def _set_text(widget, content):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def run(self):
        self.root.mainloop()


# ================================================================== 工具函数
def _short(value, head=8, tail=6):
    text = str(value or "—")
    if len(text) <= head + tail + 3:
        return text
    return "%s...%s" % (text[:head], text[-tail:])


def _fmt_time(ts):
    import time
    if not ts:
        return "—"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts)))
    except (ValueError, OSError, TypeError):
        return str(ts)


def _tx_summary(tx):
    data = tx.get("data") or {}
    tx_type = tx.get("type")
    if tx_type == "GENESIS":
        return "创世区块：%s" % (data.get("name") or "")
    if tx_type == "REGISTER":
        return "登记《%s》" % (data.get("title") or "")
    if tx_type == "TRANSFER":
        return "转让给 %s" % _short(data.get("to"))
    if tx_type == "LICENSE":
        return "%s授权给 %s" % (data.get("scope") or "", _short(data.get("to")))
    if tx_type == "DISPUTE":
        return "权属异议"
    if tx_type == "ADJUDICATE":
        return "%s异议" % (data.get("ruling") or "")
    if tx_type == "REVOKE":
        return "撤销登记"
    return ""


def main(ctx):
    """用给定的上下文启动桌面窗口。调用方负责异常提示。"""
    app = DesktopApp(ctx)
    app.run()
    return 0
