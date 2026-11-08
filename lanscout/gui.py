"""Tkinter 桌面界面。"""

from __future__ import annotations

import ctypes
import math
import os
import queue
import sys
import tempfile
import threading
import traceback
import webbrowser
from concurrent.futures import Future
from datetime import datetime
from pathlib import Path
from typing import Optional

import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, ttk

from . import APP_NAME, APP_NAME_EN, __version__
from .discovery import PORT_PROFILES
from .models import FreeIP, HostResult, ScanResult
from .netconfig import MAX_TARGET_HOSTS, get_default_interface, get_interfaces, parse_target
from .report import default_report_path, write_csv, write_html, write_json
from .scanner import ScanCancelled, ScanOptions, build_verify_advice, scan, verify_candidate

APP_BG = "#f2f5fa"
NAVY = "#0b1f3a"
NAVY_2 = "#12345c"
BLUE = "#1677ff"
BLUE_DARK = "#0f5fd7"
INK = "#172033"
MUTED = "#65758b"
LINE = "#e3e9f2"
WHITE = "#ffffff"
GREEN = "#0f9f6e"
AMBER = "#b45309"
RED = "#c2410c"

MODE_LABELS = {
    "quick": "快速",
    "standard": "标准（推荐）",
    "deep": "深度",
}
MODE_LABEL_TO_KEY = {v: k for k, v in MODE_LABELS.items()}


def _app_dir() -> Path:
    if getattr(sys, "frozen", False):  # pragma: no cover - PyInstaller 预留
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _set_dpi_awareness() -> None:
    if os.name != "nt":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _open_path(path: str | Path) -> None:
    p = str(path)
    try:
        if os.name == "nt":
            os.startfile(p)  # type: ignore[attr-defined]
        else:
            webbrowser.open(Path(p).as_uri())
    except Exception:
        pass


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} 秒"
    minutes = int(seconds // 60)
    remain = seconds - minutes * 60
    return f"{minutes} 分 {remain:.0f} 秒"


def _safe_report_path(result: ScanResult, suffix: str) -> Path:
    """生成报告路径；reports 目录不可写时回退到系统临时目录。"""
    try:
        return default_report_path(result, suffix, _app_dir() / "reports")
    except Exception:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return Path(tempfile.gettempdir()) / f"LAN-Scout-{stamp}.{suffix}"


class VerifyDialog(tk.Toplevel):
    def __init__(self, master: "LanScoutApp", ip: str, result: ScanResult):
        super().__init__(master)
        self.app = master
        self.ip = ip
        self.result = result
        self.title(f"配置前核验 · {ip}")
        self.configure(bg=WHITE)
        self.geometry("720x560")
        self.minsize(600, 440)
        self.transient(master)
        self._closed = False
        self.protocol("WM_DELETE_WINDOW", self._close)

        header = tk.Frame(self, bg=NAVY, height=64)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(
            header,
            text=f"配置前核验  ·  {ip}",
            bg=NAVY,
            fg="white",
            font=(master.font_family, 14, "bold"),
        ).pack(side=tk.LEFT, padx=20, pady=14)
        self.status = tk.Label(
            header, text="核验中…", bg=NAVY, fg="#b9d6ff", font=(master.font_family, 10)
        )
        self.status.pack(side=tk.RIGHT, padx=18)

        footer = tk.Frame(self, bg=WHITE)
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=18, pady=(0, 14))
        self.copy_btn = ttk.Button(
            footer, text="复制配置参数", style="Ghost.TButton", command=self._copy_config, state=tk.DISABLED
        )
        self.copy_btn.pack(side=tk.LEFT)
        ttk.Button(footer, text="关闭", style="Ghost.TButton", command=self._close).pack(side=tk.RIGHT)

        body = tk.Frame(self, bg=WHITE)
        body.pack(fill=tk.BOTH, expand=True, padx=18, pady=14)
        self.text = tk.Text(
            body,
            wrap=tk.WORD,
            bg="#fbfdff",
            fg=INK,
            relief=tk.FLAT,
            font=(master.font_family, 10),
            padx=14,
            pady=12,
            state=tk.DISABLED,
            highlightbackground=LINE,
            highlightthickness=1,
        )
        scroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        if result.context.direct_link:
            self._set_text(
                f"正在核验 {ip} 是否可以安全配置…\n\n"
                "将执行：多次 ICMP 探测、ARP 表查询、ARP 请求、常见 TCP 端口探测。\n"
                "如果地址确实未被使用，ARP 请求通常需要等待约 3~4 秒才有结果。\n\n"
                "请稍候，不要关闭窗口。"
            )
        else:
            self._set_text(
                f"正在核验 {ip}…\n\n"
                "目标不是本机直连网段，本次只能做 ICMP/TCP 三层探测，"
                "ARP 二层核验会被跳过。\n\n"
                "请稍候，不要关闭窗口。"
            )
        self.future: Future = Future()

        def worker() -> None:
            try:
                value = verify_candidate(ip, result)
                self.future.set_result(value)
            except Exception as exc:  # pragma: no cover - GUI 兜底
                self.future.set_exception(exc)

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, self._poll)

    def _set_text(self, value: str) -> None:
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", value)
        self.text.configure(state=tk.DISABLED)

    def _poll(self) -> None:
        if self._closed:
            return
        if not self.future.done():
            self.after(120, self._poll)
            return
        try:
            payload = self.future.result()
        except Exception as exc:
            self.status.configure(text="核验失败")
            self._set_text(f"核验时出错：{exc}\n\n请稍后再试。")
            return
        usage = payload.get("usage", {})
        config = payload.get("config", {})
        used = bool(usage.get("used"))
        cancelled = bool(usage.get("cancelled"))
        direct = bool(config.get("direct_link", True))
        l2_verified = bool(usage.get("l2_verified"))
        evidence = usage.get("evidence") or []
        lines: list[str] = []
        if used:
            self.status.configure(text="发现占用证据")
            lines.append(f"核验结果：发现 {self.ip} 有占用证据，请勿直接配置。")
            lines.append("")
            lines.append("证据：")
            lines.extend(f"  · {item}" for item in evidence)
            lines.append("")
            lines.append("建议：")
            lines.append("  1. 换一个候选 IP；")
            lines.append("  2. 如果这是你正在配置的设备，请先断开/改回 DHCP；")
            lines.append("  3. 登录 DHCP 服务器检查该地址是否已被保留或分配。")
        elif cancelled:
            self.status.configure(text="核验被中断")
            lines.append(f"核验未完成：{self.ip} 的探测被中断，不能据此判断可用。")
            lines.append("")
            lines.append("已获得的部分证据：")
            lines.extend(f"  · {item}" for item in evidence)
            lines.append("")
            lines.append("请重新执行核验，或登录 DHCP 服务器核对租约和保留。")
        elif not direct:
            self.status.configure(text="未完成二层核验")
            lines.append(f"核验未完成：目标 {self.ip} 不是本机直连网段。")
            lines.append("")
            lines.append("本工具只完成了 ICMP/TCP 三层探测，无法做 ARP 二层核验；")
            lines.append("这些结果不能用于本地静态配置决策。")
            lines.append("")
            lines.append("证据：")
            lines.extend(f"  · {item}" for item in evidence)
            lines.append("")
            lines.append("请以远端路由器/防火墙的 DHCP 租约、地址池和保留记录为准。")
        elif not l2_verified:
            self.status.configure(text="ARP 核验未完成")
            lines.append(f"核验未完成：{self.ip} 的 ARP 表查询失败，缺少二层证据。")
            lines.append("")
            lines.append("证据：")
            lines.extend(f"  · {item}" for item in evidence)
            lines.append("")
            lines.append("请不要据此配置静态 IP；修复 ARP 查询后重新扫描。")
        else:
            self.status.configure(text="未发现占用")
            lines.append(f"核验结果：本次核验仍未发现 {self.ip} 被占用。")
            lines.append("")
            lines.append("注意：这仍不等于 100% 空闲。设备可能休眠、关机，")
            lines.append("或 DHCP 服务器已经把该地址保留给其他设备。")
            lines.append("")
            lines.append("参考网络参数（IP 请自行确认后再填写）：")
            lines.append(f"  IP 地址：{config.get('ip', self.ip)}")
            lines.append(f"  子网掩码：{config.get('mask', '255.255.255.0')}")
            lines.append(f"  默认网关：{config.get('gateway') or '未识别'}")
            lines.append(f"  DNS：{'、'.join(config.get('dns') or []) or '未识别'}")
            lines.append(f"  DHCP 服务器：{config.get('dhcp_server') or '未识别'}")
            warnings = config.get("warnings") or []
            if warnings:
                lines.append("")
                lines.append("环境提醒：")
                lines.extend(f"  · {w}" for w in warnings)
            lines.append("")
            lines.append("更稳妥的做法：在 DHCP 服务器中为该设备 MAC 做地址保留，")
            lines.append("而不是直接把 IP 写死在设备里。")
        self._set_text("\n".join(lines))
        self.copy_btn.configure(state=tk.NORMAL)
        self._config_payload = payload

    def _copy_config(self) -> None:
        payload = getattr(self, "_config_payload", None)
        if not payload:
            return
        usage = payload.get("usage", {})
        config = payload.get("config", {})
        if usage.get("used"):
            result_text = "发现占用证据，请勿直接配置"
        elif usage.get("cancelled"):
            result_text = "核验被中断，未完成"
        elif not config.get("direct_link", True):
            result_text = "非直连网段，未完成二层核验"
        elif not usage.get("l2_verified"):
            result_text = "ARP 核验未完成"
        else:
            result_text = "未发现占用（非100%空闲）"
        lines = [
            f"核验结果：{result_text}",
            f"IP：{config.get('ip', self.ip)}",
            f"子网掩码：{config.get('mask', '')}",
            f"默认网关：{config.get('gateway', '')}",
            f"DNS：{'、'.join(config.get('dns') or [])}",
            f"DHCP 服务器：{config.get('dhcp_server', '')}",
        ]
        for e in usage.get("evidence") or []:
            lines.append(f"证据：{e}")
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.status.configure(text="配置参数已复制")

    def _close(self) -> None:
        self._closed = True
        self.destroy()


class LanScoutApp(tk.Tk):
    def __init__(self, auto_start: bool = False):
        super().__init__()
        self.title(f"{APP_NAME} · {APP_NAME_EN}")
        self.configure(bg=APP_BG)
        self.minsize(1080, 720)
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        width = min(1640, max(1080, screen_w - 160))
        height = min(920, max(720, screen_h - 140))
        self.geometry(f"{width}x{height}+{max(0, (screen_w - width) // 2)}+{max(0, (screen_h - height) // 2)}")

        self.interfaces = []
        self.iface_display: dict[str, object] = {}
        self.result: Optional[ScanResult] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.q: queue.Queue = queue.Queue()
        self.busy = False
        self.auto_start = auto_start
        self.last_report_path: Optional[Path] = None
        self._host_sort_col = "ip"
        self._host_sort_reverse = False
        self._selected_ip: Optional[str] = None
        self._host_items: dict[str, HostResult] = {}
        self._free_items: dict[str, FreeIP] = {}

        self.font_family = self._pick_font()
        self._configure_style()
        self._build_icon()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(80, self._load_interfaces_async)
        self.after(100, self._drain_queue)

    # ------------------------------------------------------------------ style
    def _pick_font(self) -> str:
        families = set(tkfont.families(self))
        for name in ("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", "Segoe UI"):
            if name in families:
                return name
        return "TkDefaultFont"

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=(self.font_family, 10), background=APP_BG, foreground=INK)
        style.configure("TFrame", background=APP_BG)
        style.configure("Card.TFrame", background=WHITE)
        style.configure("TLabel", background=APP_BG, foreground=INK, font=(self.font_family, 10))
        style.configure("Card.TLabel", background=WHITE, foreground=INK)
        style.configure("Muted.TLabel", background=WHITE, foreground=MUTED, font=(self.font_family, 9))
        style.configure("Header.TLabel", background=NAVY, foreground="white")
        style.configure(
            "Accent.TButton",
            background=BLUE,
            foreground="white",
            borderwidth=0,
            focusthickness=0,
            padding=(16, 9),
            font=(self.font_family, 10, "bold"),
        )
        style.map(
            "Accent.TButton",
            background=[("active", BLUE_DARK), ("disabled", "#9dbcf0")],
            foreground=[("disabled", "#edf4ff")],
        )
        style.configure(
            "Ghost.TButton",
            background="#f6f9fe",
            foreground=INK,
            borderwidth=1,
            relief=tk.FLAT,
            padding=(12, 8),
            font=(self.font_family, 9),
        )
        style.map(
            "Ghost.TButton",
            background=[("active", "#eaf2ff"), ("disabled", "#f5f7fa")],
            foreground=[("disabled", "#a2adbb")],
        )
        style.configure(
            "Small.TButton",
            background=WHITE,
            foreground=BLUE,
            borderwidth=0,
            padding=(6, 4),
            font=(self.font_family, 9),
        )
        style.map("Small.TButton", background=[("active", "#eef5ff")])
        style.configure(
            "TCombobox",
            fieldbackground=WHITE,
            background=WHITE,
            foreground=INK,
            padding=5,
            arrowsize=14,
        )
        style.map("TCombobox", fieldbackground=[("readonly", WHITE)])
        style.configure("TEntry", padding=6, fieldbackground=WHITE)
        style.configure(
            "Treeview",
            background=WHITE,
            fieldbackground=WHITE,
            foreground=INK,
            borderwidth=0,
            rowheight=32,
            font=(self.font_family, 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#f6f9fd",
            foreground="#43536a",
            relief=tk.FLAT,
            padding=(6, 8),
            font=(self.font_family, 9, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", "#e7f1ff")],
            foreground=[("selected", "#0d3d7a")],
        )
        style.map("Treeview.Heading", background=[("active", "#edf4ff")])
        style.configure(
            "TNotebook", background=WHITE, borderwidth=0, tabmargins=(0, 0, 0, 0)
        )
        style.configure(
            "TNotebook.Tab",
            background="#f4f7fb",
            foreground="#5b6b80",
            padding=(20, 10),
            font=(self.font_family, 9, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", WHITE)],
            foreground=[("selected", BLUE)],
        )
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor="#e9eff8",
            background=BLUE,
            borderwidth=0,
            thickness=8,
        )
        style.configure("TPanedwindow", background=APP_BG)

    def _build_icon(self) -> None:
        try:
            icon = tk.PhotoImage(width=32, height=32)
            icon.put(NAVY, to=(0, 0, 32, 32))
            # 简单雷达圆环
            for r in (12, 8):
                for deg in range(0, 360, 3):
                    rad = deg * math.pi / 180.0
                    x = int(16 + r * math.cos(rad))
                    y = int(16 + r * math.sin(rad))
                    if 0 <= x < 32 and 0 <= y < 32:
                        icon.put("#4c9aff", to=(x, y, x + 1, y + 1))
            icon.put("#59e0b0", to=(14, 14, 18, 18))
            self.iconphoto(True, icon)
            self._icon = icon
        except Exception:
            pass

    # --------------------------------------------------------------------- UI
    def _build_ui(self) -> None:
        self._build_header()
        self._build_footer()
        outer = tk.Frame(self, bg=APP_BG)
        outer.pack(fill=tk.BOTH, expand=True, padx=18, pady=(12, 6))
        self._build_toolbar(outer)
        self._build_stats(outer)
        self._build_main_area(outer)

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=NAVY)
        header.pack(fill=tk.X)
        left = tk.Frame(header, bg=NAVY)
        left.pack(side=tk.LEFT, padx=24, pady=(12, 14))
        tk.Label(
            left,
            text=f"{APP_NAME_EN}  ·  LAN INVENTORY",
            bg=NAVY,
            fg="#7fb4ee",
            font=(self.font_family, 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            left,
            text=APP_NAME,
            bg=NAVY,
            fg="white",
            font=(self.font_family, 20, "bold"),
        ).pack(anchor="w", pady=(1, 0))
        tk.Label(
            left,
            text="看清同一网段里谁在线、在做什么，以及哪些地址值得进一步核验",
            bg=NAVY,
            fg="#a9c4e5",
            font=(self.font_family, 9),
        ).pack(anchor="w")

        right = tk.Frame(header, bg=NAVY)
        right.pack(side=tk.RIGHT, padx=24, pady=16)
        tk.Label(
            right,
            text="仅限已授权网络",
            bg="#15365e",
            fg="#cfe2fb",
            font=(self.font_family, 9),
            padx=12,
            pady=5,
        ).pack(anchor="e")
        tk.Label(
            right,
            text="不登录 · 不猜口令 · 不做漏洞利用",
            bg=NAVY,
            fg="#7f9dbf",
            font=(self.font_family, 8),
        ).pack(anchor="e", pady=(6, 0))

    def _card(self, parent: tk.Misc) -> tuple[tk.Frame, tk.Frame]:
        card = tk.Frame(
            parent,
            bg=WHITE,
            highlightbackground=LINE,
            highlightthickness=1,
            bd=0,
        )
        inner = tk.Frame(card, bg=WHITE)
        inner.pack(fill=tk.BOTH, expand=True, padx=14, pady=12)
        return card, inner

    def _build_toolbar(self, parent: tk.Frame) -> None:
        card, inner = self._card(parent)
        card.pack(fill=tk.X)
        top = tk.Frame(inner, bg=WHITE)
        top.pack(fill=tk.X)

        tk.Label(top, text="本机网卡", bg=WHITE, fg=MUTED, font=(self.font_family, 9)).pack(
            side=tk.LEFT
        )
        self.iface_combo = ttk.Combobox(
            top, state="readonly", width=44, font=(self.font_family, 9)
        )
        self.iface_combo.pack(side=tk.LEFT, padx=(6, 6))
        self.iface_combo.bind("<<ComboboxSelected>>", self._on_interface_selected)
        self.refresh_btn = ttk.Button(
            top, text="刷新", style="Small.TButton", command=self._load_interfaces_async
        )
        self.refresh_btn.pack(side=tk.LEFT)

        tk.Label(top, text="目标网段", bg=WHITE, fg=MUTED, font=(self.font_family, 9)).pack(
            side=tk.LEFT, padx=(16, 4)
        )
        self.target_entry = ttk.Entry(top, width=20, font=("Consolas", 10))
        self.target_entry.pack(side=tk.LEFT)
        self.target_entry.insert(0, "192.168.1.0/24")
        tk.Label(top, text="模式", bg=WHITE, fg=MUTED, font=(self.font_family, 9)).pack(
            side=tk.LEFT, padx=(12, 4)
        )
        self.mode_combo = ttk.Combobox(
            top,
            state="readonly",
            width=12,
            values=list(MODE_LABELS.values()),
            font=(self.font_family, 9),
        )
        self.mode_combo.current(1)
        self.mode_combo.pack(side=tk.LEFT)
        self.mode_combo.bind("<<ComboboxSelected>>", lambda e: self._update_mode_hint())

        self.start_btn = ttk.Button(
            top, text="开始扫描", style="Accent.TButton", command=self.start_scan
        )
        self.start_btn.pack(side=tk.LEFT, padx=(16, 6))
        self.stop_btn = ttk.Button(
            top, text="停止", style="Ghost.TButton", command=self.stop_scan, state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT)

        bottom = tk.Frame(inner, bg=WHITE)
        bottom.pack(fill=tk.X, pady=(11, 0))
        self.progress = ttk.Progressbar(
            bottom, mode="determinate", maximum=100, style="Horizontal.TProgressbar"
        )
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.pct_label = tk.Label(
            bottom, text="0%", bg=WHITE, fg=BLUE, font=(self.font_family, 9, "bold"), width=5
        )
        self.pct_label.pack(side=tk.LEFT, padx=(8, 10))
        self.status_label = tk.Label(
            bottom,
            text="就绪，选择网段后开始扫描",
            bg=WHITE,
            fg=MUTED,
            font=(self.font_family, 9),
            anchor="w",
        )
        self.status_label.pack(side=tk.LEFT)
        hint_row = tk.Frame(inner, bg=WHITE)
        hint_row.pack(fill=tk.X, pady=(5, 0))
        self.mode_hint = tk.Label(
            hint_row,
            text="",
            bg=WHITE,
            fg="#8b98a8",
            font=(self.font_family, 8),
            anchor="w",
        )
        self.mode_hint.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.export_html_btn = ttk.Button(
            hint_row, text="导出 HTML", style="Ghost.TButton", command=self.export_html, state=tk.DISABLED
        )
        self.export_html_btn.pack(side=tk.RIGHT, padx=(4, 0))
        self.export_csv_btn = ttk.Button(
            hint_row, text="导出 CSV", style="Ghost.TButton", command=self.export_csv, state=tk.DISABLED
        )
        self.export_csv_btn.pack(side=tk.RIGHT, padx=(4, 0))
        self.open_report_btn = ttk.Button(
            hint_row, text="打开报告", style="Ghost.TButton", command=self.open_last_report, state=tk.DISABLED
        )
        self.open_report_btn.pack(side=tk.RIGHT, padx=(4, 0))
        self._update_mode_hint()

    def _build_stats(self, parent: tk.Frame) -> None:
        row = tk.Frame(parent, bg=APP_BG)
        row.pack(fill=tk.X, pady=(10, 0))
        self.stat_vars = {
            "target": tk.StringVar(value="—"),
            "used": tk.StringVar(value="0"),
            "free": tk.StringVar(value="0"),
            "duration": tk.StringVar(value="—"),
        }
        specs = [
            ("扫描范围", "target", "本次探测的 IPv4 地址范围", "#1677ff"),
            ("使用中", "used", "在线或疑似占用", "#0f9f6e"),
            ("未发现占用", "free", "候选地址，需按流程核验", "#d97706"),
            ("扫描耗时", "duration", "从 ping 到服务识别", "#7c3aed"),
        ]
        for i, (title, key, sub, accent) in enumerate(specs):
            card = tk.Frame(row, bg=WHITE, highlightbackground=LINE, highlightthickness=1)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            bar = tk.Frame(card, bg=accent, width=4)
            bar.pack(side=tk.LEFT, fill=tk.Y)
            body = tk.Frame(card, bg=WHITE)
            body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=14, pady=10)
            tk.Label(
                body, text=title, bg=WHITE, fg=MUTED, font=(self.font_family, 9)
            ).pack(anchor="w")
            tk.Label(
                body,
                textvariable=self.stat_vars[key],
                bg=WHITE,
                fg=INK,
                font=(self.font_family, 19 if key != "target" else 14, "bold"),
                anchor="w",
            ).pack(anchor="w", pady=(1, 0))
            tk.Label(
                body, text=sub, bg=WHITE, fg="#93a0b1", font=(self.font_family, 8), anchor="w"
            ).pack(anchor="w")
            row.grid_columnconfigure(i, weight=1)

        context = tk.Frame(parent, bg="#eaf1fb", highlightbackground="#dbe7f7", highlightthickness=1)
        context.pack(fill=tk.X, pady=(8, 0))
        self.context_label = tk.Label(
            context,
            text="正在读取本机网络配置…",
            bg="#eaf1fb",
            fg="#36567e",
            font=(self.font_family, 9),
            anchor="w",
            padx=12,
            pady=6,
        )
        self.context_label.pack(fill=tk.X)

    def _build_main_area(self, parent: tk.Frame) -> None:
        paned = tk.PanedWindow(
            parent,
            orient=tk.HORIZONTAL,
            bg=APP_BG,
            bd=0,
            sashwidth=8,
            sashrelief=tk.FLAT,
        )
        paned.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.paned = paned

        left = tk.Frame(paned, bg=WHITE, highlightbackground=LINE, highlightthickness=1)
        right = tk.Frame(paned, bg=WHITE, highlightbackground=LINE, highlightthickness=1)
        paned.add(left, minsize=620, stretch="always")
        paned.add(right, minsize=340, width=420, stretch="never")

        self._build_notebook(left)
        self._build_details(right)

    def _build_notebook(self, parent: tk.Frame) -> None:
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # 在线设备
        self.host_tab = tk.Frame(self.notebook, bg=WHITE)
        self.free_tab = tk.Frame(self.notebook, bg=WHITE)
        self.net_tab = tk.Frame(self.notebook, bg=WHITE)
        self.log_tab = tk.Frame(self.notebook, bg=WHITE)
        self.notebook.add(self.host_tab, text="在线设备")
        self.notebook.add(self.free_tab, text="未发现占用")
        self.notebook.add(self.net_tab, text="网络环境")
        self.notebook.add(self.log_tab, text="扫描日志")

        self._build_host_tab()
        self._build_free_tab()
        self._build_net_tab()
        self._build_log_tab()

    def _tree_scroll(self, parent: tk.Widget, columns: list[tuple[str, str, int]]) -> tuple[ttk.Treeview, ttk.Scrollbar, ttk.Scrollbar]:
        wrap = tk.Frame(parent, bg=WHITE)
        wrap.pack(fill=tk.BOTH, expand=True)
        tree = ttk.Treeview(wrap, columns=[c[0] for c in columns], show="headings", selectmode="browse")
        for key, title, width in columns:
            tree.heading(key, text=title)
            tree.column(key, width=width, minwidth=60, anchor=tk.W, stretch=False)
        yscroll = ttk.Scrollbar(wrap, orient=tk.VERTICAL, command=tree.yview)
        xscroll = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        wrap.grid_rowconfigure(0, weight=1)
        wrap.grid_columnconfigure(0, weight=1)
        return tree, yscroll, xscroll

    def _build_host_tab(self) -> None:
        bar = tk.Frame(self.host_tab, bg=WHITE)
        bar.pack(fill=tk.X, padx=12, pady=(10, 6))
        tk.Label(
            bar, text="在线 / 疑似占用设备", bg=WHITE, fg=INK, font=(self.font_family, 11, "bold")
        ).pack(side=tk.LEFT)
        self.host_count_label = tk.Label(
            bar, text="0 台", bg=WHITE, fg=MUTED, font=(self.font_family, 9)
        )
        self.host_count_label.pack(side=tk.LEFT, padx=(8, 0))
        tk.Label(bar, text="筛选", bg=WHITE, fg=MUTED, font=(self.font_family, 9)).pack(
            side=tk.RIGHT, padx=(0, 4)
        )
        self.host_search_var = tk.StringVar()
        search = ttk.Entry(bar, textvariable=self.host_search_var, width=18)
        search.pack(side=tk.RIGHT)
        self.host_search_var.trace_add("write", lambda *_: self._populate_hosts())

        columns = [
            ("ip", "IP 地址", 112),
            ("state", "状态", 78),
            ("kind", "设备类型", 150),
            ("hostname", "主机名", 150),
            ("mac", "MAC / 厂商", 230),
            ("services", "开放服务 / 在做什么", 300),
            ("latency", "响应", 78),
        ]
        self.host_tree, _, _ = self._tree_scroll(self.host_tab, columns)
        self.host_tree.tag_configure("local", background="#f1f8ff")
        self.host_tree.tag_configure("gateway", background="#f2fbf7")
        self.host_tree.tag_configure("warn", background="#fffaf0")
        self.host_tree.bind("<<TreeviewSelect>>", self._on_host_select)
        self.host_tree.bind("<Double-1>", self._on_host_double_click)
        self.host_tree.bind("<Button-3>", lambda e: self._show_context_menu(e, self.host_tree))
        for key, title, _ in columns:
            self.host_tree.heading(key, command=lambda k=key: self._sort_hosts(k))

        hint = tk.Label(
            self.host_tab,
            text="提示：点击列标题排序；右键可复制 IP；选择一行查看右侧详情。",
            bg=WHITE,
            fg="#93a0b1",
            font=(self.font_family, 8),
            anchor="w",
        )
        hint.pack(fill=tk.X, padx=14, pady=(4, 8))

    def _build_free_tab(self) -> None:
        top = tk.Frame(self.free_tab, bg=WHITE)
        top.pack(fill=tk.X, padx=12, pady=(10, 4))
        tk.Label(
            top, text="本次扫描未发现占用的地址", bg=WHITE, fg=INK, font=(self.font_family, 11, "bold")
        ).pack(side=tk.LEFT)
        self.free_count_label = tk.Label(
            top, text="0 个", bg=WHITE, fg=MUTED, font=(self.font_family, 9)
        )
        self.free_count_label.pack(side=tk.LEFT, padx=(8, 0))
        tk.Label(top, text="筛选", bg=WHITE, fg=MUTED, font=(self.font_family, 9)).pack(
            side=tk.RIGHT, padx=(0, 4)
        )
        self.free_search_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.free_search_var, width=18).pack(side=tk.RIGHT)
        self.free_search_var.trace_add("write", lambda *_: self._populate_free())

        note = tk.Label(
            self.free_tab,
            text="注意：未发现占用 ≠ 可以直接配置。选择 IP 后可做“配置前核验”，并查看安全配置建议。",
            bg="#fff7e8",
            fg="#8a5a12",
            font=(self.font_family, 9),
            anchor="w",
            padx=10,
            pady=6,
            wraplength=980,
            justify=tk.LEFT,
        )
        note.pack(fill=tk.X, padx=12, pady=(0, 6))

        columns = [
            ("ip", "IP 地址", 118),
            ("state", "扫描判断", 110),
            ("advice", "配置建议（简要）", 690),
        ]
        self.free_tree, _, _ = self._tree_scroll(self.free_tab, columns)
        self.free_tree.tag_configure("free", foreground="#126b4f")
        self.free_tree.tag_configure("risky", foreground="#9a5b00", background="#fffaf0")
        self.free_tree.bind("<<TreeviewSelect>>", self._on_free_select)
        self.free_tree.bind("<Button-3>", lambda e: self._show_context_menu(e, self.free_tree))
        for key, title, _ in columns:
            self.free_tree.heading(key, command=lambda k=key: self._sort_free(k))

        action = tk.Frame(self.free_tab, bg=WHITE)
        action.pack(fill=tk.X, padx=12, pady=6)
        self.verify_btn = ttk.Button(
            action, text="配置前核验选中 IP", style="Accent.TButton", command=self.verify_selected, state=tk.DISABLED
        )
        self.verify_btn.pack(side=tk.LEFT)
        ttk.Button(
            action, text="复制 IP", style="Ghost.TButton", command=self.copy_selected_free_ip
        ).pack(side=tk.LEFT, padx=6)
        ttk.Button(
            action, text="安全配置指引", style="Ghost.TButton", command=self.show_config_guide
        ).pack(side=tk.LEFT)
        self.free_hint = tk.Label(
            self.free_tab,
            text="建议：先在路由器 DHCP 中查看地址池与保留，优先做 MAC 地址保留。",
            bg=WHITE,
            fg=MUTED,
            font=(self.font_family, 8),
            anchor="w",
        )
        self.free_hint.pack(fill=tk.X, padx=14, pady=(0, 8))

    def _build_net_tab(self) -> None:
        body = tk.Frame(self.net_tab, bg=WHITE)
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)
        self.net_text = tk.Text(
            body,
            wrap=tk.WORD,
            bg="#fbfdff",
            fg=INK,
            relief=tk.FLAT,
            font=(self.font_family, 9),
            padx=12,
            pady=10,
            state=tk.DISABLED,
            highlightbackground=LINE,
            highlightthickness=1,
        )
        scroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.net_text.yview)
        self.net_text.configure(yscrollcommand=scroll.set)
        self.net_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._set_net_info(None)

    def _build_log_tab(self) -> None:
        body = tk.Frame(self.log_tab, bg=WHITE)
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)
        self.log_text = tk.Text(
            body,
            wrap=tk.WORD,
            bg="#0c1625",
            fg="#c9d8ea",
            insertbackground="white",
            relief=tk.FLAT,
            font=("Consolas", 9),
            padx=12,
            pady=10,
            state=tk.DISABLED,
        )
        scroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_details(self, parent: tk.Frame) -> None:
        head = tk.Frame(parent, bg=WHITE)
        head.pack(fill=tk.X, padx=16, pady=(14, 6))
        tk.Label(
            head, text="设备详情", bg=WHITE, fg=INK, font=(self.font_family, 11, "bold")
        ).pack(side=tk.LEFT)
        self.detail_badge = tk.Label(
            head, text="", bg=WHITE, fg=MUTED, font=(self.font_family, 9)
        )
        self.detail_badge.pack(side=tk.RIGHT)
        self.detail_text = tk.Text(
            parent,
            wrap=tk.WORD,
            width=42,
            bg="#fbfdff",
            fg=INK,
            relief=tk.FLAT,
            font=(self.font_family, 9),
            padx=14,
            pady=12,
            state=tk.DISABLED,
            highlightbackground=LINE,
            highlightthickness=1,
        )
        scroll = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=scroll.set)
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=(0, 12))
        scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=(0, 12), padx=(0, 10))
        self._set_detail_text(
            "扫描后选择左侧设备查看详情。\n\n"
            "本工具会整理：\n"
            "  · 设备类型与判断依据\n"
            "  · 主机名、MAC、厂商\n"
            "  · 开放端口与网页/服务指纹\n"
            "  · 发现证据与安全提示\n\n"
            "“未发现占用”的地址请在核验后再配置，不建议直接写死 IP。"
        )

    def _build_footer(self) -> None:
        footer = tk.Frame(self, bg=APP_BG)
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=22, pady=(4, 8))
        tk.Label(
            footer,
            text="仅扫描已获授权的网络 · 扫描结果不构成地址空闲证明",
            bg=APP_BG,
            fg="#8a98a9",
            font=(self.font_family, 8),
        ).pack(side=tk.LEFT)
        tk.Label(
            footer,
            text=f"{APP_NAME_EN} v{__version__} · Python 标准库",
            bg=APP_BG,
            fg="#8a98a9",
            font=(self.font_family, 8),
        ).pack(side=tk.RIGHT)

    def _update_mode_hint(self) -> None:
        mode = MODE_LABEL_TO_KEY.get(self.mode_combo.get(), "standard")
        info = PORT_PROFILES[mode]
        self.mode_hint.configure(
            text=f"{MODE_LABELS[mode]}模式：{info['description']}；会探测 {len(set(info['discovery']) | set(info['full']))} 个常见 TCP 端口。"
        )

    # --------------------------------------------------------------- utilities
    def _set_detail_text(self, value: str) -> None:
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", value)
        self.detail_text.configure(state=tk.DISABLED)

    def _set_net_text(self, value: str) -> None:
        self.net_text.configure(state=tk.NORMAL)
        self.net_text.delete("1.0", tk.END)
        self.net_text.insert("1.0", value)
        self.net_text.configure(state=tk.DISABLED)

    def _log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{stamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _set_status(self, message: str) -> None:
        self.status_label.configure(text=message)

    def _set_progress(self, pct: float, message: Optional[str] = None) -> None:
        self.progress["value"] = max(0, min(100, pct))
        self.pct_label.configure(text=f"{int(round(pct))}%")
        if message:
            self._set_status(message)

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        self.start_btn.configure(state=state)
        self.iface_combo.configure(state=tk.DISABLED if busy else "readonly")
        self.refresh_btn.configure(state=state)
        self.mode_combo.configure(state=tk.DISABLED if busy else "readonly")
        self.target_entry.configure(state=state)
        self.stop_btn.configure(state=tk.NORMAL if busy else tk.DISABLED)
        if busy:
            self.export_html_btn.configure(state=tk.DISABLED)
            self.export_csv_btn.configure(state=tk.DISABLED)
            self.open_report_btn.configure(state=tk.DISABLED)
        else:
            has_result = self.result is not None
            self.export_html_btn.configure(state=tk.NORMAL if has_result else tk.DISABLED)
            self.export_csv_btn.configure(state=tk.NORMAL if has_result else tk.DISABLED)
            self.open_report_btn.configure(
                state=tk.NORMAL if self.last_report_path and self.last_report_path.exists() else tk.DISABLED
            )

    def _context_text(self, result: Optional[ScanResult]) -> str:
        if result:
            c = result.context
            iface = c.interface
            interface_name = iface.alias if iface else "—"
            return (
                f"本机 {c.local_ip or '—'}（{interface_name}）   ·   "
                f"网关 {c.gateway or '未识别'}   ·   "
                f"DHCP {c.dhcp_server or '未识别'}   ·   "
                f"DNS {'、'.join(c.dns) or '未识别'}"
            )
        if not self.interfaces:
            return "正在读取本机网络配置…"
        iface = get_default_interface(self.interfaces)
        if iface:
            return (
                f"本机 {iface.ip}/{iface.prefix}（{iface.alias}）   ·   "
                f"网关 {iface.gateway or '未识别'}   ·   "
                f"DHCP {iface.dhcp_server or '未识别'}   ·   "
                f"DNS {'、'.join(iface.dns) or '未识别'}"
            )
        return "未识别到本机网卡，请手动输入目标网段。"

    # ---------------------------------------------------------- interface load
    def _load_interfaces_async(self) -> None:
        if self.busy:
            return
        self.refresh_btn.configure(state=tk.DISABLED)
        self.start_btn.configure(state=tk.DISABLED)
        self.status_label.configure(text="正在读取本机网卡信息…")

        def worker() -> None:
            try:
                items = get_interfaces()
            except Exception as exc:
                items = []
                self.q.put(("iface_error", str(exc)))
            self.q.put(("interfaces", items))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_interfaces(self, interfaces: list) -> None:
        self.interfaces = interfaces
        self.iface_display = {}
        values = []
        for iface in interfaces:
            display = iface.display_name
            # 防止同名显示项覆盖
            if display in self.iface_display:
                display = f"{display} #{iface.index}"
            self.iface_display[display] = iface
            values.append(display)
        self.iface_combo.configure(values=values)
        default = get_default_interface(interfaces)
        if default:
            for display, iface in self.iface_display.items():
                if iface is default:
                    self.iface_combo.current(values.index(display))
                    self.target_entry.delete(0, tk.END)
                    self.target_entry.insert(0, default.network_cidr)
                    break
            self.context_label.configure(text=self._context_text(None))
            self.stat_vars["target"].set(default.network_cidr)
            self._set_net_info(None)
            self.status_label.configure(text="就绪，选择网段后开始扫描")
            self.refresh_btn.configure(state=tk.NORMAL)
            self._log(
                f"已读取网卡：{default.alias} {default.network_cidr}，网关 {default.gateway or '未识别'}，"
                f"DHCP {default.dhcp_server or '未识别'}"
            )
            if self.auto_start and not self.busy:
                self.auto_start = False
                self.after(500, self.start_scan)
        else:
            self.refresh_btn.configure(state=tk.NORMAL)
            self.status_label.configure(text="未识别到可用网卡，请手动输入目标网段")
            self._log("未识别到可用 IPv4 网卡。")
        self._set_busy(False)

    def _on_interface_selected(self, _event: Optional[tk.Event] = None) -> None:
        iface = self.iface_display.get(self.iface_combo.get())
        if iface is None:
            return
        self.target_entry.configure(state=tk.NORMAL)
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, iface.network_cidr)
        self.context_label.configure(text=self._context_text(None))
        self._set_net_info(None)
        self._set_detail_text(
            f"已选择网卡：{iface.alias}\n\n"
            f"本机地址：{iface.ip}/{iface.prefix}\n"
            f"默认网关：{iface.gateway or '未识别'}\n"
            f"DHCP 服务器：{iface.dhcp_server or '未识别'}\n"
            f"DNS：{'、'.join(iface.dns) or '未识别'}\n\n"
            "点击“开始扫描”探测整个网段。"
        )

    def _set_net_info(self, result: Optional[ScanResult]) -> None:
        if result:
            c = result.context
            iface = c.interface
            lines = []
            lines.append("扫描上下文")
            lines.append("=" * 42)
            lines.append(f"目标范围：{result.target}")
            lines.append(f"扫描模式：{MODE_LABELS.get(result.mode, result.mode)}")
            lines.append(f"开始时间：{result.started_at}")
            lines.append(f"结束时间：{result.finished_at}")
            lines.append(f"扫描耗时：{_fmt_duration(result.duration_sec)}")
            lines.append(f"直连二层网络：{'是' if c.direct_link else '否'}")
            lines.append(f"探测 TCP 端口数：{result.ports_tested}")
            lines.append(f"可用地址数：{result.total_addresses}")
            lines.append(f"发现使用中：{result.used_count}")
            lines.append(f"未发现占用：{result.free_count}")
            lines.append("")
            lines.append("本机与网关")
            lines.append("=" * 42)
            if iface:
                lines.append(f"网卡：{iface.alias}")
                lines.append(f"描述：{iface.description}")
                lines.append(f"本机地址：{iface.ip}/{iface.prefix}")
                lines.append(f"MAC：{iface.mac or '—'}")
                lines.append(f"默认网关：{iface.gateway or '未识别'}")
                lines.append(f"DHCP 服务器：{iface.dhcp_server or '未识别'}")
                lines.append(f"DNS：{'、'.join(iface.dns) or '未识别'}")
                lines.append(f"网卡类型：{'虚拟' if iface.virtual else '物理'}")
            else:
                lines.append("未识别到匹配网卡。")
            lines.append("")
            lines.append("如何理解扫描结果")
            lines.append("=" * 42)
            lines.append("· 在线：ICMP、ARP 或 TCP 端口至少有一项响应。")
            lines.append("· 仅 ARP 记录：只有二层记录，可能休眠/离线/防火墙，按占用处理。")
            lines.append("· 未发现占用：本次扫描三项证据均未发现设备，但不是空闲证明。")
            lines.append("· 未探测 UDP 服务；设备休眠时无法发现。")
            if c.warnings:
                lines.append("")
                lines.append("环境提醒")
                lines.append("=" * 42)
                lines.extend(f"· {w}" for w in c.warnings)
            self._set_net_text("\n".join(lines))
            return

        if not self.interfaces:
            self._set_net_text("正在读取本机网络配置…")
            return
        iface = get_default_interface(self.interfaces)
        if not iface:
            self._set_net_text("未识别到可用 IPv4 网卡。")
            return
        lines = [
            "本机网络配置",
            "=" * 42,
            f"网卡：{iface.alias}",
            f"描述：{iface.description}",
            f"本机地址：{iface.ip}/{iface.prefix}",
            f"MAC：{iface.mac or '—'}",
            f"默认网关：{iface.gateway or '未识别'}",
            f"DHCP 服务器：{iface.dhcp_server or '未识别'}",
            f"DNS：{'、'.join(iface.dns) or '未识别'}",
            f"网卡类型：{'虚拟' if iface.virtual else '物理'}",
            "",
            "扫描前提示",
            "=" * 42,
            "· 扫描会向本网段发送 ICMP、ARP 和常见 TCP 连接请求。",
            "· 请只扫描你已获授权的网络。",
            "· 未发现占用的地址不能直接视为空闲，配置前请核对 DHCP 池与保留。",
        ]
        self._set_net_text("\n".join(lines))

    # ------------------------------------------------------------------- scan
    def _mode_key(self) -> str:
        return MODE_LABEL_TO_KEY.get(self.mode_combo.get(), "standard")

    def start_scan(self) -> None:
        if self.busy:
            return
        target_text = self.target_entry.get().strip()
        try:
            parsed = parse_target(target_text)
        except ValueError as exc:
            messagebox.showwarning("网段格式不正确", str(exc))
            return
        if parsed.count > MAX_TARGET_HOSTS:
            messagebox.showwarning(
                "范围过大",
                f"当前范围包含 {parsed.count} 个地址，超过上限 {MAX_TARGET_HOSTS}。\n"
                "请缩小到 /20 或更小的范围。",
            )
            return
        if parsed.count > 1024:
            if not messagebox.askyesno(
                "范围较大",
                f"当前范围包含 {parsed.count} 个地址，扫描会需要较长时间。\n是否继续？",
            ):
                return
        mode = self._mode_key()
        self.stop_event = threading.Event()
        self.result = None
        self._selected_ip = None
        self.last_report_path = None
        self.progress["value"] = 0
        self.pct_label.configure(text="0%")
        self._set_busy(True)
        self._clear_tables()
        self.stat_vars["target"].set(parsed.cidr)
        self.progress["value"] = 0
        self._set_status("正在启动扫描…")
        self._set_detail_text(
            f"正在扫描 {parsed.cidr}…\n\n"
            "扫描阶段：\n"
            "  1. 读取本机网络配置与 ARP 表\n"
            "  2. ICMP 探测整个网段\n"
            "  3. 常见 TCP 端口发现静默设备\n"
            "  4. 对已发现设备补扫服务\n"
            "  5. 识别主机名、网页、厂商并生成建议\n\n"
            "请稍候，扫描期间可以点击“停止”中断。"
        )
        self._log(f"开始扫描：{parsed.cidr}，模式 {MODE_LABELS[mode]}")
        options = ScanOptions(
            target=target_text,
            mode=mode,
            resolve_names=True,
            detect_services=True,
        )
        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(target_text, mode, options, list(self.interfaces) or None),
            daemon=True,
        )
        self.scan_thread.start()

    def _scan_worker(
        self, target_text: str, mode: str, options: ScanOptions, interfaces: list | None
    ) -> None:
        try:
            result = scan(
                target_text,
                mode,
                options=options,
                interfaces=interfaces,
                progress=lambda p, m: self.q.put(("progress", p, m)),
                log=lambda m: self.q.put(("log", m)),
                stop_event=self.stop_event,
            )
        except ScanCancelled:
            self.q.put(("cancelled",))
            return
        except Exception as exc:
            self.q.put(("error", str(exc), traceback.format_exc()))
            return
        report_path: Optional[Path] = None
        report_error = ""
        try:
            report_path = _safe_report_path(result, "html")
            write_html(result, report_path)
            try:
                write_json(result, report_path.with_suffix(".json"))
            except Exception:
                pass
        except Exception as exc:
            report_error = str(exc)
        self.q.put(("result", result, str(report_path) if report_path else "", report_error))

    def _free_summary_text(self, result: ScanResult) -> str:
        if not result.context.direct_link:
            return f"{result.free_count} 个地址未核验（非直连网段）"
        if any(f.state != "未发现占用" for f in result.free_ips):
            return f"{result.free_count} 个候选地址（二层核验未完成）"
        return f"{result.free_count} 个未发现占用"

    def _clear_tables(self) -> None:
        for item in self.host_tree.get_children():
            self.host_tree.delete(item)
        for item in self.free_tree.get_children():
            self.free_tree.delete(item)
        self._host_items = {}
        self._free_items = {}
        self.host_count_label.configure(text="0 台")
        self.free_count_label.configure(text="0 个")
        self.notebook.tab(self.host_tab, text="在线设备")
        self.notebook.tab(self.free_tab, text="未发现占用")
        for key in self.stat_vars:
            self.stat_vars[key].set("—" if key in ("target", "duration") else "0")
        self.verify_btn.configure(state=tk.DISABLED)
        self.detail_badge.configure(text="")

    def stop_scan(self) -> None:
        if not self.busy:
            return
        self.stop_event.set()
        self.stop_btn.configure(state=tk.DISABLED)
        self._set_status("正在停止扫描…")
        self._log("用户请求停止扫描。")

    def _drain_queue(self) -> None:
        try:
            while True:
                item = self.q.get_nowait()
                kind = item[0]
                if kind == "interfaces":
                    self._apply_interfaces(item[1])
                elif kind == "iface_error":
                    self._log(f"读取网卡失败：{item[1]}")
                elif kind == "progress":
                    _, pct, message = item
                    self._set_progress(pct, message)
                elif kind == "log":
                    self._log(item[1])
                elif kind == "result":
                    _, result, report_path, report_error = item
                    self._apply_result(result, report_path, report_error)
                elif kind == "cancelled":
                    self._on_cancelled()
                elif kind == "error":
                    self._on_scan_error(item[1], item[2])
        except queue.Empty:
            pass
        self.after(80, self._drain_queue)

    def _apply_result(self, result: ScanResult, report_path: str, report_error: str) -> None:
        self.result = result
        self._set_busy(False)
        self.progress["value"] = 100
        self.pct_label.configure(text="100%")
        free_summary = self._free_summary_text(result)
        self._set_status(f"扫描完成：{result.used_count} 台使用中，{free_summary}")
        self.stat_vars["target"].set(result.target)
        self.stat_vars["used"].set(str(result.used_count))
        self.stat_vars["free"].set(str(result.free_count))
        self.stat_vars["duration"].set(_fmt_duration(result.duration_sec))
        self.context_label.configure(text=self._context_text(result))
        self._populate_hosts()
        self._populate_free()
        self._set_net_info(result)
        self._set_detail_text(
            f"扫描完成：{result.target}\n\n"
            f"发现 {result.used_count} 台使用中设备，{free_summary}。\n"
            f"耗时 {_fmt_duration(result.duration_sec)}，探测了 {result.ports_tested} 个常见 TCP 端口。\n\n"
            "下一步：\n"
            "  · 在“在线设备”点击任意行查看“它是什么、在做什么”。\n"
            "  · 在“未发现占用”选择 IP，点击“配置前核验”。\n"
            "  · 配置前务必核对路由器的 DHCP 地址池和保留列表。\n\n"
            "未发现占用不等于 100% 空闲；设备休眠、防火墙或客户端隔离都可能造成漏检。"
        )
        self.detail_badge.configure(text="")
        self.export_html_btn.configure(state=tk.NORMAL)
        self.export_csv_btn.configure(state=tk.NORMAL)
        if report_path:
            self.last_report_path = Path(report_path)
            self.open_report_btn.configure(state=tk.NORMAL)
            self._log(f"HTML 报告已自动保存：{report_path}")
        if report_error:
            self._log(f"报告自动保存失败：{report_error}")
        if result.context.warnings:
            for warning in result.context.warnings:
                self._log(f"提示：{warning}")
        if result.errors:
            for error in result.errors:
                self._log(f"扫描异常：{error}")
        self._log(
            f"扫描完成：使用中 {result.used_count} 台；候选空闲 {result.free_count} 个；"
            f"耗时 {result.duration_sec:.1f} 秒"
        )

    def _on_cancelled(self) -> None:
        self._set_busy(False)
        self.progress["value"] = 0
        self.pct_label.configure(text="0%")
        self._set_status("扫描已停止")
        self._log("扫描已由用户停止。")
        self._set_detail_text("扫描已停止，没有生成完整结果。\n\n可以重新点击“开始扫描”。")

    def _on_scan_error(self, message: str, tb: str) -> None:
        self._set_busy(False)
        self._set_status("扫描失败")
        self.progress["value"] = 0
        self.pct_label.configure(text="0%")
        self._log(f"扫描失败：{message}")
        self._set_detail_text(f"扫描失败：\n\n{message}\n\n可以检查网段格式、网络连接后重试。")
        messagebox.showerror("扫描失败", message)

    # ------------------------------------------------------------- table fill
    def _sort_hosts(self, column: str) -> None:
        if self._host_sort_col == column:
            self._host_sort_reverse = not self._host_sort_reverse
        else:
            self._host_sort_col = column
            self._host_sort_reverse = column == "ip"
        self._populate_hosts()

    def _sort_free(self, column: str) -> None:
        self._populate_free()

    def _populate_hosts(self) -> None:
        if self.result is None:
            return
        for item in self.host_tree.get_children():
            self.host_tree.delete(item)
        query = self.host_search_var.get().strip().lower()
        hosts = list(self.result.hosts)
        key = self._host_sort_col
        if key == "ip":
            hosts.sort(key=lambda h: tuple(int(x) for x in h.ip.split(".")), reverse=self._host_sort_reverse)
        elif key == "latency":
            hosts.sort(key=lambda h: h.rtt_ms if h.rtt_ms is not None else 999999, reverse=self._host_sort_reverse)
        else:
            attr = {
                "state": "state",
                "kind": "device_type",
                "hostname": "hostname",
                "mac": "mac",
                "services": "service_summary",
            }.get(key, "ip")
            hosts.sort(key=lambda h: str(getattr(h, attr, "")).lower(), reverse=self._host_sort_reverse)
        count = 0
        self._host_items = {}
        for host in hosts:
            text = " ".join(
                [
                    host.ip,
                    host.state,
                    host.device_type,
                    host.hostname,
                    host.netbios,
                    host.mac,
                    host.vendor,
                    host.service_summary,
                ]
            ).lower()
            if query and query not in text:
                continue
            tag = []
            if host.is_local:
                tag.append("local")
            if host.is_gateway:
                tag.append("gateway")
            if host.state == "仅 ARP 记录":
                tag.append("warn")
            latency = "—"
            if host.ping_ok:
                latency = f"{host.rtt_ms:.0f} ms" if host.rtt_ms is not None else "应答"
            elif host.ports:
                latency = "端口响应"
            elif host.mac:
                latency = "仅 ARP"
            mac_vendor = host.mac or "—"
            if host.vendor:
                vendor_short = host.vendor[:14] + ("…" if len(host.vendor) > 14 else "")
                mac_vendor = f"{mac_vendor} · {vendor_short}"
            item = self.host_tree.insert(
                "",
                tk.END,
                values=(
                    host.ip,
                    host.state,
                    host.device_type,
                    host.hostname or host.netbios or host.http_title or "—",
                    mac_vendor,
                    host.service_summary or "—",
                    latency,
                ),
                tags=tuple(tag),
            )
            self._host_items[item] = host
            count += 1
        total = len(self.result.hosts)
        if query:
            self.host_count_label.configure(text=f"{count} / {total} 台")
        else:
            self.host_count_label.configure(text=f"{total} 台")
        self.notebook.tab(self.host_tab, text=f"在线设备 ({total})")

    def _populate_free(self) -> None:
        if self.result is None:
            return
        for item in self.free_tree.get_children():
            self.free_tree.delete(item)
        query = self.free_search_var.get().strip().lower()
        free_list = list(self.result.free_ips)
        free_list.sort(key=lambda f: tuple(int(x) for x in f.ip.split(".")))
        count = 0
        self._free_items = {}
        for free in free_list:
            if query and query not in free.ip and query not in free.advice.lower():
                continue
            short = free.advice
            if len(short) > 120:
                short = short[:117] + "…"
            tag = "free" if free.state == "未发现占用" else "risky"
            item = self.free_tree.insert(
                "",
                tk.END,
                values=(free.ip, free.state, short),
                tags=(tag,),
            )
            self._free_items[item] = free
            count += 1
        total = len(self.result.free_ips)
        self.free_count_label.configure(text=f"{count} / {total} 个" if query else f"{total} 个")
        all_verified = all(f.state == "未发现占用" for f in self.result.free_ips)
        tab_label = "未发现占用" if all_verified else "候选地址"
        self.notebook.tab(self.free_tab, text=f"{tab_label} ({total})")

    def _on_host_select(self, _event: Optional[tk.Event] = None) -> None:
        selected = self.host_tree.selection()
        if not selected:
            return
        host = self._host_items.get(selected[0])
        if not host:
            return
        self._selected_ip = host.ip
        self._show_host_detail(host)

    def _on_host_double_click(self, _event: Optional[tk.Event] = None) -> None:
        selected = self.host_tree.selection()
        if selected:
            host = self._host_items.get(selected[0])
            if host:
                self._show_host_detail(host)
                self._open_host_window(host)

    def _on_free_select(self, _event: Optional[tk.Event] = None) -> None:
        selected = self.free_tree.selection()
        self.verify_btn.configure(state=tk.NORMAL if selected else tk.DISABLED)
        if not selected:
            return
        free = self._free_items.get(selected[0])
        if not free:
            return
        self._selected_ip = free.ip
        self._show_free_detail(free)

    def _show_host_detail(self, host: HostResult) -> None:
        lines: list[str] = []
        lines.append(f"{host.ip}  ·  {host.device_type}")
        badge = f"{host.state} · 置信度 {host.confidence}"
        self.detail_badge.configure(text=badge)
        name = host.hostname or host.netbios or "主机名未识别"
        lines.append(f"{name}  ·  {host.vendor or '厂商未知'}")
        lines.append("")
        lines.append("基本信息")
        lines.append("─" * 32)
        lines.append(f"IP 地址    {host.ip}")
        lines.append(f"设备类型    {host.device_type}")
        if host.device_reason:
            lines.append(f"判断依据    {host.device_reason}")
        lines.append(f"主机名      {host.hostname or '—'}")
        if host.netbios and host.netbios != host.hostname:
            lines.append(f"NetBIOS     {host.netbios}")
        lines.append(f"MAC 地址    {host.mac or '—'}")
        lines.append(f"厂商        {host.vendor or '—'}")
        if host.ping_ok:
            lines.append(
                f"响应        {host.rtt_ms:.1f} ms" if host.rtt_ms is not None else "响应        有应答"
            )
            if host.ttl:
                lines.append(f"TTL         {host.ttl}")
        elif host.ports:
            lines.append("响应        仅 TCP 端口响应")
        elif host.mac:
            lines.append("响应        仅 ARP 记录")
        lines.append(f"系统推断    {host.os_guess or '—'}")
        if host.roles:
            lines.append(f"角色        {'、'.join(host.roles)}")
        lines.append("")
        lines.append("它开放了什么 / 在做什么")
        lines.append("─" * 32)
        if host.ports:
            for p in host.ports:
                line = f"{p.port:<5} {p.service}"
                if p.banner:
                    line += f"  「{p.banner[:100]}」"
                lines.append(line)
        else:
            lines.append("未发现开放 TCP 端口")
        if host.web_pages:
            lines.append("")
            lines.append("网页信息")
            for page in host.web_pages:
                if page.status or page.title or page.server:
                    lines.append(f"{page.url}  HTTP {page.status or '?'}")
                    if page.title:
                        lines.append(f"  标题：{page.title}")
                    if page.server:
                        lines.append(f"  Server：{page.server}")
                    if page.location:
                        lines.append(f"  跳转：{page.location}")
                    if page.cert_cn:
                        lines.append(f"  证书：{page.cert_cn}")
        if host.ssh_banner:
            lines.append(f"SSH Banner：{host.ssh_banner}")
        if host.ftp_banner:
            lines.append(f"FTP Banner：{host.ftp_banner}")
        if host.smtp_banner:
            lines.append(f"SMTP Banner：{host.smtp_banner}")
        lines.append("")
        lines.append("发现证据")
        lines.append("─" * 32)
        lines.extend(f"· {e}" for e in host.evidence)
        if host.notes:
            lines.append("")
            lines.append("安全提示")
            lines.append("─" * 32)
            lines.extend(f"· {n}" for n in host.notes)
        if host.service_summary:
            lines.append("")
            lines.append(f"服务摘要：{host.service_summary}")
        self._set_detail_text("\n".join(lines))

    def _open_host_window(self, host: HostResult) -> None:
        top = tk.Toplevel(self)
        top.title(f"{host.ip} · 设备详情")
        top.configure(bg=WHITE)
        top.geometry("760x640")
        top.transient(self)
        head = tk.Frame(top, bg=NAVY, height=58)
        head.pack(fill=tk.X)
        head.pack_propagate(False)
        tk.Label(
            head,
            text=f"{host.ip}  ·  {host.device_type}",
            bg=NAVY,
            fg="white",
            font=(self.font_family, 14, "bold"),
        ).pack(side=tk.LEFT, padx=18, pady=12)
        text = tk.Text(top, wrap=tk.WORD, bg="#fbfdff", fg=INK, relief=tk.FLAT,
                       font=(self.font_family, 10), padx=16, pady=12)
        scroll = ttk.Scrollbar(top, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(14, 0), pady=14)
        scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 14), pady=14)
        # 复用主面板内容生成纯文本
        old = self.detail_text.get("1.0", tk.END).strip()
        text.insert("1.0", old)
        text.configure(state=tk.DISABLED)
        top.bind("<Escape>", lambda e: top.destroy())

    def _show_free_detail(self, free: FreeIP) -> None:
        self.detail_badge.configure(text=free.state)
        if self.result:
            config = build_verify_advice(free.ip, self.result)
        else:
            config = {}
        if free.state == "未发现占用":
            next_step = "下一步：点击下方“配置前核验选中 IP”，做一次针对性的 ARP/端口核验。"
        else:
            next_step = (
                "下一步：当前结果未完成二层核验，不能作为静态配置依据；"
                "请先重新扫描或登录 DHCP 服务器核对。"
            )
        lines = [
            f"{free.ip}  ·  {free.state}",
            "",
            "扫描判断依据",
            "─" * 32,
            free.evidence,
            "",
            "配置建议",
            "─" * 32,
            free.advice,
            "",
            "风险提示",
            "─" * 32,
            free.risk,
            "",
            "参考网络参数",
            "─" * 32,
            f"子网掩码    {config.get('mask', '—')}",
            f"默认网关    {config.get('gateway') or '未识别'}",
            f"DNS        {'、'.join(config.get('dns') or []) or '未识别'}",
            f"DHCP 服务器 {config.get('dhcp_server') or '未识别'}",
            "",
            next_step,
        ]
        self._set_detail_text("\n".join(lines))

    def _show_context_menu(self, event: tk.Event, tree: ttk.Treeview) -> None:
        row = tree.identify_row(event.y)
        if not row:
            return
        tree.selection_set(row)
        menu = tk.Menu(self, tearoff=0, bg=WHITE, fg=INK, font=(self.font_family, 9))
        if tree is self.host_tree:
            host = self._host_items.get(row)
            if host:
                menu.add_command(label="复制 IP", command=lambda: self._copy_text(host.ip))
                menu.add_command(
                    label="查看完整详情",
                    command=lambda: (self._show_host_detail(host), self._open_host_window(host)),
                )
                menu.add_separator()
                menu.add_command(label="复制设备摘要", command=lambda: self._copy_text(self.detail_text.get("1.0", tk.END).strip()))
        else:
            free = self._free_items.get(row)
            if free:
                menu.add_command(label="复制 IP", command=lambda: self._copy_text(free.ip))
                menu.add_command(label="配置前核验", command=self.verify_selected)
                menu.add_command(
                    label="查看完整建议",
                    command=lambda: (self._show_free_detail(free), self.verify_btn.configure(state=tk.NORMAL)),
                )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_text(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

    # --------------------------------------------------------------- actions
    def copy_selected_free_ip(self) -> None:
        selected = self.free_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先在“未发现占用”列表中选择一个 IP。")
            return
        free = self._free_items.get(selected[0])
        if free:
            self._copy_text(free.ip)
            self._set_status(f"已复制 {free.ip}")

    def verify_selected(self) -> None:
        if self.result is None:
            return
        selected = self.free_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先在“未发现占用”列表中选择一个 IP。")
            return
        free = self._free_items.get(selected[0])
        if free:
            if not self.result.context.direct_link:
                if not messagebox.askyesno(
                    "非直连网段",
                    "目标不是本机直连网段，无法做 ARP 二层核验。\n"
                    "仍要执行 ICMP/TCP 三层探测吗？\n\n"
                    "结果不能作为本地静态配置的依据。",
                ):
                    return
            elif free.state != "未发现占用":
                if not messagebox.askyesno(
                    "二层核验未完成",
                    f"{free.ip} 的 ARP 核验未完成，当前只有三层探测证据。\n"
                    "仍要继续核验吗？",
                ):
                    return
            VerifyDialog(self, free.ip, self.result)

    def show_config_guide(self) -> None:
        top = tk.Toplevel(self)
        top.title("如何安全配置一个 IP")
        top.geometry("720x560")
        top.configure(bg=WHITE)
        top.transient(self)
        head = tk.Frame(top, bg=NAVY, height=58)
        head.pack(fill=tk.X)
        head.pack_propagate(False)
        tk.Label(
            head,
            text="如何安全配置一个 IP",
            bg=NAVY,
            fg="white",
            font=(self.font_family, 14, "bold"),
        ).pack(side=tk.LEFT, padx=18, pady=12)
        text = tk.Text(top, wrap=tk.WORD, bg="#fbfdff", fg=INK, relief=tk.FLAT,
                       font=(self.font_family, 10), padx=16, pady=14)
        scroll = ttk.Scrollbar(top, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(14, 0), pady=14)
        scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 14), pady=14)
        guide = (
            "扫描结果显示“未发现占用”只代表本次探测没有收到响应，\n"
            "不等于这个地址可以永久使用。\n\n"
            "推荐流程\n"
            "────────\n"
            "1. 登录 DHCP 服务器（通常是路由器）查看地址池范围。\n"
            "2. 查看当前租约列表和静态保留列表。\n"
            "3. 找到地址池外、没有保留记录的地址。\n"
            "4. 优先在 DHCP 中按设备 MAC 做“地址保留”，而不是直接写死。\n"
            "5. 配置完成后重新扫描，确认该地址稳定在线且无冲突。\n\n"
            "为什么不能直接配置？\n"
            "────────\n"
            "· DHCP 可能已经把该地址分配给了一台暂时关机/休眠的设备。\n"
            "· 其他管理员可能设置了静态保留，扫描器看不到。\n"
            "· 无线客户端隔离或防火墙可能让在线设备不响应探测。\n"
            "· 设备休眠时不会回应 ICMP/ARP，但唤醒后会占用地址。\n\n"
            "如果必须静态配置\n"
            "────────\n"
            "· 选择地址池之外、且已确认无保留的地址。\n"
            "· 使用与网关同网段的掩码、网关和 DNS。\n"
            "· 在资产表中记录 IP/MAC/设备位置。\n"
            "· 配置完成后用本工具再次扫描验证。\n\n"
            "安全提醒\n"
            "────────\n"
            "仅扫描你拥有或已获授权的网络。不要用本工具尝试登录设备、\n"
            "猜解口令或利用漏洞。"
        )
        text.insert("1.0", guide)
        text.configure(state=tk.DISABLED)
        top.bind("<Escape>", lambda e: top.destroy())

    def export_html(self) -> None:
        if self.result is None:
            messagebox.showinfo("提示", "请先完成一次扫描。")
            return
        try:
            initial = _safe_report_path(self.result, "html")
        except Exception as exc:
            messagebox.showerror("导出失败", f"无法准备报告目录：{exc}")
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="导出 HTML 报告",
            initialdir=str(initial.parent),
            initialfile=initial.name,
            defaultextension=".html",
            filetypes=[("HTML 报告", "*.html"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            target = write_html(self.result, path)
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        self._log(f"HTML 报告已导出：{target}")
        if messagebox.askyesno("导出成功", f"报告已保存：\n{target}\n\n是否立即打开？"):
            _open_path(target)

    def export_csv(self) -> None:
        if self.result is None:
            messagebox.showinfo("提示", "请先完成一次扫描。")
            return
        try:
            initial = _safe_report_path(self.result, "csv")
        except Exception as exc:
            messagebox.showerror("导出失败", f"无法准备报告目录：{exc}")
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="导出 CSV 结果",
            initialdir=str(initial.parent),
            initialfile=initial.name,
            defaultextension=".csv",
            filetypes=[("CSV 表格", "*.csv"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            target = write_csv(self.result, path)
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        self._log(f"CSV 已导出：{target}")
        messagebox.showinfo("导出成功", f"CSV 已保存：\n{target}\n\n可直接用 Excel 打开。")

    def open_last_report(self) -> None:
        if self.last_report_path and self.last_report_path.exists():
            _open_path(self.last_report_path)
        else:
            messagebox.showinfo("提示", "还没有可打开的报告，请先完成一次扫描。")

    # ------------------------------------------------------------------ close
    def _on_close(self) -> None:
        if self.busy:
            if not messagebox.askyesno("扫描进行中", "扫描仍在进行，确定要退出吗？\n退出会中断本次扫描。"):
                return
            self.stop_event.set()
        self.destroy()


def run_gui(auto_start: bool = False) -> None:
    _set_dpi_awareness()
    app = LanScoutApp(auto_start=auto_start)
    app.mainloop()


__all__ = ["LanScoutApp", "run_gui"]
