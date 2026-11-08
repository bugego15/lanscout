#!/usr/bin/env python3
"""局域网 IP 侦探 / LAN Scout 启动入口。

默认启动图形界面；加 --cli 使用命令行。
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path

from lanscout import APP_NAME, APP_NAME_EN, __version__
from lanscout.discovery import PORT_PROFILES
from lanscout.netconfig import get_default_interface, get_interfaces, parse_target
from lanscout.report import default_report_path, write_csv, write_html, write_json
from lanscout.scanner import ScanCancelled, scan

APP_DIR = Path(__file__).resolve().parent


def list_interfaces() -> int:
    interfaces = get_interfaces()
    if not interfaces:
        print("未识别到可用的 IPv4 网卡。")
        return 1
    print(f"{APP_NAME} v{__version__} · 本机 IPv4 网卡\n")
    for iface in interfaces:
        print(f"- {iface.display_name}")
        print(f"    IP: {iface.ip}/{iface.prefix}  MAC: {iface.mac or '—'}")
        print(f"    网关: {iface.gateway or '未识别'}  DHCP: {iface.dhcp_server or '未识别'}")
        print(f"    DNS: {'、'.join(iface.dns) or '未识别'}")
    return 0


def _print_host_table(result) -> None:
    print("\n在线 / 疑似占用设备：")
    header = f"{'IP':<16} {'状态':<10} {'设备类型':<22} {'主机名':<18} 开放服务"
    print(header)
    print("-" * min(len(header) + 20, 120))
    for host in result.hosts:
        services = "、".join(str(p.port) for p in host.ports) or "—"
        print(
            f"{host.ip:<16} {host.state:<10} {host.device_type:<22} "
            f"{(host.hostname or host.netbios or '—'):<18} {services}"
        )
    if result.free_ips:
        preview = "、".join(f.ip for f in result.free_ips[:12])
        if len(result.free_ips) > 12:
            preview += f" …（共 {len(result.free_ips)} 个）"
        print(f"\n未发现占用的候选地址：{preview}")
        print("注意：未发现占用 ≠ 可直接配置；请核对 DHCP 地址池和保留列表。")
    if result.context.warnings:
        print("\n环境提醒：")
        for warning in result.context.warnings:
            print(f"- {warning}")


def run_cli(args: argparse.Namespace) -> int:
    if args.list_interfaces:
        return list_interfaces()

    target = args.target
    if not target:
        interface = get_default_interface(get_interfaces())
        if not interface:
            print("未识别到本机网段，请用 --target 指定，例如 192.168.1.0/24", file=sys.stderr)
            return 2
        target = interface.network_cidr
        print(f"未指定 --target，自动使用本机网段：{target}")

    mode = args.mode
    if mode not in PORT_PROFILES:
        print(f"未知扫描模式：{mode}", file=sys.stderr)
        return 2
    try:
        parse_target(target)
    except ValueError as exc:
        print(f"参数错误：{exc}", file=sys.stderr)
        return 2

    stop_event = threading.Event()

    def handle_sigint(_signum, _frame):
        print("\n收到中断，正在停止扫描…", file=sys.stderr)
        stop_event.set()

    try:
        signal.signal(signal.SIGINT, handle_sigint)
    except Exception:
        pass

    last_bucket = {"value": -1}

    def on_progress(percent: float, message: str) -> None:
        bucket = int(percent // 10) * 10
        if bucket != last_bucket["value"]:
            last_bucket["value"] = bucket
            print(f"[{int(percent):3d}%] {message}", flush=True)

    def on_log(message: str) -> None:
        if args.verbose:
            print(f"  · {message}", flush=True)

    print(f"{APP_NAME_EN} v{__version__} · 正在扫描 {target}（{PORT_PROFILES[mode]['label']}模式）")
    try:
        result = scan(
            target,
            mode,
            progress=on_progress,
            log=on_log,
            stop_event=stop_event,
        )
    except ScanCancelled:
        print("扫描已停止。", file=sys.stderr)
        return 130
    except ValueError as exc:
        print(f"参数错误：{exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"扫描失败：{exc}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    print(
        f"\n扫描完成：使用中 {result.used_count} 台，未发现占用 {result.free_count} 个，"
        f"用时 {result.duration_sec:.1f} 秒。"
    )
    print(
        f"本机 {result.context.local_ip or '—'} · 网关 {result.context.gateway or '未识别'} · "
        f"DHCP {result.context.dhcp_server or '未识别'} · "
        f"DNS {'、'.join(result.context.dns) or '未识别'}"
    )
    _print_host_table(result)

    report_paths: list[Path] = []
    if args.html or not (args.csv or args.json):
        path = Path(args.html) if args.html else default_report_path(result, "html", APP_DIR / "reports")
        report_paths.append(write_html(result, path))
    if args.csv:
        report_paths.append(write_csv(result, args.csv))
    if args.json:
        report_paths.append(write_json(result, args.json))
    if report_paths:
        print("\n报告文件：")
        for path in report_paths:
            print(f"- {path}")
    print("\n安全提醒：只扫描你已获授权的网络；未发现占用的地址不等于 100% 空闲。")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lan_scout",
        description=f"{APP_NAME} / {APP_NAME_EN}：发现同网段在线 IP、识别设备在做什么，并评估候选空闲地址。",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} v{__version__}")
    parser.add_argument("--cli", action="store_true", help="使用命令行模式（默认启动图形界面）")
    parser.add_argument("--list-interfaces", action="store_true", help="列出本机 IPv4 网卡后退出")
    parser.add_argument("--target", "-t", help="目标网段/范围，例如 192.168.1.0/24 或 192.168.1.10-50")
    parser.add_argument(
        "--mode",
        "-m",
        default="standard",
        choices=["quick", "standard", "deep"],
        help="扫描模式：quick / standard / deep（默认 standard）",
    )
    parser.add_argument("--html", help="HTML 报告输出路径（默认自动生成到 reports/）")
    parser.add_argument("--csv", help="CSV 输出路径")
    parser.add_argument("--json", help="JSON 输出路径")
    parser.add_argument("--verbose", "-v", action="store_true", help="输出详细扫描日志")
    parser.add_argument("--autostart", action="store_true", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cli or args.list_interfaces or args.html or args.csv or args.json:
        return run_cli(args)
    try:
        from lanscout.gui import run_gui

        run_gui(auto_start=args.autostart)
    except Exception as exc:
        import ctypes
        import traceback

        detail = traceback.format_exc()
        log_path = APP_DIR / "lan_scout_error.log"
        try:
            log_path.write_text(detail, encoding="utf-8")
        except Exception:
            pass
        message = (
            f"图形界面启动失败：{exc}\n\n"
            f"错误日志：{log_path}\n\n"
            "可以改用命令行：\n"
            "python lan_scout.py --cli --target 192.168.1.0/24"
        )
        try:
            ctypes.windll.user32.MessageBoxW(0, message, "LAN Scout 启动失败", 0x10)
        except Exception:
            pass
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
