"""扫描编排：网段发现 → 端口探测 → 服务识别 → 空闲候选与建议。"""

from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from . import __version__
from .discovery import (
    PORT_PROFILES,
    PingReply,
    ping_sweep,
    profile_for,
    read_arp_with_status,
    scan_tcp_ports,
    service_label,
    verify_ip_usage,
)
from .fingerprint import fingerprint_hosts
from .models import (
    FreeIP,
    HostResult,
    InterfaceInfo,
    NetworkContext,
    PortInfo,
    ScanResult,
)
from .netconfig import (
    MAX_TARGET_HOSTS,
    ParsedTarget,
    describe_target,
    filter_range_reserved,
    find_matching_interface,
    get_default_interface,
    get_interfaces,
    parse_target,
    target_is_direct,
)
from .oui import vendor_for_mac

ProgressCallback = Callable[[float, str], None]
LogCallback = Callable[[str], None]

DEFAULT_ADVICE = (
    "最稳妥的方式是在 DHCP 服务器里做“地址保留”（按 MAC 绑定），而不是直接把 IP 写死；"
    "如果必须静态配置，请先确认该地址不在地址池、租约和静态保留列表中。"
)
RISK_TEXT = (
    "设备休眠、防火墙拦截 ICMP、无线 AP 客户端隔离、非直连网段都可能导致漏检；"
    "本次“未发现占用”不等于 100% 空闲。"
)


class ScanCancelled(Exception):
    """用户主动停止扫描。"""


@dataclass
class ScanOptions:
    """扫描参数。"""

    target: str = ""
    mode: str = "standard"
    resolve_names: bool = True
    detect_services: bool = True
    ping_timeout_ms: int = 450
    port_timeout: float = 0.38
    max_hosts: int = MAX_TARGET_HOSTS
    concurrency: int = 280
    ping_workers: int = 96
    fingerprint_workers: int = 8


@dataclass
class ScanProgress:
    percent: float = 0.0
    message: str = "准备扫描"


def _now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ip_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def _check_stop(stop_event: Optional[threading.Event]) -> None:
    if stop_event is not None and stop_event.is_set():
        raise ScanCancelled("用户已停止扫描")


def _normalize_arp_kind(kind: str) -> str:
    text = (kind or "").strip()
    if text in ("动态", "dynamic"):
        return "动态"
    if text in ("静态", "static"):
        return "静态"
    if text in ("无效", "invalid"):
        return "无效"
    return text or "ARP"


def _get_or_create_host(hosts: dict[str, HostResult], ip: str) -> HostResult:
    host = hosts.get(ip)
    if host is None:
        host = HostResult(ip=ip)
        hosts[ip] = host
    return host


def _merge_arp(hosts: dict[str, HostResult], arp: dict, target_ips: set[str]) -> int:
    added = 0
    for ip, entry in arp.items():
        if ip not in target_ips:
            continue
        host = _get_or_create_host(hosts, ip)
        if not host.mac and entry.mac:
            host.mac = entry.mac
            added += 1
        if not host.arp_state:
            host.arp_state = _normalize_arp_kind(entry.kind)
    return added


def _portlist(open_ports: set[int]) -> list[PortInfo]:
    return [PortInfo(port=p, service=service_label(p)) for p in sorted(open_ports)]


def _build_context(
    target: ParsedTarget,
    interfaces: list[InterfaceInfo],
) -> tuple[NetworkContext, Optional[InterfaceInfo], list[str]]:
    iface = find_matching_interface(target, interfaces)
    direct = target_is_direct(target, iface)
    context = NetworkContext(
        interface=iface,
        target=target.cidr,
        local_ip=iface.ip if iface else "",
        gateway=iface.gateway if iface else "",
        dhcp_server=iface.dhcp_server if iface else "",
        dns=list(iface.dns) if iface else [],
        direct_link=direct,
    )
    warnings: list[str] = []
    if iface is None:
        warnings.append("未找到匹配的本机网卡，本机地址/网关信息可能不完整。")
    else:
        if "推断" in f"{iface.alias} {iface.description}":
            warnings.append(
                "本机网卡信息由后备方式推断（网关/DHCP/DNS 可能未知）；"
                "请确认目标网段后再开始扫描。"
            )
        if not direct:
            warnings.append(
                "目标网段不是本机直连的二层网段，ARP 探测无法覆盖；结果可能严重漏报。"
            )
        elif iface.virtual:
            warnings.append(
                "当前使用的是虚拟网卡，通常只能看到该虚拟网络内的设备。"
            )
    if target.count > 1024:
        warnings.append(f"目标包含 {target.count} 个地址，扫描可能较慢。")
    context.warnings = list(warnings)
    return context, iface, warnings


def _make_free_ip(
    ip: str,
    context: NetworkContext,
    checked_ports: int,
    direct_link: bool,
    arp_verified: bool,
) -> FreeIP:
    if not direct_link:
        state = "未核验（非直连网段）"
        evidence = (
            "目标不是本机直连的二层网段，ARP 二层核验无效；"
            f"仅完成 ICMP 与 {checked_ports} 个常见 TCP 端口的三层探测，均未发现响应。"
        )
        advice = (
            "该地址无法在本机完成二层核验，不能作为本地静态配置依据；"
            "请以远端路由器/防火墙的租约和地址保留记录为准。"
        )
    elif not arp_verified:
        state = "未发现占用（ARP 未核验）"
        evidence = (
            "ICMP 无应答；ARP 查询未成功，二层占用情况未知；"
            f"已探测 {checked_ports} 个常见 TCP 端口，均未开放。"
        )
        advice = (
            "本次 ARP 查询失败，缺少最关键的二层证据；"
            "请重新扫描或直接登录 DHCP 服务器核对，不要据此配置静态 IP。"
        )
    else:
        state = "未发现占用"
        evidence = (
            f"ICMP 无应答；ARP 无记录；已探测 {checked_ports} 个常见 TCP 端口均未开放。"
        )
        if context.dhcp_server:
            advice = (
                f"先登录 DHCP 服务器 {context.dhcp_server} 查看地址池、租约和静态保留；"
                "建议用 DHCP 保留（MAC 绑定）而不是直接写死。若确需静态，请选择地址池外且无保留的地址。"
            )
        else:
            advice = (
                "未识别到 DHCP 服务器；配置前请确认该地址不在 DHCP 地址池或静态保留列表中。"
                + DEFAULT_ADVICE
            )
    return FreeIP(
        ip=ip,
        state=state,
        evidence=evidence,
        advice=advice,
        risk=RISK_TEXT,
        checked_ports=checked_ports,
    )


def scan(
    target_text: str,
    mode: str = "standard",
    options: Optional[ScanOptions] = None,
    interfaces: Optional[list[InterfaceInfo]] = None,
    progress: Optional[ProgressCallback] = None,
    log: Optional[LogCallback] = None,
    stop_event: Optional[threading.Event] = None,
) -> ScanResult:
    """执行一次完整扫描。"""
    started_wall = time.time()
    started_at = _now_text()
    opts = options or ScanOptions(target=target_text, mode=mode)
    if target_text:
        opts.target = target_text
    if mode:
        opts.mode = mode
    mode = opts.mode if opts.mode in PORT_PROFILES else "standard"
    profile = profile_for(mode)
    discovery_ports: list[int] = list(profile["discovery"])  # type: ignore[arg-type]
    full_ports: list[int] = list(profile["full"])  # type: ignore[arg-type]
    all_ports = sorted(set(discovery_ports) | set(full_ports))
    progress = progress or (lambda p, m: None)
    log = log or (lambda m: None)

    def report(percent: float, message: str) -> None:
        progress(max(0.0, min(100.0, float(percent))), message)

    _check_stop(stop_event)
    report(0, "正在读取本机网络配置…")
    target = parse_target(opts.target)
    if target.count > opts.max_hosts:
        raise ValueError(
            f"目标包含 {target.count} 个地址，超过上限 {opts.max_hosts}；请缩小范围。"
        )
    log(f"目标：{describe_target(target)}；模式：{PORT_PROFILES[mode]['label']}")

    if interfaces:
        effective_interfaces = interfaces
    else:
        effective_interfaces = get_interfaces()
        if effective_interfaces:
            log("调用方未提供网卡信息，已重新读取本机网卡。")
    context, iface, warnings = _build_context(target, effective_interfaces)
    if iface:
        log(
            f"本机：{iface.ip}/{iface.prefix}（{iface.alias}）；"
            f"网关：{iface.gateway or '未识别'}；DHCP：{iface.dhcp_server or '未识别'}"
        )
    else:
        log("未能识别本机网卡，扫描将仅依据目标范围进行。")

    scan_errors: list[str] = []
    if target.is_range and context.direct_link:
        moved = filter_range_reserved(target, iface)
        if moved:
            log(f"范围包含接口网络/广播地址，已排除：{'、'.join(moved)}")
            warnings.append(f"已从候选地址中排除网络/广播地址：{'、'.join(moved)}")

    for warning in warnings:
        log(f"提示：{warning}")
    report(3, "正在读取系统 ARP 表…")

    target_ip_set = set(target.hosts)
    hosts: dict[str, HostResult] = {}
    arp_success_reads = 0
    arp_last_error = ""
    arp_failure_warned = False

    def refresh_arp(stage: str) -> dict:
        nonlocal arp_success_reads, arp_last_error, arp_failure_warned
        entries, error = read_arp_with_status()
        if error:
            arp_last_error = error
            scan_errors.append(f"{stage} ARP 查询失败：{error}")
            log(f"警告：{stage} ARP 查询失败：{error}")
            if not arp_failure_warned:
                arp_failure_warned = True
                msg = (
                    f"{stage} ARP 查询失败（{error}），二层占用证据可能缺失；"
                    "本次扫描的“未发现占用”可靠性下降。"
                )
                if msg not in context.warnings:
                    context.warnings.append(msg)
            return {}
        arp_success_reads += 1
        arp_last_error = ""
        return entries

    arp = refresh_arp("初始")
    arp_added = _merge_arp(hosts, arp, target_ip_set)
    if arp_added:
        log(f"系统 ARP 表：发现 {arp_added} 个目标地址记录")

    _check_stop(stop_event)
    report(5, "正在 ICMP 探测整个网段…")

    def ping_progress(done: int, total: int) -> None:
        pct = 5 + 13 * done / max(1, total)
        report(pct, f"ICMP 探测 {done}/{total}")

    replies: dict[str, PingReply] = ping_sweep(
        target.hosts,
        timeout_ms=opts.ping_timeout_ms,
        workers=opts.ping_workers,
        progress=ping_progress,
        stop_event=stop_event,
    )
    _check_stop(stop_event)
    ping_ok_count = sum(1 for reply in replies.values() if reply.ok)
    log(f"ICMP 探测完成：{ping_ok_count} 台有应答")
    icmp_errors = {
        str(reply.error)
        for reply in replies.values()
        if not reply.ok
        and reply.error
        and reply.error not in ("timeout", "no reply")
        and not str(reply.error).startswith("status=11010")
    }
    if icmp_errors:
        detail = "；".join(sorted(icmp_errors)[:3])
        scan_errors.append(f"ICMP 探测存在异常：{detail}")
        if ping_ok_count == 0:
            msg = (
                "ICMP 探测整体失败（" + detail + "），本次结果主要依赖 ARP 和 TCP 端口；"
                "请检查安全软件/系统权限后重试。"
            )
        else:
            msg = "部分 ICMP 探测异常（" + detail + "），可能有少量设备漏检。"
        context.warnings.append(msg)
        log(f"警告：{msg}")
    for ip, reply in replies.items():
        if reply.ok:
            host = _get_or_create_host(hosts, ip)
            host.ping_ok = True
            host.rtt_ms = reply.rtt_ms
            host.ttl = reply.ttl
            host.state = "在线"

    report(19, "正在刷新 ARP 表…")
    arp = refresh_arp("ICMP 后")
    _merge_arp(hosts, arp, target_ip_set)
    log(f"ICMP 后 ARP 表：{len([h for h in hosts.values() if h.mac])} 个目标地址有 MAC 记录")

    _check_stop(stop_event)
    report(20, "正在通过常见端口寻找静默设备…")
    open_ports: dict[str, set[int]] = {}

    def discovery_progress(done: int, total: int) -> None:
        pct = 20 + 33 * done / max(1, total)
        report(pct, f"端口探测 {done}/{total}")

    discovered = scan_tcp_ports(
        target.hosts,
        discovery_ports,
        timeout=opts.port_timeout,
        concurrency=opts.concurrency,
        progress=discovery_progress,
        stop_event=stop_event,
    )
    _check_stop(stop_event)
    for ip, ports in discovered.items():
        if ports:
            open_ports.setdefault(ip, set()).update(ports)
            _get_or_create_host(hosts, ip).state = "在线"
    log(f"端口发现：{len(open_ports)} 个地址开放了至少一个常见端口")

    report(54, "正在复核 ARP 表…")
    arp = refresh_arp("端口发现后")
    _merge_arp(hosts, arp, target_ip_set)
    _check_stop(stop_event)

    # 对已发现设备补扫更完整的端口；全段只扫 discovery 端口是为了速度。
    used_ips = sorted(hosts.keys(), key=_ip_key)
    remaining_ports = sorted(set(full_ports) - set(discovery_ports))
    if used_ips and remaining_ports:
        report(56, f"正在补扫 {len(used_ips)} 台设备的更多端口…")

        def full_progress(done: int, total: int) -> None:
            pct = 56 + 18 * done / max(1, total)
            report(pct, f"深度端口探测 {done}/{total}")

        extra = scan_tcp_ports(
            used_ips,
            remaining_ports,
            timeout=opts.port_timeout,
            concurrency=opts.concurrency,
            progress=full_progress,
            stop_event=stop_event,
        )
        for ip, ports in extra.items():
            if ports:
                open_ports.setdefault(ip, set()).update(ports)
                _get_or_create_host(hosts, ip).state = "在线"
    else:
        report(74, "端口探测完成")

    _check_stop(stop_event)
    report(74, "正在汇总设备状态…")
    arp = refresh_arp("汇总时")
    _merge_arp(hosts, arp, target_ip_set)
    arp_verified = arp_success_reads > 0 and not arp_last_error

    # 某些地址可能来自 DHCP 服务器或网关配置，即使没响应也不能算空闲。
    for special_ip, role in (
        (context.gateway, "gateway"),
        (context.dhcp_server, "dhcp"),
        (context.local_ip, "local"),
    ):
        if not special_ip or special_ip not in target_ip_set:
            continue
        host = _get_or_create_host(hosts, special_ip)
        if role == "gateway":
            host.is_gateway = True
        elif role == "dhcp":
            host.is_dhcp = True
        elif role == "local":
            host.is_local = True
    for dns_ip in context.dns:
        if dns_ip in target_ip_set:
            _get_or_create_host(hosts, dns_ip).is_dns = True
    if iface and iface.ip in target_ip_set:
        local_host = _get_or_create_host(hosts, iface.ip)
        local_host.is_local = True
        if not local_host.mac and iface.mac:
            local_host.mac = iface.mac
        if not local_host.vendor and iface.mac:
            local_host.vendor = vendor_for_mac(iface.mac)

    # 组装 host 对象。
    used_ips = sorted(hosts.keys(), key=_ip_key)
    for ip in used_ips:
        host = hosts[ip]
        ports = open_ports.get(ip, set())
        host.ports = _portlist(ports)
        if host.is_local and not host.ping_ok:
            # 本机通常总是能 ping 通；如果失败，仍标记为本机配置地址。
            host.state = "本机配置地址"
        elif host.ping_ok or ports:
            host.state = "在线"
        elif host.mac:
            host.state = "仅 ARP 记录"
        else:
            host.state = "配置地址"
        if host.mac and not host.vendor:
            host.vendor = vendor_for_mac(host.mac)

    online_hosts = [hosts[ip] for ip in used_ips]
    if online_hosts:
        report(75, f"正在识别 {len(online_hosts)} 台设备的服务与身份…")
        log(f"开始识别 {len(online_hosts)} 台设备的主机名/服务/网页信息")

        def fp_progress(done: int, total: int) -> None:
            pct = 75 + 18 * done / max(1, total)
            report(pct, f"服务识别 {done}/{total}")

        fingerprint_hosts(
            online_hosts,
            context,
            resolve_names=opts.resolve_names,
            detect_services=opts.detect_services,
            progress=fp_progress,
            stop_event=stop_event,
            max_workers=opts.fingerprint_workers,
        )
    _check_stop(stop_event)

    report(94, "正在整理空闲候选与配置建议…")
    checked_port_count = len(discovery_ports)
    free_ips: list[FreeIP] = []
    for ip in target.hosts:
        if ip in hosts:
            continue
        free_ips.append(
            _make_free_ip(
                ip,
                context,
                checked_port_count,
                context.direct_link,
                arp_verified,
            )
        )

    finished_at = _now_text()
    duration = time.time() - started_wall
    result = ScanResult(
        target=target.cidr,
        mode=mode,
        started_at=started_at,
        finished_at=finished_at,
        duration_sec=duration,
        total_addresses=len(target.hosts),
        scanned_addresses=len(target.hosts),
        hosts=online_hosts,
        free_ips=free_ips,
        reserved_ips=list(target.reserved),
        context=context,
        ports_tested=len(all_ports),
        tool_version=__version__,
        errors=scan_errors,
    )
    report(100, "扫描完成")
    log(
        f"扫描完成：发现 {result.used_count} 台设备，{result.free_count} 个未发现占用的候选地址，"
        f"用时 {duration:.1f} 秒"
    )
    return result


def scan_with_defaults(
    target_text: str = "",
    mode: str = "standard",
    progress: Optional[ProgressCallback] = None,
    log: Optional[LogCallback] = None,
    stop_event: Optional[threading.Event] = None,
) -> ScanResult:
    if not target_text:
        interface = get_default_interface(get_interfaces())
        if interface is None:
            raise ValueError("未能识别本机网段，请手动输入目标，例如 192.168.1.0/24")
        target_text = interface.network_cidr
    return scan(target_text, mode, progress=progress, log=log, stop_event=stop_event)


def build_verify_advice(ip: str, result: ScanResult) -> dict[str, object]:
    """为“配置前核验”生成网络参数模板与提醒。"""
    iface = result.context.interface
    try:
        iface_net = ipaddress.ip_network(iface.cidr, strict=False) if iface else None
    except Exception:
        iface_net = None
    known_ips = {h.ip for h in result.hosts} | {f.ip for f in result.free_ips}
    known_ips.update(result.reserved_ips)
    in_target = ip in known_ips
    warnings = list(result.context.warnings)
    if iface and iface_net and ipaddress.ip_address(ip) not in iface_net:
        warnings.append("该 IP 与本机网卡不在同一子网，若直接配置可能无法通过本机测试。")
    return {
        "ip": ip,
        "mask": iface.mask if iface else "255.255.255.0",
        "prefix": iface.prefix if iface else 24,
        "gateway": result.context.gateway,
        "dns": list(result.context.dns),
        "dhcp_server": result.context.dhcp_server,
        "in_target": in_target,
        "direct_link": result.context.direct_link,
        "warnings": warnings,
        "advice": DEFAULT_ADVICE,
    }


def verify_candidate(
    ip: str,
    result: ScanResult,
    stop_event: Optional[threading.Event] = None,
) -> dict[str, object]:
    """在用户准备静态配置某个地址前做一次更谨慎的核验。"""
    profile = profile_for(result.mode)
    ports = sorted(set(profile["discovery"]) | set(profile["full"]))  # type: ignore[arg-type]
    usage = verify_ip_usage(
        ip,
        ports,
        stop_event=stop_event,
        allow_arp=result.context.direct_link,
    )
    advice = build_verify_advice(ip, result)
    return {"usage": usage, "config": advice}


__all__ = [
    "DEFAULT_ADVICE",
    "RISK_TEXT",
    "ScanCancelled",
    "ScanOptions",
    "ScanProgress",
    "build_verify_advice",
    "scan",
    "scan_with_defaults",
    "verify_candidate",
]
