"""网络发现核心：ICMP、ARP、TCP 端口探测。

只做三件低侵入的事：
1. 发 ICMP Echo（普通 ping）；
2. 读系统 ARP 表 / 单地址 ARP 探测；
3. 对常见 TCP 端口做 connect 探测（不做漏洞利用、不发畸形包）。
"""

from __future__ import annotations

import asyncio
import ctypes
import locale
import os
import re
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# ---------------------------------------------------------------------------
# 端口与服务名称
# ---------------------------------------------------------------------------

SERVICE_LABELS: dict[int, str] = {
    21: "FTP 文件传输",
    22: "SSH 远程登录",
    23: "Telnet 远程登录",
    25: "SMTP 邮件服务",
    53: "DNS 域名服务",
    80: "HTTP Web 服务",
    81: "HTTP Web 服务",
    110: "POP3 邮件服务",
    111: "RPCbind",
    135: "Windows RPC",
    139: "NetBIOS / 文件共享",
    143: "IMAP 邮件服务",
    389: "LDAP 目录服务",
    443: "HTTPS Web 服务",
    445: "SMB 文件共享",
    502: "Modbus 工业控制",
    515: "LPD 打印服务",
    548: "AFP 文件共享",
    554: "RTSP 视频流",
    631: "IPP 打印服务",
    636: "LDAPS 目录服务",
    873: "rsync 文件同步",
    902: "VMware 管理",
    1433: "SQL Server 数据库",
    1521: "Oracle 数据库",
    1723: "PPTP VPN",
    1883: "MQTT 物联网",
    2049: "NFS 文件共享",
    2375: "Docker API（未加密）",
    2376: "Docker API（TLS）",
    3000: "Web 应用",
    3306: "MySQL 数据库",
    3389: "RDP 远程桌面",
    5000: "Web 应用 / UPnP",
    5060: "SIP 语音服务",
    5357: "WSD 设备发现",
    5432: "PostgreSQL 数据库",
    5900: "VNC 远程桌面",
    6379: "Redis 数据库",
    7000: "AirPlay 投屏",
    8000: "HTTP Web 服务",
    8006: "Proxmox 虚拟化管理",
    8080: "HTTP Web 服务",
    8081: "HTTP Web 服务",
    8443: "HTTPS Web 服务",
    8888: "HTTP Web 服务",
    9000: "Web 管理服务",
    9090: "Web 管理服务",
    9100: "RAW 打印服务",
    9200: "Elasticsearch",
    10000: "Webmin 管理",
    27017: "MongoDB 数据库",
    32400: "Plex 媒体服务器",
    62078: "iOS 同步服务",
}

HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8080, 8081, 8888, 9000, 9090, 10000}
HTTPS_PORTS = {443, 8006, 8443}
BANNER_PORTS = {21, 22, 23, 25, 110, 143}

# 每种模式分两阶段：
# discovery 会对整个网段扫描，用来发现“不响应 ping 但开了常见端口”的设备；
# full 只对已经确认使用的设备补扫，避免对全段做过多连接。
PORT_PROFILES: dict[str, dict[str, object]] = {
    "quick": {
        "label": "快速",
        "description": "约 10~20 秒；适合日常巡网",
        "discovery": [22, 80, 443, 445, 554, 631, 3389, 8000, 8080, 9100],
        "full": [
            21,
            22,
            23,
            53,
            80,
            135,
            139,
            443,
            445,
            515,
            554,
            631,
            3389,
            8080,
            8443,
            9100,
            32400,
        ],
    },
    "standard": {
        "label": "标准",
        "description": "约 20~40 秒；推荐使用，识别较完整",
        "discovery": [
            21,
            22,
            23,
            53,
            80,
            135,
            139,
            443,
            445,
            515,
            554,
            631,
            1433,
            1521,
            1883,
            2375,
            3306,
            3389,
            5000,
            5432,
            5900,
            6379,
            8000,
            8006,
            8080,
            8443,
            9100,
            27017,
            32400,
        ],
        "full": [
            21,
            22,
            23,
            25,
            53,
            80,
            81,
            110,
            135,
            139,
            143,
            443,
            445,
            515,
            548,
            554,
            631,
            873,
            902,
            1433,
            1521,
            1883,
            2049,
            2375,
            3000,
            3306,
            3389,
            5000,
            5060,
            5357,
            5432,
            5900,
            6379,
            7000,
            8000,
            8006,
            8080,
            8081,
            8443,
            8888,
            9000,
            9090,
            9100,
            9200,
            10000,
            27017,
            32400,
        ],
    },
    "deep": {
        "label": "深度",
        "description": "约 40~90 秒；更多端口与服务指纹",
        "discovery": [
            21,
            22,
            23,
            25,
            53,
            80,
            81,
            110,
            111,
            135,
            139,
            143,
            389,
            443,
            445,
            502,
            515,
            548,
            554,
            631,
            636,
            873,
            902,
            1433,
            1521,
            1723,
            1883,
            2049,
            2375,
            2376,
            3000,
            3128,
            3306,
            3389,
            5000,
            5060,
            5357,
            5432,
            5900,
            6379,
            7000,
            8000,
            8006,
            8080,
            8081,
            8443,
            8888,
            9000,
            9090,
            9100,
            9200,
            10000,
            27017,
            32400,
            62078,
        ],
        "full": [
            21,
            22,
            23,
            25,
            53,
            80,
            81,
            110,
            111,
            135,
            139,
            143,
            389,
            443,
            445,
            502,
            515,
            548,
            554,
            631,
            636,
            873,
            902,
            1433,
            1521,
            1723,
            1883,
            2049,
            2375,
            2376,
            3000,
            3128,
            3306,
            3389,
            5000,
            5060,
            5357,
            5432,
            5900,
            6379,
            7000,
            8000,
            8006,
            8080,
            8081,
            8443,
            8888,
            9000,
            9090,
            9100,
            9200,
            10000,
            27017,
            32400,
            62078,
        ],
    },
}


def profile_for(mode: str) -> dict[str, object]:
    return PORT_PROFILES.get(mode, PORT_PROFILES["standard"])


def service_label(port: int) -> str:
    return SERVICE_LABELS.get(port, f"TCP {port}")


# ---------------------------------------------------------------------------
# ICMP（Windows 原生 API，不需要管理员权限，也不需要启动 254 个 ping.exe）
# ---------------------------------------------------------------------------


@dataclass
class PingReply:
    ip: str
    ok: bool = False
    rtt_ms: Optional[float] = None
    ttl: Optional[int] = None
    error: str = ""


if os.name == "nt":
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

    class _IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Ttl", ctypes.c_ubyte),
            ("Tos", ctypes.c_ubyte),
            ("Flags", ctypes.c_ubyte),
            ("OptionsSize", ctypes.c_ubyte),
            ("OptionsData", ctypes.c_void_p),
        ]

    class _ICMP_ECHO_REPLY(ctypes.Structure):
        _fields_ = [
            ("Address", ctypes.c_uint32),
            ("Status", ctypes.c_ulong),
            ("RoundTripTime", ctypes.c_ulong),
            ("DataSize", ctypes.c_ushort),
            ("Reserved", ctypes.c_ushort),
            ("Data", ctypes.c_void_p),
            ("Options", _IP_OPTION_INFORMATION),
        ]

    _iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
    _iphlpapi.IcmpSendEcho.argtypes = [
        wintypes.HANDLE,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_ushort,
        ctypes.POINTER(_IP_OPTION_INFORMATION),
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _iphlpapi.IcmpSendEcho.restype = wintypes.DWORD
    _iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    _iphlpapi.IcmpCloseHandle.restype = wintypes.BOOL
    _iphlpapi.SendARP.argtypes = [
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _iphlpapi.SendARP.restype = wintypes.DWORD


def _ping_windows(ip: str, timeout_ms: int) -> PingReply:
    handle = None
    try:
        handle = _iphlpapi.IcmpCreateFile()  # type: ignore[name-defined]
        if not handle or handle == wintypes.HANDLE(-1).value:
            return PingReply(ip, error="IcmpCreateFile 失败")
        payload = b"LAN-SCOUT" * 4
        request = ctypes.create_string_buffer(payload)
        reply_size = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(payload) + 32  # type: ignore[name-defined]
        reply_buf = ctypes.create_string_buffer(reply_size)
        dest = int.from_bytes(socket.inet_aton(ip), "little")
        count = _iphlpapi.IcmpSendEcho(  # type: ignore[name-defined]
            handle,
            dest,
            request,
            len(payload),
            None,
            reply_buf,
            reply_size,
            max(50, int(timeout_ms)),
        )
        if count:
            reply = _ICMP_ECHO_REPLY.from_buffer(reply_buf)  # type: ignore[name-defined]
            if reply.Status == 0:
                return PingReply(
                    ip,
                    ok=True,
                    rtt_ms=float(reply.RoundTripTime),
                    ttl=int(reply.Options.Ttl) or None,
                )
            return PingReply(ip, error=f"status={reply.Status}")
        return PingReply(ip, error="timeout")
    except Exception as exc:  # pragma: no cover - 系统 API 异常兜底
        return PingReply(ip, error=str(exc))
    finally:
        if handle:
            try:
                _iphlpapi.IcmpCloseHandle(handle)  # type: ignore[name-defined]
            except Exception:
                pass


def _ping_command(ip: str, timeout_ms: int) -> PingReply:
    """非 Windows 环境的兜底实现。"""
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip],
            capture_output=True,
            timeout=max(1.0, timeout_ms / 1000 + 2),
        )
    except Exception as exc:
        return PingReply(ip, error=str(exc))
    text = proc.stdout.decode("utf-8", errors="replace")
    if proc.returncode == 0:
        m = re.search(r"time[=<]([\d.]+)\s*ms", text)
        ttl = re.search(r"ttl=(\d+)", text, re.I)
        return PingReply(
            ip,
            ok=True,
            rtt_ms=float(m.group(1)) if m else None,
            ttl=int(ttl.group(1)) if ttl else None,
        )
    return PingReply(ip, error="no reply")


def ping_once(ip: str, timeout_ms: int = 700) -> PingReply:
    if os.name == "nt":
        return _ping_windows(ip, timeout_ms)
    return _ping_command(ip, timeout_ms)


def ping_sweep(
    ips: list[str],
    timeout_ms: int = 450,
    workers: int = 96,
    progress: Optional[Callable[[int, int], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> dict[str, PingReply]:
    """并发 ping 整个网段。返回所有地址的应答（含失败）。"""
    replies: dict[str, PingReply] = {}
    if not ips:
        return replies
    total = len(ips)
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, min(workers, total))) as pool:
        futures = {pool.submit(ping_once, ip, timeout_ms): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                replies[ip] = fut.result()
            except Exception as exc:
                replies[ip] = PingReply(ip, error=str(exc))
            done += 1
            if progress and (done % 8 == 0 or done == total):
                progress(done, total)
            if stop_event and stop_event.is_set():
                for pending in futures:
                    pending.cancel()
                break
    return replies


# ---------------------------------------------------------------------------
# ARP
# ---------------------------------------------------------------------------


@dataclass
class ArpEntry:
    ip: str
    mac: str
    kind: str = "dynamic"


_ARP_LINE = re.compile(
    rb"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    rb"(?P<mac>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s+"
    rb"(?P<kind>\S+)"
)


def read_arp_with_status(timeout: float = 6.0) -> tuple[dict[str, ArpEntry], str]:
    """读取 Windows ARP 表，并返回 (记录, 错误信息)。

    真实的“没有记录”和“查询失败”必须区分，否则会把 ARP 被拦截/超时
    误当成“该地址未占用”。
    """
    entries: dict[str, ArpEntry] = {}
    if os.name != "nt":
        return entries, "当前系统不支持 Windows ARP 表读取"
    try:
        proc = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        return entries, "arp -a 执行超时"
    except Exception as exc:
        return entries, f"无法执行 arp -a：{exc}"
    if proc.returncode != 0:
        stderr = (proc.stderr or b"").decode(
            locale.getpreferredencoding(False), errors="replace"
        ).strip()
        return entries, f"arp -a 退出码 {proc.returncode}" + (f"：{stderr[-160:]}" if stderr else "")
    for m in _ARP_LINE.finditer(proc.stdout):
        ip = m.group("ip").decode("ascii", errors="ignore")
        mac = m.group("mac").decode("ascii", errors="ignore").upper()
        kind_raw = m.group("kind")
        try:
            kind = kind_raw.decode(locale.getpreferredencoding(False), errors="ignore")
        except Exception:
            kind = kind_raw.decode("utf-8", errors="ignore")
        if mac in ("00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF"):
            continue
        entries[ip] = ArpEntry(ip=ip, mac=mac, kind=kind)
    return entries, ""


def read_arp(timeout: float = 6.0) -> dict[str, ArpEntry]:
    """兼容旧调用：只返回 ARP 记录，失败时返回空字典。"""
    return read_arp_with_status(timeout)[0]


def send_arp(ip: str) -> Optional[str]:
    """向单个地址发一次 ARP 请求（Windows SendARP）。

    成功返回 MAC；无设备通常需要等待约 3~4 秒后返回 None。
    这是“配置前核验”最后一道 L2 证据，不用于全段扫描。
    """
    if os.name != "nt":
        return None
    try:
        dest = int.from_bytes(socket.inet_aton(ip), "little")
        mac_buf = (wintypes.ULONG * 2)()
        size = wintypes.ULONG(6)
        ret = _iphlpapi.SendARP(dest, 0, mac_buf, ctypes.byref(size))  # type: ignore[name-defined]
        if ret != 0 or size.value < 6:
            return None
        raw = bytes(mac_buf)[:6]
        return ":".join(f"{b:02X}" for b in raw)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# TCP 端口探测
# ---------------------------------------------------------------------------


async def _check_port(
    ip: str,
    port: int,
    timeout: float,
    sem: asyncio.Semaphore,
    stop_event: Optional[threading.Event],
) -> tuple[str, int, bool]:
    if stop_event is not None and stop_event.is_set():
        return ip, port, False
    async with sem:
        if stop_event is not None and stop_event.is_set():
            return ip, port, False
        writer = None
        try:
            reader, writer = await asyncio.wait_for(  # noqa: F841
                asyncio.open_connection(ip, port), timeout=timeout
            )
            return ip, port, True
        except (asyncio.TimeoutError, OSError, ConnectionError):
            return ip, port, False
        except Exception:
            return ip, port, False
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.15)
                except Exception:
                    pass


async def _scan_tcp_async(
    hosts: list[str],
    ports: list[int],
    timeout: float,
    concurrency: int,
    progress: Optional[Callable[[int, int], None]],
    stop_event: Optional[threading.Event],
) -> dict[str, set[int]]:
    result: dict[str, set[int]] = {ip: set() for ip in hosts}
    if not hosts or not ports:
        return result
    sem = asyncio.Semaphore(max(8, concurrency))
    total = len(hosts) * len(ports)
    attempted = 0
    # 分小批创建任务，避免 /22 之类的范围一次性生成几十万个 Task。
    batch_hosts = max(16, min(128, max(16, concurrency // max(1, len(ports)) * 2)))
    for start in range(0, len(hosts), batch_hosts):
        if stop_event is not None and stop_event.is_set():
            break
        batch = hosts[start : start + batch_hosts]
        tasks = [
            asyncio.create_task(_check_port(ip, port, timeout, sem, stop_event))
            for ip in batch
            for port in ports
        ]
        cancelled = False
        for fut in asyncio.as_completed(tasks):
            try:
                ip, port, is_open = await fut
            except Exception:
                attempted += 1
                continue
            attempted += 1
            if is_open:
                result[ip].add(port)
            if progress and (attempted % 40 == 0 or attempted == total):
                progress(attempted, total)
            if stop_event is not None and stop_event.is_set():
                cancelled = True
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                break
        if cancelled:
            break
    if progress:
        progress(attempted, total)
    return result


def scan_tcp_ports(
    hosts: Iterable[str],
    ports: Iterable[int],
    timeout: float = 0.38,
    concurrency: int = 280,
    progress: Optional[Callable[[int, int], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> dict[str, set[int]]:
    host_list = [str(h) for h in hosts]
    port_list = sorted({int(p) for p in ports if 0 < int(p) < 65536})
    if not host_list or not port_list:
        return {ip: set() for ip in host_list}

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # 常规路径：当前线程没有事件循环，直接运行；异常正常向上抛出。
        return asyncio.run(
            _scan_tcp_async(host_list, port_list, timeout, concurrency, progress, stop_event)
        )

    # 当前线程已有运行中的事件循环（例如被异步程序调用）：
    # 在独立线程里运行，并原样把异常传回调用方，绝不把失败伪装成“端口全关”。
    box: dict[str, dict[str, set[int]]] = {}
    errors: dict[str, BaseException] = {}

    def runner() -> None:
        try:
            box["v"] = asyncio.run(
                _scan_tcp_async(
                    host_list, port_list, timeout, concurrency, progress, stop_event
                )
            )
        except BaseException as exc:  # noqa: BLE001 - 需要跨线程原样传递
            errors["e"] = exc

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join()
    if errors:
        raise errors["e"]
    if "v" not in box:
        raise RuntimeError("端口扫描线程未返回结果")
    return box["v"]


def check_ports_blocking(
    ip: str, ports: Iterable[int], timeout: float = 0.4, concurrency: int = 120
) -> list[int]:
    found = scan_tcp_ports([ip], ports, timeout=timeout, concurrency=concurrency)
    return sorted(found.get(ip, set()))


# ---------------------------------------------------------------------------
# 配置前二次核验
# ---------------------------------------------------------------------------


def verify_ip_usage(
    ip: str,
    ports: Iterable[int],
    ping_attempts: int = 3,
    ping_timeout_ms: int = 600,
    stop_event: Optional[threading.Event] = None,
    allow_arp: bool = True,
) -> dict[str, object]:
    """对一个准备写死到设备上的 IP 做更谨慎的占用核验。

    包含：多次 ping、ARP 表、常见端口、SendARP（若仍无证据）。
    非直连网段（allow_arp=False）时只做三层探测，不伪造二层结论。
    返回结构供 GUI/报告直接展示。
    """
    evidence: list[str] = []
    open_ports: list[int] = []
    ping_ok = False
    rtt: Optional[float] = None
    ttl: Optional[int] = None
    cancelled = False
    arp_error = ""
    l2_verified = False
    port_list = sorted({int(p) for p in ports if 0 < int(p) < 65536})
    attempts = max(1, ping_attempts)

    if stop_event is not None and stop_event.is_set():
        cancelled = True
    for _ in range(attempts):
        if cancelled or (stop_event is not None and stop_event.is_set()):
            cancelled = True
            break
        reply = ping_once(ip, timeout_ms=ping_timeout_ms)
        if reply.ok:
            ping_ok = True
            rtt = reply.rtt_ms
            ttl = reply.ttl
            break
    if ping_ok:
        evidence.append(
            f"ICMP 有应答（{rtt if rtt is not None else '?'} ms"
            + (f"，TTL {ttl}" if ttl else "")
            + "）"
        )
    elif not cancelled:
        evidence.append(f"{attempts} 次 ICMP 探测均无应答")

    if not cancelled and (stop_event is None or not stop_event.is_set()):
        open_ports = check_ports_blocking(ip, port_list)
    elif stop_event is not None and stop_event.is_set():
        cancelled = True
    if open_ports:
        evidence.append(
            "开放 TCP 端口：" + "、".join(f"{p}/{service_label(p)}" for p in open_ports[:16])
        )
    elif not cancelled:
        evidence.append(f"{len(port_list)} 个常见 TCP 端口均未开放")

    arp = None
    if allow_arp and not cancelled:
        arp_entries, arp_error = read_arp_with_status()
        arp = arp_entries.get(ip)
        if arp_error:
            evidence.append(f"ARP 表查询失败：{arp_error}")
        elif arp:
            evidence.append(f"ARP 表存在记录：{arp.mac}")
        else:
            evidence.append("系统 ARP 表中无该地址记录")
        l2_verified = not bool(arp_error)
    elif not allow_arp:
        evidence.append("目标不是本机直连网段，已跳过 ARP 二层核验（结果仅供参考）")

    mac = arp.mac if arp else ""
    positive = bool(ping_ok or open_ports or arp)
    sendarp_done = False
    if (
        allow_arp
        and not positive
        and not arp_error
        and not cancelled
        and (stop_event is None or not stop_event.is_set())
    ):
        sendarp_done = True
        mac = send_arp(ip) or ""
        if mac:
            evidence.append(f"ARP 请求收到应答：{mac}")
    if sendarp_done and not mac:
        evidence.append("ARP 请求无应答（二层未发现设备）")

    if cancelled:
        evidence.append("核验被中断，未完成全部探测。")

    used = bool(ping_ok or open_ports or arp or mac)
    return {
        "ip": ip,
        "used": used,
        "cancelled": cancelled,
        "verified": not cancelled,
        "l2_verified": bool(l2_verified and not cancelled),
        "allow_arp": allow_arp,
        "evidence": evidence,
        "open_ports": open_ports,
        "ping_ok": ping_ok,
        "rtt_ms": rtt,
        "ttl": ttl,
        "mac": mac,
        "arp_error": arp_error,
    }


def ttl_to_os(ttl: Optional[int]) -> str:
    if ttl is None:
        return "未知"
    if ttl <= 32:
        return "嵌入式设备 / 早期系统"
    if ttl <= 64:
        return "Linux / Unix / 网络设备"
    if ttl <= 128:
        return "Windows"
    return "网络设备 / 其他"


__all__ = [
    "ArpEntry",
    "BANNER_PORTS",
    "HTTP_PORTS",
    "HTTPS_PORTS",
    "PORT_PROFILES",
    "PingReply",
    "check_ports_blocking",
    "ping_once",
    "ping_sweep",
    "profile_for",
    "read_arp",
    "read_arp_with_status",
    "scan_tcp_ports",
    "send_arp",
    "service_label",
    "ttl_to_os",
    "verify_ip_usage",
]
