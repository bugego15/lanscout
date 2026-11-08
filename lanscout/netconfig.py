"""本机网络配置读取与扫描目标解析（仅使用 Python 标准库）。"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import locale
import os
import socket
import subprocess
import sys
import tempfile
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .models import InterfaceInfo

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
MAX_TARGET_HOSTS = 4096

_VIRTUAL_KEYWORDS = (
    "hyper-v",
    "vethernet",
    "wsl",
    "vmware",
    "virtualbox",
    "virtual",
    "bluetooth",
    "wi-fi direct",
    "loopback",
    "tailscale",
    "zerotier",
    "wireguard",
    "openvpn",
    "tap-windows",
    "npcap",
    "vpn",
    "tunnel",
    "docker",
)


def _decode_console(data: bytes) -> str:
    if not data:
        return ""
    for enc in (locale.getpreferredencoding(False), "utf-8", "gb18030"):
        try:
            return data.decode(enc, errors="replace")
        except Exception:
            continue
    return data.decode("utf-8", errors="replace")


def run_powershell_json(script: str, timeout: float = 25.0) -> Any:
    """执行一段 PowerShell 并把它写出的 UTF-8 JSON 读回 Python。

    使用临时文件而不是管道，避免 Windows 控制台代码页把中文网卡名弄乱。
    """
    if os.name != "nt":
        raise RuntimeError("PowerShell 网络信息读取仅支持 Windows")

    with tempfile.TemporaryDirectory(prefix="lanscout_") as td:
        out_path = Path(td) / "out.json"
        script_path = Path(td) / "query.ps1"
        # PowerShell 单引号字符串会原样保留反斜杠/单引号；使用正斜杠并转义单引号，
        # 避免用户名含 O'Brien 或路径含反斜杠时语法错误。
        ps_path = str(out_path).replace("\\", "/").replace("'", "''")
        script_text = script.replace("__OUT__", ps_path)
        # 使用带 BOM 的 UTF-8 写入 .ps1，兼容 Windows PowerShell 5.1。
        script_path.write_text(script_text, encoding="utf-8-sig")
        try:
            proc = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script_path),
                ],
                capture_output=True,
                timeout=timeout,
                creationflags=CREATE_NO_WINDOW,
            )
        except FileNotFoundError:
            raise RuntimeError("找不到 powershell.exe") from None

        if out_path.exists():
            raw = out_path.read_text(encoding="utf-8-sig", errors="replace").strip()
            if raw:
                return json.loads(raw)
        err = _decode_console(proc.stderr).strip()
        if err:
            raise RuntimeError(err[-800:])
        raise RuntimeError(f"PowerShell 查询失败（退出码 {proc.returncode}）")


_INTERFACE_PS = r"""
$ErrorActionPreference = 'Stop'
$aliases = @{}
Get-CimInstance Win32_NetworkAdapter | ForEach-Object {
    $aliases[[int]$_.InterfaceIndex] = $_
}
$dhcpState = @{}
try {
    Get-NetIPInterface -AddressFamily IPv4 | ForEach-Object {
        $dhcpState[[int]$_.InterfaceIndex] = [string]$_.Dhcp
    }
} catch { }

$out = New-Object System.Collections.ArrayList
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
    $ips = @($_.IPAddress)
    $masks = @($_.IPSubnet)
    for ($i = 0; $i -lt $ips.Count; $i++) {
        if ($ips[$i] -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { continue }
        if ($i -ge $masks.Count) { continue }
        $a = $aliases[[int]$_.InterfaceIndex]
        $gw = @($_.DefaultIPGateway | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }) | Select-Object -First 1
        $dns = @($_.DNSServerSearchOrder | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
        $alias = ''
        $netEnabled = $true
        $status = 0
        if ($null -ne $a) {
            $alias = [string]$a.NetConnectionID
            $netEnabled = [bool]$a.NetEnabled
            $status = [int]$a.NetConnectionStatus
        }
        $null = $out.Add([PSCustomObject]@{
            interface_index = [int]$_.InterfaceIndex
            alias = $alias
            description = [string]$_.Description
            ip = [string]$ips[$i]
            mask = [string]$masks[$i]
            gateway = [string]$gw
            dhcp_enabled = [bool]$_.DHCPEnabled
            dhcp_server = [string]$_.DHCPServer
            dns = $dns
            mac = [string]$_.MACAddress
            net_enabled = $netEnabled
            connection_status = $status
        })
    }
}
$json = $out | ConvertTo-Json -Depth 6 -Compress
if ($null -eq $json -or $json -eq '') { $json = '[]' }
[System.IO.File]::WriteAllText('__OUT__', $json, [System.Text.UTF8Encoding]::new($false))
"""


def _normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    cleaned = "".join(ch for ch in mac.upper() if ch.isalnum())
    if len(cleaned) != 12:
        return mac.strip().upper()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def _prefix_from_mask(mask: str) -> Optional[int]:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return None


def _looks_virtual(alias: str, description: str) -> bool:
    text = f"{alias} {description}".lower()
    return any(word in text for word in _VIRTUAL_KEYWORDS)


class _MIB_IPADDRROW(ctypes.Structure):
    _fields_ = [
        ("dwAddr", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("dwMask", wintypes.DWORD),
        ("dwBCastAddr", wintypes.DWORD),
        ("dwReasmSize", wintypes.DWORD),
        ("unused1", wintypes.USHORT),
        ("wType", wintypes.USHORT),
    ]


def _windows_ipv4_table() -> list[tuple[str, str, int, int]]:
    """直接通过 IP Helper API 读取 (IP, 掩码, 接口索引, 是否默认路由)。

    这是 PowerShell 不可用时的后备路径，避免把 WSL/Hyper-V 虚拟网卡
    误当成默认扫描目标。
    """
    if os.name != "nt":
        return []
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        iphlpapi.GetIpAddrTable.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.BOOL,
        ]
        iphlpapi.GetIpAddrTable.restype = wintypes.DWORD
        size = wintypes.ULONG(0)
        first = iphlpapi.GetIpAddrTable(None, ctypes.byref(size), False)
        if first not in (0, 122) or size.value <= 0:
            return []
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetIpAddrTable(buf, ctypes.byref(size), False)
        if ret != 0:
            return []
        num = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
        if num <= 0:
            return []
        rows = (_MIB_IPADDRROW * num).from_buffer(buf, ctypes.sizeof(wintypes.DWORD))
        best_index = -1
        try:
            iphlpapi.GetBestInterface.argtypes = [
                wintypes.ULONG,
                ctypes.POINTER(wintypes.ULONG),
            ]
            iphlpapi.GetBestInterface.restype = wintypes.DWORD
            dest = int.from_bytes(socket.inet_aton("8.8.8.8"), "little")
            best = wintypes.ULONG(0)
            if iphlpapi.GetBestInterface(dest, ctypes.byref(best)) == 0:
                best_index = int(best.value)
        except Exception:
            pass
        result: list[tuple[str, str, int, int]] = []
        for row in rows:
            if int(row.dwAddr) == 0:
                continue
            ip = socket.inet_ntoa(int(row.dwAddr).to_bytes(4, sys.byteorder))
            mask = socket.inet_ntoa(int(row.dwMask).to_bytes(4, sys.byteorder))
            if ip.startswith("127.") or ip.startswith("169.254."):
                continue
            result.append((ip, mask, int(row.dwIndex), int(row.dwIndex == best_index)))
        return result
    except Exception:
        return []


def _fallback_interfaces() -> list[InterfaceInfo]:
    """PowerShell 不可用时的最小后备：优先默认路由网卡，标记其余为虚拟/备用。"""
    found: dict[str, InterfaceInfo] = {}
    for ip, mask, index, is_default in _windows_ipv4_table():
        prefix = _prefix_from_mask(mask)
        if prefix is None:
            continue
        found[ip] = InterfaceInfo(
            index=index,
            alias="自动推断" if is_default else f"备用网卡 {index}",
            description="本机网卡（PowerShell 不可用，网关/DHCP/DNS 未知，请手动确认）",
            ip=ip,
            mask=mask,
            prefix=prefix,
            virtual=not bool(is_default),
        )
    if not found:
        try:
            infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        except Exception:
            infos = []
        for info in infos:
            ip = info[4][0]
            if ip.startswith("127.") or ip.startswith("169.254."):
                continue
            found[ip] = InterfaceInfo(
                index=0,
                alias="自动检测",
                description="本机网卡（PowerShell 不可用时推断，请手动确认）",
                ip=ip,
                mask="255.255.255.0",
                prefix=24,
                virtual=False,
            )
    return list(found.values())


def get_interfaces(force_fallback: bool = False) -> list[InterfaceInfo]:
    """读取本机所有已启用 IPv4 的网卡。物理网卡排在前面。"""
    if force_fallback or os.name != "nt":
        interfaces = _fallback_interfaces()
    else:
        try:
            raw = run_powershell_json(_INTERFACE_PS)
        except Exception:
            interfaces = _fallback_interfaces()
        else:
            if isinstance(raw, dict):
                raw = [raw]
            interfaces = []
            for item in raw or []:
                ip = str(item.get("ip") or "").strip()
                mask = str(item.get("mask") or "").strip()
                prefix = _prefix_from_mask(mask)
                if not ip or prefix is None:
                    continue
                if not item.get("net_enabled", True):
                    continue
                # NetConnectionStatus: 2 = 已连接，7 = 媒体断开。保留状态未知的项。
                status = int(item.get("connection_status") or 0)
                if status not in (0, 2):
                    continue
                alias = str(item.get("alias") or "").strip()
                description = str(item.get("description") or "").strip()
                dns_raw = item.get("dns") or []
                if isinstance(dns_raw, str):
                    dns_raw = [dns_raw]
                interfaces.append(
                    InterfaceInfo(
                        index=int(item.get("interface_index") or 0),
                        alias=alias or description or f"网卡 {item.get('interface_index')}",
                        description=description,
                        ip=ip,
                        mask=mask,
                        prefix=prefix,
                        gateway=str(item.get("gateway") or "").strip(),
                        dhcp_server=str(item.get("dhcp_server") or "").strip(),
                        dhcp_enabled=bool(item.get("dhcp_enabled")),
                        dns=[str(x) for x in dns_raw if str(x).strip()],
                        mac=_normalize_mac(str(item.get("mac") or "")),
                        virtual=_looks_virtual(alias, description),
                    )
                )
            if not interfaces:
                interfaces = _fallback_interfaces()

    # 去掉重复 IP，并按“物理 + 有网关”优先排序。
    unique: dict[str, InterfaceInfo] = {}
    for item in interfaces:
        unique.setdefault(item.ip, item)
    items = list(unique.values())
    items.sort(key=lambda i: (i.virtual, not bool(i.gateway), i.ip.count("."), i.ip))
    return items


def get_default_interface(interfaces: list[InterfaceInfo]) -> Optional[InterfaceInfo]:
    if not interfaces:
        return None
    physical = [i for i in interfaces if not i.virtual]
    for item in physical:
        if item.gateway:
            return item
    if physical:
        return physical[0]
    return interfaces[0]


@dataclass
class ParsedTarget:
    """用户输入解析后的目标范围。"""

    cidr: str
    hosts: list[str]
    reserved: list[str] = field(default_factory=list)
    network: Optional[ipaddress.IPv4Network] = None
    source: str = ""
    is_range: bool = False

    @property
    def count(self) -> int:
        return len(self.hosts)


def _expand_range(start_text: str, end_text: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    start_text = start_text.strip()
    end_text = end_text.strip()
    start = ipaddress.IPv4Address(start_text)
    if end_text.isdigit():
        parts = start_text.split(".")
        if len(parts) != 4:
            raise ValueError("范围结束地址不完整")
        end = ipaddress.IPv4Address(".".join(parts[:3] + [end_text]))
    else:
        end = ipaddress.IPv4Address(end_text)
    if int(end) < int(start):
        raise ValueError("范围结束地址不能小于开始地址")
    return start, end


def parse_target(text: str) -> ParsedTarget:
    """解析 CIDR、起止范围或单个 IP。

    支持：
        192.168.1.0/24
        192.168.1.10-192.168.1.50
        192.168.1.10-50
        192.168.1.10
    """
    raw = (text or "").strip().replace(" ", "")
    if not raw:
        raise ValueError("请输入目标网段，例如 192.168.1.0/24")

    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"网段格式不正确：{raw}") from exc
        if network.version != 4:
            raise ValueError("目前只支持 IPv4 网段")
        assert isinstance(network, ipaddress.IPv4Network)
        # 先根据前缀计算主机数，避免对 /8 这类大网段调用 hosts() 展开，
        # 在进入扫描参数校验之前就耗尽内存。
        host_count = (
            network.num_addresses - 2 if network.prefixlen <= 30 else network.num_addresses
        )
        if host_count > MAX_TARGET_HOSTS:
            raise ValueError(
                f"网段包含 {host_count} 个主机地址，超过上限 {MAX_TARGET_HOSTS}；"
                "请使用更小的网段或地址范围"
            )
        hosts = [str(ip) for ip in network.hosts()]
        reserved: list[str] = []
        if network.prefixlen <= 30:
            reserved = [str(network.network_address), str(network.broadcast_address)]
        return ParsedTarget(
            cidr=str(network),
            hosts=hosts,
            reserved=reserved,
            network=network,
            source=raw,
        )

    if "-" in raw:
        start_text, end_text = raw.split("-", 1)
        try:
            start, end = _expand_range(start_text, end_text)
        except ValueError as exc:
            raise ValueError(f"范围格式不正确：{raw}（示例：192.168.1.10-50）") from exc
        count = int(end) - int(start) + 1
        if count > MAX_TARGET_HOSTS:
            raise ValueError(
                f"范围包含 {count} 个地址，超过上限 {MAX_TARGET_HOSTS}；请缩小范围"
            )
        hosts = [str(ipaddress.IPv4Address(int(start) + i)) for i in range(count)]
        return ParsedTarget(
            cidr=f"{start}-{end}",
            hosts=hosts,
            source=raw,
            is_range=True,
        )

    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValueError(f"IP 地址格式不正确：{raw}") from exc
    if ip.version != 4:
        raise ValueError("目前只支持 IPv4 地址")
    return ParsedTarget(cidr=f"{ip}/32", hosts=[str(ip)], source=raw)


def find_matching_interface(
    target: ParsedTarget, interfaces: list[InterfaceInfo]
) -> Optional[InterfaceInfo]:
    """找到与目标范围最匹配的本机网卡（优先物理直连网卡）。"""
    if not interfaces:
        return None

    def contains(iface: InterfaceInfo, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(iface.cidr, strict=False)
        except Exception:
            return False

    candidates = [i for i in interfaces if contains(i, target.hosts[0])]
    if not candidates:
        # 范围跨多个网段时，按覆盖地址数排序。
        scored: list[tuple[int, InterfaceInfo]] = []
        for iface in interfaces:
            n = sum(1 for ip in target.hosts[:128] if contains(iface, ip))
            if n:
                scored.append((n, iface))
        scored.sort(key=lambda x: (not x[1].virtual, x[0]), reverse=True)
        return scored[0][1] if scored else get_default_interface(interfaces)

    candidates.sort(key=lambda i: (i.virtual, not bool(i.gateway)))
    return candidates[0]


def target_is_direct(target: ParsedTarget, iface: Optional[InterfaceInfo]) -> bool:
    if iface is None:
        return False
    try:
        iface_net = ipaddress.ip_network(iface.cidr, strict=False)
        if target.network is not None:
            return target.network.subnet_of(iface_net)  # type: ignore[arg-type]
        return all(ipaddress.ip_address(ip) in iface_net for ip in target.hosts)
    except Exception:
        return False


def filter_range_reserved(
    target: ParsedTarget, iface: Optional[InterfaceInfo]
) -> list[str]:
    """把范围里属于接口网络地址/广播地址的项移到 reserved。

    仅对“用户输入起止范围 + 本机直连网卡”生效。CIDR 分支已经在 parse_target
    中排除网络/广播地址。典型例子：目标 192.168.1.0-255 + /24 网卡时，
    .0 和 .255 不应作为“未发现占用”候选。
    """
    if not target.is_range or iface is None:
        return []
    try:
        network = ipaddress.ip_network(iface.cidr, strict=False)
        reserved_set = {network.network_address, network.broadcast_address}
    except Exception:
        return []
    reserved: list[str] = []
    kept: list[str] = []
    for ip in target.hosts:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            kept.append(ip)
            continue
        if addr in reserved_set:
            reserved.append(ip)
        else:
            kept.append(ip)
    if reserved:
        target.hosts = kept
        for ip in reserved:
            if ip not in target.reserved:
                target.reserved.append(ip)
    return sorted(reserved)


def describe_target(target: ParsedTarget) -> str:
    if target.is_range:
        return f"{target.cidr}（{target.count} 个地址）"
    if target.network is not None and target.network.prefixlen == 32:
        return f"{target.cidr}"
    return f"{target.cidr}（{target.count} 个可用地址）"


__all__ = [
    "MAX_TARGET_HOSTS",
    "ParsedTarget",
    "describe_target",
    "filter_range_reserved",
    "find_matching_interface",
    "get_default_interface",
    "get_interfaces",
    "parse_target",
    "run_powershell_json",
    "target_is_direct",
]
