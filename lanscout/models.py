"""数据模型。

这些对象只保存扫描结果，不依赖 Tkinter，便于 CLI / 单元测试 / 报告复用。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class InterfaceInfo:
    """本机的一块 IPv4 网卡。"""

    index: int
    alias: str
    description: str
    ip: str
    mask: str
    prefix: int
    gateway: str = ""
    dhcp_server: str = ""
    dhcp_enabled: bool = False
    dns: list[str] = field(default_factory=list)
    mac: str = ""
    virtual: bool = False

    @property
    def cidr(self) -> str:
        return f"{self.ip}/{self.prefix}"

    @property
    def network(self) -> str:
        # 由 ipaddress 计算，避免在模型里引入不必要的依赖。
        import ipaddress

        return str(ipaddress.ip_network(self.cidr, strict=False).network_address)

    @property
    def network_cidr(self) -> str:
        """网络地址形式，例如 192.168.1.0/24（而不是本机 192.168.1.50/24）。"""
        return f"{self.network}/{self.prefix}"

    @property
    def display_name(self) -> str:
        kind = "虚拟网卡" if self.virtual else "物理网卡"
        gateway = f" · 网关 {self.gateway}" if self.gateway else ""
        return f"{self.alias or self.description} · {self.cidr}（{kind}{gateway}）"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["cidr"] = self.cidr
        data["network"] = self.network
        data["display_name"] = self.display_name
        return data


@dataclass
class PortInfo:
    """一个开放 TCP 端口及其轻量指纹。"""

    port: int
    service: str = ""
    banner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WebPage:
    """一个响应了 HTTP(S) 的端口。"""

    port: int
    scheme: str
    url: str
    status: int = 0
    title: str = ""
    server: str = ""
    location: str = ""
    powered_by: str = ""
    cert_cn: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HostResult:
    """一台被发现/疑似在线的设备。"""

    ip: str
    state: str = "在线"  # 在线 / 仅 ARP 记录 / 端口响应
    mac: str = ""
    vendor: str = ""
    ping_ok: bool = False
    rtt_ms: Optional[float] = None
    ttl: Optional[int] = None
    arp_state: str = ""
    hostname: str = ""
    netbios: str = ""
    http_title: str = ""
    http_server: str = ""
    ssh_banner: str = ""
    ftp_banner: str = ""
    smtp_banner: str = ""
    ports: list[PortInfo] = field(default_factory=list)
    web_pages: list[WebPage] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    service_summary: str = ""
    device_type: str = "未知设备"
    device_reason: str = ""
    os_guess: str = ""
    roles: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    confidence: str = "中"
    is_local: bool = False
    is_gateway: bool = False
    is_dhcp: bool = False
    is_dns: bool = False

    @property
    def display_vendor(self) -> str:
        if self.vendor:
            return self.vendor
        if self.mac:
            return "厂商标识未知"
        return "—"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["display_vendor"] = self.display_vendor
        return data


@dataclass
class FreeIP:
    """本次扫描未发现占用的候选地址。"""

    ip: str
    state: str = "未发现占用"
    evidence: str = ""
    advice: str = ""
    risk: str = ""
    checked_ports: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkContext:
    """扫描时使用的网络上下文。"""

    interface: Optional[InterfaceInfo] = None
    target: str = ""
    local_ip: str = ""
    gateway: str = ""
    dhcp_server: str = ""
    dns: list[str] = field(default_factory=list)
    direct_link: bool = True
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface.to_dict() if self.interface else None,
            "target": self.target,
            "local_ip": self.local_ip,
            "gateway": self.gateway,
            "dhcp_server": self.dhcp_server,
            "dns": list(self.dns),
            "direct_link": self.direct_link,
            "warnings": list(self.warnings),
        }


@dataclass
class ScanResult:
    """一次完整扫描的结果。"""

    target: str
    mode: str = "standard"
    started_at: str = ""
    finished_at: str = ""
    duration_sec: float = 0.0
    total_addresses: int = 0
    scanned_addresses: int = 0
    hosts: list[HostResult] = field(default_factory=list)
    free_ips: list[FreeIP] = field(default_factory=list)
    reserved_ips: list[str] = field(default_factory=list)
    context: NetworkContext = field(default_factory=NetworkContext)
    ports_tested: int = 0
    tool_version: str = "1.0.0"
    errors: list[str] = field(default_factory=list)

    @property
    def used_count(self) -> int:
        return len(self.hosts)

    @property
    def free_count(self) -> int:
        return len(self.free_ips)

    def summary(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "used": self.used_count,
            "free": self.free_count,
            "total": self.total_addresses,
            "duration_sec": round(self.duration_sec, 2),
            "local_ip": self.context.local_ip,
            "gateway": self.context.gateway,
            "dhcp_server": self.context.dhcp_server,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": round(self.duration_sec, 2),
            "total_addresses": self.total_addresses,
            "scanned_addresses": self.scanned_addresses,
            "used_count": self.used_count,
            "free_count": self.free_count,
            "ports_tested": self.ports_tested,
            "tool_version": self.tool_version,
            "context": self.context.to_dict(),
            "hosts": [h.to_dict() for h in self.hosts],
            "free_ips": [f.to_dict() for f in self.free_ips],
            "reserved_ips": list(self.reserved_ips),
            "errors": list(self.errors),
        }
