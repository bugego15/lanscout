"""在线设备的轻量服务识别与设备画像。

原则：只做普通访问（HTTP GET 首页、读取服务 banner、DNS PTR、NetBIOS 名称），
不尝试登录、不猜测口令、不利用漏洞。
"""

from __future__ import annotations

import html
import http.client
import locale
import os
import platform
import random
import re
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, Optional

from .discovery import (
    BANNER_PORTS,
    HTTP_PORTS,
    HTTPS_PORTS,
    SERVICE_LABELS,
    service_label,
    ttl_to_os,
)
from .models import HostResult, NetworkContext, PortInfo, WebPage
from .oui import is_locally_administered, vendor_for_mac

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
MAX_HTTP_BODY = 220_000

_SHORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    81: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    502: "Modbus",
    515: "LPD",
    548: "AFP",
    554: "RTSP",
    631: "IPP",
    1433: "SQL Server",
    1521: "Oracle",
    1883: "MQTT",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker",
    3000: "Web",
    3306: "MySQL",
    3389: "RDP",
    5000: "Web",
    5060: "SIP",
    5357: "WSD",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    7000: "AirPlay",
    8000: "HTTP",
    8006: "Proxmox",
    8080: "HTTP-Alt",
    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "Web",
    9090: "Web",
    9100: "打印",
    9200: "Elasticsearch",
    10000: "Webmin",
    27017: "MongoDB",
    32400: "Plex",
    62078: "iOS",
}

_VENDOR_RULES: list[tuple[tuple[str, ...], str, str]] = [
    (
        ("hikvision", "dahua", "uniview", "axis ", "hanwha", "bosch security", "tiandy", "kedacom"),
        "摄像头 / 安防设备",
        "MAC 厂商属于视频监控设备厂商",
    ),
    (
        ("brother", "hewlett", "canon", "epson", "xerox", "ricoh", "kyocera", "lexmark", "fuji xerox"),
        "打印机 / 打印服务器",
        "MAC 厂商属于打印设备厂商",
    ),
    (
        ("synology", "qnap", "asustor", "terramaster", "western digital", "buffalo"),
        "NAS / 文件服务器",
        "MAC 厂商属于 NAS/存储设备厂商",
    ),
    (
        ("espressif", "tuya", "sonoff", "shelly", "itead", "raspberry pi", "particle"),
        "智能家居 / IoT 设备",
        "MAC 厂商属于物联网/开发板厂商",
    ),
    (
        ("vmware", "virtualbox", "qemu", "parallels", "hyper-v", "microsoft corporation"),
        "虚拟机 / 虚拟网卡",
        "MAC 厂商属于虚拟化平台",
    ),
    (
        ("ubiquiti", "mikrotik", "tp-link", "netgear", "d-link", "tenda", "ruijie", "h3c", "zte",
         "fiberhome", "china telecom", "sichuan tianyi", "mercury", "fast", "totolink"),
        "网络设备（路由器/AP）",
        "MAC 厂商属于网络设备厂商",
    ),
    (
        ("apple", "samsung", "xiaomi", "oppo", "vivo", "oneplus", "realme", "honor", "huawei"),
        "手机 / 消费电子",
        "MAC 厂商属于手机/消费电子厂商",
    ),
    (
        ("sonos", "roku", "google", "amazon", "lg electronics", "sony", "tcl", "hisense", "vizio"),
        "智能电视 / 音箱",
        "MAC 厂商属于影音设备厂商",
    ),
    (
        ("intel", "realtek", "broadcom", "qualcomm", "mediatek", "azurewave", "liteon", "micro-star"),
        "电脑 / 通用网络终端",
        "MAC 厂商属于电脑/网卡芯片厂商",
    ),
]


# ---------------------------------------------------------------------------
# DNS PTR
# ---------------------------------------------------------------------------


def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii", errors="ignore")
        if len(raw) > 63:
            return b""
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _read_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    next_offset = offset
    seen: set[int] = set()
    while 0 <= offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            if pointer in seen:
                break
            seen.add(pointer)
            offset = pointer
            jumped = True
            continue
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset : offset + length].decode("ascii", errors="ignore"))
        offset += length
    return ".".join(labels), next_offset


def dns_ptr(ip: str, dns_servers: Iterable[str], timeout: float = 0.9) -> str:
    """直接向本机 DNS 发 PTR 查询，避免 socket.gethostbyaddr 长时间阻塞。"""
    qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    encoded = _encode_dns_name(qname)
    if not encoded:
        return ""
    qid = random.randint(0, 65535)
    query = (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + encoded
        + struct.pack("!HH", 12, 1)
    )
    for server in dns_servers:
        server = str(server).strip()
        if not server or ":" in server:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(query, (server, 53))
            data, _ = sock.recvfrom(4096)
        except Exception:
            sock.close()
            continue
        finally:
            try:
                sock.close()
            except Exception:
                pass
        if len(data) < 12:
            continue
        rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        if rid != qid or not (flags & 0x8000) or (flags & 0x000F):
            continue
        offset = 12
        try:
            for _ in range(qdcount):
                _, offset = _read_dns_name(data, offset)
                offset += 4
            for _ in range(ancount):
                _, offset = _read_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
                offset += 10
                if rtype == 12 and rclass == 1:
                    ptr, _ = _read_dns_name(data, offset)
                    ptr = ptr.rstrip(".")
                    if ptr and "in-addr.arpa" not in ptr:
                        return ptr[:200]
                offset += rdlen
        except Exception:
            continue
    return ""


# ---------------------------------------------------------------------------
# HTTP / HTTPS
# ---------------------------------------------------------------------------


def _decode_body(body: bytes, content_type: str) -> str:
    charset = ""
    m = re.search(r"charset\s*=\s*[\"']?([\w-]+)", content_type or "", re.I)
    if m:
        charset = m.group(1)
    if not charset:
        m = re.search(rb"charset\s*=\s*[\"']?([\w-]+)", body[:4096], re.I)
        if m:
            charset = m.group(1).decode("ascii", errors="ignore")
    encodings: list[str] = []
    if charset:
        encodings.append(charset)
    encodings.extend(["utf-8", "gb18030", "big5", "latin-1"])
    for enc in encodings:
        try:
            text = body.decode(enc)
            return text
        except (UnicodeDecodeError, LookupError):
            continue
    return body.decode("utf-8", errors="replace")


def _extract_title(text: str) -> str:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    if not m:
        m = re.search(r'(?is)<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\']', text)
    if not m:
        return ""
    title = re.sub(r"(?is)<[^>]+>", " ", m.group(1))
    title = html.unescape(title)
    title = re.sub(r"\s+", " ", title).strip()
    return title[:160]


def _decode_certificate(sock: ssl.SSLSocket) -> str:
    try:
        der = sock.getpeercert(binary_form=True)
        if not der:
            return ""
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(pem)
            decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        subject = decoded.get("subject") or []
        for rdn in subject:
            for key, value in rdn:
                if key == "commonName" and str(value).strip():
                    return str(value)[:120]
        san = decoded.get("subjectAltName") or []
        for kind, value in san:
            if str(value).strip() and value not in ("0:0:0:0:0:0:0:1",):
                return str(value)[:120]
    except Exception:
        pass
    return ""


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception:
        pass
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    except Exception:
        pass
    return ctx


def http_probe(ip: str, port: int, use_ssl: bool, timeout: float = 1.9) -> WebPage:
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{ip}:{port}/"
    page = WebPage(port=port, scheme=scheme, url=url)
    conn: Optional[http.client.HTTPConnection] = None
    try:
        if use_ssl:
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=_ssl_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request(
            "GET",
            "/",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LAN-Scout/1.0",
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        page.status = int(response.status)
        page.server = (response.getheader("Server") or "")[:200]
        page.location = (response.getheader("Location") or "")[:300]
        page.powered_by = (response.getheader("X-Powered-By") or "")[:120]
        if use_ssl and isinstance(conn.sock, ssl.SSLSocket):
            page.cert_cn = _decode_certificate(conn.sock)
        body = response.read(MAX_HTTP_BODY)
        text = _decode_body(body, response.getheader("Content-Type") or "")
        page.title = _extract_title(text)
        if not page.title:
            m = re.search(r"(?is)<h1[^>]*>(.*?)</h1>", text)
            if m:
                title = re.sub(r"(?is)<[^>]+>", " ", m.group(1))
                page.title = re.sub(r"\s+", " ", html.unescape(title)).strip()[:120]
    except Exception as exc:
        page.error = str(exc)[:200]
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass
    return page


def read_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(512)
    except Exception:
        return ""
    text = data.decode("utf-8", errors="replace")
    if "�" in text:
        text = data.decode("latin-1", errors="replace")
    text = "".join(ch if ch.isprintable() or ch in "\t" else " " for ch in text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:220]


# ---------------------------------------------------------------------------
# NetBIOS / mDNS
# ---------------------------------------------------------------------------


def netbios_name(ip: str, timeout: float = 3.0) -> str:
    if os.name != "nt":
        return ""
    try:
        proc = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return ""
    raw = proc.stdout or b""
    text = raw.decode(locale.getpreferredencoding(False), errors="replace")
    names: list[str] = []
    for line in text.splitlines():
        # <00> UNIQUE 是工作站名，<20> UNIQUE 是文件服务名
        m = re.search(r"^\s*(.+?)\s+<(00|20)>\s+UNIQUE\s*$", line, re.I)
        if not m:
            continue
        name = m.group(1).strip()
        if not name or name.startswith("__MSBROWSE__") or name in names:
            continue
        names.append(name)
    return names[0][:120] if names else ""


def _mdns_query_names() -> dict[str, str]:
    """轻量 mDNS 查询：返回 A 记录 IP → .local 主机名。

    只发送标准 PTR 查询并收集应答，不刷新缓存。
    """
    names: dict[str, str] = {}
    queries = [
        "_services._dns-sd._udp.local",
        "_http._tcp.local",
        "_smb._tcp.local",
        "_ipp._tcp.local",
        "_printer._tcp.local",
        "_rtsp._tcp.local",
        "_workstation._tcp.local",
        "_device-info._tcp.local",
        "_googlecast._tcp.local",
        "_airplay._tcp.local",
    ]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.7)
        for qname in queries:
            qid = random.randint(0, 65535)
            # QCLASS 最高位 = QU（unicast-response）位，允许设备把应答
            # 单播回本 socket 的临时端口，从而无需抢占 5353 端口。
            packet = (
                struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0)
                + _encode_dns_name(qname)
                + struct.pack("!HH", 12, 0x8001)
            )
            try:
                sock.sendto(packet, ("224.0.0.251", 5353))
            except OSError:
                pass
        deadline = 1.4
        import time

        started = time.monotonic()
        while time.monotonic() - started < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break
            ip = addr[0]
            if not ip.startswith(("192.", "10.", "172.", "169.254.")):
                continue
            try:
                _parse_mdns_response(data, names, ip)
            except Exception:
                continue
    finally:
        sock.close()
    return names


def _parse_mdns_response(data: bytes, names: dict[str, str], fallback_ip: str) -> None:
    if len(data) < 12:
        return
    _, _, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = _read_dns_name(data, offset)
        offset += 4
    current_name = ""
    for _ in range(an):
        name, offset = _read_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata_offset = offset
        if rclass == 1 and rtype in (1, 12, 16, 33):
            if name.lower().endswith(".local") and rtype == 12:
                current_name = name
            elif rtype == 1 and rdlen == 4 and name.lower().endswith(".local"):
                ip = socket.inet_ntoa(data[rdata_offset : rdata_offset + 4])
                names[ip] = name.rstrip(".")
            elif rtype == 1 and rdlen == 4 and current_name:
                ip = socket.inet_ntoa(data[rdata_offset : rdata_offset + 4])
                names[ip] = current_name.rstrip(".")
        offset += rdlen
    if fallback_ip and fallback_ip not in names:
        # 对 Apple 等服务，PTR 的实例名通常比 A 记录更适合作为人类可读名称。
        pass


# ---------------------------------------------------------------------------
# 设备画像
# ---------------------------------------------------------------------------


def _hostname_from_ptr(ip: str, context: NetworkContext) -> str:
    dns_servers = list(context.dns or [])
    if context.interface and context.interface.dns:
        dns_servers = list(context.interface.dns) + dns_servers
    seen: set[str] = set()
    unique = []
    for server in dns_servers:
        if server and server not in seen:
            seen.add(server)
            unique.append(server)
    if unique:
        return dns_ptr(ip, unique)
    return ""


def _apply_web(host: HostResult) -> None:
    pages = [p for p in host.web_pages if p.error == ""]
    if not pages:
        return
    # 优先使用带标题的页面；再按常用端口排序，让结果稳定。
    order = {80: 0, 443: 1, 8080: 2, 8443: 3, 8000: 4, 8006: 5, 5000: 6, 8888: 7}
    pages.sort(key=lambda p: (not bool(p.title), order.get(p.port, 50), p.port))
    for page in pages:
        if page.title and not host.http_title:
            host.http_title = page.title
        if page.server and not host.http_server:
            host.http_server = page.server
    if not host.http_title:
        for page in pages:
            # 只记录有明确标题的页面；404/空页面不伪装成设备名称。
            if page.status and page.title:
                host.http_title = page.title[:120]
                break


def _classify(host: HostResult) -> tuple[str, str]:
    ports = {p.port for p in host.ports}
    title = (host.http_title or "").lower()
    hostname = f"{host.hostname} {host.netbios}".lower()
    vendor = (host.vendor or "").lower()
    combined = f"{title} {hostname} {vendor}"

    if host.is_local:
        system = platform.system() or "本机"
        return f"本机（{system}）", "当前运行扫描程序的电脑"

    if host.is_gateway:
        return "路由器 / 网关", "IP 与本机默认网关一致"

    if host.is_dhcp and not host.is_gateway:
        return "DHCP 服务器", "IP 与本机 DHCP 服务器一致"

    # 高置信度端口特征
    if ports & {9100, 515, 631}:
        return "打印机 / 打印服务器", "开放了 RAW/LPD/IPP 打印端口"
    if 554 in ports and (ports & {80, 8000, 8080, 8443, 37777} or any(
        word in combined for word in ("cam", "ipc", "nvr", "dvr", "hikvision", "dahua", "监控", "摄像")
    )):
        return "摄像头 / 录像机", "开放 RTSP 视频流端口"
    if 8006 in ports:
        return "虚拟化主机", "开放 Proxmox 8006 管理端口"
    if 32400 in ports:
        return "媒体服务器", "开放 Plex 32400 端口"
    if ports & {1883, 8883} or 502 in ports:
        return "智能家居 / IoT 设备", "开放 MQTT 或 Modbus 端口"
    if 2375 in ports or 2376 in ports:
        return "Docker 主机 / 服务器", "开放 Docker 管理端口"
    if 3389 in ports:
        return "Windows 电脑 / 服务器", "开放 RDP 3389 远程桌面端口"
    if 445 in ports and (139 in ports or 135 in ports):
        return "Windows 电脑 / 文件服务器", "开放 Windows SMB/NetBIOS/RPC 文件共享"
    if 445 in ports:
        if any(word in combined for word in ("nas", "synology", "qnap", "群晖", "storage")):
            return "NAS / 文件服务器", "开放 SMB 且主机名/网页指向 NAS"
        return "文件服务器 / NAS", "开放 SMB 文件共享端口"

    # 文本特征
    if any(word in combined for word in ("gateway", "router", "网关", "路由器", "光猫", "openwrt", "luci", "爱快", "ikuai", "routeros", "mikrotik")):
        return "路由器 / 网关", "网页标题或主机名包含网关/路由特征"
    if any(word in combined for word in ("camera", "ipc", "nvr", "dvr", "摄像", "hikvision", "dahua", "监控")):
        return "摄像头 / 录像机", "网页标题或主机名包含视频监控特征"
    if any(word in combined for word in ("printer", "打印", "ipp", "laserjet", "officejet")):
        return "打印机 / 打印服务器", "网页标题或主机名包含打印特征"
    if any(word in combined for word in ("nas", "synology", "qnap", "群晖", "存储")):
        return "NAS / 文件服务器", "网页标题或主机名包含 NAS/存储特征"
    if "proxmox" in combined:
        return "虚拟化主机", "网页标题包含 Proxmox"
    if "plex" in combined:
        return "媒体服务器", "网页标题包含 Plex"
    if any(word in combined for word in ("docker", "portainer")):
        return "Docker 主机 / 服务器", "网页标题包含 Docker/Portainer"
    if any(word in combined for word in ("openssh", "linux", "ubuntu", "debian", "centos", "alpine")):
        return "Linux 服务器 / 网络设备", "SSH banner 或标题包含 Linux 特征"

    # 厂商特征（优先级较低，避免误判）
    for keywords, label, reason in _VENDOR_RULES:
        if any(word in vendor for word in keywords):
            if label == "虚拟机 / 虚拟网卡" and host.mac:
                return label, reason
            if label == "网络设备（路由器/AP）" and not ports:
                return label, reason
            if ports:
                return label, reason
            return label, reason

    if ports & {80, 443, 8080, 8000, 8443, 8888, 9000, 9090}:
        if host.http_title:
            return "Web 管理设备", f"开放网页管理界面：{host.http_title[:50]}"
        return "Web 管理设备", "开放 HTTP/HTTPS 网页端口"
    if ports & {22, 21, 23}:
        return "服务器 / 网络设备", "开放远程管理端口"
    if ports:
        return "联网设备", "开放 TCP 服务：" + "、".join(str(p) for p in sorted(ports)[:4])
    return "未知设备", "仅在 L2/ARP 层被发现，未获得应用层信息"


def _build_services(host: HostResult) -> None:
    labels: list[str] = []
    for port_info in sorted(host.ports, key=lambda p: p.port):
        label = _SHORT_SERVICES.get(port_info.port, service_label(port_info.port))
        labels.append(label)
        detail = f"{port_info.port} {service_label(port_info.port)}"
        if port_info.banner and port_info.port == 22:
            detail += f"（{port_info.banner[:80]}）"
        if port_info.port in HTTP_PORTS or port_info.port in HTTPS_PORTS:
            title = next((p.title for p in host.web_pages if p.port == port_info.port and p.title), "")
            if title:
                detail += f"（{title[:60]}）"
        host.services.append(detail)
    parts: list[str] = []
    if host.http_title:
        parts.append(f"Web 管理「{host.http_title[:40]}」")
    elif any(p.port in HTTP_PORTS | HTTPS_PORTS for p in host.ports):
        parts.append("Web 服务")
    for label in labels:
        if label in ("HTTP", "HTTPS", "HTTP-Alt", "HTTPS-Alt") and parts:
            continue
        if label not in parts:
            parts.append(label)
    if not parts and host.state == "仅 ARP 记录":
        parts.append("仅 ARP 记录（设备可能休眠/防火墙）")
    host.service_summary = " · ".join(parts[:5])


def _build_evidence(host: HostResult) -> None:
    evidence: list[str] = []
    if host.ping_ok:
        rtt = f"{host.rtt_ms:.1f} ms" if host.rtt_ms is not None else "?"
        evidence.append(
            f"ICMP 有应答（{rtt}" + (f"，TTL {host.ttl}" if host.ttl else "") + "）"
        )
    if host.arp_state:
        evidence.append(f"ARP 表存在记录（{host.arp_state}）")
    if host.ports:
        evidence.append("开放 TCP 端口：" + "、".join(str(p.port) for p in host.ports[:16]))
    if host.http_title:
        evidence.append(f"HTTP 页面标题：{host.http_title}")
    if host.netbios:
        evidence.append(f"NetBIOS 名称：{host.netbios}")
    if not evidence and (host.is_gateway or host.is_dhcp or host.is_local):
        tags = []
        if host.is_gateway:
            tags.append("默认网关")
        if host.is_dhcp:
            tags.append("DHCP 服务器")
        if host.is_local:
            tags.append("本机")
        evidence.append("该地址与本机配置（" + "、".join(tags) + "）一致，按占用处理")
    if not evidence:
        evidence.append("发现存在，但缺少主动响应证据")
    host.evidence = evidence
    if host.is_local or host.is_gateway:
        host.confidence = "高"
    elif host.ping_ok or host.ports:
        host.confidence = "高" if host.http_title or len(host.ports) >= 2 else "中"
    else:
        host.confidence = "低（仅 L2 记录）"


def _build_roles(host: HostResult) -> None:
    roles: list[str] = []
    if host.is_local:
        roles.append("本机")
    if host.is_gateway:
        roles.append("默认网关")
    if host.is_dhcp:
        roles.append("DHCP 服务器")
    if host.is_dns:
        roles.append("DNS 服务器")
    ports = {p.port for p in host.ports}
    if 445 in ports or 139 in ports:
        roles.append("文件共享")
    if ports & {80, 443, 8080, 8000, 8443, 8888} and "Web 管理" not in roles:
        roles.append("Web 管理")
    if 22 in ports:
        roles.append("SSH 管理")
    if 3389 in ports:
        roles.append("远程桌面")
    if ports & {9100, 515, 631}:
        roles.append("打印服务")
    if 554 in ports:
        roles.append("视频流")
    host.roles = list(dict.fromkeys(roles))


def _build_notes(host: HostResult) -> None:
    notes: list[str] = []
    ports = {p.port for p in host.ports}
    if 23 in ports:
        notes.append("开放 Telnet 明文远程登录，若不需要建议关闭。")
    if 21 in ports:
        notes.append("开放 FTP，注意匿名访问与明文传输风险。")
    if 2375 in ports:
        notes.append("Docker API 未加密端口开放，若暴露应尽快限制访问。")
    if 445 in ports and not host.is_local:
        notes.append("SMB 文件共享端口开放，建议确认共享权限与访问控制。")
    if 3389 in ports and not host.is_local:
        notes.append("RDP 远程桌面端口开放，建议限制来源 IP 并使用强口令。")
    if host.http_title and any(word in host.http_title.lower() for word in ("login", "登录", "管理", "admin")):
        notes.append("网页疑似管理登录入口，请确认默认口令已修改。")
    if host.state == "仅 ARP 记录":
        notes.append("只有 ARP 记录，可能设备休眠、开启防火墙或已离线；不代表当前一定在线。")
    host.notes = notes


def _build_os_guess(host: HostResult) -> None:
    ports = {p.port for p in host.ports}
    if host.is_local:
        host.os_guess = platform.system() or "本机"
    elif 3389 in ports or 135 in ports:
        host.os_guess = "Windows（由 RPC/RDP 端口推断）"
    elif 445 in ports and 22 not in ports:
        host.os_guess = "Windows 或 NAS（由 SMB 端口推断）"
    elif 22 in ports:
        host.os_guess = "Linux / Unix（由 SSH 端口推断）"
    else:
        host.os_guess = ttl_to_os(host.ttl)


def finalize_host(host: HostResult) -> HostResult:
    """在服务识别之后统一生成摘要、类型、证据与风险提示。"""
    host.mac = host.mac.upper().replace("-", ":")
    if host.mac and not host.vendor:
        host.vendor = vendor_for_mac(host.mac)
    if host.is_local and not host.hostname:
        host.hostname = socket.gethostname()
    _apply_web(host)
    _build_services(host)
    _build_os_guess(host)
    host.device_type, host.device_reason = _classify(host)
    _build_roles(host)
    _build_evidence(host)
    _build_notes(host)
    return host


def fingerprint_host(
    host: HostResult,
    context: NetworkContext,
    resolve_names: bool = True,
    detect_services: bool = True,
    mdns_names: Optional[dict[str, str]] = None,
    timeout: float = 1.9,
    stop_event: Optional[threading.Event] = None,
) -> HostResult:
    """补全单台设备的主机名、banner、HTTP 页面。"""

    def stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    port_map = {p.port: p for p in host.ports}
    if host.is_local:
        host.hostname = host.hostname or socket.gethostname()
    elif resolve_names and not host.hostname:
        if stopped():
            return finalize_host(host)
        host.hostname = _hostname_from_ptr(host.ip, context)
        if not host.hostname and mdns_names:
            host.hostname = mdns_names.get(host.ip, "")
    if stopped():
        return finalize_host(host)

    if detect_services:
        # NetBIOS：只在出现 SMB 相关端口时尝试，避免无谓等待。
        if 445 in port_map or 139 in port_map:
            host.netbios = netbios_name(host.ip, timeout=2.0)
            if host.netbios and not host.hostname:
                host.hostname = host.netbios
        if stopped():
            return finalize_host(host)

        for port in sorted(BANNER_PORTS & set(port_map)):
            if stopped():
                return finalize_host(host)
            banner = read_banner(host.ip, port)
            if not banner:
                continue
            port_map[port].banner = banner
            if port == 22 and not host.ssh_banner:
                host.ssh_banner = banner
            elif port == 21 and not host.ftp_banner:
                host.ftp_banner = banner
            elif port == 25 and not host.smtp_banner:
                host.smtp_banner = banner

        web_ports = sorted(
            [p for p in port_map if p in HTTP_PORTS or p in HTTPS_PORTS],
            key=lambda p: (
                0 if p == 80 else 1 if p == 443 else 2 if p == 8080 else 3 if p == 8443 else 10,
                p,
            ),
        )
        for port in web_ports[:3]:
            if stopped():
                break
            use_ssl = port in HTTPS_PORTS
            page = http_probe(host.ip, port, use_ssl=use_ssl, timeout=timeout)
            if page.status or page.title or page.server:
                host.web_pages.append(page)

    return finalize_host(host)


def fingerprint_hosts(
    hosts: list[HostResult],
    context: NetworkContext,
    resolve_names: bool = True,
    detect_services: bool = True,
    progress: Optional[Callable[[int, int], None]] = None,
    stop_event: Optional[threading.Event] = None,
    max_workers: int = 8,
) -> list[HostResult]:
    """并发补全所有在线设备；每个 host 内部仍串行，避免一次发太多请求。"""
    if not hosts:
        return []
    mdns_names: dict[str, str] = {}
    if not (stop_event and stop_event.is_set()):
        try:
            mdns_names = _mdns_query_names()
        except Exception:
            mdns_names = {}
    done = 0
    total = len(hosts)
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, total))) as pool:
        futures = {
            pool.submit(
                fingerprint_host,
                host,
                context,
                resolve_names=resolve_names,
                detect_services=detect_services,
                mdns_names=mdns_names,
                stop_event=stop_event,
            ): host
            for host in hosts
        }
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                fut.result()
            except Exception as exc:
                host.notes.append(f"识别过程出错：{exc}")
                finalize_host(host)
            done += 1
            if progress:
                progress(done, total)
            if stop_event and stop_event.is_set():
                for pending in futures:
                    pending.cancel()
                break
    # 若中途停止，未完成的 host 也补上基础画像。
    for host in hosts:
        if host.device_type == "未知设备" and not host.service_summary:
            finalize_host(host)
    return hosts


def service_names(host: HostResult) -> str:
    if not host.ports:
        return "—"
    return "、".join(_SHORT_SERVICES.get(p.port, str(p.port)) for p in sorted(host.ports, key=lambda p: p.port))


__all__ = [
    "dns_ptr",
    "finalize_host",
    "fingerprint_host",
    "fingerprint_hosts",
    "http_probe",
    "netbios_name",
    "read_banner",
    "service_names",
]
