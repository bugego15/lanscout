"""扫描结果对比与资产台账。

工具原本每次扫描都是一张独立快照，看不出"变化"。这个模块补上两件事：

1. **对比**：以 MAC 为主键（DHCP 会让 IP 漂移，MAC 不会），找出新增设备、
   消失设备、端口增减、主机名/类型变化，输出文本或自包含 HTML。
2. **台账**：把多次扫描的 JSON 聚合成一份按 MAC 归档的资产表，回答
   "这台设备什么时候第一次出现、上次在哪、开过哪些端口"。

只依赖标准库，输入是 ``ScanResult.to_dict()`` / ``write_json`` 产出的字典，
因此可以直接读历史文件，也能拿内存里的结果做即时对比。
"""

from __future__ import annotations

import csv
import html
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

HISTORY_DIRNAME = "history"

# 端口 → 中文服务名，用于把"新增 3389"写成"新增 3389（远程桌面）"。
_PORT_LABELS = {
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
    515: "打印",
    548: "AFP",
    554: "RTSP",
    631: "IPP",
    873: "Rsync",
    902: "VMware",
    1433: "SQL Server",
    1521: "Oracle",
    1883: "MQTT",
    2049: "NFS",
    2375: "Docker",
    3000: "Web 服务",
    3306: "MySQL",
    3389: "远程桌面",
    5000: "Web 服务",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "Web 服务",
    8006: "Proxmox",
    8080: "Web 服务",
    8443: "HTTPS 管理",
    8888: "Web 服务",
    9000: "Web 服务",
    9090: "Web 服务",
    9100: "打印",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def port_label(port: int) -> str:
    name = _PORT_LABELS.get(port)
    return f"{port}（{name}）" if name else str(port)


# ---------------------------------------------------------------------------
# 快照
# ---------------------------------------------------------------------------


@dataclass
class HostSnapshot:
    """一台设备在某一时刻的可比较状态。"""

    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    device_type: str = "未知设备"
    os_guess: str = ""
    state: str = ""
    title: str = ""
    ports: set[int] = field(default_factory=set)

    @property
    def key(self) -> str:
        """设备身份：优先 MAC，没有 MAC 时退回 IP。"""
        return self.mac.upper() if self.mac else f"ip:{self.ip}"

    @property
    def display_name(self) -> str:
        return self.hostname or self.title or self.device_type or "未知设备"

    def port_text(self) -> str:
        return "、".join(str(p) for p in sorted(self.ports)) or "—"


def snapshot_from_host(data: dict[str, Any]) -> HostSnapshot:
    """把 JSON 里的单台设备字典转成快照。缺字段一律按空值处理，兼容旧报告。"""
    ports: set[int] = set()
    for item in data.get("ports") or []:
        if isinstance(item, dict):
            try:
                ports.add(int(item.get("port")))
            except (TypeError, ValueError):
                continue
        else:
            try:
                ports.add(int(item))
            except (TypeError, ValueError):
                continue
    return HostSnapshot(
        ip=str(data.get("ip") or ""),
        mac=str(data.get("mac") or ""),
        vendor=str(data.get("vendor") or ""),
        hostname=str(data.get("hostname") or data.get("netbios") or ""),
        device_type=str(data.get("device_type") or "未知设备"),
        os_guess=str(data.get("os_guess") or ""),
        state=str(data.get("state") or ""),
        title=str(data.get("http_title") or ""),
        ports=ports,
    )


def snapshot_from_result(result: Any) -> HostSnapshot:
    """从 HostResult 对象直接建快照（GUI 即时对比用）。"""
    return snapshot_from_host(result.to_dict())


def _snapshots(scan: dict[str, Any]) -> dict[str, HostSnapshot]:
    result: dict[str, HostSnapshot] = {}
    for item in scan.get("hosts") or []:
        if not isinstance(item, dict) or not item.get("ip"):
            continue
        snap = snapshot_from_host(item)
        result[snap.key] = snap
    return result


# ---------------------------------------------------------------------------
# 对比
# ---------------------------------------------------------------------------


@dataclass
class HostChange:
    """同一台设备（同 MAC）在两次扫描之间的变化。"""

    snapshot: HostSnapshot
    opened: list[int] = field(default_factory=list)
    closed: list[int] = field(default_factory=list)
    fields: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def significant(self) -> bool:
        """只有端口或身份变化才算"值得看"的变化。"""
        return bool(self.opened or self.closed or self.fields)

    def summary(self) -> str:
        parts: list[str] = []
        if self.opened:
            parts.append("新开 " + "、".join(port_label(p) for p in self.opened))
        if self.closed:
            parts.append("关闭 " + "、".join(port_label(p) for p in self.closed))
        for name, old, new in self.fields:
            parts.append(f"{name} {old or '—'} → {new or '—'}")
        return "；".join(parts)


@dataclass
class ScanDiff:
    """两次扫描的差异结果。"""

    previous_at: str = ""
    current_at: str = ""
    previous_target: str = ""
    current_target: str = ""
    added: list[HostSnapshot] = field(default_factory=list)
    removed: list[HostSnapshot] = field(default_factory=list)
    changed: list[HostChange] = field(default_factory=list)
    unchanged: int = 0

    @property
    def total(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed) + self.unchanged

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def headline(self) -> str:
        if not self.has_changes:
            return f"与上次相比没有设备变化（{self.unchanged} 台一致）"
        return (
            f"新增 {len(self.added)} 台 · 消失 {len(self.removed)} 台 · "
            f"变化 {len(self.changed)} 台 · 无变化 {self.unchanged} 台"
        )


def compare_scans(previous: dict[str, Any], current: dict[str, Any]) -> ScanDiff:
    """对比两份扫描结果。

    以 MAC 为主键。同一台设备换了 IP 会记为 "IP" 字段变化，而不是
    "一台消失 + 一台新增" —— 这正是 DHCP 环境里最容易看错的地方。
    """
    old = _snapshots(previous)
    new = _snapshots(current)

    diff = ScanDiff(
        previous_at=str(previous.get("finished_at") or previous.get("started_at") or ""),
        current_at=str(current.get("finished_at") or current.get("started_at") or ""),
        previous_target=str(previous.get("target") or ""),
        current_target=str(current.get("target") or ""),
    )

    for key, snap in new.items():
        before = old.get(key)
        if before is None:
            diff.added.append(snap)
            continue

        change = HostChange(snapshot=snap)
        change.opened = sorted(snap.ports - before.ports)
        change.closed = sorted(before.ports - snap.ports)
        for name, old_value, new_value in (
            ("IP", before.ip, snap.ip),
            ("主机名", before.hostname, snap.hostname),
            ("设备类型", before.device_type, snap.device_type),
            ("厂商", before.vendor, snap.vendor),
            ("系统", before.os_guess, snap.os_guess),
        ):
            if old_value == new_value:
                continue
            # 主机名一侧为空通常只是"这次没解析出来"（DNS/NetBIOS 时好时坏），
            # 不是设备真的改名，报出来只会淹没真正的变化。
            if name == "主机名" and not (old_value and new_value):
                continue
            change.fields.append((name, old_value, new_value))

        if change.significant:
            diff.changed.append(change)
        else:
            diff.unchanged += 1

    for key, snap in old.items():
        if key not in new:
            diff.removed.append(snap)

    diff.added.sort(key=lambda s: _ip_sort_key(s.ip))
    diff.removed.sort(key=lambda s: _ip_sort_key(s.ip))
    diff.changed.sort(key=lambda c: _ip_sort_key(c.snapshot.ip))
    return diff


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except Exception:
        return (999,)


# ---------------------------------------------------------------------------
# 文本渲染（CLI / GUI 共用）
# ---------------------------------------------------------------------------


def render_diff_text(diff: ScanDiff, limit: int = 20) -> str:
    """把差异渲染成便于终端/文本框阅读的中文摘要。"""
    lines: list[str] = []
    span = f"{diff.previous_at or '上次'} → {diff.current_at or '本次'}"
    lines.append(f"扫描对比 · {span}")
    if diff.previous_target and diff.current_target:
        lines.append(f"范围：{diff.previous_target} → {diff.current_target}")
        if diff.previous_target != diff.current_target:
            lines.append("注意：两次扫描范围不同，下面的\u201c新增/消失\u201d可能只是范围变化造成的。")
    lines.append(diff.headline())

    if diff.added:
        lines.append("")
        lines.append(f"新增设备（{len(diff.added)} 台）：")
        for snap in diff.added[:limit]:
            lines.append(
                f"  + {snap.ip:<15} {snap.mac or '—':<18} "
                f"{snap.vendor or '厂商未知':<24} {snap.display_name} · {snap.port_text()}"
            )
        if len(diff.added) > limit:
            lines.append(f"  …还有 {len(diff.added) - limit} 台")

    if diff.removed:
        lines.append("")
        lines.append(f"消失设备（{len(diff.removed)} 台）：")
        for snap in diff.removed[:limit]:
            lines.append(
                f"  - {snap.ip:<15} {snap.mac or '—':<18} "
                f"{snap.vendor or '厂商未知':<24} {snap.display_name} · {snap.port_text()}"
            )
        if len(diff.removed) > limit:
            lines.append(f"  …还有 {len(diff.removed) - limit} 台")

    if diff.changed:
        lines.append("")
        lines.append(f"发生变化（{len(diff.changed)} 台）：")
        for change in diff.changed[:limit]:
            snap = change.snapshot
            lines.append(f"  ~ {snap.ip:<15} {snap.display_name}")
            lines.append(f"      {change.summary()}")
        if len(diff.changed) > limit:
            lines.append(f"  …还有 {len(diff.changed) - limit} 台")

    if not diff.has_changes:
        lines.append("")
        lines.append("设备清单、端口和身份都没有变化。")

    lines.append("")
    lines.append("提示：新增设备若是陌生 MAC/厂商，建议先在网关核对 DHCP 租约再决定是否放行。")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML 渲染
# ---------------------------------------------------------------------------

_DIFF_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b1f24;--muted:#5b6672;--line:#e3e6ea;
--ok:#0f8a4d;--warn:#b26a00;--bad:#c02b2b;--accent:#2f6feb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:36px 24px 64px}
h1{font-size:23px;margin:0 0 6px}
.sub{color:var(--muted);font-size:13px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:0 0 26px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi b{display:block;font-size:22px;line-height:1.25}
.kpi span{color:var(--muted);font-size:12px}
h2{font-size:16px;margin:26px 0 10px;padding-left:9px;border-left:3px solid var(--accent)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:10px;overflow:hidden;font-size:13.5px}
th,td{padding:8px 11px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#eef1f5;font-weight:600;font-size:12.5px;color:#3d4753}
tr:last-child td{border-bottom:none}
code{background:#f2f4f7;padding:1px 5px;border-radius:4px;font-size:12.5px;
font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.add{color:var(--ok);font-weight:600}
.rem{color:var(--bad);font-weight:600}
.chg{color:var(--warn);font-weight:600}
.empty{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:18px;color:var(--muted)}
footer{margin-top:34px;padding-top:16px;border-top:1px solid var(--line);
color:var(--muted);font-size:12.5px}
"""


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _diff_table(headers: list[str]) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    return f"<table><tr>{head}</tr>"


def build_diff_html(diff: ScanDiff) -> str:
    """生成自包含的对比报告（可直接发给同事或存档）。"""
    span = f"{diff.previous_at or '上次'} → {diff.current_at or '本次'}"
    parts: list[str] = [
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        f"<title>局域网扫描对比 · {_e(span)}</title><style>{_DIFF_CSS}</style></head><body><div class=\"wrap\">",
        "<h1>局域网扫描对比</h1>",
        f"<div class=\"sub\">{_e(span)}<br>",
        f"范围：{_e(diff.previous_target or '—')} → {_e(diff.current_target or '—')}</div>",
        "<div class=\"grid\">",
        f"<div class=\"kpi\"><b class=\"add\">{len(diff.added)}</b><span>新增设备</span></div>",
        f"<div class=\"kpi\"><b class=\"rem\">{len(diff.removed)}</b><span>消失设备</span></div>",
        f"<div class=\"kpi\"><b class=\"chg\">{len(diff.changed)}</b><span>发生变化</span></div>",
        f"<div class=\"kpi\"><b>{diff.unchanged}</b><span>无变化</span></div>",
        "</div>",
    ]

    if not diff.has_changes:
        parts.append("<div class=\"empty\">两次扫描之间设备清单、端口和身份都没有变化。</div>")
    else:
        if diff.added:
            parts.append(f"<h2>新增设备（{len(diff.added)} 台）</h2>")
            parts.append(_diff_table(["IP", "MAC", "厂商", "识别", "开放端口"]))
            for snap in diff.added:
                parts.append(
                    "<tr>"
                    f"<td><code>{_e(snap.ip)}</code></td><td>{_e(snap.mac or '—')}</td>"
                    f"<td>{_e(snap.vendor or '厂商未知')}</td><td>{_e(snap.display_name)}</td>"
                    f"<td>{_e(snap.port_text())}</td></tr>"
                )
            parts.append("</table>")

        if diff.removed:
            parts.append(f"<h2>消失设备（{len(diff.removed)} 台）</h2>")
            parts.append(_diff_table(["IP", "MAC", "厂商", "识别", "最后已知端口"]))
            for snap in diff.removed:
                parts.append(
                    "<tr>"
                    f"<td><code>{_e(snap.ip)}</code></td><td>{_e(snap.mac or '—')}</td>"
                    f"<td>{_e(snap.vendor or '厂商未知')}</td><td>{_e(snap.display_name)}</td>"
                    f"<td>{_e(snap.port_text())}</td></tr>"
                )
            parts.append("</table>")

        if diff.changed:
            parts.append(f"<h2>发生变化（{len(diff.changed)} 台）</h2>")
            parts.append(_diff_table(["IP", "设备", "变化"]))
            for change in diff.changed:
                snap = change.snapshot
                parts.append(
                    "<tr>"
                    f"<td><code>{_e(snap.ip)}</code></td>"
                    f"<td>{_e(snap.display_name)}<br><span class=\"sub\">{_e(snap.mac or '—')}</span></td>"
                    f"<td>{_e(change.summary())}</td></tr>"
                )
            parts.append("</table>")

    parts.append(
        "<footer>对比以 MAC 为主键：同一台设备更换 IP 会记为 \u201cIP 变化\u201d，"
        "不会被误判成\u201c一台消失 + 一台新增\u201d。<br>"
        "新增设备建议先在网关核对 DHCP 租约；消失设备可能只是休眠或关机。</footer>"
    )
    parts.append("</div></body></html>")
    return "".join(parts)


def write_diff_html(diff: ScanDiff, path: str | Path) -> Path:
    target = Path(path)
    if target.parent and str(target.parent):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(build_diff_html(diff), encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# 资产台账
# ---------------------------------------------------------------------------


@dataclass
class AssetRow:
    """跨多次扫描聚合出来的一条资产记录。"""

    key: str
    mac: str
    ips: list[str] = field(default_factory=list)
    vendor: str = ""
    device_type: str = ""
    hostname: str = ""
    os_guess: str = ""
    ports: set[int] = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""
    scans: int = 0

    @property
    def ip_text(self) -> str:
        if not self.ips:
            return "—"
        if len(self.ips) == 1:
            return self.ips[0]
        return f"{self.ips[-1]}（历史 {len(self.ips)} 个）"

    @property
    def port_text(self) -> str:
        return " ".join(str(p) for p in sorted(self.ports)) or "—"


INVENTORY_HEADERS = [
    "MAC",
    "最近 IP",
    "历史 IP",
    "厂商",
    "设备类型",
    "主机名",
    "系统判断",
    "开放端口",
    "首次发现",
    "最后发现",
    "出现次数",
]


def build_inventory(scans: Iterable[dict[str, Any]]) -> list[AssetRow]:
    """把多份扫描结果聚合成资产台账，按最后发现时间倒序。"""
    rows: dict[str, AssetRow] = {}
    ordered = sorted(
        (s for s in scans if isinstance(s, dict)),
        key=lambda s: str(s.get("finished_at") or s.get("started_at") or ""),
    )
    for scan in ordered:
        seen_at = str(scan.get("finished_at") or scan.get("started_at") or "")
        for item in scan.get("hosts") or []:
            if not isinstance(item, dict) or not item.get("ip"):
                continue
            snap = snapshot_from_host(item)
            row = rows.get(snap.key)
            if row is None:
                row = AssetRow(key=snap.key, mac=snap.mac or "—", first_seen=seen_at)
                rows[snap.key] = row
            if snap.ip and snap.ip not in row.ips:
                row.ips.append(snap.ip)
            row.vendor = snap.vendor or row.vendor
            row.device_type = snap.device_type or row.device_type
            row.hostname = snap.hostname or row.hostname
            row.os_guess = snap.os_guess or row.os_guess
            row.ports |= snap.ports
            row.last_seen = seen_at or row.last_seen
            row.scans += 1

    return sorted(rows.values(), key=lambda r: (r.last_seen, r.ips[-1] if r.ips else ""), reverse=True)


def write_inventory_csv(rows: Iterable[AssetRow], path: str | Path) -> Path:
    """导出 Excel 友好的台账（UTF-8 BOM，中文不乱码）。"""
    target = Path(path)
    if target.parent and str(target.parent):
        target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(INVENTORY_HEADERS)
        for row in rows:
            writer.writerow(
                [
                    row.mac,
                    row.ips[-1] if row.ips else "",
                    " ".join(row.ips),
                    row.vendor,
                    row.device_type,
                    row.hostname,
                    row.os_guess,
                    row.port_text,
                    row.first_seen,
                    row.last_seen,
                    row.scans,
                ]
            )
    return target


# ---------------------------------------------------------------------------
# 历史快照
# ---------------------------------------------------------------------------


def history_dir(reports_dir: str | Path) -> Path:
    return Path(reports_dir) / HISTORY_DIRNAME


def save_snapshot(scan: dict[str, Any], reports_dir: str | Path) -> Path:
    """把一次扫描结果存进 reports/history/，供下次对比。"""
    folder = history_dir(reports_dir)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = str(scan.get("finished_at") or "").replace("-", "").replace(":", "").replace(" ", "_")
    if not stamp:
        import datetime

        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    target = folder / f"scan_{stamp}.json"
    target.write_text(json.dumps(scan, ensure_ascii=False, indent=1), encoding="utf-8")
    return target


def list_snapshots(reports_dir: str | Path) -> list[Path]:
    folder = history_dir(reports_dir)
    if not folder.exists():
        return []
    return sorted(folder.glob("*.json"), key=lambda p: p.stat().st_mtime)


def latest_snapshot(reports_dir: str | Path, exclude: Optional[Path] = None) -> Optional[Path]:
    """取最近一份历史快照；exclude 用于排除刚写入的本次结果。"""
    excluded = exclude.resolve() if exclude else None
    for path in reversed(list_snapshots(reports_dir)):
        try:
            if excluded and path.resolve() == excluded:
                continue
        except OSError:
            pass
        return path
    return None


def load_scan(path: str | Path) -> dict[str, Any]:
    """读取扫描 JSON，并做最低限度的结构校验。"""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "hosts" not in data:
        raise ValueError(f"不是有效的扫描结果文件：{path}")
    return data


def load_baseline(spec: str, reports_dir: str | Path, exclude: Optional[Path] = None) -> Optional[dict[str, Any]]:
    """解析 --baseline 参数：``last`` 表示最近一份历史快照，其余按路径读取。"""
    if spec.strip().lower() in ("last", "auto", ""):
        path = latest_snapshot(reports_dir, exclude=exclude)
        return load_scan(path) if path else None
    return load_scan(spec)


__all__ = [
    "AssetRow",
    "HostChange",
    "HostSnapshot",
    "ScanDiff",
    "build_diff_html",
    "build_inventory",
    "compare_scans",
    "history_dir",
    "latest_snapshot",
    "list_snapshots",
    "load_baseline",
    "load_scan",
    "port_label",
    "render_diff_text",
    "save_snapshot",
    "snapshot_from_host",
    "snapshot_from_result",
    "write_diff_html",
    "write_inventory_csv",
]
