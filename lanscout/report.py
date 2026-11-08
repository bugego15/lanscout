"""扫描结果导出：自包含 HTML 报告、CSV、JSON。"""

from __future__ import annotations

import csv
import html
import io
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

from . import APP_NAME, APP_NAME_EN, __version__
from .discovery import PORT_PROFILES
from .models import HostResult, ScanResult


def _e(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _mode_label(mode: str) -> str:
    return str(PORT_PROFILES.get(mode, {}).get("label", mode))


def _risk_host_count(result: ScanResult) -> int:
    return sum(1 for h in result.hosts if h.state == "仅 ARP 记录")


def _group_ips(ips: Iterable[str]) -> list[str]:
    """把连续 IP 按 /24 分组后合并成 a-b 形式，用于报告里紧凑展示。

    不能只看最后一段，否则 /20 的 192.168.0.254 与 192.168.1.1
    会被错误合并成“1-254”。
    """
    by_prefix: dict[str, list[int]] = {}
    for ip in ips:
        parts = ip.split(".")
        if len(parts) != 4:
            continue
        try:
            last = int(parts[3])
        except ValueError:
            continue
        by_prefix.setdefault(".".join(parts[:3]), []).append(last)
    groups: list[str] = []
    for prefix in sorted(by_prefix, key=lambda p: tuple(int(x) for x in p.split("."))):
        values = sorted(set(by_prefix[prefix]))
        start = prev = values[0]
        for value in values[1:]:
            if value == prev + 1:
                prev = value
                continue
            groups.append(
                f"{prefix}.{start}" if start == prev else f"{prefix}.{start}-{prev}"
            )
            start = prev = value
        groups.append(f"{prefix}.{start}" if start == prev else f"{prefix}.{start}-{prev}")
    return groups


def _port_scopes(result: ScanResult) -> tuple[int, int]:
    """返回 (全段发现端口数, 在线设备补扫后的总端口数)。"""
    profile = PORT_PROFILES.get(result.mode, {})
    discovery = len(set(profile.get("discovery", [])))  # type: ignore[arg-type]
    full = len(set(profile.get("full", []))) or result.ports_tested  # type: ignore[arg-type]
    if result.free_ips:
        # 未发现占用地址实际只经过全段 discovery 端口扫描。
        discovery = result.free_ips[0].checked_ports or discovery
    return discovery, full


def _csv_safe(value: object) -> object:
    """防止 Excel/CSV 公式注入（主机名等来自被扫描设备的不可信字段）。"""
    if isinstance(value, str) and value:
        if value[0] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + value
    return value


def _host_card(host: HostResult, context) -> str:
    state_class = {
        "在线": "ok",
        "仅 ARP 记录": "warn",
        "配置地址": "neutral",
        "本机配置地址": "neutral",
    }.get(host.state, "neutral")
    subtitle = host.hostname or host.netbios or "主机名未识别"
    vendor = host.vendor or "厂商未知"
    mac = host.mac or "未获得 MAC"
    roles = " · ".join(host.roles) if host.roles else "—"
    os_guess = host.os_guess or "—"
    confidence = host.confidence or "—"
    response = "—"
    if host.ping_ok:
        if host.rtt_ms is not None:
            response = f"{host.rtt_ms:.1f} ms / TTL {host.ttl if host.ttl else '?'}"
        else:
            response = f"有应答 / TTL {host.ttl if host.ttl else '?'}"
    elif host.ports:
        response = "仅端口响应"
    elif host.mac:
        response = "仅 ARP 记录"

    port_chips = "".join(
        f'<span class="chip port">{_e(p.port)} · {_e(p.service)}</span>'
        for p in host.ports
    ) or '<span class="muted">未发现开放端口</span>'

    web_rows = ""
    for page in host.web_pages:
        if not page.url:
            continue
        # 无标题、无 Server 的 4xx/错误页对“设备在做什么”帮助很小，避免报告噪声。
        if not (page.title or page.server or (page.status and page.status < 400)):
            continue
        bits = [
            f'<span class="mono">{_e(page.url)}</span>',
            f"HTTP {_e(page.status)}" if page.status else "HTTP 响应",
        ]
        if page.title:
            bits.append(f"标题：{_e(page.title)}")
        if page.server:
            bits.append(f"Server：{_e(page.server)}")
        if page.location:
            bits.append(f"跳转：{_e(page.location)}")
        if page.cert_cn:
            bits.append(f"证书：{_e(page.cert_cn)}")
        web_rows += "<li>" + "；".join(bits) + "</li>"
    web_block = (
        f'<div class="subblock"><div class="subtitle">网页信息</div><ul>{web_rows}</ul></div>'
        if web_rows
        else ""
    )

    banners: list[str] = []
    if host.ssh_banner:
        banners.append("SSH：" + host.ssh_banner)
    if host.ftp_banner:
        banners.append("FTP：" + host.ftp_banner)
    if host.smtp_banner:
        banners.append("SMTP：" + host.smtp_banner)
    banner_block = (
        '<div class="subblock"><div class="subtitle">服务 Banner</div><ul>'
        + "".join(f"<li>{_e(b)}</li>" for b in banners)
        + "</ul></div>"
        if banners
        else ""
    )

    evidence = "".join(f"<li>{_e(item)}</li>" for item in host.evidence) or "<li>—</li>"
    notes = "".join(f"<li>{_e(item)}</li>" for item in host.notes)
    note_block = (
        f'<div class="subblock note"><div class="subtitle">安全提示</div><ul>{notes}</ul></div>'
        if notes
        else ""
    )
    return f"""
    <article class="host">
      <div class="host-head">
        <div>
          <span class="ip">{_e(host.ip)}</span>
          <span class="badge {state_class}">{_e(host.state)}</span>
          <span class="badge type">{_e(host.device_type)}</span>
        </div>
        <div class="confidence">置信度：{_e(confidence)}</div>
      </div>
      <div class="host-sub">{_e(subtitle)} · {_e(vendor)}</div>
      <table class="kv">
        <tr><th>MAC / 厂商</th><td><span class="mono">{_e(mac)}</span> · {_e(vendor)}</td>
            <th>角色</th><td>{_e(roles)}</td></tr>
        <tr><th>主机名 / NetBIOS</th><td>{_e(subtitle)}</td>
            <th>响应</th><td>{_e(response)}</td></tr>
        <tr><th>系统推断</th><td>{_e(os_guess)}</td>
            <th>判断依据</th><td>{_e(host.device_reason or "—")}</td></tr>
      </table>
      <div class="subblock"><div class="subtitle">开放服务</div><div class="chips">{port_chips}</div></div>
      {web_block}
      {banner_block}
      <div class="subblock"><div class="subtitle">发现证据</div><ul>{evidence}</ul></div>
      {note_block}
    </article>
    """


def build_html(result: ScanResult) -> str:
    """生成完全自包含的 HTML 报告（无外部 CSS/JS/字体依赖）。"""
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    iface = result.context.interface
    interface_text = (
        f"{iface.alias}（{iface.description}） · {iface.ip}/{iface.prefix}"
        if iface
        else "未识别"
    )
    warnings = "".join(f"<li>{_e(w)}</li>" for w in result.context.warnings)
    warnings_block = (
        f'<section class="alert amber"><h2>扫描环境提示</h2><ul>{warnings}</ul></section>'
        if warnings
        else ""
    )
    host_cards = "".join(_host_card(h, result.context) for h in result.hosts)
    if not host_cards:
        host_cards = '<div class="empty">本次扫描没有发现明显在线的设备。</div>'

    free_groups = _group_ips([f.ip for f in result.free_ips])
    free_chips = "".join(
        f'<span class="chip free" title="{_e(f.advice)}">{_e(f.ip)}</span>'
        for f in result.free_ips
    )
    reserved_chips = "".join(f'<span class="chip reserved">{_e(ip)}</span>' for ip in result.reserved_ips)
    dhcp = result.context.dhcp_server or "未识别"
    gateway = result.context.gateway or "未识别"
    dns = "、".join(result.context.dns) if result.context.dns else "未识别"
    local_ip = result.context.local_ip or "未识别"
    port_count = result.ports_tested
    discovery_port_count, full_port_count = _port_scopes(result)
    free_hint = (
        f"连续地址段：{_e('、'.join(free_groups[:40]))}"
        if free_groups
        else "—"
    )
    if len(free_groups) > 40:
        free_hint += " …"
    free_states = {f.state for f in result.free_ips}
    arp_unverified = any("ARP 未核验" in s for s in free_states)
    if not result.context.direct_link:
        free_sub = "非直连目标，仅完成三层探测"
    elif arp_unverified:
        free_sub = "含 ARP 未核验地址，不能直接配置"
    else:
        free_sub = "候选地址，不能直接视为空闲"
    free_heading = "未发现占用的候选地址"
    if not result.context.direct_link or arp_unverified:
        free_heading = "候选地址（核验未完成）"
    if not result.context.direct_link:
        free_scope = (
            "目标不是本机直连网段，无法做 ARP 二层核验；"
            f"以下仅表示三层 ICMP/TCP 未发现响应（全段探测 {discovery_port_count} 个端口）。"
        )
    elif arp_unverified:
        free_scope = (
            "本次 ARP 查询失败，二层占用情况未知；"
            f"全段仅探测 {discovery_port_count} 个常见 TCP 端口。"
        )
    else:
        free_scope = (
            f"判断依据：ICMP 无应答 + ARP 无记录 + 全段探测 {discovery_port_count} 个常见 TCP 端口均未开放"
            f"（在线设备另补扫至 {full_port_count} 个）。这只是“扫描时未见占用”，不是空闲证明。"
        )
    errors_block = ""
    if result.errors:
        errors_block = (
            '<section class="alert amber"><h2>扫描异常</h2><ul>'
            + "".join(f"<li>{_e(e)}</li>" for e in result.errors)
            + "</ul><p class=\"muted\">出现异常时，“未发现占用”的可靠性会下降，请修复后重扫。</p></section>"
        )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(APP_NAME)} · {_e(result.target)} 扫描报告</title>
<style>
:root {{
  --navy:#0b1f3a; --blue:#1677ff; --ink:#162033; --muted:#64748b;
  --line:#e4eaf2; --bg:#f3f6fa; --white:#fff; --green:#0f9f6e;
  --amber:#b45309; --red:#c2410c;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink);
  font-family:"Microsoft YaHei UI","Microsoft YaHei","PingFang SC",-apple-system,Segoe UI,sans-serif;
  line-height:1.6; font-size:14px; }}
.hero {{ background:linear-gradient(125deg,#07182c 0%,#0b2b52 55%,#15498a 100%);
  color:#fff; padding:34px 40px 30px; }}
.brand {{ font-size:12px; letter-spacing:.28em; color:#8db7ef; font-weight:700; }}
.hero h1 {{ margin:8px 0 8px; font-size:30px; line-height:1.25; letter-spacing:.02em; }}
.hero .meta {{ color:#c3d8f3; font-size:13px; }}
.hero .meta span {{ margin-right:22px; white-space:nowrap; }}
main {{ max-width:1120px; margin:0 auto; padding:24px 20px 48px; }}
.cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-top:-46px; }}
.card {{ background:var(--white); border:1px solid var(--line); border-radius:14px;
  padding:18px 18px 15px; box-shadow:0 10px 30px rgba(15,35,70,.07); }}
.card .label {{ color:var(--muted); font-size:12px; }}
.card .value {{ font-size:27px; font-weight:700; margin-top:4px; letter-spacing:.01em; }}
.card .sub {{ color:var(--muted); font-size:12px; margin-top:4px; }}
section {{ background:var(--white); border:1px solid var(--line); border-radius:14px;
  padding:22px 24px; margin-top:20px; box-shadow:0 4px 18px rgba(20,40,80,.04); }}
h2 {{ margin:0 0 14px; font-size:18px; }}
h3 {{ margin:0 0 8px; font-size:15px; }}
.alert {{ border-left:4px solid var(--blue); }}
.alert.amber {{ border-left-color:#d97706; background:#fffaf0; }}
.alert.red {{ border-left-color:#dc2626; background:#fff5f5; }}
.alert ul {{ margin:8px 0 0 20px; padding:0; }}
.alert li {{ margin:4px 0; }}
.muted {{ color:var(--muted); }}
.mono {{ font-family:Consolas,"Cascadia Mono",monospace; font-size:12.5px; }}
.badge {{ display:inline-block; border-radius:999px; padding:2px 9px; font-size:12px;
  vertical-align:middle; margin-left:8px; }}
.badge.ok {{ background:#e8f8f1; color:#087f5b; }}
.badge.warn {{ background:#fff4e5; color:#b45309; }}
.badge.neutral {{ background:#eef3fb; color:#3b5b85; }}
.badge.type {{ background:#eaf2ff; color:#1458b4; }}
.host {{ border:1px solid var(--line); border-radius:12px; padding:18px 20px; margin:14px 0;
  background:linear-gradient(180deg,#fbfdff 0%,#fff 100%); }}
.host-head {{ display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; }}
.ip {{ font-size:21px; font-weight:700; font-family:Consolas,monospace; color:#0b2b52; }}
.confidence {{ color:var(--muted); font-size:12px; }}
.host-sub {{ color:var(--muted); margin:6px 0 12px; }}
.kv {{ width:100%; border-collapse:collapse; margin:10px 0; table-layout:fixed; }}
.kv th, .kv td {{ border-bottom:1px dashed #edf1f7; text-align:left; padding:7px 8px;
  vertical-align:top; word-break:break-word; }}
.kv th {{ width:14%; color:var(--muted); font-weight:500; background:#fafcff; }}
.kv td {{ width:36%; }}
.subblock {{ margin-top:14px; }}
.subtitle {{ font-size:12px; font-weight:700; color:#3b5b85; letter-spacing:.04em; margin-bottom:6px; }}
.subblock ul {{ margin:4px 0 0 20px; padding:0; }}
.subblock li {{ margin:3px 0; }}
.chips {{ display:flex; flex-wrap:wrap; gap:7px; }}
.chip {{ display:inline-block; border:1px solid #dbe5f1; background:#f8fbff; border-radius:7px;
  padding:4px 9px; font-family:Consolas,"Cascadia Mono",monospace; font-size:12.5px; }}
.chip.port {{ border-color:#cfe1ff; background:#eef6ff; color:#0d4f9e; }}
.chip.free {{ border-color:#c9ecd9; background:#f1fbf5; color:#0b7351; }}
.chip.reserved {{ border-color:#e5e7eb; background:#f7f8fa; color:#6b7280; }}
.note {{ border-left:3px solid #f59e0b; padding-left:12px; }}
.online {{ color:var(--green); font-weight:700; }}
.empty {{ padding:18px; color:var(--muted); background:#f8fafc; border-radius:9px; }}
.steps {{ display:grid; grid-template-columns:repeat(2,1fr); gap:14px; }}
.step {{ border:1px solid var(--line); border-radius:10px; padding:14px 16px; background:#fbfdff; }}
.step .n {{ width:24px; height:24px; border-radius:50%; background:var(--blue); color:#fff;
  display:inline-flex; align-items:center; justify-content:center; font-weight:700; font-size:12px;
  margin-right:8px; }}
.step b {{ color:#0b2b52; }}
.foot {{ text-align:center; color:#8a98aa; font-size:12px; padding:16px 0 0; }}
@media (max-width:900px) {{
  .cards {{ grid-template-columns:repeat(2,1fr); }}
  .kv, .kv tr, .kv th, .kv td {{ display:block; width:auto; }}
  .kv th {{ border-bottom:none; padding-bottom:0; }}
  .steps {{ grid-template-columns:1fr; }}
  .hero {{ padding:26px 20px; }}
}}
@media print {{
  body {{ background:#fff; }}
  .hero {{ background:#0b1f3a !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .card, section, .host {{ box-shadow:none; break-inside:avoid; }}
  main {{ max-width:none; }}
}}
</style>
</head>
<body>
<header class="hero">
  <div class="brand">{_e(APP_NAME_EN)} · LAN INVENTORY REPORT</div>
  <h1>{_e(APP_NAME)}：{_e(result.target)} 扫描报告</h1>
  <div class="meta">
    <span>生成时间：{_e(generated)}</span>
    <span>扫描模式：{_e(_mode_label(result.mode))}</span>
    <span>耗时：{result.duration_sec:.1f} 秒</span>
    <span>工具版本：v{_e(__version__)}</span>
  </div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="label">扫描范围</div><div class="value">{_e(result.target)}</div>
      <div class="sub">共 {result.total_addresses} 个可用地址</div></div>
    <div class="card"><div class="label">发现使用中</div><div class="value">{result.used_count}</div>
      <div class="sub">其中仅 ARP 记录 {_risk_host_count(result)} 台</div></div>
    <div class="card"><div class="label">未发现占用</div><div class="value">{result.free_count}</div>
      <div class="sub">{_e(free_sub)}</div></div>
    <div class="card"><div class="label">探测端口</div><div class="value">{port_count}</div>
      <div class="sub">全段 {discovery_port_count} 个 / 设备补扫至 {full_port_count} 个</div></div>
  </div>

  <section class="alert red">
    <h2>先看这里：未发现占用 ≠ 可以直接配置</h2>
    <p>扫描器只能证明“本次扫描时，这个地址没有响应 ICMP、没有出现在 ARP 表、也没有开放我们探测的 TCP 端口”。
    它无法看到 DHCP 地址池、租约、静态保留，也无法唤醒休眠设备。直接把候选 IP 写死在设备上，
    仍可能与后来上线的设备发生地址冲突。</p>
    <p><b>推荐做法：</b>优先在 DHCP 服务器 {_e(dhcp)} 中做“地址保留 / MAC 绑定”；如果必须静态配置，
    先确认该地址不在 DHCP 池、租约和保留列表中，再在配置后重新扫描一次确认。</p>
  </section>

  {warnings_block}
  {errors_block}

  <section>
    <h2>在线 / 疑似占用设备（{result.used_count} 台）</h2>
    <p class="muted">“仅 ARP 记录”表示只有二层地址记录，可能是休眠、离线或防火墙设备；保守起见仍按占用处理。</p>
    {host_cards}
  </section>

  <section>
    <h2>{_e(free_heading)}（{result.free_count} 个）</h2>
    <p class="muted">{free_scope}</p>
    <div class="chips">{free_chips or '<span class="muted">无</span>'}</div>
    <p class="muted" style="margin-top:12px">地址段速览：{free_hint}</p>
    {f'<div class="subblock"><div class="subtitle">网络/广播保留地址</div><div class="chips">{reserved_chips}</div></div>' if reserved_chips else ''}
  </section>

  <section>
    <h2>如何安全启用一个候选 IP</h2>
    <div class="steps">
      <div class="step"><span class="n">1</span><b>查 DHCP 地址池</b><br>登录 {_e(dhcp)}，查看地址池起止、当前租约与静态保留。不要只凭扫描结果判断。</div>
      <div class="step"><span class="n">2</span><b>优先做地址保留</b><br>把设备 MAC 绑定到指定 IP，让 DHCP 统一管理，避免以后冲突。</div>
      <div class="step"><span class="n">3</span><b>静态配置要避开池</b><br>如必须静态，选择地址池外、无保留记录、非网关/DNS/本机的地址，并记录在案。</div>
      <div class="step"><span class="n">4</span><b>配置后再扫描</b><br>设置完成后再跑一次本工具，确认该 IP 稳定在线且没有其他设备冲突。</div>
    </div>
  </section>

  <section>
    <h2>网络环境</h2>
    <table class="kv">
      <tr><th>本机网卡</th><td colspan="3">{_e(interface_text)}</td></tr>
      <tr><th>本机 IP</th><td>{_e(local_ip)}</td><th>默认网关</th><td>{_e(gateway)}</td></tr>
      <tr><th>DHCP 服务器</th><td>{_e(dhcp)}</td><th>DNS</th><td>{_e(dns)}</td></tr>
      <tr><th>目标网段</th><td>{_e(result.target)}</td><th>直连二层</th><td>{'是' if result.context.direct_link else '否（结果可能漏报）'}</td></tr>
      <tr><th>开始时间</th><td>{_e(result.started_at)}</td><th>结束时间</th><td>{_e(result.finished_at)}</td></tr>
    </table>
    <p class="muted">需要手工配置时的参考参数：子网掩码 {_e(iface.mask if iface else '请以实际网段为准')}，
    默认网关 {_e(gateway)}，DNS {_e(dns)}。IP 本身请按上面的安全流程选择。</p>
  </section>

  <section class="alert amber">
    <h2>扫描局限与安全边界</h2>
    <ul>
      <li>只探测 TCP 常见端口，不探测 UDP（如 SNMP、部分 DHCP、mDNS 服务可能漏掉）。</li>
      <li>ICMP 被防火墙拦截的主机，仍可能通过 ARP 或开放端口被发现；但休眠/关机设备无法被发现。</li>
      <li>如果目标不是本机直连网段，ARP 探测无效，结果会明显漏报。</li>
      <li>本工具不尝试登录、不猜口令、不利用漏洞；请只扫描你已获授权的网络。</li>
    </ul>
  </section>

  <div class="foot">
    {_e(APP_NAME)} v{_e(__version__)} · 生成于 {_e(generated)} · 请妥善保管报告中的网络资产信息
  </div>
</main>
</body>
</html>
"""


def write_html(result: ScanResult, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(build_html(result), encoding="utf-8")
    return target


def build_csv(result: ScanResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    def write_row(values: list[object]) -> None:
        writer.writerow([_csv_safe(value) for value in values])

    write_row(
        [
            "类型",
            "IP",
            "状态",
            "设备类型",
            "主机名",
            "MAC",
            "厂商",
            "TTL",
            "延迟ms",
            "开放端口",
            "服务摘要",
            "角色",
            "发现证据",
            "安全提示",
            "判断/建议",
        ]
    )
    for host in result.hosts:
        write_row(
            [
                "已占用",
                host.ip,
                host.state,
                host.device_type,
                host.hostname or host.netbios,
                host.mac,
                host.vendor,
                host.ttl or "",
                f"{host.rtt_ms:.1f}" if host.rtt_ms is not None else "",
                " ".join(str(p.port) for p in host.ports),
                host.service_summary,
                " / ".join(host.roles),
                " | ".join(host.evidence),
                " | ".join(host.notes),
                "",
            ]
        )
    for free in result.free_ips:
        write_row(
            [
                "候选地址（未核验）",
                free.ip,
                free.state,
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                free.evidence,
                free.risk,
                free.advice,
            ]
        )
    for reserved in result.reserved_ips:
        write_row(
            [
                "网络/广播地址",
                reserved,
                "保留",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "不可分配给主机",
            ]
        )
    return buffer.getvalue()


def write_csv(result: ScanResult, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    # newline="" 防止 Windows 把 csv.writer 的 \r\n 再翻译成 \r\r\n。
    # utf-8-sig 带 BOM，Excel 打开中文不乱码。
    with open(target, "w", encoding="utf-8-sig", newline="") as handle:
        handle.write(build_csv(result))
    return target


def write_json(result: ScanResult, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return target


def default_report_path(result: ScanResult, suffix: str = "html", reports_dir: Path | None = None) -> Path:
    if reports_dir is None:
        reports_dir = Path(__file__).resolve().parent.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^0-9A-Za-z._-]+", "_", result.target.replace("/", "_").replace(":", "-"))
    return reports_dir / f"局域网扫描报告_{safe_target}_{stamp}.{suffix}"


def report_stem(result: ScanResult) -> str:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^0-9A-Za-z._-]+", "_", result.target.replace("/", "_"))
    return f"局域网扫描报告_{safe_target}_{stamp}"


__all__ = [
    "build_csv",
    "build_html",
    "default_report_path",
    "report_stem",
    "write_csv",
    "write_html",
    "write_json",
]
