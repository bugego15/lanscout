"""不依赖网络的单元测试。

运行：
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from lanscout.discovery import service_label, ttl_to_os
from lanscout.models import (
    FreeIP,
    HostResult,
    InterfaceInfo,
    NetworkContext,
    PortInfo,
    ScanResult,
    WebPage,
)
from lanscout.netconfig import (
    filter_range_reserved,
    find_matching_interface,
    parse_target,
    target_is_direct,
)
from lanscout.oui import normalize_mac, vendor_for_mac
from lanscout.report import build_csv, build_html, write_csv


def sample_interface() -> InterfaceInfo:
    return InterfaceInfo(
        index=16,
        alias="以太网",
        description="Intel Ethernet",
        ip="192.168.1.50",
        mask="255.255.255.0",
        prefix=24,
        gateway="192.168.1.1",
        dhcp_server="192.168.1.1",
        dhcp_enabled=True,
        dns=["192.168.1.1"],
        mac="02:AA:BB:CC:DD:EE",
    )


class TargetParsingTests(unittest.TestCase):
    def test_cidr(self) -> None:
        target = parse_target("192.168.1.0/24")
        self.assertEqual(target.cidr, "192.168.1.0/24")
        self.assertEqual(target.count, 254)
        self.assertIn("192.168.1.1", target.hosts)
        self.assertNotIn("192.168.1.255", target.hosts)
        self.assertEqual(target.reserved, ["192.168.1.0", "192.168.1.255"])

    def test_range_shorthand(self) -> None:
        target = parse_target("192.168.1.10-13")
        self.assertEqual(target.count, 4)
        self.assertEqual(target.hosts[0], "192.168.1.10")
        self.assertEqual(target.hosts[-1], "192.168.1.13")

    def test_single_ip(self) -> None:
        target = parse_target("192.168.1.7")
        self.assertEqual(target.hosts, ["192.168.1.7"])
        self.assertEqual(target.cidr, "192.168.1.7/32")

    def test_invalid(self) -> None:
        with self.assertRaises(ValueError):
            parse_target("192.168.1.999")
        with self.assertRaises(ValueError):
            parse_target("not-an-ip")

    def test_huge_cidr_rejected_before_expanding(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            parse_target("10.0.0.0/8")
        self.assertIn("超过上限", str(ctx.exception))
        with self.assertRaises(ValueError):
            parse_target("172.16.0.0/12")

    def test_range_reserved_addresses_filtered(self) -> None:
        iface = sample_interface()
        target = parse_target("192.168.1.0-255")
        self.assertEqual(target.count, 256)
        moved = filter_range_reserved(target, iface)
        self.assertEqual(moved, ["192.168.1.0", "192.168.1.255"])
        self.assertEqual(target.count, 254)
        self.assertNotIn("192.168.1.0", target.hosts)
        self.assertNotIn("192.168.1.255", target.hosts)
        self.assertIn("192.168.1.0", target.reserved)

    def test_direct_link(self) -> None:
        iface = sample_interface()
        target = parse_target("192.168.1.0/24")
        self.assertIs(find_matching_interface(target, [iface]), iface)
        self.assertTrue(target_is_direct(target, iface))
        remote = parse_target("10.0.0.0/24")
        self.assertFalse(target_is_direct(remote, iface))


class DiscoveryHelperTests(unittest.TestCase):
    def test_service_label(self) -> None:
        self.assertIn("HTTP", service_label(80))
        self.assertIn("RDP", service_label(3389))

    def test_ttl(self) -> None:
        self.assertEqual(ttl_to_os(64), "Linux / Unix / 网络设备")
        self.assertEqual(ttl_to_os(128), "Windows")
        self.assertEqual(ttl_to_os(None), "未知")


class OuiTests(unittest.TestCase):
    def test_normalize(self) -> None:
        self.assertEqual(normalize_mac("00-0c-29-aa-bb-cc"), "00:0C:29:AA:BB:CC")

    def test_known_vendor(self) -> None:
        self.assertIn("VMware", vendor_for_mac("00:0C:29:AA:BB:CC"))


def sample_result() -> ScanResult:
    iface = sample_interface()
    context = NetworkContext(
        interface=iface,
        target="192.168.1.0/24",
        local_ip=iface.ip,
        gateway=iface.gateway,
        dhcp_server=iface.dhcp_server,
        dns=list(iface.dns),
        direct_link=True,
    )
    host = HostResult(
        ip="192.168.1.1",
        state="在线",
        mac="02:11:22:33:44:55",
        vendor="Demo Networks",
        ping_ok=True,
        rtt_ms=0.8,
        ttl=64,
        hostname="<script>alert(1)</script>",
        http_title="示例路由器管理页面",
        device_type="路由器 / 网关",
        device_reason="IP 与本机默认网关一致",
        os_guess="Linux / Unix / 网络设备",
        service_summary="Web 管理「示例路由器管理页面」 · FTP",
        confidence="高",
        is_gateway=True,
        is_dhcp=True,
        ports=[PortInfo(port=80, service="HTTP Web 服务")],
        web_pages=[
            WebPage(
                port=80,
                scheme="http",
                url="http://192.168.1.1:80/",
                status=200,
                title="示例路由器管理页面",
                server="ty_httpd",
            )
        ],
        evidence=["ICMP 有应答", "开放端口 80"],
        notes=["测试提示"],
    )
    free = FreeIP(
        ip="192.168.1.2",
        evidence="ICMP 无应答；ARP 无记录",
        advice="先核验 DHCP 地址池",
        risk="设备休眠可能漏检",
        checked_ports=29,
    )
    return ScanResult(
        target="192.168.1.0/24",
        mode="standard",
        started_at="2026-01-01 00:00:00",
        finished_at="2026-01-01 00:00:10",
        duration_sec=10.0,
        total_addresses=254,
        scanned_addresses=254,
        hosts=[host],
        free_ips=[free],
        reserved_ips=["192.168.1.0", "192.168.1.255"],
        context=context,
        ports_tested=47,
    )


class ReportTests(unittest.TestCase):
    def test_html_escapes_user_content(self) -> None:
        report = build_html(sample_result())
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report)
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertIn("未发现占用 ≠ 可以直接配置", report)
        self.assertIn("192.168.1.2", report)

    def test_free_section_uses_discovery_port_scope(self) -> None:
        report = build_html(sample_result())
        self.assertIn("全段探测 29 个常见 TCP 端口", report)
        self.assertIn("在线设备另补扫至 47 个", report)
        self.assertNotIn("ARP 无记录 + 47 个", report)

    def test_csv_contains_both_sections(self) -> None:
        csv_text = build_csv(sample_result())
        self.assertIn("已占用", csv_text)
        self.assertIn("候选地址（未核验）", csv_text)
        self.assertIn("192.168.1.1", csv_text)
        self.assertIn("192.168.1.2", csv_text)
        self.assertIn("网络/广播地址", csv_text)

    def test_csv_roundtrip_no_double_crlf(self) -> None:
        result = sample_result()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "result.csv"
            write_csv(result, path)
            raw = path.read_bytes()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\r\r\n", raw)
            with open(path, "r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(len(rows), 5)  # 表头 + 1 已占用 + 1 候选 + 2 保留
            self.assertFalse(any(row == [] for row in rows))

    def test_csv_formula_injection_neutralized(self) -> None:
        result = sample_result()
        result.hosts[0].hostname = "=cmd|' /C calc'!A0"
        csv_text = build_csv(result)
        self.assertIn("'=cmd", csv_text)
        self.assertNotIn(",=cmd", csv_text)

    def test_report_marks_unverified_free_addresses(self) -> None:
        result = sample_result()
        result.free_ips[0].state = "未发现占用（ARP 未核验）"
        result.errors = ["初始 ARP 查询失败：测试错误"]
        report = build_html(result)
        self.assertIn("候选地址（核验未完成）", report)
        self.assertIn("扫描异常", report)
        self.assertIn("ARP 未核验", report)

    def test_report_marks_non_direct_target(self) -> None:
        result = sample_result()
        result.context.direct_link = False
        result.free_ips[0].state = "未核验（非直连网段）"
        report = build_html(result)
        self.assertIn("候选地址（核验未完成）", report)
        self.assertIn("非直连目标，仅完成三层探测", report)


if __name__ == "__main__":
    unittest.main()
