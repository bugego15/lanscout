"""对比 / 台账 / mDNS 解析的离线单元测试（不访问网络）。"""

from __future__ import annotations

import csv
import io
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

from lanscout.compare import (
    build_diff_html,
    build_inventory,
    compare_scans,
    load_scan,
    render_diff_text,
    save_snapshot,
    write_inventory_csv,
)
from lanscout.discovery import console_encoding
from lanscout.fingerprint import _encode_dns_name, _parse_mdns_response


def _host(ip, mac, ports=(445,), hostname="", vendor="", dtype="Windows 电脑", osg=""):
    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "device_type": dtype,
        "os_guess": osg,
        "ports": [{"port": p, "service": "", "banner": ""} for p in ports],
    }


def _scan(hosts, finished="2026-11-09 10:00:00", target="192.168.1.0/24"):
    return {"target": target, "finished_at": finished, "hosts": hosts}


class CompareTests(unittest.TestCase):
    def test_added_and_removed(self):
        old = _scan([_host("192.168.1.10", "AA:AA:AA:AA:AA:01")])
        new = _scan([_host("192.168.1.20", "AA:AA:AA:AA:AA:02")], finished="2026-11-09 11:00:00")
        diff = compare_scans(old, new)
        self.assertEqual([s.ip for s in diff.added], ["192.168.1.20"])
        self.assertEqual([s.ip for s in diff.removed], ["192.168.1.10"])
        self.assertFalse(diff.changed)
        self.assertEqual(diff.unchanged, 0)
        self.assertTrue(diff.has_changes)

    def test_port_change_is_reported(self):
        old = _scan([_host("192.168.1.10", "AA:AA:AA:AA:AA:01", ports=(445,))])
        new = _scan([_host("192.168.1.10", "AA:AA:AA:AA:AA:01", ports=(445, 3389))])
        diff = compare_scans(old, new)
        self.assertEqual(len(diff.changed), 1)
        change = diff.changed[0]
        self.assertEqual(change.opened, [3389])
        self.assertEqual(change.closed, [])
        self.assertIn("3389", change.summary())
        self.assertIn("远程桌面", change.summary())

    def test_ip_change_keeps_device_identity(self):
        """同一 MAC 换 IP 不能被算成"一台消失 + 一台新增"。"""
        old = _scan([_host("192.168.1.10", "AA:AA:AA:AA:AA:01")])
        new = _scan([_host("192.168.1.87", "AA:AA:AA:AA:AA:01")])
        diff = compare_scans(old, new)
        self.assertFalse(diff.added)
        self.assertFalse(diff.removed)
        self.assertEqual(len(diff.changed), 1)
        fields = dict((name, (o, n)) for name, o, n in diff.changed[0].fields)
        self.assertEqual(fields["IP"], ("192.168.1.10", "192.168.1.87"))

    def test_no_change(self):
        scan = _scan([_host("192.168.1.10", "AA:AA:AA:AA:AA:01")])
        diff = compare_scans(scan, scan)
        self.assertFalse(diff.has_changes)
        self.assertEqual(diff.unchanged, 1)
        self.assertIn("没有设备变化", diff.headline())

    def test_empty_hostname_is_not_a_change(self):
        """主机名一侧为空只是"没解析出来"，不该报成设备变化。"""
        old = _scan([_host("192.168.1.10", "AA:AA:AA:AA:AA:01", hostname="localhost")])
        new = _scan([_host("192.168.1.10", "AA:AA:AA:AA:AA:01", hostname="")])
        diff = compare_scans(old, new)
        self.assertFalse(diff.has_changes)
        self.assertEqual(diff.unchanged, 1)

    def test_real_hostname_change_is_reported(self):
        old = _scan([_host("192.168.1.10", "AA:AA:AA:AA:AA:01", hostname="DESKTOP-A")])
        new = _scan([_host("192.168.1.10", "AA:AA:AA:AA:AA:01", hostname="DESKTOP-B")])
        diff = compare_scans(old, new)
        self.assertEqual(len(diff.changed), 1)
        self.assertIn("DESKTOP-A → DESKTOP-B", diff.changed[0].summary())

    def test_text_mentions_scope_mismatch(self):
        old = _scan([], target="192.168.1.0/24")
        new = _scan([], target="10.0.0.0/24")
        text = render_diff_text(compare_scans(old, new))
        self.assertIn("范围不同", text)

    def test_diff_html_escapes_content(self):
        old = _scan([])
        new = _scan([_host("192.168.1.50", "AA:AA:AA:AA:AA:09", vendor="<script>x</script>")])
        page = build_diff_html(compare_scans(old, new))
        self.assertNotIn("<script>x</script>", page)
        self.assertIn("&lt;script&gt;", page)


class InventoryTests(unittest.TestCase):
    def test_aggregates_same_mac_across_scans(self):
        first = _scan(
            [_host("192.168.1.10", "AA:BB:CC:DD:EE:01", ports=(445,), vendor="HP")],
            finished="2026-11-01 09:00:00",
        )
        second = _scan(
            [_host("192.168.1.77", "AA:BB:CC:DD:EE:01", ports=(445, 3389), vendor="HP")],
            finished="2026-11-09 09:00:00",
        )
        rows = build_inventory([second, first])  # 乱序输入也要按时间聚合
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.ips, ["192.168.1.10", "192.168.1.77"])
        self.assertEqual(row.ports, {445, 3389})
        self.assertEqual(row.scans, 2)
        self.assertEqual(row.first_seen, "2026-11-01 09:00:00")
        self.assertEqual(row.last_seen, "2026-11-09 09:00:00")
        self.assertEqual(row.vendor, "HP")

    def test_csv_has_bom_and_header(self):
        rows = build_inventory([_scan([_host("192.168.1.10", "AA:BB:CC:DD:EE:01")])])
        with tempfile.TemporaryDirectory() as tmp:
            path = write_inventory_csv(rows, Path(tmp) / "资产台账.csv")
            raw = path.read_bytes()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
            text = raw.decode("utf-8-sig")
            header = next(csv.reader(io.StringIO(text)))
            self.assertEqual(header[0], "MAC")
            self.assertIn("首次发现", header)

    def test_snapshot_roundtrip(self):
        scan = _scan([_host("192.168.1.10", "AA:BB:CC:DD:EE:01")])
        with tempfile.TemporaryDirectory() as tmp:
            path = save_snapshot(scan, tmp)
            self.assertTrue(path.exists())
            self.assertEqual(path.parent.name, "history")
            self.assertEqual(load_scan(path)["target"], scan["target"])
            from lanscout.compare import latest_snapshot

            self.assertEqual(latest_snapshot(tmp), path)
            self.assertIsNone(latest_snapshot(tmp, exclude=path))

    def test_load_scan_rejects_other_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.json"
            path.write_text('{"foo": 1}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_scan(path)


def _rr(name: str, rtype: int, rdata: bytes, cls: int = 1, ttl: int = 120) -> bytes:
    return _encode_dns_name(name) + struct.pack("!HHIH", rtype, cls, ttl, len(rdata)) + rdata


def _mdns(records: list[bytes]) -> bytes:
    return struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


class MdnsTests(unittest.TestCase):
    def test_a_record_maps_ip_to_local_name(self):
        records = [
            _rr("myhost.local", 1, socket.inet_aton("192.168.1.50")),
        ]
        names: dict[str, str] = {}
        _parse_mdns_response(_mdns(records), names, "192.168.1.50")
        self.assertEqual(names.get("192.168.1.50"), "myhost.local")

    def test_ptr_instance_used_as_fallback(self):
        """只回 PTR + SRV、没有 A 记录时，也要能拿到名字（修复前的死代码路径）。"""
        instance = "某某的 MacBook._airplay._tcp.local"
        records = [
            _rr("_airplay._tcp.local", 12, _encode_dns_name(instance)),
            _rr(instance, 33, struct.pack("!HHH", 0, 0, 7000) + _encode_dns_name("mbp.local")),
        ]
        names: dict[str, str] = {}
        _parse_mdns_response(_mdns(records), names, "192.168.1.60")
        self.assertEqual(names.get("192.168.1.60"), "mbp.local")

    def test_service_type_ptr_does_not_leak(self):
        """_services._dns-sd._udp.local → _http._tcp.local 这类应答不能当主机名。"""
        records = [
            _rr("_services._dns-sd._udp.local", 12, _encode_dns_name("_http._tcp.local")),
        ]
        names: dict[str, str] = {}
        _parse_mdns_response(_mdns(records), names, "192.168.1.70")
        self.assertEqual(names, {})


class EncodingTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "console_encoding 的 OEM 分支只在 Windows 生效")
    def test_console_encoding_returns_codec(self):
        encoding = console_encoding()
        self.assertIsInstance(encoding, str)
        # 必须能真正解码 GBK 的“动态”，而不是抛异常或返回 utf-8
        self.assertEqual("动态".encode("gbk").decode(encoding), "动态")


if __name__ == "__main__":
    unittest.main()
