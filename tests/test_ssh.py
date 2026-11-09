"""SSH 模块的离线单元测试（不建立真实连接）。"""

from __future__ import annotations

import unittest

from lanscout.ssh import ExecResult, SshSession, _parse_ssh_target, HAS_PARAMIKO


class ParseTargetTests(unittest.TestCase):
    def test_plain_host(self):
        self.assertEqual(_parse_ssh_target("192.168.1.42", "root"), ("192.168.1.42", 22, "root"))

    def test_user_and_port(self):
        self.assertEqual(
            _parse_ssh_target("admin@192.168.1.42:2222", "root"),
            ("192.168.1.42", 2222, "admin"),
        )

    def test_port_only(self):
        self.assertEqual(_parse_ssh_target("10.0.0.5:2200", "root"), ("10.0.0.5", 2200, "root"))

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            _parse_ssh_target("10.0.0.5:abc", "root")

    def test_empty(self):
        with self.assertRaises(ValueError):
            _parse_ssh_target("", "root")


class ExecResultTests(unittest.TestCase):
    def test_text_merges_stderr(self):
        result = ExecResult(command="x", exit_code=1, stdout="ok", stderr="boom")
        self.assertIn("ok", result.text())
        self.assertIn("boom", result.text())
        self.assertFalse(result.ok)

    def test_text_truncates_long_output(self):
        result = ExecResult(command="x", exit_code=0, stdout="a" * 5000)
        text = result.text(max_chars=100)
        self.assertIn("已截断", text)
        self.assertLess(len(text), 300)

    def test_ok_flag(self):
        self.assertTrue(ExecResult(command="x", exit_code=0, stdout="").ok)


class SessionTests(unittest.TestCase):
    def test_describe_uses_facts(self):
        session = SshSession(host="192.168.1.42", username="root")
        session.facts = {"HOST": "ATK-DLRK3568", "KERNEL": "Linux 4.19.232", "ARCH": "aarch64"}
        text = session.describe()
        self.assertIn("root@192.168.1.42:22", text)
        self.assertIn("ATK-DLRK3568", text)
        self.assertIn("aarch64", text)

    def test_password_is_not_in_repr(self):
        """口令不能出现在 repr 里，避免被日志顺手打出来。"""
        session = SshSession(host="192.168.1.42", username="root", _password="s3cret")
        self.assertNotIn("s3cret", repr(session))

    def test_not_connected_raises(self):
        session = SshSession(host="192.168.1.42")
        self.assertFalse(session.connected)
        from lanscout.ssh import SshError

        with self.assertRaises(SshError):
            session.exec("uname -a")

    @unittest.skipIf(HAS_PARAMIKO, "仅在缺少 paramiko 的环境检查降级提示")
    def test_missing_paramiko_message(self):  # pragma: no cover - 取决于环境
        from lanscout.ssh import SshUnavailable

        with self.assertRaises(SshUnavailable):
            SshSession(host="192.168.1.42").connect()


if __name__ == "__main__":
    unittest.main()
