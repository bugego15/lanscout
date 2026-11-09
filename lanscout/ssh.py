"""可选的 SSH 登录能力。

设计红线（和其他扫描功能保持一致）：

* **只对用户显式指定的一台设备建连**，绝不在扫描结果上批量尝试口令 ——
  那等于把巡网工具变成撞库工具，还会把域账户锁死；
* **口令只存在于内存**，默认不落盘、不写日志、不进报告；
* 执行过的命令会留在会话历史里，便于回溯"我到底做了什么"；
* 没装 paramiko 时核心功能完全不受影响，只是这个入口不可用。

依赖：``pip install paramiko``（可选）。
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:  # pragma: no cover - 取决于环境是否安装
    import paramiko

    HAS_PARAMIKO = True
except Exception:  # pragma: no cover
    paramiko = None  # type: ignore[assignment]
    HAS_PARAMIKO = False

DEFAULT_TIMEOUT = 8.0


class SshError(RuntimeError):
    """SSH 相关错误，message 直接面向用户。"""


class SshAuthError(SshError):
    """用户名/口令被拒绝。"""


class SshUnavailable(SshError):
    """缺少 paramiko 依赖。"""


@dataclass
class ExecResult:
    """一条命令的执行结果。"""

    command: str
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def text(self, max_chars: int = 20000) -> str:
        body = self.stdout
        if self.stderr.strip():
            body += ("\n" if body else "") + "[stderr]\n" + self.stderr
        if len(body) > max_chars:
            body = body[:max_chars] + f"\n…输出过长，已截断（共 {len(body)} 字符）"
        return body.rstrip()

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration": round(self.duration, 3),
        }


@dataclass
class RemoteFile:
    name: str
    path: str
    size: int = 0
    is_dir: bool = False
    mode: str = ""
    mtime: str = ""


@dataclass
class SshSession:
    """一条到单台设备的 SSH 会话（口令只在内存里）。"""

    host: str
    port: int = 22
    username: str = "root"
    _password: str = field(default="", repr=False)
    timeout: float = DEFAULT_TIMEOUT
    _client: Optional["paramiko.SSHClient"] = field(default=None, repr=False)
    _sftp: Optional["paramiko.SFTPClient"] = field(default=None, repr=False)
    fingerprint: str = ""
    facts: dict[str, str] = field(default_factory=dict)
    history: list[ExecResult] = field(default_factory=list)

    # ---------------------------------------------------------------- 连接
    def connect(self) -> None:
        if not HAS_PARAMIKO:
            raise SshUnavailable("未安装 paramiko，无法使用 SSH 功能。\n请执行：pip install paramiko")
        if not self.host:
            raise SshError("没有指定主机地址。")
        client = paramiko.SSHClient()
        # 首次连接采用 TOFU：记住指纹并把指纹展示给用户核对，不静默信任陌生主机。
        try:
            client.load_system_host_keys()
        except Exception:
            pass
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self._password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        except paramiko.AuthenticationException as exc:
            raise SshAuthError(
                f"登录被拒绝：用户名或口令不正确（{self.username}@{self.host}）。"
            ) from exc
        except paramiko.SSHException as exc:
            raise SshError(f"SSH 协商失败：{exc}") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise SshError(f"连接超时：{self.host}:{self.port} 无响应。") from exc
        except OSError as exc:
            raise SshError(f"无法连接 {self.host}:{self.port}：{exc}") from exc
        self._client = client
        try:
            key = client.get_transport().get_remote_server_key()
            self.fingerprint = f"{key.get_name()} {key.fingerprint}"
        except Exception:
            self.fingerprint = ""

    @property
    def connected(self) -> bool:
        if self._client is None:
            return False
        transport = self._client.get_transport()
        return bool(transport and transport.is_active())

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def _require(self) -> "paramiko.SSHClient":
        if not self.connected:
            raise SshError("SSH 会话已断开，请重新登录。")
        return self._client  # type: ignore[return-value]

    # ---------------------------------------------------------------- 执行
    def exec(self, command: str, timeout: float = 20.0, pty: bool = False) -> ExecResult:
        client = self._require()
        started = time.time()
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=pty)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            code = stdout.channel.recv_exit_status()
        except socket.timeout as exc:
            raise SshError(f"命令超时（{timeout:.0f} 秒）：{command}") from exc
        except Exception as exc:
            raise SshError(f"命令执行失败：{exc}") from exc
        result = ExecResult(
            command=command,
            exit_code=code,
            stdout=out,
            stderr=err,
            duration=time.time() - started,
        )
        self.history.append(result)
        return result

    def probe_facts(self) -> dict[str, str]:
        """登录后拉一组只读信息，用于在界面上确认"这是哪台机器"。"""
        script = (
            "echo HOST=$(hostname 2>/dev/null);"
            "echo KERNEL=$(uname -sr 2>/dev/null);"
            "echo ARCH=$(uname -m 2>/dev/null);"
            "echo UPTIME=$(uptime 2>/dev/null | sed 's/^ *//');"
            "echo MEM=$(free -h 2>/dev/null | awk '/Mem:/{print $2\"/\"$3\" used\"}');"
            "echo DISK=$(df -h / 2>/dev/null | awk 'NR==2{print $2\" total, \"$5\" used\"}')"
        )
        result = self.exec(script, timeout=15)
        facts: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                facts[key.strip()] = value.strip()
        self.facts = facts
        return facts

    # ---------------------------------------------------------------- 文件
    def _sftp_client(self):
        if self._sftp is None:
            self._sftp = self._require().open_sftp()
        return self._sftp

    def list_dir(self, path: str = ".") -> list[RemoteFile]:
        client = self._sftp_client()
        try:
            entries = client.listdir_attr(path)
        except FileNotFoundError as exc:
            raise SshError(f"目录不存在：{path}") from exc
        except PermissionError as exc:
            raise SshError(f"没有权限访问：{path}") from exc
        except Exception as exc:
            raise SshError(f"读取目录失败：{exc}") from exc
        items: list[RemoteFile] = []
        for entry in entries:
            mode = entry.st_mode or 0
            items.append(
                RemoteFile(
                    name=entry.filename,
                    path=f"{path.rstrip('/')}/{entry.filename}" if path not in ("", ".") else entry.filename,
                    size=entry.st_size or 0,
                    is_dir=bool(mode & 0o040000),
                    mode=oct(mode & 0o777)[2:].rjust(3, "0"),
                    mtime=time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.st_mtime or 0)),
                )
            )
        items.sort(key=lambda f: (not f.is_dir, f.name.lower()))
        return items

    def download(self, remote_path: str, local_path: str | Path) -> Path:
        client = self._sftp_client()
        target = Path(local_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            client.get(remote_path, str(target))
        except Exception as exc:
            raise SshError(f"下载失败：{exc}") from exc
        return target

    def upload(self, local_path: str | Path, remote_path: str) -> None:
        client = self._sftp_client()
        try:
            client.put(str(local_path), remote_path)
        except Exception as exc:
            raise SshError(f"上传失败：{exc}") from exc

    # ---------------------------------------------------------------- 展示
    def describe(self) -> str:
        parts = [f"{self.username}@{self.host}:{self.port}"]
        if self.facts.get("HOST"):
            parts.append(f"主机名 {self.facts['HOST']}")
        if self.facts.get("KERNEL"):
            parts.append(f"内核 {self.facts['KERNEL']}")
        if self.facts.get("ARCH"):
            parts.append(self.facts["ARCH"])
        return " · ".join(parts)


def parse_ssh_target(spec: str, default_user: str = "root") -> tuple[str, int, str]:
    """解析 ``[user@]host[:port]``，返回 ``(host, port, user)``。"""
    user = default_user
    rest = (spec or "").strip()
    if not rest:
        raise ValueError("需要主机地址，例如 192.168.1.42 或 root@192.168.1.42:22")
    if "@" in rest:
        user, _, rest = rest.partition("@")
    port = 22
    if ":" in rest:
        host, _, port_text = rest.partition(":")
        rest = host
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError(f"端口不是数字：{port_text}") from exc
    if not rest:
        raise ValueError("主机地址为空")
    return rest, port, user or default_user


# 兼容早期测试/调用里的私有命名
_parse_ssh_target = parse_ssh_target


# 常用只读命令，GUI 上做成一键按钮，避免手打。
QUICK_COMMANDS: list[tuple[str, str]] = [
    ("系统信息", "uname -a; echo; uptime"),
    ("磁盘占用", "df -h"),
    ("内存", "free -h"),
    ("进程 TOP10", "ps -eo pid,ppid,pcpu,pmem,comm --sort=-pcpu | head -n 11"),
    ("监听端口", "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"),
    ("网卡地址", "ip -brief addr 2>/dev/null || ifconfig"),
    ("启动服务", "systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -n 20"),
    ("最近登录", "last -n 15 2>/dev/null"),
    ("内核日志尾部", "dmesg 2>/dev/null | tail -n 25"),
]


__all__ = [
    "DEFAULT_TIMEOUT",
    "HAS_PARAMIKO",
    "QUICK_COMMANDS",
    "parse_ssh_target",
    "ExecResult",
    "RemoteFile",
    "SshAuthError",
    "SshError",
    "SshSession",
    "SshUnavailable",
]
