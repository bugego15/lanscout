"""MAC OUI → 厂商名称（离线，数据来自 IEEE / Wireshark manuf）。"""

from __future__ import annotations

import gzip
import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Optional

# 找不到数据文件时的最小兜底（覆盖常见消费/网络厂商）。
_FALLBACK = {
    "000C29": "VMware, Inc.",
    "00155D": "Microsoft Corporation",
    "005056": "VMware, Inc.",
    "080027": "PCS Systemtechnik GmbH (VirtualBox)",
    "3C5282": "Intel Corporate",
    "3C5A37": "Samsung Electronics",
    "44D9E7": "Ubiquiti Inc.",
    "50C7BF": "TP-Link",
    "525400": "QEMU virtual NIC",
    "5C0272": "Huawei Technologies",
    "6C5AB0": "TCL",
    "7CDFA1": "Espressif Inc.",
    "8C1645": "Apple, Inc.",
    "A4C138": "Apple, Inc.",
    "B827EB": "Raspberry Pi Foundation",
    "BCF5AC": "LG Electronics",
    "C0EEFB": "Huawei Technologies",
    "D8D385": "Apple, Inc.",
    "ECF8EB": "Sichuan Tianyi Comheart Telecom",
    "F4F5D8": "Huawei Technologies",
    "FC9D05": "Micro-Star INTL CO., LTD.",
}


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):  # pragma: no cover - PyInstaller 预留
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def data_path() -> Path:
    return _base_dir() / "data" / "oui.json.gz"


@lru_cache(maxsize=1)
def load_oui() -> dict[str, str]:
    path = data_path()
    if path.exists():
        try:
            with gzip.open(path, "rt", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict) and raw:
                return {str(k).upper(): str(v) for k, v in raw.items()}
        except Exception:
            pass
    return dict(_FALLBACK)


def normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    cleaned = "".join(ch for ch in mac.upper() if ch.isalnum())
    if len(cleaned) != 12:
        return mac.strip().upper()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def prefix_of(mac: str) -> str:
    normalized = normalize_mac(mac)
    return "".join(ch for ch in normalized if ch.isalnum())[:6].upper()


@lru_cache(maxsize=2048)
def vendor_for_mac(mac: str) -> str:
    prefix = prefix_of(mac)
    if len(prefix) < 6:
        return ""
    vendor = load_oui().get(prefix, "")
    if vendor:
        return vendor
    if is_locally_administered(mac):
        return "本地管理 MAC（随机地址/虚拟设备）"
    return ""


def is_locally_administered(mac: str) -> bool:
    normalized = normalize_mac(mac)
    digits = "".join(ch for ch in normalized if ch.isalnum())
    if len(digits) < 2:
        return False
    try:
        first = int(digits[:2], 16)
    except ValueError:
        return False
    return bool(first & 0x02)


def is_multicast(mac: str) -> bool:
    digits = "".join(ch for ch in normalize_mac(mac) if ch.isalnum())
    if len(digits) < 2:
        return False
    try:
        return bool(int(digits[:2], 16) & 0x01)
    except ValueError:
        return False


def database_info() -> dict[str, object]:
    db = load_oui()
    path = data_path()
    return {
        "entries": len(db),
        "path": str(path),
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "source": "IEEE OUI / Wireshark manuf",
    }


__all__ = [
    "database_info",
    "is_locally_administered",
    "is_multicast",
    "load_oui",
    "normalize_mac",
    "prefix_of",
    "vendor_for_mac",
]
