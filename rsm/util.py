"""Общие хелперы: нормализация идентификаторов, время, JSON/JSONL."""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import re
from pathlib import Path

# Мусорные серийники, которые BIOS отдаёт «по умолчанию» — по ним склеивать нельзя.
JUNK_SERIALS = {
    "", "0", "none", "null", "n/a", "na", "not specified", "not available",
    "to be filled by o.e.m.", "default string", "system serial number",
    "0123456789", "123456789", "chassis serial number",
}
# Пустые/широковещательные MAC, VRRP (keepalived) и docker-bridge — не уникальны.
JUNK_MAC_PREFIXES = ("00:00:00", "ff:ff:ff", "00:00:5e:00:01", "02:42")

_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def parse_time(value) -> dt.datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if isinstance(value, (int, float)) or str(value).strip().isdigit():
        return dt.datetime.fromtimestamp(int(value), dt.timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    try:
        t = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def iso(t: dt.datetime | None) -> str | None:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


def days_between(later: dt.datetime, earlier: dt.datetime | None) -> float:
    if earlier is None:
        return 0.0
    return (later - earlier).total_seconds() / 86400


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def norm_token(value) -> str:
    """Единый вид значений словаря: нижний регистр, пробелы/подчёркивания → дефис."""
    return re.sub(r"[\s_]+", "-", str(value).strip().lower()).strip("-")


def is_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def norm_hostname(name) -> str | None:
    if not name:
        return None
    n = str(name).strip().lower().rstrip(".")
    if not n or is_ip(n) or not _HOST_RE.match(n):
        return None
    return n


def short_hostname(name) -> str | None:
    n = norm_hostname(name)
    return n.split(".")[0] if n else None


def norm_uuid(value) -> str | None:
    if not value:
        return None
    h = re.sub(r"[^0-9a-f]", "", str(value).lower())
    if len(h) != 32 or set(h) <= {"0"} or set(h) <= {"f"}:
        return None
    return h


def swap_uuid(h: str) -> str:
    """Перестановка байт первых трёх полей UUID (little-endian в SMBIOS < 2.6).

    Из-за этого vCenter (config.uuid) и Linux (/sys/class/dmi/id/product_uuid)
    у одной и той же ВМ иногда показывают «разные» UUID.
    """
    return (h[6:8] + h[4:6] + h[2:4] + h[0:2] + h[10:12] + h[8:10]
            + h[14:16] + h[12:14] + h[16:])


def uuid_key(value) -> str | None:
    """Канонический ключ UUID, не зависящий от порядка байт."""
    h = norm_uuid(value)
    return min(h, swap_uuid(h)) if h else None


def norm_mac(value) -> str | None:
    if not value:
        return None
    h = re.sub(r"[^0-9a-f]", "", str(value).lower())
    if len(h) != 12:
        return None
    mac = ":".join(h[i:i + 2] for i in range(0, 12, 2))
    return None if mac.startswith(JUNK_MAC_PREFIXES) else mac


def norm_serial(value) -> str | None:
    if not value:
        return None
    s = re.sub(r"\s+", " ", str(value)).strip().lower()
    return None if s in JUNK_SERIALS or len(s) < 4 else s


def stable_id(prefix: str, *parts) -> str:
    digest = hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:10]
    return f"{prefix}-{digest}"


def parse_cpu_m(q) -> int:
    """Kubernetes CPU quantity → милликоры ('500m' → 500, '2' → 2000)."""
    if q in (None, ""):
        return 0
    s = str(q).strip()
    try:
        return int(float(s[:-1])) if s.endswith("m") else int(float(s) * 1000)
    except ValueError:
        return 0


_MEM_UNITS = {"Ki": 2 ** 10, "Mi": 2 ** 20, "Gi": 2 ** 30, "Ti": 2 ** 40,
              "K": 10 ** 3, "M": 10 ** 6, "G": 10 ** 9, "T": 10 ** 12, "": 1}


def parse_mem_mb(q) -> int:
    """Kubernetes memory quantity → MiB ('512Mi' → 512, '65842404Ki' → 64299)."""
    if q in (None, ""):
        return 0
    m = re.fullmatch(r"([0-9.]+)([KMGT]i?|)", str(q).strip())
    return int(float(m.group(1)) * _MEM_UNITS[m.group(2)] / 2 ** 20) if m else 0


def read_json(path, default=None):
    p = Path(path)
    if not p.exists():
        return default
    with p.open(encoding="utf-8") as f:
        return json.load(f)


def write_json(path, data) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)


def read_jsonl(path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path, rows) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
