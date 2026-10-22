"""DNS: CSV-выгрузка зоны (name,type,value). A-записи дают связку hostname ↔ IP.

DNS не доказывает, что хост жив (alive не выставляется): старые записи
остаются после вывода серверов и как раз помогают находить конфликты IP.
"""
from __future__ import annotations

import csv

from ..util import short_hostname
from .base import observation


def collect(cfg) -> list[dict]:
    records: dict[str, set] = {}
    for path in sorted(cfg.raw("dns").glob("*.csv")):
        with path.open(encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if (row.get("type") or "A").upper() not in ("A", "AAAA"):
                    continue
                name = (row.get("name") or "").strip().lower().rstrip(".")
                if name:
                    records.setdefault(name, set()).add(row["value"].strip())
    return [observation("dns", "host",
                        keys={"host": [short_hostname(name)], "ip": sorted(ips)},
                        attrs={"hostname": short_hostname(name), "fqdn": name, "ips": sorted(ips)},
                        ref=name)
            for name, ips in sorted(records.items())]
