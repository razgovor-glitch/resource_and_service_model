"""Подтверждённое людьми владение (имеет приоритет над любыми правилами).

Источники:
  config/ownership_overrides.csv     — ручной реестр (host,owner_team,service,environment,criticality,confirmed_by,confirmed_at,comment)
  data/raw/netbox/confirmed.json     — объекты NetBox с rsm_owner_confirmed=true (`rsm netbox pull`)
Подтверждения, сделанные командой `rsm confirm`, хранятся прямо в CMDB и читаются при build.
"""
from __future__ import annotations

import csv
import json

from ..util import is_ip, short_hostname
from .base import observation

FIELDS = ("owner_team", "service", "environment", "criticality")


def collect(cfg) -> list[dict]:
    out = []
    if cfg.overrides_csv.exists():
        with cfg.overrides_csv.open(encoding="utf-8") as f:
            for row in csv.DictReader(r for r in f if not r.startswith("#")):
                host = (row.get("host") or "").strip()
                if not host:
                    continue
                out.append(observation(
                    "manual", "confirmation",
                    keys={"ip": [host]} if is_ip(host) else {"host": [short_hostname(host)]},
                    attrs={**{k: row.get(k) for k in FIELDS}, "confirmed_by": row.get("confirmed_by"),
                           "confirmed_at": row.get("confirmed_at"), "origin": cfg.overrides_csv.name},
                    ref=f"overrides:{host}"))
    nb = cfg.raw("netbox", "confirmed.json")
    if nb.exists():
        for obj in json.loads(nb.read_text(encoding="utf-8")):
            out.append(observation(
                "manual", "confirmation",
                keys={"rsm_id": [obj.get("rsm_id")], "host": [short_hostname(obj.get("name"))]},
                attrs={**{k: obj.get(k) for k in FIELDS}, "confirmed_by": obj.get("confirmed_by") or "netbox",
                       "confirmed_at": obj.get("confirmed_at"), "origin": "netbox"},
                ref=f"netbox:{obj.get('url') or obj.get('name')}"))
    return out
