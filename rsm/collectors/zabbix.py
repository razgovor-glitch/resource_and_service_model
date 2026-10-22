"""Zabbix: результат API host.get (см. `rsm fetch zabbix`).

Даёт группы хостов, теги, инвентарь и доступность агента. Записи о давно
выведенных серверах в Zabbix — частое явление: они видны как alive=false.
"""
from __future__ import annotations

import json

from ..util import short_hostname
from .base import observation


def collect(cfg) -> list[dict]:
    path = cfg.raw("zabbix", "hosts.json")
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    hosts = data.get("result", data) if isinstance(data, dict) else data
    out = []
    for h in hosts:
        interfaces = h.get("interfaces") or []
        ips = [i["ip"] for i in interfaces if i.get("ip") and cfg.ip_usable(i["ip"])]
        dns = next((i["dns"] for i in interfaces if i.get("dns")), None)
        avail = {str(i.get("available")) for i in interfaces}
        if str(h.get("status", "0")) == "1":       # хост отключён в Zabbix
            alive = False
        elif "1" in avail:
            alive = True
        elif "2" in avail:
            alive = False
        else:
            alive = None                             # агент в active-режиме / неизвестно
        inv = h.get("inventory") if isinstance(h.get("inventory"), dict) else {}
        groups = [g["name"] for g in (h.get("hostgroups") or h.get("groups") or [])]
        tags = {t["tag"].lower(): t.get("value", "") for t in h.get("tags") or []}
        hostname = short_hostname(h.get("host")) or short_hostname(dns)
        out.append(observation(
            "zabbix", "host",
            keys={"host": [h.get("host"), dns], "ip": ips,
                  "serial": [inv.get("serialno_a")], "mac": [inv.get("macaddress_a")]},
            attrs={"hostname": hostname, "fqdn": dns, "ips": ips, "os": inv.get("os"),
                   "serial": inv.get("serialno_a"), "groups": groups, "tags": tags,
                   "zabbix_name": h.get("name"), "alive": alive},
            ref=str(h.get("hostid") or h.get("host"))))
    return out
