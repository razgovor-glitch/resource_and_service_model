"""Ansible: факты хостов + инвентори.

Ожидаемые файлы:
  data/raw/ansible/facts/<inventory_hostname>  — JSON фактов. Поддерживаются оба формата:
      * вывод `ansible -m setup --tree DIR` / плейбука deploy/ansible/collect_facts.yml:
        {"ansible_facts": {...}}
      * jsonfile fact cache: {...факты...}
  data/raw/ansible/inventory.json — `ansible-inventory -i INV --list`

Хосты, которые есть в инвентори, но без фактов (недоступны), тоже попадают в модель
с alive=false: «объявлен, но не отвечает» — важный сигнал для legacy.
"""
from __future__ import annotations

import json

from ..util import iso, parse_time, short_hostname
from .base import observation

# hostvars, которые считаются явным объявлением владельца/сервиса
HOSTVAR_TAGS = ("owner_team", "team", "service", "environment", "env", "criticality")


def fact(f: dict, *names):
    for n in names:
        for k in (f"ansible_{n}", n):
            v = f.get(k)
            if v not in (None, "", "NA"):
                return v
    return None


def _inventory(path) -> tuple[dict, dict]:
    """→ (host → [группы, включая родительские], host → hostvars)."""
    if not path.exists():
        return {}, {}
    inv = json.loads(path.read_text(encoding="utf-8"))
    hostvars = (inv.get("_meta") or {}).get("hostvars") or {}
    parents: dict[str, set] = {}
    direct: dict[str, set] = {}
    for group, spec in inv.items():
        if group == "_meta" or not isinstance(spec, dict):
            continue
        for child in spec.get("children", []):
            parents.setdefault(child, set()).add(group)
        for host in spec.get("hosts", []):
            direct.setdefault(host, set()).add(group)

    def ancestors(g, seen=None):
        seen = seen or set()
        for p in parents.get(g, ()):
            if p not in seen:
                seen.add(p)
                ancestors(p, seen)
        return seen

    groups = {}
    for host, gs in direct.items():
        allg = set(gs)
        for g in gs:
            allg |= ancestors(g)
        groups[host] = sorted(allg - {"all", "ungrouped"})
    return groups, hostvars


def collect(cfg) -> list[dict]:
    base = cfg.raw("ansible")
    groups, hostvars = _inventory(base / "inventory.json")
    out, with_facts = [], set()
    facts_dir = base / "facts"
    for p in sorted(facts_dir.glob("*")) if facts_dir.exists() else []:
        if p.is_dir() or p.name.startswith("."):
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if d.get("unreachable") or d.get("failed"):
            continue
        f = d.get("ansible_facts", d)
        inv_name = p.name
        with_facts.add(inv_name)
        dip = fact(f, "default_ipv4") or {}
        ips = [ip for ip in fact(f, "all_ipv4_addresses") or [] if cfg.ip_usable(ip)]
        if dip.get("address") and dip["address"] not in ips:
            ips.insert(0, dip["address"])
        virt_role = fact(f, "virtualization_role")
        local = fact(f, "local") or {}
        tags = {k: v for k, v in (hostvars.get(inv_name) or {}).items() if k in HOSTVAR_TAGS}
        tags.update({f"fact_{k}": v for k, v in (local.get("rsm") or {}).items()})  # /etc/ansible/facts.d/rsm.fact
        services = fact(f, "services") or {}
        running = sorted(n.removesuffix(".service") for n, s in services.items()
                         if isinstance(s, dict) and s.get("state") == "running")
        hostname = fact(f, "hostname")
        dist = " ".join(x for x in (fact(f, "distribution"), fact(f, "distribution_version")) if x)
        out.append(observation(
            "ansible", "host",
            keys={"uuid": [fact(f, "product_uuid")], "serial": [fact(f, "product_serial")],
                  "mac": [dip.get("macaddress")],
                  "host": [hostname, fact(f, "fqdn"), short_hostname(inv_name)],
                  "ip": [dip.get("address")]},
            attrs={"hostname": short_hostname(hostname) or short_hostname(inv_name),
                   "fqdn": fact(f, "fqdn"), "ips": ips, "macs": [dip.get("macaddress")],
                   "os": dist or fact(f, "os_family"), "kernel": fact(f, "kernel"),
                   "cpu": fact(f, "processor_vcpus"), "memory_mb": fact(f, "memtotal_mb"),
                   "vendor": fact(f, "system_vendor"), "model": fact(f, "product_name"),
                   "serial": fact(f, "product_serial"), "uuid": fact(f, "product_uuid"),
                   "virtual": (virt_role == "guest") if virt_role else None,
                   "platform": (fact(f, "virtualization_type") or "").lower() or None,
                   "groups": groups.get(inv_name, []), "tags": tags,
                   "services_running": running, "alive": True,
                   "observed_at": iso(parse_time((fact(f, "date_time") or {}).get("iso8601")))},
            ref=inv_name))

    # Объявлены в инвентори, но факты не собраны.
    for inv_name in sorted(set(groups) | set(hostvars)):
        if inv_name in with_facts:
            continue
        hv = hostvars.get(inv_name) or {}
        out.append(observation(
            "ansible", "host",
            keys={"host": [short_hostname(inv_name)], "ip": [hv.get("ansible_host")]},
            attrs={"hostname": short_hostname(inv_name), "ips": [hv["ansible_host"]] if hv.get("ansible_host") else [],
                   "groups": groups.get(inv_name, []),
                   "tags": {k: v for k, v in hv.items() if k in HOSTVAR_TAGS},
                   "alive": False, "ansible_unreachable": True},
            ref=inv_name))
    return out
