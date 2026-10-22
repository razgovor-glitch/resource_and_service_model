"""Склейка наблюдений в конфигурационные единицы (CI) и сопоставление с CMDB.

Алгоритм:
  1. У каждого наблюдения вычисляются ключи идентичности.
     Сильные: uuid (без учёта порядка байт), serial, mac, host (короткое имя).
     Слабый:  ip — переиспользуется, поэтому склеивает только наблюдения без сильных ключей
              (nmap без rDNS, Zabbix только с IP).
  2. Union-find по сильным ключам, затем «подвешивание» IP-only наблюдений.
  3. Поля CI берутся по приоритету источников (config: precedence), списки объединяются.
  4. Конфликты: несколько UUID в одной CI, один IP у разных CI.
  5. identify(): каждой CI ищется существующая запись CMDB по ключам → стабильный id.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from .util import (days_between, norm_mac, norm_serial, parse_time, stable_id,
                   uuid_key)

SCALAR_FIELDS = (
    "hostname", "fqdn", "os", "kernel", "cpu", "memory_mb", "vendor", "model", "serial", "uuid",
    "virtual", "platform", "vm_name", "power_state", "vcenter_cluster", "datacenter", "folder",
    "esxi_host", "annotation", "k8s_cluster", "k8s_role", "k8s_version", "k8s_node_uid", "node_pool",
    "mac_vendor", "zabbix_name",
)
HW_VENDORS = re.compile(r"dell|hpe?\b|hewlett|lenovo|supermicro|huawei|fujitsu|cisco|inspur|gigabyte", re.I)
LIST_FIELDS = ("ips", "macs", "open_ports", "services_running", "nmap_services")


class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, i):
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def identity_keys(obs: dict, cfg) -> tuple[list[str], list[str]]:
    k = obs.get("keys", {})
    strong = []
    strong += [f"uuid:{x}" for x in map(uuid_key, k.get("uuid", [])) if x]
    strong += [f"serial:{x}" for x in map(norm_serial, k.get("serial", [])) if x]
    strong += [f"mac:{x}" for x in map(norm_mac, k.get("mac", [])) if x]
    strong += [f"host:{x}" for x in map(cfg.host_key, k.get("host", [])) if x]
    weak = [f"ip:{ip}" for ip in k.get("ip", []) if cfg.ip_usable(ip)]
    return sorted(set(strong)), sorted(set(weak))


def resolve(host_obs: list[dict], cfg, now) -> tuple[list[dict], list[dict]]:
    """→ (список CI, список конфликтов склейки)."""
    for o in host_obs:
        o["_strong"], o["_weak"] = identity_keys(o, cfg)
    uf = UnionFind(len(host_obs))
    owner: dict[str, int] = {}
    weak_only = []
    for i, o in enumerate(host_obs):
        if not o["_strong"]:
            weak_only.append(i)
            continue
        for key in o["_strong"]:
            if key in owner:
                uf.union(i, owner[key])
            else:
                owner[key] = i

    conflicts = []
    ip_comp = defaultdict(set)
    for i, o in enumerate(host_obs):
        if o["_strong"]:
            for key in o["_weak"]:
                ip_comp[key].add(uf.find(i))
    weak_owner: dict[str, int] = {}
    for i in weak_only:
        o = host_obs[i]
        comps = {uf.find(c) for key in o["_weak"] for c in ip_comp.get(key, ())}
        if len(comps) == 1:
            uf.union(i, comps.pop())
        elif len(comps) > 1:
            conflicts.append({"type": "ambiguous-ip", "detail":
                              f"{o['source']} {o['ref']}: IP {o['_weak']} принадлежит нескольким хостам"})
        else:
            for key in o["_weak"]:
                if key in weak_owner:
                    uf.union(i, weak_owner[key])
                else:
                    weak_owner[key] = i

    groups = defaultdict(list)
    for i, o in enumerate(host_obs):
        groups[uf.find(i)].append(o)
    cis = [_build_ci(obs, cfg, now) for obs in groups.values()]
    _detect_ip_conflicts(cis, cfg)
    cis.sort(key=lambda c: (c["hostname"] or "~", c["ips"][:1]))
    return cis, conflicts


def _fresh(o: dict, cfg, now) -> bool:
    t = parse_time(o["attrs"].get("observed_at"))
    return t is None or days_between(now, t) * 24 <= cfg.lifecycle["freshness_hours"]


def _build_ci(obs: list[dict], cfg, now) -> dict:
    ci: dict = {"kind": "host", "conflicts": [], "provenance": {}}
    for field in SCALAR_FIELDS:
        order = cfg.precedence(field)
        rank = {s: i for i, s in enumerate(order)}
        cands = []
        for o in obs:
            v = o["attrs"].get(field)
            if v in (None, "", []):
                continue
            if field in ("hostname", "fqdn") and not cfg.host_key(v):
                continue
            cands.append((rank.get(o["source"], len(order)), o["source"], v))
        if cands:
            _, src, v = min(cands, key=lambda c: (c[0], c[1]))
            ci[field] = v
            ci["provenance"][field] = src
        else:
            ci[field] = None
    for field in LIST_FIELDS:
        vals = {v for o in obs for v in o["attrs"].get(field, [])}
        if field == "ips":
            vals = {v for v in vals if cfg.ip_usable(v)}
        ci[field] = sorted(vals, key=lambda x: (str(type(x)), x))
    ci["tags"] = {f"{o['source']}:{k}": v for o in obs for k, v in (o["attrs"].get("tags") or {}).items()}
    ci["labels"] = {k: v for o in obs for k, v in (o["attrs"].get("labels") or {}).items()}
    ci["groups"] = sorted({f"{o['source']}:{g}" for o in obs for g in o["attrs"].get("groups", [])})
    ci["sources"] = sorted({o["source"] for o in obs})
    ci["observations"] = [{"source": o["source"], "ref": o["ref"], "alive": o["attrs"].get("alive")} for o in obs]
    ci["alive"] = any(o["attrs"].get("alive") is True and _fresh(o, cfg, now) for o in obs)
    ci["identity_keys"] = sorted({k for o in obs for k in o["_strong"] + o["_weak"]})
    if ci["virtual"] is None and ci["platform"] in ("vmware", "kvm", "xen", "hyperv", "openstack"):
        ci["virtual"] = True
    if ci["virtual"] is None and HW_VENDORS.search(ci.get("vendor") or ""):
        ci["virtual"] = False
    if not ci["hostname"]:
        ci["hostname"] = f"ip-{ci['ips'][0].replace('.', '-')}" if ci["ips"] else None
        ci["unnamed"] = True
    uuids = {k for k in ci["identity_keys"] if k.startswith("uuid:")}
    if len(uuids) > 1:
        ci["conflicts"].append({"type": "identity", "detail":
                                f"в одну CI склеились разные UUID {sorted(uuids)} — вероятно дубль имени/MAC"})
    return ci


def _detect_ip_conflicts(cis: list[dict], cfg) -> None:
    by_ip = defaultdict(list)
    for ci in cis:
        for ip in ci["ips"]:
            if not cfg.ip_conflict_ignored(ip):
                by_ip[ip].append(ci)
    for ip, owners in by_ip.items():
        if len(owners) < 2:
            continue
        for ci in owners:
            others = sorted(o["hostname"] or "?" for o in owners if o is not ci)
            ci["conflicts"].append({"type": "ip-conflict", "detail": f"IP {ip} также у {', '.join(others)}"})


def identify(cis: list[dict], key_index: dict[str, list[str]]) -> None:
    """Присвоить CI стабильные id: переиспользовать запись CMDB, если совпал любой сильный ключ."""
    used = {}
    for ci in cis:
        strong = [k for k in ci["identity_keys"] if not k.startswith("ip:")]
        cands = Counter(cid for k in strong for cid in key_index.get(k, []))
        if not strong:
            cands = Counter(cid for k in ci["identity_keys"] for cid in key_index.get(k, []))
        cid = None
        if cands:
            best, _ = cands.most_common(1)[0]
            if len(cands) > 1:
                ci["conflicts"].append({"type": "cmdb-duplicate",
                                        "detail": f"совпадает с несколькими записями CMDB: {sorted(cands)}"})
            if best in used:
                ci["conflicts"].append({"type": "cmdb-duplicate",
                                        "detail": f"запись {best} уже сопоставлена с {used[best]}"})
            else:
                cid = best
        if not cid:
            seed = strong[0] if strong else (ci["identity_keys"][:1] or [ci["hostname"]])[0]
            cid = stable_id("ci", seed)
            while cid in used:
                cid = stable_id("ci", cid)
        ci["id"] = cid
        used[cid] = ci["hostname"]
