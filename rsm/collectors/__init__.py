"""Коллекторы: читают сырые выгрузки из data/raw/<source>/ и превращают их
в единый формат наблюдений (observation), который пишется в data/staging/<source>.jsonl.

Наблюдение — это «что источник X знает о сущности»:
    {"source": "vcenter", "kind": "host", "ref": "vm-123",
     "keys":  {"uuid": [...], "mac": [...], "host": [...], "ip": [...], "serial": [...]},
     "attrs": {...нормализованные атрибуты...}}

kind: host | k8s_namespace | k8s_workload | k8s_placement | service | confirmation
"""
from __future__ import annotations

from ..util import write_jsonl
from . import ansible, dns, git, k8s, manual, nmap, vcenter, zabbix

COLLECTORS = {
    "nmap": nmap.collect,
    "dns": dns.collect,
    "ansible": ansible.collect,
    "vcenter": vcenter.collect,
    "zabbix": zabbix.collect,
    "k8s": k8s.collect,
    "git": git.collect,
    "manual": manual.collect,
}


def run_collect(cfg, only: list[str] | None = None) -> dict[str, int]:
    counts = {}
    for name, fn in COLLECTORS.items():
        if only and name not in only:
            continue
        if not cfg.source_enabled(name):
            continue
        rows = fn(cfg)
        write_jsonl(cfg.staging_dir / f"{name}.jsonl", rows)
        counts[name] = len(rows)
    return counts
