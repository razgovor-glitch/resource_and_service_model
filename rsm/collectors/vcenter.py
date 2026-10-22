"""vCenter: JSON-выгрузка ВМ (контракт ниже), её делает deploy/vcenter/export_vcenter.ps1 (PowerCLI).

Контракт (список ВМ или {"exported_at": ..., "vms": [...]}):
  name, uuid (BIOS UUID = config.uuid), instance_uuid, guest_hostname, ip_addresses[],
  mac_addresses[], guest_os, num_cpu, memory_mb, power_state, cluster, datacenter,
  folder, esxi_host, tags{категория: значение}, annotation, custom_attributes{}
"""
from __future__ import annotations

import json

from ..util import iso, parse_time, short_hostname
from .base import observation


def _tags(vm: dict) -> dict:
    tags = {}
    for k, v in (vm.get("tags") or {}).items():
        tags[k.lower()] = ",".join(map(str, v)) if isinstance(v, list) else v
    for k, v in (vm.get("custom_attributes") or {}).items():
        if v not in (None, ""):
            tags.setdefault(k.lower(), v)
    return tags


def collect(cfg) -> list[dict]:
    out = []
    for path in sorted(cfg.raw("vcenter").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        exported_at = None
        if isinstance(data, dict):
            exported_at = iso(parse_time(data.get("exported_at")))
            data = data.get("vms", [])
        for vm in data:
            guest = vm.get("guest_hostname")
            hostname = cfg.host_key(guest) and short_hostname(guest)
            if not hostname:  # VMware Tools не отдал имя или отдал «localhost» — пробуем имя ВМ
                hostname = cfg.host_key(vm.get("name")) and short_hostname(vm.get("name"))
            ips = [ip for ip in vm.get("ip_addresses") or [] if cfg.ip_usable(ip)]
            power = vm.get("power_state")
            out.append(observation(
                "vcenter", "host",
                keys={"uuid": [vm.get("uuid")], "mac": vm.get("mac_addresses") or [],
                      "host": [hostname], "ip": ips},
                attrs={"hostname": hostname, "fqdn": guest if guest and "." in guest else None,
                       "vm_name": vm.get("name"), "ips": ips, "macs": vm.get("mac_addresses") or [],
                       "os": vm.get("guest_os"), "cpu": vm.get("num_cpu"), "memory_mb": vm.get("memory_mb"),
                       "uuid": vm.get("uuid"), "virtual": True, "platform": "vmware",
                       "vcenter_cluster": vm.get("cluster"), "datacenter": vm.get("datacenter"),
                       "folder": vm.get("folder"), "esxi_host": vm.get("esxi_host"),
                       "power_state": power, "tags": _tags(vm), "annotation": vm.get("annotation"),
                       "alive": str(power).lower() in ("poweredon", "powered_on"),
                       "observed_at": exported_at},
                ref=vm.get("instance_uuid") or vm.get("name")))
    return out
