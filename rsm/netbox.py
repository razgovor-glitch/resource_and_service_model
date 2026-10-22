"""Публикация модели в NetBox (resource CMDB) и обратное чтение подтверждений.

  rsm netbox bootstrap [--apply]   custom fields, теги, команды-tenants, типы кластеров, site/role/type
  rsm netbox sync [--apply]        upsert ВМ (virtualization) и железа (dcim) с владельцами
  rsm netbox pull                  объекты с rsm_owner_confirmed=true → data/raw/netbox/confirmed.json

По умолчанию — dry-run: план изменений пишется в data/reports/netbox-plan.json.
Без NETBOX_URL работает офлайн (считает NetBox пустым) — удобно проверить payload'ы.

Модель в NetBox:
  команда              → Tenant (группа tenants «teams»)
  сервис/окружение/... → custom fields rsm_* на Device и VirtualMachine
  K8s / vSphere кластер→ Cluster (типы kubernetes / vmware)
  подтверждение        → custom field rsm_owner_confirmed (ставит человек; sync его не трогает)
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from .cmdb import CMDB
from .util import parse_time, write_json

OBJECT_TYPES = ["dcim.device", "virtualization.virtualmachine"]
CUSTOM_FIELDS = [
    ("rsm_id", "RSM ID", "text"),
    ("rsm_service", "Сервис", "text"),
    ("rsm_environment", "Окружение", "text"),
    ("rsm_criticality", "Критичность", "text"),
    ("rsm_support_model", "Модель поддержки", "text"),
    ("rsm_role", "Роль (выведена)", "text"),
    ("rsm_owner_status", "Статус владения", "text"),
    ("rsm_owner_confidence", "Уверенность атрибуции", "decimal"),
    ("rsm_owner_evidence", "Улики атрибуции", "longtext"),
    ("rsm_owner_confirmed", "Владелец подтверждён", "boolean"),
    ("rsm_lifecycle", "Жизненный цикл", "text"),
    ("rsm_last_seen", "Последний раз жив", "datetime"),
    ("rsm_sources", "Источники discovery", "text"),
    ("rsm_ips", "IP-адреса", "text"),
]
TAGS = ["rsm-managed", "rsm-unowned", "rsm-needs-confirmation", "rsm-conflict", "rsm-stale"]
STATUS = {"active": "active", "stale": "offline", "decommission-candidate": "decommissioning"}
OWNERSHIP_CF = ("rsm_service", "rsm_environment", "rsm_criticality", "rsm_support_model")


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", str(s).lower()).strip("-")[:100] or "x"


class NetBox:
    def __init__(self, url: str | None, token: str | None, apply: bool):
        self.url = url.rstrip("/") if url else None
        self.token = token
        self.apply = apply and bool(url)
        self.plan: list[dict] = []
        self._fake_id = 0
        self.version = "4.0"
        if self.url:
            self.version = str(self._req("GET", "/api/status/").get("netbox-version", "4.0"))

    @property
    def offline(self) -> bool:
        return not self.url

    def _req(self, method, path, body=None, params=None):
        url = self.url + path + ("?" + urllib.parse.urlencode(params, doseq=True) if params else "")
        auth = f"Bearer {self.token}" if (self.token or "").startswith("nbt_") else f"Token {self.token}"
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": auth, "Content-Type": "application/json",
                                              "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as err:
            raise RuntimeError(f"NetBox {method} {path}: {err.code} {err.read().decode()[:500]}") from err

    def list(self, path, **params) -> list[dict]:
        if self.offline:
            return []
        out, params = [], {"limit": 500, **params}
        page = self._req("GET", path, params=params)
        out += page.get("results", [])
        while page.get("next"):
            nxt = urllib.parse.urlparse(page["next"])
            page = self._req("GET", nxt.path, params=urllib.parse.parse_qs(nxt.query))
            out += page.get("results", [])
        return out

    def create(self, path, payload, label):
        self.plan.append({"action": "create", "path": path, "object": label, "payload": payload})
        if self.apply:
            return self._req("POST", path, payload)
        self._fake_id -= 1
        return {"id": self._fake_id, **payload}

    def patch(self, path, obj_id, payload, label, diff):
        self.plan.append({"action": "update", "path": f"{path}{obj_id}/", "object": label, "diff": diff})
        if self.apply:
            return self._req("PATCH", f"{path}{obj_id}/", payload)
        return {"id": obj_id, **payload}

    def ensure(self, path, lookup: dict, payload: dict, label: str) -> dict:
        found = self.list(path, **lookup)
        return found[0] if found else self.create(path, payload, label)


def client(cfg, apply: bool) -> NetBox:
    nb = cfg.main.get("netbox") or {}
    return NetBox(os.environ.get(nb.get("url_env", "NETBOX_URL")),
                  os.environ.get(nb.get("token_env", "NETBOX_TOKEN")), apply)


# ---------------------------------------------------------------- bootstrap
def bootstrap(cfg, nb: NetBox) -> dict:
    ot_key = "object_types" if not nb.version.startswith("3.") else "content_types"
    for name, label, typ in CUSTOM_FIELDS:
        nb.ensure("/api/extras/custom-fields/", {"name": name},
                  {"name": name, "label": label, "type": typ, ot_key: OBJECT_TYPES, "group_name": "RSM",
                   **({"default": False} if typ == "boolean" else {})}, f"custom field {name}")
    for t in TAGS:
        nb.ensure("/api/extras/tags/", {"slug": t}, {"name": t, "slug": t}, f"tag {t}")
    group = nb.ensure("/api/tenancy/tenant-groups/", {"slug": "teams"}, {"name": "teams", "slug": "teams"}, "tenant group teams")
    for team in cfg.teams:
        nb.ensure("/api/tenancy/tenants/", {"slug": slug(team)},
                  {"name": team, "slug": slug(team), "group": group["id"]}, f"tenant {team}")
    for ct in ("kubernetes", "vmware", "unclassified"):
        nb.ensure("/api/virtualization/cluster-types/", {"slug": ct}, {"name": ct, "slug": ct}, f"cluster type {ct}")
    _infra(cfg, nb)
    return _summary(nb)


def _infra(cfg, nb: NetBox) -> dict:
    conf = cfg.main.get("netbox") or {}
    site = conf.get("site", "dc1")
    ids = {"site": nb.ensure("/api/dcim/sites/", {"slug": slug(site)},
                             {"name": site, "slug": slug(site), "status": "active"}, f"site {site}")["id"]}
    mf = nb.ensure("/api/dcim/manufacturers/", {"slug": "generic"}, {"name": "Generic", "slug": "generic"}, "manufacturer")
    ids["device_type"] = nb.ensure("/api/dcim/device-types/", {"slug": "generic-server"},
                                   {"manufacturer": mf["id"], "model": "Generic server", "slug": "generic-server"},
                                   "device type")["id"]
    for role, color in (("server", "2196f3"), ("k8s-node", "9c27b0"), ("unknown", "9e9e9e")):
        ids[f"role:{role}"] = nb.ensure("/api/dcim/device-roles/", {"slug": role},
                                        {"name": role, "slug": role, "color": color}, f"device role {role}")["id"]
    return ids


# ---------------------------------------------------------------- sync
def sync(cfg, nb: NetBox) -> dict:
    infra = _infra(cfg, nb)
    tenants = {t["slug"]: t["id"] for t in nb.list("/api/tenancy/tenants/")}
    ctypes = {t["slug"]: t["id"] for t in nb.list("/api/virtualization/cluster-types/")}
    clusters = {c["name"]: c["id"] for c in nb.list("/api/virtualization/clusters/")}

    def cluster_id(name, ctype):
        if ctype not in ctypes:
            ctypes[ctype] = nb.create("/api/virtualization/cluster-types/", {"name": ctype, "slug": ctype},
                                      f"cluster type {ctype}")["id"]
        if name not in clusters:
            clusters[name] = nb.create("/api/virtualization/clusters/",
                                       {"name": name, "type": ctypes[ctype], "status": "active"},
                                       f"cluster {name}")["id"]
        return clusters[name]

    def tenant_id(team):
        if not team:
            return None
        s = slug(team)
        if s not in tenants:
            tenants[s] = nb.create("/api/tenancy/tenants/", {"name": team, "slug": s}, f"tenant {team}")["id"]
        return tenants[s]

    existing = {}
    for path in ("/api/virtualization/virtual-machines/", "/api/dcim/devices/"):
        for obj in nb.list(path):
            rid = (obj.get("custom_fields") or {}).get("rsm_id")
            existing[rid or f"name:{obj['name']}"] = (path, obj)

    stats = {"create": 0, "update": 0, "unchanged": 0, "skipped_confirmed_fields": 0, "type_mismatch": []}
    for ci in CMDB(cfg.cmdb_path).rows():
        is_vm = bool(ci.get("virtual"))
        path = "/api/virtualization/virtual-machines/" if is_vm else "/api/dcim/devices/"
        if ci.get("k8s_cluster"):
            cl = cluster_id(ci["k8s_cluster"], "kubernetes")
        elif ci.get("vcenter_cluster"):
            cl = cluster_id(ci["vcenter_cluster"], "vmware")
        else:
            cl = cluster_id("rsm-unclassified", "unclassified") if is_vm else None
        cf = {"rsm_id": ci["id"], "rsm_service": ci.get("service"), "rsm_environment": ci.get("environment"),
              "rsm_criticality": ci.get("criticality"), "rsm_support_model": ci.get("support_model"),
              "rsm_role": ci.get("role"), "rsm_owner_status": ci.get("owner_status"),
              "rsm_owner_confidence": ci.get("owner_confidence"),
              "rsm_owner_evidence": "\n".join(ci["attribution"]["owner_team"]["evidence"][:5]),
              "rsm_lifecycle": ci["lifecycle"], "rsm_sources": ", ".join(ci["sources"]),
              "rsm_ips": ", ".join(ci["ips"]),
              "rsm_last_seen": (parse_time(ci["last_alive"]).isoformat() if ci.get("last_alive") else None)}
        tags = ["rsm-managed"] + {"unowned": ["rsm-unowned"], "needs-confirmation": ["rsm-needs-confirmation"],
                                  "conflict": ["rsm-conflict"]}.get(ci.get("owner_status"), [])
        if ci["lifecycle"] != "active":
            tags.append("rsm-stale")
        payload = {"name": ci["hostname"], "status": STATUS.get(ci["lifecycle"], "active"),
                   "tenant": tenant_id(ci.get("owner_team")), "custom_fields": cf,
                   "tags": [{"slug": t} for t in tags]}
        if cl:
            payload["cluster"] = cl
        if is_vm:
            payload.update({"vcpus": ci.get("cpu"), "memory": ci.get("memory_mb")})
        else:
            role = "k8s-node" if ci.get("k8s_cluster") else ("server" if ci.get("virtual") is False else "unknown")
            payload.update({"device_type": infra["device_type"], "role": infra[f"role:{role}"], "site": infra["site"],
                            "serial": (ci.get("serial") or "")[:50]})
        payload = {k: v for k, v in payload.items() if v is not None}

        found = existing.get(ci["id"]) or existing.get(f"name:{ci['hostname']}")
        if not found:
            nb.create(path, payload, ci["hostname"])
            stats["create"] += 1
            continue
        fpath, obj = found
        if fpath != path:
            # ВМ ↔ железо: тип объекта в NetBox не меняем автоматически (нужно пересоздать вручную)
            stats["type_mismatch"].append(ci["hostname"])
            continue
        # Чужие теги (поставленные людьми) сохраняем: PATCH tags заменяет список целиком.
        payload["tags"] = [{"slug": t["slug"]} for t in obj.get("tags") or []
                           if not t["slug"].startswith("rsm-")] + payload["tags"]
        if (obj.get("custom_fields") or {}).get("rsm_owner_confirmed"):
            # Владение подтверждено человеком в NetBox — эти поля не трогаем.
            payload.pop("tenant", None)
            for k in OWNERSHIP_CF:
                cf.pop(k, None)
            stats["skipped_confirmed_fields"] += 1
        diff = _diff(obj, payload)
        if diff:
            nb.patch(fpath, obj["id"], {k: payload[k] for k in diff}, ci["hostname"], diff)
            stats["update"] += 1
        else:
            stats["unchanged"] += 1
    return {**stats, **_summary(nb)}


def _same_cf(a, b) -> bool:
    """NetBox может вернуть значение в другом виде: '…Z' вместо '…+00:00', 1 вместо 1.0."""
    if a == b:
        return True
    if isinstance(a, str) and isinstance(b, str) and re.match(r"\d{4}-\d\d-\d\dT", a) and re.match(r"\d{4}-\d\d-\d\dT", b):
        return parse_time(a) == parse_time(b)
    return False


def _diff(obj: dict, payload: dict) -> dict:
    def ref(v):
        return v.get("id") if isinstance(v, dict) else v

    diff = {}
    for k, v in payload.items():
        cur = obj.get(k)
        if k == "custom_fields":
            changed = {ck: cv for ck, cv in v.items() if not _same_cf((cur or {}).get(ck), cv)}
            if changed:
                diff[k] = changed
        elif k == "tags":
            if sorted(t["slug"] for t in cur or []) != sorted(t["slug"] for t in v):
                diff[k] = v
        elif isinstance(cur, dict) and "value" in cur:      # status: {"value": "active", ...}
            if cur["value"] != v:
                diff[k] = v
        elif ref(cur) != v:
            diff[k] = v
    return diff


def _summary(nb: NetBox) -> dict:
    return {"mode": "apply" if nb.apply else ("dry-run (offline)" if nb.offline else "dry-run"),
            "planned_actions": len(nb.plan)}


def write_plan(cfg, nb: NetBox) -> str:
    path = cfg.reports_dir / "netbox-plan.json"
    write_json(path, nb.plan)
    return str(path)


# ---------------------------------------------------------------- pull confirmed
def pull_confirmed(cfg, nb: NetBox) -> int:
    if nb.offline:
        raise RuntimeError("для pull нужен NETBOX_URL/NETBOX_TOKEN")
    out = []
    for path in ("/api/virtualization/virtual-machines/", "/api/dcim/devices/"):
        for obj in nb.list(path, cf_rsm_owner_confirmed="true"):
            cf = obj.get("custom_fields") or {}
            out.append({"rsm_id": cf.get("rsm_id"), "name": obj["name"], "url": obj.get("url"),
                        "owner_team": (obj.get("tenant") or {}).get("slug"),
                        "service": cf.get("rsm_service"), "environment": cf.get("rsm_environment"),
                        "criticality": cf.get("rsm_criticality"), "confirmed_by": "netbox",
                        "confirmed_at": obj.get("last_updated")})
    write_json(cfg.raw("netbox", "confirmed.json"), out)
    return len(out)
