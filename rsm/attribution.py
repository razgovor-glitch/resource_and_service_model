"""Движок правил атрибуции: «чей сервер / namespace».

Каждое правило (config/attribution_rules.yaml) = условия `when` + значения `set` + вес.
Значения могут ссылаться на именованные группы регэкспов: set: {owner_team: "{team}"}.
Все совпавшие правила — это улики (evidence). Улики за одно значение складываются
по noisy-OR: score = 1 - Π(1 - w). Победитель + статус:

  confirmed           подтверждено человеком (overrides.csv / NetBox / rsm confirm)
  auto                score ≥ thresholds.auto
  needs-confirmation  thresholds.needs_confirmation ≤ score < auto
  conflict            второй кандидат слишком близко к первому
  unknown             нет улик или они слабее needs_confirmation
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from functools import lru_cache

from .util import as_list, norm_token

FIELDS = ("owner_team", "service", "environment", "criticality", "role")


@lru_cache(maxsize=None)
def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.I)


@lru_cache(maxsize=None)
def _net(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


class Rule:
    def __init__(self, spec: dict, idx: int):
        self.name = spec.get("name") or f"rule-{idx}"
        self.applies_to = set(as_list(spec.get("applies_to", "host")))
        self.when = spec.get("when") or {}
        self.set = spec.get("set") or {}
        self.weight = float(spec.get("weight", 0.5))
        unknown = set(self.when) - CONDITIONS
        if unknown:
            raise ValueError(f"правило {self.name}: неизвестные условия {sorted(unknown)}")

    def check(self, view: dict):
        caps, ev = {}, []
        for cond, arg in self.when.items():
            res = _CHECKS[cond](view, arg, caps)
            if res is None:
                return None
            ev.append(res)
        return caps, ev


def _c_match(view, arg, caps):
    ev = []
    for field, pattern in arg.items():
        for v in as_list(view.get(field)):
            m = _rx(pattern).search(str(v)) if v not in (None, "") else None
            if m:
                caps.update({k: x for k, x in m.groupdict().items() if x})
                ev.append(f"{field}={v}")
                break
        else:
            return None
    return ", ".join(ev)


def _c_kv(store_name, label):
    def check(view, arg, caps):
        keys = {k.lower() for k in as_list(arg.get("key"))}
        sources = set(as_list(arg.get("source")))
        for full_key, val in (view.get(store_name) or {}).items():
            src, _, key = full_key.partition(":") if store_name == "tags" else ("k8s", "", full_key)
            if key.lower() not in keys or (sources and src not in sources) or val in (None, ""):
                continue
            if arg.get("value"):
                m = _rx(arg["value"]).search(str(val))
                if not m:
                    continue
                caps.update({k: x for k, x in m.groupdict().items() if x})
            caps["value"] = str(val)
            return f"{label} {full_key}={val}"
        return None
    return check


def _c_group(view, arg, caps):
    pattern = arg["pattern"] if isinstance(arg, dict) else arg
    sources = set(as_list(arg.get("source"))) if isinstance(arg, dict) else set()
    for g in view.get("groups") or []:
        src, _, name = g.partition(":")
        if sources and src not in sources:
            continue
        m = _rx(pattern).search(name)
        if m:
            caps.update({k: x for k, x in m.groupdict().items() if x})
            return f"группа {g}"
    return None


def _c_subnet(view, arg, caps):
    for ip in view.get("ips") or []:
        for cidr in as_list(arg):
            if ipaddress.ip_address(ip) in _net(cidr):
                return f"IP {ip} ∈ {cidr}"
    return None


def _c_port(view, arg, caps):
    hit = sorted({int(p) for p in as_list(arg)} & set(view.get("open_ports") or []))
    return f"открыты порты {hit}" if hit else None


def _c_ports_all(view, arg, caps):
    need = {int(p) for p in as_list(arg)}
    return f"открыты порты {sorted(need)}" if need <= set(view.get("open_ports") or []) else None


def _c_service_running(view, arg, caps):
    for s in view.get("services_running") or []:
        if _rx(arg).search(s):
            return f"запущен {s}"
    return None


def _c_source(view, arg, caps):
    hit = set(as_list(arg)) & set(view.get("sources") or [])
    return f"источник {sorted(hit)}" if hit else None


def _c_only_source(view, arg, caps):
    srcs = set(view.get("sources") or [])
    return f"виден только в {sorted(srcs)}" if srcs and srcs <= set(as_list(arg)) else None


_CHECKS = {
    "match": _c_match, "tag": _c_kv("tags", "тег"), "label": _c_kv("labels", "label"),
    "group": _c_group, "subnet": _c_subnet, "port": _c_port, "ports_all": _c_ports_all,
    "service_running": _c_service_running, "source": _c_source, "only_source": _c_only_source,
}
CONDITIONS = set(_CHECKS)


def _render(tpl, caps) -> str | None:
    try:
        v = str(tpl).format(**caps)
    except (KeyError, IndexError):
        return None
    return v.strip() or None


def catalog_rules(cfg) -> list[Rule]:
    """Каталог сервисов сам порождает правила: hosts-паттерны и k8s namespaces → service."""
    out = []
    for svc, spec in cfg.catalog.items():
        for i, pattern in enumerate(as_list((spec or {}).get("hosts"))):
            out.append(Rule({"name": f"catalog:{svc}:hosts", "when": {"match": {"hostname": pattern}},
                             "set": {"service": svc}, "weight": 0.85}, i))
        for i, ns in enumerate(as_list((spec or {}).get("k8s_namespaces"))):
            out.append(Rule({"name": f"catalog:{svc}:namespace", "applies_to": "namespace",
                             "when": {"match": {"name": f"^{re.escape(ns)}$"}},
                             "set": {"service": svc}, "weight": 0.9}, i))
    return out


class Engine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.rules = [Rule(r, i) for i, r in enumerate(cfg.rules)] + catalog_rules(cfg)

    def evaluate(self, view: dict, kind: str = "host", confirmed: dict | None = None) -> dict:
        cand: dict = defaultdict(lambda: defaultdict(dict))  # field → value → rule → (w, evidence)
        notes: list[str] = []
        for rule in self.rules:
            if kind not in rule.applies_to:
                continue
            hit = rule.check(view)
            if hit is None:
                continue
            caps, ev = hit
            evidence = f"{rule.name}: {'; '.join(ev)}"
            for field, tpl in rule.set.items():
                raw = _render(tpl, caps)
                if not raw:
                    continue
                if field == "owner_person":
                    team = self.cfg.people.get(norm_token(raw))
                    if team:
                        self._add(cand, "owner_team", team, rule.name, rule.weight * 0.9,
                                  f"{evidence} → {raw} из команды {team} (people.yaml)", notes)
                    else:
                        notes.append(f"человек '{raw}' не найден в people.yaml")
                    continue
                self._add(cand, field, raw, rule.name, rule.weight, evidence, notes)
        self._derive(cand, notes)
        result = {f: self._resolve(f, cand.get(f, {}), (confirmed or {}).get(f)) for f in FIELDS}
        crit = result["criticality"]
        result["support_model"] = {"value": self.cfg.support_model(crit["value"]), "status": crit["status"],
                                   "confidence": crit["confidence"],
                                   "evidence": ["из criticality"] if crit["value"] else []}
        result["notes"] = sorted(set(notes))
        return result

    def _add(self, cand, field, raw, rule, weight, evidence, notes):
        value, known = self.cfg.normalize(field, raw)
        if not value:
            return
        if not known:
            weight *= 0.5
            evidence += f" [значения '{raw}' нет в словаре — вес снижен]"
            notes.append(f"неизвестное значение {field}='{raw}' (добавьте в dictionary.yaml / каталог)")
        prev = cand[field][value].get(rule)
        if not prev or prev[0] < weight:
            cand[field][value][rule] = (round(weight, 3), evidence)

    @staticmethod
    def _score(rules: dict) -> float:
        p = 1.0
        for w, _ in rules.values():
            p *= 1 - min(w, 0.999)
        return 1 - p

    def _best(self, values: dict):
        if not values:
            return None
        return max(((v, self._score(r)) for v, r in values.items()), key=lambda x: x[1])

    def _derive(self, cand, notes):
        """Производные улики: сервис → владелец/критичность (каталог), окружение → критичность."""
        svc = self._best(cand.get("service"))
        env = self._best(cand.get("environment"))
        if svc:
            name, score = svc
            spec = self.cfg.catalog.get(name) or {}
            if spec.get("owner_team"):
                self._add(cand, "owner_team", spec["owner_team"], "service-catalog", score * 0.95,
                          f"service-catalog: сервис {name} принадлежит {spec['owner_team']}", notes)
            if spec.get("criticality") and not (env and self.cfg.env_criticality(env[0])):
                self._add(cand, "criticality", spec["criticality"], "service-catalog", score * 0.95,
                          f"service-catalog: критичность сервиса {name}", notes)
        if env and self.cfg.env_criticality(env[0]):
            self._add(cand, "criticality", self.cfg.env_criticality(env[0]), "env-criticality", env[1] * 0.95,
                      f"env-criticality: окружение {env[0]}", notes)

    def _resolve(self, field: str, values: dict, confirmed: dict | None) -> dict:
        ranked = sorted(((self._score(r), v, r) for v, r in values.items()), key=lambda x: -x[0])
        evidence = [f"{v} ← {ev} (w={w:.2f})" for _, v, r in ranked
                    for w, ev in sorted(r.values(), key=lambda x: -x[0])]
        alternatives = [{"value": v, "confidence": round(s, 2)} for s, v, _ in ranked[1:4]]
        if confirmed and confirmed.get("value"):
            value = confirmed["value"]
            src = f"подтверждено: {confirmed.get('by') or '?'} {confirmed.get('at') or ''} ({confirmed.get('origin')})"
            return {"value": value, "suggestion": value, "confidence": 1.0, "status": "confirmed",
                    "evidence": [src] + evidence,
                    "alternatives": [{"value": v, "confidence": round(s, 2)} for s, v, _ in ranked if v != value][:3]}
        if not ranked:
            return {"value": None, "suggestion": None, "confidence": 0.0, "status": "unknown",
                    "evidence": [], "alternatives": []}
        th = self.cfg.thresholds
        top_s, top_v, _ = ranked[0]
        second = ranked[1][0] if len(ranked) > 1 else 0.0
        if top_s < th["needs_confirmation"]:
            status = "unknown"
        elif field != "role" and second >= th["needs_confirmation"] and top_s - second < th["conflict_margin"]:
            status = "conflict"
        elif top_s >= th["auto"]:
            status = "auto"
        else:
            status = "needs-confirmation"
        return {"value": top_v if status != "unknown" else None, "suggestion": top_v,
                "confidence": round(top_s, 2), "status": status, "evidence": evidence,
                "alternatives": alternatives}


def host_view(ci: dict) -> dict:
    """Плоское представление CI, по которому матчатся правила."""
    keys = ("hostname", "fqdn", "vm_name", "os", "annotation", "k8s_cluster", "k8s_role", "vcenter_cluster",
            "datacenter", "folder", "platform", "node_pool", "zabbix_name", "ips", "open_ports",
            "services_running", "sources", "tags", "labels", "groups")
    return {k: ci.get(k) for k in keys}


OWNER_STATUS = {"unknown": "unowned"}


def flatten(target: dict, attribution: dict) -> None:
    """Скопировать итоговые значения атрибуции в плоские поля CI/namespace."""
    target["attribution"] = attribution
    for f in (*FIELDS, "support_model"):
        target[f] = attribution[f]["value"]
    own = attribution["owner_team"]
    target["owner_status"] = OWNER_STATUS.get(own["status"], own["status"])
    target["owner_confidence"] = own["confidence"]
    target["owner_suggestion"] = own.get("suggestion")
