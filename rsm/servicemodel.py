"""Сервисный слой: сервисы ↔ namespaces ↔ workloads ↔ ноды ↔ кластеры, команды.

- namespaces атрибутируются тем же движком правил (applies_to: namespace);
- workload наследует владельца namespace, если сам не размечен (labels team/service);
- для каждой k8s-ноды считается, чьи нагрузки на ней работают (доля CPU requests),
  и критичность ноды поднимается до максимальной критичности её нагрузок;
- сервисы, которые встречаются в разметке, но отсутствуют в каталоге, — «незарегистрированные».
"""
from __future__ import annotations

from collections import defaultdict

from .attribution import flatten
from .util import short_hostname

TIER = {"tier-1": 1, "tier-2": 2, "tier-3": 3, "tier-4": 4}
SERVICE_LABELS = ("service", "app.kubernetes.io/part-of", "app.kubernetes.io/name")


def _ns_view(a: dict) -> dict:
    ann = a.get("annotations") or {}
    return {"name": a["name"], "k8s_cluster": a["cluster"], "labels": a.get("labels") or {},
            "tags": {f"k8s:{k}": v for k, v in ann.items()},
            "annotation": "\n".join(f"{k}: {v}" for k, v in ann.items()), "sources": ["k8s"]}


def build(cfg, engine, cis: list[dict], obs_by_kind: dict) -> dict:
    # --- namespaces ---
    namespaces = {}
    for o in obs_by_kind.get("k8s_namespace", []):
        a = o["attrs"]
        ns = {"id": f"{a['cluster']}/{a['name']}", "cluster": a["cluster"], "name": a["name"],
              "labels": a.get("labels") or {}, "annotations": a.get("annotations") or {}}
        flatten(ns, engine.evaluate(_ns_view(a), "namespace"))
        ns["workloads"], ns["cpu_m"] = [], 0
        namespaces[ns["id"]] = ns

    # --- workloads ---
    workloads = []
    for o in obs_by_kind.get("k8s_workload", []):
        a = o["attrs"]
        ns = namespaces.get(f"{a['cluster']}/{a['namespace']}", {})
        labels = a.get("labels") or {}
        svc = next((cfg.normalize("service", labels[k])[0] for k in SERVICE_LABELS
                    if labels.get(k) and cfg.normalize("service", labels[k])[1]), None)
        team, team_known = cfg.normalize("owner_team", labels.get("team") or labels.get("owner"))
        wl = {"id": f"{a['cluster']}/{a['namespace']}/{a['kind']}/{a['name']}", "cluster": a["cluster"],
              "namespace": a["namespace"], "kind": a["kind"], "name": a["name"], "replicas": a.get("replicas"),
              "images": a.get("images", []), "helm_release": a.get("helm_release"), "argocd_app": a.get("argocd_app"),
              "service": svc or ns.get("service"), "owner_team": team if team_known else ns.get("owner_team"),
              "attributed_by": "labels" if (svc or team_known) else "namespace"}
        workloads.append(wl)
        if ns:
            ns["workloads"].append(f"{a['kind']}/{a['name']}")

    # --- размещение подов на нодах ---
    node_index = {(ci.get("k8s_cluster"), ci["hostname"]): ci for ci in cis if ci.get("k8s_cluster")}
    usage = defaultdict(lambda: defaultdict(int))     # ci_id → ns_id → cpu_m
    for o in obs_by_kind.get("k8s_placement", []):
        a = o["attrs"]
        ns_id = f"{a['cluster']}/{a['namespace']}"
        if ns_id in namespaces:
            namespaces[ns_id]["cpu_m"] += a["cpu_m"]
        ci = node_index.get((a["cluster"], short_hostname(a["node"])))
        if ci:
            usage[ci["id"]][ns_id] += a["cpu_m"]
    by_id = {ci["id"]: ci for ci in cis}
    for ci_id, per_ns in usage.items():
        ci = by_id[ci_id]
        total = sum(per_ns.values()) or 1
        consumers = []
        for ns_id, cpu in sorted(per_ns.items(), key=lambda x: -x[1]):
            ns = namespaces.get(ns_id, {})
            consumers.append({"namespace": ns_id, "owner_team": ns.get("owner_team"), "service": ns.get("service"),
                              "criticality": ns.get("criticality"), "cpu_m": cpu, "share": round(cpu / total, 3)})
        ci["k8s_consumers"] = consumers
        _inherit_criticality(cfg, ci, consumers)

    # --- сервисы ---
    services = {}
    for name, spec in cfg.catalog.items():
        services[name] = {"name": name, "owner_team": spec.get("owner_team"), "criticality": spec.get("criticality"),
                          "registered": True, "origin": cfg.catalog_origin.get(name), "repo": spec.get("repo"),
                          "description": spec.get("description"), "hosts": [], "namespaces": [], "workloads": 0,
                          "k8s_nodes": set(), "clusters": set()}

    def svc_entry(name, team=None):
        if name not in services:
            services[name] = {"name": name, "owner_team": team, "criticality": None, "registered": False,
                              "origin": "discovered", "repo": None, "description": None, "hosts": [],
                              "namespaces": [], "workloads": 0, "k8s_nodes": set(), "clusters": set()}
        return services[name]

    for ci in cis:
        if ci.get("service"):
            svc_entry(ci["service"], ci.get("owner_team"))["hosts"].append(ci["id"])
    for ns in namespaces.values():
        if ns.get("service"):
            e = svc_entry(ns["service"], ns.get("owner_team"))
            e["namespaces"].append(ns["id"])
            e["clusters"].add(ns["cluster"])
    for wl in workloads:
        if wl.get("service"):
            svc_entry(wl["service"], wl.get("owner_team"))["workloads"] += 1
    for ci in cis:
        for c in ci.get("k8s_consumers", []):
            if c.get("service"):
                services[c["service"]]["k8s_nodes"].add(ci["id"])
    for s in services.values():
        s["k8s_nodes"] = sorted(s["k8s_nodes"])
        s["clusters"] = sorted(s["clusters"])

    # --- команды (showback) ---
    teams = defaultdict(lambda: {"servers": 0, "services": set(), "namespaces": 0, "k8s_cpu_m": 0})
    for ci in cis:
        if ci.get("owner_team"):
            teams[ci["owner_team"]]["servers"] += 1
    for s in services.values():
        if s.get("owner_team"):
            teams[s["owner_team"]]["services"].add(s["name"])
    for ns in namespaces.values():
        if ns.get("owner_team"):
            teams[ns["owner_team"]]["namespaces"] += 1
            teams[ns["owner_team"]]["k8s_cpu_m"] += ns["cpu_m"]
    team_rows = []
    for t, v in sorted(teams.items()):
        info = cfg.team_info(t)
        team_rows.append({"team": t, "known": t in cfg.teams, "oncall": info.get("oncall"), "lead": info.get("lead"),
                          "servers": v["servers"], "services": sorted(v["services"]),
                          "namespaces": v["namespaces"], "k8s_cpu_cores": round(v["k8s_cpu_m"] / 1000, 1)})

    return {"namespaces": sorted(namespaces.values(), key=lambda n: n["id"]),
            "workloads": sorted(workloads, key=lambda w: w["id"]),
            "services": sorted(services.values(), key=lambda s: s["name"]),
            "teams": team_rows}


def _inherit_criticality(cfg, ci: dict, consumers: list[dict]) -> None:
    tiers = [(TIER[c["criticality"]], c) for c in consumers if c.get("criticality") in TIER]
    if not tiers:
        return
    best, src = min(tiers, key=lambda x: x[0])
    current = TIER.get(ci.get("criticality") or "", 99)
    if best >= current:
        return
    crit = f"tier-{best}"
    ev = f"k8s-inherit: на ноде работают нагрузки {src['namespace']} ({src['service']}, {crit})"
    ci["attribution"]["criticality"] = {"value": crit, "suggestion": crit, "confidence": 0.9, "status": "auto",
                                        "evidence": [ev] + ci["attribution"]["criticality"].get("evidence", []),
                                        "alternatives": []}
    ci["attribution"]["support_model"] = {"value": cfg.support_model(crit), "status": "auto", "confidence": 0.9,
                                          "evidence": ["из criticality"]}
    ci["criticality"] = crit
    ci["support_model"] = cfg.support_model(crit)
